//! Forwarding to upstream resolvers: one transport per server, picked by
//! speed, with one retry on the next best server.

pub mod doh;
pub mod endpoint;
mod outage;
pub mod stream;
pub mod tls;
mod udp;

#[cfg(test)]
pub(crate) mod test_dns;
#[cfg(test)]
mod test_doh;
#[cfg(test)]
pub(crate) mod test_tls;

use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::BuildHasher;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout_at};

use crate::budget::{Budget, Charge};
use crate::config::{LimitsConfig, UpstreamConfig};
use crate::dns::wire::{self, Header, flags};

use doh::DohUpstream;
use endpoint::Bootstrap;
use outage::{Outage, Report};
use stream::{Dial, StreamUpstream};
use tls::{Alpn, Tls, TlsDialer};

const DEFAULT_DNS_PORT: u16 = 53;
const INITIAL_SRTT_MS: f64 = 100.0;
const SRTT_WEIGHT_OF_NEW_SAMPLE: f64 = 0.3;
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub enum UpstreamError {
    Timeout,
    Io(io::Error),
    /// The connection went away before a reply arrived.
    Closed,
    BadReply,
    /// A DoH server answered with something other than HTTP 200.
    HttpStatus(u16),
    ReplyTooLarge,
    /// The global budget for reply bytes has no room for this reply.
    BudgetExhausted,
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpstreamError::Timeout => {
                write!(formatter, "timed out")
            }

            UpstreamError::Io(error) => {
                write!(formatter, "{error}")
            }

            UpstreamError::Closed => {
                write!(formatter, "connection closed")
            }

            UpstreamError::BadReply => {
                write!(formatter, "invalid reply")
            }

            UpstreamError::HttpStatus(status) => {
                write!(formatter, "HTTP status {status}")
            }

            UpstreamError::ReplyTooLarge => {
                write!(formatter, "reply too large")
            }

            UpstreamError::BudgetExhausted => {
                write!(formatter, "no room in the pending-bytes budget")
            }
        }
    }
}

impl std::error::Error for UpstreamError {}

impl From<io::Error> for UpstreamError {
    fn from(error: io::Error) -> UpstreamError {
        UpstreamError::Io(error)
    }
}

/// Random bits for query IDs and server choice. `RandomState` is seeded by the
/// OS, which avoids a dependency on a random number crate.
pub(crate) fn random_u64() -> u64 {
    RandomState::new().hash_one(0u8)
}

/// True when `reply` is a response to `request`: same ID and opcode, QR set,
/// and the same question. The name is compared without regard to letter case,
/// the type and class exactly.
pub(crate) fn is_answer_to(request: &[u8], reply: &[u8]) -> bool {
    let (Ok(request_header), Ok(reply_header)) = (Header::parse(request), Header::parse(reply))
    else {
        return false;
    };

    if request_header.id != reply_header.id
        || reply_header.flags & flags::QR == 0
        || request_header.opcode() != reply_header.opcode()
        || reply_header.question_count != 1
    {
        return false;
    }

    let Ok(name_end) = wire::skip_name(request, wire::HEADER_LEN) else {
        return false;
    };

    let question_end = name_end + 4;

    let (Some(asked), Some(echoed)) = (
        request.get(wire::HEADER_LEN..question_end),
        reply.get(wire::HEADER_LEN..question_end),
    ) else {
        return false;
    };

    let name_len = name_end - wire::HEADER_LEN;

    asked[..name_len].eq_ignore_ascii_case(&echoed[..name_len])
        && asked[name_len..] == echoed[name_len..]
}

/// A reply together with the claim on the pending-bytes budget that pays for
/// holding it. Dropping the charge gives the bytes back.
pub type Charged = (Vec<u8>, Charge);

/// A `Charged` reply and the position of the configured server that gave it.
#[derive(Debug)]
pub struct Answered {
    pub reply: Vec<u8>,
    pub charge: Charge,
    pub server: usize,
}

/// UDP with a fall back to TCP on the same address for truncated answers.
struct UdpUpstream {
    server: SocketAddr,
    max_reply: usize,
    tcp: StreamUpstream,
}

/// How to reach one upstream server.
enum Transport {
    Udp(UdpUpstream),
    Tcp(StreamUpstream),
    Dot(StreamUpstream),
    Doh(DohUpstream),
}

impl Transport {
    async fn query(
        &self,
        request: &mut [u8],
        budget: &Arc<Budget>,
        deadline: Instant,
    ) -> Result<Charged, UpstreamError> {
        match self {
            Transport::Udp(upstream) => {
                let reply =
                    udp::exchange(upstream.server, request, upstream.max_reply, deadline).await?;
                let truncated = Header::parse(&reply).is_ok_and(|header| header.truncated());
                if truncated {
                    // Uncharged bytes must not outlive the wait for the TCP answer.
                    drop(reply);

                    return upstream.tcp.query_charged(request, budget, deadline).await;
                }

                let charge = budget
                    .try_charge(reply.len())
                    .ok_or(UpstreamError::BudgetExhausted)?;

                Ok((reply, charge))
            }

            Transport::Tcp(upstream) | Transport::Dot(upstream) => {
                upstream.query_charged(request, budget, deadline).await
            }

            Transport::Doh(upstream) => upstream.query_charged(request, budget, deadline).await,
        }
    }
}

struct Health {
    srtt_ms: f64,
    failures: u32,
    retry_at: Option<Instant>,
    /// What has been logged about the current run of failures.
    outage: Outage,
}

/// What one server has done since picoguard started. Fixed size, whatever the traffic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    pub answered: u64,
    pub failed: u64,
    pub answer_micros: u64,
}

impl Tally {
    pub fn count_answer(&mut self, took: Duration) {
        self.answered += 1;
        self.answer_micros = self
            .answer_micros
            .saturating_add(u64::try_from(took.as_micros()).unwrap_or(u64::MAX));
    }

    pub fn count_failure(&mut self) {
        self.failed += 1;
    }

    /// Milliseconds with one decimal, over the answers only.
    pub fn average_ms(&self) -> Option<f64> {
        if self.answered == 0 {
            return None;
        }

        Some((self.answer_micros as f64 / self.answered as f64 / 100.0).round() / 10.0)
    }
}

struct Upstream {
    label: String,
    transport: Transport,
    /// Caps the requests in flight to this server.
    limiter: Semaphore,
    health: Mutex<Health>,
    tally: Mutex<Tally>,
    /// How long the first failure of a run keeps the server out of the pick; it doubles for
    /// each failure after that. A field so that a test can make it longer than the test.
    first_backoff: Duration,
}

impl Upstream {
    fn new(label: String, transport: Transport, limits: &LimitsConfig) -> Upstream {
        Upstream {
            label,
            transport,
            limiter: Semaphore::new(limits.upstream_concurrency),
            health: Mutex::new(Health {
                srtt_ms: INITIAL_SRTT_MS,
                failures: 0,
                retry_at: None,
                outage: Outage::default(),
            }),
            tally: Mutex::new(Tally::default()),
            first_backoff: FIRST_BACKOFF,
        }
    }

    async fn query(
        &self,
        request: &mut [u8],
        budget: &Arc<Budget>,
        deadline: Instant,
    ) -> Result<Charged, UpstreamError> {
        let started = Instant::now();
        let (result, exchange_time) = self.send(request, budget, deadline).await;

        match &result {
            Ok(_) => {
                self.tally.lock().unwrap().count_answer(exchange_time);
                self.record_success(started.elapsed());
            }

            // Our own limit says nothing about the server.
            Err(UpstreamError::BudgetExhausted) => {
                self.tally.lock().unwrap().count_failure();
            }

            Err(error) => {
                self.tally.lock().unwrap().count_failure();
                self.record_failure(error);
            }
        }

        result
    }

    /// The result, and how long the exchange took from the moment this try held one of the
    /// server's slots. It is zero when no slot came free.
    async fn send(
        &self,
        request: &mut [u8],
        budget: &Arc<Budget>,
        deadline: Instant,
    ) -> (Result<Charged, UpstreamError>, Duration) {
        let Ok(acquired) = timeout_at(deadline, self.limiter.acquire()).await else {
            return (Err(UpstreamError::Timeout), Duration::ZERO);
        };

        let Ok(_permit) = acquired else {
            return (Err(UpstreamError::Closed), Duration::ZERO);
        };

        let sent = Instant::now();
        let Ok(result) =
            timeout_at(deadline, self.transport.query(request, budget, deadline)).await
        else {
            return (Err(UpstreamError::Timeout), sent.elapsed());
        };

        (result, sent.elapsed())
    }

    fn record_success(&self, elapsed: Duration) {
        let mut health = self.health.lock().unwrap();
        let sample = elapsed.as_secs_f64() * 1000.0;
        health.srtt_ms =
            health.srtt_ms * (1.0 - SRTT_WEIGHT_OF_NEW_SAMPLE) + sample * SRTT_WEIGHT_OF_NEW_SAMPLE;
        health.failures = 0;
        health.retry_at = None;

        if let Some(recovered) = health.outage.succeeded(Instant::now()) {
            log::info!(
                "upstream {} answers again after {} failed queries",
                self.label,
                recovered.failures
            );
        }
    }

    fn record_failure(&self, error: &UpstreamError) {
        let mut health = self.health.lock().unwrap();
        match health.outage.failed(Instant::now()) {
            Report::Silent => {}

            Report::Started => {
                log::warn!("upstream {} failed: {error}", self.label);
            }

            Report::Continues { suppressed } => {
                log::warn!(
                    "upstream {} is still failing, {suppressed} more failures not logged: {error}",
                    self.label
                );
            }
        }

        health.failures += 1;
        let backoff = self
            .first_backoff
            .saturating_mul(1 << (health.failures - 1).min(6))
            .min(MAX_BACKOFF);
        health.retry_at = Some(Instant::now() + backoff);
    }
}

/// The configured upstream servers and how a query picks among them.
pub struct Upstreams {
    servers: Vec<Upstream>,
    timeout: Duration,
}

impl Upstreams {
    /// Builds the servers named in the config.
    pub fn from_config(
        upstream: &UpstreamConfig,
        limits: &LimitsConfig,
    ) -> Result<Upstreams, String> {
        let bootstrap = Bootstrap::new(&upstream.bootstrap);

        Upstreams::with_parts(
            upstream,
            limits,
            Arc::new(Tls::with_webpki_roots()),
            Arc::new(bootstrap),
        )
    }

    /// Like `from_config`, with the TLS settings (roots, AES policy) and the
    /// bootstrap resolver given.
    pub fn with_parts(
        upstream: &UpstreamConfig,
        limits: &LimitsConfig,
        tls: Arc<Tls>,
        bootstrap: Arc<Bootstrap>,
    ) -> Result<Upstreams, String> {
        let timeout = Duration::from_millis(upstream.timeout_ms);
        let context = Context {
            limits,
            timeout,
            tls: &tls,
            bootstrap: &bootstrap,
        };
        let mut servers = Vec::new();

        for spec in &upstream.servers {
            let transport = parse_server(spec, &context)?;
            servers.push(Upstream::new(spec.clone(), transport, limits));
        }

        Ok(Upstreams { servers, timeout })
    }

    /// A single plain-DNS server, such as the local resolver.
    pub fn plain(
        server: SocketAddr,
        upstream: &UpstreamConfig,
        limits: &LimitsConfig,
    ) -> Upstreams {
        let timeout = Duration::from_millis(upstream.timeout_ms);
        let transport = udp_transport(server, limits, timeout);

        Upstreams {
            servers: vec![Upstream::new(format!("udp://{server}"), transport, limits)],
            timeout,
        }
    }

    /// Each server's label as configured, with what it has done since start, in config order.
    pub fn tallies(&self) -> impl Iterator<Item = (&str, Tally)> + '_ {
        self.servers
            .iter()
            .map(|server| (server.label.as_str(), *server.tally.lock().unwrap()))
    }

    /// Like `query_charged`, without a limit on the bytes held.
    pub async fn query(&self, request: &mut [u8]) -> Result<Vec<u8>, UpstreamError> {
        let unlimited = Budget::new(usize::MAX);

        Ok(self.query_charged(request, &unlimited).await?.reply)
    }

    /// Sends `request` to the best server and, if that fails, once more to the
    /// next best. The ID in `request` is replaced. The first try gets half of
    /// the timeout so the second still has time. The reply comes with its
    /// charge on `budget`, taken while it was received, so that no reply
    /// bytes are held without being counted. A reply that does not fit
    /// the budget is `BudgetExhausted`, which is not retried.
    pub async fn query_charged(
        &self,
        request: &mut [u8],
        budget: &Arc<Budget>,
    ) -> Result<Answered, UpstreamError> {
        let started = Instant::now();
        let first = self.pick(None, random_unit());

        let first_attempt = self.servers[first]
            .query(request, budget, started + self.timeout / 2)
            .await;
        match first_attempt {
            Ok((reply, charge)) => {
                return Ok(Answered {
                    reply,
                    charge,
                    server: first,
                });
            }

            Err(UpstreamError::BudgetExhausted) => {
                return Err(UpstreamError::BudgetExhausted);
            }

            Err(_) => {}
        }

        let second = self.pick(Some(first), random_unit());

        let (reply, charge) = self.servers[second]
            .query(request, budget, started + self.timeout)
            .await?;

        Ok(Answered {
            reply,
            charge,
            server: second,
        })
    }

    /// Weighted random choice by inverse smoothed RTT among servers that are
    /// not backing off. `roll` is in `[0, 1)`.
    fn pick(&self, avoid: Option<usize>, roll: f64) -> usize {
        let now = Instant::now();
        let mut candidates: Vec<usize> = (0..self.servers.len())
            .filter(|index| Some(*index) != avoid)
            .collect();
        if candidates.is_empty() {
            candidates = (0..self.servers.len()).collect();
        }

        let healthy: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|index| {
                let health = self.servers[*index].health.lock().unwrap();

                health.retry_at.is_none_or(|retry_at| retry_at <= now)
            })
            .collect();

        if healthy.is_empty() {
            return candidates
                .into_iter()
                .min_by_key(|index| self.servers[*index].health.lock().unwrap().retry_at)
                .unwrap_or_default();
        }

        let weights: Vec<f64> = healthy
            .iter()
            .map(|index| 1.0 / self.servers[*index].health.lock().unwrap().srtt_ms.max(1.0))
            .collect();
        let mut remaining = roll * weights.iter().sum::<f64>();
        for (index, weight) in healthy.iter().zip(&weights) {
            if remaining < *weight {
                return *index;
            }

            remaining -= weight;
        }

        healthy[healthy.len() - 1]
    }
}

fn random_unit() -> f64 {
    (random_u64() >> 11) as f64 / (1u64 << 53) as f64
}

fn udp_transport(server: SocketAddr, limits: &LimitsConfig, timeout: Duration) -> Transport {
    Transport::Udp(UdpUpstream {
        server,
        max_reply: limits.upstream_reply_max,
        tcp: StreamUpstream::new(Dial::Plain(server), limits, timeout),
    })
}

/// What building a transport from a server URL needs besides the URL.
struct Context<'a> {
    limits: &'a LimitsConfig,
    timeout: Duration,
    tls: &'a Arc<Tls>,
    bootstrap: &'a Arc<Bootstrap>,
}

fn parse_server(spec: &str, context: &Context) -> Result<Transport, String> {
    let (limits, timeout) = (context.limits, context.timeout);

    if let Some(address) = spec.strip_prefix("udp://") {
        return Ok(udp_transport(
            parse_address(spec, address, DEFAULT_DNS_PORT)?,
            limits,
            timeout,
        ));
    }

    if let Some(address) = spec.strip_prefix("tcp://") {
        let server = parse_address(spec, address, DEFAULT_DNS_PORT)?;

        return Ok(Transport::Tcp(StreamUpstream::new(
            Dial::Plain(server),
            limits,
            timeout,
        )));
    }

    if let Some(rest) = spec.strip_prefix("tls://") {
        let target = endpoint::parse_tls(spec, rest, context.bootstrap)?;
        let dialer = TlsDialer::new(
            Arc::clone(context.tls),
            Alpn::Dot,
            target.server_name,
            target.remote,
            spec.to_string(),
        );

        return Ok(Transport::Dot(StreamUpstream::new(
            Dial::Tls(dialer),
            limits,
            timeout,
        )));
    }

    if let Some(rest) = spec.strip_prefix("https://") {
        let (target, uri) = endpoint::parse_https(spec, rest, context.bootstrap)?;
        let dialer = TlsDialer::new(
            Arc::clone(context.tls),
            Alpn::H2,
            target.server_name,
            target.remote,
            spec.to_string(),
        );

        return Ok(Transport::Doh(DohUpstream::new(dialer, uri, limits)));
    }

    Err(format!(
        "upstream {spec}: encrypted upstreams are not supported yet, use udp:// or tcp://"
    ))
}

fn parse_address(spec: &str, address: &str, default_port: u16) -> Result<SocketAddr, String> {
    if let Ok(server) = address.parse::<SocketAddr>() {
        return Ok(server);
    }

    address
        .parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, default_port))
        .map_err(|_| format!("upstream {spec}: expected an IP address and optional port"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    use super::*;
    use crate::upstream::test_dns::{
        ANSWER_MARKER, FakeDns, address_of, answer, fake_dns, query_for,
    };
    use crate::upstream::test_doh::{doh_server, respond_with_answer};
    use crate::upstream::test_tls::{TestPki, TlsServer};

    struct Fake {
        address: SocketAddr,
        received: Arc<AtomicUsize>,
    }

    type Replies = Vec<(Duration, Vec<u8>)>;

    /// A UDP server that answers each datagram with whatever `behavior` returns.
    async fn fake_udp(behavior: impl Fn(&[u8]) -> Replies + Send + Sync + 'static) -> Fake {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let address = socket.local_addr().unwrap();
        let received = Arc::new(AtomicUsize::new(0));
        let behavior = Arc::new(behavior);
        let counter = Arc::clone(&received);

        tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            loop {
                let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                    break;
                };

                counter.fetch_add(1, Ordering::SeqCst);
                let replies = behavior(&buffer[..length]);
                let socket = Arc::clone(&socket);
                tokio::spawn(async move {
                    for (delay, reply) in replies {
                        tokio::time::sleep(delay).await;
                        let _ = socket.send_to(&reply, peer).await;
                    }
                });
            }
        });

        Fake { address, received }
    }

    async fn good_udp() -> Fake {
        fake_udp(|request| vec![(Duration::ZERO, answer(request, ANSWER_MARKER, false))]).await
    }

    async fn dead_udp() -> Fake {
        fake_udp(|_| Vec::new()).await
    }

    fn upstreams(servers: Vec<String>, timeout_ms: u64) -> Upstreams {
        let config = UpstreamConfig {
            servers,
            timeout_ms,
            ..UpstreamConfig::default()
        };

        Upstreams::from_config(&config, &LimitsConfig::default()).unwrap()
    }

    fn udp_url(fake: &Fake) -> String {
        format!("udp://{}", fake.address)
    }

    #[test]
    fn the_average_is_over_answers_only_in_milliseconds_with_one_decimal() {
        let mut tally = Tally::default();

        assert_eq!(tally.average_ms(), None);

        tally.count_answer(Duration::from_millis(10));
        tally.count_answer(Duration::from_micros(13_049));
        tally.count_failure();

        assert_eq!(tally.answered, 2);
        assert_eq!(tally.failed, 1);
        assert_eq!(tally.answer_micros, 23_049);
        assert_eq!(tally.average_ms(), Some(11.5));
    }

    #[test]
    fn a_tally_adds_a_few_bytes_per_server() {
        assert!(std::mem::size_of::<Mutex<Tally>>() <= 64);
    }

    #[tokio::test]
    async fn udp_query_returns_the_answer_with_the_id_we_sent() {
        let server = good_udp().await;
        let upstreams = upstreams(vec![udp_url(&server)], 1000);
        let mut query = query_for("example.com.");

        let reply = upstreams.query(&mut query).await.unwrap();

        assert_eq!(address_of(&reply), ANSWER_MARKER);
        assert_eq!(reply[0..2], query[0..2]);
    }

    #[tokio::test]
    async fn udp_ignores_replies_with_a_wrong_id_or_question() {
        let server = fake_udp(|request| {
            let mut wrong_id = answer(request, [6, 6, 6, 6], false);
            wrong_id[0] ^= 0xFF;
            let other_question = answer(&query_for("other.example."), [7, 7, 7, 7], false);
            let mut with_our_id = other_question;
            with_our_id[0..2].copy_from_slice(&request[0..2]);

            vec![
                (Duration::ZERO, wrong_id),
                (Duration::ZERO, with_our_id),
                (
                    Duration::from_millis(20),
                    answer(request, ANSWER_MARKER, false),
                ),
            ]
        })
        .await;
        let upstreams = upstreams(vec![udp_url(&server)], 1000);

        let reply = upstreams
            .query(&mut query_for("example.com."))
            .await
            .unwrap();

        assert_eq!(address_of(&reply), ANSWER_MARKER);
    }

    #[tokio::test]
    async fn a_dead_server_times_out_after_two_tries_within_the_budget() {
        let server = dead_udp().await;
        let upstreams = upstreams(vec![udp_url(&server)], 600);
        let started = Instant::now();

        let result = upstreams.query(&mut query_for("example.com.")).await;

        assert!(matches!(result, Err(UpstreamError::Timeout)));
        assert!(started.elapsed() >= Duration::from_millis(590));
        assert!(started.elapsed() < Duration::from_millis(2000));
        assert_eq!(server.received.load(Ordering::SeqCst), 2, "one retry");
    }

    #[tokio::test]
    async fn a_slow_server_within_the_timeout_still_answers() {
        let server = fake_udp(|request| {
            vec![(
                Duration::from_millis(150),
                answer(request, ANSWER_MARKER, false),
            )]
        })
        .await;
        let upstreams = upstreams(vec![udp_url(&server)], 1000);

        let reply = upstreams.query(&mut query_for("example.com.")).await;

        assert!(reply.is_ok());
    }

    #[tokio::test]
    async fn queries_fail_over_to_the_other_server() {
        let dead = dead_udp().await;
        let good = good_udp().await;
        let upstreams = upstreams(vec![udp_url(&dead), udp_url(&good)], 1000);

        for _ in 0..6 {
            let reply = upstreams
                .query(&mut query_for("example.com."))
                .await
                .unwrap();

            assert_eq!(address_of(&reply), ANSWER_MARKER);
        }
    }

    #[tokio::test]
    async fn every_transport_hands_the_reply_over_with_its_charge() {
        let udp = good_udp().await;
        let upstreams = upstreams(vec![udp_url(&udp)], 1000);
        let budget = Budget::new(10_000);

        let Answered { reply, charge, .. } = upstreams
            .query_charged(&mut query_for("example.com."), &budget)
            .await
            .unwrap();

        assert_eq!(charge.bytes(), reply.len());
        assert_eq!(budget.used(), reply.len());

        drop(charge);

        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn a_reply_that_does_not_fit_the_budget_is_neither_retried_nor_blamed_on_the_server() {
        let udp = good_udp().await;
        let upstreams = upstreams(vec![udp_url(&udp)], 1000);
        let budget = Budget::new(10);

        let result = upstreams
            .query_charged(&mut query_for("example.com."), &budget)
            .await;

        assert!(
            matches!(result, Err(UpstreamError::BudgetExhausted)),
            "{result:?}"
        );
        assert_eq!(udp.received.load(Ordering::SeqCst), 1);
        assert_eq!(upstreams.servers[0].health.lock().unwrap().failures, 0);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn a_failed_server_is_skipped_while_it_backs_off() {
        let dead = dead_udp().await;
        let good = good_udp().await;
        let mut upstreams = upstreams(vec![udp_url(&dead), udp_url(&good)], 1000);
        // The backoff lasts longer than the test, however slow the machine is.
        for server in &mut upstreams.servers {
            server.first_backoff = MAX_BACKOFF;
        }

        for _ in 0..12 {
            upstreams
                .query(&mut query_for("example.com."))
                .await
                .unwrap();
        }

        assert!(dead.received.load(Ordering::SeqCst) <= 1);
    }

    #[tokio::test]
    async fn a_truncated_udp_answer_is_fetched_again_over_tcp() {
        // The same port number for TCP and UDP; another test may hold the UDP
        // side of a port that was free for TCP, so draw again.
        let (listener, udp) = loop {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            if let Ok(udp) = UdpSocket::bind(address).await {
                break (listener, udp);
            }
        };

        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            while let Ok((length, peer)) = udp.recv_from(&mut buffer).await {
                let reply = answer(&buffer[..length], [1, 1, 1, 1], true);
                let _ = udp.send_to(&reply, peer).await;
            }
        });
        tokio::spawn(serve_tcp(listener, Arc::new(AtomicUsize::new(0)), None));
        let upstreams = upstreams(vec![format!("udp://{address}")], 1000);

        let reply = upstreams
            .query(&mut query_for("example.com."))
            .await
            .unwrap();

        assert_eq!(address_of(&reply), ANSWER_MARKER);
        assert!(!Header::parse(&reply).unwrap().truncated());
        let (_, tally) = upstreams.tallies().next().unwrap();
        assert_eq!((tally.answered, tally.failed), (1, 0));
    }

    /// Answers framed queries on every accepted connection. With `limit`,
    /// closes a connection after that many queries.
    async fn serve_tcp(listener: TcpListener, accepted: Arc<AtomicUsize>, limit: Option<usize>) {
        loop {
            let Ok((mut connection, _)) = listener.accept().await else {
                break;
            };

            accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut served = 0;
                loop {
                    let mut length = [0u8; 2];
                    if connection.read_exact(&mut length).await.is_err() {
                        break;
                    }

                    let mut query = vec![0; usize::from(u16::from_be_bytes(length))];
                    if connection.read_exact(&mut query).await.is_err() {
                        break;
                    }

                    let reply = answer(&query, ANSWER_MARKER, false);
                    let mut frame = (reply.len() as u16).to_be_bytes().to_vec();
                    frame.extend_from_slice(&reply);
                    if connection.write_all(&frame).await.is_err() {
                        break;
                    }

                    served += 1;
                    if limit == Some(served) {
                        break;
                    }
                }
            });
        }
    }

    #[tokio::test]
    async fn tcp_upstream_reuses_one_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        tokio::spawn(serve_tcp(listener, Arc::clone(&accepted), None));
        let upstreams = upstreams(vec![format!("tcp://{address}")], 1000);

        for _ in 0..5 {
            let reply = upstreams
                .query(&mut query_for("example.com."))
                .await
                .unwrap();

            assert_eq!(address_of(&reply), ANSWER_MARKER);
        }

        assert_eq!(accepted.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_tcp_reply_is_charged_and_one_that_does_not_fit_is_not_blamed_on_the_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve_tcp(listener, Arc::new(AtomicUsize::new(0)), None));
        let upstreams = upstreams(vec![format!("tcp://{address}")], 1000);
        let budget = Budget::new(10_000);

        let Answered { reply, charge, .. } = upstreams
            .query_charged(&mut query_for("example.com."), &budget)
            .await
            .unwrap();
        assert_eq!((charge.bytes(), budget.used()), (reply.len(), reply.len()));
        drop(charge);
        assert_eq!(budget.used(), 0);

        let tiny = Budget::new(10);
        let result = upstreams
            .query_charged(&mut query_for("example.com."), &tiny)
            .await;

        assert!(
            matches!(result, Err(UpstreamError::BudgetExhausted)),
            "{result:?}"
        );
        assert_eq!(upstreams.servers[0].health.lock().unwrap().failures, 0);
        assert_eq!(tiny.used(), 0);
    }

    #[tokio::test]
    async fn a_failover_counts_a_failure_on_the_first_server_and_an_answer_on_the_second() {
        let dead = dead_udp().await;
        let slow = fake_udp(|request| {
            vec![(
                Duration::from_millis(50),
                answer(request, ANSWER_MARKER, false),
            )]
        })
        .await;
        let upstreams = upstreams(vec![udp_url(&dead), udp_url(&slow)], 1000);
        upstreams.servers[1].health.lock().unwrap().retry_at =
            Some(Instant::now() + Duration::from_secs(30));

        let started = Instant::now();
        upstreams
            .query(&mut query_for("example.com."))
            .await
            .unwrap();
        let whole_query_ms = started.elapsed().as_secs_f64() * 1000.0;

        let tallies: Vec<Tally> = upstreams.tallies().map(|(_, tally)| tally).collect();
        assert_eq!(tallies[0].answered, 0);
        assert_eq!(tallies[0].failed, 1);
        assert_eq!(tallies[0].average_ms(), None);
        assert_eq!(tallies[1].answered, 1);
        assert_eq!(tallies[1].failed, 0);
        let average = tallies[1].average_ms().unwrap();
        // The dead server is tried first and is given half the 1000 ms timeout, so the exchange
        // with the second server ends at least 500 ms before the whole query does, however
        // loaded the machine is. A time that included the first try would not.
        assert!(average >= 50.0, "{average}");
        assert!(
            average < whole_query_ms - 400.0,
            "{average} in {whole_query_ms}"
        );
    }

    #[tokio::test]
    async fn a_server_that_only_times_out_counts_each_try_as_a_failure() {
        let dead = dead_udp().await;
        let upstreams = upstreams(vec![udp_url(&dead)], 400);

        let result = upstreams.query(&mut query_for("example.com.")).await;

        assert!(matches!(result, Err(UpstreamError::Timeout)));
        let (_, tally) = upstreams.tallies().next().unwrap();
        assert_eq!((tally.answered, tally.failed), (0, 2));
        assert_eq!(tally.average_ms(), None);
    }

    #[tokio::test]
    async fn waiting_for_a_free_slot_is_not_part_of_the_response_time() {
        let server = fake_udp(|request| {
            vec![(
                Duration::from_millis(200),
                answer(request, ANSWER_MARKER, false),
            )]
        })
        .await;
        let config = UpstreamConfig {
            servers: vec![udp_url(&server)],
            timeout_ms: 2000,
            ..UpstreamConfig::default()
        };
        let limits = LimitsConfig {
            upstream_concurrency: 1,
            ..LimitsConfig::default()
        };
        let upstreams = Arc::new(Upstreams::from_config(&config, &limits).unwrap());

        let started = Instant::now();
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let upstreams = Arc::clone(&upstreams);
            tasks.push(tokio::spawn(async move {
                upstreams.query(&mut query_for("example.com.")).await
            }));
        }

        for task in tasks {
            task.await.unwrap().unwrap();
        }

        let both_done_after = started.elapsed();

        let (_, tally) = upstreams.tallies().next().unwrap();
        assert_eq!(tally.answered, 2);
        assert!(tally.average_ms().unwrap() >= 200.0);
        // The second query waits for the first. With that wait counted, the two times would add
        // up to 1.5 times the whole run; left out, they add up to less than the whole run.
        assert!(
            u128::from(tally.answer_micros) * 5 < both_done_after.as_micros() * 6,
            "{tally:?} against {both_done_after:?}"
        );
    }

    #[tokio::test]
    async fn a_reply_the_budget_cannot_hold_counts_as_a_failure_without_blaming_the_server() {
        let udp = good_udp().await;
        let over_udp = upstreams(vec![udp_url(&udp)], 1000);

        let result = over_udp
            .query_charged(&mut query_for("example.com."), &Budget::new(10))
            .await;

        assert!(matches!(result, Err(UpstreamError::BudgetExhausted)));
        let (_, tally) = over_udp.tallies().next().unwrap();
        assert_eq!((tally.answered, tally.failed), (0, 1));
        assert_eq!(over_udp.servers[0].health.lock().unwrap().failures, 0);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve_tcp(listener, Arc::new(AtomicUsize::new(0)), None));
        let over_tcp = upstreams(vec![format!("tcp://{address}")], 1000);

        let fits = over_tcp
            .query_charged(&mut query_for("example.com."), &Budget::new(10_000))
            .await;
        drop(fits);
        let result = over_tcp
            .query_charged(&mut query_for("example.com."), &Budget::new(10))
            .await;

        assert!(matches!(result, Err(UpstreamError::BudgetExhausted)));
        let (_, tally) = over_tcp.tallies().next().unwrap();
        assert_eq!((tally.answered, tally.failed), (1, 1));
        assert_eq!(over_tcp.servers[0].health.lock().unwrap().failures, 0);
    }

    #[test]
    fn fresh_servers_list_their_labels_in_config_order_with_nothing_counted() {
        let upstreams = upstreams(
            vec![
                "udp://192.0.2.1:53".to_string(),
                "tcp://192.0.2.2:53".to_string(),
            ],
            1000,
        );

        let listed: Vec<(&str, Tally)> = upstreams.tallies().collect();

        assert_eq!(
            listed,
            vec![
                ("udp://192.0.2.1:53", Tally::default()),
                ("tcp://192.0.2.2:53", Tally::default()),
            ]
        );
    }

    #[tokio::test]
    async fn tcp_upstream_reconnects_after_the_server_closes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        tokio::spawn(serve_tcp(listener, Arc::clone(&accepted), Some(2)));
        let upstreams = upstreams(vec![format!("tcp://{address}")], 1000);

        for _ in 0..5 {
            let reply = upstreams
                .query(&mut query_for("example.com."))
                .await
                .unwrap();

            assert_eq!(address_of(&reply), ANSWER_MARKER);
        }

        assert!(accepted.load(Ordering::SeqCst) >= 3);
    }

    #[tokio::test]
    async fn a_refused_tcp_connection_is_an_error() {
        let free_port = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap()
        };

        let upstreams = upstreams(vec![format!("tcp://{free_port}")], 300);

        let result = upstreams.query(&mut query_for("example.com.")).await;

        assert!(matches!(result, Err(UpstreamError::Io(_))));
    }

    #[tokio::test]
    async fn concurrent_requests_per_server_are_capped() {
        let current = Arc::new(AtomicUsize::new(0));
        let highest = Arc::new(AtomicUsize::new(0));
        let (seen_current, seen_highest) = (Arc::clone(&current), Arc::clone(&highest));
        let server = fake_udp(move |request| {
            let now = seen_current.fetch_add(1, Ordering::SeqCst) + 1;
            seen_highest.fetch_max(now, Ordering::SeqCst);
            let current = Arc::clone(&seen_current);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(60)).await;
                current.fetch_sub(1, Ordering::SeqCst);
            });

            vec![(
                Duration::from_millis(60),
                answer(request, ANSWER_MARKER, false),
            )]
        })
        .await;
        let config = UpstreamConfig {
            servers: vec![udp_url(&server)],
            timeout_ms: 2000,
            ..UpstreamConfig::default()
        };
        let limits = LimitsConfig {
            upstream_concurrency: 2,
            ..LimitsConfig::default()
        };
        let upstreams = Arc::new(Upstreams::from_config(&config, &limits).unwrap());

        let mut tasks = Vec::new();
        for _ in 0..6 {
            let upstreams = Arc::clone(&upstreams);
            tasks.push(tokio::spawn(async move {
                upstreams.query(&mut query_for("example.com.")).await
            }));
        }

        for task in tasks {
            task.await.unwrap().unwrap();
        }

        assert!(highest.load(Ordering::SeqCst) <= 2);
    }

    fn two_dummy_servers() -> Upstreams {
        upstreams(
            vec![
                "udp://192.0.2.1:53".to_string(),
                "udp://192.0.2.2:53".to_string(),
            ],
            1000,
        )
    }

    #[tokio::test]
    async fn faster_servers_get_more_of_the_rolls() {
        let upstreams = two_dummy_servers();
        upstreams.servers[0].health.lock().unwrap().srtt_ms = 10.0;
        upstreams.servers[1].health.lock().unwrap().srtt_ms = 30.0;

        // Weights 1/10 and 1/30: the first server owns the first 75% of rolls.
        assert_eq!(upstreams.pick(None, 0.0), 0);
        assert_eq!(upstreams.pick(None, 0.74), 0);
        assert_eq!(upstreams.pick(None, 0.76), 1);
        assert_eq!(upstreams.pick(None, 0.999), 1);
    }

    #[tokio::test]
    async fn backing_off_and_avoided_servers_are_not_picked() {
        let upstreams = two_dummy_servers();
        upstreams.servers[0].health.lock().unwrap().retry_at =
            Some(Instant::now() + Duration::from_secs(30));

        assert_eq!(upstreams.pick(None, 0.0), 1);
        assert_eq!(upstreams.pick(None, 0.99), 1);
        assert_eq!(
            upstreams.pick(Some(1), 0.0),
            0,
            "avoiding the only healthy one"
        );
    }

    #[tokio::test]
    async fn when_every_server_backs_off_the_soonest_is_tried() {
        let upstreams = two_dummy_servers();
        let now = Instant::now();
        upstreams.servers[0].health.lock().unwrap().retry_at = Some(now + Duration::from_secs(30));
        upstreams.servers[1].health.lock().unwrap().retry_at = Some(now + Duration::from_secs(5));

        assert_eq!(upstreams.pick(None, 0.0), 1);
    }

    #[tokio::test]
    async fn a_single_server_is_used_even_when_avoided() {
        let upstreams = upstreams(vec!["udp://192.0.2.1:53".to_string()], 1000);

        assert_eq!(upstreams.pick(Some(0), 0.5), 0);
    }

    #[tokio::test]
    async fn failures_back_off_exponentially_and_success_clears_it() {
        let upstreams = upstreams(vec!["udp://192.0.2.1:53".to_string()], 1000);
        let server = &upstreams.servers[0];

        server.record_failure(&UpstreamError::Timeout);
        let first = server.health.lock().unwrap().retry_at.unwrap();
        server.record_failure(&UpstreamError::Timeout);
        let second = server.health.lock().unwrap().retry_at.unwrap();
        for _ in 0..20 {
            server.record_failure(&UpstreamError::Timeout);
        }

        let capped = server.health.lock().unwrap().retry_at.unwrap();

        assert!(second > first + Duration::from_millis(500));
        assert!(capped <= Instant::now() + MAX_BACKOFF);
        server.record_success(Duration::from_millis(5));
        let health = server.health.lock().unwrap();
        assert_eq!(health.failures, 0);
        assert!(health.retry_at.is_none());
    }

    fn parse(spec: &str, bootstrap: &[&str]) -> Result<Transport, String> {
        let tls = Arc::new(Tls::with_webpki_roots());
        let limits = LimitsConfig::default();
        let bootstrap: Vec<IpAddr> = bootstrap.iter().map(|ip| ip.parse().unwrap()).collect();
        let bootstrap = Arc::new(Bootstrap::new(&bootstrap));
        let context = Context {
            limits: &limits,
            timeout: Duration::from_secs(1),
            tls: &tls,
            bootstrap: &bootstrap,
        };

        parse_server(spec, &context)
    }

    #[test]
    fn server_urls_parse_with_default_ports() {
        let udp = parse("udp://9.9.9.10", &[]);
        let v6 = parse("udp://[::1]:5353", &[]);
        let tcp = parse("tcp://192.168.1.1:5300", &[]);

        assert!(
            matches!(udp, Ok(Transport::Udp(ref u)) if u.server == "9.9.9.10:53".parse().unwrap())
        );
        assert!(
            matches!(v6, Ok(Transport::Udp(ref u)) if u.server == "[::1]:5353".parse().unwrap())
        );
        assert!(
            matches!(tcp, Ok(Transport::Tcp(ref t)) if matches!(t.dial, Dial::Plain(server) if server == "192.168.1.1:5300".parse().unwrap()))
        );
    }

    #[test]
    fn encrypted_urls_map_to_dot_and_doh_transports() {
        let doh_ip = parse("https://1.1.1.1/dns-query", &[]);
        let doh_host = parse("https://dns.example/dns-query", &["9.9.9.9"]);
        let dot_ip = parse("tls://1.1.1.1#cloudflare-dns.com", &[]);
        let dot_host = parse("tls://dns.quad9.net", &["9.9.9.9"]);

        assert!(matches!(doh_ip, Ok(Transport::Doh(_))));
        assert!(matches!(doh_host, Ok(Transport::Doh(_))));
        assert!(matches!(
            dot_ip,
            Ok(Transport::Dot(StreamUpstream {
                dial: Dial::Tls(_),
                ..
            }))
        ));
        assert!(matches!(dot_host, Ok(Transport::Dot(_))));
    }

    #[test]
    fn bad_server_urls_are_errors() {
        let hostname = parse("udp://dns.example", &[]).err().unwrap();
        let no_bootstrap = parse("https://dns.example/dns-query", &[]).err().unwrap();
        let no_bootstrap_dot = parse("tls://dns.example", &[]).err().unwrap();
        let bad_name = parse("tls://1.1.1.1#not a name", &[]).err().unwrap();

        assert!(hostname.contains("IP address"), "{hostname}");
        assert!(
            no_bootstrap.contains("upstream.bootstrap"),
            "{no_bootstrap}"
        );
        assert!(no_bootstrap_dot.contains("upstream.bootstrap"));
        assert!(bad_name.contains("server name"), "{bad_name}");
    }

    #[test]
    fn the_default_config_builds_four_doh_upstreams_without_a_bootstrap() {
        let upstreams =
            Upstreams::from_config(&UpstreamConfig::default(), &LimitsConfig::default()).unwrap();

        assert_eq!(upstreams.servers.len(), 4);
        assert!(
            upstreams
                .servers
                .iter()
                .all(|server| matches!(server.transport, Transport::Doh(_)))
        );
    }

    async fn dot_echo_server(pki: &TestPki) -> TlsServer {
        let config = pki.server_config(&["dot"], rustls::crypto::ring::default_provider());

        TlsServer::start(config, |mut stream| async move {
            loop {
                let mut length = [0u8; 2];
                if stream.read_exact(&mut length).await.is_err() {
                    break;
                }

                let mut query = vec![0; usize::from(u16::from_be_bytes(length))];
                if stream.read_exact(&mut query).await.is_err() {
                    break;
                }

                let reply = answer(&query, ANSWER_MARKER, false);
                let mut frame = (reply.len() as u16).to_be_bytes().to_vec();
                frame.extend_from_slice(&reply);
                if stream.write_all(&frame).await.is_err() {
                    break;
                }
            }
        })
        .await
    }

    /// Queries `spec` through a full `Upstreams`, trusting the test CA and
    /// resolving host names through `dns`.
    async fn query_encrypted(pki: &TestPki, dns: &FakeDns, spec: String) -> Vec<u8> {
        let config = UpstreamConfig {
            servers: vec![spec],
            timeout_ms: 3000,
            ..UpstreamConfig::default()
        };
        let tls = Arc::new(Tls::with_roots(pki.roots(), true));
        let bootstrap = Arc::new(Bootstrap::at(vec![dns.address]));
        let upstreams =
            Upstreams::with_parts(&config, &LimitsConfig::default(), tls, bootstrap).unwrap();

        upstreams
            .query(&mut query_for("example.com."))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn doh_urls_with_an_ip_or_a_bootstrapped_host_name_answer() {
        let pki = TestPki::new();
        let dns = fake_dns(vec![std::net::Ipv4Addr::LOCALHOST], Vec::new()).await;
        let server = doh_server(&pki, |_, body| respond_with_answer(body)).await;
        let port = server.address.port();

        let by_ip =
            query_encrypted(&pki, &dns, format!("https://127.0.0.1:{port}/dns-query")).await;
        let by_name =
            query_encrypted(&pki, &dns, format!("https://localhost:{port}/dns-query")).await;

        assert_eq!(address_of(&by_ip), ANSWER_MARKER);
        assert_eq!(address_of(&by_name), ANSWER_MARKER);
        assert_eq!(
            dns.queries.load(Ordering::SeqCst),
            2,
            "only the host name was resolved"
        );
    }

    #[tokio::test]
    async fn dot_urls_with_an_ip_a_server_name_or_a_bootstrapped_host_answer() {
        let pki = TestPki::new();
        let dns = fake_dns(vec![std::net::Ipv4Addr::LOCALHOST], Vec::new()).await;
        let server = dot_echo_server(&pki).await;
        let port = server.address.port();

        let by_ip = query_encrypted(&pki, &dns, format!("tls://127.0.0.1:{port}")).await;
        let named = query_encrypted(&pki, &dns, format!("tls://127.0.0.1:{port}#localhost")).await;
        let by_name = query_encrypted(&pki, &dns, format!("tls://localhost:{port}")).await;

        assert_eq!(address_of(&by_ip), ANSWER_MARKER);
        assert_eq!(address_of(&named), ANSWER_MARKER);
        assert_eq!(address_of(&by_name), ANSWER_MARKER);
        assert_eq!(dns.queries.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_certificate_for_another_name_is_refused() {
        let pki = TestPki::new();
        let server = dot_echo_server(&pki).await;
        let config = UpstreamConfig {
            servers: vec![format!(
                "tls://127.0.0.1:{}#other.example",
                server.address.port()
            )],
            timeout_ms: 1000,
            ..UpstreamConfig::default()
        };
        let tls = Arc::new(Tls::with_roots(pki.roots(), true));
        let bootstrap = Arc::new(Bootstrap::at(Vec::new()));
        let upstreams =
            Upstreams::with_parts(&config, &LimitsConfig::default(), tls, bootstrap).unwrap();

        let result = upstreams.query(&mut query_for("example.com.")).await;

        assert!(result.is_err());
    }

    #[test]
    fn answers_are_matched_on_id_flags_and_question() {
        let query = query_for("Example.com.");
        let good = answer(&query, ANSWER_MARKER, false);
        let mut not_a_response = good.clone();
        not_a_response[2] &= 0x7F;
        let mut wrong_id = good.clone();
        wrong_id[1] ^= 1;
        let lowercased = {
            let mut reply = good.clone();
            reply[13..20].make_ascii_lowercase();
            reply
        };

        let other_name = answer(&query_for("other.com."), ANSWER_MARKER, false);

        assert!(is_answer_to(&query, &good));
        assert!(is_answer_to(&query, &lowercased));
        assert!(!is_answer_to(&query, &not_a_response));
        assert!(!is_answer_to(&query, &wrong_id));
        assert!(!is_answer_to(&query, &other_name));
        assert!(!is_answer_to(&query, &good[..10]));
    }

    #[test]
    fn the_question_type_and_class_must_match_exactly() {
        let query = query_for("example.com.");
        let name_end = wire::skip_name(&query, wire::HEADER_LEN).unwrap();
        let good = answer(&query, ANSWER_MARKER, false);
        // Types 65 (0x41) and 97 (0x61) differ only in an ASCII case bit.
        let mut other_type = good.clone();
        other_type[name_end + 1] = 33;
        let mut other_class = good.clone();
        other_class[name_end + 3] = 3;
        let mut asked_65 = query.clone();
        asked_65[name_end + 1] = 0x41;
        let mut replied_97 = answer(&asked_65, ANSWER_MARKER, false);
        replied_97[name_end + 1] = 0x61;
        let mut other_opcode = good.clone();
        other_opcode[2] |= 0x08;

        assert!(!is_answer_to(&query, &other_type));
        assert!(!is_answer_to(&query, &other_class));
        assert!(is_answer_to(
            &asked_65,
            &answer(&asked_65, ANSWER_MARKER, false)
        ));
        assert!(!is_answer_to(&asked_65, &replied_97));
        assert!(!is_answer_to(&query, &other_opcode));
    }

    fn small_reply_limit() -> LimitsConfig {
        LimitsConfig {
            upstream_reply_max: 30,
            ..LimitsConfig::default()
        }
    }

    #[tokio::test]
    async fn a_udp_answer_over_the_reply_limit_is_an_error() {
        let server = good_udp().await;
        let config = UpstreamConfig {
            servers: vec![udp_url(&server)],
            timeout_ms: 1000,
            ..UpstreamConfig::default()
        };
        let upstreams = Upstreams::from_config(&config, &small_reply_limit()).unwrap();

        let result = upstreams.query(&mut query_for("example.com.")).await;

        assert!(
            matches!(result, Err(UpstreamError::ReplyTooLarge)),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn a_tcp_answer_over_the_reply_limit_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve_tcp(listener, Arc::new(AtomicUsize::new(0)), None));
        let config = UpstreamConfig {
            servers: vec![format!("tcp://{address}")],
            timeout_ms: 1000,
            ..UpstreamConfig::default()
        };
        let upstreams = Upstreams::from_config(&config, &small_reply_limit()).unwrap();

        let result = upstreams.query(&mut query_for("example.com.")).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn queries_waiting_behind_a_connect_keep_their_own_deadlines() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve_tcp(listener, Arc::new(AtomicUsize::new(0)), None));
        let upstreams = Arc::new(upstreams(vec![format!("tcp://{address}")], 5000));
        let connecting = {
            let upstreams = Arc::clone(&upstreams);
            tokio::spawn(async move {
                let Transport::Tcp(tcp) = &upstreams.servers[0].transport else {
                    unreachable!();
                };

                let _held = tcp.connect_lock.lock().await;
                tokio::time::sleep(Duration::from_millis(300)).await;
            })
        };

        tokio::task::yield_now().await;
        let started = Instant::now();

        let impatient = {
            let upstreams = Arc::clone(&upstreams);
            tokio::spawn(async move {
                upstreams.servers[0]
                    .query(
                        &mut query_for("a.example."),
                        &Budget::new(usize::MAX),
                        Instant::now() + Duration::from_millis(80),
                    )
                    .await
            })
        };

        let patient = {
            let upstreams = Arc::clone(&upstreams);
            tokio::spawn(async move {
                upstreams.servers[0]
                    .query(
                        &mut query_for("b.example."),
                        &Budget::new(usize::MAX),
                        Instant::now() + Duration::from_secs(3),
                    )
                    .await
            })
        };

        let impatient = impatient.await.unwrap();
        let impatient_took = started.elapsed();
        let patient = patient.await.unwrap();

        assert!(matches!(impatient, Err(UpstreamError::Timeout)));
        assert!(
            impatient_took < Duration::from_millis(250),
            "{impatient_took:?}"
        );
        assert!(patient.is_ok());
        connecting.await.unwrap();
    }
}
