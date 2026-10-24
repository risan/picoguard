//! Forwarding to upstream resolvers: one transport per server, picked by
//! speed, with one retry on the next best server.

pub mod stream;
pub mod tls;
mod udp;

#[cfg(test)]
mod test_tls;

use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::BuildHasher;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout_at};

use crate::config::{LimitsConfig, UpstreamConfig};
use crate::dns::wire::{self, Header, flags};

use stream::StreamClient;

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

struct TcpUpstream {
    server: SocketAddr,
    client: StreamClient,
    connect_lock: tokio::sync::Mutex<()>,
}

impl TcpUpstream {
    fn new(server: SocketAddr, limits: &LimitsConfig, timeout: Duration) -> TcpUpstream {
        TcpUpstream {
            server,
            client: StreamClient::new(limits.upstream_reply_max, timeout),
            connect_lock: tokio::sync::Mutex::new(()),
        }
    }

    async fn query(&self, request: &mut [u8], deadline: Instant) -> Result<Vec<u8>, UpstreamError> {
        self.ensure_connected(deadline).await?;

        let reply = self.client.query(request, deadline).await?;
        if !is_answer_to(request, &reply) {
            return Err(UpstreamError::BadReply);
        }

        Ok(reply)
    }

    async fn ensure_connected(&self, deadline: Instant) -> Result<(), UpstreamError> {
        let Ok(_serialize_connects) = timeout_at(deadline, self.connect_lock.lock()).await else {
            return Err(UpstreamError::Timeout);
        };
        if self.client.is_connected() {
            return Ok(());
        }

        let Ok(connected) = timeout_at(deadline, TcpStream::connect(self.server)).await else {
            return Err(UpstreamError::Timeout);
        };
        let stream = connected?;
        stream.set_nodelay(true)?;
        self.client.attach(stream);

        Ok(())
    }
}

/// UDP with a fall back to TCP on the same address for truncated answers.
struct UdpUpstream {
    server: SocketAddr,
    max_reply: usize,
    tcp: TcpUpstream,
}

/// How to reach one upstream server. DoH and DoT join in a later phase.
enum Transport {
    Udp(UdpUpstream),
    Tcp(TcpUpstream),
}

impl Transport {
    async fn query(&self, request: &mut [u8], deadline: Instant) -> Result<Vec<u8>, UpstreamError> {
        match self {
            Transport::Udp(upstream) => {
                let reply =
                    udp::exchange(upstream.server, request, upstream.max_reply, deadline).await?;
                let truncated = Header::parse(&reply).is_ok_and(|header| header.truncated());
                if truncated {
                    return upstream.tcp.query(request, deadline).await;
                }

                Ok(reply)
            }

            Transport::Tcp(upstream) => upstream.query(request, deadline).await,
        }
    }
}

struct Health {
    srtt_ms: f64,
    failures: u32,
    retry_at: Option<Instant>,
}

struct Upstream {
    label: String,
    transport: Transport,
    /// Caps the requests in flight to this server.
    limiter: Semaphore,
    health: Mutex<Health>,
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
            }),
        }
    }

    async fn query(&self, request: &mut [u8], deadline: Instant) -> Result<Vec<u8>, UpstreamError> {
        let started = Instant::now();
        let result = self.send(request, deadline).await;

        match &result {
            Ok(_) => {
                self.record_success(started.elapsed());
            }

            Err(error) => {
                self.record_failure(error);
            }
        }

        result
    }

    async fn send(&self, request: &mut [u8], deadline: Instant) -> Result<Vec<u8>, UpstreamError> {
        let Ok(acquired) = timeout_at(deadline, self.limiter.acquire()).await else {
            return Err(UpstreamError::Timeout);
        };
        let _permit = acquired.map_err(|_| UpstreamError::Closed)?;

        let Ok(result) = timeout_at(deadline, self.transport.query(request, deadline)).await else {
            return Err(UpstreamError::Timeout);
        };

        result
    }

    fn record_success(&self, elapsed: Duration) {
        let mut health = self.health.lock().unwrap();
        let sample = elapsed.as_secs_f64() * 1000.0;
        health.srtt_ms =
            health.srtt_ms * (1.0 - SRTT_WEIGHT_OF_NEW_SAMPLE) + sample * SRTT_WEIGHT_OF_NEW_SAMPLE;
        health.failures = 0;
        health.retry_at = None;
    }

    fn record_failure(&self, error: &UpstreamError) {
        let mut health = self.health.lock().unwrap();
        if health.failures == 0 {
            log::warn!("upstream {} failed: {error}", self.label);
        }

        health.failures += 1;
        let backoff = FIRST_BACKOFF
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
    /// Builds the servers named in the config. Only `udp://` and `tcp://` work
    /// until the encrypted transports exist.
    pub fn from_config(
        upstream: &UpstreamConfig,
        limits: &LimitsConfig,
    ) -> Result<Upstreams, String> {
        let timeout = Duration::from_millis(upstream.timeout_ms);
        let mut servers = Vec::new();

        for spec in &upstream.servers {
            let transport = parse_server(spec, limits, timeout)?;
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

    /// Sends `request` to the best server and, if that fails, once more to the
    /// next best. The ID in `request` is replaced. The first try gets half of
    /// the timeout so the second still has time.
    pub async fn query(&self, request: &mut [u8]) -> Result<Vec<u8>, UpstreamError> {
        let started = Instant::now();
        let first = self.pick(None, random_unit());

        let first_attempt = self.servers[first]
            .query(request, started + self.timeout / 2)
            .await;
        if let Ok(reply) = first_attempt {
            return Ok(reply);
        }

        let second = self.pick(Some(first), random_unit());

        self.servers[second]
            .query(request, started + self.timeout)
            .await
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
        tcp: TcpUpstream::new(server, limits, timeout),
    })
}

fn parse_server(spec: &str, limits: &LimitsConfig, timeout: Duration) -> Result<Transport, String> {
    if let Some(address) = spec.strip_prefix("udp://") {
        return Ok(udp_transport(
            parse_address(spec, address)?,
            limits,
            timeout,
        ));
    }

    if let Some(address) = spec.strip_prefix("tcp://") {
        let server = parse_address(spec, address)?;

        return Ok(Transport::Tcp(TcpUpstream::new(server, limits, timeout)));
    }

    Err(format!(
        "upstream {spec}: encrypted upstreams are not supported yet, use udp:// or tcp://"
    ))
}

fn parse_address(spec: &str, address: &str) -> Result<SocketAddr, String> {
    if let Ok(server) = address.parse::<SocketAddr>() {
        return Ok(server);
    }

    address
        .parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, DEFAULT_DNS_PORT))
        .map_err(|_| format!("upstream {spec}: expected an IP address and optional port"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hickory_proto::rr::RecordType;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    use super::*;
    use crate::dns::test_util::QuerySpec;
    use crate::dns::wire::rtype;

    const ANSWER_MARKER: [u8; 4] = [192, 0, 2, 1];

    fn query_for(name: &str) -> Vec<u8> {
        QuerySpec::new(name, RecordType::A).bytes()
    }

    /// A reply to `request` with one A record, optionally with TC set.
    fn answer(request: &[u8], address: [u8; 4], truncated: bool) -> Vec<u8> {
        let question_end = wire::skip_name(request, wire::HEADER_LEN).unwrap() + 4;
        let mut reply = request[..question_end].to_vec();
        let reply_flags = 0x8180u16 | if truncated { flags::TC } else { 0 };
        reply[2..4].copy_from_slice(&reply_flags.to_be_bytes());
        reply[6..12].copy_from_slice(&[0, 1, 0, 0, 0, 0]);
        reply.extend_from_slice(&[0xC0, 0x0C]);
        reply.extend_from_slice(&rtype::A.to_be_bytes());
        reply.extend_from_slice(&[0, 1, 0, 0, 0, 60, 0, 4]);
        reply.extend_from_slice(&address);

        reply
    }

    fn address_of(reply: &[u8]) -> [u8; 4] {
        reply[reply.len() - 4..].try_into().unwrap()
    }

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
    async fn a_failed_server_is_skipped_while_it_backs_off() {
        let dead = dead_udp().await;
        let good = good_udp().await;
        let upstreams = upstreams(vec![udp_url(&dead), udp_url(&good)], 1000);

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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let udp = UdpSocket::bind(address).await.unwrap();
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

    #[test]
    fn server_urls_parse_with_default_ports() {
        let limits = LimitsConfig::default();
        let timeout = Duration::from_secs(1);

        let udp = parse_server("udp://9.9.9.10", &limits, timeout);
        let v6 = parse_server("udp://[::1]:5353", &limits, timeout);
        let tcp = parse_server("tcp://192.168.1.1:5300", &limits, timeout);

        assert!(
            matches!(udp, Ok(Transport::Udp(ref u)) if u.server == "9.9.9.10:53".parse().unwrap())
        );
        assert!(
            matches!(v6, Ok(Transport::Udp(ref u)) if u.server == "[::1]:5353".parse().unwrap())
        );
        assert!(
            matches!(tcp, Ok(Transport::Tcp(ref t)) if t.server == "192.168.1.1:5300".parse().unwrap())
        );
    }

    #[test]
    fn bad_and_encrypted_server_urls_are_errors() {
        let limits = LimitsConfig::default();
        let timeout = Duration::from_secs(1);

        let encrypted = parse_server("https://1.1.1.1/dns-query", &limits, timeout)
            .err()
            .unwrap();
        let hostname = parse_server("udp://dns.example", &limits, timeout)
            .err()
            .unwrap();

        assert!(encrypted.contains("not supported yet"), "{encrypted}");
        assert!(hostname.contains("IP address"), "{hostname}");
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
