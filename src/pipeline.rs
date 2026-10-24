//! What happens to one client query:
//!
//! 1. normalize the request and handle the special cases;
//! 2. request filtering;
//! 3. cache lookup (a hit goes straight to 6);
//! 4. coalescing: one upstream query per distinct question in flight;
//! 5. upstream;
//! 6. response filtering, always under the policy current at delivery;
//! 7. cache insert and the client reply.

use std::collections::HashMap;
use std::fmt::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::oneshot;

use crate::budget::{Budget, Charge};
use crate::cache::{Cache, CacheKey, EntryToken, Memo};
use crate::config::{Cidr, Config, is_allowed};
use crate::dns::build::{self, Protocol, Reply, ReplyParts, TtlRule};
use crate::dns::wire::{Name, Query, QueryError, ResponseInfo, rcode, rtype};
use crate::filter::engine::{BlockedAnswer, Decision, blocked_answer};
use crate::policy::{Policy, PolicyView};
use crate::stats::{Event, QueryResult, Stats, StatsSettings};
use crate::upstream::{Answered, UpstreamError, Upstreams};

/// Reverse lookups of these ranges go to the local resolver.
const PRIVATE_NETWORKS: [&str; 7] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
];
const IPV4_REVERSE_LABELS: usize = 6;
const IPV6_REVERSE_LABELS: usize = 34;
/// Longest name text the statistics see; a name with many escapes is cut.
const STATS_NAME_BYTES: usize = 256;

/// What the steps that need no waiting settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quick {
    /// A reply is in the output buffer.
    Replied,
    /// Nothing to send.
    Dropped,
    /// Steps 4 to 7 are needed: call `Pipeline::answer`.
    NeedsUpstream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Default,
    Local,
}

/// Who asked and since when, for the statistics.
#[derive(Clone, Copy)]
struct Asker {
    client: IpAddr,
    started: Instant,
}

impl Asker {
    fn new(client: IpAddr) -> Asker {
        Asker {
            client,
            started: Instant::now(),
        }
    }
}

/// A name as text in a fixed buffer, so recording a query allocates nothing.
struct NameText {
    bytes: [u8; STATS_NAME_BYTES],
    len: usize,
}

impl NameText {
    fn of(name: &Name) -> NameText {
        let mut text = NameText {
            bytes: [0; STATS_NAME_BYTES],
            len: 0,
        };
        let _ = write!(text, "{name}");

        text
    }

    fn as_str(&self) -> &str {
        // The text of a name is ASCII, so a cut never splits a character.
        std::str::from_utf8(&self.bytes[..self.len]).unwrap_or_default()
    }
}

impl fmt::Write for NameText {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let room = STATS_NAME_BYTES - self.len;
        let kept = text.len().min(room);
        self.bytes[self.len..self.len + kept].copy_from_slice(&text.as_bytes()[..kept]);
        self.len += kept;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum Failure {
    Upstream,
    Overloaded,
}

/// An upstream reply held until every waiting client has its answer.
struct Delivery {
    bytes: Vec<u8>,
    info: ResponseInfo,
    /// The cache entry made from these bytes, if they were cached.
    cached_as: Option<EntryToken>,
    /// The upstream that gave the reply. `None` for the local resolver.
    server: Option<u8>,
    _charge: Charge,
}

impl Delivery {
    fn parts(&self) -> ReplyParts<'_> {
        ReplyParts {
            bytes: &self.bytes,
            ttl_offsets: &self.info.ttl_offsets,
            opt_start: self.info.opt_start,
        }
    }
}

type Outcome = Result<Arc<Delivery>, Failure>;

/// A query that waited for everything except its decision. See `Pipeline::prepare`.
pub struct Prepared(Inner);

enum Inner {
    /// A reply no policy can change: an error, or the answer to a malformed query.
    Final(Vec<u8>),
    /// The compact query, and the upstream reply it waited for (`None`: the cache answers).
    Undecided {
        request: Vec<u8>,
        protocol: Protocol,
        asker: Asker,
        delivery: Option<Arc<Delivery>>,
    },
}

impl Prepared {
    #[cfg(test)]
    pub(crate) fn fixed(reply: Vec<u8>) -> Prepared {
        Prepared(Inner::Final(reply))
    }

    /// What the queued reply holds until it is written, for the byte limit of a queue. The
    /// upstream reply is also charged to the pending-bytes budget for as long as it is held.
    pub fn held_bytes(&self) -> usize {
        match &self.0 {
            Inner::Final(_) => 0,

            Inner::Undecided {
                request, delivery, ..
            } => match delivery {
                Some(delivery) => delivery.bytes.len(),
                None => request.len(),
            },
        }
    }
}

#[derive(Default)]
struct Inflight {
    queries: HashMap<Vec<u8>, Vec<oneshot::Sender<Outcome>>>,
    /// Clients waiting for an upstream reply, coalesced ones included.
    waiting: usize,
}

struct WaitingClient {
    pipeline: Arc<Pipeline>,
}

impl Drop for WaitingClient {
    fn drop(&mut self) {
        self.pipeline.inflight.lock().unwrap().waiting -= 1;
    }
}

pub struct Pipeline {
    udp_size: u16,
    refuse_any: bool,
    cache_min_ttl: u32,
    cache_max_ttl: u32,
    blocked_ttl: u32,
    max_inflight_queries: usize,
    max_waiting_clients: usize,
    blocked_hosts: Vec<Name>,
    local_domains: Vec<Name>,
    private_networks: Vec<Cidr>,
    upstreams: Arc<Upstreams>,
    local_resolver: Option<Upstreams>,
    cache: Mutex<Cache>,
    inflight: Mutex<Inflight>,
    policy: Arc<Policy>,
    budget: Arc<Budget>,
    stats: Arc<Stats>,
}

impl Pipeline {
    pub fn new(config: &Config, policy: Arc<Policy>) -> Result<Arc<Pipeline>, String> {
        let upstreams = Arc::new(Upstreams::from_config(&config.upstream, &config.limits)?);
        let local_resolver = config
            .local
            .resolver
            .map(|resolver| Upstreams::plain(resolver, &config.upstream, &config.limits));

        Ok(Arc::new(Pipeline {
            udp_size: config.server.udp_size,
            refuse_any: config.refuse_any,
            cache_min_ttl: config.cache.min_ttl,
            cache_max_ttl: config.cache.max_ttl,
            blocked_ttl: config.blocked_ttl,
            max_inflight_queries: config.limits.max_inflight_queries,
            max_waiting_clients: config.limits.max_waiting_clients,
            blocked_hosts: parse_names("blocked_hosts", &config.blocked_hosts)?,
            local_domains: parse_names("local.domains", &config.local.domains)?,
            private_networks: PRIVATE_NETWORKS
                .iter()
                .map(|network| network.parse().expect("private network is valid"))
                .collect(),
            upstreams,
            local_resolver,
            cache: Mutex::new(Cache::new(&config.cache)),
            inflight: Mutex::new(Inflight::default()),
            policy,
            budget: Budget::new(config.limits.pending_bytes),
            stats: Arc::new(Stats::new(StatsSettings {
                top_k: config.stats.top_k,
                query_log_entries: config.stats.query_log_entries,
            })),
        }))
    }

    /// What the pipeline records about the queries it answers.
    pub fn stats(&self) -> &Arc<Stats> {
        &self.stats
    }

    /// The upstream pool, shared with the list downloader, which resolves list hosts through
    /// it.
    pub fn upstreams(&self) -> &Arc<Upstreams> {
        &self.upstreams
    }

    /// The budget for replies held for delivery. Queued TCP replies draw on it.
    pub fn budget(&self) -> &Arc<Budget> {
        &self.budget
    }

    /// Steps 1 to 3 and 6: everything that needs no waiting. A cache hit is
    /// answered here, so a UDP listener can reply without spawning a task.
    pub fn answer_quickly(
        &self,
        request: &[u8],
        protocol: Protocol,
        client: IpAddr,
        out: &mut Vec<u8>,
    ) -> Quick {
        self.quickly(request, protocol, Some(&Asker::new(client)), out)
    }

    /// `answer_quickly`, recording the query only when `asker` is given: a reply that waits
    /// for its decision is recorded when it is decided.
    fn quickly(
        &self,
        request: &[u8],
        protocol: Protocol,
        asker: Option<&Asker>,
        out: &mut Vec<u8>,
    ) -> Quick {
        self.try_answer_quickly(request, protocol, asker, out)
            .unwrap_or_else(|quick| quick)
    }

    /// The whole pipeline for one request. Returns false when there is
    /// nothing to send. UDP overload drops the query, TCP overload answers
    /// SERVFAIL.
    pub async fn answer(
        self: &Arc<Pipeline>,
        request: Vec<u8>,
        protocol: Protocol,
        client: IpAddr,
        out: &mut Vec<u8>,
    ) -> bool {
        match self.prepare(request, protocol, client).await {
            Some(prepared) => self.finish(&prepared, out),
            None => false,
        }
    }

    /// Steps 1 to 5: everything up to the decision. A stream reply may wait in a queue
    /// behind a slow client, so its decision is left to `finish`, called when the reply is
    /// about to be written (D20). `None` means there is nothing to send.
    ///
    /// Before waiting, the request is replaced by a compact copy of what the reply needs
    /// (see `build::compact_query`), so a padded query does not stay in memory while the
    /// upstream is slow.
    pub async fn prepare(
        self: &Arc<Pipeline>,
        request: Vec<u8>,
        protocol: Protocol,
        client: IpAddr,
    ) -> Option<Prepared> {
        let asker = Asker::new(client);
        let mut out = Vec::new();
        let quick = self.quickly(&request, protocol, None, &mut out);
        if quick == Quick::Dropped {
            return None;
        }

        let Ok(parsed) = Query::parse(&request) else {
            // A malformed query: the header-only reply does not depend on any policy.
            return Some(Prepared(Inner::Final(out)));
        };
        let compact = build::compact_query(&parsed);
        drop(request);
        if quick == Quick::Replied {
            return Some(Prepared(Inner::Undecided {
                request: compact,
                protocol,
                asker,
                delivery: None,
            }));
        }

        let query = Query::parse(&compact).ok()?;
        let Ok((_waiting, receiver)) = self.join_or_start(&query) else {
            return self.overloaded(&query, protocol, &asker, out);
        };

        match receiver.await {
            Ok(Ok(delivery)) => Some(Prepared(Inner::Undecided {
                request: compact,
                protocol,
                asker,
                delivery: Some(delivery),
            })),

            Ok(Err(Failure::Overloaded)) => self.overloaded(&query, protocol, &asker, out),

            _ => {
                Reply::new(&query, self.udp_size, protocol).error(rcode::SERVFAIL, &mut out);
                self.record(&asker, &query, QueryResult::Error, None);

                Some(Prepared(Inner::Final(out)))
            }
        }
    }

    /// Steps 2 and 6 under the policy of this moment, and the reply in `out`. Returns false
    /// when there is nothing to send.
    pub fn finish(&self, prepared: &Prepared, out: &mut Vec<u8>) -> bool {
        match &prepared.0 {
            Inner::Final(bytes) => {
                out.clear();
                out.extend_from_slice(bytes);

                true
            }

            Inner::Undecided {
                request,
                protocol,
                asker,
                delivery: Some(delivery),
            } => {
                let Ok(query) = Query::parse(request) else {
                    return false;
                };
                let reply = Reply::new(&query, self.udp_size, *protocol);
                self.deliver(&query, &reply, delivery, asker, out);

                true
            }

            // The cache entry may be gone by now; then there is no answer to give.
            Inner::Undecided {
                request,
                protocol,
                asker,
                delivery: None,
            } => {
                self.quickly(request, *protocol, Some(asker), out) == Quick::Replied
                    || self.servfail(request, *protocol, asker, out)
            }
        }
    }

    /// A SERVFAIL in place of `prepared`, for a reply that cannot be queued or written.
    pub fn failure_of(&self, prepared: &Prepared) -> Option<Prepared> {
        let mut out = Vec::new();

        match &prepared.0 {
            Inner::Final(bytes) => {
                out.extend_from_slice(bytes);
            }

            Inner::Undecided {
                request, protocol, ..
            } => {
                if !self.write_servfail(request, *protocol, &mut out) {
                    return None;
                }
            }
        }

        Some(Prepared(Inner::Final(out)))
    }

    fn write_servfail(&self, request: &[u8], protocol: Protocol, out: &mut Vec<u8>) -> bool {
        let Ok(query) = Query::parse(request) else {
            return false;
        };

        Reply::new(&query, self.udp_size, protocol).error(rcode::SERVFAIL, out);

        true
    }

    /// A SERVFAIL for a query that was expected to have an answer.
    fn servfail(
        &self,
        request: &[u8],
        protocol: Protocol,
        asker: &Asker,
        out: &mut Vec<u8>,
    ) -> bool {
        if let Ok(query) = Query::parse(request) {
            self.record(asker, &query, QueryResult::Error, None);
        }

        self.write_servfail(request, protocol, out)
    }

    fn record(&self, asker: &Asker, query: &Query<'_>, result: QueryResult, server: Option<u8>) {
        let name = NameText::of(&query.question.name);

        self.stats.record(&Event {
            client: asker.client,
            qname: name.as_str(),
            qtype: query.question.qtype,
            result,
            upstream: server,
            latency: asker.started.elapsed(),
        });
    }

    fn try_answer_quickly(
        &self,
        request: &[u8],
        protocol: Protocol,
        asker: Option<&Asker>,
        out: &mut Vec<u8>,
    ) -> Result<Quick, Quick> {
        let query = Query::parse(request).map_err(|error| {
            if let QueryError::Reject { header, rcode } = error {
                build::header_only(&header, rcode, out);

                return Quick::Replied;
            }

            Quick::Dropped
        })?;
        let reply = Reply::new(&query, self.udp_size, protocol);
        let name = &query.question.name;
        let record = |result| {
            if let Some(asker) = asker {
                self.record(asker, &query, result, None);
            }
        };

        if self.blocked_hosts.contains(name) {
            reply.error(rcode::REFUSED, out);
            record(QueryResult::BlockedRequest);

            return Ok(Quick::Replied);
        }

        if self.refuse_any && query.question.qtype == rtype::ANY {
            reply.error(rcode::NOTIMP, out);
            record(QueryResult::BlockedRequest);

            return Ok(Quick::Replied);
        }

        if self.route_of(name) == Route::Local && self.local_resolver.is_none() {
            reply.error(rcode::NXDOMAIN, out);
            record(QueryResult::Error);

            return Ok(Quick::Replied);
        }

        let now = Instant::now();
        let view = self.policy.view(now);
        if let Decision::Block { ips } = view.check_request(&query) {
            self.write_blocked(&reply, query.question.qtype, &ips, out);
            record(QueryResult::BlockedRequest);

            return Ok(Quick::Replied);
        }

        let key = CacheKey::new(&query);
        let mut cache = self.cache.lock().unwrap();
        let Some(hit) = cache.get(&key, now) else {
            return Ok(Quick::NeedsUpstream);
        };

        let token = hit.token;
        let remembered = hit
            .memo
            .filter(|memo| !view.paused && memo.generation == view.generation);
        let decision = match remembered {
            Some(memo) => memo.decision,
            None => view.check_response(hit.parts),
        };
        match &decision {
            Decision::Pass => {
                reply.from_upstream(hit.parts, self.ttl_rule(hit.age_secs), out);
                record(QueryResult::Cached);
            }

            Decision::Block { ips } => {
                self.write_blocked(&reply, query.question.qtype, ips, out);
                record(QueryResult::BlockedResponse);
            }
        }

        self.remember(&mut cache, &key, token, &view, &decision);

        Ok(Quick::Replied)
    }

    /// Steps 2 and 6 for a reply that just arrived from the upstream, under the policy of
    /// this moment: whatever was decided while the query was in flight does not count, the
    /// question included (a rule may have been added, or a pause may have ended).
    fn deliver(
        &self,
        query: &Query<'_>,
        reply: &Reply<'_, '_>,
        delivery: &Delivery,
        asker: &Asker,
        out: &mut Vec<u8>,
    ) {
        let view = self.policy.view(Instant::now());
        if let Decision::Block { ips } = view.check_request(query) {
            self.write_blocked(reply, query.question.qtype, &ips, out);
            self.record(asker, query, QueryResult::BlockedRequest, None);

            return;
        }

        let decision = view.check_response(delivery.parts());
        if let Some(token) = delivery.cached_as {
            self.remember(
                &mut self.cache.lock().unwrap(),
                &CacheKey::new(query),
                token,
                &view,
                &decision,
            );
        }

        match decision {
            Decision::Pass => {
                reply.from_upstream(delivery.parts(), self.ttl_rule(0), out);
                self.record(asker, query, QueryResult::Pass, delivery.server);
            }

            Decision::Block { ips } => {
                self.write_blocked(reply, query.question.qtype, &ips, out);
                self.record(asker, query, QueryResult::BlockedResponse, delivery.server);
            }
        }
    }

    /// Keeps the decision with the cached reply. A paused policy decides nothing, so there
    /// is nothing to keep.
    fn remember(
        &self,
        cache: &mut Cache,
        key: &CacheKey<'_>,
        token: EntryToken,
        view: &PolicyView,
        decision: &Decision,
    ) {
        if !view.paused {
            let memo = Memo {
                generation: view.generation,
                decision: decision.clone(),
            };
            cache.set_memo(key, token, memo);
        }
    }

    /// The reply AdGuard Home's default mode gives for a blocked name (plan 4.7).
    fn write_blocked(&self, reply: &Reply<'_, '_>, qtype: u16, ips: &[IpAddr], out: &mut Vec<u8>) {
        match blocked_answer(qtype, ips) {
            BlockedAnswer::Ips(addresses) => reply.addresses(&addresses, self.blocked_ttl, out),
            BlockedAnswer::Empty => reply.error(rcode::NOERROR, out),
            BlockedAnswer::NoData => reply.blocked(self.blocked_ttl, out),
            BlockedAnswer::TooMany => reply.too_big(out),
        }
    }

    fn ttl_rule(&self, age: u32) -> TtlRule {
        TtlRule {
            min: self.cache_min_ttl,
            max: self.cache_max_ttl,
            age,
        }
    }

    /// What a query gets when a limit is reached: UDP is dropped, TCP is answered SERVFAIL.
    fn overloaded(
        &self,
        query: &Query<'_>,
        protocol: Protocol,
        asker: &Asker,
        mut out: Vec<u8>,
    ) -> Option<Prepared> {
        if protocol == Protocol::Udp {
            self.stats.record_dropped();

            return None;
        }

        Reply::new(query, self.udp_size, protocol).error(rcode::SERVFAIL, &mut out);
        self.record(asker, query, QueryResult::Error, None);

        Some(Prepared(Inner::Final(out)))
    }

    fn route_of(&self, name: &Name) -> Route {
        let is_private_reverse = reverse_address(name)
            .is_some_and(|address| is_allowed(&self.private_networks, address));
        let is_local_domain = self
            .local_domains
            .iter()
            .any(|domain| name.is_subdomain_of(domain));

        if is_private_reverse || is_local_domain {
            return Route::Local;
        }

        Route::Default
    }

    /// Step 4. Joins the upstream query already running for this question or
    /// starts one. Fails when the limits on waiting clients, queries in
    /// flight or held reply bytes are reached.
    fn join_or_start(
        self: &Arc<Pipeline>,
        query: &Query<'_>,
    ) -> Result<(WaitingClient, oneshot::Receiver<Outcome>), Failure> {
        let identity = CacheKey::new(query).identity();
        let (sender, receiver) = oneshot::channel();
        let mut inflight = self.inflight.lock().unwrap();

        if inflight.waiting >= self.max_waiting_clients || self.budget.is_exhausted() {
            return Err(Failure::Overloaded);
        }

        if let Some(waiters) = inflight.queries.get_mut(&identity) {
            waiters.push(sender);
        } else {
            if inflight.queries.len() >= self.max_inflight_queries {
                return Err(Failure::Overloaded);
            }

            inflight.queries.insert(identity.clone(), vec![sender]);
            tokio::spawn(Arc::clone(self).resolve(
                identity,
                build::upstream_query(query, self.udp_size),
                self.route_of(&query.question.name),
            ));
        }

        inflight.waiting += 1;

        Ok((
            WaitingClient {
                pipeline: Arc::clone(self),
            },
            receiver,
        ))
    }

    /// Steps 5 and 7 for one question, then wakes everyone waiting for it.
    /// `request` is the normalized upstream query, the only copy of the
    /// question that is kept while waiting.
    async fn resolve(self: Arc<Pipeline>, identity: Vec<u8>, request: Vec<u8>, route: Route) {
        let outcome = self.fetch(request, route).await;
        let waiters = self
            .inflight
            .lock()
            .unwrap()
            .queries
            .remove(&identity)
            .unwrap_or_default();

        for waiter in waiters {
            let _ = waiter.send(outcome.clone());
        }
    }

    async fn fetch(&self, mut request: Vec<u8>, route: Route) -> Outcome {
        let upstreams = if route == Route::Local {
            self.local_resolver.as_ref().ok_or(Failure::Upstream)?
        } else {
            &self.upstreams
        };
        let Answered {
            reply: mut bytes,
            charge,
            server,
        } = upstreams
            .query_charged(&mut request, &self.budget)
            .await
            .map_err(|error| {
                log::debug!("upstream query failed: {error}");

                match error {
                    UpstreamError::BudgetExhausted => Failure::Overloaded,
                    _ => Failure::Upstream,
                }
            })?;
        let mut info = ResponseInfo::parse(&bytes).map_err(|_| Failure::Upstream)?;
        info.cap_soa_ttls(&mut bytes);

        let query = Query::parse(&request).map_err(|_| Failure::Upstream)?;
        let cached_as = self.cache.lock().unwrap().insert(
            &CacheKey::new(&query),
            &bytes,
            &info,
            Instant::now(),
        );

        Ok(Arc::new(Delivery {
            bytes,
            info,
            cached_as,
            server: if route == Route::Default {
                u8::try_from(server).ok()
            } else {
                None
            },
            _charge: charge,
        }))
    }
}

fn parse_names(field: &str, texts: &[String]) -> Result<Vec<Name>, String> {
    texts
        .iter()
        .map(|text| {
            Name::from_text(text)
                .ok_or_else(|| format!("{field}: {text:?} is not a valid domain name"))
        })
        .collect()
}

/// The address named by a full `in-addr.arpa` or `ip6.arpa` name.
fn reverse_address(name: &Name) -> Option<IpAddr> {
    let mut labels: [&[u8]; IPV6_REVERSE_LABELS] = [&[]; IPV6_REVERSE_LABELS];
    let mut count = 0;

    for label in name.labels() {
        if count == labels.len() {
            return None;
        }

        labels[count] = label;
        count += 1;
    }

    if count == IPV4_REVERSE_LABELS && labels[4] == b"in-addr" && labels[5] == b"arpa" {
        let octet = |label: &[u8]| std::str::from_utf8(label).ok()?.parse::<u8>().ok();

        return Some(IpAddr::V4(Ipv4Addr::new(
            octet(labels[3])?,
            octet(labels[2])?,
            octet(labels[1])?,
            octet(labels[0])?,
        )));
    }

    if count == IPV6_REVERSE_LABELS && labels[32] == b"ip6" && labels[33] == b"arpa" {
        let mut octets = [0u8; 16];

        for (index, nibble_label) in labels[..32].iter().enumerate() {
            let [character] = nibble_label else {
                return None;
            };

            let nibble = (*character as char).to_digit(16)? as u8;
            let position = 31 - index;
            octets[position / 2] |= nibble << (4 * (1 - position % 2));
        }

        return Some(IpAddr::V6(Ipv6Addr::from(octets)));
    }

    None
}

#[cfg(test)]
mod tests {
    use hickory_proto::rr::RecordType;

    use super::*;
    use crate::dns::test_util::{QuerySpec, ResponseSpec, a, parse};
    use crate::filter::engine::{CompiledList, Engine};
    use crate::filter::parse::ListFormat;

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

    fn address_of(text: &str) -> Option<IpAddr> {
        reverse_address(&Name::from_text(text).unwrap())
    }

    #[test]
    fn a_name_text_for_the_statistics_is_cut_when_escapes_make_it_long() {
        let short = NameText::of(&Name::from_text("Www.Example.COM.").unwrap());
        let mut wire = Vec::new();
        for _ in 0..3 {
            wire.push(60);
            wire.extend_from_slice(&[0xff; 60]);
        }
        wire.push(0);
        let (name, _) = crate::dns::wire::read_name(&wire, 0).unwrap();
        let long = NameText::of(&name);

        assert_eq!(short.as_str(), "www.example.com");
        assert_eq!(long.as_str().len(), STATS_NAME_BYTES);
        assert!(long.as_str().starts_with("\\255\\255"));
    }

    #[test]
    fn ipv4_reverse_names_give_the_address() {
        assert_eq!(
            address_of("4.3.2.10.in-addr.arpa."),
            Some("10.2.3.4".parse().unwrap())
        );
        assert_eq!(
            address_of("1.1.168.192.IN-ADDR.ARPA"),
            Some("192.168.1.1".parse().unwrap())
        );
    }

    fn ipv6_reverse(address: &str) -> String {
        let octets = address.parse::<Ipv6Addr>().unwrap().octets();
        let nibbles: Vec<String> = octets
            .iter()
            .rev()
            .flat_map(|octet| [octet & 0x0F, octet >> 4])
            .map(|nibble| format!("{nibble:x}"))
            .collect();

        format!("{}.ip6.arpa", nibbles.join("."))
    }

    #[test]
    fn ipv6_reverse_names_give_the_address() {
        assert_eq!(
            address_of(&ipv6_reverse("fd00::1")),
            Some("fd00::1".parse().unwrap())
        );
        assert_eq!(
            address_of(&ipv6_reverse("fe80::1234:5678")),
            Some("fe80::1234:5678".parse().unwrap())
        );
    }

    #[test]
    fn partial_and_odd_reverse_names_are_not_addresses() {
        for name in [
            "10.in-addr.arpa",
            "3.2.10.in-addr.arpa",
            "5.4.3.2.10.in-addr.arpa",
            "256.3.2.10.in-addr.arpa",
            "x.3.2.10.in-addr.arpa",
            "4.3.2.10.example.com",
            "example.com",
            "1.0.0.0.ip6.arpa",
        ] {
            assert_eq!(address_of(name), None, "{name}");
        }

        let full = ipv6_reverse("fd00::1");
        assert_eq!(address_of(&full.replacen('1', "g", 1)), None);
        assert_eq!(address_of(&full.replacen('1', "10", 1)), None);
        assert_eq!(address_of(&format!("0.{full}")), None);
    }

    fn pipeline_with_local(domains: &[&str], resolver: Option<&str>) -> Arc<Pipeline> {
        let mut config = Config::default();
        config.upstream.servers = vec!["udp://127.0.0.1:9".to_string()];
        config.local.domains = domains.iter().map(|domain| domain.to_string()).collect();
        config.local.resolver = resolver.map(|address| address.parse().unwrap());

        Pipeline::new(&config, Arc::new(Policy::new())).unwrap()
    }

    #[tokio::test]
    async fn private_reverse_names_and_local_domains_take_the_local_route() {
        let pipeline = pipeline_with_local(&["lan", "home.arpa."], Some("127.0.0.1:9"));
        let route = |text: &str| pipeline.route_of(&Name::from_text(text).unwrap());

        for local in [
            "4.3.2.10.in-addr.arpa",
            "9.0.16.172.in-addr.arpa",
            "1.1.168.192.in-addr.arpa",
            "5.0.64.100.in-addr.arpa",
            "5.0.254.169.in-addr.arpa",
            "printer.lan",
            "lan",
            "a.b.home.arpa",
        ] {
            assert_eq!(route(local), Route::Local, "{local}");
        }

        for public in [
            "4.3.2.8.in-addr.arpa",
            "1.0.32.172.in-addr.arpa",
            "5.0.128.100.in-addr.arpa",
            "example.com",
            "scan",
            "lan.example.com",
        ] {
            assert_eq!(route(public), Route::Default, "{public}");
        }
    }

    #[tokio::test]
    async fn bad_names_in_the_config_are_reported() {
        let mut config = Config::default();
        config.upstream.servers = vec!["udp://127.0.0.1:9".to_string()];
        config.blocked_hosts = vec!["a..b".to_string()];

        let error = Pipeline::new(&config, Arc::new(Policy::new()))
            .err()
            .unwrap();

        assert!(error.contains("blocked_hosts"), "{error}");
    }

    #[tokio::test]
    async fn the_default_encrypted_upstreams_build_a_pipeline() {
        let config = Config::default();

        assert!(Pipeline::new(&config, Arc::new(Policy::new())).is_ok());
    }

    fn policy_of(rules: &str) -> Arc<Policy> {
        let (list, _) = CompiledList::from_text(ListFormat::Adblock, rules);

        Arc::new(Policy::with_engine(Arc::new(Engine::new(
            vec![Arc::new(list)],
            Vec::new(),
        ))))
    }

    fn reply_with_address(spec: &QuerySpec, address: [u8; 4]) -> Vec<u8> {
        ResponseSpec {
            answers: vec![a(&spec.name, 300, address.into())],
            ..ResponseSpec::default()
        }
        .bytes(spec)
    }

    #[tokio::test]
    async fn a_delayed_waiter_cannot_leave_its_memo_on_a_replacement_entry() {
        let mut config = Config::default();
        config.upstream.servers = vec!["udp://127.0.0.1:9".to_string()];
        let pipeline = Pipeline::new(&config, policy_of("||9.9.9.9^\n")).unwrap();
        let spec = QuerySpec::new("late.example.", RecordType::A);
        let request = spec.bytes();
        let query = Query::parse(&request).unwrap();
        let key = CacheKey::new(&query);

        let old_bytes = reply_with_address(&spec, [1, 1, 1, 1]);
        let old_info = ResponseInfo::parse(&old_bytes).unwrap();
        let old_token =
            pipeline
                .cache
                .lock()
                .unwrap()
                .insert(&key, &old_bytes, &old_info, Instant::now());
        let old_delivery = Delivery {
            bytes: old_bytes,
            info: old_info,
            cached_as: old_token,
            server: None,
            _charge: pipeline.budget.try_charge(1).unwrap(),
        };

        // The entry is replaced by a reply the policy blocks before the waiter runs.
        let new_bytes = reply_with_address(&spec, [9, 9, 9, 9]);
        let new_info = ResponseInfo::parse(&new_bytes).unwrap();
        pipeline
            .cache
            .lock()
            .unwrap()
            .insert(&key, &new_bytes, &new_info, Instant::now())
            .unwrap();

        let reply = Reply::new(&query, pipeline.udp_size, Protocol::Udp);
        let mut out = Vec::new();
        pipeline.deliver(&query, &reply, &old_delivery, &Asker::new(CLIENT), &mut out);
        assert_eq!(&parse(&out).answers[0].data.to_string(), "1.1.1.1");

        let quick = pipeline.answer_quickly(&request, Protocol::Udp, CLIENT, &mut out);
        assert_eq!(quick, Quick::Replied);
        assert_eq!(&parse(&out).answers[0].data.to_string(), "0.0.0.0");
    }

    #[tokio::test]
    async fn a_blocked_decision_with_many_ips_is_recomputed_instead_of_held_in_the_cache() {
        let host_rules: String = (0..200)
            .map(|index| format!("10.0.{}.{} 9.9.9.9\n", index / 256, index % 256))
            .collect();
        let mut config = Config::default();
        config.upstream.servers = vec!["udp://127.0.0.1:9".to_string()];
        let pipeline = Pipeline::new(&config, policy_of(&host_rules)).unwrap();
        let spec = QuerySpec::new("late.example.", RecordType::A);
        let request = spec.bytes();
        let query = Query::parse(&request).unwrap();
        let bytes = reply_with_address(&spec, [9, 9, 9, 9]);
        let info = ResponseInfo::parse(&bytes).unwrap();
        let token = pipeline.cache.lock().unwrap().insert(
            &CacheKey::new(&query),
            &bytes,
            &info,
            Instant::now(),
        );
        let bytes_without_memo = pipeline.cache.lock().unwrap().bytes();
        let delivery = Delivery {
            bytes,
            info,
            cached_as: token,
            server: None,
            _charge: pipeline.budget.try_charge(1).unwrap(),
        };
        let reply = Reply::new(&query, pipeline.udp_size, Protocol::Tcp);
        let mut out = Vec::new();

        pipeline.deliver(&query, &reply, &delivery, &Asker::new(CLIENT), &mut out);
        assert_eq!(parse(&out).answers.len(), 200);
        assert_eq!(pipeline.cache.lock().unwrap().bytes(), bytes_without_memo);

        let quick = pipeline.answer_quickly(&request, Protocol::Tcp, CLIENT, &mut out);
        assert_eq!(quick, Quick::Replied);
        assert_eq!(parse(&out).answers.len(), 200);
        assert_eq!(pipeline.cache.lock().unwrap().bytes(), bytes_without_memo);
    }
}
