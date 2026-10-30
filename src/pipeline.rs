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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::budget::{Budget, Charge};
use crate::cache::{Cache, CacheKey, EntryToken, Memo};
use crate::config::{Cidr, Config, is_allowed};
use crate::dns::build::{self, Protocol, Reply, ReplyParts, TtlRule};
use crate::dns::wire::{Header, Name, Query, QueryError, ResponseInfo, flags, rcode, rtype};
use crate::filter::engine::{BlockedAnswer, Decision, Verdict, blocked_answer};
use crate::policy::{Policy, PolicyView};
use crate::stats::{Event, QueryResult, Stats, StatsSettings};
use crate::upstream::{Answered, Tally, UpstreamError, Upstreams};

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
/// The reverse zones of RFC 6303 that are served locally: a name at or under one of them is
/// answered like the reverse name of a private address, DNS-SD browse names included.
const PRIVATE_REVERSE_ZONES: [&str; 11] = [
    "10.in-addr.arpa",
    "168.192.in-addr.arpa",
    "127.in-addr.arpa",
    "254.169.in-addr.arpa",
    "d.f.ip6.arpa",
    "c.f.ip6.arpa",
    "8.e.f.ip6.arpa",
    "9.e.f.ip6.arpa",
    "a.e.f.ip6.arpa",
    "b.e.f.ip6.arpa",
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
];
const IPV4_REVERSE_LABELS: usize = 6;
const IPV6_REVERSE_LABELS: usize = 34;

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

/// What answered a query without waiting, and how it counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Settled {
    /// The configuration decides this one, whatever the policy.
    Static(QueryResult),
    Blocked(QueryResult),
    Cached(QueryResult),
}

impl Settled {
    fn result(self) -> QueryResult {
        match self {
            Settled::Static(result) | Settled::Blocked(result) | Settled::Cached(result) => result,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Counted {
    result: QueryResult,
    server: Option<u8>,
}

impl Counted {
    fn of(result: QueryResult) -> Counted {
        Counted {
            result,
            server: None,
        }
    }
}

/// What is left to do once `Pipeline::finish` has built a reply: count the query with
/// `Pipeline::count`, after the reply has been chosen for good.
#[must_use]
pub struct Finished(Option<Counted>);

#[derive(Debug, Clone, Copy)]
enum Source {
    /// A cache hit; `stale` when it was served from the optimistic window.
    Cache { stale: bool },
    /// The upstream that gave the reply. `None` for the local resolver.
    Upstream(Option<u8>),
}

impl Source {
    fn server(self) -> Option<u8> {
        match self {
            Source::Cache { .. } => None,
            Source::Upstream(server) => server,
        }
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
    /// How old the bytes were when they were received: a cache hit has been cached for a while.
    age_secs_when_received: u32,
    received: Instant,
    source: Source,
    _charge: Charge,
}

impl Delivery {
    fn new(
        bytes: Vec<u8>,
        info: ResponseInfo,
        cached_as: Option<EntryToken>,
        age_secs_when_received: u32,
        source: Source,
        charge: Charge,
    ) -> Delivery {
        Delivery {
            bytes,
            info,
            cached_as,
            age_secs_when_received,
            received: Instant::now(),
            source,
            _charge: charge,
        }
    }

    fn age_secs(&self) -> u32 {
        let waited = u32::try_from(self.received.elapsed().as_secs()).unwrap_or(u32::MAX);

        self.age_secs_when_received.saturating_add(waited)
    }

    fn is_stale(&self) -> bool {
        matches!(self.source, Source::Cache { stale: true })
    }

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
    /// The compact query, and the upstream reply it waited for or the cache hit it was
    /// answered from. `None`: a static answer, or a block; `finish` asks again if the block
    /// has ended by then.
    Undecided {
        request: Vec<u8>,
        protocol: Protocol,
        asker: Asker,
        delivery: Option<Arc<Delivery>>,
    },
    /// The compact query of a question that got no answer; `finish` writes the SERVFAIL.
    Failed {
        request: Vec<u8>,
        protocol: Protocol,
        asker: Asker,
    },
}

impl Prepared {
    #[cfg(test)]
    pub(crate) fn fixed(reply: Vec<u8>) -> Prepared {
        Prepared(Inner::Final(reply))
    }

    /// The compact query and the asker of a reply that is not final yet.
    fn asked(&self) -> Option<(&[u8], &Asker)> {
        match &self.0 {
            Inner::Final(_) => None,

            Inner::Undecided { request, asker, .. } | Inner::Failed { request, asker, .. } => {
                Some((request, asker))
            }
        }
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

            Inner::Failed { request, .. } => request.len(),
        }
    }
}

#[derive(Default)]
struct Inflight {
    queries: HashMap<Vec<u8>, Vec<oneshot::Sender<Outcome>>>,
    /// Clients waiting for an upstream reply, coalesced ones included.
    waiting: usize,
    /// Background refreshes of stale entries, each in `queries` with no waiter of its own.
    refreshing: usize,
}

struct WaitingClient {
    pipeline: Arc<Pipeline>,
}

impl Drop for WaitingClient {
    fn drop(&mut self) {
        self.pipeline.inflight.lock().unwrap().waiting -= 1;
    }
}

struct RefreshSlot {
    pipeline: Arc<Pipeline>,
}

impl Drop for RefreshSlot {
    fn drop(&mut self) {
        self.pipeline.inflight.lock().unwrap().refreshing -= 1;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerKind {
    Upstream,
    Local,
}

/// What one server has done since start, for the status page.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerTally {
    pub label: String,
    pub kind: ServerKind,
    pub tally: Tally,
}

/// How many answers the cache holds and the bytes counted against its limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CacheSize {
    pub entries: usize,
    pub bytes: usize,
}

pub struct Pipeline {
    udp_size: u16,
    resume_limit: Duration,
    refuse_any: bool,
    cache_min_ttl: u32,
    cache_max_ttl: u32,
    optimistic_answer_ttl: u32,
    blocked_ttl: u32,
    max_inflight_queries: usize,
    max_waiting_clients: usize,
    max_refreshes: usize,
    blocked_hosts: Vec<Name>,
    local_domains: Vec<Name>,
    private_reverse_zones: Vec<Name>,
    private_networks: Vec<Cidr>,
    upstreams: Arc<Upstreams>,
    local_resolver: Option<(SocketAddr, Upstreams)>,
    cache: Mutex<Cache>,
    inflight: Mutex<Inflight>,
    policy: Arc<Policy>,
    budget: Arc<Budget>,
    stats: Arc<Stats>,
}

impl Pipeline {
    pub fn new(config: &Config, policy: Arc<Policy>) -> Result<Arc<Pipeline>, String> {
        let upstreams = Arc::new(Upstreams::from_config(&config.upstream, &config.limits)?);
        let local_resolver = config.local.resolver.map(|resolver| {
            (
                resolver,
                Upstreams::plain(resolver, &config.upstream, &config.limits),
            )
        });
        // A refresh holds a question slot and, while it waits, one exchange slot of a server.
        // Refreshes take at most half of the smaller pool, so client misses keep the other
        // half; at least one may run, so a single-slot setup still refreshes.
        let refresh_slots = config
            .limits
            .max_inflight_queries
            .min(config.limits.upstream_concurrency);

        Ok(Arc::new(Pipeline {
            udp_size: config.server.udp_size,
            resume_limit: Duration::from_millis(config.upstream.timeout_ms),
            refuse_any: config.refuse_any,
            cache_min_ttl: config.cache.min_ttl,
            cache_max_ttl: config.cache.max_ttl,
            optimistic_answer_ttl: config.cache.optimistic_answer_ttl_secs,
            blocked_ttl: config.blocked_ttl,
            max_inflight_queries: config.limits.max_inflight_queries,
            max_waiting_clients: config.limits.max_waiting_clients,
            max_refreshes: (refresh_slots / 2).max(1),
            blocked_hosts: parse_names("blocked_hosts", &config.blocked_hosts)?,
            local_domains: parse_names("local.domains", &config.local.domains)?,
            private_reverse_zones: private_reverse_zones(),
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

    /// The configured servers in config order, then the local resolver when there is one.
    pub fn upstream_tallies(&self) -> Vec<ServerTally> {
        let servers = self.upstreams.tallies().map(|(label, tally)| ServerTally {
            label: label.to_string(),
            kind: ServerKind::Upstream,
            tally,
        });
        let local = self.local_resolver.iter().flat_map(|(address, resolver)| {
            resolver.tallies().map(|(_, tally)| ServerTally {
                label: address.to_string(),
                kind: ServerKind::Local,
                tally,
            })
        });

        servers.chain(local).collect()
    }

    pub fn cache_size(&self) -> CacheSize {
        let cache = self.cache.lock().unwrap();

        CacheSize {
            entries: cache.len(),
            bytes: cache.bytes(),
        }
    }

    /// Empties the cache and returns how many answers it held. Lookups in flight are not
    /// cancelled: their answers are cached when they land.
    pub fn clear_cache(&self) -> usize {
        self.cache.lock().unwrap().clear()
    }

    /// The budget for replies held for delivery. Queued TCP replies draw on it.
    pub fn budget(&self) -> &Arc<Budget> {
        &self.budget
    }

    /// Steps 1 to 3 and 6: everything that needs no waiting. A cache hit is
    /// answered here, so a UDP listener can reply without spawning a task.
    pub fn answer_quickly(
        self: &Arc<Pipeline>,
        request: &[u8],
        protocol: Protocol,
        client: IpAddr,
        out: &mut Vec<u8>,
    ) -> Quick {
        match self.settle(request, protocol, Some(&Asker::new(client)), out) {
            Ok(_) => Quick::Replied,
            Err(quick) => quick,
        }
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
        let Some(prepared) = self.prepare(request, protocol, client).await else {
            return false;
        };

        let Some(finished) = self.finish(&prepared, out).await else {
            return false;
        };

        self.count(&prepared, finished);

        true
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
        let settled = self.settle(&request, protocol, None, &mut out);
        if settled == Err(Quick::Dropped) {
            return None;
        }

        let Ok(parsed) = Query::parse(&request) else {
            // A malformed query: the header-only reply does not depend on any policy.
            return Some(Prepared(Inner::Final(out)));
        };
        let compact = build::compact_query(&parsed);
        drop(request);
        match settled {
            Ok(Settled::Cached(_)) => {
                // The entry may be gone before the reply is written, so the reply keeps its
                // own copy of the bytes, charged like an upstream reply.
                let query = Query::parse(&compact).ok()?;
                let Some(delivery) = self.hold_cache_hit(&query) else {
                    return self.shed(compact, protocol, asker);
                };

                return Some(Prepared(Inner::Undecided {
                    request: compact,
                    protocol,
                    asker,
                    delivery: Some(delivery),
                }));
            }

            Ok(Settled::Static(_) | Settled::Blocked(_)) => {
                return Some(Prepared(Inner::Undecided {
                    request: compact,
                    protocol,
                    asker,
                    delivery: None,
                }));
            }

            Err(_) => {}
        }

        let query = Query::parse(&compact).ok()?;
        let Ok((_waiting, receiver)) = self.join_or_start(&query) else {
            return self.shed(compact, protocol, asker);
        };

        match receiver.await {
            Ok(Ok(delivery)) => Some(Prepared(Inner::Undecided {
                request: compact,
                protocol,
                asker,
                delivery: Some(delivery),
            })),

            Ok(Err(Failure::Overloaded)) => self.shed(compact, protocol, asker),

            _ => Some(Prepared(Inner::Failed {
                request: compact,
                protocol,
                asker,
            })),
        }
    }

    /// Steps 2 and 6 under the policy of this moment, and the reply in `out`. A question that
    /// was blocked when it was prepared and is not any more is resolved now (steps 4 and 5),
    /// for at most the upstream timeout. Returns `None` when there is nothing to send.
    ///
    /// The query is not counted yet: the caller may still replace the reply (see `count`).
    pub async fn finish(
        self: &Arc<Pipeline>,
        prepared: &Prepared,
        out: &mut Vec<u8>,
    ) -> Option<Finished> {
        match &prepared.0 {
            Inner::Final(bytes) => {
                out.clear();
                out.extend_from_slice(bytes);

                Some(Finished(None))
            }

            Inner::Undecided {
                request,
                protocol,
                delivery: Some(delivery),
                ..
            } => {
                let query = Query::parse(request).ok()?;
                let reply = Reply::new(&query, self.udp_size, *protocol);

                Some(Finished(Some(self.deliver(&query, &reply, delivery, out))))
            }

            Inner::Undecided {
                request,
                protocol,
                delivery: None,
                ..
            } => match self.settle(request, *protocol, None, out) {
                Ok(settled) => Some(Finished(Some(Counted::of(settled.result())))),
                Err(Quick::Replied) => Some(Finished(None)),
                Err(Quick::Dropped) => None,
                Err(Quick::NeedsUpstream) => self.resume(request, *protocol, out).await,
            },

            Inner::Failed {
                request, protocol, ..
            } => self
                .servfail(request, *protocol, out)
                .then_some(Finished(Some(Counted::of(QueryResult::Error)))),
        }
    }

    /// Records the query in the statistics, with the result `finish` found. Called once the
    /// reply is final: after it has been queued, framed and charged, or when a UDP reply is
    /// ready. A reply replaced by a SERVFAIL on the way is counted by `failure_of` instead.
    pub fn count(&self, prepared: &Prepared, finished: Finished) {
        let (Some(counted), Some((request, asker))) = (finished.0, prepared.asked()) else {
            return;
        };

        if let Ok(query) = Query::parse(request) {
            self.record(asker, &query, counted.result, counted.server);
        }
    }

    async fn resume(
        self: &Arc<Pipeline>,
        request: &[u8],
        protocol: Protocol,
        out: &mut Vec<u8>,
    ) -> Option<Finished> {
        let query = Query::parse(request).ok()?;
        let reply = Reply::new(&query, self.udp_size, protocol);
        let Ok((_waiting, receiver)) = self.join_or_start(&query) else {
            return self.shed_now(&reply, protocol, out);
        };

        match timeout(self.resume_limit, receiver).await {
            Ok(Ok(Ok(delivery))) => {
                Some(Finished(Some(self.deliver(&query, &reply, &delivery, out))))
            }

            Ok(Ok(Err(Failure::Overloaded))) => self.shed_now(&reply, protocol, out),

            _ => {
                reply.error(rcode::SERVFAIL, out);

                Some(Finished(Some(Counted::of(QueryResult::Error))))
            }
        }
    }

    /// A SERVFAIL in place of `prepared`, for a reply that cannot be queued or written. A
    /// query that was not answered yet is counted here, as the error it ends in.
    pub fn failure_of(&self, prepared: &Prepared) -> Option<Prepared> {
        let mut out = Vec::new();

        match &prepared.0 {
            Inner::Final(bytes) => {
                out.extend_from_slice(bytes);
            }

            Inner::Undecided {
                request, protocol, ..
            }
            | Inner::Failed {
                request, protocol, ..
            } => {
                if !self.servfail(request, *protocol, &mut out) {
                    return None;
                }

                self.count(prepared, Finished(Some(Counted::of(QueryResult::Error))));
            }
        }

        Some(Prepared(Inner::Final(out)))
    }

    fn servfail(&self, request: &[u8], protocol: Protocol, out: &mut Vec<u8>) -> bool {
        let Ok(query) = Query::parse(request) else {
            return false;
        };

        Reply::new(&query, self.udp_size, protocol).error(rcode::SERVFAIL, out);

        true
    }

    fn record(&self, asker: &Asker, query: &Query<'_>, result: QueryResult, server: Option<u8>) {
        self.stats.record(&Event {
            client: asker.client,
            qname: &query.question.name,
            qtype: query.question.qtype,
            result,
            upstream: server,
            latency: asker.started.elapsed(),
        });
    }

    /// Steps 1 to 3 and 6. `Err` says what is left to do: nothing (`Replied` is a
    /// header-only answer to a malformed query), or the upstream. The query is recorded
    /// when `asker` is given. A stale cache hit is answered and starts a background refresh.
    fn settle(
        self: &Arc<Pipeline>,
        request: &[u8],
        protocol: Protocol,
        asker: Option<&Asker>,
        out: &mut Vec<u8>,
    ) -> Result<Settled, Quick> {
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

            result
        };

        if self.blocked_hosts.contains(name) {
            reply.error(rcode::REFUSED, out);

            return Ok(Settled::Static(record(QueryResult::BlockedRequest)));
        }

        if self.refuse_any && query.question.qtype == rtype::ANY {
            reply.error(rcode::NOTIMP, out);

            return Ok(Settled::Static(record(QueryResult::BlockedRequest)));
        }

        if self.route_of(name) == Route::Local && self.local_resolver.is_none() {
            reply.error(rcode::NXDOMAIN, out);

            return Ok(Settled::Static(record(QueryResult::Error)));
        }

        let now = Instant::now();
        let view = self.policy.view(self.policy.now());
        let request_verdict = view.check_request(&query);
        if let Verdict::Block { ips } = &request_verdict {
            self.write_blocked(&reply, query.question.qtype, ips, out);

            return Ok(Settled::Blocked(record(counted_as(
                out,
                QueryResult::BlockedRequest,
            ))));
        }

        let key = CacheKey::new(&query);
        let mut cache = self.cache.lock().unwrap();
        let Some(hit) = cache.get(&key, now) else {
            return Err(Quick::NeedsUpstream);
        };

        let token = hit.token;
        let stale = hit.stale;
        let remembered = hit
            .memo
            .filter(|memo| !view.paused && memo.generation == view.generation);
        let decision = match remembered {
            Some(memo) => memo.decision,
            None if request_verdict == Verdict::Allow => Decision::Pass,
            None => view.check_response(hit.parts),
        };
        let result = match &decision {
            Decision::Pass => {
                reply.from_upstream(hit.parts, self.ttl_rule(hit.age_secs, hit.stale), out);

                QueryResult::Cached
            }

            Decision::Block { ips } => {
                self.write_blocked(&reply, query.question.qtype, ips, out);

                QueryResult::BlockedResponse
            }
        };

        self.remember(&mut cache, &key, token, &view, &decision);
        // The inflight lock is never taken while the cache lock is held.
        drop(cache);

        if stale {
            self.refresh(&query);
        }

        Ok(Settled::Cached(record(counted_as(out, result))))
    }

    /// A copy of the cached reply to `query`, charged to the pending-bytes budget. `None`
    /// when there is no such entry or the budget cannot hold the copy.
    fn hold_cache_hit(&self, query: &Query<'_>) -> Option<Arc<Delivery>> {
        let mut cache = self.cache.lock().unwrap();
        let hit = cache.get(&CacheKey::new(query), Instant::now())?;
        let charge = self.budget.try_charge(hit.parts.bytes.len())?;
        let bytes = hit.parts.bytes.to_vec();
        let info = ResponseInfo::parse(&bytes).ok()?;

        Some(Arc::new(Delivery::new(
            bytes,
            info,
            Some(hit.token),
            hit.age_secs,
            Source::Cache { stale: hit.stale },
            charge,
        )))
    }

    /// Steps 2 and 6 for a reply that just arrived from the upstream, under the policy of
    /// this moment: whatever was decided while the query was in flight does not count, the
    /// question included (a rule may have been added, or a pause may have ended).
    fn deliver(
        &self,
        query: &Query<'_>,
        reply: &Reply<'_, '_>,
        delivery: &Delivery,
        out: &mut Vec<u8>,
    ) -> Counted {
        let view = self.policy.view(self.policy.now());
        let request_verdict = view.check_request(query);
        if let Verdict::Block { ips } = &request_verdict {
            self.write_blocked(reply, query.question.qtype, ips, out);

            return Counted::of(counted_as(out, QueryResult::BlockedRequest));
        }

        let decision = if request_verdict == Verdict::Allow {
            Decision::Pass
        } else {
            view.check_response(delivery.parts())
        };
        if let Some(token) = delivery.cached_as {
            self.remember(
                &mut self.cache.lock().unwrap(),
                &CacheKey::new(query),
                token,
                &view,
                &decision,
            );
        }

        let result = match decision {
            Decision::Pass => {
                let ttl_rule = self.ttl_rule(delivery.age_secs(), delivery.is_stale());
                reply.from_upstream(delivery.parts(), ttl_rule, out);

                match delivery.source {
                    Source::Cache { .. } => QueryResult::Cached,
                    Source::Upstream(_) => QueryResult::Pass,
                }
            }

            Decision::Block { ips } => {
                self.write_blocked(reply, query.question.qtype, &ips, out);

                QueryResult::BlockedResponse
            }
        };

        Counted {
            result: counted_as(out, result),
            server: delivery.source.server(),
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

    /// A stale answer carries the optimistic answer TTL in every record, the SOA of a
    /// negative answer included; a fresh one is clamped and aged.
    fn ttl_rule(&self, age: u32, stale: bool) -> TtlRule {
        if stale {
            return TtlRule {
                min: self.optimistic_answer_ttl,
                max: self.optimistic_answer_ttl,
                age: 0,
            };
        }

        TtlRule {
            min: self.cache_min_ttl,
            max: self.cache_max_ttl,
            age,
        }
    }

    /// A query that reaches a limit: UDP is dropped, TCP is answered SERVFAIL.
    fn shed(&self, request: Vec<u8>, protocol: Protocol, asker: Asker) -> Option<Prepared> {
        if self.drops(protocol) {
            return None;
        }

        Some(Prepared(Inner::Failed {
            request,
            protocol,
            asker,
        }))
    }

    /// `shed` for a query being finished, whose reply goes to `out`.
    fn shed_now(
        &self,
        reply: &Reply<'_, '_>,
        protocol: Protocol,
        out: &mut Vec<u8>,
    ) -> Option<Finished> {
        if self.drops(protocol) {
            return None;
        }

        reply.error(rcode::SERVFAIL, out);

        Some(Finished(Some(Counted::of(QueryResult::Error))))
    }

    fn drops(&self, protocol: Protocol) -> bool {
        if protocol != Protocol::Udp {
            return false;
        }

        self.stats.record_dropped();

        true
    }

    fn route_of(&self, name: &Name) -> Route {
        let is_private_reverse = reverse_address(name)
            .is_some_and(|address| is_allowed(&self.private_networks, address));
        let is_local_domain = self
            .local_domains
            .iter()
            .chain(&self.private_reverse_zones)
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

    /// Starts a background lookup that replaces the stale entry of `query`, unless one is in
    /// flight for the question already (its answer replaces the entry), or the refresh limit,
    /// the question slots or the pending-bytes budget are used up. A skipped refresh is tried
    /// again on the next stale hit. No client waits on it and it is not recorded.
    fn refresh(self: &Arc<Pipeline>, query: &Query<'_>) {
        let identity = CacheKey::new(query).identity();
        let mut inflight = self.inflight.lock().unwrap();

        if inflight.queries.contains_key(&identity)
            || inflight.refreshing >= self.max_refreshes
            || inflight.queries.len() >= self.max_inflight_queries
            || self.budget.is_exhausted()
        {
            return;
        }

        inflight.queries.insert(identity.clone(), Vec::new());
        inflight.refreshing += 1;
        drop(inflight);

        let slot = RefreshSlot {
            pipeline: Arc::clone(self),
        };
        let resolve = Arc::clone(self).resolve(
            identity,
            build::upstream_query(query, self.udp_size),
            self.route_of(&query.question.name),
        );
        tokio::spawn(async move {
            resolve.await;
            drop(slot);
        });
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
            self.local_resolver
                .as_ref()
                .map(|(_, resolver)| resolver)
                .ok_or(Failure::Upstream)?
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
        let key = CacheKey::new(&query);
        let mut cache = self.cache.lock().unwrap();
        let cached_as = cache.insert(&key, &bytes, &info, Instant::now());
        // A final answer the cache refuses (TTL 0, no SOA, too big) is what the upstream says
        // now, so a stale entry for the question is no longer the best answer.
        if cached_as.is_none() && is_final_answer(&info) {
            cache.forget(&key);
        }

        drop(cache);

        let source = Source::Upstream(if route == Route::Default {
            u8::try_from(server).ok()
        } else {
            None
        });

        Ok(Arc::new(Delivery::new(
            bytes, info, cached_as, 0, source, charge,
        )))
    }
}

/// An answer that settles the question: NOERROR or NXDOMAIN, not truncated, with no extended
/// rcode.
fn is_final_answer(info: &ResponseInfo) -> bool {
    let header = &info.header;

    matches!(header.rcode(), rcode::NOERROR | rcode::NXDOMAIN)
        && header.flags & flags::TC == 0
        && info.extended_rcode == 0
}

/// A SERVFAIL is an error, whatever built it: the upstream, a rebuild that failed, or a
/// blocked answer too big for the stream.
fn counted_as(reply: &[u8], result: QueryResult) -> QueryResult {
    if Header::parse(reply).is_ok_and(|header| header.rcode() == rcode::SERVFAIL) {
        QueryResult::Error
    } else {
        result
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

fn private_reverse_zones() -> Vec<Name> {
    let private_172 = (16..=31).map(|second| format!("{second}.172.in-addr.arpa"));

    PRIVATE_REVERSE_ZONES
        .iter()
        .map(|zone| zone.to_string())
        .chain(private_172)
        .map(|zone| Name::from_text(&zone).expect("private reverse zone is valid"))
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hickory_proto::rr::RecordType;

    use super::*;
    use crate::dns::test_util::{QuerySpec, ResponseSpec, a, parse};
    use crate::filter::engine::{CompiledList, Engine};
    use crate::filter::parse::ListFormat;
    use crate::upstream::test_dns::{self, fake_dns};

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));

    fn address_of(text: &str) -> Option<IpAddr> {
        reverse_address(&Name::from_text(text).unwrap())
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
            "1.0.0.127.in-addr.arpa",
            "printer.lan",
            "lan",
            "a.b.home.arpa",
        ] {
            assert_eq!(route(local), Route::Local, "{local}");
        }

        for subtree in [
            "10.in-addr.arpa",
            "2.10.in-addr.arpa",
            "16.172.in-addr.arpa",
            "31.172.in-addr.arpa",
            "168.192.in-addr.arpa",
            "lb._dns-sd._udp.0.1.168.192.in-addr.arpa",
            "b._dns-sd._udp.0.0.10.in-addr.arpa",
            "127.in-addr.arpa",
            "254.169.in-addr.arpa",
            "d.f.ip6.arpa",
            "c.f.ip6.arpa",
            "1.0.d.f.ip6.arpa",
            "8.e.f.ip6.arpa",
            "9.e.f.ip6.arpa",
            "a.e.f.ip6.arpa",
            "b.E.f.ip6.arpa",
            "lb._dns-sd._udp.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.f.ip6.arpa",
        ] {
            assert_eq!(route(subtree), Route::Local, "{subtree}");
        }

        let loopback = ipv6_reverse("::1");
        assert_eq!(route(&loopback), Route::Local, "{loopback}");
        assert_eq!(route(&format!("lb._dns-sd.{loopback}")), Route::Local);

        for public in [
            "in-addr.arpa",
            "ip6.arpa",
            "11.in-addr.arpa",
            "15.172.in-addr.arpa",
            "32.172.in-addr.arpa",
            "169.192.in-addr.arpa",
            "253.169.in-addr.arpa",
            "169.in-addr.arpa",
            "e.f.ip6.arpa",
            "c.e.f.ip6.arpa",
            "0.f.ip6.arpa",
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
    async fn names_under_a_private_reverse_zone_never_go_upstream() {
        let pipeline = pipeline_with_local(&[], None);

        for name in [
            "lb._dns-sd._udp.0.1.168.192.in-addr.arpa.",
            "10.in-addr.arpa.",
            "b._dns-sd._udp.0.0.10.in-addr.arpa.",
        ] {
            let request = QuerySpec::new(name, RecordType::PTR).bytes();
            let mut out = Vec::new();

            let quick = pipeline.answer_quickly(&request, Protocol::Udp, CLIENT, &mut out);

            assert_eq!(quick, Quick::Replied, "{name}");
            assert_eq!(u16::from(parse(&out).metadata.response_code), 3, "{name}");
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

    #[tokio::test]
    async fn upstream_tallies_list_the_servers_in_config_order_then_the_local_resolver() {
        let mut config = Config::default();
        config.upstream.servers = vec![
            "udp://192.0.2.1:53".to_string(),
            "tcp://192.0.2.2:53".to_string(),
        ];
        config.local.resolver = Some("192.0.2.53:53".parse().unwrap());

        let pipeline = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();
        let listed: Vec<(String, ServerKind)> = pipeline
            .upstream_tallies()
            .into_iter()
            .map(|server| {
                assert_eq!(server.tally, Tally::default());

                (server.label, server.kind)
            })
            .collect();

        assert_eq!(
            listed,
            vec![
                ("udp://192.0.2.1:53".to_string(), ServerKind::Upstream),
                ("tcp://192.0.2.2:53".to_string(), ServerKind::Upstream),
                ("192.0.2.53:53".to_string(), ServerKind::Local),
            ]
        );

        config.local.resolver = None;
        let without_local = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();

        assert!(
            without_local
                .upstream_tallies()
                .iter()
                .all(|server| server.kind == ServerKind::Upstream)
        );
    }

    fn engine_with(rules: &str) -> Arc<Engine> {
        let (list, _) = CompiledList::from_text(ListFormat::Adblock, rules);

        Arc::new(Engine::new(vec![Arc::new(list)], Vec::new()))
    }

    fn policy_of(rules: &str) -> Arc<Policy> {
        Arc::new(Policy::with_engine(engine_with(rules)))
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
        let old_delivery = Delivery::new(
            old_bytes,
            old_info,
            old_token,
            0,
            Source::Upstream(None),
            pipeline.budget.try_charge(1).unwrap(),
        );

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
        pipeline.deliver(&query, &reply, &old_delivery, &mut out);
        assert_eq!(&parse(&out).answers[0].data.to_string(), "1.1.1.1");

        let quick = pipeline.answer_quickly(&request, Protocol::Udp, CLIENT, &mut out);
        assert_eq!(quick, Quick::Replied);
        assert_eq!(&parse(&out).answers[0].data.to_string(), "0.0.0.0");
    }

    #[tokio::test]
    async fn an_allowed_request_skips_response_filtering_on_delivery_and_on_a_cache_hit() {
        let mut config = Config::default();
        config.upstream.servers = vec!["udp://127.0.0.1:9".to_string()];
        let pipeline = Pipeline::new(&config, policy_of("@@||ok.example^\n||9.9.9.9^\n")).unwrap();

        for (name, blocked) in [("ok.example.", false), ("other.example.", true)] {
            let spec = QuerySpec::new(name, RecordType::A);
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
            let delivery = Delivery::new(
                bytes,
                info,
                token,
                0,
                Source::Upstream(None),
                pipeline.budget.try_charge(1).unwrap(),
            );
            let reply = Reply::new(&query, pipeline.udp_size, Protocol::Udp);
            let expected = if blocked { "0.0.0.0" } else { "9.9.9.9" };
            let mut out = Vec::new();

            pipeline.deliver(&query, &reply, &delivery, &mut out);
            assert_eq!(&parse(&out).answers[0].data.to_string(), expected, "{name}");

            let quick = pipeline.answer_quickly(&request, Protocol::Udp, CLIENT, &mut out);
            assert_eq!(quick, Quick::Replied);
            assert_eq!(&parse(&out).answers[0].data.to_string(), expected, "{name}");
        }
    }

    #[tokio::test]
    async fn a_compressed_question_is_answered_with_formerr() {
        let mut config = Config::default();
        config.upstream.servers = vec!["udp://127.0.0.1:9".to_string()];
        let pipeline = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();
        let mut request = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        request.extend_from_slice(&[0xC0, 0x04, 0, 1, 0, 1]);
        let mut out = Vec::new();

        let quick = pipeline.answer_quickly(&request, Protocol::Udp, CLIENT, &mut out);

        assert_eq!(quick, Quick::Replied);
        assert_eq!(out.len(), 12);
        assert_eq!(u16::from(parse(&out).metadata.response_code), 1);
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
        let delivery = Delivery::new(
            bytes,
            info,
            token,
            0,
            Source::Upstream(None),
            pipeline.budget.try_charge(1).unwrap(),
        );
        let reply = Reply::new(&query, pipeline.udp_size, Protocol::Tcp);
        let mut out = Vec::new();

        pipeline.deliver(&query, &reply, &delivery, &mut out);
        assert_eq!(parse(&out).answers.len(), 200);
        assert_eq!(pipeline.cache.lock().unwrap().bytes(), bytes_without_memo);

        let quick = pipeline.answer_quickly(&request, Protocol::Tcp, CLIENT, &mut out);
        assert_eq!(quick, Quick::Replied);
        assert_eq!(parse(&out).answers.len(), 200);
        assert_eq!(pipeline.cache.lock().unwrap().bytes(), bytes_without_memo);
    }

    fn offline_config() -> Config {
        let mut config = Config::default();
        config.upstream.servers = vec!["udp://127.0.0.1:9".to_string()];

        config
    }

    /// Caches an A reply for `spec` as if it had been received `age_secs` ago.
    fn insert_aged(
        pipeline: &Pipeline,
        spec: &QuerySpec,
        address: [u8; 4],
        ttl: u32,
        age_secs: u64,
    ) -> Option<EntryToken> {
        let request = spec.bytes();
        let query = Query::parse(&request).unwrap();
        let bytes = ResponseSpec {
            answers: vec![a(&spec.name, ttl, address.into())],
            ..ResponseSpec::default()
        }
        .bytes(spec);
        let info = ResponseInfo::parse(&bytes).unwrap();
        let inserted = Instant::now()
            .checked_sub(Duration::from_secs(age_secs))
            .expect("the machine has been up for minutes");

        pipeline
            .cache
            .lock()
            .unwrap()
            .insert(&CacheKey::new(&query), &bytes, &info, inserted)
    }

    fn answer_ttls(out: &[u8]) -> Vec<u32> {
        parse(out).answers.iter().map(|record| record.ttl).collect()
    }

    fn answer_addresses(out: &[u8]) -> Vec<String> {
        parse(out)
            .answers
            .iter()
            .map(|record| record.data.to_string())
            .collect()
    }

    fn counters(pipeline: &Pipeline) -> crate::stats::Counters {
        pipeline.stats().snapshot().counters
    }

    #[tokio::test]
    async fn a_stale_hit_is_answered_at_once_with_the_answer_ttl() {
        let pipeline = Pipeline::new(&offline_config(), Arc::new(Policy::new())).unwrap();
        let stale = QuerySpec::new("stale.example.", RecordType::A);
        let fresh = QuerySpec::new("fresh.example.", RecordType::A);
        insert_aged(&pipeline, &stale, [1, 1, 1, 1], 300, 301).unwrap();
        insert_aged(&pipeline, &fresh, [2, 2, 2, 2], 300, 10).unwrap();
        let mut out = Vec::new();

        let quick = pipeline.answer_quickly(&stale.bytes(), Protocol::Udp, CLIENT, &mut out);
        assert_eq!(quick, Quick::Replied);
        assert_eq!(answer_ttls(&out), [30]);
        assert_eq!(answer_addresses(&out), ["1.1.1.1"]);

        let quick = pipeline.answer_quickly(&fresh.bytes(), Protocol::Udp, CLIENT, &mut out);
        assert_eq!(quick, Quick::Replied);
        assert_eq!(answer_ttls(&out), [290]);
        assert_eq!(answer_addresses(&out), ["2.2.2.2"]);

        let counters = counters(&pipeline);
        assert_eq!(counters.total, 2);
        assert_eq!(counters.cached, 2);
        assert_eq!(counters.upstream, 0);
    }

    #[tokio::test]
    async fn a_stale_hit_over_tcp_is_delivered_with_the_answer_ttl() {
        let pipeline = Pipeline::new(&offline_config(), Arc::new(Policy::new())).unwrap();
        let stale = QuerySpec::new("stale.example.", RecordType::A);
        insert_aged(&pipeline, &stale, [1, 1, 1, 1], 300, 301).unwrap();
        let mut out = Vec::new();

        let prepared = pipeline
            .prepare(stale.bytes(), Protocol::Tcp, CLIENT)
            .await
            .unwrap();
        let finished = pipeline.finish(&prepared, &mut out).await.unwrap();
        pipeline.count(&prepared, finished);

        assert_eq!(answer_ttls(&out), [30]);
        assert_eq!(answer_addresses(&out), ["1.1.1.1"]);
        assert_eq!(counters(&pipeline).cached, 1);
    }

    #[tokio::test]
    async fn past_its_window_an_expired_entry_needs_the_upstream() {
        let mut config = offline_config();
        config.cache.optimistic_max_age_secs = 10;
        let pipeline = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();
        let stale = QuerySpec::new("stale.example.", RecordType::A);
        insert_aged(&pipeline, &stale, [1, 1, 1, 1], 300, 311).unwrap();
        let mut out = Vec::new();

        let quick = pipeline.answer_quickly(&stale.bytes(), Protocol::Udp, CLIENT, &mut out);

        assert_eq!(quick, Quick::NeedsUpstream);
        assert!(pipeline.cache.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn with_optimism_off_an_expired_entry_needs_the_upstream() {
        let mut config = offline_config();
        config.cache.optimistic = false;
        let pipeline = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();
        let stale = QuerySpec::new("stale.example.", RecordType::A);
        insert_aged(&pipeline, &stale, [1, 1, 1, 1], 300, 301).unwrap();
        let mut out = Vec::new();

        let quick = pipeline.answer_quickly(&stale.bytes(), Protocol::Udp, CLIENT, &mut out);

        assert_eq!(quick, Quick::NeedsUpstream);
        assert!(pipeline.cache.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_stale_answer_takes_the_decision_of_the_policy_of_now() {
        let policy = Arc::new(Policy::new());
        let pipeline = Pipeline::new(&offline_config(), Arc::clone(&policy)).unwrap();
        let stale = QuerySpec::new("stale.example.", RecordType::A);
        let request = stale.bytes();
        let token = insert_aged(&pipeline, &stale, [9, 9, 9, 9], 300, 301).unwrap();
        let query = Query::parse(&request).unwrap();
        pipeline.cache.lock().unwrap().set_memo(
            &CacheKey::new(&query),
            token,
            Memo {
                generation: 0,
                decision: Decision::Pass,
            },
        );
        let mut out = Vec::new();
        let ask = |out: &mut Vec<u8>| {
            let quick = pipeline.answer_quickly(&request, Protocol::Udp, CLIENT, out);
            assert_eq!(quick, Quick::Replied);
        };

        policy.swap_engine(engine_with("||9.9.9.9^\n"));
        ask(&mut out);
        assert_eq!(answer_addresses(&out), ["0.0.0.0"]);
        assert_eq!(answer_ttls(&out), [pipeline.blocked_ttl]);
        assert_eq!(counters(&pipeline).blocked_response, 1);

        policy.pause(Duration::from_secs(60), policy.now());
        ask(&mut out);
        assert_eq!(answer_addresses(&out), ["9.9.9.9"]);
        assert_eq!(answer_ttls(&out), [30]);

        policy.resume();
        ask(&mut out);
        assert_eq!(answer_addresses(&out), ["0.0.0.0"]);
        assert_eq!(counters(&pipeline).blocked_response, 2);

        policy.swap_engine(engine_with("||stale.example^\n"));
        ask(&mut out);
        assert_eq!(answer_ttls(&out), [pipeline.blocked_ttl]);
        assert_eq!(counters(&pipeline).blocked_request, 1);
    }

    fn config_for_upstream(address: SocketAddr) -> Config {
        let mut config = Config::default();
        config.upstream.servers = vec![format!("udp://{address}")];

        config
    }

    fn inflight_counts(pipeline: &Pipeline) -> (usize, usize, usize) {
        let inflight = pipeline.inflight.lock().unwrap();

        (
            inflight.queries.len(),
            inflight.refreshing,
            inflight.waiting,
        )
    }

    /// Polls until no lookup is in flight and no refresh holds a slot, for at most 3 s.
    async fn wait_for_refreshes(pipeline: &Pipeline) {
        let deadline = Instant::now() + Duration::from_secs(3);

        while inflight_counts(pipeline).0 > 0 || inflight_counts(pipeline).1 > 0 {
            assert!(
                Instant::now() < deadline,
                "the refresh did not end within 3 s"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn ask_quickly(pipeline: &Arc<Pipeline>, spec: &QuerySpec, out: &mut Vec<u8>) -> Quick {
        pipeline.answer_quickly(&spec.bytes(), Protocol::Udp, CLIENT, out)
    }

    fn first_tally(pipeline: &Pipeline) -> Tally {
        pipeline.upstream_tallies()[0].tally
    }

    #[tokio::test]
    async fn twenty_stale_hits_start_one_refresh_that_waits_for_no_client() {
        let fake = fake_dns(vec![Ipv4Addr::new(2, 2, 2, 2)], vec![]).await;
        let pipeline =
            Pipeline::new(&config_for_upstream(fake.address), Arc::new(Policy::new())).unwrap();
        let spec = QuerySpec::new("stale.example.", RecordType::A);
        insert_aged(&pipeline, &spec, [1, 1, 1, 1], 300, 301).unwrap();
        let mut out = Vec::new();

        for _ in 0..20 {
            assert_eq!(ask_quickly(&pipeline, &spec, &mut out), Quick::Replied);
            assert_eq!(answer_addresses(&out), ["1.1.1.1"]);
            assert_eq!(answer_ttls(&out), [30]);
        }

        assert_eq!(inflight_counts(&pipeline), (1, 1, 0));

        wait_for_refreshes(&pipeline).await;
        assert_eq!(fake.queries.load(Ordering::SeqCst), 1);

        assert_eq!(ask_quickly(&pipeline, &spec, &mut out), Quick::Replied);
        assert_eq!(answer_addresses(&out), ["2.2.2.2"]);
        assert_eq!(answer_ttls(&out), [60]);
        assert_eq!(fake.queries.load(Ordering::SeqCst), 1);

        let counters = counters(&pipeline);
        assert_eq!(counters.total, 21);
        assert_eq!(counters.cached, 21);
        assert_eq!(counters.upstream, 0);
        assert_eq!(pipeline.stats().query_log(1000).len(), 21);
        assert_eq!(first_tally(&pipeline).answered, 1);
    }

    #[tokio::test]
    async fn a_stale_hit_joins_a_lookup_in_flight_for_its_question() {
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let config = config_for_upstream(silent.local_addr().unwrap());
        let pipeline = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();
        let spec = QuerySpec::new("stale.example.", RecordType::A);
        let request = spec.bytes();
        let _lookup = pipeline
            .join_or_start(&Query::parse(&request).unwrap())
            .unwrap();
        insert_aged(&pipeline, &spec, [1, 1, 1, 1], 300, 301).unwrap();
        let mut out = Vec::new();

        assert_eq!(ask_quickly(&pipeline, &spec, &mut out), Quick::Replied);
        assert_eq!(answer_ttls(&out), [30]);

        let (queries, refreshing, _) = inflight_counts(&pipeline);
        assert_eq!(queries, 1);
        assert_eq!(refreshing, 0);
    }

    #[tokio::test]
    async fn a_client_miss_joins_a_refresh_in_flight() {
        let fake = fake_dns(vec![Ipv4Addr::new(2, 2, 2, 2)], vec![]).await;
        let pipeline =
            Pipeline::new(&config_for_upstream(fake.address), Arc::new(Policy::new())).unwrap();
        let spec = QuerySpec::new("stale.example.", RecordType::A);
        let request = spec.bytes();
        insert_aged(&pipeline, &spec, [1, 1, 1, 1], 300, 301).unwrap();
        let mut out = Vec::new();
        assert_eq!(ask_quickly(&pipeline, &spec, &mut out), Quick::Replied);

        // Stands in for an eviction while the refresh runs.
        pipeline
            .cache
            .lock()
            .unwrap()
            .forget(&CacheKey::new(&Query::parse(&request).unwrap()));

        assert!(
            pipeline
                .answer(request, Protocol::Udp, CLIENT, &mut out)
                .await
        );
        assert_eq!(answer_addresses(&out), ["2.2.2.2"]);
        assert_eq!(fake.queries.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn refreshes_take_at_most_half_of_the_question_slots() {
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut config = config_for_upstream(silent.local_addr().unwrap());
        config.limits.max_inflight_queries = 4;
        let pipeline = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();
        let mut out = Vec::new();

        for index in 0..5 {
            let spec = QuerySpec::new(&format!("stale{index}.example."), RecordType::A);
            insert_aged(&pipeline, &spec, [1, 1, 1, 1], 300, 301).unwrap();

            assert_eq!(ask_quickly(&pipeline, &spec, &mut out), Quick::Replied);
            assert_eq!(answer_ttls(&out), [30]);
        }

        let (queries, refreshing, _) = inflight_counts(&pipeline);
        assert_eq!(refreshing, 2);
        assert_eq!(queries, 2);

        let client_lookup = |name: &str| {
            let request = QuerySpec::new(name, RecordType::A).bytes();

            pipeline.join_or_start(&Query::parse(&request).unwrap())
        };
        let _first = client_lookup("new0.example.").unwrap();
        let _second = client_lookup("new1.example.").unwrap();
        assert!(matches!(
            client_lookup("new2.example."),
            Err(Failure::Overloaded)
        ));
    }

    /// An upstream that never answers names starting with `stale` and answers any other A
    /// question at once with 3.3.3.3. Returns its address and how many `stale` queries it got.
    async fn deaf_to_stale_names() -> (SocketAddr, Arc<AtomicUsize>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let stale_received = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&stale_received);

        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
                let query = &buffer[..length];
                if query.get(13..18) == Some(&b"stale"[..]) {
                    counter.fetch_add(1, Ordering::SeqCst);

                    continue;
                }

                let reply = test_dns::answer(query, [3, 3, 3, 3], false);
                let _ = socket.send_to(&reply, peer).await;
            }
        });

        (address, stale_received)
    }

    #[tokio::test]
    async fn refreshes_leave_half_of_a_servers_slots_to_a_cold_query() {
        let (address, stale_received) = deaf_to_stale_names().await;
        let mut config = config_for_upstream(address);
        config.limits.upstream_concurrency = 4;
        config.upstream.timeout_ms = 4000;
        let pipeline = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();
        let mut out = Vec::new();

        for index in 0..5 {
            let spec = QuerySpec::new(&format!("stale{index}.example."), RecordType::A);
            insert_aged(&pipeline, &spec, [1, 1, 1, 1], 300, 301).unwrap();

            assert_eq!(ask_quickly(&pipeline, &spec, &mut out), Quick::Replied);
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        while inflight_counts(&pipeline).1 != 2 || stale_received.load(Ordering::SeqCst) != 2 {
            assert!(
                Instant::now() < deadline,
                "two refreshes never held a server slot: {:?}, {} received",
                inflight_counts(&pipeline),
                stale_received.load(Ordering::SeqCst)
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let cold = QuerySpec::new("cold.example.", RecordType::A).bytes();
        let asked = Instant::now();
        assert!(pipeline.answer(cold, Protocol::Udp, CLIENT, &mut out).await);
        let took = asked.elapsed();

        assert_eq!(answer_addresses(&out), ["3.3.3.3"]);
        // Without a free slot, the first try would give up waiting for one at half the
        // timeout; anything below that means the query found a slot.
        assert!(took < Duration::from_millis(2000), "took {took:?}");
    }

    #[tokio::test]
    async fn a_single_slot_setup_still_refreshes() {
        let fake = fake_dns(vec![Ipv4Addr::new(2, 2, 2, 2)], vec![]).await;
        let mut config = config_for_upstream(fake.address);
        config.limits.max_inflight_queries = 1;
        let pipeline = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();
        let first = QuerySpec::new("first.example.", RecordType::A);
        let second = QuerySpec::new("second.example.", RecordType::A);
        insert_aged(&pipeline, &first, [1, 1, 1, 1], 300, 301).unwrap();
        insert_aged(&pipeline, &second, [1, 1, 1, 1], 300, 301).unwrap();
        let mut out = Vec::new();

        assert_eq!(ask_quickly(&pipeline, &first, &mut out), Quick::Replied);
        assert_eq!(inflight_counts(&pipeline).1, 1);

        assert_eq!(ask_quickly(&pipeline, &second, &mut out), Quick::Replied);
        assert_eq!(inflight_counts(&pipeline).0, 1);

        wait_for_refreshes(&pipeline).await;
        assert_eq!(ask_quickly(&pipeline, &first, &mut out), Quick::Replied);
        assert_eq!(answer_addresses(&out), ["2.2.2.2"]);
        assert_eq!(answer_ttls(&out), [60]);
    }

    #[tokio::test]
    async fn a_failed_refresh_keeps_the_stale_entry_and_is_no_client_error() {
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut config = config_for_upstream(silent.local_addr().unwrap());
        config.upstream.timeout_ms = 200;
        let pipeline = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();
        let spec = QuerySpec::new("stale.example.", RecordType::A);
        insert_aged(&pipeline, &spec, [1, 1, 1, 1], 300, 301).unwrap();
        let mut out = Vec::new();

        assert_eq!(ask_quickly(&pipeline, &spec, &mut out), Quick::Replied);
        wait_for_refreshes(&pipeline).await;
        assert_eq!(pipeline.cache.lock().unwrap().len(), 1);

        assert_eq!(ask_quickly(&pipeline, &spec, &mut out), Quick::Replied);
        assert_eq!(answer_ttls(&out), [30]);
        assert_eq!(inflight_counts(&pipeline).1, 1);

        assert_eq!(counters(&pipeline).errors, 0);
        assert!(first_tally(&pipeline).failed >= 1);
    }

    #[tokio::test]
    async fn an_answer_the_cache_cannot_keep_drops_the_stale_entry() {
        let fake = fake_dns(vec![Ipv4Addr::new(2, 2, 2, 2)], vec![]).await;
        fake.set_v4(vec![]);
        let pipeline =
            Pipeline::new(&config_for_upstream(fake.address), Arc::new(Policy::new())).unwrap();
        let spec = QuerySpec::new("stale.example.", RecordType::A);
        insert_aged(&pipeline, &spec, [1, 1, 1, 1], 300, 301).unwrap();
        let mut out = Vec::new();

        assert_eq!(ask_quickly(&pipeline, &spec, &mut out), Quick::Replied);
        wait_for_refreshes(&pipeline).await;

        assert_eq!(fake.queries.load(Ordering::SeqCst), 1);
        assert!(pipeline.cache.lock().unwrap().is_empty());
        assert_eq!(
            ask_quickly(&pipeline, &spec, &mut out),
            Quick::NeedsUpstream
        );
    }

    #[tokio::test]
    async fn a_name_blocked_by_its_request_starts_no_refresh() {
        let pipeline = Pipeline::new(&offline_config(), policy_of("||x.example^\n")).unwrap();
        let spec = QuerySpec::new("x.example.", RecordType::A);
        insert_aged(&pipeline, &spec, [1, 1, 1, 1], 300, 301).unwrap();
        let mut out = Vec::new();

        assert_eq!(ask_quickly(&pipeline, &spec, &mut out), Quick::Replied);

        assert_eq!(answer_addresses(&out), ["0.0.0.0"]);
        assert_eq!(inflight_counts(&pipeline), (0, 0, 0));
    }

    #[tokio::test]
    async fn clearing_the_cache_reports_what_it_removed_and_the_next_query_needs_the_upstream() {
        let pipeline = Pipeline::new(&offline_config(), Arc::new(Policy::new())).unwrap();
        let specs: Vec<QuerySpec> = ["a.example.", "b.example.", "c.example."]
            .iter()
            .map(|name| QuerySpec::new(name, RecordType::A))
            .collect();
        insert_aged(&pipeline, &specs[0], [1, 1, 1, 1], 300, 301).unwrap();
        insert_aged(&pipeline, &specs[1], [1, 1, 1, 1], 300, 10).unwrap();
        insert_aged(&pipeline, &specs[2], [1, 1, 1, 1], 300, 0).unwrap();
        let bytes = pipeline.cache.lock().unwrap().bytes();

        assert_eq!(pipeline.cache_size(), CacheSize { entries: 3, bytes });

        assert_eq!(pipeline.clear_cache(), 3);
        assert_eq!(
            pipeline.cache_size(),
            CacheSize {
                entries: 0,
                bytes: 0
            }
        );

        let mut out = Vec::new();
        assert_eq!(
            ask_quickly(&pipeline, &specs[0], &mut out),
            Quick::NeedsUpstream
        );
    }
}
