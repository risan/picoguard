//! Bounded LRU of upstream replies. Entries keep the upstream bytes so every
//! delivery rebuilds the reply and takes the filter decision under the policy
//! of that moment.

use std::time::Instant;

use lru::LruCache;
use xxhash_rust::xxh3::xxh3_64;

use crate::config::CacheConfig;
use crate::dns::build::ReplyParts;
use crate::dns::wire::{HEADER_LEN, Name, Query, ResponseInfo, flags, rcode};
use crate::filter::engine::Decision;

/// Struct, LRU node, hash slot and allocator overhead of one entry, counted
/// against `max_bytes` on top of the payload.
const ENTRY_OVERHEAD: usize = 160;
const FLAG_RD: u8 = 1;
const FLAG_DO: u8 = 2;
const FLAG_CD: u8 = 4;
const QUESTION_TAIL_LEN: usize = 4;

/// Identifies what was asked: lowercase name, type, class, and the request bits
/// that change the answer (RD, DO, CD). It is also the coalescing identity.
#[derive(Debug, Clone, Copy)]
pub struct CacheKey<'q> {
    hash: u64,
    request_flags: u8,
    name: &'q Name,
    qtype: u16,
    qclass: u16,
}

impl<'q> CacheKey<'q> {
    pub fn new(query: &'q Query<'_>) -> CacheKey<'q> {
        let mut request_flags = 0;
        if query.header.recursion_desired() {
            request_flags |= FLAG_RD;
        }

        if query.dnssec_ok() {
            request_flags |= FLAG_DO;
        }

        if query.header.checking_disabled() {
            request_flags |= FLAG_CD;
        }

        let name = &query.question.name;
        let mut input = [0u8; 5 + crate::dns::wire::MAX_NAME_LEN];
        input[0] = request_flags;
        input[1..3].copy_from_slice(&query.question.qtype.to_be_bytes());
        input[3..5].copy_from_slice(&query.question.qclass.to_be_bytes());
        let wire = name.as_wire();
        input[5..5 + wire.len()].copy_from_slice(wire);

        CacheKey {
            hash: xxh3_64(&input[..5 + wire.len()]),
            request_flags,
            name,
            qtype: query.question.qtype,
            qclass: query.question.qclass,
        }
    }

    /// The full key as bytes, for maps that must not trust a 64-bit hash.
    pub fn identity(&self) -> Vec<u8> {
        let wire = self.name.as_wire();
        let mut identity = Vec::with_capacity(5 + wire.len());
        identity.push(self.request_flags);
        identity.extend_from_slice(&self.qtype.to_be_bytes());
        identity.extend_from_slice(&self.qclass.to_be_bytes());
        identity.extend_from_slice(wire);

        identity
    }

    fn question_matches(&self, message: &[u8]) -> bool {
        let wire = self.name.as_wire();
        let tail_start = HEADER_LEN + wire.len();

        let mut tail = [0u8; QUESTION_TAIL_LEN];
        tail[0..2].copy_from_slice(&self.qtype.to_be_bytes());
        tail[2..4].copy_from_slice(&self.qclass.to_be_bytes());

        message.get(HEADER_LEN..tail_start) == Some(wire)
            && message.get(tail_start..tail_start + QUESTION_TAIL_LEN) == Some(&tail[..])
    }
}

/// A filter decision remembered with the policy generation that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Memo {
    pub generation: u64,
    pub decision: Decision,
}

struct Entry {
    bytes: Box<[u8]>,
    ttl_offsets: Box<[u16]>,
    opt_start: Option<u16>,
    request_flags: u8,
    inserted: Instant,
    lifetime_secs: u32,
    memo: Option<Memo>,
}

impl Entry {
    fn cost(&self) -> usize {
        cost_of(self.bytes.len(), self.ttl_offsets.len())
    }

    fn age_secs(&self, now: Instant) -> u32 {
        let age = now.saturating_duration_since(self.inserted).as_secs();

        u32::try_from(age).unwrap_or(u32::MAX)
    }

    fn matches(&self, key: &CacheKey<'_>) -> bool {
        self.request_flags == key.request_flags && key.question_matches(&self.bytes)
    }
}

fn cost_of(payload_len: usize, ttl_count: usize) -> usize {
    payload_len + ttl_count * size_of::<u16>() + ENTRY_OVERHEAD
}

pub struct Hit<'a> {
    pub parts: ReplyParts<'a>,
    pub age_secs: u32,
    pub memo: Option<Memo>,
}

pub struct Cache {
    entries: LruCache<u64, Entry>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    min_ttl: u32,
    max_ttl: u32,
    max_response_size: usize,
}

impl Cache {
    pub fn new(config: &CacheConfig) -> Cache {
        Cache {
            entries: LruCache::unbounded(),
            bytes: 0,
            max_entries: config.max_entries,
            max_bytes: config.max_bytes,
            min_ttl: config.min_ttl,
            max_ttl: config.max_ttl,
            max_response_size: config.max_response_size,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Bytes counted against `max_bytes`.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Returns a live entry for `key` and marks it recently used. An expired
    /// entry is removed.
    pub fn get(&mut self, key: &CacheKey<'_>, now: Instant) -> Option<Hit<'_>> {
        let (matches, expired) = self
            .entries
            .peek(&key.hash)
            .map(|entry| {
                (
                    entry.matches(key),
                    entry.age_secs(now) >= entry.lifetime_secs,
                )
            })
            .unwrap_or_default();

        if !matches {
            return None;
        }

        if expired {
            self.remove(key.hash);

            return None;
        }

        let entry = self.entries.get(&key.hash)?;

        Some(Hit {
            parts: ReplyParts {
                bytes: &entry.bytes,
                ttl_offsets: &entry.ttl_offsets,
                opt_start: entry.opt_start,
            },
            age_secs: entry.age_secs(now),
            memo: entry.memo.clone(),
        })
    }

    /// Stores `reply` if it may be cached and returns whether it was stored.
    /// The question echoed in `reply` is rewritten to the key's lowercase form.
    pub fn insert(
        &mut self,
        key: &CacheKey<'_>,
        reply: &[u8],
        info: &ResponseInfo,
        now: Instant,
    ) -> bool {
        let Some(lifetime_secs) = self.lifetime_of(info) else {
            return false;
        };

        let cost = cost_of(reply.len(), info.ttl_offsets.len());
        if reply.len() > self.max_response_size || cost > self.max_bytes {
            return false;
        }

        let name_len = key.name.as_wire().len();
        let echoed_name = reply.get(HEADER_LEN..HEADER_LEN + name_len);
        if !echoed_name.is_some_and(|echoed| echoed.eq_ignore_ascii_case(key.name.as_wire())) {
            return false;
        }

        let mut bytes = reply.to_vec();
        bytes[HEADER_LEN..HEADER_LEN + name_len].copy_from_slice(key.name.as_wire());
        if !key.question_matches(&bytes) {
            return false;
        }

        self.remove(key.hash);
        while self.entries.len() >= self.max_entries || self.bytes + cost > self.max_bytes {
            let Some((_, evicted)) = self.entries.pop_lru() else {
                break;
            };

            self.bytes -= evicted.cost();
        }

        let entry = Entry {
            bytes: bytes.into_boxed_slice(),
            ttl_offsets: info.ttl_offsets.clone().into_boxed_slice(),
            opt_start: info.opt_start,
            request_flags: key.request_flags,
            inserted: now,
            lifetime_secs,
            memo: None,
        };
        self.bytes += entry.cost();
        self.entries.put(key.hash, entry);

        true
    }

    /// Remembers a filter decision on the entry for `key`, if it is still there.
    pub fn set_memo(&mut self, key: &CacheKey<'_>, memo: Memo) {
        if let Some(entry) = self.entries.peek_mut(&key.hash)
            && entry.matches(key)
        {
            entry.memo = Some(memo);
        }
    }

    fn remove(&mut self, hash: u64) {
        if let Some(entry) = self.entries.pop(&hash) {
            self.bytes -= entry.cost();
        }
    }

    /// How long a reply may be served, or `None` if it must not be cached:
    /// only NOERROR and NXDOMAIN, never truncated. Negative replies (NXDOMAIN,
    /// and NODATA, also behind a CNAME chain) live as long as the SOA's
    /// negative TTL and every record they carry, and are skipped without a
    /// SOA; other replies live as long as their smallest TTL.
    fn lifetime_of(&self, info: &ResponseInfo) -> Option<u32> {
        let header = &info.header;
        if !header.is_response() || header.flags & flags::TC != 0 || info.extended_rcode != 0 {
            return None;
        }

        let lifetime = if info.is_negative {
            info.negative_ttl?.min(info.min_ttl?)
        } else if header.rcode() == rcode::NOERROR {
            info.min_ttl?
        } else {
            return None;
        };
        let lifetime = lifetime.clamp(self.min_ttl, self.max_ttl);

        (lifetime > 0).then_some(lifetime)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hickory_proto::rr::RecordType;

    use super::*;
    use crate::dns::test_util::{QuerySpec, ResponseSpec, a, cname, soa};

    fn config() -> CacheConfig {
        CacheConfig::default()
    }

    struct Fixture {
        query_bytes: Vec<u8>,
        spec: QuerySpec,
    }

    impl Fixture {
        fn new(name: &str) -> Fixture {
            Fixture::from(QuerySpec::new(name, RecordType::A))
        }

        fn from(spec: QuerySpec) -> Fixture {
            Fixture {
                query_bytes: spec.bytes(),
                spec,
            }
        }

        fn query(&self) -> Query<'_> {
            Query::parse(&self.query_bytes).unwrap()
        }

        fn positive(&self, ttl: u32) -> Vec<u8> {
            ResponseSpec {
                answers: vec![a(&self.spec.name, ttl, [192, 0, 2, 1].into())],
                edns: Some(1232),
                ..ResponseSpec::default()
            }
            .bytes(&self.spec)
        }
    }

    fn insert(cache: &mut Cache, fixture: &Fixture, reply: &[u8], now: Instant) -> bool {
        let query = fixture.query();
        let info = ResponseInfo::parse(reply).unwrap();

        cache.insert(&CacheKey::new(&query), reply, &info, now)
    }

    fn age_of_hit(cache: &mut Cache, fixture: &Fixture, now: Instant) -> Option<u32> {
        let query = fixture.query();

        cache
            .get(&CacheKey::new(&query), now)
            .map(|hit| hit.age_secs)
    }

    #[test]
    fn a_stored_reply_is_returned_with_its_age() {
        let mut cache = Cache::new(&config());
        let fixture = Fixture::new("example.com.");
        let reply = fixture.positive(60);
        let start = Instant::now();

        assert!(insert(&mut cache, &fixture, &reply, start));

        let query = fixture.query();
        let hit = cache
            .get(&CacheKey::new(&query), start + Duration::from_secs(7))
            .unwrap();
        assert_eq!(hit.age_secs, 7);
        assert_eq!(hit.parts.bytes, &reply[..]);
        assert!(hit.parts.opt_start.is_some());
        assert_eq!(hit.parts.ttl_offsets.len(), 1);
    }

    #[test]
    fn an_entry_expires_at_its_smallest_ttl() {
        let mut cache = Cache::new(&config());
        let fixture = Fixture::new("example.com.");
        let reply = ResponseSpec {
            answers: vec![
                a("example.com.", 300, [192, 0, 2, 1].into()),
                a("example.com.", 60, [192, 0, 2, 2].into()),
            ],
            ..ResponseSpec::default()
        }
        .bytes(&fixture.spec);
        let start = Instant::now();
        insert(&mut cache, &fixture, &reply, start);

        assert_eq!(
            age_of_hit(&mut cache, &fixture, start + Duration::from_secs(59)),
            Some(59)
        );
        assert_eq!(
            age_of_hit(&mut cache, &fixture, start + Duration::from_secs(60)),
            None
        );
        assert!(cache.is_empty());
        assert_eq!(cache.bytes(), 0);
    }

    #[test]
    fn ttls_are_clamped_to_the_configured_range() {
        let mut cache = Cache::new(&CacheConfig {
            min_ttl: 30,
            max_ttl: 100,
            ..config()
        });
        let short = Fixture::new("short.example.");
        let long = Fixture::new("long.example.");
        let start = Instant::now();
        insert(&mut cache, &short, &short.positive(5), start);
        insert(&mut cache, &long, &long.positive(86_400), start);

        let after_29 = start + Duration::from_secs(29);
        let after_30 = start + Duration::from_secs(30);
        let after_99 = start + Duration::from_secs(99);
        let after_100 = start + Duration::from_secs(100);

        assert!(age_of_hit(&mut cache, &short, after_29).is_some());
        assert!(age_of_hit(&mut cache, &short, after_30).is_none());
        assert!(age_of_hit(&mut cache, &long, after_99).is_some());
        assert!(age_of_hit(&mut cache, &long, after_100).is_none());
    }

    #[test]
    fn a_zero_ttl_is_not_cached() {
        let mut cache = Cache::new(&config());
        let fixture = Fixture::new("example.com.");

        assert!(!insert(
            &mut cache,
            &fixture,
            &fixture.positive(0),
            Instant::now()
        ));
        assert!(cache.is_empty());
    }

    #[test]
    fn negative_replies_live_as_long_as_the_soa_says() {
        let mut cache = Cache::new(&config());
        let start = Instant::now();
        let nxdomain = Fixture::new("nx.example.");
        let nodata = Fixture::new("nodata.example.");
        let reply = |fixture: &Fixture, rcode: u8| {
            ResponseSpec {
                authorities: vec![soa("example.", 900, 45)],
                rcode,
                ..ResponseSpec::default()
            }
            .bytes(&fixture.spec)
        };

        assert!(insert(&mut cache, &nxdomain, &reply(&nxdomain, 3), start));
        assert!(insert(&mut cache, &nodata, &reply(&nodata, 0), start));

        let before = start + Duration::from_secs(44);
        let after = start + Duration::from_secs(45);
        assert!(age_of_hit(&mut cache, &nxdomain, before).is_some());
        assert!(age_of_hit(&mut cache, &nodata, before).is_some());
        assert!(age_of_hit(&mut cache, &nxdomain, after).is_none());
        assert!(age_of_hit(&mut cache, &nodata, after).is_none());
    }

    fn chain_reply(
        fixture: &Fixture,
        rcode: u8,
        cname_ttl: u32,
        terminal_answers: Vec<hickory_proto::rr::Record>,
        authorities: Vec<hickory_proto::rr::Record>,
    ) -> Vec<u8> {
        let mut answers = vec![cname(&fixture.spec.name, cname_ttl, "edge.example.net.")];
        answers.extend(terminal_answers);

        ResponseSpec {
            answers,
            authorities,
            rcode,
            ..ResponseSpec::default()
        }
        .bytes(&fixture.spec)
    }

    fn lifetime_in_secs(cache: &mut Cache, fixture: &Fixture, start: Instant) -> Option<u64> {
        (0..=1000u64)
            .find(|secs| age_of_hit(cache, fixture, start + Duration::from_secs(*secs)).is_none())
    }

    #[test]
    fn nodata_behind_a_cname_chain_lives_as_long_as_the_negative_ttl() {
        let mut cache = Cache::new(&config());
        let fixture = Fixture::new("www.example.com.");
        let start = Instant::now();
        let reply = chain_reply(&fixture, 0, 300, vec![], vec![soa("example.net.", 900, 45)]);

        assert!(insert(&mut cache, &fixture, &reply, start));

        assert_eq!(lifetime_in_secs(&mut cache, &fixture, start), Some(45));
    }

    #[test]
    fn a_short_cname_ttl_bounds_a_negative_reply_behind_the_chain() {
        let soa_record = || vec![soa("example.net.", 900, 45)];
        let fixture = Fixture::new("www.example.com.");
        let start = Instant::now();

        for rcode in [0, 3] {
            let mut cache = Cache::new(&config());
            let reply = chain_reply(&fixture, rcode, 20, vec![], soa_record());

            assert!(insert(&mut cache, &fixture, &reply, start));

            assert_eq!(
                lifetime_in_secs(&mut cache, &fixture, start),
                Some(20),
                "rcode {rcode}"
            );
        }
    }

    #[test]
    fn nxdomain_behind_a_cname_chain_uses_the_negative_ttl_when_it_is_shorter() {
        let mut cache = Cache::new(&config());
        let fixture = Fixture::new("www.example.com.");
        let start = Instant::now();
        let reply = chain_reply(&fixture, 3, 300, vec![], vec![soa("example.net.", 900, 45)]);

        assert!(insert(&mut cache, &fixture, &reply, start));

        assert_eq!(lifetime_in_secs(&mut cache, &fixture, start), Some(45));
    }

    #[test]
    fn nodata_behind_a_cname_chain_without_a_soa_is_not_cached() {
        let mut cache = Cache::new(&config());
        let fixture = Fixture::new("www.example.com.");
        let reply = chain_reply(&fixture, 0, 300, vec![], vec![]);

        assert!(!insert(&mut cache, &fixture, &reply, Instant::now()));
    }

    #[test]
    fn a_cname_chain_that_ends_in_data_is_a_positive_reply_whatever_the_record_order() {
        let fixture = Fixture::new("www.example.com.");
        let start = Instant::now();
        let terminal = || vec![a("edge.example.net.", 120, [192, 0, 2, 1].into())];
        let authority = || vec![soa("example.net.", 900, 45)];
        let in_order = chain_reply(&fixture, 0, 300, terminal(), authority());
        let out_of_order = ResponseSpec {
            answers: vec![
                a("edge.example.net.", 120, [192, 0, 2, 1].into()),
                cname("www.example.com.", 300, "edge.example.net."),
            ],
            authorities: authority(),
            ..ResponseSpec::default()
        }
        .bytes(&fixture.spec);

        for reply in [in_order, out_of_order] {
            let mut cache = Cache::new(&config());

            assert!(insert(&mut cache, &fixture, &reply, start));

            assert_eq!(lifetime_in_secs(&mut cache, &fixture, start), Some(120));
        }
    }

    #[test]
    fn a_reply_with_an_extended_rcode_is_not_cached() {
        let mut cache = Cache::new(&config());
        let fixture = Fixture::new("example.com.");
        let mut reply = ResponseSpec {
            authorities: vec![soa("example.com.", 900, 45)],
            edns: Some(1232),
            ..ResponseSpec::default()
        }
        .bytes(&fixture.spec);
        let opt_start = reply.len() - 11;
        reply[opt_start + 5] = 1;

        assert!(!insert(&mut cache, &fixture, &reply, Instant::now()));
    }

    #[test]
    fn replies_that_must_not_be_cached_are_refused() {
        let mut cache = Cache::new(&config());
        let fixture = Fixture::new("example.com.");
        let start = Instant::now();
        let without_soa = |rcode| {
            ResponseSpec {
                rcode,
                ..ResponseSpec::default()
            }
            .bytes(&fixture.spec)
        };
        let mut truncated = fixture.positive(60);
        truncated[2] |= 0x02;
        let mut query_not_response = fixture.positive(60);
        query_not_response[2] &= 0x7F;

        assert!(
            !insert(&mut cache, &fixture, &without_soa(3), start),
            "NXDOMAIN without SOA"
        );
        assert!(
            !insert(&mut cache, &fixture, &without_soa(0), start),
            "NODATA without SOA"
        );
        assert!(
            !insert(&mut cache, &fixture, &without_soa(2), start),
            "SERVFAIL"
        );
        assert!(
            !insert(&mut cache, &fixture, &without_soa(5), start),
            "REFUSED"
        );
        assert!(
            !insert(&mut cache, &fixture, &truncated, start),
            "truncated"
        );
        assert!(!insert(&mut cache, &fixture, &query_not_response, start));
        assert!(cache.is_empty());
    }

    #[test]
    fn rd_do_and_cd_get_separate_entries() {
        let mut cache = Cache::new(&config());
        let start = Instant::now();
        let base = Fixture::new("example.com.");
        let mut no_rd = QuerySpec::new("example.com.", RecordType::A);
        no_rd.recursion_desired = false;
        let mut cd = QuerySpec::new("example.com.", RecordType::A);
        cd.checking_disabled = true;
        let mut dnssec = QuerySpec::new("example.com.", RecordType::A);
        dnssec.edns = Some((1232, true));
        let mut edns_without_do = QuerySpec::new("example.com.", RecordType::A);
        edns_without_do.edns = Some((4096, false));

        insert(&mut cache, &base, &base.positive(60), start);

        assert!(age_of_hit(&mut cache, &base, start).is_some());
        assert!(
            age_of_hit(&mut cache, &Fixture::from(edns_without_do), start).is_some(),
            "EDNS without DO shares the plain entry"
        );
        for other in [no_rd, cd, dnssec] {
            assert!(age_of_hit(&mut cache, &Fixture::from(other), start).is_none());
        }
    }

    #[test]
    fn type_class_and_name_are_part_of_the_key_but_letter_case_is_not() {
        let mut cache = Cache::new(&config());
        let start = Instant::now();
        let lower = Fixture::new("example.com.");
        insert(&mut cache, &lower, &lower.positive(60), start);

        let upper = Fixture::new("EXAMPLE.Com.");
        let other_name = Fixture::new("example.org.");
        let aaaa = Fixture::from(QuerySpec::new("example.com.", RecordType::AAAA));

        assert!(age_of_hit(&mut cache, &upper, start).is_some());
        assert!(age_of_hit(&mut cache, &other_name, start).is_none());
        assert!(age_of_hit(&mut cache, &aaaa, start).is_none());
    }

    #[test]
    fn the_stored_question_is_lowercase() {
        let mut cache = Cache::new(&config());
        let fixture = Fixture::new("MiXeD.Example.com.");
        let reply = fixture.positive(60);
        let start = Instant::now();
        insert(&mut cache, &fixture, &reply, start);

        let query = fixture.query();
        let hit = cache.get(&CacheKey::new(&query), start).unwrap();

        assert_eq!(&hit.parts.bytes[13..18], b"mixed");
    }

    #[test]
    fn a_hash_collision_is_a_miss_not_a_wrong_answer() {
        let mut cache = Cache::new(&config());
        let start = Instant::now();
        let stored = Fixture::new("example.com.");
        insert(&mut cache, &stored, &stored.positive(60), start);
        let other = Fixture::new("example.org.");
        let other_query = other.query();
        let mut colliding = CacheKey::new(&other_query);
        let stored_query = stored.query();
        colliding.hash = CacheKey::new(&stored_query).hash;

        assert!(cache.get(&colliding, start).is_none());
        assert_eq!(cache.len(), 1, "the other entry stays");
    }

    #[test]
    fn the_least_recently_used_entry_is_evicted_first() {
        let mut cache = Cache::new(&CacheConfig {
            max_entries: 3,
            ..config()
        });
        let start = Instant::now();
        let names = ["a.example.", "b.example.", "c.example.", "d.example."];
        let fixtures: Vec<Fixture> = names.iter().map(|name| Fixture::new(name)).collect();
        for fixture in &fixtures[..3] {
            insert(&mut cache, fixture, &fixture.positive(60), start);
        }

        assert!(age_of_hit(&mut cache, &fixtures[0], start).is_some());

        insert(&mut cache, &fixtures[3], &fixtures[3].positive(60), start);

        assert_eq!(cache.len(), 3);
        assert!(
            age_of_hit(&mut cache, &fixtures[1], start).is_none(),
            "b was least recent"
        );
        for kept in [0, 2, 3] {
            assert!(age_of_hit(&mut cache, &fixtures[kept], start).is_some());
        }
    }

    fn large_positive(fixture: &Fixture, size: usize) -> Vec<u8> {
        ResponseSpec {
            answers: vec![crate::dns::test_util::txt(&fixture.spec.name, 60, size)],
            ..ResponseSpec::default()
        }
        .bytes(&fixture.spec)
    }

    #[test]
    fn the_byte_cap_evicts_old_entries_to_make_room() {
        let mut cache = Cache::new(&CacheConfig {
            max_bytes: 4000,
            ..config()
        });
        let start = Instant::now();
        let fixtures: Vec<Fixture> = (0..10)
            .map(|index| {
                Fixture::from(QuerySpec::new(
                    &format!("big{index}.example."),
                    RecordType::TXT,
                ))
            })
            .collect();

        for fixture in &fixtures {
            let reply = large_positive(fixture, 1000);
            assert!(insert(&mut cache, fixture, &reply, start));
            assert!(cache.bytes() <= 4000, "{} bytes", cache.bytes());
        }

        assert!(cache.len() < 10);
        assert!(cache.len() >= 2);
        let newest = fixtures.last().unwrap();
        assert!(age_of_hit(&mut cache, newest, start).is_some());
        assert!(age_of_hit(&mut cache, &fixtures[0], start).is_none());
    }

    #[test]
    fn replies_over_the_size_limit_or_the_byte_cap_are_not_admitted() {
        let fixture = Fixture::from(QuerySpec::new("big.example.", RecordType::TXT));
        let reply = large_positive(&fixture, 2300);
        assert!(reply.len() > 2000);
        let start = Instant::now();
        let mut small_responses = Cache::new(&CacheConfig {
            max_response_size: 1500,
            ..config()
        });
        let mut small_cache = Cache::new(&CacheConfig {
            max_bytes: 2000,
            ..config()
        });
        let mut roomy = Cache::new(&config());

        assert!(!insert(&mut small_responses, &fixture, &reply, start));
        assert!(!insert(&mut small_cache, &fixture, &reply, start));
        assert!(insert(&mut roomy, &fixture, &reply, start));
    }

    #[test]
    fn inserting_the_same_key_again_replaces_it_and_keeps_the_count_exact() {
        let mut cache = Cache::new(&config());
        let start = Instant::now();
        let fixture = Fixture::new("example.com.");
        insert(&mut cache, &fixture, &fixture.positive(60), start);
        let bytes_once = cache.bytes();

        insert(
            &mut cache,
            &fixture,
            &fixture.positive(60),
            start + Duration::from_secs(30),
        );

        assert_eq!(cache.len(), 1);
        assert_eq!(cache.bytes(), bytes_once);
        assert_eq!(
            age_of_hit(&mut cache, &fixture, start + Duration::from_secs(31)),
            Some(1)
        );
    }

    #[test]
    fn a_memo_is_kept_with_its_entry_and_replaced_on_reinsert() {
        let mut cache = Cache::new(&config());
        let start = Instant::now();
        let fixture = Fixture::new("example.com.");
        let query = fixture.query();
        let key = CacheKey::new(&query);
        insert(&mut cache, &fixture, &fixture.positive(60), start);
        assert_eq!(cache.get(&key, start).unwrap().memo, None);

        let memo = Memo {
            generation: 7,
            decision: Decision::Pass,
        };
        cache.set_memo(&key, memo.clone());

        assert_eq!(cache.get(&key, start).unwrap().memo, Some(memo));
        insert(&mut cache, &fixture, &fixture.positive(60), start);
        assert_eq!(cache.get(&key, start).unwrap().memo, None);
    }

    #[test]
    fn a_memo_for_a_missing_entry_is_ignored() {
        let mut cache = Cache::new(&config());
        let fixture = Fixture::new("example.com.");
        let query = fixture.query();

        cache.set_memo(
            &CacheKey::new(&query),
            Memo {
                generation: 1,
                decision: Decision::Pass,
            },
        );

        assert!(cache.is_empty());
    }

    #[test]
    fn identities_differ_by_flags_type_and_name_only() {
        let plain = Fixture::new("Example.com.");
        let same = Fixture::new("example.COM.");
        let mut no_rd = QuerySpec::new("example.com.", RecordType::A);
        no_rd.recursion_desired = false;
        let no_rd = Fixture::from(no_rd);
        let aaaa = Fixture::from(QuerySpec::new("example.com.", RecordType::AAAA));
        let identity = |fixture: &Fixture| CacheKey::new(&fixture.query()).identity();

        assert_eq!(identity(&plain), identity(&same));
        assert_ne!(identity(&plain), identity(&no_rd));
        assert_ne!(identity(&plain), identity(&aaaa));
    }

    /// Time to insert `measured` new names into a cache already holding
    /// `preload`. Messages are built once and only the 7-letter first label
    /// (at offset 13) changes, so building them costs almost nothing.
    fn time_inserts(preload: usize, measured: usize) -> Duration {
        let mut cache = Cache::new(&CacheConfig {
            max_entries: preload,
            max_bytes: usize::MAX / 2,
            ..config()
        });
        let start = Instant::now();
        let template = Fixture::new("h000000.example.");
        let reply_template = template.positive(60);
        let messages = |index: usize| {
            let label = format!("h{index:06}");
            let mut query = template.query_bytes.clone();
            let mut reply = reply_template.clone();
            query[13..20].copy_from_slice(label.as_bytes());
            reply[13..20].copy_from_slice(label.as_bytes());

            (query, reply)
        };
        let insert_index = |cache: &mut Cache, index: usize| {
            let (query_bytes, reply) = messages(index);
            let query = Query::parse(&query_bytes).unwrap();
            let info = ResponseInfo::parse(&reply).unwrap();

            cache.insert(&CacheKey::new(&query), &reply, &info, start);
        };

        for index in 0..preload {
            insert_index(&mut cache, index);
        }

        let timer = Instant::now();
        for index in preload..preload + measured {
            insert_index(&mut cache, index);
        }

        timer.elapsed()
    }

    #[test]
    fn insert_cost_stays_flat_when_the_cache_is_full() {
        let small = time_inserts(10_000, 20_000);
        let large = time_inserts(100_000, 20_000);

        assert!(
            large < small * 5 + Duration::from_millis(50),
            "10k entries: {small:?}, 100k entries: {large:?}"
        );
    }
}
