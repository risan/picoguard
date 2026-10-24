//! Counters, hourly buckets, top-k lists and the query log, all in memory with
//! sizes fixed at construction (plan D15). Nothing reaches the disk.

use std::cmp::Reverse;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

pub const DEFAULT_TOP_K: usize = 50;
pub const DEFAULT_QUERY_LOG_ENTRIES: usize = 1_000;
pub const HOURS: usize = 24;

const SECONDS_PER_HOUR: u64 = 3_600;

/// Seconds since the Unix epoch.
pub type Clock = Box<dyn Fn() -> u64 + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatsSettings {
    pub top_k: usize,
    pub query_log_entries: usize,
}

impl Default for StatsSettings {
    fn default() -> StatsSettings {
        StatsSettings {
            top_k: DEFAULT_TOP_K,
            query_log_entries: DEFAULT_QUERY_LOG_ENTRIES,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryResult {
    /// Resolved by an upstream and not blocked.
    Pass,
    BlockedRequest,
    /// The answer (a CNAME target or an address) matched a rule.
    BlockedResponse,
    Cached,
    /// SERVFAIL or no usable answer.
    Error,
}

/// One answered query. `qname` is the name as the filter saw it (lowercase,
/// no trailing dot): it is the key of the top-k lists.
pub struct Event<'a> {
    pub client: IpAddr,
    pub qname: &'a str,
    pub qtype: u16,
    pub result: QueryResult,
    /// Position of the upstream that answered or failed, if one was asked.
    pub upstream: Option<u8>,
    pub latency: Duration,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub total: u64,
    pub blocked_request: u64,
    pub blocked_response: u64,
    pub cached: u64,
    pub upstream: u64,
    pub errors: u64,
    /// Queries shed under overload. They are not part of `total`.
    pub dropped: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct HourlyBucket {
    /// Unix seconds at the start of the UTC hour.
    pub hour_start: u64,
    pub total: u64,
    pub blocked: u64,
}

/// Space-Saving entry: the true count lies in `count - max_error..=count`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TopEntry<K> {
    pub key: K,
    pub count: u64,
    pub max_error: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QueryLogEntry {
    pub time: u64,
    pub client: IpAddr,
    pub qname: Box<str>,
    pub qtype: u16,
    pub result: QueryResult,
    pub upstream: Option<u8>,
    pub latency_us: u32,
}

#[derive(Clone, Debug)]
pub struct StatsSnapshot {
    pub counters: Counters,
    /// Oldest first; the last bucket is the current hour.
    pub hourly: Vec<HourlyBucket>,
    /// The top-k lists are approximate (Space-Saving), most frequent first.
    pub top_queried: Vec<TopEntry<Box<str>>>,
    pub top_blocked: Vec<TopEntry<Box<str>>>,
    pub top_clients: Vec<TopEntry<IpAddr>>,
}

struct Counted<K> {
    key: K,
    count: u64,
    error: u64,
}

/// Space-Saving: a key that does not fit takes over the entry with the lowest
/// count and inherits that count as its error bound.
struct TopK<K> {
    capacity: usize,
    entries: Vec<Counted<K>>,
}

impl<K: Clone> TopK<K> {
    fn new(capacity: usize) -> TopK<K> {
        TopK {
            capacity,
            entries: Vec::with_capacity(capacity),
        }
    }

    /// `make_key` runs only when the key is new, so a repeated key costs no allocation.
    fn record(&mut self, is_key: impl Fn(&K) -> bool, make_key: impl FnOnce() -> K) {
        if self.capacity == 0 {
            return;
        }

        if let Some(entry) = self.entries.iter_mut().find(|entry| is_key(&entry.key)) {
            entry.count += 1;

            return;
        }

        if self.entries.len() < self.capacity {
            self.entries.push(Counted {
                key: make_key(),
                count: 1,
                error: 0,
            });

            return;
        }

        let lowest = self
            .entries
            .iter_mut()
            .min_by_key(|entry| entry.count)
            .expect("capacity is above zero and the list is full");
        lowest.error = lowest.count;
        lowest.count += 1;
        lowest.key = make_key();
    }

    fn top(&self) -> Vec<TopEntry<K>> {
        let mut top: Vec<TopEntry<K>> = self
            .entries
            .iter()
            .map(|entry| TopEntry {
                key: entry.key.clone(),
                count: entry.count,
                max_error: entry.error,
            })
            .collect();
        top.sort_by_key(|entry| Reverse(entry.count));

        top
    }
}

#[derive(Clone, Copy, Default)]
struct Hour {
    /// Hours since the epoch; a slot is reused every 24 hours and this tells which one it holds.
    number: u64,
    total: u64,
    blocked: u64,
}

/// A slot of the query log ring. Its name text is reused for every entry the slot holds.
struct LogSlot {
    time: u64,
    client: IpAddr,
    qname: String,
    qtype: u16,
    result: QueryResult,
    upstream: Option<u8>,
    latency_us: u32,
}

impl LogSlot {
    fn new(time: u64, event: &Event) -> LogSlot {
        let mut slot = LogSlot {
            time,
            client: event.client,
            qname: String::new(),
            qtype: event.qtype,
            result: event.result,
            upstream: event.upstream,
            latency_us: 0,
        };
        slot.set(time, event);

        slot
    }

    fn set(&mut self, time: u64, event: &Event) {
        self.time = time;
        self.client = event.client;
        self.qname.clear();
        self.qname.push_str(event.qname);
        self.qtype = event.qtype;
        self.result = event.result;
        self.upstream = event.upstream;
        self.latency_us = u32::try_from(event.latency.as_micros()).unwrap_or(u32::MAX);
    }

    fn entry(&self) -> QueryLogEntry {
        QueryLogEntry {
            time: self.time,
            client: self.client,
            qname: self.qname.as_str().into(),
            qtype: self.qtype,
            result: self.result,
            upstream: self.upstream,
            latency_us: self.latency_us,
        }
    }
}

struct QueryLog {
    capacity: usize,
    slots: Vec<LogSlot>,
    /// Once the ring is full, the slot of the oldest entry and the next to overwrite.
    oldest: usize,
}

impl QueryLog {
    fn new(capacity: usize) -> QueryLog {
        QueryLog {
            capacity,
            slots: Vec::with_capacity(capacity),
            oldest: 0,
        }
    }

    fn push(&mut self, time: u64, event: &Event) {
        if self.capacity == 0 {
            return;
        }

        if self.slots.len() < self.capacity {
            self.slots.push(LogSlot::new(time, event));
        } else {
            self.slots[self.oldest].set(time, event);
            self.oldest = (self.oldest + 1) % self.capacity;
        }
    }

    fn newest_first(&self, limit: usize) -> Vec<QueryLogEntry> {
        let length = self.slots.len();

        (0..length.min(limit))
            .map(|age| self.slots[(self.oldest + length - 1 - age) % length].entry())
            .collect()
    }
}

struct Inner {
    counters: Counters,
    hours: [Hour; HOURS],
    queried: TopK<Box<str>>,
    blocked: TopK<Box<str>>,
    clients: TopK<IpAddr>,
    log: QueryLog,
}

pub struct Stats {
    clock: Clock,
    inner: Mutex<Inner>,
}

impl Stats {
    pub fn new(settings: StatsSettings) -> Stats {
        Stats::with_clock(settings, Box::new(unix_seconds))
    }

    pub fn with_clock(settings: StatsSettings, clock: Clock) -> Stats {
        Stats {
            clock,
            inner: Mutex::new(Inner {
                counters: Counters::default(),
                hours: [Hour::default(); HOURS],
                queried: TopK::new(settings.top_k),
                blocked: TopK::new(settings.top_k),
                clients: TopK::new(settings.top_k),
                log: QueryLog::new(settings.query_log_entries),
            }),
        }
    }

    pub fn record(&self, event: &Event) {
        let now = (self.clock)();
        let blocked = matches!(
            event.result,
            QueryResult::BlockedRequest | QueryResult::BlockedResponse
        );
        let mut inner = self.inner.lock().unwrap();

        inner.counters.total += 1;
        match event.result {
            QueryResult::Pass => inner.counters.upstream += 1,
            QueryResult::BlockedRequest => inner.counters.blocked_request += 1,
            QueryResult::BlockedResponse => inner.counters.blocked_response += 1,
            QueryResult::Cached => inner.counters.cached += 1,
            QueryResult::Error => inner.counters.errors += 1,
        }

        let hour_number = now / SECONDS_PER_HOUR;
        let hour = &mut inner.hours[hour_number as usize % HOURS];
        if hour.number != hour_number {
            *hour = Hour {
                number: hour_number,
                ..Hour::default()
            };
        }
        hour.total += 1;
        if blocked {
            hour.blocked += 1;
        }

        let qname = event.qname;
        inner.queried.record(|key| **key == *qname, || qname.into());
        if blocked {
            inner.blocked.record(|key| **key == *qname, || qname.into());
        }
        let client = event.client;
        inner.clients.record(|key| *key == client, || client);

        inner.log.push(now, event);
    }

    /// A query shed before it was read, so there is no name to log.
    pub fn record_dropped(&self) {
        self.inner.lock().unwrap().counters.dropped += 1;
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        let now_hour = (self.clock)() / SECONDS_PER_HOUR;
        let inner = self.inner.lock().unwrap();

        let hourly = (0..HOURS as u64)
            .rev()
            .map(|hours_ago| {
                let number = now_hour.saturating_sub(hours_ago);
                let stored = inner.hours[number as usize % HOURS];
                let (total, blocked) = if stored.number == number {
                    (stored.total, stored.blocked)
                } else {
                    (0, 0)
                };

                HourlyBucket {
                    hour_start: number * SECONDS_PER_HOUR,
                    total,
                    blocked,
                }
            })
            .collect();

        StatsSnapshot {
            counters: inner.counters,
            hourly,
            top_queried: inner.queried.top(),
            top_blocked: inner.blocked.top(),
            top_clients: inner.clients.top(),
        }
    }

    /// The most recent entries, newest first.
    pub fn query_log(&self, limit: usize) -> Vec<QueryLogEntry> {
        self.inner.lock().unwrap().log.newest_first(limit)
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    /// 2023-11-14 00:00:00 UTC.
    const MIDNIGHT: u64 = 19_675 * 86_400;
    const HOUR: u64 = SECONDS_PER_HOUR;

    fn client(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
    }

    fn event(qname: &str, result: QueryResult) -> Event<'_> {
        Event {
            client: client(2),
            qname,
            qtype: 1,
            result,
            upstream: None,
            latency: Duration::from_micros(100),
        }
    }

    fn stats_at(settings: StatsSettings, start: u64) -> (Stats, Arc<AtomicU64>) {
        let time = Arc::new(AtomicU64::new(start));
        let clock_time = Arc::clone(&time);
        let stats = Stats::with_clock(
            settings,
            Box::new(move || clock_time.load(Ordering::Relaxed)),
        );

        (stats, time)
    }

    fn small(top_k: usize, query_log_entries: usize) -> StatsSettings {
        StatsSettings {
            top_k,
            query_log_entries,
        }
    }

    #[test]
    fn defaults_are_the_planned_sizes() {
        let settings = StatsSettings::default();

        assert_eq!(settings.top_k, 50);
        assert_eq!(settings.query_log_entries, 1_000);
    }

    #[test]
    fn counters_follow_each_result() {
        let (stats, _) = stats_at(StatsSettings::default(), MIDNIGHT);

        let results = [
            (QueryResult::Pass, 3),
            (QueryResult::BlockedRequest, 2),
            (QueryResult::BlockedResponse, 4),
            (QueryResult::Cached, 5),
            (QueryResult::Error, 1),
        ];
        for (result, times) in results {
            for _ in 0..times {
                stats.record(&event("example.com", result));
            }
        }
        stats.record_dropped();
        stats.record_dropped();

        assert_eq!(
            stats.snapshot().counters,
            Counters {
                total: 15,
                blocked_request: 2,
                blocked_response: 4,
                cached: 5,
                upstream: 3,
                errors: 1,
                dropped: 2,
            }
        );
    }

    #[test]
    fn fresh_stats_are_empty() {
        let (stats, _) = stats_at(StatsSettings::default(), MIDNIGHT);
        let snapshot = stats.snapshot();

        assert_eq!(snapshot.counters, Counters::default());
        assert_eq!(snapshot.hourly.len(), 24);
        assert!(snapshot.hourly.iter().all(|bucket| bucket.total == 0));
        assert!(snapshot.top_queried.is_empty());
        assert!(stats.query_log(10).is_empty());
    }

    #[test]
    fn blocked_domains_list_only_blocked_results() {
        let (stats, _) = stats_at(StatsSettings::default(), MIDNIGHT);

        stats.record(&event("ads.example", QueryResult::BlockedRequest));
        stats.record(&event("ads.example", QueryResult::BlockedResponse));
        stats.record(&event("tracker.example", QueryResult::BlockedRequest));
        stats.record(&event("fine.example", QueryResult::Pass));
        let snapshot = stats.snapshot();

        let blocked: Vec<(&str, u64)> = snapshot
            .top_blocked
            .iter()
            .map(|entry| (&*entry.key, entry.count))
            .collect();
        assert_eq!(blocked, [("ads.example", 2), ("tracker.example", 1)]);
        assert_eq!(snapshot.top_queried.len(), 3);
    }

    #[test]
    fn clients_are_counted_per_address() {
        let (stats, _) = stats_at(StatsSettings::default(), MIDNIGHT);

        for last in [7, 7, 7, 9] {
            let mut query = event("example.com", QueryResult::Pass);
            query.client = client(last);
            stats.record(&query);
        }
        let clients = stats.snapshot().top_clients;

        assert_eq!(clients[0].key, client(7));
        assert_eq!(clients[0].count, 3);
        assert_eq!(clients[1].key, client(9));
    }

    #[test]
    fn space_saving_replaces_the_lowest_count_and_keeps_its_error() {
        let mut top = TopK::<Box<str>>::new(2);
        for name in ["a", "a", "a", "b", "c"] {
            top.record(|key| **key == *name, || name.into());
        }
        let entries = top.top();

        assert_eq!(entries.len(), 2);
        assert_eq!(&*entries[0].key, "a");
        assert_eq!((entries[0].count, entries[0].max_error), (3, 0));
        assert_eq!(&*entries[1].key, "c");
        assert_eq!((entries[1].count, entries[1].max_error), (2, 1));
    }

    #[test]
    fn zero_sizes_keep_nothing_and_do_not_fail() {
        let (stats, _) = stats_at(small(0, 0), MIDNIGHT);

        stats.record(&event("example.com", QueryResult::Pass));
        let snapshot = stats.snapshot();

        assert_eq!(snapshot.counters.total, 1);
        assert!(snapshot.top_queried.is_empty());
        assert!(snapshot.top_clients.is_empty());
        assert!(stats.query_log(10).is_empty());
    }

    /// A deterministic stream: names drawn with probability proportional to
    /// 1 / rank^1.2, which is how resolver traffic looks.
    fn skewed_stream(distinct: usize, length: usize) -> Vec<usize> {
        let mut cumulative = Vec::with_capacity(distinct);
        let mut sum = 0.0_f64;
        for rank in 1..=distinct {
            sum += 1.0 / (rank as f64).powf(1.2);
            cumulative.push(sum);
        }

        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let draw = (state >> 11) as f64 / (1_u64 << 53) as f64 * sum;
                cumulative.partition_point(|&reach| reach < draw)
            })
            .collect()
    }

    #[test]
    fn top_k_finds_the_true_top_ten_of_a_skewed_stream_within_its_error_bounds() {
        const LENGTH: usize = 200_000;
        let names: Vec<String> = (0..5_000)
            .map(|rank| format!("site{rank}.example"))
            .collect();
        let (stats, _) = stats_at(small(50, 0), MIDNIGHT);
        let mut truth: HashMap<&str, u64> = HashMap::new();
        for rank in skewed_stream(names.len(), LENGTH) {
            let name = names[rank].as_str();
            *truth.entry(name).or_default() += 1;
            stats.record(&event(name, QueryResult::Pass));
        }
        let reported = stats.snapshot().top_queried;

        let mut ranked: Vec<(&str, u64)> =
            truth.iter().map(|(name, count)| (*name, *count)).collect();
        ranked.sort_by_key(|&(name, count)| (Reverse(count), name));
        for (name, _) in &ranked[..10] {
            assert!(
                reported.iter().any(|entry| &*entry.key == *name),
                "{name} is missing from the reported top 50"
            );
        }

        for entry in &reported {
            let true_count = truth.get(&*entry.key).copied().unwrap_or(0);
            assert!(
                entry.count - entry.max_error <= true_count && true_count <= entry.count,
                "{}: true {true_count}, reported {} with error {}",
                entry.key,
                entry.count,
                entry.max_error
            );
        }

        let guaranteed = LENGTH as u64 / 50;
        for (name, count) in ranked.iter().filter(|(_, count)| *count > guaranteed) {
            assert!(
                reported.iter().any(|entry| &*entry.key == *name),
                "{name} occurs {count} times, above n/k, and must be reported"
            );
        }

        assert_eq!(
            reported.iter().map(|entry| entry.count).sum::<u64>(),
            LENGTH as u64
        );
        assert!(
            reported
                .windows(2)
                .all(|pair| pair[0].count >= pair[1].count)
        );
    }

    fn logged_names(stats: &Stats, limit: usize) -> Vec<String> {
        stats
            .query_log(limit)
            .into_iter()
            .map(|entry| entry.qname.to_string())
            .collect()
    }

    #[test]
    fn query_log_lists_newest_first_until_full() {
        let (stats, _) = stats_at(small(5, 3), MIDNIGHT);

        stats.record(&event("one.example", QueryResult::Pass));
        stats.record(&event("two.example", QueryResult::Pass));

        assert_eq!(logged_names(&stats, 10), ["two.example", "one.example"]);
    }

    #[test]
    fn query_log_overwrites_the_oldest_entry_first() {
        let (stats, _) = stats_at(small(5, 3), MIDNIGHT);

        for number in 1..=7 {
            stats.record(&event(&format!("q{number}.example"), QueryResult::Pass));
        }

        assert_eq!(
            logged_names(&stats, 10),
            ["q7.example", "q6.example", "q5.example"]
        );
        assert_eq!(logged_names(&stats, 2), ["q7.example", "q6.example"]);
    }

    #[test]
    fn query_log_keeps_every_field() {
        let (stats, time) = stats_at(small(5, 3), MIDNIGHT);
        time.store(MIDNIGHT + 42, Ordering::Relaxed);

        stats.record(&Event {
            client: client(77),
            qname: "example.com",
            qtype: 28,
            result: QueryResult::Error,
            upstream: Some(1),
            latency: Duration::from_millis(12),
        });

        assert_eq!(
            stats.query_log(1),
            [QueryLogEntry {
                time: MIDNIGHT + 42,
                client: client(77),
                qname: "example.com".into(),
                qtype: 28,
                result: QueryResult::Error,
                upstream: Some(1),
                latency_us: 12_000,
            }]
        );
    }

    #[test]
    fn a_huge_latency_is_capped() {
        let (stats, _) = stats_at(small(5, 3), MIDNIGHT);
        let mut query = event("example.com", QueryResult::Pass);
        query.latency = Duration::from_secs(10_000);

        stats.record(&query);

        assert_eq!(stats.query_log(1)[0].latency_us, u32::MAX);
    }

    fn totals(stats: &Stats) -> Vec<u64> {
        stats
            .snapshot()
            .hourly
            .iter()
            .map(|bucket| bucket.total)
            .collect()
    }

    #[test]
    fn hourly_buckets_roll_over_at_midnight() {
        let (stats, time) = stats_at(StatsSettings::default(), MIDNIGHT - HOUR / 2);

        stats.record(&event("a.example", QueryResult::Pass));
        stats.record(&event("b.example", QueryResult::BlockedRequest));
        time.store(MIDNIGHT + HOUR / 6, Ordering::Relaxed);
        stats.record(&event("c.example", QueryResult::Pass));
        let hourly = stats.snapshot().hourly;

        assert_eq!(hourly.len(), 24);
        assert_eq!(hourly[23].hour_start, MIDNIGHT);
        assert_eq!((hourly[23].total, hourly[23].blocked), (1, 0));
        assert_eq!(hourly[22].hour_start, MIDNIGHT - HOUR);
        assert_eq!((hourly[22].total, hourly[22].blocked), (2, 1));
        assert_eq!(hourly[0].hour_start, MIDNIGHT - 23 * HOUR);
    }

    #[test]
    fn skipped_hours_read_as_empty() {
        let (stats, time) = stats_at(StatsSettings::default(), MIDNIGHT + 10 * HOUR);

        stats.record(&event("a.example", QueryResult::Pass));
        time.store(MIDNIGHT + 15 * HOUR + 5, Ordering::Relaxed);
        stats.record(&event("b.example", QueryResult::Pass));
        stats.record(&event("b.example", QueryResult::Pass));

        let mut expected = vec![0; 24];
        expected[23] = 2;
        expected[18] = 1;
        assert_eq!(totals(&stats), expected);
    }

    #[test]
    fn a_slot_is_cleared_when_its_hour_comes_round_again() {
        let (stats, time) = stats_at(StatsSettings::default(), MIDNIGHT + 3 * HOUR);

        for _ in 0..4 {
            stats.record(&event("a.example", QueryResult::BlockedRequest));
        }
        time.store(MIDNIGHT + 27 * HOUR, Ordering::Relaxed);
        stats.record(&event("b.example", QueryResult::Pass));
        let hourly = stats.snapshot().hourly;

        assert_eq!((hourly[23].total, hourly[23].blocked), (1, 0));
        assert_eq!(totals(&stats).iter().sum::<u64>(), 1);
    }

    #[test]
    fn reading_after_a_quiet_day_shows_nothing_but_keeps_the_counters() {
        let (stats, time) = stats_at(StatsSettings::default(), MIDNIGHT);

        stats.record(&event("a.example", QueryResult::Pass));
        time.store(MIDNIGHT + 2 * 86_400, Ordering::Relaxed);

        assert_eq!(totals(&stats), vec![0; 24]);
        assert_eq!(stats.snapshot().counters.total, 1);
    }

    #[test]
    fn a_day_of_consecutive_hours_fills_every_bucket() {
        let (stats, time) = stats_at(StatsSettings::default(), MIDNIGHT);

        for hour in 0..30 {
            time.store(MIDNIGHT + hour * HOUR, Ordering::Relaxed);
            stats.record(&event("a.example", QueryResult::Pass));
        }

        assert_eq!(totals(&stats), vec![1; 24]);
    }
}
