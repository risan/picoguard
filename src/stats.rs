//! Counters, hourly buckets, top-k lists and the query log, all in memory with
//! sizes fixed at construction (plan D15). The query log never reaches the disk; the rest is
//! saved by `stats_store`.

use std::cmp::Reverse;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::dns::wire::{Name, read_name};
use crate::stats_store::SavedStats;

pub const DEFAULT_TOP_K: usize = 50;
pub const DEFAULT_QUERY_LOG_ENTRIES: usize = 1_000;
pub const DEFAULT_RETENTION_DAYS: u32 = 30;
/// The retentions the page and `[stats] retention_days` allow.
pub const RETENTION_CHOICES: [u32; 4] = [1, 7, 30, 90];
/// The hours the chart on the status page shows.
pub const HOURS: usize = 24;
/// The hourly ring holds the longest retention.
pub const MAX_HISTORY_HOURS: usize = 90 * 24;
/// What the hourly ring takes, allocated once.
pub const HISTORY_BYTES: usize = MAX_HISTORY_HOURS * std::mem::size_of::<Hour>();

const SECONDS_PER_HOUR: u64 = 3_600;
const SECONDS_PER_DAY: i64 = 86_400;
/// Longest name text shown; a name with many escapes is cut and marked.
const SHOWN_NAME_BYTES: usize = 256;
const CUT_MARK: char = '\u{2026}';

/// Seconds since the Unix epoch.
pub type Clock = Box<dyn Fn() -> u64 + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatsSettings {
    pub top_k: usize,
    pub query_log_entries: usize,
    pub retention_days: u32,
}

impl Default for StatsSettings {
    fn default() -> StatsSettings {
        StatsSettings {
            top_k: DEFAULT_TOP_K,
            query_log_entries: DEFAULT_QUERY_LOG_ENTRIES,
            retention_days: DEFAULT_RETENTION_DAYS,
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
    /// Answered from a rewrite or SafeSearch (plan D7).
    Rewritten,
    /// SERVFAIL or no usable answer.
    Error,
}

/// One answered query. `qname` is the name as the filter saw it (lowercase): it is the
/// identity of the top-k entries.
pub struct Event<'a> {
    pub client: IpAddr,
    pub qname: &'a Name,
    pub qtype: u16,
    pub result: QueryResult,
    /// Position of the upstream that answered or failed, if one was asked.
    pub upstream: Option<u8>,
    pub latency: Duration,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub total: u64,
    pub blocked_request: u64,
    pub blocked_response: u64,
    pub cached: u64,
    pub upstream: u64,
    pub rewritten: u64,
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

/// The hours of one local day, for the longer ranges of the chart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DailyBucket {
    /// Unix seconds at local midnight.
    pub day_start: u64,
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

impl<K> TopEntry<K> {
    fn with_key<T>(self, key: impl FnOnce(K) -> T) -> TopEntry<T> {
        TopEntry {
            key: key(self.key),
            count: self.count,
            max_error: self.max_error,
        }
    }
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
    /// Unix seconds: when the counters, history and top lists started counting.
    pub since: u64,
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

    fn clear(&mut self) {
        self.entries.clear();
    }

    /// Takes the entries with the highest counts, up to the capacity.
    fn fill(&mut self, mut entries: Vec<Counted<K>>) {
        entries.sort_by_key(|entry| Reverse(entry.count));
        self.entries.clear();
        self.entries.extend(entries.into_iter().take(self.capacity));
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
pub struct Hour {
    /// Hours since the epoch; a slot is reused every `MAX_HISTORY_HOURS` hours and this tells
    /// which one it holds.
    number: u64,
    total: u64,
    blocked: u64,
}

/// A slot of the query log ring. Its name text is reused for every entry the slot holds.
struct LogSlot {
    time: u64,
    client: IpAddr,
    /// The name in wire format.
    qname: Vec<u8>,
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
            qname: Vec::new(),
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
        let wire = event.qname.as_wire();
        self.qname.clear();
        // Exact growth: the default doubling would let 1,000 slots hold ~2x the longest name.
        self.qname.reserve_exact(wire.len());
        self.qname.extend_from_slice(wire);
        self.qtype = event.qtype;
        self.result = event.result;
        self.upstream = event.upstream;
        self.latency_us = u32::try_from(event.latency.as_micros()).unwrap_or(u32::MAX);
    }

    fn entry(&self) -> QueryLogEntry {
        QueryLogEntry {
            time: self.time,
            client: self.client,
            qname: read_name(&self.qname, 0)
                .map_or_else(|_| Box::from(""), |(name, _)| shown(&name)),
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

    fn clear(&mut self) {
        self.slots.clear();
        self.oldest = 0;
    }

    fn newest_first(&self, limit: usize) -> Vec<QueryLogEntry> {
        let length = self.slots.len();

        (0..length.min(limit))
            .map(|age| self.slots[(self.oldest + length - 1 - age) % length].entry())
            .collect()
    }
}

struct Inner {
    since: u64,
    retention_days: u32,
    counters: Counters,
    hours: Box<[Hour]>,
    queried: TopK<Name>,
    blocked: TopK<Name>,
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
        let since = clock();

        Stats {
            clock,
            inner: Mutex::new(Inner {
                since,
                retention_days: clamp_retention(settings.retention_days),
                counters: Counters::default(),
                hours: vec![Hour::default(); MAX_HISTORY_HOURS].into_boxed_slice(),
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
            QueryResult::Rewritten => inner.counters.rewritten += 1,
            QueryResult::Error => inner.counters.errors += 1,
        }

        let hour_number = now / SECONDS_PER_HOUR;
        let hour = &mut inner.hours[hour_number as usize % MAX_HISTORY_HOURS];
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
        inner.queried.record(|key| key == qname, || qname.clone());
        if blocked {
            inner.blocked.record(|key| key == qname, || qname.clone());
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
                let stored = inner.hours[number as usize % MAX_HISTORY_HOURS];
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
            since: inner.since,
            counters: inner.counters,
            hourly,
            top_queried: shown_top(&inner.queried),
            top_blocked: shown_top(&inner.blocked),
            top_clients: inner.clients.top(),
        }
    }

    /// The most recent entries, newest first.
    pub fn query_log(&self, limit: usize) -> Vec<QueryLogEntry> {
        self.inner.lock().unwrap().log.newest_first(limit)
    }

    pub fn retention_days(&self) -> u32 {
        self.inner.lock().unwrap().retention_days
    }

    /// Hours older than the retention are no longer shown or saved. Shortening or lengthening
    /// it drops what is older than the shorter of the two, so a longer retention never brings
    /// back what the shorter one had dropped.
    pub fn set_retention(&self, days: u32) {
        let now_hour = (self.clock)() / SECONDS_PER_HOUR;
        let mut inner = self.inner.lock().unwrap();
        let days = clamp_retention(days);
        let kept_hours = retention_hours(days.min(inner.retention_days));

        for hour in inner.hours.iter_mut() {
            if !is_kept(hour.number, now_hour, kept_hours) {
                *hour = Hour::default();
            }
        }

        inner.retention_days = days;
    }

    /// The last `days` local days, oldest first and the last one today, with the hours of
    /// each. `days` is cut to the retention. One offset (seconds east of UTC) serves the whole
    /// range, so a day that has a clock change in it is split an hour off.
    pub fn daily(&self, days: u32, utc_offset_seconds: i32) -> Vec<DailyBucket> {
        let now = (self.clock)();
        let now_hour = now / SECONDS_PER_HOUR;
        let inner = self.inner.lock().unwrap();
        let days = days.min(inner.retention_days);
        let offset = i64::from(utc_offset_seconds);
        let today = (now as i64 + offset).div_euclid(SECONDS_PER_DAY);
        let first_day = today - i64::from(days) + 1;
        let mut buckets: Vec<DailyBucket> = (first_day..=today)
            .map(|day| DailyBucket {
                day_start: u64::try_from(day * SECONDS_PER_DAY - offset).unwrap_or(0),
                total: 0,
                blocked: 0,
            })
            .collect();
        let kept_hours = retention_hours(inner.retention_days);

        for hour in inner.hours.iter() {
            if hour.total == 0 || !is_kept(hour.number, now_hour, kept_hours) {
                continue;
            }

            let day =
                (hour.number as i64 * SECONDS_PER_HOUR as i64 + offset).div_euclid(SECONDS_PER_DAY);
            if day >= first_day {
                let bucket = &mut buckets[(day - first_day) as usize];
                bucket.total += hour.total;
                bucket.blocked += hour.blocked;
            }
        }

        buckets
    }

    /// Starts counting again from now: counters, history and the three top lists. The query
    /// log is kept.
    pub fn clear(&self) {
        let now = (self.clock)();
        let mut inner = self.inner.lock().unwrap();

        inner.since = now;
        inner.counters = Counters::default();
        inner.hours.fill(Hour::default());
        inner.queried.clear();
        inner.blocked.clear();
        inner.clients.clear();
    }

    pub fn clear_query_log(&self) {
        self.inner.lock().unwrap().log.clear();
    }

    /// What is worth keeping across a restart, for the file `stats_store` writes. The upstream
    /// tallies are not in `Stats`; the pipeline adds them.
    pub fn saved(&self) -> SavedStats {
        let now_hour = (self.clock)() / SECONDS_PER_HOUR;
        let inner = self.inner.lock().unwrap();
        let kept_hours = retention_hours(inner.retention_days);
        let mut hours: Vec<(u64, u64, u64)> = inner
            .hours
            .iter()
            .filter(|hour| hour.total > 0 && is_kept(hour.number, now_hour, kept_hours))
            .map(|hour| (hour.number, hour.total, hour.blocked))
            .collect();
        hours.sort_unstable();

        SavedStats {
            version: SavedStats::VERSION,
            since: inner.since,
            counters: inner.counters,
            hours,
            top_queried: saved_names(&inner.queried),
            top_blocked: saved_names(&inner.blocked),
            top_clients: inner
                .clients
                .top()
                .into_iter()
                .map(|entry| (entry.key, entry.count, entry.max_error))
                .collect(),
            upstreams: Vec::new(),
        }
    }

    /// Puts what `saved` read back from the file in place of what is counted now. Hours
    /// outside the retention or in the future, and names that are not names, are skipped; a
    /// top list keeps the highest counts that fit.
    pub fn restore(&self, saved: &SavedStats) {
        let now = (self.clock)();
        let now_hour = now / SECONDS_PER_HOUR;
        let mut inner = self.inner.lock().unwrap();
        let kept_hours = retention_hours(inner.retention_days);

        inner.since = saved.since.min(now);
        inner.counters = saved.counters;
        inner.hours.fill(Hour::default());

        for &(number, total, blocked) in &saved.hours {
            if is_kept(number, now_hour, kept_hours) {
                inner.hours[number as usize % MAX_HISTORY_HOURS] = Hour {
                    number,
                    total,
                    blocked: blocked.min(total),
                };
            }
        }

        inner.queried.fill(restored_names(&saved.top_queried));
        inner.blocked.fill(restored_names(&saved.top_blocked));
        inner.clients.fill(
            saved
                .top_clients
                .iter()
                .map(|&(key, count, error)| Counted {
                    key,
                    count,
                    error: error.min(count),
                })
                .collect(),
        );
    }
}

fn clamp_retention(days: u32) -> u32 {
    days.clamp(1, RETENTION_CHOICES[RETENTION_CHOICES.len() - 1])
}

fn retention_hours(days: u32) -> u64 {
    u64::from(days) * 24
}

/// Whether the hour `number` is not in the future and lies within the last `kept_hours`.
fn is_kept(number: u64, now_hour: u64, kept_hours: u64) -> bool {
    number <= now_hour && now_hour - number < kept_hours
}

fn saved_names(top: &TopK<Name>) -> Vec<(String, u64, u64)> {
    top.top()
        .into_iter()
        .map(|entry| (to_hex(entry.key.as_wire()), entry.count, entry.max_error))
        .collect()
}

fn restored_names(saved: &[(String, u64, u64)]) -> Vec<Counted<Name>> {
    saved
        .iter()
        .filter(|&&(_, count, _)| count > 0)
        .filter_map(|(hex, count, error)| {
            let wire = from_hex(hex)?;
            let (name, end) = read_name(&wire, 0).ok()?;

            (end == wire.len()).then_some(Counted {
                key: name,
                count: *count,
                error: (*error).min(*count),
            })
        })
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }

    text
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }

    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16)?;
            let low = char::from(pair[1]).to_digit(16)?;

            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

fn shown_top(top: &TopK<Name>) -> Vec<TopEntry<Box<str>>> {
    top.top()
        .into_iter()
        .map(|entry| entry.with_key(|name| shown(&name)))
        .collect()
}

/// The text of a name for people: escaped, and cut with a mark when it is long.
fn shown(name: &Name) -> Box<str> {
    let mut text = name.to_string();

    if text.len() > SHOWN_NAME_BYTES {
        // The text of a name is ASCII, so a cut never splits a character.
        text.truncate(SHOWN_NAME_BYTES);
        text.push(CUT_MARK);
    }

    text.into()
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

    fn name(text: &str) -> Name {
        Name::from_text(text).unwrap()
    }

    fn event(qname: &Name, result: QueryResult) -> Event<'_> {
        Event {
            client: client(2),
            qname,
            qtype: 1,
            result,
            upstream: None,
            latency: Duration::from_micros(100),
        }
    }

    fn record(stats: &Stats, qname: &str, result: QueryResult) {
        stats.record(&event(&name(qname), result));
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
            ..StatsSettings::default()
        }
    }

    #[test]
    fn counters_follow_each_result() {
        let (stats, _) = stats_at(StatsSettings::default(), MIDNIGHT);

        let results = [
            (QueryResult::Pass, 3),
            (QueryResult::BlockedRequest, 2),
            (QueryResult::BlockedResponse, 4),
            (QueryResult::Cached, 5),
            (QueryResult::Rewritten, 6),
            (QueryResult::Error, 1),
        ];
        for (result, times) in results {
            for _ in 0..times {
                record(&stats, "example.com", result);
            }
        }

        stats.record_dropped();
        stats.record_dropped();

        assert_eq!(
            stats.snapshot().counters,
            Counters {
                total: 21,
                blocked_request: 2,
                blocked_response: 4,
                cached: 5,
                upstream: 3,
                rewritten: 6,
                errors: 1,
                dropped: 2,
            }
        );
    }

    #[test]
    fn clients_are_counted_per_address() {
        let (stats, _) = stats_at(StatsSettings::default(), MIDNIGHT);

        for last in [7, 7, 7, 9] {
            let qname = name("example.com");
            let mut query = event(&qname, QueryResult::Pass);
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

        record(&stats, "example.com", QueryResult::Pass);
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
            record(&stats, name, QueryResult::Pass);
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

    /// Three labels of 60 bytes that print as `\255` each: 720 characters of text. Names for
    /// different `last` bytes share their first 716.
    fn escaped_name(last: u8) -> Name {
        let mut wire = Vec::new();
        for _ in 0..3 {
            wire.push(60);
            wire.extend_from_slice(&[0xff; 60]);
        }

        wire.push(0);
        wire[181] = last;

        read_name(&wire, 0).unwrap().0
    }

    #[test]
    fn a_short_name_is_shown_whole_in_lowercase() {
        assert_eq!(&*shown(&name("Www.Example.COM.")), "www.example.com");
    }

    #[test]
    fn a_long_name_is_shown_cut_and_marked() {
        let text = shown(&escaped_name(1));

        assert!(text.starts_with("\\255\\255"));
        assert!(text.ends_with(CUT_MARK));
        assert_eq!(text.len(), SHOWN_NAME_BYTES + CUT_MARK.len_utf8());
    }

    #[test]
    fn names_that_look_alike_once_cut_are_separate_entries_and_log_lines() {
        let (stats, _) = stats_at(small(5, 5), MIDNIGHT);
        let (first, second) = (escaped_name(1), escaped_name(2));

        for qname in [&first, &second, &first] {
            stats.record(&event(qname, QueryResult::BlockedRequest));
        }

        let counts = |top: Vec<TopEntry<Box<str>>>| top.iter().map(|e| e.count).collect::<Vec<_>>();
        let snapshot = stats.snapshot();
        assert_eq!(counts(snapshot.top_queried), [2, 1]);
        assert_eq!(counts(snapshot.top_blocked), [2, 1]);
        assert_eq!(logged_names(&stats, 3)[0], *shown(&first));
    }

    #[test]
    fn query_log_overwrites_the_oldest_entry_first() {
        let (stats, _) = stats_at(small(5, 3), MIDNIGHT);

        for number in 1..=7 {
            record(&stats, &format!("q{number}.example"), QueryResult::Pass);
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
            qname: &name("example.com"),
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
        let qname = name("example.com");
        let mut query = event(&qname, QueryResult::Pass);
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

        record(&stats, "a.example", QueryResult::Pass);
        record(&stats, "b.example", QueryResult::BlockedRequest);
        time.store(MIDNIGHT + HOUR / 6, Ordering::Relaxed);
        record(&stats, "c.example", QueryResult::Pass);
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

        record(&stats, "a.example", QueryResult::Pass);
        time.store(MIDNIGHT + 15 * HOUR + 5, Ordering::Relaxed);
        record(&stats, "b.example", QueryResult::Pass);
        record(&stats, "b.example", QueryResult::Pass);

        let mut expected = vec![0; 24];
        expected[23] = 2;
        expected[18] = 1;
        assert_eq!(totals(&stats), expected);
    }

    #[test]
    fn a_slot_is_cleared_when_its_hour_comes_round_again() {
        let (stats, time) = stats_at(StatsSettings::default(), MIDNIGHT + 3 * HOUR);

        for _ in 0..4 {
            record(&stats, "a.example", QueryResult::BlockedRequest);
        }

        let round_again = MIDNIGHT + (3 + MAX_HISTORY_HOURS as u64) * HOUR;
        time.store(round_again, Ordering::Relaxed);
        record(&stats, "b.example", QueryResult::Pass);
        let hourly = stats.snapshot().hourly;

        assert_eq!((hourly[23].total, hourly[23].blocked), (1, 0));
        assert_eq!(totals(&stats).iter().sum::<u64>(), 1);
        assert_eq!(
            stats.daily(90, 0).iter().map(|day| day.total).sum::<u64>(),
            1
        );
    }

    #[test]
    fn reading_after_a_quiet_day_shows_nothing_but_keeps_the_counters() {
        let (stats, time) = stats_at(StatsSettings::default(), MIDNIGHT);

        record(&stats, "a.example", QueryResult::Pass);
        time.store(MIDNIGHT + 2 * 86_400, Ordering::Relaxed);

        assert_eq!(totals(&stats), vec![0; 24]);
        assert_eq!(stats.snapshot().counters.total, 1);
    }

    #[test]
    fn a_day_of_consecutive_hours_fills_every_bucket() {
        let (stats, time) = stats_at(StatsSettings::default(), MIDNIGHT);

        for hour in 0..30 {
            time.store(MIDNIGHT + hour * HOUR, Ordering::Relaxed);
            record(&stats, "a.example", QueryResult::Pass);
        }

        assert_eq!(totals(&stats), vec![1; 24]);
    }

    fn retaining(days: u32) -> StatsSettings {
        StatsSettings {
            retention_days: days,
            ..StatsSettings::default()
        }
    }

    /// One query in each of `hours` consecutive hours ending at `last_hour`.
    fn one_query_an_hour(stats: &Stats, time: &AtomicU64, last_hour: u64, hours: u64) {
        for hour in (last_hour + 1 - hours)..=last_hour {
            time.store(hour * HOUR, Ordering::Relaxed);
            record(stats, "a.example", QueryResult::Pass);
        }
    }

    fn day_totals(stats: &Stats, days: u32, offset: i32) -> Vec<u64> {
        stats
            .daily(days, offset)
            .iter()
            .map(|day| day.total)
            .collect()
    }

    #[test]
    fn the_ring_holds_ninety_days_of_hours() {
        let (stats, time) = stats_at(retaining(90), MIDNIGHT);
        let last_hour = MIDNIGHT / HOUR + 24 * 100 + 23;

        one_query_an_hour(&stats, &time, last_hour, 24 * 100);

        assert_eq!(stats.daily(90, 0).len(), 90);
        assert_eq!(day_totals(&stats, 90, 0), vec![24; 90]);
        assert_eq!(totals(&stats), vec![1; 24]);
    }

    #[test]
    fn days_are_cut_to_the_retention() {
        let (stats, time) = stats_at(retaining(7), MIDNIGHT);

        one_query_an_hour(&stats, &time, MIDNIGHT / HOUR + 24 * 30 + 23, 24 * 30);

        assert_eq!(day_totals(&stats, 90, 0), vec![24; 7]);
        assert_eq!(day_totals(&stats, 3, 0), vec![24; 3]);
        assert!(stats.daily(0, 0).is_empty());
    }

    #[test]
    fn days_follow_the_time_zone_of_the_viewer() {
        let (stats, time) = stats_at(retaining(30), MIDNIGHT + 2 * HOUR);

        record(&stats, "a.example", QueryResult::BlockedRequest);
        time.store(MIDNIGHT + 22 * HOUR, Ordering::Relaxed);
        record(&stats, "a.example", QueryResult::Pass);
        let counts = |days: &[DailyBucket]| -> Vec<(u64, u64)> {
            days.iter().map(|day| (day.total, day.blocked)).collect()
        };

        let utc = stats.daily(2, 0);
        assert_eq!(utc[1].day_start, MIDNIGHT);
        assert_eq!(utc[0].day_start, MIDNIGHT - 86_400);
        assert_eq!(counts(&utc), [(0, 0), (2, 1)]);

        // 22:00 UTC is already tomorrow three hours east of Greenwich.
        let east = stats.daily(2, 3 * 3_600);
        assert_eq!(east[1].day_start, MIDNIGHT + 86_400 - 3 * 3_600);
        assert_eq!(counts(&east), [(1, 1), (1, 0)]);

        // 02:00 UTC is still yesterday five hours west.
        let west = stats.daily(2, -5 * 3_600);
        assert_eq!(west[1].day_start, MIDNIGHT + 5 * 3_600);
        assert_eq!(counts(&west), [(1, 1), (1, 0)]);
    }

    #[test]
    fn shortening_the_retention_drops_older_hours_for_good() {
        let (stats, time) = stats_at(retaining(30), MIDNIGHT);
        one_query_an_hour(&stats, &time, MIDNIGHT / HOUR + 24 * 30 + 23, 24 * 30);

        stats.set_retention(7);
        assert_eq!(stats.retention_days(), 7);
        assert_eq!(day_totals(&stats, 30, 0), vec![24; 7]);

        stats.set_retention(30);
        assert_eq!(stats.retention_days(), 30);
        assert_eq!(
            day_totals(&stats, 30, 0).iter().sum::<u64>(),
            7 * 24,
            "the hours dropped at 7 days do not come back"
        );
    }

    #[test]
    fn hours_that_age_past_the_retention_drop_out_before_a_longer_one_returns() {
        let (stats, time) = stats_at(retaining(1), MIDNIGHT);
        record(&stats, "a.example", QueryResult::Pass);
        time.store(MIDNIGHT + 30 * HOUR, Ordering::Relaxed);

        stats.set_retention(7);

        assert_eq!(day_totals(&stats, 7, 0).iter().sum::<u64>(), 0);
    }

    #[test]
    fn clear_starts_over_but_keeps_the_query_log_and_the_capacity() {
        let (stats, time) = stats_at(small(5, 10), MIDNIGHT);
        for _ in 0..3 {
            record(&stats, "ads.example", QueryResult::BlockedRequest);
        }

        time.store(MIDNIGHT + 2 * HOUR, Ordering::Relaxed);
        stats.record_dropped();
        stats.clear();
        let snapshot = stats.snapshot();

        assert_eq!(snapshot.since, MIDNIGHT + 2 * HOUR);
        assert_eq!(snapshot.counters, Counters::default());
        assert!(snapshot.top_queried.is_empty());
        assert!(snapshot.top_blocked.is_empty());
        assert!(snapshot.top_clients.is_empty());
        assert_eq!(totals(&stats), vec![0; 24]);
        assert_eq!(day_totals(&stats, 1, 0), vec![0]);
        assert_eq!(stats.query_log(10).len(), 3);

        for number in 0..5 {
            record(&stats, &format!("n{number}.example"), QueryResult::Pass);
        }

        assert_eq!(stats.snapshot().top_queried.len(), 5);
    }

    #[test]
    fn clearing_the_query_log_keeps_the_statistics() {
        let (stats, _) = stats_at(small(5, 3), MIDNIGHT);
        for number in 0..5 {
            record(&stats, &format!("n{number}.example"), QueryResult::Pass);
        }

        stats.clear_query_log();

        assert!(stats.query_log(10).is_empty());
        assert_eq!(stats.snapshot().counters.total, 5);

        for number in 0..4 {
            record(&stats, &format!("m{number}.example"), QueryResult::Pass);
        }

        assert_eq!(
            logged_names(&stats, 10),
            ["m3.example", "m2.example", "m1.example"]
        );
    }

    #[test]
    fn since_is_the_start_until_a_clear() {
        let (stats, time) = stats_at(StatsSettings::default(), MIDNIGHT + 5);
        assert_eq!(stats.snapshot().since, MIDNIGHT + 5);

        time.store(MIDNIGHT + 99, Ordering::Relaxed);
        record(&stats, "a.example", QueryResult::Pass);
        assert_eq!(stats.snapshot().since, MIDNIGHT + 5);
    }

    fn busy_stats() -> (Stats, Arc<AtomicU64>) {
        let (stats, time) = stats_at(small(3, 10), MIDNIGHT + 40 * HOUR);

        for number in 0..4 {
            let qname = name(&format!("n{number}.example"));
            for _ in 0..=number {
                stats.record(&Event {
                    client: client(number + 1),
                    ..event(&qname, QueryResult::Pass)
                });
            }
        }

        for hour in 1..=5 {
            time.store(MIDNIGHT + (40 + hour) * HOUR, Ordering::Relaxed);
            record(&stats, "ads.example", QueryResult::BlockedResponse);
        }

        stats.record_dropped();

        (stats, time)
    }

    #[test]
    fn what_is_saved_comes_back() {
        let (stats, time) = busy_stats();
        let saved = stats.saved();
        let (other, other_time) = stats_at(small(3, 10), 0);
        other_time.store(time.load(Ordering::Relaxed), Ordering::Relaxed);

        other.restore(&saved);

        assert_eq!(other.saved(), saved);
        assert_eq!(other.snapshot().top_queried.len(), 3);
        assert_eq!(other.snapshot().counters, stats.snapshot().counters);
        assert_eq!(other.snapshot().since, saved.since);
        assert_eq!(day_totals(&other, 3, 0), day_totals(&stats, 3, 0));
        assert_eq!(saved.hours.len(), 6);
        assert!(saved.hours.windows(2).all(|pair| pair[0].0 < pair[1].0));
    }

    #[test]
    fn a_saved_top_list_keeps_the_highest_counts_that_fit() {
        let (stats, time) = busy_stats();
        let saved = stats.saved();
        let (fewer, fewer_time) = stats_at(small(2, 10), 0);
        fewer_time.store(time.load(Ordering::Relaxed), Ordering::Relaxed);

        fewer.restore(&saved);
        let top = fewer.snapshot().top_queried;

        let counts: Vec<u64> = top.iter().map(|entry| entry.count).collect();
        let expected: Vec<u64> = saved.top_queried.iter().take(2).map(|row| row.1).collect();
        assert_eq!(counts, expected);
        assert_eq!(top.len(), 2);
    }

    #[test]
    fn restore_skips_old_future_and_malformed_entries() {
        let (stats, time) = stats_at(retaining(7), MIDNIGHT + 10 * HOUR);
        let now_hour = time.load(Ordering::Relaxed) / HOUR;
        let mut saved = busy_stats().0.saved();
        saved.since = u64::MAX;
        saved.hours = vec![
            (now_hour, 4, 9),
            (now_hour - 7 * 24, 5, 0),
            (now_hour - 7 * 24 + 1, 6, 1),
            (now_hour + 1, 7, 0),
        ];
        saved.top_queried = vec![
            ("not hex".to_string(), 9, 0),
            ("03777777".to_string(), 8, 0),
            ("076578616d706c6500".to_string(), 7, 99),
            ("076578616d706c650000".to_string(), 6, 0),
            ("076578616d706c6500".to_string(), 0, 0),
        ];

        stats.restore(&saved);
        let snapshot = stats.snapshot();

        assert_eq!(snapshot.since, time.load(Ordering::Relaxed));
        assert_eq!(snapshot.hourly[23].total, 4);
        assert_eq!(snapshot.hourly[23].blocked, 4);
        assert_eq!(
            stats.saved().hours,
            [(now_hour - 7 * 24 + 1, 6, 1), (now_hour, 4, 4)]
        );
        let names: Vec<(String, u64, u64)> = snapshot
            .top_queried
            .iter()
            .map(|entry| (entry.key.to_string(), entry.count, entry.max_error))
            .collect();
        assert_eq!(names, [("example".to_string(), 7, 7)]);
    }
}
