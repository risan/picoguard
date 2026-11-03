//! Memory held by full stats with long names and a full 90-day history. This file has its own
//! test binary so that the counting allocator sees only this one test.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use picoguard::dns::wire::Name;
use picoguard::stats::{Event, HISTORY_BYTES, QueryResult, Stats, StatsSettings};

const BUDGET_BYTES: usize = 512 * 1024;
/// What a malloc implementation adds to every block, on top of the size asked for.
const ALLOCATION_OVERHEAD: usize = 16;

#[path = "common/counting.rs"]
mod counting;

use counting::{live, live_allocations};

#[global_allocator]
static ALLOCATOR: counting::Counting = counting::Counting;

/// 2023-11-14 00:00:00 UTC.
const START: u64 = 19_675 * 86_400;

const LONG_NAME_LENGTH: usize = 4 * 61 + 3 + 4;

/// A name of 251 bytes, close to the DNS maximum of 253, that differs for every `number`.
fn long_name(number: usize) -> String {
    name_with_tld(number, "com")
}

fn name_with_tld(number: usize, tld: &str) -> String {
    let label = format!("{number:0>8}{}", "x".repeat(53));

    format!("{label}.{label}.{label}.{label}.{tld}")
}

fn record(stats: &Stats, number: usize, text: &str) {
    let name = Name::from_text(text).unwrap();
    let result = if number.is_multiple_of(2) {
        QueryResult::BlockedRequest
    } else {
        QueryResult::Pass
    };
    stats.record(&Event {
        client: IpAddr::V4(Ipv4Addr::from(number as u32)),
        qname: &name,
        qtype: 1,
        result,
        upstream: Some(0),
        latency: Duration::from_micros(500),
    });
}

#[test]
fn full_stats_with_long_names_and_ninety_days_stay_within_the_budget() {
    let bytes_before = live();
    let allocations_before = live_allocations();
    let time = Arc::new(AtomicU64::new(START));
    let clock = Arc::clone(&time);
    let stats = Stats::with_clock(
        StatsSettings {
            retention_days: 90,
            ..StatsSettings::default()
        },
        Box::new(move || clock.load(Ordering::Relaxed)),
    );

    // Fill the query-log ring with slightly shorter names first: overwriting a slot with a
    // longer name must not double the slot's buffer.
    for number in 0..1_000 {
        record(&stats, number, &name_with_tld(number, "c"));
    }

    // Nine queries an hour for 100 days, ending at the end of a day: every slot of the ring
    // is used, then reused.
    for number in 0..21_600 {
        time.store(START + (number as u64 / 9) * 3_600, Ordering::Relaxed);
        let text = long_name(number);
        assert_eq!(text.len(), LONG_NAME_LENGTH);
        record(&stats, number, &text);
    }

    let bytes = live() - bytes_before;
    let allocations = live_allocations() - allocations_before;
    let with_overhead = bytes + allocations * ALLOCATION_OVERHEAD;
    println!(
        "stats memory: {bytes} bytes in {allocations} allocations, {with_overhead} with malloc overhead"
    );

    assert_eq!(stats.query_log(usize::MAX).len(), 1_000);
    assert_eq!(stats.snapshot().top_queried.len(), 50);
    let days = stats.daily(90, 0);
    assert_eq!(days.len(), 90);
    assert_eq!(
        days.iter().map(|day| day.total).sum::<u64>(),
        90 * 24 * 9,
        "every hour of the last 90 days holds its nine queries"
    );
    assert!(bytes >= HISTORY_BYTES, "the ring is part of what is held");
    assert!(
        with_overhead <= BUDGET_BYTES,
        "stats hold {with_overhead} bytes, budget {BUDGET_BYTES}"
    );
}
