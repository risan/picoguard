//! Memory held by full stats with long names. This file has its own test
//! binary so that the counting allocator sees only this one test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use picoguard::stats::{Event, QueryResult, Stats, StatsSettings};

const BUDGET_BYTES: usize = 512 * 1024;
/// What a malloc implementation adds to every block, on top of the size asked for.
const ALLOCATION_OVERHEAD: usize = 16;

struct CountingAllocator;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static LIVE_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
            LIVE_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }

        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        LIVE_ALLOCATIONS.fetch_sub(1, Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const LONG_NAME_LENGTH: usize = 4 * 61 + 3 + 4;

/// A name of 251 bytes, close to the DNS maximum of 253, that differs for every `number`.
fn long_name(number: usize) -> String {
    let label = format!("{number:0>8}{}", "x".repeat(53));

    format!("{label}.{label}.{label}.{label}.com")
}

#[test]
fn full_stats_with_long_names_stay_within_half_a_megabyte() {
    let bytes_before = LIVE_BYTES.load(Ordering::Relaxed);
    let allocations_before = LIVE_ALLOCATIONS.load(Ordering::Relaxed);
    let stats = Stats::new(StatsSettings::default());

    for number in 0..20_000 {
        let name = long_name(number);
        assert_eq!(name.len(), LONG_NAME_LENGTH);
        let result = if number % 2 == 0 {
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

    let bytes = LIVE_BYTES.load(Ordering::Relaxed) - bytes_before;
    let allocations = LIVE_ALLOCATIONS.load(Ordering::Relaxed) - allocations_before;
    let with_overhead = bytes + allocations * ALLOCATION_OVERHEAD;
    println!(
        "stats memory: {bytes} bytes in {allocations} allocations, {with_overhead} with malloc overhead"
    );

    assert_eq!(stats.query_log(usize::MAX).len(), 1_000);
    assert_eq!(stats.snapshot().top_queried.len(), 50);
    assert!(
        with_overhead <= BUDGET_BYTES,
        "stats hold {with_overhead} bytes, budget {BUDGET_BYTES}"
    );
}
