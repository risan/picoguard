//! Recording a query allocates nothing once the query log has been filled and the top lists
//! know the names. This file has its own test binary so that the counting allocator sees
//! only this one test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use picoguard::stats::{Event, QueryResult, Stats, StatsSettings};

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);

        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);

        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const NAMES: usize = 10;
const LOG_ENTRIES: usize = 100;

/// Every name has the same length, so a ring slot warmed with one name holds any other.
fn names_for(queries: usize) -> Vec<String> {
    (0..queries)
        .map(|number| format!("name{:02}.example", number % NAMES))
        .collect()
}

fn record_all(stats: &Stats, names: &[String]) {
    for (number, name) in names.iter().enumerate() {
        let result = if (number / NAMES).is_multiple_of(2) {
            QueryResult::BlockedRequest
        } else {
            QueryResult::Pass
        };

        stats.record(&Event {
            client: IpAddr::V4(Ipv4Addr::new(192, 168, 1, (number % 5) as u8)),
            qname: name,
            qtype: 1,
            result,
            upstream: Some(0),
            latency: Duration::from_micros(500),
        });
    }
}

#[test]
fn recording_a_query_allocates_nothing_once_the_ring_is_warm() {
    let stats = Stats::new(StatsSettings {
        top_k: 50,
        query_log_entries: LOG_ENTRIES,
    });
    record_all(&stats, &names_for(LOG_ENTRIES * 4));
    let names = names_for(5_000);

    let before = ALLOCATIONS.load(Ordering::Relaxed);
    record_all(&stats, &names);
    let allocations = ALLOCATIONS.load(Ordering::Relaxed) - before;

    assert_eq!(allocations, 0, "allocations while recording 5000 queries");
    assert_eq!(stats.query_log(usize::MAX).len(), LOG_ENTRIES);
}
