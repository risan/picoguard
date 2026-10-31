//! Memory held by a full device-name table. This file has its own test binary so that the
//! counting allocator sees only this one test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use picoguard::names::{Found, MAX_LOOKUPS, MAX_NAMES, NameTable};

const BUDGET_BYTES: usize = 40_000;
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

fn address(number: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + number as u32))
}

/// Shows and settles `count` addresses from `first`, `MAX_LOOKUPS` at a time.
fn fill(table: &mut NameTable, first: usize, count: usize, name: impl Fn(usize) -> String) {
    let now = Instant::now();
    let numbers: Vec<usize> = (first..first + count).collect();
    for batch in numbers.chunks(MAX_LOOKUPS) {
        for number in batch {
            assert!(table.shown(address(*number), now).look_up);
        }

        for number in batch {
            let found = Found {
                name: name(*number).into(),
                ttl: 3600,
            };
            table.settle(address(*number), Some(found), now);
        }
    }
}

fn measured(bytes_before: usize, allocations_before: usize, phase: &str) -> usize {
    let bytes = LIVE_BYTES.load(Ordering::Relaxed) - bytes_before;
    let allocations = LIVE_ALLOCATIONS.load(Ordering::Relaxed) - allocations_before;
    let with_overhead = bytes + allocations * ALLOCATION_OVERHEAD;
    println!(
        "device names, {phase}: {bytes} bytes in {allocations} allocations, {with_overhead} with malloc overhead"
    );

    with_overhead
}

#[test]
fn a_full_name_table_stays_within_40_kb() {
    let bytes_before = LIVE_BYTES.load(Ordering::Relaxed);
    let allocations_before = LIVE_ALLOCATIONS.load(Ordering::Relaxed);
    let mut table = NameTable::new(MAX_LOOKUPS);

    fill(&mut table, 0, MAX_NAMES, |number| {
        format!("device-{number:03}.lan")
    });

    assert_eq!(table.len(), MAX_NAMES);
    let typical = measured(bytes_before, allocations_before, "typical names");
    assert!(
        typical <= BUDGET_BYTES,
        "a table of typical names holds {typical} bytes, budget {BUDGET_BYTES}"
    );

    fill(&mut table, MAX_NAMES, 300, |number| {
        format!("{number:0>8}{}", "x".repeat(245))
    });

    assert!(table.len() <= MAX_NAMES);
    let longest = measured(bytes_before, allocations_before, "253-byte names");
    assert!(
        longest <= BUDGET_BYTES,
        "a table of 253-byte names holds {longest} bytes, budget {BUDGET_BYTES}"
    );
}
