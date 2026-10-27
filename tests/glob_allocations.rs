//! Matching a glob rule allocates nothing for a name that fits a DNS message. This file has
//! its own test binary so that the counting allocator sees only this one test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use picoguard::filter::pattern::Matcher;

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // Only the matching thread is counted: the test harness may allocate on its own
    // threads at any time (seen on a GitHub runner).
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

fn count() {
    if COUNTING.with(Cell::get) {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();

        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count();

        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn matching_a_glob_with_wildcards_allocates_nothing() {
    let patterns = ["||ad*.example^", "*a*b*c^", "|x*y|", "ads*.*^"];
    let matchers: Vec<Matcher> = patterns
        .iter()
        .map(|pattern| Matcher::compile(pattern).unwrap())
        .collect();
    let long = format!("{}.example", "a".repeat(240));
    let hosts = ["ads1.example", "www.ad.example", "xy", "cab.org", &long];
    let urls: Vec<String> = hosts.iter().map(|host| format!("http://{host}")).collect();

    let mut matched = 0;
    COUNTING.with(|counting| counting.set(true));
    for _ in 0..200 {
        for matcher in &matchers {
            for (host, url) in hosts.iter().zip(&urls) {
                matched += usize::from(matcher.is_match(host, url));
            }
        }
    }

    COUNTING.with(|counting| counting.set(false));
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);

    assert!(matched > 0);
    assert_eq!(allocations, 0, "allocations while matching 4000 checks");
}
