//! Counting an exchange allocates nothing. This file has its own test binary so that the
//! counting allocator sees only this one test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use picoguard::upstream::Tally;

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    // Only the counting thread is counted: the test harness may allocate on its own
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

const EXCHANGES: u64 = 10_000;

#[test]
fn counting_exchanges_allocates_nothing() {
    let tally = Mutex::new(Tally::default());

    COUNTING.with(|counting| counting.set(true));
    for number in 0..EXCHANGES {
        let mut tally = tally.lock().unwrap();

        if number % 4 == 3 {
            tally.count_failure();
        } else {
            tally.count_answer(Duration::from_micros(number));
        }

        tally.average_ms();
    }
    COUNTING.with(|counting| counting.set(false));
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);
    let tally = tally.lock().unwrap();

    assert_eq!(allocations, 0, "allocations while counting 10000 exchanges");
    assert_eq!(tally.answered + tally.failed, EXCHANGES);
}
