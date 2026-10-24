//! Heap cost of plain rules. This test binary has a counting global allocator and a single
//! test, so nothing else allocates while it measures.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use picoguard::filter::engine::CompiledList;
use picoguard::filter::parse::ListFormat;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size(), Ordering::Relaxed);

        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.fetch_add(new_size, Ordering::Relaxed);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);

        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

const RULES: usize = 450_000;

#[test]
fn a_plain_rule_costs_at_most_nine_bytes_of_heap() {
    let mut text = String::with_capacity(RULES * 30);
    for n in 0..RULES {
        text.push_str(&format!("||host{n}.tracker{}.example^\n", n % 977));
    }

    let before = LIVE.load(Ordering::Relaxed);
    let (list, summary) = CompiledList::from_text(ListFormat::Adblock, &text);
    let after = LIVE.load(Ordering::Relaxed);

    assert_eq!(summary.counters.block_sub, RULES as u64);
    assert_eq!(list.rule_count(), RULES);

    let per_rule = (after - before) as f64 / RULES as f64;
    println!("heap per plain rule: {per_rule:.3} bytes");
    assert!(per_rule <= 9.0, "{per_rule} bytes per rule");
}
