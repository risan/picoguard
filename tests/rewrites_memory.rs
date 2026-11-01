//! What the rewrite table holds (plan D7): 1000 rewrites, the most the config and the page
//! allow, within an explicit budget, and replacing the table from the page leaves nothing
//! behind. This file has its own test binary so that the counting allocator sees only this
//! one test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use picoguard::config::{Config, Rewrite};
use picoguard::pipeline::Pipeline;
use picoguard::policy::Policy;
use picoguard::rewrites::Rewrites;

const ENTRIES: usize = 1000;
const SWAPS: usize = 20;
/// 1000 home names, 900 with an address and 100 wildcards with a target name. Measured:
/// 80,170 bytes.
const TYPICAL_BUDGET: usize = 96 * 1024;
/// 1000 names of 239 characters, each with a target name as long. Measured:
/// 520,960 bytes.
const LONGEST_BUDGET: usize = 640 * 1024;

struct CountingAllocator;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }

        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn live() -> usize {
    LIVE_BYTES.load(Ordering::Relaxed)
}

fn rewrite(name: String, answer: String) -> Rewrite {
    Rewrite { name, answer }
}

fn typical() -> Vec<Rewrite> {
    (0..ENTRIES)
        .map(|index| {
            if index < 900 {
                rewrite(
                    format!("host-{index}.home.lan"),
                    format!("192.168.{}.{}", index / 250, index % 250 + 1),
                )
            } else {
                rewrite(
                    format!("*.svc-{index}.home.lan"),
                    format!("host-{}.home.lan", index - 900),
                )
            }
        })
        .collect()
}

/// A name of four labels, 239 characters in all, unique to `index` and `kind`.
fn long_name(kind: &str, index: usize) -> String {
    let label = |part: usize| format!("{kind}{index:04}{part}{}", "x".repeat(53));

    format!("{}.{}.{}.{}", label(1), label(2), label(3), label(4))
}

fn longest() -> Vec<Rewrite> {
    (0..ENTRIES)
        .map(|index| rewrite(long_name("a", index), long_name("t", index)))
        .collect()
}

/// 500 addresses on one name, and 500 names rewritten to it: the aliases share the
/// addresses. Measured: 38,995 bytes; a copy for each alias held 4,288,995.
const SHARED_BUDGET: usize = 48 * 1024;

/// One name with 500 addresses, and 500 aliases whose target is that name, so each answers
/// with its addresses.
fn shared() -> Vec<Rewrite> {
    (0..ENTRIES)
        .map(|index| {
            if index < ENTRIES / 2 {
                rewrite(
                    "many.home.lan".to_string(),
                    format!("10.0.{}.{}", index / 250, index % 250 + 1),
                )
            } else {
                rewrite(
                    format!("alias-{index}.home.lan"),
                    "many.home.lan".to_string(),
                )
            }
        })
        .collect()
}

/// The bytes the table of `rewrites` holds once built.
fn held_by(rewrites: &[Rewrite]) -> (Rewrites, usize) {
    let before = live();
    let table = Rewrites::new(rewrites).unwrap();

    (table, live() - before)
}

#[tokio::test]
async fn a_thousand_rewrites_fit_their_budget_and_replacing_them_leaves_nothing() {
    let typical = typical();
    let longest = longest();
    assert!(longest.iter().all(|entry| entry.name.len() == 239));

    let (typical_table, typical_bytes) = held_by(&typical);
    let (longest_table, longest_bytes) = held_by(&longest);
    let (shared_table, shared_bytes) = held_by(&shared());
    println!(
        "1000 rewrites hold {typical_bytes} bytes; with the longest names {longest_bytes}; \
         500 addresses on one name and 500 aliases of it {shared_bytes}"
    );

    assert_eq!(typical_table.len(), ENTRIES);
    assert_eq!(shared_table.len(), ENTRIES / 2 + 1);
    assert!(typical_bytes <= TYPICAL_BUDGET, "{typical_bytes}");
    assert!(longest_bytes <= LONGEST_BUDGET, "{longest_bytes}");
    assert!(shared_bytes <= SHARED_BUDGET, "{shared_bytes}");
    drop((typical_table, longest_table, shared_table));

    let mut config = Config::default();
    config.upstream.servers = vec!["udp://127.0.0.1:9".to_string()];
    config.rewrites = typical.clone();
    let pipeline = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();
    let before = live();
    for swap in 0..SWAPS {
        let rewrites = if swap % 2 == 0 { &longest } else { &typical };
        let replaced = pipeline.replace_rewrites(Arc::new(Rewrites::new(rewrites).unwrap()));
        drop(replaced);
    }

    let after = live();
    println!("after {SWAPS} replacements: {before} -> {after} bytes");
    assert!(
        after <= before + 1024,
        "{} bytes more after {SWAPS} replacements",
        after.saturating_sub(before)
    );
}
