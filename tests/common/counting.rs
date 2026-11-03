//! The counting allocator of the memory tests. A test binary installs it with
//! `#[global_allocator] static ALLOCATOR: counting::Counting = counting::Counting;` and reads the
//! counters through the functions below. It pulls this file in with
//! `#[path = "common/counting.rs"] mod counting;` instead of `mod common;`, which would drag in
//! the DNS and HTTP helpers.
//!
//! A `realloc` is counted as a move: the old and the new block are both live until the copy is
//! done, so the peak sees both. The counters belong to the process, so a binary whose tests
//! measure must not run them at the same time.

#![allow(dead_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

pub struct Counting;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);
static LIVE_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

fn grow(bytes: usize) {
    let live = LIVE_BYTES.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            grow(layout.size());
            LIVE_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }

        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        LIVE_ALLOCATIONS.fetch_sub(1, Ordering::Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        grow(new_size);
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);

        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

/// The bytes allocated and not yet freed.
pub fn live() -> usize {
    LIVE_BYTES.load(Ordering::Relaxed)
}

/// The blocks allocated and not yet freed.
pub fn live_allocations() -> usize {
    LIVE_ALLOCATIONS.load(Ordering::Relaxed)
}

/// The most live bytes since the last `reset_peak`.
pub fn peak_bytes() -> usize {
    PEAK_BYTES.load(Ordering::Relaxed)
}

/// Starts a peak measurement; returns the live bytes it counts from.
pub fn reset_peak() -> usize {
    let live = live();
    PEAK_BYTES.store(live, Ordering::Relaxed);

    live
}

/// How far the peak rose above `before`.
pub fn peak_since(before: usize) -> usize {
    peak_bytes().saturating_sub(before)
}

/// Lets the drops that run on other tasks finish before a reading.
pub async fn settle() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}
