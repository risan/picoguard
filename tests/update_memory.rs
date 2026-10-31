//! What the update check holds while it runs and after it ends. This file has its own test
//! binary so that the counting allocator sees only these tests, which take turns.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::http::ListServer;
use picoguard::lists::{Downloader, Names};
use picoguard::update::{Build, Checker, Outcome, Updates};
use picoguard::upstream::tls::Tls;

const FIXTURE: &str = include_str!("fixtures/github/release-latest.json");
const PEAK_BUDGET_BYTES: usize = 512 * 1024;
const KEPT_BUDGET_BYTES: usize = 4 * 1024;
const FAILURE_BUDGET_BYTES: usize = 1024;
const MANY_WORDS_PEAK_BUDGET_BYTES: usize = 1024 * 1024;
const JSON: Option<&str> = Some("application/json");

struct CountingAllocator;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            let live = LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
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

/// The tests share one allocator, so they must not overlap.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn live() -> usize {
    LIVE_BYTES.load(Ordering::Relaxed)
}

fn start_measuring() -> usize {
    let before = live();
    PEAK_BYTES.store(before, Ordering::Relaxed);

    before
}

fn peak_since(before: usize) -> usize {
    PEAK_BYTES.load(Ordering::Relaxed).saturating_sub(before)
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

fn checker(url: &str) -> Checker {
    let downloader = Downloader::new(
        Names::Resolver(Arc::new(|_| {
            Box::pin(async { Err(io::Error::other("no DNS in this test")) })
        })),
        Arc::new(Tls::with_webpki_roots()),
    );

    Checker::new(downloader, url)
}

fn in_runtime(work: impl Future<Output = ()>) {
    let _turn = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(work);
}

/// One check with a throw-away checker, so that what tokio grows on first use is not counted.
async fn warm_up(url: &str) {
    let updates = Updates::new(Build::current());
    let mut checker = checker(url);
    checker.check(&updates).await;
    drop(checker);
    settle().await;
}

async fn measure_a_check_against(server: &ListServer, label: &str) {
    let url = server.url("/latest");
    warm_up(&url).await;
    let updates = Updates::new(Build::current());
    let mut checker = checker(&url);
    let before = start_measuring();

    let (outcome, _) = checker.check(&updates).await;
    settle().await;

    let peak = peak_since(before);
    let kept = live().saturating_sub(before);
    println!("update check ({label}): peak {peak} bytes, kept {kept} bytes");

    assert_eq!(outcome, Outcome::Newer("99.0.0".to_string()));
    assert!(peak < PEAK_BUDGET_BYTES, "peak {peak} bytes");
    assert!(kept < KEPT_BUDGET_BYTES, "kept {kept} bytes");
}

#[test]
fn a_check_peaks_below_half_a_megabyte_and_keeps_under_four_kilobytes() {
    in_runtime(async {
        let server = ListServer::start().await;
        server.serve_typed("/latest", FIXTURE, None, JSON);

        measure_a_check_against(&server, "no ETag").await;
    });
}

#[test]
fn the_longest_etag_is_held_within_the_same_bound() {
    in_runtime(async {
        let server = ListServer::start().await;
        let etag = format!("\"{}\"", "a".repeat(998));
        server.serve_typed("/latest", FIXTURE, Some(&etag), JSON);

        measure_a_check_against(&server, "1000-byte ETag").await;
    });
}

#[test]
fn a_failed_check_after_a_good_one_keeps_nothing_more() {
    in_runtime(async {
        let server = ListServer::start().await;
        server.serve_typed("/ok", FIXTURE, None, JSON);
        server.serve_typed("/big", &"x".repeat(300 * 1024), None, JSON);
        let good_url = server.url("/ok");
        warm_up(&good_url).await;
        let updates = Updates::new(Build::current());
        let mut good = checker(&good_url);
        let mut failing = checker(&server.url("/big"));

        good.check(&updates).await;
        settle().await;
        let before = start_measuring();

        let (outcome, _) = failing.check(&updates).await;
        settle().await;

        let peak = peak_since(before);
        let kept = live().saturating_sub(before);
        println!("failed update check: peak {peak} bytes, kept {kept} bytes");

        assert_ne!(outcome, Outcome::Newer("99.0.0".to_string()));
        assert_eq!(updates.view().latest.as_deref(), Some("99.0.0"));
        assert!(kept < FAILURE_BUDGET_BYTES, "kept {kept} bytes");
    });
}

#[test]
fn a_near_limit_answer_of_one_letter_words_stays_within_a_megabyte() {
    in_runtime(async {
        let notes = "a ".repeat(100_000);
        let answer = serde_json::json!({ "tag_name": "v99.0.0", "body": notes }).to_string();
        let server = ListServer::start().await;
        server.serve_typed("/latest", &answer, None, JSON);
        let url = server.url("/latest");
        warm_up(&url).await;
        let updates = Updates::new(Build::current());
        let mut checker = checker(&url);
        let before = start_measuring();

        let (outcome, _) = checker.check(&updates).await;
        settle().await;

        let peak = peak_since(before);
        println!("update check (100000 one-letter words): peak {peak} bytes");

        assert_eq!(outcome, Outcome::Newer("99.0.0".to_string()));
        assert!(peak < MANY_WORDS_PEAK_BUDGET_BYTES, "peak {peak} bytes");
    });
}
