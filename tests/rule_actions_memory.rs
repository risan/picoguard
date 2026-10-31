//! Rules from the status page cost only their own bytes in force, and a change peaks at one
//! more copy of them and the settings file it saves: alone, in a burst, and beside a list
//! refresh. This test binary has a
//! counting global allocator and a single test, so nothing else allocates while it measures.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::io;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::http::ListServer;
use picoguard::config::{Config, ListConfig, ListFormat};
use picoguard::filter::compile::CompileWorker;
use picoguard::filter::snapshot::SnapshotStore;
use picoguard::lists::{Downloader, MAX_PIECE_BYTES, PIECE_QUEUE};
use picoguard::policy::Policy;
use picoguard::scheduler::{
    Action, ListControl, MAX_PENDING_CHANGES, RuleError, Scheduler, Timing,
};
use picoguard::settings::{self, Saved, Settings};
use picoguard::upstream::tls::Tls;
use tokio::task::JoinHandle;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        grow(layout.size());

        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        grow(new_size);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);

        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

const PAGE_RULES: usize = 500;

/// Measured: 61 bytes per rule in force (its share of the rule list, its name, and an 8-byte
/// hash in a page list); 500 rules cost 30,964 bytes.
const PER_RULE_BYTES: usize = 256;

/// Rule-set shells, the engine struct, and a respawned blocking-pool thread.
const FIXED_BYTES: usize = 32 * 1024;

/// The engine struct, the empty rule-set shells, the file write's task and allocator slack of
/// one change. Measured: a change with 500 rules peaked 3,059 bytes above one copy of them and
/// their 38,040-byte settings file.
const CHANGE_SLACK_BYTES: usize = 4 * 1024;

/// Run-to-run variance of the refresh itself: how far the download may run ahead of the
/// compiler, the queued pieces plus the one being filled and the one being parsed. Measured
/// at 336 KiB between two lone refreshes on a busy machine.
const REFRESH_VARIANCE_BYTES: usize = (PIECE_QUEUE + 2) * MAX_PIECE_BYTES;

const FLIPS: usize = 20;

/// A change task waiting for the lock, with its answer channel: measured at about 630 bytes.
/// At most `MAX_PENDING_CHANGES` exist, one of them the change that runs.
const PER_PENDING_CHANGE_BYTES: usize = 1024;

/// A caller waiting for a permit, with the name it sends: measured at 150 to 350 bytes. In
/// the server, callers are requests, bounded by its connection limit.
const PER_WAITING_CALLER_BYTES: usize = 512;

/// Idle blocking-pool threads made before any baseline; tokio keeps an idle one for 10 s.
const BLOCKING_THREADS: usize = 16;

fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// Starts a peak measurement; returns the live bytes it counts from.
fn reset_peak() -> usize {
    let live = live();
    PEAK.store(live, Ordering::Relaxed);

    live
}

fn peak_since(before: usize) -> usize {
    PEAK.load(Ordering::Relaxed).saturating_sub(before)
}

/// The live bytes once three reads 50 ms apart agree: drops run on the blocking pool and the
/// compile worker. Two seconds at most.
async fn settle() -> usize {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut reads = Vec::with_capacity(64);
    loop {
        tokio::time::sleep(Duration::from_millis(50)).await;
        reads.push(live());
        let agreed = reads.len() >= 3 && reads[reads.len() - 3..].windows(2).all(|w| w[0] == w[1]);
        if agreed || Instant::now() >= deadline || reads.len() == reads.capacity() {
            return reads[reads.len() - 1];
        }
    }
}

/// 200,000 plain rules, 50 wildcard rules and `extra` more plain rules.
fn list_body(extra: usize) -> Vec<u8> {
    let mut text = String::with_capacity(5 * 1024 * 1024);
    for number in 0..200_000 {
        text.push_str(&format!("||name{number}.example^\n"));
    }

    for number in 0..50 {
        text.push_str(&format!("||ad{number}*.wild.example^\n"));
    }

    for number in 0..extra {
        text.push_str(&format!("||extra{number}.example^\n"));
    }

    text.into_bytes()
}

/// In 64 KiB pieces 10 ms apart, so the worker compiles while the list arrives.
fn serve(server: &ListServer, extra: usize) {
    server.serve_slowly(
        "/big.txt",
        list_body(extra),
        64 * 1024,
        Duration::from_millis(10),
    );
}

fn page_name(number: usize) -> String {
    format!("page-rule-{number:03}.example")
}

fn first_action(number: usize) -> Action {
    if number < PAGE_RULES / 2 {
        Action::Block
    } else {
        Action::Allow
    }
}

fn other(action: Action) -> Action {
    match action {
        Action::Block => Action::Allow,
        Action::Allow => Action::Block,
    }
}

fn generation(policy: &Policy) -> u64 {
    policy.view(Instant::now()).generation
}

/// Tasks that each flip the action of one name. They start running at the next await.
fn spawn_flips(
    control: &Arc<ListControl>,
    numbers: Range<usize>,
) -> Vec<JoinHandle<Result<(), RuleError>>> {
    numbers
        .map(|number| {
            let control = Arc::clone(control);

            tokio::spawn(async move {
                control
                    .add_button_rule(&page_name(number), other(first_action(number)))
                    .await
            })
        })
        .collect()
}

/// Leaves every answer unread until the generation shows all the changes applied.
async fn finish_flips(
    flips: Vec<JoinHandle<Result<(), RuleError>>>,
    policy: &Policy,
    generation_reached: u64,
) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while generation(policy) < generation_reached {
        assert!(Instant::now() < deadline, "the flips were not applied");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    for flip in flips {
        assert_eq!(flip.await.unwrap(), Ok(()));
    }
}

fn downloader() -> Downloader {
    Downloader::new(
        Arc::new(|_| Box::pin(async { Err(io::Error::other("no DNS in this test")) })),
        Arc::new(Tls::with_webpki_roots()),
    )
}

#[tokio::test(flavor = "current_thread")]
async fn page_rules_cost_only_their_own_bytes_and_a_change_peaks_at_one_copy_of_them() {
    let server = ListServer::start().await;
    serve(&server, 0);
    let state = common::release::scratch("rule-actions-memory");
    let mut config = Config {
        lists: vec![ListConfig {
            name: Some("big".to_string()),
            url: Some(server.url("/big.txt")),
            format: ListFormat::Adblock,
            ..ListConfig::default()
        }],
        ..Config::default()
    };
    config.state.dir = state.clone();
    let mut scheduler = Scheduler::boot(
        &config,
        Arc::new(Saved::new(config.clone(), Settings::default(), None)),
        CompileWorker::spawn().unwrap(),
        Arc::new(SnapshotStore::disabled()),
        Timing {
            hour: Duration::from_secs(3600),
            retries: [Duration::from_secs(3600); 4],
            first_check: Duration::from_secs(3600 * 1000),
        },
    )
    .await
    .unwrap();
    let (policy, control) = (scheduler.policy(), scheduler.control());
    let downloader = downloader();
    scheduler.refresh(0, &downloader).await;
    assert_eq!(scheduler.list(0).unwrap().slow_rule_count(), 50);

    // The blocking pool's threads and tokio's own tables exist before any baseline. The pool
    // starts a thread whenever none is idle, and a thread that has just finished a task is
    // not idle yet, so back-to-back changes would start threads during a measurement: 8 in a
    // burst of 20 when measured, about 3.5 KB each. Those are not page rules.
    let warm: Vec<_> = (0..BLOCKING_THREADS)
        .map(|_| tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_millis(50))))
        .collect();
    for thread in warm {
        thread.await.unwrap();
    }

    control
        .add_button_rule("warm-up.example", Action::Block)
        .await
        .unwrap();
    control.remove_button_rule("warm-up.example").await.unwrap();
    settle().await;

    serve(&server, 1);
    let before = reset_peak();
    scheduler.refresh(0, &downloader).await;
    let refresh_peak = peak_since(before);
    let l1 = settle().await;

    for number in 0..PAGE_RULES {
        control
            .add_button_rule(&page_name(number), first_action(number))
            .await
            .unwrap();
    }

    let one_copy = settle().await.saturating_sub(l1);
    assert!(
        one_copy <= PAGE_RULES * PER_RULE_BYTES + FIXED_BYTES,
        "{PAGE_RULES} page rules cost {one_copy} bytes"
    );

    let before = reset_peak();
    control
        .add_button_rule(&page_name(0), other(first_action(0)))
        .await
        .unwrap();
    let change_peak = peak_since(before);
    settle().await;
    // The file is encoded once into a buffer of its exact size.
    let file_bytes = std::fs::metadata(state.join(settings::FILE_NAME))
        .unwrap()
        .len() as usize;
    assert!(
        change_peak <= one_copy + file_bytes + CHANGE_SLACK_BYTES,
        "a change peaked at {change_peak} bytes, one copy is {one_copy}, the file {file_bytes}"
    );
    assert!(
        change_peak < refresh_peak,
        "a change peaked at {change_peak} bytes, a refresh at {refresh_peak}"
    );

    // The test's own 20 tasks are made before the measurement, like the requests a burst
    // arrives in; the changes start at the next await.
    let flips = spawn_flips(&control, 1..1 + FLIPS);
    let generation_before = generation(&policy);
    let before = reset_peak();
    finish_flips(flips, &policy, generation_before + FLIPS as u64).await;
    let burst_peak = peak_since(before);
    settle().await;
    // One change's peak plus the bookkeeping of the others: no second copy of the rules.
    let burst_limit = change_peak
        + (MAX_PENDING_CHANGES - 1) * PER_PENDING_CHANGE_BYTES
        + FLIPS * PER_WAITING_CALLER_BYTES;
    assert!(
        burst_peak <= burst_limit,
        "a burst peaked at {burst_peak} bytes, one change at {change_peak}, one copy is {one_copy}"
    );

    serve(&server, 2);
    let before = reset_peak();
    let refreshing = tokio::spawn(async move {
        scheduler.refresh(0, &downloader).await;

        scheduler
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while server.active() != 1 {
        assert!(Instant::now() < deadline, "the refresh never started");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    let flips = spawn_flips(&control, 1 + FLIPS..1 + 2 * FLIPS);
    let generation_before = generation(&policy);
    finish_flips(flips, &policy, generation_before + FLIPS as u64).await;
    let scheduler = refreshing.await.unwrap();
    let overlap_peak = peak_since(before);
    settle().await;

    println!(
        "refresh_peak {refresh_peak}, one_copy {one_copy} ({} per rule), file_bytes {file_bytes}, \
         change_peak {change_peak}, burst_peak {burst_peak}, overlap_peak {overlap_peak}",
        one_copy / PAGE_RULES
    );
    assert!(
        overlap_peak <= refresh_peak + burst_limit + REFRESH_VARIANCE_BYTES,
        "beside a refresh the peak was {overlap_peak} bytes; a refresh alone {refresh_peak}, \
         a burst alone {burst_peak}, one copy {one_copy}"
    );

    for number in 0..PAGE_RULES {
        control
            .remove_button_rule(&page_name(number))
            .await
            .unwrap();
    }

    let left = settle().await.saturating_sub(l1);
    assert!(
        left <= FIXED_BYTES,
        "{left} bytes left after every page rule was removed"
    );
    assert_eq!(scheduler.list(0).unwrap().slow_rule_count(), 50);
}
