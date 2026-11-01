//! What adding and removing lists from the page leaves behind. A removed list, its engine and
//! its compile are freed, so twenty adds and removes hold no more than the first. This file
//! has its own test binary so that the counting allocator sees only this one test.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::http::ListServer;
use picoguard::config::{Config, StateConfig};
use picoguard::filter::compile::CompileWorker;
use picoguard::filter::snapshot::SnapshotStore;
use picoguard::lists::{Downloader, Names};
use picoguard::scheduler::{ListControl, ListEdit, Scheduler, Timing};
use picoguard::settings::{self, ListRole};
use picoguard::upstream::tls::Tls;

const CYCLES: usize = 20;
/// What the later adds and removes may hold beyond the first, in all. Measured: 7,968 bytes
/// after 19 more and 8,183 after 79: threads and tables that warm up once, not a cost of each
/// change.
const ALLOWANCE: usize = 16 * 1024;
const RULES: usize = 20_000;

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

async fn add_and_remove(control: &Arc<ListControl>, url: &str) {
    control
        .add_list(ListEdit::Add {
            role: ListRole::Block,
            name: Some("Cycled".to_string()),
            url: url.to_string(),
            refresh_hours: 24,
        })
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let outcome = loop {
        if let Some(outcome) = control.pending_list().and_then(|list| list.outcome) {
            break outcome;
        }

        assert!(Instant::now() < deadline, "the add never ended");
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    assert_eq!(outcome, Ok(()));
    assert_eq!(control.statuses()[0].rules, RULES);

    control
        .change_lists(ListEdit::Remove {
            role: ListRole::Block,
            source: url.to_string(),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn lists_added_and_removed_from_the_page_leave_nothing_behind() {
    let state = std::env::temp_dir().join(format!(
        "picoguard-list-change-memory-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&state);
    std::fs::create_dir_all(&state).unwrap();
    let config = Config {
        lists: Vec::new(),
        state: StateConfig {
            dir: state.clone(),
            persist_lists: false,
        },
        ..Config::default()
    };
    let server = ListServer::start().await;
    let list: String = (0..RULES)
        .map(|index| format!("||n{index}.example^\n"))
        .collect();
    server.serve("/cycled.txt", &list, None);
    drop(list);
    let url = server.url("/cycled.txt");
    let loaded = settings::with_saved(config);
    let scheduler = Scheduler::boot(
        &loaded.config,
        Arc::new(loaded.saved),
        CompileWorker::spawn().unwrap(),
        Arc::new(SnapshotStore::disabled()),
        Timing {
            hour: Duration::from_secs(3600),
            retries: [Duration::from_secs(3600); 4],
            first_check: Duration::from_secs(3600),
        },
    )
    .await
    .unwrap();
    let control = scheduler.control();
    let downloader = Downloader::new(
        Names::Resolver(Arc::new(|_| {
            Box::pin(async { Err(io::Error::other("no DNS in this test")) })
        })),
        Arc::new(Tls::with_webpki_roots()),
    );
    tokio::spawn(scheduler.run(downloader, std::future::pending()));

    add_and_remove(&control, &url).await;
    let after_one = live();
    for _ in 1..CYCLES {
        add_and_remove(&control, &url).await;
    }

    let grown = live().saturating_sub(after_one);
    eprintln!("{} more adds and removes: {grown} bytes", CYCLES - 1);
    assert!(control.statuses().is_empty());
    assert!(
        grown <= ALLOWANCE,
        "{grown} bytes held after {CYCLES} adds and removes"
    );
    let _ = std::fs::remove_dir_all(&state);
}
