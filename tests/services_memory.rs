//! What the blocked services hold (plan D8): the index of a catalog the size of AdGuard's, the
//! lists of every service switched on, and nothing once they are off again. The catalog here
//! is made up, in the shape and size of AdGuard's (142 services, 2,406 rules, icons of about
//! 1.6 KB). This file has its own test binary so that the counting allocator sees only this one
//! test.

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
use picoguard::pipeline::Pipeline;
use picoguard::scheduler::{ListControl, Scheduler, Timing};
use picoguard::settings::{self, PageChange};
use picoguard::upstream::tls::Tls;

const SERVICES: usize = 142;
const RULES: usize = 2406;
/// The index of 142 services. Measured: 12,355 bytes.
const INDEX_BUDGET: usize = 16 * 1024;
/// Every service switched on: 142 lists of 2,406 rules in all, and the engine that holds
/// them. Measured: 103,454 bytes.
const ALL_ON_BUDGET: usize = 160 * 1024;
/// The most a switch-on held for a moment above what it keeps: the body of 318 KB, its parse
/// and the compiles. Measured: 788,026 bytes.
const PEAK_BUDGET: usize = 1024 * 1024;
/// What the first round of on and off may leave: threads of tokio's blocking pool that start
/// for the first save and parse. Measured: 23,652 bytes.
const WARM_UP_ALLOWANCE: usize = 32 * 1024;
/// What five more rounds may leave behind in all: more threads of that pool. Measured: 0 and
/// 4,970 bytes.
const ROUNDS_ALLOWANCE: usize = 16 * 1024;

struct CountingAllocator;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

fn grow(size: usize) {
    let live = LIVE_BYTES.fetch_add(size, Ordering::Relaxed) + size;
    PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            grow(layout.size());
        }

        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    /// Counted as a move: the old and the new block both live until the copy is done.
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        grow(new_size);
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);

        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn live() -> usize {
    LIVE_BYTES.load(Ordering::Relaxed)
}

/// Made-up services of AdGuard's sizes: ids and names of 6 to 20 characters, a dozen groups,
/// 2,406 rules spread over them, and an icon each.
fn catalog() -> String {
    let groups = [
        "social_network",
        "streaming",
        "gaming",
        "messenger",
        "shopping",
        "ai",
    ];
    let icon = format!("<svg>{}</svg>", "M0 0h24v24H0z".repeat(125));
    let entries: Vec<String> = (0..SERVICES)
        .map(|n| {
            let rules = RULES / SERVICES + usize::from(n < RULES % SERVICES);
            let rules: Vec<String> = (0..rules)
                .map(|rule| format!("\"||cdn{rule}.service{n}.example^\""))
                .collect();

            format!(
                "{{\"id\": \"service_{n:03}\", \"name\": \"Service number {n}\", \"group\": \
                 \"{}\", \"icon_svg\": \"{icon}\", \"rules\": [{}]}}",
                groups[n % groups.len()],
                rules.join(", ")
            )
        })
        .collect();

    format!(
        "{{\"blocked_services\": [{}], \"groups\": []}}",
        entries.join(",\n")
    )
}

async fn switch(control: &Arc<ListControl>, pipeline: &Arc<Pipeline>, ids: &[String]) {
    let change = PageChange {
        services: Some(Some(ids.to_vec())),
        ..PageChange::default()
    };

    control.change_settings(pipeline, change).await.unwrap();
}

#[tokio::test]
async fn the_index_and_the_lists_of_the_services_switched_on_stay_within_their_budgets() {
    let state =
        std::env::temp_dir().join(format!("picoguard-services-memory-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state);
    std::fs::create_dir_all(&state).unwrap();
    let server = ListServer::start().await;
    let body = catalog();
    eprintln!("catalog of {} bytes", body.len());
    server.serve("/services.json", &body, None);
    drop(body);
    let mut config = Config {
        lists: Vec::new(),
        state: StateConfig {
            dir: state.clone(),
            persist_lists: false,
        },
        ..Config::default()
    };
    config.services.catalog_url = server.url("/services.json");
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
    let pipeline = Pipeline::new(&loaded.config, scheduler.policy()).unwrap();
    let downloader = Downloader::new(
        Names::Resolver(Arc::new(|_| {
            Box::pin(async { Err(io::Error::other("no DNS in this test")) })
        })),
        Arc::new(Tls::with_webpki_roots()),
    );
    tokio::spawn(scheduler.run(downloader, std::future::pending()));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let before = live();
    let deadline = Instant::now() + Duration::from_secs(10);
    let ids: Vec<String> = loop {
        let view = control.services_view();
        if !view.loading {
            assert_eq!(view.error, None);
            break view
                .services
                .into_iter()
                .map(|service| service.id)
                .collect();
        }

        assert!(Instant::now() < deadline, "the index never loaded");
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let index = live()
        - before
        - ids.capacity() * size_of::<String>()
        - ids.iter().map(String::len).sum::<usize>();
    eprintln!("index of {} services: {index} bytes", ids.len());
    assert_eq!(ids.len(), SERVICES);
    assert!(index <= INDEX_BUDGET, "the index holds {index} bytes");

    let off = live();
    PEAK_BYTES.store(off, Ordering::Relaxed);
    switch(&control, &pipeline, &ids).await;
    let peak = PEAK_BYTES.load(Ordering::Relaxed) - off;
    let all_on = live() - off;
    eprintln!("all {SERVICES} switched on: {all_on} bytes held, {peak} at the peak");
    assert!(all_on <= ALL_ON_BUDGET, "{all_on} bytes held");
    assert!(peak <= all_on + PEAK_BUDGET, "{peak} bytes at the peak");
    assert_eq!(server.requested("/services.json"), 2);

    switch(&control, &pipeline, &[]).await;
    let after_one = live();
    for _ in 0..5 {
        switch(&control, &pipeline, &ids).await;
        switch(&control, &pipeline, &[]).await;
    }

    let grown = live().saturating_sub(after_one);
    eprintln!("five more rounds of on and off: {grown} bytes");
    assert!(grown <= ROUNDS_ALLOWANCE, "{grown} bytes left behind");
    assert!(
        after_one.saturating_sub(off) <= WARM_UP_ALLOWANCE,
        "{} bytes left by the first round",
        after_one.saturating_sub(off)
    );
    let _ = std::fs::remove_dir_all(&state);
}
