//! The resident memory of a process that runs what the daemon runs: the DNS listener, the
//! status page, the scheduler with the three default lists downloaded and persisted as
//! snapshots, and the stager, while a list refresh in which every list changed overlaps an
//! 8 MiB update download. This file has its own test binary so that nothing else of the test
//! suite adds to the peak. The servers read files and a pattern in 16 KiB pieces, so they
//! do not inflate the figure.

mod common;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::harness::{answering_upstream, config_for, start_with_policy};
use common::release::{TARGET, hex, scratch, sign, test_key};
use common::stream::{Route, StreamServer, pattern_hash};
use picoguard::config::{ListConfig, ListFormat};
use picoguard::filter::compile::CompileWorker;
use picoguard::filter::snapshot::SnapshotStore;
use picoguard::lists::Downloader;
use picoguard::scheduler::{ListControl, Scheduler, Timing};
use picoguard::stage::{StageSetup, StageTiming, Stager};
use picoguard::update::{Build, Latest, Updates};
use picoguard::upstream::tls::Tls;
use picoguard::web::{self, Web, WebListeners};

const LISTS: [&str; 3] = ["adguard-dns", "hagezi-pro", "hagezi-tif-mini"];
const VERSION: &str = "9.9.9";
const BINARY_BYTES: u64 = 8 * 1024 * 1024;
/// The 64 MiB `MemoryMax` minus room for the page cache of the written files.
const HWM_LIMIT_KIB: u64 = 56 * 1024;
/// A list may end without a newline, so the rule starts its own line.
const EXTRA_RULE: &str = "\n||stage-rss-extra.example^\n";

fn no_dns() -> Downloader {
    Downloader::new(
        Arc::new(|_| Box::pin(async { Err(io::Error::other("no DNS in this test")) })),
        Arc::new(Tls::with_webpki_roots()),
    )
}

/// Unpacks a list into `<dir>/<name>.txt`, and a copy with one more rule into
/// `<dir>/<name>-changed.txt`, without holding either in memory.
fn unpack(name: &str, dir: &Path) -> (PathBuf, PathBuf) {
    let packed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/lists")
        .join(format!("{name}.txt.gz"));
    let original = dir.join(format!("{name}.txt"));
    let changed = dir.join(format!("{name}-changed.txt"));
    let mut reader = flate2::read::GzDecoder::new(fs::File::open(packed).unwrap());
    io::copy(&mut reader, &mut fs::File::create(&original).unwrap()).unwrap();
    fs::copy(&original, &changed).unwrap();
    io::Write::write_all(
        &mut fs::OpenOptions::new().append(true).open(&changed).unwrap(),
        EXTRA_RULE.as_bytes(),
    )
    .unwrap();

    (original, changed)
}

fn proc_value(file: &str, key: &str) -> Option<u64> {
    fs::read_to_string(file)
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
}

fn cgroup_file(name: &str) -> Option<String> {
    let cgroups = fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = cgroups.lines().find_map(|line| line.strip_prefix("0::"))?;

    fs::read_to_string(format!("/sys/fs/cgroup{path}/{name}")).ok()
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(300);

    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn rules(control: &ListControl) -> Vec<usize> {
    control
        .statuses()
        .iter()
        .map(|status| status.rules)
        .collect()
}

fn modified(path: &Path) -> Option<std::time::SystemTime> {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
}

#[tokio::test]
async fn a_list_refresh_during_an_update_download_stays_within_the_memory_limit() {
    let root = scratch("stage-rss");
    for dir in ["state", "installer", "lists"] {
        fs::create_dir(root.join(dir)).unwrap();
    }

    let server = StreamServer::start().await;
    let mut urls = Vec::new();
    let mut changed_files = Vec::new();

    for name in LISTS {
        let (original, changed) = unpack(name, &root.join("lists"));
        let path = format!("/{name}.txt");
        server.set(&path, Route::File(original));
        urls.push(server.url(&path));
        changed_files.push((path, changed));
    }

    let sums = format!("{}  picoguard-{TARGET}\n", hex(&pattern_hash(BINARY_BYTES))).into_bytes();
    let base = format!("/download/v{VERSION}");
    server.set(&format!("{base}/SHA256SUMS.sig"), Route::Bytes(sign(&sums)));
    server.set(&format!("{base}/SHA256SUMS"), Route::Bytes(sums));
    server.set(
        &format!("{base}/picoguard-{TARGET}"),
        Route::Pattern {
            size: BINARY_BYTES,
            hold_at_half: true,
        },
    );

    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = config_for(&upstream);
    config.lists = LISTS
        .iter()
        .zip(&urls)
        .map(|(name, url)| ListConfig {
            name: Some(name.to_string()),
            url: Some(url.clone()),
            format: ListFormat::Adblock,
            ..ListConfig::default()
        })
        .collect();
    config.web.bind = vec!["127.0.0.1".parse().unwrap()];
    config.web.port = 0;
    config.web.user = Some("admin".to_string());
    config.web.password = Some("s3cret".to_string());
    config.state.dir = root.join("state");

    let store = Arc::new(SnapshotStore::open(&config.state.dir).unwrap());
    let scheduler = Scheduler::boot(
        &config,
        CompileWorker::spawn().unwrap(),
        Arc::clone(&store),
        Timing {
            hour: Duration::from_secs(3600),
            retries: [Duration::from_secs(3600); 4],
            first_check: Duration::from_secs(3600 * 1000),
        },
    )
    .await
    .unwrap();
    let policy = scheduler.policy();
    let control = scheduler.control();
    tokio::spawn(scheduler.run(no_dns(), std::future::pending()));

    let dns = start_with_policy(&config, Arc::clone(&policy)).await;
    let updates = Arc::new(Updates::new(Build::Release));
    updates.show(Some(Latest {
        version: VERSION.to_string(),
        notes: String::new(),
    }));
    let stager = Stager::new(
        StageSetup {
            target: Some(TARGET),
            base_url: server.url("/download"),
            state_dir: root.join("state"),
            installer_dir: root.join("installer"),
            key: test_key(),
            max_binary_bytes: 16 * 1024 * 1024,
            timing: StageTiming {
                poll: Duration::from_secs(1),
                wait: Duration::from_secs(600),
            },
        },
        Arc::clone(&updates),
        Arc::new(|_| Box::pin(async { Err(io::Error::other("no DNS in this test")) })),
        Arc::new(Tls::with_webpki_roots()),
    );
    let listeners = WebListeners::bind(&config.web).unwrap();
    web::spawn(
        listeners,
        Arc::new(
            Web::new(
                &config,
                Arc::clone(dns.pipeline.stats()),
                Arc::clone(&policy),
                Arc::clone(&control),
                updates,
                Arc::clone(&stager),
            )
            .unwrap(),
        ),
    );

    // Bootstrap: every list loaded and persisted.
    control.refresh_all();
    let snapshots: Vec<PathBuf> = urls
        .iter()
        .map(|url| store.path_for(url).unwrap())
        .collect();
    until("the three lists to load and persist", || {
        rules(&control).iter().all(|rules| *rules > 0) && snapshots.iter().all(|path| path.exists())
    })
    .await;
    store.flush().await;
    let rules_before = rules(&control);
    let written_before: Vec<_> = snapshots.iter().map(|path| modified(path)).collect();
    println!("lists loaded: {rules_before:?} rules");

    // Overlap: every list changes while the update is held half way down.
    for (path, changed) in &changed_files {
        server.set(path, Route::File(changed.clone()));
    }

    stager.start(VERSION).unwrap();
    until("the download to be under way", || {
        stager
            .view()
            .is_some_and(|view| view.state == "downloading" && view.bytes.unwrap_or(0) > 1 << 20)
    })
    .await;

    control.refresh_all();
    until("every list to be replaced and persisted", || {
        let replaced = rules(&control)
            .iter()
            .zip(&rules_before)
            .all(|(now, before)| now > before);

        replaced
            && snapshots
                .iter()
                .zip(&written_before)
                .all(|(path, before)| modified(path) > *before)
    })
    .await;

    assert_eq!(
        stager.view().unwrap().state,
        "downloading",
        "the update ended before the refresh did, so they did not overlap"
    );

    server.release();
    until("the update to be staged", || {
        stager.view().is_some_and(|view| view.state == "waiting")
    })
    .await;

    let high_water = proc_value("/proc/self/status", "VmHWM:").expect("VmHWM");
    println!("VmHWM {high_water} kB");
    println!(
        "memory.peak {}",
        cgroup_file("memory.peak")
            .unwrap_or_else(|| "unavailable".to_string())
            .trim()
    );
    println!(
        "{}",
        cgroup_file("memory.events")
            .and_then(|events| events
                .lines()
                .find(|line| line.starts_with("oom_kill"))
                .map(str::to_string))
            .unwrap_or_else(|| "oom_kill unavailable".to_string())
    );

    assert!(
        high_water < HWM_LIMIT_KIB,
        "VmHWM {high_water} kB is not below {HWM_LIMIT_KIB} kB"
    );
}
