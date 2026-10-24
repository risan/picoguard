//! The list scheduler against a local list server: boot from snapshots, refresh, swap, and
//! the failure paths. Nothing leaves the machine.

mod common;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use common::harness::{answering_upstream, ask, config_for, start_with_policy};
use common::http::ListServer;
use hickory_proto::op::{Message, Query as DnsQuery};
use hickory_proto::rr::{Name, RecordType};
use picoguard::config::{Config, ListConfig, ListFormat, StateConfig};
use picoguard::dns::wire::Query;
use picoguard::filter::compile::{CompileOptions, CompileWorker};
use picoguard::filter::engine::Decision;
use picoguard::filter::snapshot::{self, SnapshotStore};
use picoguard::lists::{Downloader, resolver_over};
use picoguard::policy::Policy;
use picoguard::scheduler::{Role, Scheduler, Timing};
use picoguard::upstream::Upstreams;
use picoguard::upstream::tls::Tls;

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

struct StateDir(PathBuf);

impl StateDir {
    fn new() -> StateDir {
        let path = std::env::temp_dir().join(format!(
            "picoguard-list-sync-{}-{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();

        StateDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn snapshot_files(&self) -> Vec<PathBuf> {
        match fs::read_dir(self.0.join("lists")) {
            Ok(entries) => entries.map(|entry| entry.unwrap().path()).collect(),
            Err(_) => Vec::new(),
        }
    }
}

impl Drop for StateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Collects the warnings the scheduler logs, for tests that count them.
struct Capture;

static WARNINGS: Mutex<Vec<String>> = Mutex::new(Vec::new());

impl log::Log for Capture {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Warn
    }

    fn log(&self, record: &log::Record) {
        if record.level() == log::Level::Warn {
            WARNINGS.lock().unwrap().push(record.args().to_string());
        }
    }

    fn flush(&self) {}
}

fn warnings_about(label: &str) -> usize {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        log::set_logger(&Capture).unwrap();
        log::set_max_level(log::LevelFilter::Warn);
    });

    WARNINGS
        .lock()
        .unwrap()
        .iter()
        .filter(|message| message.contains(label))
        .count()
}

/// Installs the capturing logger before the first warning is logged.
fn capture_warnings() {
    warnings_about("");
}

fn quick_timing() -> Timing {
    Timing {
        hour: Duration::from_millis(5),
        retries: [Duration::from_millis(20); 4],
        first_check: Duration::from_millis(10),
    }
}

fn url_list(name: &str, url: String) -> ListConfig {
    ListConfig {
        name: Some(name.to_string()),
        url: Some(url),
        format: ListFormat::Adblock,
        ..ListConfig::default()
    }
}

fn path_list(path: PathBuf) -> ListConfig {
    ListConfig {
        path: Some(path),
        ..ListConfig::default()
    }
}

fn config_of(dir: &StateDir, lists: Vec<ListConfig>) -> Config {
    Config {
        lists,
        state: StateConfig {
            dir: dir.path().to_path_buf(),
            ..StateConfig::default()
        },
        ..Config::default()
    }
}

fn downloader() -> Downloader {
    Downloader::new(
        Arc::new(|_| Box::pin(async { Err(io::Error::other("no DNS in this test")) })),
        Arc::new(Tls::with_webpki_roots()),
    )
}

async fn boot_with(config: &Config, store: SnapshotStore) -> (Scheduler, Arc<SnapshotStore>) {
    let store = Arc::new(store);
    let scheduler = Scheduler::boot(
        config,
        CompileWorker::spawn().unwrap(),
        Arc::clone(&store),
        quick_timing(),
    )
    .await
    .unwrap();

    (scheduler, store)
}

async fn boot(config: &Config) -> (Scheduler, Arc<SnapshotStore>) {
    boot_with(config, SnapshotStore::open(&config.state.dir).unwrap()).await
}

fn blocked(policy: &Policy, name: &str) -> bool {
    let mut message = Message::query();
    message.add_query(DnsQuery::query(
        Name::from_ascii(name).unwrap(),
        RecordType::A,
    ));
    let packet = message.to_vec().unwrap();
    let query = Query::parse(&packet).unwrap();

    policy.view(Instant::now()).check_request(&query) != Decision::Pass
}

fn generation(policy: &Policy) -> u64 {
    policy.view(Instant::now()).generation
}

const V1: &str = "||ads.example^\n";
const V2: &str = "||ads.example^\n||tracker.example^\n";

#[tokio::test]
async fn a_list_without_a_snapshot_starts_empty_and_the_first_refresh_loads_it() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/l.txt", V1, Some("\"v1\""));
    let config = config_of(&dir, vec![url_list("first", server.url("/l.txt"))]);
    let (mut scheduler, store) = boot(&config).await;
    let policy = scheduler.policy();

    assert!(!blocked(&policy, "ads.example."));
    assert!(scheduler.list(0).is_none());

    scheduler.refresh(0, &downloader()).await;

    assert!(blocked(&policy, "ads.example."));
    assert_eq!(generation(&policy), 1);
    assert!(store.bytes_written() > 0);
    assert_eq!(dir.snapshot_files().len(), 1);
}

#[tokio::test]
async fn a_restart_boots_from_the_snapshots_without_the_network() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/a.txt", V1, Some("\"a\""));
    server.serve("/b.txt", "||other.example^\n", None);
    let lists = vec![
        url_list("restart-a", server.url("/a.txt")),
        url_list("restart-b", server.url("/b.txt")),
    ];
    let config = config_of(&dir, lists);
    {
        let (mut scheduler, _) = boot(&config).await;
        scheduler.refresh(0, &downloader()).await;
        scheduler.refresh(1, &downloader()).await;
    }

    server.stop().await;
    capture_warnings();
    let (mut scheduler, store) = boot(&config).await;
    let policy = scheduler.policy();

    assert!(blocked(&policy, "ads.example."));
    assert!(blocked(&policy, "other.example."));
    assert_eq!(
        generation(&policy),
        0,
        "the first engine is already complete"
    );

    let before = Arc::clone(scheduler.list(0).unwrap());
    for _ in 0..3 {
        scheduler.refresh(0, &downloader()).await;
    }

    assert!(blocked(&policy, "ads.example."));
    assert!(Arc::ptr_eq(&before, scheduler.list(0).unwrap()));
    assert_eq!(store.bytes_written(), 0);
    assert_eq!(
        warnings_about("restart-a"),
        1,
        "one warning per failure streak"
    );
}

#[tokio::test]
async fn an_unchanged_list_keeps_its_arrays_and_writes_nothing() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/plain.txt", V1, None);
    server.serve("/tagged.txt", V1, Some("\"t\""));
    let lists = vec![
        url_list("plain", server.url("/plain.txt")),
        url_list("tagged", server.url("/tagged.txt")),
    ];
    let (mut scheduler, store) = boot(&config_of(&dir, lists)).await;
    let policy = scheduler.policy();
    scheduler.refresh(0, &downloader()).await;
    scheduler.refresh(1, &downloader()).await;
    let written = store.bytes_written();
    let generation_before = generation(&policy);
    let plain = Arc::clone(scheduler.list(0).unwrap());
    let tagged = Arc::clone(scheduler.list(1).unwrap());

    // Without a validator the whole list comes again and compiles to the same thing; with
    // one the server says 304.
    scheduler.refresh(0, &downloader()).await;
    scheduler.refresh(1, &downloader()).await;

    assert!(Arc::ptr_eq(&plain, scheduler.list(0).unwrap()));
    assert!(Arc::ptr_eq(&tagged, scheduler.list(1).unwrap()));
    assert_eq!(server.not_modified(), 1);
    assert_eq!(store.bytes_written(), written);
    assert_eq!(generation(&policy), generation_before);
}

#[tokio::test]
async fn an_unchanged_list_after_a_restart_keeps_the_loaded_arrays_and_writes_nothing() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/l.txt", V1, None);
    let config = config_of(&dir, vec![url_list("same", server.url("/l.txt"))]);
    {
        let (mut scheduler, _) = boot(&config).await;
        scheduler.refresh(0, &downloader()).await;
    }

    let (mut scheduler, store) = boot(&config).await;
    let loaded = Arc::clone(scheduler.list(0).unwrap());
    scheduler.refresh(0, &downloader()).await;

    assert!(Arc::ptr_eq(&loaded, scheduler.list(0).unwrap()));
    assert_eq!(store.bytes_written(), 0);
    assert_eq!(generation(&scheduler.policy()), 0);
}

#[tokio::test]
async fn a_changed_list_is_swapped_in_written_once_and_the_old_copy_released() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/l.txt", V1, Some("\"v1\""));
    let config = config_of(&dir, vec![url_list("changing", server.url("/l.txt"))]);
    let (mut scheduler, store) = boot(&config).await;
    let policy = scheduler.policy();
    scheduler.refresh(0, &downloader()).await;
    let old = Arc::clone(scheduler.list(0).unwrap());
    let written = store.bytes_written();
    assert!(!blocked(&policy, "tracker.example."));

    server.serve("/l.txt", V2, Some("\"v2\""));
    scheduler.refresh(0, &downloader()).await;

    assert!(blocked(&policy, "tracker.example."));
    assert!(blocked(&policy, "ads.example."));
    assert_eq!(generation(&policy), 2);
    assert!(!Arc::ptr_eq(&old, scheduler.list(0).unwrap()));
    assert!(store.bytes_written() > written);

    // The old engine and the old list go to the compile worker; once it has dropped them
    // this test holds the last reference.
    for _ in 0..200 {
        if Arc::strong_count(&old) == 1 {
            break;
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(Arc::strong_count(&old), 1);
}

#[tokio::test]
async fn every_kind_of_failure_keeps_the_last_good_list() {
    capture_warnings();
    let dir = StateDir::new();
    let server = ListServer::start().await;
    let closed = ListServer::start().await.stop().await;
    server.serve("/status.txt", V1, Some("\"s\""));
    server.serve("/cap.txt", V1, Some("\"c\""));
    server.serve("/budget.txt", V1, Some("\"b\""));
    let capped = ListConfig {
        max_body_bytes: 64,
        ..url_list("failing-cap", server.url("/cap.txt"))
    };
    let budgeted = ListConfig {
        slow_rule_budget: 4096,
        ..url_list("failing-budget", server.url("/budget.txt"))
    };
    let lists = vec![
        url_list("failing-status", server.url("/status.txt")),
        capped,
        budgeted,
        url_list("failing-network", format!("http://{closed}/l.txt")),
    ];
    let (mut scheduler, _) = boot(&config_of(&dir, lists)).await;
    let policy = scheduler.policy();
    for index in 0..3 {
        scheduler.refresh(index, &downloader()).await;
    }

    let in_force: Vec<_> = (0..3)
        .map(|index| Arc::clone(scheduler.list(index).unwrap()))
        .collect();
    let generation_before = generation(&policy);

    server.fail("/status.txt", 503);
    let long_line = format!("||{}.example^\n", "a".repeat(100));
    server.serve("/cap.txt", &long_line, Some("\"c2\""));
    let many_slow_rules: String = (0..200)
        .map(|index| format!("||slow{index}*.example^$dnstype=A\n"))
        .collect();
    server.serve("/budget.txt", &many_slow_rules, Some("\"b2\""));
    for index in 0..4 {
        scheduler.refresh(index, &downloader()).await;
        scheduler.refresh(index, &downloader()).await;
    }

    for (index, before) in in_force.iter().enumerate() {
        assert!(
            Arc::ptr_eq(before, scheduler.list(index).unwrap()),
            "{index}"
        );
    }

    assert!(scheduler.list(3).is_none());
    assert!(blocked(&policy, "ads.example."));
    assert_eq!(generation(&policy), generation_before);
    for label in [
        "failing-status",
        "failing-cap",
        "failing-budget",
        "failing-network",
    ] {
        assert_eq!(warnings_about(label), 1, "{label}: one warning per streak");
    }
}

#[tokio::test]
async fn a_success_ends_a_failure_streak_and_the_next_failure_warns_again() {
    capture_warnings();
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/l.txt", V1, None);
    let config = config_of(&dir, vec![url_list("streaks", server.url("/l.txt"))]);
    let (mut scheduler, _) = boot(&config).await;
    scheduler.refresh(0, &downloader()).await;

    for _ in 0..2 {
        server.fail("/l.txt", 500);
        scheduler.refresh(0, &downloader()).await;
        scheduler.refresh(0, &downloader()).await;
        server.serve("/l.txt", V1, None);
        scheduler.refresh(0, &downloader()).await;
    }

    assert_eq!(warnings_about("streaks"), 2);
}

#[tokio::test]
async fn a_200_without_rules_replaces_nothing() {
    capture_warnings();
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/l.txt", V1, Some("\"v1\""));
    let config = config_of(&dir, vec![url_list("emptied", server.url("/l.txt"))]);
    let (mut scheduler, store) = boot(&config).await;
    let policy = scheduler.policy();
    scheduler.refresh(0, &downloader()).await;
    let good = Arc::clone(scheduler.list(0).unwrap());
    let written = store.bytes_written();
    let generation_before = generation(&policy);

    server.serve("/l.txt", "# Rate limited, try later\n", Some("\"v2\""));
    scheduler.refresh(0, &downloader()).await;

    assert!(Arc::ptr_eq(&good, scheduler.list(0).unwrap()));
    assert!(blocked(&policy, "ads.example."));
    assert_eq!(generation(&policy), generation_before);
    assert_eq!(store.bytes_written(), written);
    assert_eq!(warnings_about("emptied"), 1);
}

#[tokio::test]
async fn a_list_that_never_had_rules_accepts_an_empty_first_copy() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/l.txt", "! nothing yet\n", None);
    let config = config_of(&dir, vec![url_list("empty-first", server.url("/l.txt"))]);
    let (mut scheduler, _) = boot(&config).await;

    scheduler.refresh(0, &downloader()).await;

    assert_eq!(scheduler.list(0).unwrap().rule_count(), 0);
}

#[tokio::test]
async fn a_changed_format_in_the_config_recompiles_and_rewrites_the_snapshot() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/l.txt", "0.0.0.0 ads.example\n", Some("\"v1\""));
    let adblock = url_list("format", server.url("/l.txt"));
    {
        let (mut scheduler, store) = boot(&config_of(&dir, vec![adblock.clone()])).await;
        scheduler.refresh(0, &downloader()).await;
        assert!(store.bytes_written() > 0);
    }

    let hosts = ListConfig {
        format: ListFormat::Hosts,
        ..adblock
    };
    let (mut scheduler, store) = boot(&config_of(&dir, vec![hosts])).await;
    let policy = scheduler.policy();

    assert!(scheduler.list(0).is_none(), "the old snapshot does not fit");
    assert!(!blocked(&policy, "ads.example."));

    scheduler.refresh(0, &downloader()).await;

    assert!(blocked(&policy, "ads.example."));
    assert_eq!(
        server.not_modified(),
        0,
        "validators of a snapshot that does not fit are not sent"
    );
    assert!(store.bytes_written() > 0, "the snapshot is written again");
}

#[tokio::test]
async fn without_persistence_nothing_is_read_or_written() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/l.txt", V1, Some("\"v1\""));
    let config = config_of(&dir, vec![url_list("volatile", server.url("/l.txt"))]);
    {
        let (mut scheduler, _) = boot(&config).await;
        scheduler.refresh(0, &downloader()).await;
    }

    let files_before = dir.snapshot_files();
    assert_eq!(files_before.len(), 1);
    let modified = fs::metadata(&files_before[0]).unwrap().modified().unwrap();

    let (mut scheduler, store) = boot_with(&config, SnapshotStore::disabled()).await;
    assert!(
        scheduler.list(0).is_none(),
        "the snapshot on disk is not read"
    );

    server.serve("/l.txt", V2, Some("\"v2\""));
    scheduler.refresh(0, &downloader()).await;

    assert!(blocked(&scheduler.policy(), "tracker.example."));
    assert_eq!(store.bytes_written(), 0);
    assert_eq!(dir.snapshot_files(), files_before);
    assert_eq!(
        fs::metadata(&files_before[0]).unwrap().modified().unwrap(),
        modified
    );

    let fresh = StateDir::new();
    let config = config_of(&fresh, vec![url_list("volatile", server.url("/l.txt"))]);
    let (mut scheduler, _) = boot_with(&config, SnapshotStore::disabled()).await;
    scheduler.refresh(0, &downloader()).await;
    assert!(!fresh.path().join("lists").exists());
}

#[tokio::test]
async fn refreshes_never_overlap() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.set_delay(Duration::from_millis(60));
    let mut lists = Vec::new();
    for index in 0..4 {
        let path = format!("/l{index}.txt");
        server.serve(&path, &format!("||list{index}.example^\n"), Some("\"e\""));
        lists.push(url_list(&format!("serial-{index}"), server.url(&path)));
    }

    let (scheduler, _) = boot(&config_of(&dir, lists)).await;
    let policy = scheduler.policy();
    let running = tokio::spawn(scheduler.run(downloader(), std::future::pending()));
    tokio::time::sleep(Duration::from_millis(1500)).await;
    running.abort();

    assert!(server.requests() >= 8, "{} requests", server.requests());
    assert_eq!(server.most_active(), 1);
    assert!(blocked(&policy, "list3.example."));
}

#[tokio::test]
async fn the_loop_checks_lists_again_with_their_validators_and_retries_after_a_failure() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/ok.txt", V1, Some("\"ok\""));
    server.fail("/bad.txt", 503);
    let lists = vec![
        url_list("loop-ok", server.url("/ok.txt")),
        url_list("loop-bad", server.url("/bad.txt")),
    ];
    let (scheduler, _) = boot(&config_of(&dir, lists)).await;
    let running = tokio::spawn(scheduler.run(downloader(), std::future::pending()));
    tokio::time::sleep(Duration::from_millis(800)).await;
    running.abort();

    assert!(server.not_modified() >= 2, "{} 304s", server.not_modified());
    assert!(server.requests() >= 6, "{} requests", server.requests());
}

#[tokio::test]
async fn local_files_rules_and_allowlists_make_one_engine() {
    let dir = StateDir::new();
    fs::write(
        dir.file("block.txt"),
        "||list.example^\n||both.example^\n||allowed.example^\n",
    )
    .unwrap();
    fs::write(dir.file("allow.txt"), "||allowed.example^\n").unwrap();
    let mut config = config_of(&dir, vec![path_list(dir.file("block.txt"))]);
    config.rules = vec![
        "||user.example^".to_string(),
        "@@||both.example^".to_string(),
    ];
    config.allowlists = vec![path_list(dir.file("allow.txt"))];

    let (scheduler, store) = boot(&config).await;
    let policy = scheduler.policy();

    assert!(blocked(&policy, "user.example."));
    assert!(blocked(&policy, "sub.list.example."));
    assert!(!blocked(&policy, "both.example."));
    assert!(!blocked(&policy, "allowed.example."));
    assert!(!blocked(&policy, "other.example."));
    assert_eq!(store.bytes_written(), 0, "local files have no snapshot");
}

#[tokio::test]
async fn unreadable_files_are_skipped_and_the_format_and_cap_are_honoured() {
    let dir = StateDir::new();
    fs::write(dir.file("ok.txt"), "||ok.example^\n").unwrap();
    fs::write(
        dir.file("hosts.txt"),
        "0.0.0.0 a.example\n0.0.0.0 b.example\n",
    )
    .unwrap();
    let hosts = ListConfig {
        format: ListFormat::Hosts,
        max_rules: 1,
        ..path_list(dir.file("hosts.txt"))
    };
    let config = config_of(
        &dir,
        vec![
            path_list(dir.file("missing.txt")),
            path_list(dir.file("ok.txt")),
            hosts,
        ],
    );

    let (mut scheduler, _) = boot(&config).await;
    let policy = scheduler.policy();

    assert!(blocked(&policy, "ok.example."));
    assert!(blocked(&policy, "a.example."));
    assert!(!blocked(&policy, "b.example."));
    assert!(scheduler.list(0).is_none());

    // The missing file appears later and is picked up by its refresh.
    fs::write(dir.file("missing.txt"), "||late.example^\n").unwrap();
    scheduler.refresh(0, &downloader()).await;
    assert!(blocked(&policy, "late.example."));
}

#[tokio::test]
async fn a_changed_local_file_is_swapped_in_and_an_unchanged_one_is_kept() {
    let dir = StateDir::new();
    fs::write(dir.file("l.txt"), V1).unwrap();
    let config = config_of(&dir, vec![path_list(dir.file("l.txt"))]);
    let (mut scheduler, _) = boot(&config).await;
    let policy = scheduler.policy();
    let loaded = Arc::clone(scheduler.list(0).unwrap());

    scheduler.refresh(0, &downloader()).await;
    assert!(Arc::ptr_eq(&loaded, scheduler.list(0).unwrap()));

    fs::write(dir.file("l.txt"), V2).unwrap();
    scheduler.refresh(0, &downloader()).await;

    assert!(!Arc::ptr_eq(&loaded, scheduler.list(0).unwrap()));
    assert!(blocked(&policy, "tracker.example."));
}

#[tokio::test]
async fn list_hosts_are_resolved_through_the_upstream_pool() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/l.txt", V1, None);
    let dns = answering_upstream([127, 0, 0, 1], Duration::ZERO).await;
    let upstreams = Upstreams::plain(
        dns.address,
        &Config::default().upstream,
        &Config::default().limits,
    );
    let downloader = Downloader::new(
        resolver_over(Arc::new(upstreams)),
        Arc::new(Tls::with_webpki_roots()),
    );
    let url = format!("http://lists.example:{}/l.txt", server.address.port());
    let config = config_of(&dir, vec![url_list("resolved", url)]);
    let (mut scheduler, _) = boot(&config).await;

    scheduler.refresh(0, &downloader).await;

    assert!(blocked(&scheduler.policy(), "ads.example."));
    assert!(dns.count() >= 1);
}

#[tokio::test]
async fn queries_in_flight_during_a_swap_get_the_new_policy_and_none_are_lost() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/l.txt", "||old.example^\n", Some("\"v1\""));
    let config = config_of(&dir, vec![url_list("swapping", server.url("/l.txt"))]);
    let (mut scheduler, _) = boot(&config).await;
    scheduler.refresh(0, &downloader()).await;
    let policy = scheduler.policy();

    let upstream = answering_upstream([9, 9, 9, 9], Duration::from_millis(800)).await;
    let mut dns_config = config_for(&upstream);
    dns_config.upstream.timeout_ms = 10_000;
    let dns = start_with_policy(&dns_config, Arc::clone(&policy)).await;

    // 30 queries wait for the slow upstream (the pool lets 32 wait at once); the swap lands
    // while they wait.
    let waiting: Vec<_> = (0..30)
        .map(|index| {
            let dns = dns.clone();
            tokio::spawn(async move {
                let name = format!("flight{index}.example.");

                ask(&dns, &name, RecordType::A).await
            })
        })
        .collect();
    for _ in 0..600 {
        if upstream.count() >= 30 {
            break;
        }

        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    assert_eq!(upstream.count(), 30, "every query waits for the upstream");

    // Names the old and the new list both decide the same way are asked all the time.
    let steady = {
        let dns = dns.clone();
        tokio::spawn(async move {
            let mut wrong = 0;
            for _ in 0..30 {
                let old = ask(&dns, "old.example.", RecordType::A).await;
                if old.answers.len() != 1 || old.answers[0].ttl != 10 {
                    wrong += 1;
                }

                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            wrong
        })
    };

    server.serve(
        "/l.txt",
        "||old.example^\n||flight0.example^\n||flight1.example^\n",
        Some("\"v2\""),
    );
    scheduler.refresh(0, &downloader()).await;
    assert_eq!(generation(&policy), 2);

    let mut blocked_replies = Vec::new();
    for (index, reply) in waiting.into_iter().enumerate() {
        let reply = reply.await.unwrap();
        assert_eq!(reply.answers.len(), 1, "flight{index} got no answer");
        blocked_replies.push(reply.answers[0].ttl == 10);
    }

    // Decided at delivery under the new list: the two newly blocked names are blocked, the
    // rest pass with the upstream's 300 s TTL.
    assert_eq!(
        blocked_replies.iter().filter(|blocked| **blocked).count(),
        2
    );
    assert!(blocked_replies[0] && blocked_replies[1]);
    assert_eq!(steady.await.unwrap(), 0);
}

/// Rewrites the snapshot of the first list as if an older compiler had written it.
async fn age_snapshot(config: &Config, version: u32) {
    let list = &config.lists[0];
    let options = CompileOptions::new(list.format, list.max_rules);
    let store = SnapshotStore::open(&config.state.dir).unwrap();
    let path = store.path_for(list.url.as_ref().unwrap()).unwrap();
    let mut snapshot = CompileWorker::spawn()
        .unwrap()
        .load(path, options)
        .await
        .unwrap();

    snapshot.meta.compiler_version = version;
    snapshot.meta.fingerprint = snapshot::fingerprint(
        snapshot.meta.content_hash,
        snapshot.meta.configured_format,
        snapshot.meta.effective_format,
        snapshot.meta.max_rules,
        version,
    );
    store.save(snapshot).await.unwrap();
}

/// Compiler version 2 is the one that kept `$ORIGIN .` in RPZ owners (fixed in 3). Whatever
/// it wrote must be compiled again, whether or not the server would answer 304.
#[tokio::test]
async fn a_snapshot_of_the_previous_compiler_is_compiled_again_without_validators() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/l.txt", V1, None);
    let config = config_of(&dir, vec![url_list("upgrade-plain", server.url("/l.txt"))]);
    {
        let (mut scheduler, _) = boot(&config).await;
        scheduler.refresh(0, &downloader()).await;
    }

    age_snapshot(&config, 2).await;
    let (mut scheduler, store) = boot(&config).await;
    let policy = scheduler.policy();

    assert!(scheduler.list(0).is_none(), "the old snapshot is not used");
    assert!(!blocked(&policy, "ads.example."));

    scheduler.refresh(0, &downloader()).await;

    assert!(blocked(&policy, "ads.example."));
    assert!(store.bytes_written() > 0, "the snapshot is rewritten");
    server.stop().await;
    let (offline, _) = boot(&config).await;
    assert!(blocked(&offline.policy(), "ads.example."));
}

#[tokio::test]
async fn a_snapshot_of_the_previous_compiler_is_compiled_again_whatever_its_validators() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/l.txt", V1, Some("\"v1\""));
    let config = config_of(&dir, vec![url_list("upgrade-tagged", server.url("/l.txt"))]);
    {
        let (mut scheduler, _) = boot(&config).await;
        scheduler.refresh(0, &downloader()).await;
    }

    age_snapshot(&config, 2).await;
    let (mut scheduler, store) = boot(&config).await;
    let policy = scheduler.policy();
    scheduler.refresh(0, &downloader()).await;

    assert_eq!(
        server.not_modified(),
        0,
        "no validator is sent for a snapshot that was not used"
    );
    assert!(blocked(&policy, "ads.example."));
    assert!(store.bytes_written() > 0);
    server.stop().await;
    let (offline, _) = boot(&config).await;
    assert!(blocked(&offline.policy(), "ads.example."));
}

/// A login or error page served with status 200 compiles to junk rules; it must never
/// replace the list in force.
#[tokio::test]
async fn a_web_page_with_status_200_changes_nothing() {
    capture_warnings();
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/l.txt", V1, Some("\"v1\""));
    let config = config_of(&dir, vec![url_list("html-page", server.url("/l.txt"))]);
    let (mut scheduler, store) = boot(&config).await;
    let policy = scheduler.policy();
    scheduler.refresh(0, &downloader()).await;
    let list = Arc::clone(scheduler.list(0).unwrap());
    let written = store.bytes_written();
    let generation_before = generation(&policy);
    let snapshot_path = dir.snapshot_files().remove(0);
    let snapshot_before = fs::read(&snapshot_path).unwrap();
    let page = "<!DOCTYPE html>\n<html><body>\n||junk.example^\nSign in\n</body></html>\n";

    for (body, content_type) in [
        (page, Some("text/html; charset=utf-8")),
        (page, None),
        ("  \n<HTML><body>Sign in", Some("text/plain")),
    ] {
        server.serve_typed("/l.txt", body, Some("\"page\""), content_type);
        scheduler.refresh(0, &downloader()).await;

        assert!(Arc::ptr_eq(&list, scheduler.list(0).unwrap()));
        assert!(blocked(&policy, "ads.example."));
        assert!(!blocked(&policy, "junk.example."));
        assert_eq!(generation(&policy), generation_before);
        assert_eq!(store.bytes_written(), written);
        assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot_before);
    }

    // The validators of the list in force were not replaced by the page's ETag.
    server.serve("/l.txt", V1, Some("\"v1\""));
    scheduler.refresh(0, &downloader()).await;
    assert_eq!(server.not_modified(), 1);
    assert_eq!(warnings_about("html-page"), 1, "one warning per streak");
}

/// Makes the snapshot directory impossible to create, the way a full or read-only disk
/// would; `clear` puts the disk right again.
struct BlockedSnapshots(PathBuf);

impl BlockedSnapshots {
    fn new(dir: &StateDir) -> BlockedSnapshots {
        let path = dir.file("lists");
        fs::write(&path, b"in the way").unwrap();

        BlockedSnapshots(path)
    }

    fn clear(&self) {
        fs::remove_file(&self.0).unwrap();
    }
}

#[tokio::test]
async fn a_failed_snapshot_write_is_retried_while_the_list_stays_unchanged() {
    capture_warnings();
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/tagged.txt", V1, Some("\"t\""));
    server.serve("/plain.txt", V1, None);
    let lists = vec![
        url_list("retry-tagged", server.url("/tagged.txt")),
        url_list("retry-plain", server.url("/plain.txt")),
    ];
    let config = config_of(&dir, lists);
    let (mut scheduler, store) = boot(&config).await;
    let disk = BlockedSnapshots::new(&dir);
    let policy = scheduler.policy();
    scheduler.refresh(0, &downloader()).await;
    scheduler.refresh(1, &downloader()).await;

    assert!(blocked(&policy, "ads.example."), "the list is in force");
    assert_eq!(warnings_about("retry-tagged"), 1);
    assert_eq!(store.bytes_written(), 0);

    // A retry on a disk that is still broken fails again, quietly.
    scheduler.retry_save(0).await;
    assert_eq!(warnings_about("retry-tagged"), 1, "one warning per streak");

    // The disk is fine now, but an unchanged list (304, or the same content again) is
    // checked without writing anything.
    disk.clear();
    scheduler.refresh(0, &downloader()).await;
    scheduler.refresh(1, &downloader()).await;

    assert_eq!(server.not_modified(), 1);
    assert_eq!(store.bytes_written(), 0);
    assert!(dir.snapshot_files().is_empty());

    scheduler.retry_save(0).await;
    scheduler.retry_save(1).await;

    assert_eq!(dir.snapshot_files().len(), 2);
    let written = store.bytes_written();
    assert!(written > 0);
    scheduler.retry_save(0).await;
    assert_eq!(
        store.bytes_written(),
        written,
        "nothing is pending any more"
    );

    drop(scheduler);
    server.stop().await;
    let (offline, _) = boot(&config).await;

    assert!(offline.list(0).is_some() && offline.list(1).is_some());
    assert!(blocked(&offline.policy(), "ads.example."));
}

#[tokio::test]
async fn the_loop_writes_a_failed_snapshot_by_itself() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/l.txt", V1, Some("\"v1\""));
    let config = config_of(&dir, vec![url_list("loop-retry", server.url("/l.txt"))]);
    let (mut scheduler, _) = boot(&config).await;
    let disk = BlockedSnapshots::new(&dir);
    scheduler.refresh(0, &downloader()).await;
    assert!(dir.snapshot_files().is_empty());

    disk.clear();
    let running = tokio::spawn(scheduler.run(downloader(), std::future::pending()));
    let deadline = Instant::now() + Duration::from_secs(10);
    while dir.snapshot_files().is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    running.abort();

    assert_eq!(dir.snapshot_files().len(), 1);
}

/// A newer copy replaces the one that could not be written; the old one is never written.
#[tokio::test]
async fn a_newer_list_supersedes_a_snapshot_that_was_never_written() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/l.txt", V1, Some("\"v1\""));
    let config = config_of(&dir, vec![url_list("superseded", server.url("/l.txt"))]);
    let (mut scheduler, _) = boot(&config).await;
    let disk = BlockedSnapshots::new(&dir);
    scheduler.refresh(0, &downloader()).await;

    disk.clear();
    server.serve("/l.txt", V2, Some("\"v2\""));
    scheduler.refresh(0, &downloader()).await;
    drop(scheduler);
    server.stop().await;
    let (offline, _) = boot(&config).await;

    assert!(blocked(&offline.policy(), "tracker.example."));
}

/// What SIGTERM asks of the loop: the refresh in progress completes and is saved, and no
/// other refresh starts.
#[tokio::test]
async fn stopping_the_loop_finishes_the_refresh_in_progress_and_starts_no_other() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/l.txt", V1, Some("\"v1\""));
    server.set_delay(Duration::from_millis(300));
    let config = config_of(&dir, vec![url_list("stopping", server.url("/l.txt"))]);
    let (scheduler, _) = boot(&config).await;
    let policy = scheduler.policy();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(scheduler.run(downloader(), async {
        let _ = stopped.await;
    }));

    while server.requests() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), running)
        .await
        .expect("the loop stops")
        .unwrap();

    assert!(blocked(&policy, "ads.example."), "the refresh was finished");
    assert_eq!(dir.snapshot_files().len(), 1, "and saved");
    // The intervals are milliseconds long, so a loop that went on would have asked again.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(server.requests(), 1);
}

#[tokio::test]
async fn stopping_the_loop_tries_once_more_to_write_a_pending_snapshot() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/l.txt", V1, Some("\"v1\""));
    let config = config_of(&dir, vec![url_list("last-try", server.url("/l.txt"))]);
    let (mut scheduler, _) = boot(&config).await;
    let disk = BlockedSnapshots::new(&dir);
    scheduler.refresh(0, &downloader()).await;
    disk.clear();

    scheduler.run(downloader(), async {}).await;

    assert_eq!(dir.snapshot_files().len(), 1);
}

fn slow_timing() -> Timing {
    Timing {
        hour: Duration::from_secs(3600),
        retries: [Duration::from_secs(3600); 4],
        first_check: Duration::from_secs(3600 * 1000),
    }
}

async fn wait_for_requests(server: &ListServer, count: usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while server.requests() < count {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{} of {count} requests", server.requests()));
}

#[tokio::test]
async fn asking_for_a_refresh_checks_every_list_once_and_one_at_a_time() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.set_delay(Duration::from_millis(40));
    let mut lists = Vec::new();
    for index in 0..3 {
        let path = format!("/l{index}.txt");
        server.serve(&path, &format!("||list{index}.example^\n"), Some("\"e\""));
        lists.push(url_list(&format!("manual-{index}"), server.url(&path)));
    }
    let config = config_of(&dir, lists);
    let scheduler = Scheduler::boot(
        &config,
        CompileWorker::spawn().unwrap(),
        Arc::new(SnapshotStore::disabled()),
        slow_timing(),
    )
    .await
    .unwrap();
    let control = scheduler.control();
    let running = tokio::spawn(scheduler.run(downloader(), std::future::pending()));

    // Lists without a snapshot are fetched at once; after that the interval is a day.
    wait_for_requests(&server, 3).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(server.requests(), 3);

    control.refresh_all();
    wait_for_requests(&server, 6).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    running.abort();

    assert_eq!(server.requests(), 6, "once per list");
    assert_eq!(server.not_modified(), 3, "the validators were sent");
    assert_eq!(server.most_active(), 1);
}

#[tokio::test]
async fn the_status_of_a_list_follows_its_refreshes() {
    let dir = StateDir::new();
    let server = ListServer::start().await;
    server.serve("/good.txt", "0.0.0.0 ads.example\n", Some("\"g\""));
    server.fail("/bad.txt", 503);
    let mut config = config_of(
        &dir,
        vec![
            ListConfig {
                format: ListFormat::Hosts,
                ..url_list("good", server.url("/good.txt"))
            },
            url_list("bad", server.url("/bad.txt")),
        ],
    );
    config.allowlists = vec![url_list("allow", server.url("/good.txt"))];
    let (mut scheduler, _) = boot(&config).await;
    let control = scheduler.control();

    let before = control.statuses();
    assert_eq!(
        before
            .iter()
            .map(|list| list.name.as_str())
            .collect::<Vec<_>>(),
        ["good", "bad", "allow"]
    );
    assert_eq!(
        before.iter().map(|list| list.role).collect::<Vec<_>>(),
        [Role::Blocklist, Role::Blocklist, Role::Allowlist]
    );
    assert!(before.iter().all(|list| {
        list.format.is_none()
            && list.rules == 0
            && list.checked.is_none()
            && list.last_error.is_none()
    }));

    scheduler.refresh(0, &downloader()).await;
    scheduler.refresh(1, &downloader()).await;

    let after = control.statuses();
    assert_eq!(after[0].format, Some(ListFormat::Hosts));
    assert_eq!(after[0].rules, 1);
    assert!(after[0].checked.is_some() && after[0].last_error.is_none());
    assert!(after[1].checked.is_none());
    assert!(
        after[1]
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("503")),
        "{:?}",
        after[1].last_error
    );
    assert_eq!(after[2].rules, 0);

    server.serve("/bad.txt", V1, None);
    scheduler.refresh(1, &downloader()).await;

    let recovered = control.statuses();
    assert_eq!(recovered[1].rules, 1);
    assert_eq!(recovered[1].format, Some(ListFormat::Adblock));
    assert!(recovered[1].last_error.is_none());
}
