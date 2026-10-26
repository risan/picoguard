//! Downloading, verifying and staging an update against a local fake of the release
//! downloads, with a throwaway signing key. Nothing leaves the machine: every URL is an IP
//! literal on 127.0.0.1 and the resolver always fails.

mod common;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::http::ListServer;
use common::release::{Files, TARGET, scratch, sign_with, sums_line, test_key};
use picoguard::release::Request;
use picoguard::stage::{InstallView, Refused, StageSetup, StageTiming, Stager};
use picoguard::update::{Build, Latest, Updates};
use picoguard::upstream::tls::Tls;

const VERSION: &str = "9.9.9";
const CAP: u64 = 64 * 1024;
const FOUR_FILES: [&str; 4] = ["SHA256SUMS", "SHA256SUMS.sig", "picoguard", "request"];

fn path(file: &str) -> String {
    format!("/download/v{VERSION}/{file}")
}

fn binary_path() -> String {
    path(&format!("picoguard-{TARGET}"))
}

fn binary() -> Vec<u8> {
    (0..30_000u32)
        .map(|index| (index * 7 % 251) as u8)
        .collect()
}

fn release_files() -> Files {
    Files::good(VERSION, &binary())
}

fn serve(server: &ListServer, files: &Files) {
    server.serve_bytes(&path("SHA256SUMS"), files.sums.clone());
    server.serve_bytes(&path("SHA256SUMS.sig"), files.signature.clone());
    server.serve_bytes(&binary_path(), files.binary.clone());
}

fn setup(server: &ListServer, root: &Path) -> StageSetup {
    StageSetup {
        target: Some(TARGET),
        base_url: server.url("/download"),
        state_dir: root.join("state"),
        installer_dir: root.join("installer"),
        key: test_key(),
        max_binary_bytes: CAP,
        timing: StageTiming {
            poll: Duration::from_millis(20),
            wait: Duration::from_secs(2),
        },
    }
}

fn updates_with(version: &str) -> Arc<Updates> {
    let updates = Arc::new(Updates::new(Build::Release));
    updates.show(Some(Latest {
        version: version.to_string(),
        notes: String::new(),
    }));

    updates
}

fn stager_from(setup: StageSetup, updates: Arc<Updates>) -> Arc<Stager> {
    Stager::new(
        setup,
        updates,
        Arc::new(|_| Box::pin(async { Err(io::Error::other("no DNS in this test")) })),
        Arc::new(Tls::with_webpki_roots()),
    )
}

struct Rig {
    server: ListServer,
    root: PathBuf,
    stager: Arc<Stager>,
}

impl Rig {
    fn staged(&self) -> PathBuf {
        self.root.join("state/update")
    }
}

async fn make_rig(name: &str, files: &Files) -> Rig {
    let root = scratch(&format!("stage-update-{name}"));
    fs::create_dir(root.join("state")).unwrap();
    fs::create_dir(root.join("installer")).unwrap();
    let server = ListServer::start().await;
    serve(&server, files);
    let stager = stager_from(setup(&server, &root), updates_with(VERSION));

    Rig {
        server,
        root,
        stager,
    }
}

fn is_running(view: &InstallView) -> bool {
    matches!(view.state, "checking" | "downloading" | "verifying")
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);

    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Polls until the update leaves the states that run.
async fn ended(stager: &Stager) -> InstallView {
    until("the update to stop running", || {
        stager.view().is_some_and(|view| !is_running(&view))
    })
    .await;

    stager.view().unwrap()
}

async fn start_and_end(rig: &Rig) -> InstallView {
    rig.stager.start(VERSION).unwrap();

    ended(&rig.stager).await
}

/// The names in `dir`; a directory that was never made holds nothing.
fn names(dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();

    names
}

/// Every path below `root`, relative to it, sorted.
fn listing(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, root: &Path, found: &mut Vec<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            found.push(path.strip_prefix(root).unwrap().display().to_string());

            if path.is_dir() {
                walk(&path, root, found);
            }
        }
    }

    let mut found = Vec::new();
    walk(root, root, &mut found);
    found.sort();

    found
}

fn assert_failed(view: &InstallView, reason_starts: &str) {
    assert_eq!(view.state, "failed", "{view:?}");
    let reason = view.reason.as_deref().unwrap();
    assert!(reason.starts_with(reason_starts), "{reason:?}");
    assert!(reason.len() <= 200 && !reason.contains('\n'), "{reason:?}");
}

#[tokio::test]
async fn a_good_update_is_staged_and_waits() {
    let files = release_files();
    let rig = make_rig("good", &files).await;

    let view = start_and_end(&rig).await;

    assert_eq!(view.state, "waiting");
    assert_eq!(view.version, VERSION);
    assert_eq!(names(&rig.staged()), FOUR_FILES);
    assert_eq!(
        fs::read(rig.staged().join("picoguard")).unwrap(),
        files.binary
    );
    assert_eq!(
        fs::read(rig.staged().join("SHA256SUMS")).unwrap(),
        files.sums
    );
    assert_eq!(
        fs::read(rig.staged().join("SHA256SUMS.sig")).unwrap(),
        files.signature
    );

    let request = Request::parse(&fs::read(rig.staged().join("request")).unwrap()).unwrap();

    assert_eq!(request.version, VERSION);
    assert_eq!(request.id.len(), 16);

    for requested in [path("SHA256SUMS"), path("SHA256SUMS.sig"), binary_path()] {
        assert_eq!(rig.server.requested(&requested), 1, "{requested}");
    }
}

#[tokio::test]
async fn a_bad_signature_stops_before_the_binary() {
    let mut other_key = release_files();
    other_key.signature = sign_with(8, &other_key.sums);
    let mut short = release_files();
    short.signature.truncate(63);
    let mut changed = release_files();
    changed.sums.push(b'\n');

    for (name, files) in [
        ("other-key", other_key),
        ("short", short),
        ("changed", changed),
    ] {
        let rig = make_rig(&format!("signature-{name}"), &files).await;

        let view = start_and_end(&rig).await;

        assert_failed(&view, "signature");
        assert_eq!(rig.server.requested(&binary_path()), 0, "{name}");
        assert!(names(&rig.staged()).is_empty(), "{name}");
    }
}

#[tokio::test]
async fn a_binary_that_does_not_match_is_removed() {
    let mut changed = release_files();
    changed.binary[100] ^= 1;
    let mut missing_line = release_files();
    missing_line.resign(&sums_line("picoguard-other", &missing_line.binary));
    let mut two_lines = release_files();
    let line = sums_line(&format!("picoguard-{TARGET}"), &two_lines.binary);
    two_lines.resign(&format!("{line}{line}"));

    for (name, files, reason) in [
        ("changed", changed, "the binary does not match"),
        (
            "missing-line",
            missing_line,
            "the release has no binary for",
        ),
        ("two-lines", two_lines, "SHA256SUMS lists"),
    ] {
        let rig = make_rig(name, &files).await;

        let view = start_and_end(&rig).await;

        assert_failed(&view, reason);
        assert!(names(&rig.staged()).is_empty(), "{name}");
    }

    let rig = make_rig("binary-404", &release_files()).await;
    rig.server.fail(&binary_path(), 404);

    let view = start_and_end(&rig).await;

    assert_failed(&view, "picoguard: HTTP status 404");
    assert!(names(&rig.staged()).is_empty());

    let rig = make_rig("sums-404", &release_files()).await;
    rig.server.fail(&path("SHA256SUMS"), 404);

    let view = start_and_end(&rig).await;

    assert_failed(&view, "SHA256SUMS: HTTP status 404");
    assert_eq!(rig.server.requested(&binary_path()), 0);
    assert!(names(&rig.staged()).is_empty());
}

#[tokio::test]
async fn a_binary_over_the_cap_is_refused() {
    let big = vec![b'x'; 100 * 1024];
    let mut files = release_files();
    files.binary = big.clone();
    files.resign(&sums_line(&format!("picoguard-{TARGET}"), &big));

    let rig = make_rig("over-cap", &files).await;
    let view = start_and_end(&rig).await;

    assert_failed(&view, "the binary is larger than");
    assert!(names(&rig.staged()).is_empty());

    let rig = make_rig("over-cap-unsized", &files).await;
    rig.server.serve_unsized(&binary_path(), big);
    let view = start_and_end(&rig).await;

    assert_failed(&view, "the binary is larger than");
    assert!(names(&rig.staged()).is_empty());
}

#[tokio::test]
async fn a_redirected_binary_is_followed() {
    let files = release_files();
    let rig = make_rig("redirect", &files).await;
    rig.server
        .serve_bytes("/elsewhere/bin", files.binary.clone());
    rig.server.redirect(&binary_path(), "/elsewhere/bin");

    let view = start_and_end(&rig).await;

    assert_eq!(view.state, "waiting");
    assert_eq!(rig.server.requested("/elsewhere/bin"), 1);
    assert_eq!(names(&rig.staged()), FOUR_FILES);
}

#[tokio::test]
async fn nothing_is_written_outside_the_update_directory() {
    let files = release_files();
    let rig = make_rig("outside", &files).await;

    assert_eq!(start_and_end(&rig).await.state, "waiting");
    assert_eq!(
        listing(&rig.root),
        [
            "installer",
            "state",
            "state/update",
            "state/update/SHA256SUMS",
            "state/update/SHA256SUMS.sig",
            "state/update/picoguard",
            "state/update/request",
        ]
    );

    let mut changed = files.clone();
    changed.binary[0] ^= 1;
    let rig = make_rig("outside-failed", &files).await;
    rig.server.serve_bytes(&binary_path(), changed.binary);

    assert_eq!(start_and_end(&rig).await.state, "failed");
    assert_eq!(listing(&rig.root), ["installer", "state", "state/update"]);

    let root = scratch("stage-update-outside-missing");
    fs::create_dir(root.join("installer")).unwrap();
    let server = ListServer::start().await;
    serve(&server, &files);
    let stager = stager_from(setup(&server, &root), updates_with(VERSION));
    stager.start(VERSION).unwrap();

    let view = ended(&stager).await;

    assert_failed(&view, "disk");
    assert_eq!(listing(&root), ["installer"]);
}

#[tokio::test]
async fn a_second_start_is_refused_while_one_runs() {
    let files = release_files();
    let rig = make_rig("second", &files).await;
    rig.server.serve_slowly(
        &binary_path(),
        files.binary.clone(),
        10_000,
        Duration::from_millis(150),
    );

    rig.stager.start(VERSION).unwrap();

    assert_eq!(rig.stager.start(VERSION), Err(Refused::InProgress));
    assert!(!rig.stager.can_install());
    assert_eq!(ended(&rig.stager).await.state, "waiting");
    assert_eq!(rig.stager.start(VERSION), Err(Refused::InProgress));
    assert_eq!(rig.server.requested(&path("SHA256SUMS")), 1);
    assert_eq!(rig.server.requested(&binary_path()), 1);
}

#[tokio::test]
async fn a_failed_update_can_be_retried() {
    let files = release_files();
    let rig = make_rig("retry", &files).await;
    rig.server.fail(&binary_path(), 404);

    let view = start_and_end(&rig).await;

    assert_failed(&view, "picoguard: HTTP status 404");
    assert!(rig.staged().is_dir());
    assert!(names(&rig.staged()).is_empty());
    assert!(rig.stager.can_install());

    rig.server.serve_bytes(&binary_path(), files.binary.clone());
    let view = start_and_end(&rig).await;

    assert_eq!(view.state, "waiting");
    assert_eq!(names(&rig.staged()), FOUR_FILES);
}

#[tokio::test]
async fn a_disk_failure_stops_the_download_and_can_be_retried() {
    let files = release_files();
    let rig = make_rig("disk", &files).await;
    fs::remove_dir(rig.root.join("state")).unwrap();
    rig.server.serve_slowly(
        &binary_path(),
        files.binary.clone(),
        1024,
        Duration::from_secs(30),
    );
    let started = Instant::now();

    rig.stager.start(VERSION).unwrap();
    let view = ended(&rig.stager).await;

    assert_failed(&view, "disk");
    assert!(started.elapsed() < Duration::from_secs(1));
    until("the connection to close", || rig.server.active() == 0).await;
    assert!(started.elapsed() < Duration::from_secs(2));

    let watch = Instant::now();
    while watch.elapsed() < Duration::from_millis(500) {
        assert_ne!(rig.stager.view().unwrap().state, "downloading");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    fs::create_dir(rig.root.join("state")).unwrap();
    rig.server.serve_bytes(&binary_path(), files.binary.clone());

    let view = start_and_end(&rig).await;

    assert_eq!(view.state, "waiting");
    assert_eq!(names(&rig.staged()), FOUR_FILES);
    until("the connections to close", || rig.server.active() == 0).await;
}
