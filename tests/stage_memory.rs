//! What staging an update holds while it runs and after it ends, and what `verify-update`
//! holds. This file has its own test binary so that the counting allocator sees only these
//! checks. The binary comes from a server that writes a 16 KiB pattern over and over, so
//! neither side ever holds a whole binary.

mod common;

use std::fs;
use std::io;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use common::release::{Files, REQUEST_ID, TARGET, hex, scratch, sign, test_key};
use common::stream::{Route, StreamServer, pattern_hash};
use picoguard::lists::Names;
use picoguard::release::{Request, VerifySetup, verify_update};
use picoguard::stage::{StageSetup, StageTiming, Stager};
use picoguard::update::{Build, Latest, Updates};
use picoguard::upstream::tls::Tls;

const MIB: u64 = 1024 * 1024;
const PEAK_BUDGET_BYTES: usize = 1024 * 1024;
const KEPT_BUDGET_BYTES: usize = 1024;
const VERSION: &str = "9.9.9";
const SHORT_RUNS: usize = 60;
const LONG_RUNS: usize = 8;

#[path = "common/counting.rs"]
mod counting;

use counting::{live, peak_since, reset_peak, settle};

#[global_allocator]
static ALLOCATOR: counting::Counting = counting::Counting;

/// The counters are the process's, so the tests take turns: each holds this while it prepares
/// and measures.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn base(version: &str, file: &str) -> String {
    format!("/download/v{version}/{file}")
}

/// A release of `size` bytes of the pattern, signed with the test key.
fn serve_release(server: &StreamServer, size: u64) {
    let sums = format!("{}  picoguard-{TARGET}\n", hex(&pattern_hash(size))).into_bytes();
    server.set(&base(VERSION, "SHA256SUMS.sig"), Route::Bytes(sign(&sums)));
    server.set(&base(VERSION, "SHA256SUMS"), Route::Bytes(sums));
    server.set(
        &base(VERSION, &format!("picoguard-{TARGET}")),
        Route::Pattern {
            size,
            hold_at_half: false,
        },
    );
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);

    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Stages the release on the server, answers it as the installer with a failure, and returns
/// the peak and what stayed.
async fn stage_once(stager: &Arc<Stager>, root: &std::path::Path) -> (usize, usize) {
    let before = reset_peak();

    stager.start(VERSION).unwrap();
    until("waiting", || {
        stager.view().is_some_and(|view| view.state == "waiting")
    })
    .await;
    let request = Request::parse(&fs::read(root.join("state/update/request")).unwrap()).unwrap();
    fs::write(
        root.join("installer/result"),
        format!("id={}\noutcome=failed\nreason=a test\n", request.id),
    )
    .unwrap();
    until("failed", || {
        stager.view().is_some_and(|view| view.state == "failed")
    })
    .await;
    settle().await;

    (peak_since(before), live().saturating_sub(before))
}

#[test]
fn staging_peaks_below_a_megabyte_whatever_the_size_and_keeps_nothing() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let root = scratch("stage-memory");
        fs::create_dir(root.join("state")).unwrap();
        fs::create_dir(root.join("installer")).unwrap();
        let server = StreamServer::start().await;
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
                max_binary_bytes: 16 * MIB,
                timing: StageTiming {
                    poll: Duration::from_millis(10),
                    wait: Duration::from_secs(60),
                },
            },
            updates,
            Names::Resolver(Arc::new(|_| {
                Box::pin(async { Err(io::Error::other("no DNS in this test")) })
            })),
            Arc::new(Tls::with_webpki_roots()),
        );

        // What tokio and the first connections grow on first use is not the update's.
        serve_release(&server, 256 * 1024);
        stage_once(&stager, &root).await;
        stage_once(&stager, &root).await;

        // How many 64 KiB pieces are in flight at once depends on how the threads happen to
        // run, and a short transfer rarely fills the pipeline, so each size is staged several
        // times and its worst run is held to the budget. The two peaks are not compared:
        // which one is higher depends on that timing, not on the size.
        let worst = async |size: u64, runs: usize| {
            serve_release(&server, size);
            let mut worst = (0, 0);

            for _ in 0..runs {
                let (peak, kept) = stage_once(&stager, &root).await;
                worst = (worst.0.max(peak), worst.1.max(kept));
            }

            worst
        };
        let (peak_1, kept_1) = worst(MIB, SHORT_RUNS).await;
        let (peak_8, kept_8) = worst(8 * MIB, LONG_RUNS).await;

        println!("staging 1 MiB: peak {peak_1} bytes, kept {kept_1} bytes");
        println!("staging 8 MiB: peak {peak_8} bytes, kept {kept_8} bytes");

        assert!(peak_1 < PEAK_BUDGET_BYTES, "peak {peak_1} bytes");
        assert!(peak_8 < PEAK_BUDGET_BYTES, "peak {peak_8} bytes");
        assert!(kept_1 < KEPT_BUDGET_BYTES, "kept {kept_1} bytes");
        assert!(kept_8 < KEPT_BUDGET_BYTES, "kept {kept_8} bytes");
    });
}

#[test]
fn verifying_an_update_peaks_below_a_megabyte() {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
    let root = scratch("verify-memory");
    let script = b"#!/bin/sh\necho \"picoguard 9.9.9\"\nexit 0\n";
    let mut binary = script.to_vec();
    binary.resize(8 * MIB as usize, b'#');
    let mut files = Files::good(VERSION, &binary);
    files.request = Request {
        id: REQUEST_ID.to_string(),
        version: VERSION.to_string(),
    }
    .format()
    .into_bytes();
    files.write(&root.join("staged"));
    drop(binary);
    drop(files);
    let setup = VerifySetup {
        key: test_key(),
        target: Some(TARGET),
        running: env!("CARGO_PKG_VERSION"),
    };
    let before = reset_peak();

    let outcome = verify_update(&root.join("staged"), &root.join("out"), &setup);

    let peak = peak_since(before);
    println!("verify-update of 8 MiB: peak {peak} bytes");

    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(peak < PEAK_BUDGET_BYTES, "peak {peak} bytes");
}
