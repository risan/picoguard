//! Snapshots of the real benchmark lists: a loaded snapshot decides exactly like the list
//! compiled from source, and a refresh that brings the same text writes nothing.

mod common;

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::{Query, load_real};
use picoguard::filter::compile::{CompileOptions, CompileWorker, Compiled};
use picoguard::filter::engine::{Decision, Engine, blocked_answer};
use picoguard::filter::parse::{ListFormat, dns_type_code};
use picoguard::filter::snapshot::{Snapshot, SnapshotStore, load};
use picoguard::lists::{MAX_PIECE_BYTES, Piece, Validators};

const MAX_RULES: u32 = 3_000_000;

struct StateDir(PathBuf);

impl StateDir {
    fn new(label: &str) -> StateDir {
        let path = std::env::temp_dir().join(format!("picoguard-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();

        StateDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for StateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn options() -> CompileOptions {
    CompileOptions::new(ListFormat::Auto, MAX_RULES)
}

fn source(index: usize) -> String {
    format!("https://lists.example/list{index}.txt")
}

async fn compile(worker: &CompileWorker, text: &str) -> Compiled {
    let compilation = worker.start(options());
    for piece in text.as_bytes().chunks(MAX_PIECE_BYTES) {
        compilation
            .pieces
            .send(Piece::Data(piece.to_vec()))
            .await
            .unwrap();
    }

    compilation.pieces.send(Piece::End).await.unwrap();

    compilation.result().await.unwrap()
}

fn engine_of(snapshots: &[Snapshot]) -> Engine {
    Engine::new(
        snapshots.iter().map(|s| Arc::clone(&s.list)).collect(),
        Vec::new(),
    )
}

fn answer(engine: &Engine, query: &Query) -> (bool, String) {
    let is_ip = query.input.parse::<IpAddr>().is_ok();
    let check = dns_type_code(&query.check_type).unwrap();
    let query_type = dns_type_code(&query.query_type).unwrap();

    match engine.check(&query.input, check, is_ip) {
        Decision::Pass => (false, String::new()),
        Decision::Block { ips } => (true, format!("{:?}", blocked_answer(query_type, &ips))),
    }
}

#[tokio::test]
async fn loaded_snapshots_of_the_real_lists_decide_like_the_compiled_lists() {
    let real = load_real();
    let worker = CompileWorker::spawn().unwrap();
    let state = StateDir::new("snapshot-real");
    let store = SnapshotStore::open(state.path()).unwrap();

    let mut compiled = Vec::new();
    for (index, text) in real.lists.iter().enumerate() {
        let list = compile(&worker, text).await;
        let snapshot = Snapshot::new(&list, &options(), &source(index), Validators::default());
        store
            .save(Snapshot::new(
                &list,
                &options(),
                &source(index),
                Validators::default(),
            ))
            .await;
        compiled.push(snapshot);
    }

    store.flush().await;

    let mut loaded = Vec::new();
    for (index, snapshot) in compiled.iter().enumerate() {
        let path = store.path_for(&source(index)).unwrap();
        let from_disk = worker.load(path, options()).await.unwrap();
        assert_eq!(from_disk.meta, snapshot.meta);
        assert_eq!(from_disk.counters, snapshot.counters);
        assert_eq!(from_disk.list.rule_count(), snapshot.list.rule_count());
        assert_eq!(
            from_disk.list.slow_rule_count(),
            snapshot.list.slow_rule_count()
        );
        assert_eq!(from_disk.list.regex_failed(), snapshot.list.regex_failed());
        loaded.push(from_disk);
    }

    let from_source = engine_of(&compiled);
    let from_snapshots = engine_of(&loaded);
    let mut blocked = 0;
    for entry in &real.expected {
        let expected = answer(&from_source, &entry.query);
        assert_eq!(
            answer(&from_snapshots, &entry.query),
            expected,
            "{}",
            entry.query.key()
        );
        if expected.0 {
            blocked += 1;
        }
    }

    assert_eq!(real.expected.len(), 3000);
    assert!(blocked > 1000);
}

#[tokio::test]
async fn a_refresh_with_the_same_text_writes_nothing_even_after_a_restart() {
    let real = load_real();
    let state = StateDir::new("snapshot-restart");
    let mut sizes = Vec::new();
    {
        let worker = CompileWorker::spawn().unwrap();
        let store = SnapshotStore::open(state.path()).unwrap();
        for (index, text) in real.lists.iter().enumerate() {
            let list = compile(&worker, text).await;
            store
                .save(Snapshot::new(
                    &list,
                    &options(),
                    &source(index),
                    Validators::default(),
                ))
                .await;
        }

        store.flush().await;
        for index in 0..real.lists.len() {
            let path = store.path_for(&source(index)).unwrap();
            sizes.push(fs::metadata(path).unwrap().len());
        }

        assert_eq!(store.bytes_written(), sizes.iter().sum::<u64>());
    }

    let worker = CompileWorker::spawn().unwrap();
    let store = SnapshotStore::open(state.path()).unwrap();
    let mut modified = Vec::new();
    for (index, text) in real.lists.iter().enumerate() {
        let path = store.path_for(&source(index)).unwrap();
        let boot = worker.load(path.clone(), options()).await.unwrap();
        assert!(boot.fits(&source(index), &options()));
        modified.push(fs::metadata(&path).unwrap().modified().unwrap());

        let refreshed = compile(&worker, text).await;
        assert_eq!(refreshed.fingerprint, boot.meta.fingerprint);
        store
            .save(Snapshot::new(
                &refreshed,
                &options(),
                &source(index),
                Validators::default(),
            ))
            .await;
    }

    store.flush().await;

    assert_eq!(store.bytes_written(), 0);
    for (index, before) in modified.iter().enumerate() {
        let path = store.path_for(&source(index)).unwrap();
        assert_eq!(fs::metadata(path).unwrap().modified().unwrap(), *before);
    }

    let total: u64 = sizes.iter().sum();
    println!("snapshot sizes for the three real lists: {sizes:?} bytes, {total} in total");
    assert!(total < 8 * 1024 * 1024);
}

#[tokio::test]
async fn a_changed_format_with_the_same_text_is_rewritten_after_a_restart() {
    let real = load_real();
    let text = &real.lists[2];
    let state = StateDir::new("snapshot-format");
    let as_domains = CompileOptions {
        format: ListFormat::Domains,
        ..options()
    };
    {
        let worker = CompileWorker::spawn().unwrap();
        let store = SnapshotStore::open(state.path()).unwrap();
        let list = compile(&worker, text).await;
        store
            .save(Snapshot::new(
                &list,
                &options(),
                &source(0),
                Validators::default(),
            ))
            .await;
        store.flush().await;
    }

    let worker = CompileWorker::spawn().unwrap();
    let store = SnapshotStore::open(state.path()).unwrap();
    let path = store.path_for(&source(0)).unwrap();
    let boot = load(&path, &options()).unwrap();
    assert!(boot.fits(&source(0), &options()));
    assert!(!boot.fits(&source(0), &as_domains));

    let compilation = worker.start(as_domains);
    for piece in text.as_bytes().chunks(MAX_PIECE_BYTES) {
        compilation
            .pieces
            .send(Piece::Data(piece.to_vec()))
            .await
            .unwrap();
    }

    compilation.pieces.send(Piece::End).await.unwrap();
    let recompiled = compilation.result().await.unwrap();
    assert_eq!(recompiled.content_hash, boot.meta.content_hash);
    assert_ne!(recompiled.fingerprint, boot.meta.fingerprint);

    store
        .save(Snapshot::new(
            &recompiled,
            &as_domains,
            &source(0),
            Validators::default(),
        ))
        .await;
    store.flush().await;

    assert!(store.bytes_written() > 0);
    let rewritten = load(&path, &options()).unwrap();
    assert_eq!(rewritten.meta.configured_format, ListFormat::Domains);
}
