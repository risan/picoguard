//! Heap cost of loading a snapshot. This test binary has a counting global allocator and a
//! single test, so nothing else allocates while it measures.

use picoguard::filter::compile::{CompileOptions, CompileWorker};
use picoguard::filter::parse::ListFormat;
use picoguard::filter::snapshot::{Snapshot, SnapshotStore, load};
use picoguard::lists::{MAX_PIECE_BYTES, Piece, Validators};

#[path = "common/counting.rs"]
mod counting;

use counting::{live, peak_bytes, reset_peak};

#[global_allocator]
static ALLOCATOR: counting::Counting = counting::Counting;

const RULES: usize = 450_000;
const MAX_RULES: u32 = 3_000_000;

#[tokio::test]
async fn loading_a_snapshot_costs_eight_bytes_per_plain_rule_and_no_scratch() {
    let state =
        std::env::temp_dir().join(format!("picoguard-snapshot-memory-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state);
    let options = CompileOptions::new(ListFormat::Adblock, MAX_RULES);

    let worker = CompileWorker::spawn().unwrap();
    let store = SnapshotStore::open(&state).unwrap();
    let compilation = worker.start(options);
    let mut piece = Vec::new();
    for n in 0..RULES {
        piece.extend_from_slice(format!("||host{n}.tracker{}.example^\n", n % 977).as_bytes());
        if piece.len() >= MAX_PIECE_BYTES - 64 {
            compilation
                .pieces
                .send(Piece::Data(std::mem::take(&mut piece)))
                .await
                .unwrap();
        }
    }

    compilation.pieces.send(Piece::Data(piece)).await.unwrap();
    compilation.pieces.send(Piece::End).await.unwrap();
    let compiled = compilation.result().await.unwrap();
    assert_eq!(compiled.list.rule_count(), RULES);

    store
        .save(Snapshot::new(
            &compiled,
            &options,
            "memory",
            Validators::default(),
        ))
        .await
        .unwrap();
    store.flush().await;
    let path = store.path_for("memory").unwrap();
    drop(compiled);

    let before = reset_peak();
    let loaded = load(&path, &options).unwrap();
    let after = live();
    let peak = peak_bytes();

    assert_eq!(loaded.list.rule_count(), RULES);
    let per_rule = (after - before) as f64 / RULES as f64;
    let scratch = peak - after;
    println!("loaded snapshot: {per_rule:.3} bytes per rule, {scratch} bytes of scratch at peak");
    assert!(per_rule <= 8.1, "{per_rule} bytes per rule");
    assert!(scratch <= 256 * 1024, "{scratch} bytes of scratch");

    let _ = std::fs::remove_dir_all(&state);
}
