//! A refresh of an RPZ zone with one record that never closes its parenthesis must not hold
//! the whole body in memory. This test binary has a counting global allocator and a single
//! test, so nothing else allocates while it measures.

use picoguard::filter::compile::{CompileOptions, CompileWorker};
use picoguard::filter::engine::{Decision, Engine, TYPE_A};
use picoguard::filter::parse::ListFormat;
use picoguard::lists::{MAX_PIECE_BYTES, Piece};

#[path = "common/counting.rs"]
mod counting;

use counting::{peak_bytes, reset_peak};

#[global_allocator]
static ALLOCATOR: counting::Counting = counting::Counting;

const BODY_BYTES: usize = 48 * 1024 * 1024;

/// The queue holds 4 pieces of 64 KiB; the parser and the record buffer add a few KiB.
const PEAK_LIMIT: usize = 1024 * 1024;

#[tokio::test]
async fn an_rpz_record_that_never_closes_is_discarded_while_streaming() {
    let worker = CompileWorker::spawn().unwrap();
    let options = CompileOptions::new(ListFormat::Rpz, 1_000_000);
    let compilation = worker.start(options);

    let before = reset_peak();
    let opening = b"$ORIGIN rpz.example.\nopen.example CNAME . (\n";
    let filler_line = format!("{}\n", "x".repeat(1000)).into_bytes();
    let mut piece = opening.to_vec();
    let mut sent = 0;
    while sent < BODY_BYTES {
        piece.extend_from_slice(&filler_line);
        if piece.len() > MAX_PIECE_BYTES - filler_line.len() {
            sent += piece.len();
            compilation
                .pieces
                .send(Piece::Data(std::mem::take(&mut piece)))
                .await
                .unwrap();
        }
    }

    piece.extend_from_slice(b")\nclosed.example CNAME .\n");
    compilation.pieces.send(Piece::Data(piece)).await.unwrap();
    compilation.pieces.send(Piece::End).await.unwrap();
    let compiled = compilation.result().await.unwrap();
    let peak = peak_bytes() - before;

    assert!(peak < PEAK_LIMIT, "the refresh held {peak} bytes");
    let engine = Engine::new(vec![compiled.list], Vec::new());
    assert!(matches!(
        engine.check("closed.example", TYPE_A, false),
        Decision::Block { .. }
    ));
}
