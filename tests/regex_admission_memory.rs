//! A regex rule of a list compiled within an admission limit (plan D6) never builds more than
//! the limit leaves: the compile stops before the automaton is held. This test binary has a
//! counting allocator that keeps the highest total, and one test, so nothing else allocates
//! while it measures.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use picoguard::filter::compile::{CompileError, CompileOptions, CompileWorker};
use picoguard::filter::engine::CompiledList;
use picoguard::filter::parse::ListFormat;
use picoguard::lists::Piece;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
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

    /// Counted as a move: the old and the new block both live until the copy is done.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        grow(new_size);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);

        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// About 620 KB once compiled: well under the regex size cap, far over the admission below.
const EXPENSIVE: &str = "||plain.example^\n/\\pL{40}/\n";
const ADMISSION_BYTES: usize = 64 * 1024;
/// The pieces in flight, the parser's line buffer and the small parts of a compile.
const FIXED_BYTES: usize = 64 * 1024;

/// The list compiled from `text` within `admission_bytes`, and the most the compile held.
async fn compile(
    worker: &CompileWorker,
    admission_bytes: usize,
    text: &str,
) -> (Result<Arc<CompiledList>, CompileError>, usize) {
    let options = CompileOptions::new(ListFormat::Adblock, 1000);
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);

    let compilation = worker.start_within(options, admission_bytes);
    compilation
        .pieces
        .send(Piece::Data(text.as_bytes().to_vec()))
        .await
        .unwrap();
    compilation.pieces.send(Piece::End).await.unwrap();
    let result = compilation.result().await.map(|compiled| compiled.list);
    let peak = PEAK.load(Ordering::Relaxed) - before;

    (result, peak)
}

#[tokio::test]
async fn a_regex_is_built_only_within_its_admission_and_its_charge_covers_the_build() {
    let worker = CompileWorker::spawn().unwrap();

    for text in ["/a.c/\n", "/\\pL{2}/\n", "/\\pL{10}/\n", EXPENSIVE] {
        let (free, peak) = compile(&worker, usize::MAX, text).await;
        let list = free.unwrap();
        let charge = list.compile_charge();
        println!("{text:?}: peak {peak} bytes, compile_charge {charge}");

        assert_eq!(list.slow_rule_count(), 1, "{text:?} is valid");
        assert!(
            peak <= charge + FIXED_BYTES,
            "{text:?}: peak {peak}, charge {charge}"
        );

        let (admitted, admitted_peak) = compile(&worker, charge, text).await;
        assert!(admitted.is_ok(), "{text:?} within its charge");
        assert!(admitted_peak <= charge + FIXED_BYTES);

        let (refused, _) = compile(&worker, charge - 1, text).await;
        assert_eq!(
            refused.err(),
            Some(CompileError::OverMemoryBudget),
            "{text:?}"
        );
    }

    // Too complex to build at all: a failed rule, with or without a limit, once it has room.
    let too_complex = "/\\pL{100}/\n";
    let (free, peak) = compile(&worker, usize::MAX, too_complex).await;
    let charge = free.as_ref().unwrap().compile_charge();
    println!("{too_complex:?}: peak {peak} bytes, compile_charge {charge}");
    assert_eq!(free.unwrap().regex_failed(), 1);
    assert!(peak <= charge + FIXED_BYTES);
    let (admitted, _) = compile(&worker, charge, too_complex).await;
    assert_eq!(admitted.unwrap().regex_failed(), 1);
    let (refused, _) = compile(&worker, charge - 1, too_complex).await;
    assert_eq!(refused.err(), Some(CompileError::OverMemoryBudget));

    for admission in [ADMISSION_BYTES, 1024 * 1024, 2 * 1024 * 1024] {
        let (refused, peak) = compile(&worker, admission, EXPENSIVE).await;
        println!("within {admission}: peak {peak} bytes");

        assert_eq!(refused.err(), Some(CompileError::OverMemoryBudget));
        assert!(
            peak <= admission + FIXED_BYTES,
            "held {peak} bytes before it was refused within {admission}"
        );
    }
}
