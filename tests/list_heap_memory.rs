//! What a compiled list holds and what its compile holds at the peak, measured on the real
//! lists, against `CompiledList::heap_bytes` and `CompiledList::compile_charge`, which the
//! memory budget counts (plan D6). This test binary has a counting allocator that also keeps
//! the highest total, and one test, so nothing else allocates while it measures.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use picoguard::filter::compile::{CompileOptions, CompileWorker, Compiled};
use picoguard::filter::parse::ListFormat;
use picoguard::lists::{MAX_PIECE_BYTES, Piece};

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

/// The pieces in the queue, the one being parsed and the parser's line buffer: the same for
/// every list, whatever its size.
const COMPILE_FIXED_BYTES: usize = 512 * 1024;

/// Compiles the gzipped fixture `name` in pieces of 64 KiB. Returns the list with the bytes it
/// holds and the most the compile held, both counted from the moment before the compile.
async fn compile(
    worker: &CompileWorker,
    name: &str,
    format: ListFormat,
) -> (Compiled, usize, usize) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/lists")
        .join(format!("{name}.txt.gz"));
    let mut reader = flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap());
    let options = CompileOptions::new(format, 3_000_000);
    let mut piece = vec![0; MAX_PIECE_BYTES];
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);

    let compilation = worker.start(options);
    loop {
        let length = reader.read(&mut piece).unwrap();
        if length == 0 {
            break;
        }

        compilation
            .pieces
            .send(Piece::Data(piece[..length].to_vec()))
            .await
            .unwrap();
    }

    compilation.pieces.send(Piece::End).await.unwrap();
    let compiled = compilation.result().await.unwrap();
    let held = LIVE.load(Ordering::Relaxed) - before;
    let peak = PEAK.load(Ordering::Relaxed) - before;

    (compiled, held, peak)
}

#[tokio::test]
async fn heap_bytes_is_what_a_list_holds_and_the_compile_charge_covers_its_peak() {
    let worker = CompileWorker::spawn().unwrap();

    for (name, format) in [
        ("hagezi-pro", ListFormat::Adblock),
        ("adguard-dns", ListFormat::Adblock),
        ("hagezi-tif-mini", ListFormat::Adblock),
        ("hagezi-wildcard-dyndns", ListFormat::Wildcard),
    ] {
        let (compiled, held, peak) = compile(&worker, name, format).await;
        let list = &compiled.list;
        let heap = list.heap_bytes();
        let charge = list.compile_charge();
        println!(
            "{name}: {} rules ({} slow); holds {held} bytes, heap_bytes {heap}; \
             peak {peak} bytes ({:.1} per rule), compile_charge {charge}",
            list.rule_count(),
            list.slow_rule_count(),
            peak as f64 / list.rule_count() as f64,
        );

        // The list's own allocations, plus the small parts of the `Compiled` around it.
        assert!(
            held <= heap + 4096,
            "{name}: holds {held}, heap_bytes {heap}"
        );
        // The slow rules are charged more than they hold, never less.
        assert!(
            heap <= held * 2 + 4096,
            "{name}: holds {held}, heap_bytes {heap}"
        );
        assert!(
            peak <= charge + COMPILE_FIXED_BYTES,
            "{name}: peak {peak}, compile_charge {charge}"
        );
    }
}
