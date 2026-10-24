//! A snapshot with counts its bytes cannot back must be refused without reserving memory
//! for them. This test binary has a counting global allocator and a single test, so nothing
//! else allocates while it measures.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use picoguard::filter::compile::{CompileOptions, CompileWorker};
use picoguard::filter::parse::ListFormat;
use picoguard::filter::snapshot::{Snapshot, SnapshotError, SnapshotStore, load};
use picoguard::lists::{Piece, Validators};
use xxhash_rust::xxh3::xxh3_128;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
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

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        grow(new_size);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);

        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

const PREAMBLE_BYTES: usize = 12;
const CHECKSUM_BYTES: usize = 16;

/// The load buffer and the checksum buffer are 64 KiB each; anything near the size a forged
/// count would reserve (megabytes) is far above this.
const LOAD_PEAK_LIMIT: usize = 512 * 1024;

fn forged(good: &[u8], groups: u32, slow: u32, fix_checksum: bool) -> Vec<u8> {
    let mut bytes = good.to_vec();
    let end = bytes.len() - CHECKSUM_BYTES;
    bytes[end - 8..end - 4].copy_from_slice(&groups.to_le_bytes());
    bytes[end - 4..end].copy_from_slice(&slow.to_le_bytes());
    if fix_checksum {
        let sum = xxh3_128(&bytes[PREAMBLE_BYTES..end]);
        bytes[end..].copy_from_slice(&sum.to_le_bytes());
    }

    bytes
}

fn peak_of_loading(path: &std::path::Path, options: &CompileOptions) -> (usize, SnapshotError) {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let error = load(path, options)
        .err()
        .expect("the file should be refused");
    let peak = PEAK.load(Ordering::Relaxed);

    (peak - before, error)
}

#[tokio::test]
async fn a_forged_count_reserves_nothing() {
    let state =
        std::env::temp_dir().join(format!("picoguard-snapshot-hostile-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state);
    let options = CompileOptions::new(ListFormat::Adblock, 3_000_000);

    let worker = CompileWorker::spawn().unwrap();
    let store = SnapshotStore::open(&state).unwrap();
    let compilation = worker.start(options);
    compilation
        .pieces
        .send(Piece::Data(b"||a.example^\n".to_vec()))
        .await
        .unwrap();
    compilation.pieces.send(Piece::End).await.unwrap();
    let compiled = compilation.result().await.unwrap();
    store
        .save(Snapshot::new(
            &compiled,
            &options,
            "https://lists.example/hostile",
            Validators::default(),
        ))
        .await
        .unwrap();
    store.flush().await;
    let path = store.path_for("https://lists.example/hostile").unwrap();
    let good = std::fs::read(&path).unwrap();
    drop(compiled);

    // 2.9 million host groups (40 bytes each when reserved) or slow rules (hundreds of bytes
    // each) in a file of a few hundred bytes, with the checksum correct and with it wrong.
    for (groups, slow) in [(2_900_000, 0), (0, 2_900_000)] {
        for fix_checksum in [true, false] {
            std::fs::write(&path, forged(&good, groups, slow, fix_checksum)).unwrap();

            let (peak, error) = peak_of_loading(&path, &options);

            let expected = if fix_checksum {
                matches!(error, SnapshotError::Truncated)
            } else {
                matches!(error, SnapshotError::BadChecksum)
            };
            assert!(expected, "{groups}/{slow}/{fix_checksum}: {error:?}");
            assert!(
                peak < LOAD_PEAK_LIMIT,
                "{groups}/{slow}/{fix_checksum}: peak {peak}"
            );
        }
    }

    let _ = std::fs::remove_dir_all(&state);
}
