//! The memory estimate of plan D6 against what the process holds, measured with a counting
//! allocator: full stats with the longest names, a cache filled to its `max_bytes`, and real
//! lists. Each part must stay within its share of the estimate, and the estimate must not be
//! far above what was measured. This file has its own test binary, with one test, so that the
//! allocator sees nothing else.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use picoguard::cache::{Cache, CacheKey};
use picoguard::config::{CacheConfig, StatsConfig};
use picoguard::dns::wire::{Name, Query, ResponseInfo};
use picoguard::filter::compile::{CompileOptions, CompileWorker};
use picoguard::filter::engine::CompiledList;
use picoguard::filter::parse::ListFormat;
use picoguard::lists::{MAX_PIECE_BYTES, Piece};
use picoguard::memory;
use picoguard::stats::{Event, QueryResult, Stats, StatsSettings};

/// What a malloc implementation adds to every block, on top of the size asked for.
const ALLOCATION_OVERHEAD: usize = 16;

struct Counting;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static LIVE_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        LIVE_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);

        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        LIVE_ALLOCATIONS.fetch_sub(1, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE_BYTES.fetch_add(new_size, Ordering::Relaxed);
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);

        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// The heap held now, with the allocator's overhead on every block.
fn held() -> usize {
    LIVE_BYTES.load(Ordering::Relaxed)
        + LIVE_ALLOCATIONS.load(Ordering::Relaxed) * ALLOCATION_OVERHEAD
}

/// A name of 253 characters, the longest, that differs for every `number`.
fn longest_name(number: usize) -> String {
    let label = |tail: &str| format!("{number:0>8}{tail}");
    let long = label(&"x".repeat(55));

    format!("{long}.{long}.{long}.{}", label(&"y".repeat(51)))
}

fn fill_stats(settings: StatsSettings) -> (Stats, usize) {
    let before = held();
    let stats = Stats::new(settings);
    let rounds = 4 * (settings.query_log_entries + settings.top_k);

    for number in 0..rounds {
        let name = Name::from_text(&longest_name(number)).unwrap();
        stats.record(&Event {
            client: IpAddr::V4(Ipv4Addr::from(number as u32)),
            qname: &name,
            qtype: 1,
            result: if number % 2 == 0 {
                QueryResult::BlockedRequest
            } else {
                QueryResult::Pass
            },
            upstream: Some(0),
            latency: Duration::from_micros(500),
        });
    }

    let bytes = held() - before;

    (stats, bytes)
}

/// An A query for `name` and its answer, with `extra` bytes of TXT-like padding in the
/// additional section, so replies of several sizes go into the cache.
fn query_and_reply(name: &str, padding: usize) -> (Vec<u8>, Vec<u8>) {
    let mut query = vec![0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }

    query.push(0);
    query.extend_from_slice(&[0, 1, 0, 1]);

    let mut reply = query.clone();
    reply[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    reply[4..12].copy_from_slice(&[0, 1, 0, 1, 0, 0, 0, 1]);
    reply.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 0x2C, 0, 4, 192, 0, 2, 1]);
    let text = vec![b'p'; padding.min(255)];
    reply.extend_from_slice(&[0xC0, 0x0C, 0, 16, 0, 1, 0, 0, 1, 0x2C]);
    reply.extend_from_slice(&((text.len() + 1) as u16).to_be_bytes());
    reply.push(text.len() as u8);
    reply.extend_from_slice(&text);

    (query, reply)
}

fn fill_cache(max_bytes: usize) -> (Cache, usize) {
    let before = held();
    let mut cache = Cache::new(&CacheConfig {
        max_entries: usize::MAX / 2,
        max_bytes,
        ..CacheConfig::default()
    });
    let now = Instant::now();
    let mut number = 0;

    // Until it is full by bytes, then as many again, so it evicts and refills.
    let mut evicting = 0;
    while evicting == 0 || evicting < cache.len() {
        let (query, reply) = query_and_reply(&format!("n{number}.cache.example"), number % 200);
        let parsed = Query::parse(&query).unwrap();
        let info = ResponseInfo::parse(&reply).unwrap();
        let length = cache.len();
        cache
            .insert(&CacheKey::new(&parsed), &reply, &info, now)
            .unwrap();
        if cache.len() <= length {
            evicting += 1;
        }

        number += 1;
    }

    let bytes = held() - before;

    (cache, bytes)
}

async fn compile_fixture(worker: &CompileWorker, name: &str) -> Arc<CompiledList> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/lists")
        .join(format!("{name}.txt.gz"));
    let mut reader = flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap());
    let compilation = worker.start(CompileOptions::new(ListFormat::Adblock, 3_000_000));
    let mut piece = vec![0; MAX_PIECE_BYTES];
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

    drop(piece);
    compilation.pieces.send(Piece::End).await.unwrap();

    compilation.result().await.unwrap().list
}

#[tokio::test]
async fn the_estimate_covers_full_stats_a_full_cache_and_real_lists() {
    let worker = CompileWorker::spawn().unwrap();
    let start = held();

    let mut stats_parts = Vec::new();
    for (query_log_entries, top_k) in [(1000, 50), (5000, 100)] {
        let config = StatsConfig {
            query_log_entries,
            top_k,
        };
        let (stats, bytes) = fill_stats(StatsSettings {
            query_log_entries,
            top_k,
        });
        let reserved = memory::stats_bytes(&config);
        println!(
            "stats {query_log_entries} entries, top {top_k}: {bytes} bytes, reserved {reserved}"
        );
        assert!(bytes <= reserved, "stats hold {bytes}, reserved {reserved}");
        assert!(
            bytes >= reserved * 3 / 4,
            "stats hold {bytes}, reserved {reserved}"
        );
        stats_parts.push((stats, bytes, reserved));
    }

    let mut cache_parts = Vec::new();
    for max_bytes in [256 * 1024, 4 * 1024 * 1024] {
        let (cache, bytes) = fill_cache(max_bytes);
        let reserved = memory::cache_bytes(max_bytes);
        println!(
            "cache of {max_bytes} bytes: {} entries counting {}, {bytes} bytes held, reserved {reserved}",
            cache.len(),
            cache.bytes()
        );
        assert!(
            bytes <= reserved,
            "the cache holds {bytes}, reserved {reserved}"
        );
        assert!(
            bytes >= reserved * 3 / 4,
            "the cache holds {bytes}, reserved {reserved}"
        );
        cache_parts.push((cache, bytes, reserved));
    }

    let before_lists = held();
    let mut lists = Vec::new();
    for name in ["hagezi-pro", "adguard-dns", "hagezi-tif-mini"] {
        lists.push(compile_fixture(&worker, name).await);
    }

    let lists_held = held() - before_lists;
    let heap: usize = lists.iter().map(|list| list.heap_bytes()).sum();
    println!("lists: {lists_held} bytes held, heap_bytes {heap}");
    assert!(
        lists_held <= heap,
        "the lists hold {lists_held}, heap_bytes {heap}"
    );

    // Everything together, against the estimate without the idle process and the buffers
    // under load, which a test cannot fill: the default stats, a full default cache, the lists.
    let measured = stats_parts[0].1 + cache_parts[1].1 + lists_held;
    let estimated = stats_parts[0].2 + cache_parts[1].2 + heap;
    println!("together: {measured} bytes held, {estimated} estimated");
    assert!(held() - start >= measured);
    assert!(measured <= estimated);
    assert!(
        estimated <= measured * 3 / 2,
        "the estimate is far above what is held"
    );
}
