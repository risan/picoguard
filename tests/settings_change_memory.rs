//! What changing the cache and the upstream servers from the page costs. A cache change puts
//! an empty cache in place and frees the old one, slab and hash table included, at once. A
//! replaced upstream pool is freed when it is no longer used, so changes leave nothing behind.
//! This file has its own test binary so that the counting allocator sees only this one test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use picoguard::config::{CacheConfig, Config};
use picoguard::dns::build::Protocol;
use picoguard::pipeline::Pipeline;
use picoguard::policy::Policy;
use picoguard::upstream::Upstreams;
use tokio::net::UdpSocket;

const NAMES: usize = 500;
const SWAPS: usize = 20;
const HEADER_LEN: usize = 12;
const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// The stats of the names asked (query log, top lists), which stay after the cache is replaced.
/// Measured: 6,950 bytes held after the replacement, for 500 names; the full cache held 102,672.
const STATS_ALLOWANCE: usize = 16 * 1024;
/// One query through a new pool: its cache entry and its stats. Measured: 6,032 bytes for 20
/// replacements, 302 per replacement; a pool left behind would hold its TLS root store.
const PER_SWAP_ALLOWANCE: usize = 1024;

struct CountingAllocator;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }

        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn live() -> usize {
    LIVE_BYTES.load(Ordering::Relaxed)
}

/// Where the question of `message` ends: after its name, type and class.
fn question_end(message: &[u8]) -> usize {
    let mut at = HEADER_LEN;
    while message[at] != 0 {
        at += usize::from(message[at]) + 1;
    }

    at + 1 + 4
}

/// An A query for `n<index>.example.` (four digits).
fn query(index: usize) -> Vec<u8> {
    let mut query = vec![0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    let label = format!("n{index:04}");
    query.push(label.len() as u8);
    query.extend_from_slice(label.as_bytes());
    query.push(7);
    query.extend_from_slice(b"example");
    query.extend_from_slice(&[0, 0, 1, 0, 1]);

    query
}

/// Answers every query with one A record (TTL 300, 192.0.2.1), from fixed buffers.
async fn upstream() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut query = [0u8; 512];
        let mut reply = [0u8; 512];
        while let Ok((length, peer)) = socket.recv_from(&mut query).await {
            if length < HEADER_LEN {
                continue;
            }

            let end = question_end(&query[..length]);
            reply[..end].copy_from_slice(&query[..end]);
            reply[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            reply[4..12].copy_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
            let record = [0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 0x2C, 0, 4, 192, 0, 2, 1];
            reply[end..end + record.len()].copy_from_slice(&record);
            let _ = socket.send_to(&reply[..end + record.len()], peer).await;
        }
    });

    address
}

async fn ask(pipeline: &Arc<Pipeline>, index: usize) {
    let mut out = Vec::new();

    assert!(
        pipeline
            .answer(query(index), Protocol::Udp, CLIENT, &mut out)
            .await,
        "no answer for name {index}"
    );
}

#[tokio::test]
async fn a_replaced_cache_and_replaced_upstream_pools_leave_nothing_behind() {
    let mut config = Config::default();
    config.upstream.servers = vec![format!("udp://{}", upstream().await)];
    let pipeline = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();
    ask(&pipeline, 9999).await;
    let baseline = live();

    for index in 0..NAMES {
        ask(&pipeline, index).await;
    }

    assert_eq!(pipeline.cache_size().entries, NAMES + 1);
    let cache_bytes = pipeline.cache_size().bytes;
    let held_full = live() - baseline;

    drop(pipeline.replace_cache(&CacheConfig {
        min_ttl: 60,
        ..config.cache.clone()
    }));

    let held_replaced = live().saturating_sub(baseline);
    eprintln!(
        "held with {NAMES} names: {held_full} bytes (cache counts {cache_bytes}); \
         after the replacement: {held_replaced}"
    );
    assert_eq!(pipeline.cache_size().entries, 0);
    // The counted cost is a little above what the entries take on the heap.
    assert!(
        held_full - held_replaced >= cache_bytes * 9 / 10,
        "the replacement freed {} of {cache_bytes} counted bytes",
        held_full - held_replaced
    );
    assert!(
        held_replaced <= STATS_ALLOWANCE,
        "{held_replaced} bytes held after the replacement"
    );

    drop(
        pipeline
            .upstreams()
            .replace(Upstreams::from_config(&config.upstream, &config.limits).unwrap()),
    );
    ask(&pipeline, NAMES).await;
    let one_swap = live();

    for swap in 1..=SWAPS {
        drop(
            pipeline
                .upstreams()
                .replace(Upstreams::from_config(&config.upstream, &config.limits).unwrap()),
        );
        ask(&pipeline, NAMES + swap).await;
    }

    let grown = live().saturating_sub(one_swap);
    eprintln!("{SWAPS} more upstream replacements: {grown} bytes");
    assert_eq!(pipeline.upstreams().generations(), 1);
    assert!(
        grown <= SWAPS * PER_SWAP_ALLOWANCE,
        "{grown} bytes held after {SWAPS} replacements"
    );
}
