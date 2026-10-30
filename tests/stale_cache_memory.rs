//! Memory held by stale cache entries and the refreshes they start, and what a clear frees.
//! This file has its own test binary so that the counting allocator sees only this one test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use picoguard::config::Config;
use picoguard::pipeline::{CacheSize, Pipeline};
use picoguard::policy::Policy;
use picoguard::server::{self, Listeners};
use tokio::net::UdpSocket;

const NAMES: usize = 500;
const ANSWERED: usize = NAMES;
/// `max(1, min(max_inflight_queries 128, upstream_concurrency 128) / 2)`.
const MAX_REFRESHES: usize = 64;
const ANSWER_TTL: u32 = 30;
const HEADER_LEN: usize = 12;
/// What one refresh waiting on the silent upstream holds: its task, whose lookup future is
/// the one a client miss runs (6.5 KiB before it is first polled), the question in flight and
/// the exchange state. Measured: 1,051,729 bytes held with the stale entries and 64 refreshes,
/// 167,293 before the stale round, so about 13.5 KiB per refresh.
const REFRESH_ALLOWANCE: usize = 16 * 1024;
/// The stats ring, the top lists, the 64 KiB upstream receive buffer and the runtime's own
/// state. Measured: 957,057 bytes held after the clear, about 71 KiB beyond the refreshes.
const OTHER_ALLOWANCE: usize = 192 * 1024;

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

fn live_since(baseline: usize) -> usize {
    LIVE_BYTES.load(Ordering::Relaxed).saturating_sub(baseline)
}

/// Where the question of `message` ends: after its name, type and class.
fn question_end(message: &[u8]) -> usize {
    let mut at = HEADER_LEN;
    while message[at] != 0 {
        at += usize::from(message[at]) + 1;
    }

    at + 1 + 4
}

/// Writes an A query for `n<index>.example.` (three digits) into `buffer`; returns its length.
fn write_query(buffer: &mut [u8; 512], id: u16, index: usize) -> usize {
    buffer[..HEADER_LEN].copy_from_slice(&[0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    buffer[..2].copy_from_slice(&id.to_be_bytes());
    let digits = [
        b'0' + (index / 100) as u8,
        b'0' + (index / 10 % 10) as u8,
        b'0' + (index % 10) as u8,
    ];
    let mut at = HEADER_LEN;
    for label in [&[b'n', digits[0], digits[1], digits[2]][..], b"example"] {
        buffer[at] = label.len() as u8;
        buffer[at + 1..at + 1 + label.len()].copy_from_slice(label);
        at += label.len() + 1;
    }

    buffer[at..at + 5].copy_from_slice(&[0, 0, 1, 0, 1]);

    at + 5
}

/// Answers each of the first `ANSWERED` queries with one A record (TTL 1, 192.0.2.1) and
/// is silent after. Its buffers are fixed, so it allocates nothing per query.
async fn upstream_that_answers_once_each() -> (SocketAddr, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let received = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&received);

    tokio::spawn(async move {
        let mut query = [0u8; 512];
        let mut reply = [0u8; 512];
        while let Ok((length, peer)) = socket.recv_from(&mut query).await {
            if counter.fetch_add(1, Ordering::SeqCst) >= ANSWERED || length < HEADER_LEN {
                continue;
            }

            let end = question_end(&query[..length]);
            reply[..end].copy_from_slice(&query[..end]);
            reply[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
            reply[4..12].copy_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
            let record = [0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 1];
            reply[end..end + record.len()].copy_from_slice(&record);
            let _ = socket.send_to(&reply[..end + record.len()], peer).await;
        }
    });

    (address, received)
}

/// Asks every name once, one at a time, and hands the TTL of each answer to `check`.
async fn ask_all(client: &UdpSocket, server: SocketAddr, mut check: impl FnMut(usize, u32)) {
    let mut query = [0u8; 512];
    let mut reply = [0u8; 512];

    for index in 0..NAMES {
        let id = index as u16;
        let length = write_query(&mut query, id, index);
        client.send_to(&query[..length], server).await.unwrap();

        let (received, _) =
            tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut reply))
                .await
                .unwrap_or_else(|_| panic!("no answer for name {index}"))
                .unwrap();
        let reply = &reply[..received];
        let end = question_end(reply);
        assert_eq!(reply[..2], id.to_be_bytes(), "name {index}");
        assert_eq!(reply[6..8], [0, 1], "one answer for name {index}");
        assert_eq!(reply[end..end + 2], [0xC0, 0x0C], "name {index}");

        let ttl = u32::from_be_bytes(reply[end + 6..end + 10].try_into().unwrap());
        check(index, ttl);
    }
}

#[tokio::test]
async fn stale_entries_and_their_refreshes_stay_inside_the_cache_limits_and_a_clear_frees_them() {
    let (upstream, received) = upstream_that_answers_once_each().await;
    let mut config = Config::default();
    config.server.bind = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
    config.server.port = 0;
    config.upstream.servers = vec![format!("udp://{upstream}")];
    config.upstream.timeout_ms = 20_000;
    config.limits.upstream_concurrency = 128;
    let pipeline = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();
    let listeners = Listeners::bind(&config.server).unwrap();
    let server = listeners.udp_addresses()[0];
    server::spawn(listeners, Arc::clone(&pipeline), &config);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    tokio::task::yield_now().await;
    let baseline = LIVE_BYTES.load(Ordering::Relaxed);

    ask_all(&client, server, |index, ttl| {
        assert_eq!(ttl, 1, "name {index}");
    })
    .await;
    assert_eq!(pipeline.cache_size().entries, NAMES);

    tokio::time::sleep(Duration::from_millis(1100)).await;
    ask_all(&client, server, |index, ttl| {
        assert_eq!(ttl, ANSWER_TTL, "stale name {index}");
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(received.load(Ordering::SeqCst), NAMES + MAX_REFRESHES);

    let held_stale = live_since(baseline);
    let cache_bytes = pipeline.cache_size().bytes;
    let refreshes_and_other = MAX_REFRESHES * REFRESH_ALLOWANCE + OTHER_ALLOWANCE;
    eprintln!("held with stale entries: {held_stale} bytes, cache counts {cache_bytes}");
    assert!(
        held_stale <= cache_bytes + refreshes_and_other,
        "{held_stale} bytes held, the cache counts {cache_bytes}"
    );

    assert_eq!(pipeline.clear_cache(), NAMES);
    assert_eq!(
        pipeline.cache_size(),
        CacheSize {
            entries: 0,
            bytes: 0
        }
    );

    let held_cleared = live_since(baseline);
    eprintln!("held after the clear: {held_cleared} bytes");
    assert!(
        held_stale - held_cleared >= cache_bytes / 2,
        "the clear freed {} of {cache_bytes} counted bytes",
        held_stale - held_cleared
    );
    assert!(
        held_cleared <= refreshes_and_other,
        "{held_cleared} bytes held after the clear"
    );
}
