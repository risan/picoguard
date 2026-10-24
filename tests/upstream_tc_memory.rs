//! A truncated UDP reply must not stay in memory while the TCP retry waits. This file has its
//! own test binary so that the counting allocator sees only this one test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use picoguard::budget::Budget;
use picoguard::config::{LimitsConfig, UpstreamConfig};
use picoguard::upstream::Upstreams;
use tokio::net::{TcpListener, UdpSocket};

const QUERIES: usize = 32;
const SETTLE: Duration = Duration::from_millis(500);
/// The largest datagram that crosses the loopback interface without fragmenting.
const LARGE_TRUNCATED_REPLY: usize = 1472;
const SMALL_TRUNCATED_REPLY: usize = 40;
const TRUNCATED_FLAGS: [u8; 2] = 0x8380u16.to_be_bytes();

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

fn query_for(name: &str) -> Vec<u8> {
    let mut message = Message::query();
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));

    message.to_vec().unwrap()
}

/// UDP and TCP on one port: the UDP side answers every datagram with a truncated reply of
/// `reply_size` bytes and counts them, the TCP side accepts and never says a word.
async fn truncating_server_with_a_stalled_tcp_side(
    reply_size: usize,
) -> (SocketAddr, Arc<AtomicUsize>) {
    loop {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = udp.local_addr().unwrap();
        let Ok(tcp) = TcpListener::bind(address).await else {
            continue;
        };

        let truncated_replies = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&truncated_replies);
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            while let Ok((length, peer)) = udp.recv_from(&mut buffer).await {
                let mut reply = buffer[..length].to_vec();
                reply[2..4].copy_from_slice(&TRUNCATED_FLAGS);
                reply.resize(reply_size, 0);
                let _ = udp.send_to(&reply, peer).await;
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = tcp.accept().await {
                held.push(stream);
            }
        });

        return (address, truncated_replies);
    }
}

/// The bytes still allocated after `QUERIES` queries have all reached the stalled TCP retry.
async fn bytes_held_while_the_tcp_retry_stalls(reply_size: usize) -> usize {
    let (server, truncated_replies) = truncating_server_with_a_stalled_tcp_side(reply_size).await;
    let upstream = UpstreamConfig {
        timeout_ms: 30_000,
        ..UpstreamConfig::default()
    };
    let limits = LimitsConfig {
        upstream_concurrency: QUERIES,
        ..LimitsConfig::default()
    };
    let upstreams = Arc::new(Upstreams::plain(server, &upstream, &limits));
    let budget = Budget::new(usize::MAX);
    let before = LIVE_BYTES.load(Ordering::Relaxed);

    let queries: Vec<_> = (0..QUERIES)
        .map(|index| {
            let upstreams = Arc::clone(&upstreams);
            let budget = Arc::clone(&budget);

            tokio::spawn(async move {
                let mut request = query_for(&format!("q{index}.example."));

                upstreams.query_charged(&mut request, &budget).await
            })
        })
        .collect();
    while truncated_replies.load(Ordering::SeqCst) < QUERIES {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(SETTLE).await;

    let held = LIVE_BYTES.load(Ordering::Relaxed).saturating_sub(before);
    assert!(
        queries.iter().all(|query| !query.is_finished()),
        "every query must still wait for the TCP answer"
    );
    for query in queries {
        query.abort();
    }
    tokio::time::sleep(SETTLE).await;

    held
}

#[tokio::test]
async fn large_truncated_udp_replies_are_not_held_while_the_tcp_retry_waits() {
    let with_small_replies = bytes_held_while_the_tcp_retry_stalls(SMALL_TRUNCATED_REPLY).await;
    let with_large_replies = bytes_held_while_the_tcp_retry_stalls(LARGE_TRUNCATED_REPLY).await;

    // Holding every truncated datagram would add about QUERIES * 1,400 bytes.
    let extra = with_large_replies.saturating_sub(with_small_replies);
    assert!(
        extra < QUERIES * 200,
        "{extra} more bytes held with large replies ({with_large_replies} against {with_small_replies})"
    );
}
