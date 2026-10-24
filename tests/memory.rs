//! Memory held while queries wait for a stalled upstream. This file has its own
//! test binary so that the counting allocator sees only this one test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Edns, Message, Query};
use hickory_proto::rr::{Name, RecordType};
use picoguard::config::Config;
use picoguard::pipeline::Pipeline;
use picoguard::policy::Policy;
use picoguard::server::{self, Listeners};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

const MAX_MESSAGE: usize = 65_535;
const OPTION_PADDING: u16 = 12;
const SETTLE: Duration = Duration::from_millis(500);

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

/// A query for `name` with an EDNS padding option that fills the message to
/// the 65,535-byte maximum of a TCP frame.
fn padded_query(name: &str) -> Vec<u8> {
    let mut message = Message::query();
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    message.set_edns(Edns::new());
    let mut bytes = message.to_vec().unwrap();

    let option_length = MAX_MESSAGE - bytes.len() - 4;
    let rdata_length_at = bytes.len() - 2;
    bytes[rdata_length_at..].copy_from_slice(&((option_length + 4) as u16).to_be_bytes());
    bytes.extend_from_slice(&OPTION_PADDING.to_be_bytes());
    bytes.extend_from_slice(&(option_length as u16).to_be_bytes());
    bytes.resize(MAX_MESSAGE, 0);

    bytes
}

#[tokio::test]
async fn padded_tcp_queries_waiting_for_a_stalled_upstream_hold_little_memory() {
    const CONNECTIONS: usize = 16;
    const QUERIES_PER_CONNECTION: usize = 4;
    let silent_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.server.bind = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
    config.server.port = 0;
    config.upstream.servers = vec![format!("udp://{}", silent_upstream.local_addr().unwrap())];
    config.upstream.timeout_ms = 20_000;
    let pipeline = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();
    let listeners = Listeners::bind(&config.server).unwrap();
    let tcp = listeners.tcp_addresses()[0];
    server::spawn(listeners, pipeline, &config);
    tokio::task::yield_now().await;
    let before = LIVE_BYTES.load(Ordering::Relaxed);

    let mut clients = Vec::new();
    for connection in 0..CONNECTIONS {
        let mut stream = TcpStream::connect(tcp).await.unwrap();
        for query in 0..QUERIES_PER_CONNECTION {
            let request = padded_query(&format!("q{query}.c{connection}.example."));
            stream
                .write_all(&(request.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&request).await.unwrap();
        }

        clients.push(stream);
    }

    tokio::time::sleep(SETTLE).await;

    let held = LIVE_BYTES.load(Ordering::Relaxed).saturating_sub(before);
    assert!(
        held < 1024 * 1024,
        "{held} bytes held for {} waiting queries",
        CONNECTIONS * QUERIES_PER_CONNECTION
    );
    drop(clients);
}
