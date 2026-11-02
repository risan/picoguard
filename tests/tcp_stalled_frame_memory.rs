//! Memory held by TCP clients that announce a large frame and then stall. This file has its
//! own test binary so that the counting allocator sees only this one test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use picoguard::config::Config;
use picoguard::pipeline::Pipeline;
use picoguard::policy::Policy;
use picoguard::server::{self, Listeners};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

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

#[tokio::test]
async fn tcp_clients_announcing_a_big_frame_and_stalling_hold_only_the_read_buffer() {
    let silent_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::default();
    config.server.bind = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
    config.server.port = 0;
    config.upstream.servers = vec![format!("udp://{}", silent_upstream.local_addr().unwrap())];
    let connections = config.limits.tcp_max_connections;
    let pipeline = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();
    let listeners = Listeners::bind(&config.server).unwrap();
    let tcp = listeners.tcp_addresses()[0];
    server::spawn(listeners, pipeline, &config);
    tokio::task::yield_now().await;
    let before = LIVE_BYTES.load(Ordering::Relaxed);

    let mut clients = Vec::new();
    for _ in 0..connections {
        let mut stream = TcpStream::connect(tcp).await.unwrap();
        stream.write_all(&u16::MAX.to_be_bytes()).await.unwrap();
        stream.write_all(&[0; 16]).await.unwrap();
        clients.push(stream);
    }

    tokio::time::sleep(SETTLE).await;

    let held = LIVE_BYTES.load(Ordering::Relaxed).saturating_sub(before);
    let announced = connections * usize::from(u16::MAX);
    // A buffer sized by the announced length would hold all of `announced`; the read buffer
    // and the connection's own state come to about a fifth of that.
    assert!(
        held < announced / 2,
        "{held} bytes held by {connections} stalled frames of {announced} announced bytes"
    );
    drop(clients);
}
