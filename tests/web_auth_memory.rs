//! What the status page keeps after many sign-ins and failed ones from many addresses: the
//! failure table is allocated once, and only one right credential is cached. This file has its
//! own test binary so that the counting allocator sees only this test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use picoguard::config::Config;
use picoguard::password::PasswordHash;
use picoguard::policy::Policy;
use picoguard::scheduler::ListControl;
use picoguard::stage::{StageSetup, StageTiming, Stager};
use picoguard::stats::Stats;
use picoguard::update::{Build, Updates};
use picoguard::upstream::tls::Tls;
use picoguard::web::{self, Web, WebListeners};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;

const KEPT_BUDGET_BYTES: usize = 10 * 1024;

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

/// The tests share one allocator, so they must not overlap.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn live() -> usize {
    LIVE_BYTES.load(Ordering::Relaxed)
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// Everything a `Web` needs, built before anything is measured.
struct Parts {
    config: Config,
    stats: Arc<Stats>,
    policy: Arc<Policy>,
    lists: Arc<ListControl>,
    updates: Arc<Updates>,
    stager: Arc<Stager>,
    listeners: WebListeners,
}

fn parts() -> Parts {
    let mut config = Config::default();
    config.web.bind = vec!["127.0.0.1".parse().unwrap()];
    config.web.port = 0;
    config.web.user = Some("admin".to_string());
    config.web.password_hash = Some(PasswordHash::new(b"s3cret", 1000).unwrap());
    let updates = Arc::new(Updates::new(Build::current()));
    let stager = Stager::new(
        StageSetup {
            target: None,
            base_url: String::new(),
            state_dir: PathBuf::from("/nonexistent"),
            installer_dir: PathBuf::from("/nonexistent"),
            key: [0; 32],
            max_binary_bytes: 0,
            timing: StageTiming::default(),
        },
        Arc::clone(&updates),
        Arc::new(|_| Box::pin(async { Err(io::Error::other("no DNS in this test")) })),
        Arc::new(Tls::with_webpki_roots()),
    );
    let listeners = WebListeners::bind(&config.web).unwrap();

    Parts {
        stats: Arc::new(Stats::new(Default::default())),
        policy: Arc::new(Policy::new()),
        lists: Arc::new(ListControl::default()),
        updates,
        stager,
        listeners,
        config,
    }
}

fn start(parts: Parts) -> SocketAddr {
    let address = parts.listeners.addresses()[0];
    let web = Web::new(
        &parts.config,
        parts.stats,
        parts.policy,
        parts.lists,
        parts.updates,
        parts.stager,
    )
    .unwrap();
    web::spawn(parts.listeners, Arc::new(web));

    address
}

/// The status code, and whether a session cookie was set.
async fn send(address: SocketAddr, from: &str, request: String) -> (u16, bool) {
    let from: IpAddr = from.parse().unwrap();
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::new(from, 0)).unwrap();
    let mut stream = socket.connect(address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.unwrap();
    let reply = String::from_utf8_lossy(&reply);
    let status = reply.split(' ').nth(1).unwrap().parse().unwrap();

    (status, reply.contains("set-cookie: picoguard_session="))
}

async fn login(address: SocketAddr, from: &str, password: &str) -> (u16, bool) {
    let body = format!("{{\"user\": \"admin\", \"password\": \"{password}\"}}");
    let request = format!(
        "POST /api/login HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );

    send(address, from, request).await
}

async fn basic(address: SocketAddr, from: &str) -> u16 {
    let request = format!(
        "GET /api/status HTTP/1.1\r\nHost: {address}\r\n\
         Authorization: Basic YWRtaW46czNjcmV0\r\n\r\n"
    );

    send(address, from, request).await.0
}

#[test]
fn logins_and_failures_from_many_addresses_keep_memory_within_ten_kilobytes() {
    let _turn = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let warm = start(parts());
        assert_eq!(login(warm, "127.0.0.1", "s3cret").await, (200, true));
        assert_eq!(login(warm, "127.0.0.1", "wrong").await, (401, false));
        assert_eq!(basic(warm, "127.0.0.1").await, 200);
        settle().await;

        let parts = parts();
        let before = live();

        let address = start(parts);
        for host in 1..=150 {
            let from = format!("127.0.1.{host}");
            for _ in 0..4 {
                assert_eq!(login(address, &from, "wrong").await, (401, false));
            }
            assert_eq!(login(address, &from, "s3cret").await, (200, true));
        }
        // The table ends full of live entries, with evictions done.
        for host in 1..=250 {
            let from = format!("127.0.2.{host}");
            assert_eq!(login(address, &from, "wrong").await, (401, false));
        }
        settle().await;

        let kept = live().saturating_sub(before);
        println!("1,000 sign-in attempts from 400 addresses: kept {kept} bytes");

        assert!(kept <= KEPT_BUDGET_BYTES, "kept {kept} bytes");
    });
}
