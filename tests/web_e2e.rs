//! The status page and its API over real sockets: each endpoint, basic auth, the access policy
//! (peer, `Host`, `Origin`, content type, body size, method), pause and the manual refresh.
//! Nothing leaves the machine.

mod common;

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::harness::{
    Running, a_record, answering_upstream, ask, config_for, fake_upstream, name, reply_to,
    start_with_policy,
};
use common::http::ListServer;
use common::release::{Files, TARGET, scratch, test_key};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::PTR;
use hickory_proto::rr::{RData, Record, RecordType};
use picoguard::config::{Config, ListConfig, ListFormat};
use picoguard::dns::wire::Name;
use picoguard::filter::compile::CompileWorker;
use picoguard::filter::snapshot::SnapshotStore;
use picoguard::lists::{Downloader, Names};
use picoguard::password::PasswordHash;
use picoguard::policy::Policy;
use picoguard::scheduler::{Action, ListControl, Scheduler, Timing};
use picoguard::settings;
use picoguard::stage::{StageSetup, StageTiming, Stager};
use picoguard::stats::{Event, QueryResult};
use picoguard::stats_store::StatsSaver;
use picoguard::update::{self, Build, CheckTiming, Latest, Updates};
use picoguard::upstream::tls::Tls;
use picoguard::web::{self, Web, WebListeners};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

const ADMIN: &str = "YWRtaW46czNjcmV0";
const WRONG_PASSWORD: &str = "YWRtaW46d3Jvbmc=";
const OTHER_USER: &str = "b3RoZXI6czNjcmV0";

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|error| panic!("{error}: {}", self.body))
    }

    /// The `picoguard_session` value this reply sets.
    fn session(&self) -> Option<String> {
        let cookie = self
            .header("set-cookie")?
            .strip_prefix("picoguard_session=")?;

        Some(cookie.split(';').next()?.to_string())
    }
}

/// A request written by hand, so a test can send what a browser never would.
struct Request {
    method: &'static str,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn get(path: &str) -> Request {
    Request {
        method: "GET",
        path: path.to_string(),
        headers: Vec::new(),
        body: Vec::new(),
    }
}

fn login(user: &str, password: &str) -> Request {
    post(
        "/api/login",
        &serde_json::json!({ "user": user, "password": password }).to_string(),
    )
}

fn post(path: &str, body: &str) -> Request {
    Request {
        method: "POST",
        path: path.to_string(),
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: body.as_bytes().to_vec(),
    }
}

impl Request {
    fn header(mut self, name: &str, value: &str) -> Request {
        self.headers
            .retain(|(key, _)| !key.eq_ignore_ascii_case(name));
        self.headers.push((name.to_string(), value.to_string()));

        self
    }

    fn is_signed_in(&self) -> bool {
        self.headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("authorization"))
    }

    fn signed_in(self, credentials: &str) -> Request {
        self.header("Authorization", &format!("Basic {credentials}"))
    }

    /// What the page's own script sends with every call.
    fn by_page(self) -> Request {
        self.header("X-Requested-With", "picoguard")
    }

    /// Only the cookie: a pass can never come from basic auth.
    fn with_session(self, token: &str) -> Request {
        assert!(
            !self.is_signed_in(),
            "a cookie-only request carries basic auth"
        );

        self.header("Cookie", &format!("picoguard_session={token}"))
    }

    fn bytes(&self, default_host: SocketAddr) -> Vec<u8> {
        let mut text = format!("{} {} HTTP/1.1\r\n", self.method, self.path);
        if !self
            .headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("host"))
        {
            text.push_str(&format!("Host: {default_host}\r\n"));
        }

        for (name, value) in &self.headers {
            text.push_str(&format!("{name}: {value}\r\n"));
        }

        let declares_length = self
            .headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("content-length"));
        let is_chunked = self
            .headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("transfer-encoding"));
        if !declares_length && !is_chunked && self.method == "POST" {
            text.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }

        text.push_str("\r\n");
        let mut bytes = text.into_bytes();
        bytes.extend_from_slice(&self.body);

        bytes
    }
}

/// Writes `bytes` and reads until the server closes. Empty when the server sent nothing.
async fn exchange(address: SocketAddr, bytes: &[u8]) -> Vec<u8> {
    let Ok(stream) = TcpStream::connect(address).await else {
        return Vec::new();
    };

    exchange_on(stream, bytes).await
}

/// As `exchange`, from another loopback address, so the server sees another client.
async fn exchange_from(address: SocketAddr, from: IpAddr, bytes: &[u8]) -> Vec<u8> {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::new(from, 0)).unwrap();
    let Ok(stream) = socket.connect(address).await else {
        return Vec::new();
    };

    exchange_on(stream, bytes).await
}

async fn exchange_on(mut stream: TcpStream, bytes: &[u8]) -> Vec<u8> {
    let _ = stream.write_all(bytes).await;

    let mut received = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), async {
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(length) => received.extend_from_slice(&chunk[..length]),
            }
        }
    })
    .await;
    assert!(read.is_ok(), "the server kept the connection open");

    received
}

fn parse_reply(bytes: &[u8]) -> Option<Reply> {
    let text = String::from_utf8_lossy(bytes).to_string();
    let (head, body) = text.split_once("\r\n\r\n")?;
    let mut lines = head.lines();
    let status = lines.next()?.split(' ').nth(1)?.parse().ok()?;
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        .collect();

    Some(Reply {
        status,
        headers,
        body: body.to_string(),
    })
}

struct Site {
    web: SocketAddr,
    dns: Running,
    policy: Arc<Policy>,
    control: Arc<ListControl>,
    updates: Arc<Updates>,
    /// The fake of the release downloads the stager reads.
    release: ListServer,
    stager: Arc<Stager>,
    /// Sends the administrator's credentials with every request that has none of its own.
    signs_in: bool,
    /// Where the settings file is saved.
    state: PathBuf,
}

impl Site {
    async fn send(&self, request: Request) -> Reply {
        let request = if self.signs_in && !request.is_signed_in() {
            request.signed_in(ADMIN)
        } else {
            request
        };
        let bytes = exchange(self.web, &request.bytes(self.web)).await;

        parse_reply(&bytes).unwrap_or_else(|| panic!("no reply: {bytes:?}"))
    }

    /// Sends the request as it is, never with the administrator's credentials.
    async fn send_as_is(&self, request: Request) -> Reply {
        let bytes = exchange(self.web, &request.bytes(self.web)).await;

        parse_reply(&bytes).unwrap_or_else(|| panic!("no reply: {bytes:?}"))
    }

    /// As `send_as_is`, from another client address.
    async fn send_from(&self, from: &str, request: Request) -> Reply {
        let from: IpAddr = from.parse().unwrap();
        let bytes = exchange_from(self.web, from, &request.bytes(self.web)).await;

        parse_reply(&bytes).unwrap_or_else(|| panic!("no reply: {bytes:?}"))
    }

    /// True when the server closed the connection without sending anything.
    async fn is_ignored(&self, request: Request) -> bool {
        exchange(self.web, &request.bytes(self.web))
            .await
            .is_empty()
    }

    fn is_paused(&self) -> bool {
        self.policy.view(Instant::now()).paused
    }
}

fn no_dns() -> Downloader {
    Downloader::new(
        Names::Resolver(Arc::new(|_| {
            Box::pin(async { Err(io::Error::other("no DNS in this test")) })
        })),
        Arc::new(Tls::with_webpki_roots()),
    )
}

fn local_config(upstream: &common::harness::FakeUpstream) -> Config {
    let mut config = config_for(upstream);
    config.lists = Vec::new();
    config.rules = vec!["||ads.example^".to_string()].into();
    config.web.bind = vec!["127.0.0.1".parse().unwrap()];
    config.web.port = 0;
    with_credentials(&mut config);

    config
}

fn with_credentials(config: &mut Config) {
    config.web.user = Some("admin".to_string());
    config.web.password = Some("s3cret".to_string());
}

fn without_credentials(config: &mut Config) {
    config.web.user = None;
    config.web.password = None;
}

/// User `admin` with a hash of `password` instead of the plaintext.
fn hashed_config(
    upstream: &common::harness::FakeUpstream,
    password: &str,
    iterations: u32,
) -> Config {
    let mut config = local_config(upstream);
    config.web.password = None;
    config.web.password_hash = Some(PasswordHash::new(password.as_bytes(), iterations).unwrap());

    config
}

/// A scheduler that refreshes nothing by itself for a day, so a refresh is always asked for.
fn day_long_timing() -> Timing {
    Timing {
        hour: Duration::from_secs(3600),
        retries: [Duration::from_secs(3600); 4],
        first_check: Duration::from_secs(3600 * 1000),
    }
}

/// What the stager of a site is built for.
#[derive(Clone, Copy)]
struct SiteKind {
    build: Build,
    /// Whether the installer directory exists.
    installer: bool,
    /// Whether this is one of the three release targets.
    release_target: bool,
}

static SITES: AtomicUsize = AtomicUsize::new(0);

const OFFERED: &str = "9.9.9";

fn offered() -> Latest {
    Latest {
        version: OFFERED.to_string(),
        notes: String::new(),
    }
}

fn release_binary() -> Vec<u8> {
    (0..30_000u32)
        .map(|index| (index * 7 % 251) as u8)
        .collect()
}

fn serve_release(server: &ListServer, files: &Files) {
    let base = format!("/download/v{OFFERED}");
    server.serve_bytes(&format!("{base}/SHA256SUMS"), files.sums.clone());
    server.serve_bytes(&format!("{base}/SHA256SUMS.sig"), files.signature.clone());
    server.serve_bytes(&format!("{base}/picoguard-{TARGET}"), files.binary.clone());
}

async fn site(config: Config) -> Site {
    site_with(
        config,
        SiteKind {
            build: Build::current(),
            installer: true,
            release_target: true,
        },
    )
    .await
}

async fn site_with(config: Config, kind: SiteKind) -> Site {
    site_saving(config, kind, None).await
}

/// A site whose state folder holds `saved` as its settings file before it starts. The state
/// folder is the stager's, as in the server.
async fn site_saving(config: Config, kind: SiteKind, saved: Option<&str>) -> Site {
    site_timed(config, kind, saved, day_long_timing()).await
}

/// `site_saving` with the scheduler on `timing`.
async fn site_timed(
    mut config: Config,
    kind: SiteKind,
    saved: Option<&str>,
    timing: Timing,
) -> Site {
    let root = scratch(&format!("web-e2e-{}", SITES.fetch_add(1, Ordering::SeqCst)));
    let state = root.join("state");
    std::fs::create_dir(&state).unwrap();
    if let Some(saved) = saved {
        std::fs::write(state.join(settings::FILE_NAME), saved).unwrap();
    }

    config.state.dir = state.clone();
    let loaded = settings::with_saved(config);
    let config = loaded.config;
    let scheduler = Scheduler::boot(
        &config,
        Arc::new(loaded.saved),
        CompileWorker::spawn().unwrap(),
        Arc::new(SnapshotStore::disabled()),
        timing,
    )
    .await
    .unwrap();
    let policy = scheduler.policy();
    let control = scheduler.control();
    tokio::spawn(scheduler.run(no_dns(), std::future::pending()));

    let dns = start_with_policy(&config, Arc::clone(&policy)).await;
    let listeners = WebListeners::bind(&config.web).unwrap();
    let address = listeners.addresses()[0];
    let updates = Arc::new(Updates::new(kind.build));
    if kind.installer {
        std::fs::create_dir(root.join("installer")).unwrap();
    }

    let release = ListServer::start().await;
    serve_release(&release, &Files::good(OFFERED, &release_binary()));
    let stager = Stager::new(
        StageSetup {
            target: kind.release_target.then_some(TARGET),
            base_url: release.url("/download"),
            state_dir: state.clone(),
            installer_dir: root.join("installer"),
            key: test_key(),
            max_binary_bytes: 1024 * 1024,
            timing: StageTiming {
                poll: Duration::from_millis(20),
                wait: Duration::from_secs(5),
            },
        },
        Arc::clone(&updates),
        Names::Resolver(Arc::new(|_| {
            Box::pin(async { Err(io::Error::other("no DNS in this test")) })
        })),
        Arc::new(Tls::with_webpki_roots()),
    );
    let web_state = Web::new(
        &config,
        Arc::clone(&dns.pipeline),
        Arc::new(if config.stats.persist {
            StatsSaver::open(state.clone())
        } else {
            StatsSaver::disabled()
        }),
        Arc::clone(&policy),
        Arc::clone(&control),
        Arc::clone(&updates),
        Arc::clone(&stager),
    )
    .unwrap();
    web::spawn(listeners, Arc::new(web_state));

    Site {
        web: address,
        dns,
        policy,
        control,
        updates,
        release,
        stager,
        signs_in: config.web.user.is_some(),
        state,
    }
}

async fn plain_site() -> (Site, common::harness::FakeUpstream) {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let site = site(local_config(&upstream)).await;

    (site, upstream)
}

const PAGE_CSP: &str =
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'";

#[tokio::test]
async fn the_page_is_served_with_protective_headers() {
    let (site, _upstream) = plain_site().await;

    let reply = site.send(get("/")).await;

    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(reply.body, include_str!("../src/web/index.html"));
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(reply.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(reply.header("x-frame-options"), Some("DENY"));
    assert_eq!(reply.header("content-security-policy"), Some(PAGE_CSP));
    // No answer ever grants a cross-origin read.
    assert!(reply.header("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn an_unknown_path_is_not_found() {
    let (site, _upstream) = plain_site().await;

    for path in [
        "/nope",
        "/api",
        "/api/status/",
        "/index.html",
        "/api/lists/other",
    ] {
        assert_eq!(site.send(get(path)).await.status, 404, "{path}");
    }
}

#[tokio::test]
async fn status_counts_the_queries_that_were_answered() {
    let (site, _upstream) = plain_site().await;
    ask(&site.dns, "ads.example.", RecordType::A).await;
    ask(&site.dns, "ads.example.", RecordType::AAAA).await;
    ask(&site.dns, "ok.example.", RecordType::A).await;
    ask(&site.dns, "ok.example.", RecordType::A).await;

    let reply = site.send(get("/api/status")).await;
    let status = reply.json();

    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("content-type"), Some("application/json"));
    assert_eq!(status["counters"]["total"], 4);
    assert_eq!(status["counters"]["blocked_request"], 2);
    assert_eq!(status["counters"]["upstream"], 1);
    assert_eq!(status["counters"]["cached"], 1);
    assert_eq!(status["counters"]["errors"], 0);
    assert_eq!(status["counters"]["dropped"], 0);
    assert_eq!(status["blocked_percent"], 50.0);

    let hourly = status["hourly"].as_array().unwrap();
    assert_eq!(hourly.len(), 24);
    assert_eq!(hourly[23]["total"], 4);
    assert_eq!(hourly[23]["blocked"], 2);

    assert_eq!(status["top_blocked"]["approximate"], true);
    assert_eq!(status["top_blocked"]["entries"][0]["key"], "ads.example");
    assert_eq!(status["top_blocked"]["entries"][0]["count"], 2);
    assert_eq!(status["top_queried"]["approximate"], true);
    assert_eq!(status["top_queried"]["entries"][0]["key"], "ads.example");
    assert_eq!(status["top_clients"]["approximate"], true);
    assert_eq!(status["top_clients"]["entries"][0]["key"], "127.0.0.1");
    assert_eq!(status["top_clients"]["entries"][0]["count"], 4);
    assert_eq!(status["pause"]["paused"], false);
    assert!(status["pause"]["seconds_left"].is_null());
    assert!(status["generation"].is_u64());
    assert!(status["lists"].as_array().unwrap().is_empty());
}

fn upstream_entries(status: &Value) -> &Vec<Value> {
    status["upstreams"].as_array().unwrap()
}

#[tokio::test]
async fn a_query_for_a_local_name_counts_on_the_local_resolver_only() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let router = answering_upstream([192, 168, 1, 9], Duration::from_millis(20)).await;
    let mut config = local_config(&upstream);
    config.local.resolver = Some(router.address);
    config.local.domains = vec!["lan".to_string()];
    let site = site(config).await;

    ask(&site.dns, "printer.lan.", RecordType::A).await;

    let status = site.send(get("/api/status")).await.json();
    let servers = upstream_entries(&status);

    assert_eq!(servers[1]["kind"], "local");
    assert_eq!(servers[1]["label"], router.address.to_string());
    assert_eq!(servers[1]["answered"], 1);
    assert_eq!(servers[1]["failed"], 0);
    assert!(servers[1]["avg_ms"].as_f64().unwrap() >= 20.0);
    assert_eq!(servers[0]["answered"], 0);
    assert_eq!(servers[0]["failed"], 0);
    assert!(servers[0]["avg_ms"].is_null());
    assert_eq!(upstream.count(), 0);
}

#[tokio::test]
async fn cache_hits_and_names_blocked_by_rule_change_no_upstream_counter() {
    let (site, upstream) = plain_site().await;
    ask(&site.dns, "ok.example.", RecordType::A).await;
    ask(&site.dns, "ok.example.", RecordType::A).await;
    ask(&site.dns, "ads.example.", RecordType::A).await;

    let status = site.send(get("/api/status")).await.json();
    let servers = upstream_entries(&status);

    assert_eq!(status["counters"]["upstream"], 1);
    assert_eq!(status["counters"]["cached"], 1);
    assert_eq!(status["counters"]["blocked_request"], 1);
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0]["answered"], 1);
    assert_eq!(servers[0]["failed"], 0);
    assert_eq!(upstream.count(), 1);
}

#[tokio::test]
async fn the_status_lists_every_upstream_in_config_order_then_the_local_resolver() {
    let first = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let second = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let router = answering_upstream([192, 168, 1, 9], Duration::ZERO).await;
    let mut config = local_config(&first);
    config.upstream.servers = vec![
        format!("udp://{}", first.address),
        format!("udp://{}", second.address),
    ];
    config.local.resolver = Some(router.address);
    let site = site(config).await;

    let status = site.send(get("/api/status")).await.json();
    let servers = upstream_entries(&status);

    let labels: Vec<&str> = servers
        .iter()
        .map(|server| server["label"].as_str().unwrap())
        .collect();
    let kinds: Vec<&str> = servers
        .iter()
        .map(|server| server["kind"].as_str().unwrap())
        .collect();
    assert_eq!(
        labels,
        [
            format!("udp://{}", first.address),
            format!("udp://{}", second.address),
            router.address.to_string(),
        ]
    );
    assert_eq!(kinds, ["upstream", "upstream", "local"]);
    for server in servers {
        let mut keys: Vec<&str> = server
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();

        assert_eq!(keys, ["answered", "avg_ms", "failed", "kind", "label"]);
        assert_eq!(server["answered"], 0);
        assert_eq!(server["failed"], 0);
        assert!(server["avg_ms"].is_null());
    }
}

#[tokio::test]
async fn clearing_the_cache_empties_it_and_the_next_query_goes_upstream() {
    let (site, upstream) = plain_site().await;
    ask(&site.dns, "ok.example.", RecordType::A).await;
    ask(&site.dns, "other.example.", RecordType::A).await;

    let status = site.send(get("/api/status")).await.json();
    assert_eq!(status["cache"]["entries"], 2);
    assert!(status["cache"]["bytes"].as_u64().unwrap() > 0);
    let upstream_before = status["counters"]["upstream"].as_u64().unwrap();

    let cleared = site.send(post("/api/cache/clear", "{}")).await;
    assert_eq!(cleared.status, 200);
    assert_eq!(cleared.body, "{\"cleared\":2}");

    let status = site.send(get("/api/status")).await.json();
    assert_eq!(
        status["cache"],
        serde_json::json!({"entries": 0, "bytes": 0})
    );

    ask(&site.dns, "ok.example.", RecordType::A).await;
    assert_eq!(upstream.count(), 3);
    let status = site.send(get("/api/status")).await.json();
    assert_eq!(status["counters"]["upstream"], upstream_before + 1);
}

#[tokio::test]
async fn the_query_log_is_newest_first_and_never_longer_than_the_ring() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    config.stats.query_log_entries = 3;
    let site = site(config).await;
    for name in ["a.example.", "b.example.", "c.example.", "ads.example."] {
        ask(&site.dns, name, RecordType::A).await;
    }

    let all = site.send(get("/api/querylog")).await;
    let entries = all.json()["entries"].as_array().unwrap().clone();

    assert_eq!(all.status, 200);
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0]["qname"], "ads.example");
    assert_eq!(entries[0]["result"], "blocked_request");
    assert_eq!(entries[0]["client"], "127.0.0.1");
    assert_eq!(entries[0]["qtype"], 1);
    assert!(entries[0]["upstream"].is_null());
    assert_eq!(entries[1]["qname"], "c.example");
    assert_eq!(entries[1]["result"], "pass");
    assert_eq!(entries[1]["upstream"], 0);
    assert!(entries[1]["latency_us"].is_u64() && entries[1]["time"].is_u64());

    let two = site.send(get("/api/querylog?limit=2")).await;
    assert_eq!(two.json()["entries"].as_array().unwrap().len(), 2);

    let too_many = site.send(get("/api/querylog?limit=100000")).await;
    assert_eq!(too_many.json()["entries"].as_array().unwrap().len(), 3);

    let none = site.send(get("/api/querylog?limit=0")).await;
    assert!(none.json()["entries"].as_array().unwrap().is_empty());

    for bad in ["abc", "-1", "", "1.5"] {
        let reply = site.send(get(&format!("/api/querylog?limit={bad}"))).await;
        assert_eq!(reply.status, 400, "limit={bad}");
    }
}

#[tokio::test]
async fn one_query_log_answer_is_cut_to_a_thousand_entries() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    config.stats.query_log_entries = 1_500;
    let site = site(config).await;
    for index in 0..1_500 {
        record_client(&site, "127.0.0.1", &format!("n{index}.example."));
    }

    let everything = site.send(get("/api/querylog?limit=100000")).await;
    let entries = everything.json()["entries"].as_array().unwrap().clone();

    assert_eq!(entries.len(), 1_000);
    assert_eq!(entries[0]["qname"], "n1499.example");
}

/// Records a query from `client` straight into the site's stats: the names code sees only the
/// addresses the views show, however they got there.
fn record_client(site: &Site, client: &str, qname: &str) {
    let qname = Name::from_text(qname).unwrap();
    site.dns.pipeline.stats().record(&Event {
        client: client.parse().unwrap(),
        qname: &qname,
        qtype: 1,
        result: QueryResult::Pass,
        upstream: Some(0),
        latency: Duration::from_micros(500),
    });
}

/// A router that answers the PTR questions in `answers` (owner, target, TTL) and NXDOMAIN to
/// anything else.
async fn router(answers: &[(&str, &str, u32)]) -> common::harness::FakeUpstream {
    let answers: Vec<(String, String, u32)> = answers
        .iter()
        .map(|(owner, target, ttl)| (owner.to_string(), target.to_string(), *ttl))
        .collect();

    fake_upstream(move |query| {
        let owner = query.queries[0].name().to_string();
        let mut reply = reply_to(query, Vec::new());
        match answers.iter().find(|(known, _, _)| *known == owner) {
            Some((_, target, ttl)) => {
                let data = RData::PTR(PTR(name(target)));
                reply.add_answer(Record::from_rdata(name(&owner), *ttl, data));
            }

            None => {
                reply.metadata.response_code = ResponseCode::NXDomain;
            }
        }

        vec![(Duration::ZERO, reply)]
    })
    .await
}

fn client_entry<'a>(status: &'a Value, client: &str) -> &'a Value {
    status["top_clients"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["key"] == client)
        .unwrap_or_else(|| panic!("{client} is not a top client: {status}"))
}

fn log_entries<'a>(log: &'a Value, client: &str) -> Vec<&'a Value> {
    let entries: Vec<&Value> = log["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["client"] == client)
        .collect();
    assert!(!entries.is_empty(), "{client} is not in the log: {log}");

    entries
}

fn keys_of(entry: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = entry
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();

    keys
}

/// Every top client and every log entry carries `name`, and it is null.
fn assert_every_name_is_null(status: &Value, log: &Value) {
    let clients = status["top_clients"]["entries"].as_array().unwrap();
    let entries = log["entries"].as_array().unwrap();
    for entry in clients.iter().chain(entries) {
        assert_eq!(entry.get("name"), Some(&Value::Null), "{entry}");
    }
}

async fn status_and_log(site: &Site) -> (Value, Value) {
    let status = site.send(get("/api/status")).await.json();
    let log = site.send(get("/api/querylog")).await.json();

    (status, log)
}

fn local_entry(status: &Value) -> &Value {
    upstream_entries(status)
        .iter()
        .find(|server| server["kind"] == "local")
        .unwrap()
}

#[tokio::test]
async fn a_private_client_gets_its_router_name_on_a_later_poll() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let router = router(&[("50.110.168.192.in-addr.arpa.", "Risan-PC.lan.", 600)]).await;
    let mut config = local_config(&upstream);
    config.local.resolver = Some(router.address);
    let site = site(config).await;
    record_client(&site, "192.168.110.50", "a.example.");
    record_client(&site, "192.168.110.50", "b.example.");
    record_client(&site, "192.168.110.51", "c.example.");
    ask(&site.dns, "ok.example.", RecordType::A).await;

    let first = site.send(get("/api/status")).await.json();
    let named = client_entry(&first, "192.168.110.50");

    assert!(named["name"].is_null());
    assert_eq!(keys_of(named), ["count", "key", "max_error", "name"]);

    let started = Instant::now();
    let status = loop {
        let status = site.send(get("/api/status")).await.json();
        if client_entry(&status, "192.168.110.50")["name"] == "risan-pc.lan" {
            break status;
        }

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "no name: {status}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    assert!(client_entry(&status, "192.168.110.51")["name"].is_null());
    assert!(client_entry(&status, "127.0.0.1")["name"].is_null());

    let log = site.send(get("/api/querylog")).await.json();
    for entry in log_entries(&log, "192.168.110.50") {
        assert_eq!(entry["name"], "risan-pc.lan");
    }

    for client in ["192.168.110.51", "127.0.0.1"] {
        for entry in log_entries(&log, client) {
            assert!(entry["name"].is_null(), "{entry}");
        }
    }

    let entries = log["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 4);
    for entry in entries {
        assert_eq!(
            keys_of(entry),
            [
                "client",
                "latency_us",
                "name",
                "qname",
                "qtype",
                "result",
                "time",
                "upstream"
            ]
        );
    }

    let status = site.send(get("/api/status")).await.json();
    assert_eq!(router.count(), 2);
    assert_eq!(local_entry(&status)["answered"], 2);
    assert_eq!(status["counters"]["total"], 4);
}

#[tokio::test]
async fn without_a_local_resolver_names_are_null_and_nothing_is_looked_up() {
    let (site, upstream) = plain_site().await;
    record_client(&site, "192.168.110.50", "a.example.");

    for _ in 0..2 {
        let (status, log) = status_and_log(&site).await;

        assert_eq!(client_entry(&status, "192.168.110.50")["count"], 1);
        assert_every_name_is_null(&status, &log);
    }

    assert_eq!(upstream.count(), 0);
}

#[tokio::test]
async fn a_router_silent_to_lookups_holds_up_neither_dns_nor_the_page() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let ptr_asked: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let asked = Arc::clone(&ptr_asked);
    let router = fake_upstream(move |query| {
        let question = &query.queries[0];
        if question.query_type() == RecordType::PTR {
            asked.lock().unwrap().push(question.name().to_string());

            return Vec::new();
        }

        let owner = question.name().to_string();

        vec![(
            Duration::ZERO,
            reply_to(query, vec![a_record(&owner, 300, [192, 168, 1, 9])]),
        )]
    })
    .await;
    let distinct_names = || {
        ptr_asked
            .lock()
            .unwrap()
            .iter()
            .collect::<HashSet<_>>()
            .len()
    };
    let mut config = local_config(&upstream);
    config.local.resolver = Some(router.address);
    config.local.domains = vec!["lan".to_string()];
    config.limits.upstream_concurrency = 1;
    let site = site(config).await;
    for number in 0..20 {
        record_client(&site, &format!("192.168.1.{}", 100 + number), "a.example.");
    }

    let t0 = Instant::now();
    let status = site.send(get("/api/status")).await.json();

    assert!(t0.elapsed() < Duration::from_secs(1), "{:?}", t0.elapsed());
    let clients = status["top_clients"]["entries"].as_array().unwrap();
    assert_eq!(clients.len(), 20);
    assert!(clients.iter().all(|client| client["name"].is_null()));

    while distinct_names() < 4 {
        assert!(
            t0.elapsed() < Duration::from_secs(1),
            "4 lookups within 1 s"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The client pool has one slot; the lookups hold four of their own.
    let asked_at = Instant::now();
    let answer = ask(&site.dns, "printer.lan.", RecordType::A).await;
    assert!(
        asked_at.elapsed() < Duration::from_secs(1),
        "{:?}",
        asked_at.elapsed()
    );
    assert_eq!(answer.answers[0].data.to_string(), "192.168.1.9");

    site.send(get("/api/status")).await;
    // A second try asks the same name again; only names count here.
    assert_eq!(
        distinct_names(),
        4,
        "the cap holds while four are in flight"
    );

    let started = Instant::now();
    let local = loop {
        let status = site.send(get("/api/status")).await.json();
        let local = local_entry(&status).clone();
        if local["failed"].as_u64().unwrap() >= 8 {
            break local;
        }

        assert!(started.elapsed() < Duration::from_secs(6), "{local}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    // Two tries for each of the first four; the next four have not failed yet.
    assert_eq!(local["failed"], 8);
    assert_eq!(local["answered"], 1);
    assert!(
        t0.elapsed() >= Duration::from_millis(1900),
        "{:?}",
        t0.elapsed()
    );

    // The first four gave up and freed their slots, so a poll starts the next four.
    site.send(get("/api/status")).await;
    let started = Instant::now();
    while distinct_names() < 8 {
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{}",
            distinct_names()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(distinct_names(), 8);
    let status = site.send(get("/api/status")).await.json();
    assert_eq!(status["counters"]["total"], 21);
}

#[tokio::test]
async fn without_a_password_no_lookup_starts() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let router = router(&[]).await;
    let mut config = local_config(&upstream);
    without_credentials(&mut config);
    config.local.resolver = Some(router.address);
    let site = site(config).await;
    record_client(&site, "192.168.110.50", "a.example.");

    for _ in 0..2 {
        let status = site.send(get("/api/status")).await.json();

        assert!(status.get("top_clients").is_none());
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(router.count(), 0);
}

#[tokio::test]
async fn without_a_password_an_unnamed_list_shows_its_host_and_never_its_address() {
    let list_server = ListServer::start().await;
    list_server.serve("/secret-token-123/list.txt", "||tracker.example^\n", None);
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let url = list_server.url("/secret-token-123/list.txt");
    let unnamed = |config: &mut Config| {
        config.lists = vec![ListConfig {
            url: Some(url.clone()),
            format: ListFormat::Adblock,
            ..ListConfig::default()
        }];
    };
    let mut config = local_config(&upstream);
    without_credentials(&mut config);
    unnamed(&mut config);
    let open = site(config).await;
    let mut config = local_config(&upstream);
    unnamed(&mut config);
    let signed_in = site(config).await;

    for site in [&open, &signed_in] {
        for _ in 0..200 {
            if site.send(get("/api/lists")).await.json()["lists"][0]["rules"] == 1 {
                break;
            }

            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    for path in ["/api/lists", "/api/status"] {
        let reply = open.send(get(path)).await;

        assert!(
            !reply.body.contains("secret-token-123"),
            "{path}: {}",
            reply.body
        );
        assert_eq!(reply.json()["lists"][0]["name"], "127.0.0.1", "{path}");
        assert_eq!(reply.json()["lists"][0]["rules"], 1, "{path}");
    }

    let lists = signed_in.send(get("/api/lists")).await.json();
    assert_eq!(lists["lists"][0]["name"], url.as_str());
    assert_eq!(lists["lists"][0]["source"], url.as_str());
}

#[tokio::test]
async fn without_a_password_no_refresh_error_is_shown_not_even_a_relative_redirect() {
    let list_server = ListServer::start().await;
    list_server.redirect("/list.txt", "/secret-token-123/a b");
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let named = |config: &mut Config| {
        config.lists = vec![ListConfig {
            name: Some("Ads".to_string()),
            url: Some(list_server.url("/list.txt")),
            format: ListFormat::Adblock,
            ..ListConfig::default()
        }];
    };
    let mut config = local_config(&upstream);
    without_credentials(&mut config);
    named(&mut config);
    let open = site(config).await;
    let mut config = local_config(&upstream);
    named(&mut config);
    let signed_in = site(config).await;

    for site in [&open, &signed_in] {
        for _ in 0..200 {
            if !site.send(get("/api/lists")).await.json()["lists"][0]["last_error"].is_null() {
                break;
            }

            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    let error = signed_in.send(get("/api/lists")).await.json()["lists"][0]["last_error"].clone();
    assert!(
        error.as_str().unwrap().contains("secret-token-123"),
        "the error names the path with a password: {error}"
    );

    for path in ["/api/lists", "/api/status"] {
        let reply = open.send(get(path)).await;

        assert!(
            !reply.body.contains("secret-token-123"),
            "{path}: {}",
            reply.body
        );
        assert_eq!(
            reply.json()["lists"][0]["last_error"],
            "the last refresh failed (set a password to see why)",
            "{path}"
        );
    }
}

#[tokio::test]
async fn lists_report_their_state_and_a_refresh_failure() {
    let list_server = ListServer::start().await;
    list_server.serve(
        "/ok.txt",
        "||tracker.example^\n||more.example^\n",
        Some("\"v1\""),
    );
    list_server.fail("/bad.txt", 503);
    let dir = std::env::temp_dir().join(format!("picoguard-web-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("local.txt");
    std::fs::write(
        &file,
        "0.0.0.0 one.example\n0.0.0.0 two.example\n0.0.0.0 three.example\n",
    )
    .unwrap();
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    config.lists = vec![
        ListConfig {
            name: Some("remote".to_string()),
            url: Some(list_server.url("/ok.txt")),
            format: ListFormat::Adblock,
            ..ListConfig::default()
        },
        ListConfig {
            name: Some("broken".to_string()),
            url: Some(list_server.url("/bad.txt")),
            format: ListFormat::Adblock,
            ..ListConfig::default()
        },
        ListConfig {
            name: Some("local".to_string()),
            path: Some(file),
            format: ListFormat::Hosts,
            ..ListConfig::default()
        },
    ];
    let site = site(config).await;

    // The scheduler fetches the two URLs at once.
    let mut lists = Value::Null;
    for _ in 0..200 {
        lists = site.send(get("/api/lists")).await.json();
        if lists["lists"][1]["last_error"].is_string() && lists["lists"][0]["rules"] == 2 {
            break;
        }

        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let lists = lists["lists"].as_array().unwrap();
    assert_eq!(lists.len(), 3);
    assert_eq!(lists[0]["name"], "remote");
    assert_eq!(lists[0]["kind"], "blocklist");
    assert_eq!(lists[0]["format"], "adblock");
    assert_eq!(lists[0]["rules"], 2);
    assert!(lists[0]["age_seconds"].as_u64().unwrap() < 60);
    assert!(lists[0]["last_error"].is_null());
    assert_eq!(lists[1]["name"], "broken");
    assert_eq!(lists[1]["rules"], 0);
    assert!(lists[1]["age_seconds"].is_null() && lists[1]["format"].is_null());
    assert!(lists[1]["last_error"].as_str().unwrap().contains("503"));
    assert_eq!(lists[2]["name"], "local");
    assert_eq!(lists[2]["format"], "hosts");
    assert_eq!(lists[2]["rules"], 3);

    // The status carries the same lists.
    let status = site.send(get("/api/status")).await.json();
    assert_eq!(status["lists"].as_array().unwrap().len(), 3);

    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn pausing_through_the_api_switches_filtering_off_until_it_ends() {
    let (site, _upstream) = plain_site().await;
    let is_blocked =
        |reply: hickory_proto::op::Message| reply.answers[0].data.to_string() == "0.0.0.0";

    assert!(is_blocked(
        ask(&site.dns, "ads.example.", RecordType::A).await
    ));

    let paused = site.send(post("/api/pause", "{\"minutes\": 5}")).await;
    let pause = paused.json();
    assert_eq!(paused.status, 200);
    assert_eq!(pause["paused"], true);
    let seconds_left = pause["seconds_left"].as_u64().unwrap();
    assert!((295..=300).contains(&seconds_left), "{seconds_left}");
    assert!(pause["until"].as_u64().unwrap() > 1_700_000_000);

    assert!(site.is_paused());
    assert!(!is_blocked(
        ask(&site.dns, "ads.example.", RecordType::A).await
    ));

    let status = site.send(get("/api/status")).await.json();
    assert_eq!(status["pause"]["paused"], true);

    // The pause ends by itself: the policy is judged against its deadline, so nothing has
    // to happen when it passes.
    let generation = site.policy.view(Instant::now()).generation;
    let almost = site.policy.view(Instant::now() + Duration::from_secs(299));
    let over = site.policy.view(Instant::now() + Duration::from_secs(301));
    assert!(almost.paused && !over.paused);
    assert_eq!(over.generation, generation);

    let resumed = site.send(post("/api/resume", "")).await;
    assert_eq!(resumed.status, 200);
    assert_eq!(resumed.json()["paused"], false);
    assert!(!site.is_paused());
    assert!(is_blocked(
        ask(&site.dns, "ads.example.", RecordType::A).await
    ));
}

#[tokio::test]
async fn pause_takes_one_to_1440_minutes_and_nothing_else() {
    let (site, _upstream) = plain_site().await;

    for body in [
        "{\"minutes\": 0}",
        "{\"minutes\": 1441}",
        "{\"minutes\": -5}",
        "{\"minutes\": 2.5}",
        "{\"minutes\": \"5\"}",
        "{\"minutes\": 5, \"extra\": 1}",
        "{}",
        "[]",
        "5",
        "",
        "not json",
    ] {
        let reply = site.send(post("/api/pause", body)).await;
        assert_eq!(reply.status, 400, "{body:?}");
        assert!(reply.json()["error"].is_string());
        assert!(!site.is_paused(), "{body:?}");
    }

    for (body, minutes) in [("{\"minutes\":1}", 1), ("{\"minutes\":1440}", 1440)] {
        let reply = site.send(post("/api/pause", body)).await;
        assert_eq!(reply.status, 200, "{body}");
        let left = reply.json()["seconds_left"].as_u64().unwrap();
        assert!(left > minutes * 60 - 5 && left <= minutes * 60, "{left}");
    }
}

#[tokio::test]
async fn a_requested_refresh_checks_every_list_once() {
    let list_server = ListServer::start().await;
    list_server.set_delay(Duration::from_millis(30));
    list_server.serve("/a.txt", "||a.example^\n", Some("\"a\""));
    list_server.serve("/b.txt", "||b.example^\n", Some("\"b\""));
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    config.lists = ["a", "b"]
        .iter()
        .map(|name| ListConfig {
            name: Some(name.to_string()),
            url: Some(list_server.url(&format!("/{name}.txt"))),
            format: ListFormat::Adblock,
            ..ListConfig::default()
        })
        .collect();
    let site = site(config).await;
    wait_for_requests(&list_server, 2).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(list_server.requests(), 2, "the first fetch, nothing more");

    let reply = site.send(post("/api/lists/refresh", "")).await;
    assert_eq!(reply.status, 202);
    wait_for_requests(&list_server, 4).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(list_server.requests(), 4, "one more check of each list");
    assert_eq!(list_server.not_modified(), 2);
    assert_eq!(list_server.most_active(), 1);
}

async fn wait_for_requests(server: &ListServer, count: usize) {
    for _ in 0..400 {
        if server.requests() >= count {
            return;
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    panic!("{} of {count} requests", server.requests());
}

const UPDATE_BODY: &str = "{\"version\": \"9.9.9\"}";

/// A site whose saved settings hold a list the page can edit and remove, served by a server of
/// its own, and a rule the page can remove.
struct SeededSite {
    site: Site,
    list: String,
    _server: ListServer,
}

impl std::ops::Deref for SeededSite {
    type Target = Site;

    fn deref(&self) -> &Site {
        &self.site
    }
}

async fn seeded_site(config: Config, full: bool) -> SeededSite {
    let server = ListServer::start().await;
    server.serve("/seeded.txt", "||seeded.example^\n", None);
    let list = server.url("/seeded.txt");
    let saved = serde_json::json!({
        "version": 1,
        "page_rules": [{"name": "x.example", "action": "block"}],
        "lists": [{"role": "block", "name": "Seeded", "url": list, "refresh_hours": 12, "enabled": true}],
    })
    .to_string();
    let kind = SiteKind {
        build: if full {
            Build::Release
        } else {
            Build::current()
        },
        installer: true,
        release_target: true,
    };
    let site = site_saving(config, kind, Some(&saved)).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    while site.control.statuses().first().map(|status| status.rules) != Some(1) {
        assert!(Instant::now() < deadline, "the seeded list never loaded");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert!(!no_page_rules(&site).await, "the rule is seeded");
    if full {
        site.updates.show(Some(offered()));
    }

    SeededSite {
        site,
        list,
        _server: server,
    }
}

/// Everything a change could alter, as the page and the saved file would show it.
#[derive(Debug, PartialEq)]
struct Changeable {
    paused: bool,
    settings_in_force: String,
    page_rules_in_force: String,
    settings_file: Option<Value>,
    lists: String,
    lists_on_page: bool,
    pending_list: String,
}

async fn changeable(site: &Site) -> Changeable {
    Changeable {
        paused: site.is_paused(),
        settings_in_force: format!("{:?}", *site.control.saved().lock().await),
        page_rules_in_force: site
            .control
            .with_button_rules(|rules| format!("{rules:?}"))
            .await,
        settings_file: saved_settings(site),
        lists: format!("{:?}", site.control.statuses()),
        lists_on_page: site.control.lists_on_page(),
        pending_list: format!("{:?}", site.control.pending_list()),
    }
}

/// A route that changes something, with a request body it accepts.
struct ChangeRoute {
    name: &'static str,
    path: &'static str,
    valid_body: String,
    size_limit: usize,
    /// A get of the same path reads instead of being refused.
    reads_by_get: bool,
    /// Signing in and out are open to a client that is not signed in.
    needs_sign_in: bool,
}

fn change_routes(seeded_list: &str) -> Vec<ChangeRoute> {
    let route = |name, path, valid_body: &str| ChangeRoute {
        name,
        path,
        valid_body: valid_body.to_string(),
        size_limit: 1024,
        reads_by_get: false,
        needs_sign_in: true,
    };
    let evil = "http://127.0.0.1:9/evil.txt";
    let seeded = serde_json::json!({"role": "block", "source": seeded_list});
    let edit = serde_json::json!({"role": "block", "source": seeded_list, "enabled": false});

    vec![
        route("pause", "/api/pause", "{\"minutes\": 5}"),
        route("resume", "/api/resume", ""),
        route("refresh", "/api/lists/refresh", ""),
        route("update", "/api/update", UPDATE_BODY),
        route("cache clear", "/api/cache/clear", "{}"),
        route("stats clear", "/api/stats/clear", "{}"),
        route("query log clear", "/api/querylog/clear", "{}"),
        ChangeRoute {
            reads_by_get: true,
            ..route("rule add", "/api/rules", NEW_RULE_BODY)
        },
        route("rule removal", "/api/rules/remove", REMOVE_BODY),
        ChangeRoute {
            size_limit: 64 * 1024,
            reads_by_get: true,
            ..route(
                "settings",
                "/api/settings",
                &rewrite_body(&[("evil.lan", "10.6.6.6")]),
            )
        },
        route("list add", "/api/lists/add", &add_body("Evil", evil)),
        route("list edit", "/api/lists/edit", &edit.to_string()),
        route("list removal", "/api/lists/remove", &seeded.to_string()),
        route("lists reset", "/api/lists/reset", "{}"),
        ChangeRoute {
            needs_sign_in: false,
            ..route(
                "login",
                "/api/login",
                &serde_json::json!({"user": "admin", "password": "s3cret"}).to_string(),
            )
        },
        ChangeRoute {
            needs_sign_in: false,
            ..route("logout", "/api/logout", "{}")
        },
    ]
}

impl ChangeRoute {
    fn valid(&self) -> Request {
        post(self.path, &self.valid_body)
    }

    /// The valid body with a member that takes it past the size limit of the route.
    fn oversized_body(&self) -> String {
        let padding = "x".repeat(self.size_limit);
        let body = self.valid_body.trim_end();

        match body.strip_suffix('}') {
            Some(object) => format!("{object},\"padding\":\"{padding}\"}}"),
            None => format!("{{\"padding\":\"{padding}\"}}"),
        }
    }

    /// Every way to be refused that applies to the route, each as the valid request with one
    /// thing wrong, and the status that refuses it.
    fn refused(&self) -> Vec<(String, Request, u16)> {
        let path = self.path;
        let body = self.valid_body.as_str();
        let oversized = self.oversized_body();
        let chunked = Request {
            headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ],
            body: format!("{:x}\r\n{}\r\n0\r\n\r\n", oversized.len(), oversized).into_bytes(),
            ..post(path, "")
        };
        let mut rows = vec![
            (
                "from another origin",
                self.valid().header("Origin", "http://evil.example"),
                403,
            ),
            (
                "from the same host and another port",
                self.valid().header("Origin", "http://127.0.0.1:1"),
                403,
            ),
            (
                "from an https origin",
                self.valid().header("Origin", "https://127.0.0.1"),
                403,
            ),
            (
                "from a null origin",
                self.valid().header("Origin", "null"),
                403,
            ),
            (
                "for a name that is not configured",
                self.valid().header("Host", "evil.example"),
                403,
            ),
            (
                "for a rebound name with the right port",
                self.valid().header("Host", "localhost:8080"),
                403,
            ),
            (
                "as plain text",
                self.valid().header("Content-Type", "text/plain"),
                415,
            ),
            (
                "as a form",
                self.valid()
                    .header("Content-Type", "application/x-www-form-urlencoded"),
                415,
            ),
            (
                "without a content type",
                Request {
                    headers: Vec::new(),
                    ..self.valid()
                },
                415,
            ),
            ("over its size limit", post(path, &oversized), 413),
            ("over its size limit without a length", chunked, 413),
            (
                "as a put",
                Request {
                    method: "PUT",
                    ..self.valid()
                },
                405,
            ),
        ];
        if !self.reads_by_get {
            rows.push(("as a get", get(path), 405));
            rows.push((
                "as a get with its body",
                Request {
                    body: body.as_bytes().to_vec(),
                    ..get(path)
                },
                405,
            ));
        }

        rows.into_iter()
            .map(|(what, request, status)| (format!("{} {what}", self.name), request, status))
            .collect()
    }
}

/// Every refused request of every change route, and a change posted to a read.
fn rejected_mutations(seeded_list: &str) -> Vec<(String, Request, u16)> {
    let mut rejected: Vec<(String, Request, u16)> = change_routes(seeded_list)
        .iter()
        .flat_map(ChangeRoute::refused)
        .collect();
    rejected.push((
        "a post of a read".to_string(),
        post("/api/status", "{}"),
        405,
    ));
    rejected.push(("a post of the page".to_string(), post("/", "{}"), 405));

    rejected
}

const RULE_BODY: &str = "{\"name\":\"x.example\",\"action\":\"block\"}";
/// A rule the seeded sites do not hold, so a refused add would show as a change.
const NEW_RULE_BODY: &str = "{\"name\":\"new.example\",\"action\":\"block\"}";
const REMOVE_BODY: &str = "{\"name\":\"x.example\"}";

/// True when no rule was added from the page.
async fn no_page_rules(site: &Site) -> bool {
    site.control.with_button_rules(<[_]>::is_empty).await
}

async fn assert_mutations_are_rejected(site: &SeededSite, sign_in: impl Fn(Request) -> Request) {
    let cached = cache_one_answer(site).await;
    let before = changeable(site).await;

    for (what, request, status) in rejected_mutations(&site.list) {
        let reply = site.send_as_is(sign_in(request)).await;

        assert_eq!(reply.status, status, "{what}");
        assert_eq!(reply.header("set-cookie"), None, "{what} set a cookie");
        assert_nothing_was_started(site, &what);
        assert_cache_kept(site, cached, &what);
        assert_eq!(changeable(site).await, before, "{what} changed something");
    }
}

/// Asks a name the upstream answers, so the cache holds an entry a clear would remove.
/// Returns how many entries the cache holds then.
async fn cache_one_answer(site: &Site) -> usize {
    ask(&site.dns, "kept.example.", RecordType::A).await;
    let entries = site.dns.pipeline.cache_size().entries;
    assert!(entries >= 1);

    entries
}

fn assert_cache_kept(site: &Site, entries: usize, what: &str) {
    assert!(
        site.dns.pipeline.cache_size().entries >= entries,
        "{what} cleared the cache"
    );
}

/// A rejected request never reaches the release fake and never starts an update.
fn assert_nothing_was_started(site: &Site, what: &str) {
    assert_eq!(site.release.requests(), 0, "{what} reached the release");
    assert!(site.stager.view().is_none(), "{what} started an update");
}

async fn open_site() -> (Site, common::harness::FakeUpstream) {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    without_credentials(&mut config);

    (site(config).await, upstream)
}

#[tokio::test]
async fn the_status_shows_the_version_and_a_newer_one_with_or_without_a_password() {
    let (with_password, _upstream) = plain_site().await;
    let (without_password, _other) = open_site().await;

    for site in [&with_password, &without_password] {
        let status = site.send(get("/api/status")).await.json();

        assert_eq!(status["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(status["update"]["build"], Build::current().name());
        for absent in ["latest", "notes", "how"] {
            assert!(status["update"].get(absent).is_none(), "{absent}");
        }

        site.updates.show(Some(Latest {
            version: "9.9.9".to_string(),
            notes: "Faster lists".to_string(),
        }));

        let status = site.send(get("/api/status")).await.json();

        assert_eq!(status["update"]["latest"], "9.9.9");
        assert_eq!(status["update"]["notes"], "Faster lists");
        assert_eq!(status["update"]["how"], Build::current().how());
    }
}

#[tokio::test]
async fn a_hanging_check_holds_up_neither_dns_nor_the_page() {
    let (site, _upstream) = plain_site().await;
    let github = ListServer::start().await;
    github.set_delay(Duration::from_secs(30));
    let timing = CheckTiming {
        first_min: Duration::ZERO,
        first_max: Duration::ZERO,
        every: Duration::from_secs(3600),
    };
    let check = update::start(
        &Config::default(),
        &github.url("/latest"),
        Names::Resolver(Arc::new(|_| {
            Box::pin(async { Err(io::Error::other("no DNS in this test")) })
        })),
        Arc::new(Tls::with_webpki_roots()),
        Arc::clone(&site.updates),
        timing,
    )
    .expect("the check is on");

    let waiting = Instant::now();
    while github.requests() == 0 {
        assert!(waiting.elapsed() < Duration::from_secs(5), "no request");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let answers = async {
        ask(&site.dns, "ok.example.", RecordType::A).await;
        site.send(get("/api/status")).await
    };
    let status = tokio::time::timeout(Duration::from_secs(2), answers)
        .await
        .expect("DNS and the page answer while the check hangs");
    check.abort();

    assert_eq!(status.status, 200);
    assert_eq!(github.requests(), 1);
}

const SET_A_PASSWORD: &str = "set web.user and web.password_hash (or web.password) to use this";

#[tokio::test]
async fn private_status_fields_are_left_out_without_a_password_and_shown_with_one() {
    let (with_password, upstream) = plain_site().await;
    let (without_password, _other) = open_site().await;
    for site in [&with_password, &without_password] {
        ask(&site.dns, "ads.example.", RecordType::A).await;
        ask(&site.dns, "ok.example.", RecordType::A).await;
    }

    let signed_in = with_password.send(get("/api/status")).await.json();

    assert!(signed_in.get("limited").is_none());
    for private in ["top_queried", "top_blocked", "top_clients"] {
        assert!(signed_in.get(private).is_some(), "{private}");
    }
    assert_eq!(
        upstream_entries(&signed_in)[0]["label"],
        format!("udp://{}", upstream.address)
    );
    let mut keys: Vec<&str> = signed_in["cache"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["bytes", "entries"]);

    assert_eq!(without_password.send(get("/")).await.status, 200);
    assert_eq!(without_password.send(get("/api/lists")).await.status, 200);
    let reply = without_password.send(get("/api/status")).await;
    let read_only = reply.json();

    assert_eq!(reply.status, 200);
    assert_eq!(read_only["counters"]["total"], 2);
    assert_eq!(read_only["blocked_percent"], 50.0);
    assert!(read_only["lists"].is_array());
    assert_eq!(read_only["limited"], SET_A_PASSWORD);
    for private in [
        "top_queried",
        "top_blocked",
        "top_clients",
        "upstreams",
        "cache",
    ] {
        assert!(read_only.get(private).is_none(), "{private}");
    }
    assert!(!reply.body.contains("ads.example"));
    assert!(!reply.body.contains("udp://"));
}

#[tokio::test]
async fn without_a_password_the_log_and_every_change_are_forbidden() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    without_credentials(&mut config);
    let site = seeded_site(config, false).await;
    ask(&site.dns, "ads.example.", RecordType::A).await;
    let cached = cache_one_answer(&site).await;
    let before = changeable(&site).await;

    let log = site.send(get("/api/querylog")).await;
    assert_eq!(log.status, 403);
    assert!(log.json()["error"].as_str().unwrap().contains("web.user"));
    assert!(
        log.json()["error"]
            .as_str()
            .unwrap()
            .contains("web.password")
    );
    assert!(!log.body.contains("ads.example"));

    let changes = change_routes(&site.list)
        .into_iter()
        .map(|route| (route.name, route.valid()));
    for (what, request) in [
        ("a get of pause", get("/api/pause")),
        ("the rules", get("/api/rules")),
        ("explain", get("/api/explain?name=ads.example")),
        ("the settings", get("/api/settings")),
        ("the services", get("/api/services")),
    ]
    .into_iter()
    .chain(changes)
    {
        let reply = site.send(request).await;

        assert_eq!(reply.status, 403, "{what}");
        assert_eq!(reply.json()["error"], SET_A_PASSWORD, "{what}");
    }

    assert_cache_kept(&site, cached, "a forbidden change");
    assert_eq!(changeable(&site).await, before);
}

#[tokio::test]
async fn the_page_asks_for_the_log_only_when_the_status_is_not_limited() {
    let (site, _upstream) = open_site().await;

    let page = site.send(get("/")).await.body;

    assert!(page.contains("status.limited"));
    assert!(page.contains("[hidden]"));
}

#[tokio::test]
async fn unsafe_mutations_are_rejected_without_a_password() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    without_credentials(&mut config);
    let site = seeded_site(config, true).await;
    let cached = cache_one_answer(&site).await;
    let before = changeable(&site).await;

    for (what, request, _) in rejected_mutations(&site.list) {
        let target = request.path.clone();
        let reply = site.send(request).await;

        // A path that no password guards keeps its own answer for a bad method.
        let expected = if matches!(target.as_str(), "/api/status" | "/") {
            405
        } else {
            403
        };
        assert_eq!(reply.status, expected, "{what}");
        assert_nothing_was_started(&site, &what);
        assert_cache_kept(&site, cached, &what);
        assert_eq!(changeable(&site).await, before, "{what} changed something");
    }
}

#[tokio::test]
async fn unsafe_mutations_are_rejected_with_a_password_and_valid_credentials() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let site = seeded_site(local_config(&upstream), true).await;

    assert_mutations_are_rejected(&site, |request| request.signed_in(ADMIN)).await;
}

#[tokio::test]
async fn unsafe_mutations_are_rejected_with_a_session_cookie() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let site = seeded_site(local_config(&upstream), true).await;
    let token = site
        .send_as_is(login("admin", "s3cret"))
        .await
        .session()
        .unwrap();

    assert_mutations_are_rejected(&site, |request| request.with_session(&token)).await;
}

/// The refusals of the tables only mean something if the same request, with nothing wrong,
/// is accepted.
#[tokio::test]
async fn every_change_route_accepts_the_request_the_tables_refuse() {
    let mut routes = tokio::task::JoinSet::new();
    for index in 0..change_routes("").len() {
        routes.spawn(async move {
            let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
            let site = seeded_site(local_config(&upstream), true).await;
            let route = change_routes(&site.list).swap_remove(index);
            let reply = site.send(route.valid()).await;

            (route.name, reply.status, reply.body)
        });
    }

    while let Some(done) = routes.join_next().await {
        let (name, status, body) = done.unwrap();

        assert!(status == 200 || status == 202, "{name}: {status} {body}");
    }
}

#[tokio::test]
async fn a_get_of_a_mutation_names_the_method_that_works() {
    let (site, _upstream) = plain_site().await;

    let reply = site.send(get("/api/pause")).await;
    let read = site.send(post("/api/status", "{}")).await;
    let removal = site.send(get("/api/rules/remove")).await;
    let rules = site
        .send(Request {
            method: "PUT",
            ..post("/api/rules", RULE_BODY)
        })
        .await;
    let settings = site
        .send(Request {
            method: "PUT",
            ..post("/api/settings", "{}")
        })
        .await;

    assert_eq!(reply.header("allow"), Some("POST"));
    assert_eq!(read.header("allow"), Some("GET"));
    assert_eq!(removal.header("allow"), Some("POST"));
    assert_eq!(rules.header("allow"), Some("GET, POST"));
    assert_eq!(settings.status, 405);
    assert_eq!(settings.header("allow"), Some("GET, POST"));
}

#[tokio::test]
async fn with_a_password_the_page_opens_without_a_prompt_and_the_api_needs_a_sign_in() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let site = seeded_site(local_config(&upstream), false).await;
    let before = changeable(&site).await;
    let reads = [
        "/api/status",
        "/api/querylog",
        "/api/lists",
        "/api/rules",
        "/api/explain?name=ads.example",
        "/api/settings",
        "/api/services",
    ];
    let changes: Vec<ChangeRoute> = change_routes(&site.list)
        .into_iter()
        .filter(|route| route.needs_sign_in)
        .collect();
    let requests = || {
        reads
            .iter()
            .map(|path| get(path))
            .chain(changes.iter().map(ChangeRoute::valid))
    };

    let page = site.send_as_is(get("/")).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("<title>picoguard"));
    assert_eq!(page.header("www-authenticate"), None);

    for request in requests() {
        let path = request.path.clone();
        let reply = site.send_as_is(request).await;

        assert_eq!(reply.status, 401, "{path}");
        assert_eq!(
            reply.header("www-authenticate"),
            Some("Basic realm=\"picoguard\""),
            "{path}"
        );
        assert!(!reply.body.contains("counters"), "{path}");
    }

    for request in requests() {
        let path = request.path.clone();
        let reply = site.send_as_is(request.by_page()).await;

        assert_eq!(reply.status, 401, "{path}");
        assert_eq!(reply.header("www-authenticate"), None, "{path}");
    }

    let wrong_credentials = [
        WRONG_PASSWORD,
        OTHER_USER,
        "YWRtaW46czNjcmU=",
        "YWRtaW46czNjcmV0eA==",
        "",
    ];
    // Each request from its own address, so none of them reaches the limit.
    for (attempt, credentials) in wrong_credentials.iter().enumerate() {
        for (index, request) in requests().enumerate() {
            let path = request.path.clone();
            let from = format!("127.0.{}.{}", 10 + attempt, 1 + index);
            let reply = site.send_from(&from, request.signed_in(credentials)).await;

            assert_eq!(reply.status, 401, "{path} {credentials:?}");
            assert_eq!(
                reply.header("www-authenticate"),
                Some("Basic realm=\"picoguard\""),
                "{path} {credentials:?}"
            );
        }
    }

    assert_eq!(changeable(&site).await, before);

    for path in reads {
        let reply = site.send_as_is(get(path).signed_in(ADMIN)).await;
        assert_eq!(reply.status, 200, "{path}");
    }

    let lowercase_scheme = get("/api/status").header("Authorization", &format!("basic {ADMIN}"));
    assert_eq!(site.send_as_is(lowercase_scheme).await.status, 200);

    let paused = site
        .send_as_is(post("/api/pause", "{\"minutes\": 5}").signed_in(ADMIN))
        .await;
    assert_eq!(paused.status, 200);
    assert!(site.is_paused());
    let resumed = site
        .send_as_is(post("/api/resume", "").signed_in(ADMIN))
        .await;
    assert_eq!(resumed.status, 200);
    assert!(!site.is_paused());
}

const TOO_MANY_ATTEMPTS: &str = "{\"error\":\"too many attempts, try again later\"}";

#[tokio::test]
async fn wrong_basic_auth_counts_toward_the_limit_and_anonymous_requests_do_not() {
    let (site, _upstream) = plain_site().await;

    for _ in 0..10 {
        let reply = site.send_from("127.0.0.2", get("/api/status")).await;
        assert_eq!(reply.status, 401);
    }

    for _ in 0..5 {
        let reply = site
            .send_from("127.0.0.2", get("/api/status").signed_in(WRONG_PASSWORD))
            .await;
        assert_eq!(reply.status, 401);
    }

    let limited = site
        .send_from("127.0.0.2", get("/api/status").signed_in(ADMIN))
        .await;
    assert_eq!(limited.status, 429);
    assert_eq!(limited.body, TOO_MANY_ATTEMPTS);
    assert_eq!(limited.header("www-authenticate"), None);

    let other = site
        .send_from("127.0.0.3", get("/api/status").signed_in(ADMIN))
        .await;
    assert_eq!(other.status, 200);
}

#[tokio::test]
async fn an_anonymous_request_is_asked_to_sign_in_before_a_path_is_found_missing() {
    let (site, _upstream) = plain_site().await;

    let anonymous = site.send_as_is(get("/nope")).await;
    let signed_in = site.send_as_is(get("/nope").signed_in(ADMIN)).await;

    assert_eq!(anonymous.status, 401);
    assert_eq!(signed_in.status, 404);
}

#[tokio::test]
async fn a_bearer_token_is_not_a_login_and_does_not_count_toward_the_limit() {
    let (site, _upstream) = plain_site().await;

    for _ in 0..10 {
        let reply = site
            .send_from(
                "127.0.0.2",
                get("/api/status").header("Authorization", "Bearer x"),
            )
            .await;
        assert_eq!(reply.status, 401);
    }

    let reply = site
        .send_from("127.0.0.2", get("/api/status").signed_in(ADMIN))
        .await;
    assert_eq!(reply.status, 200);
}

#[tokio::test]
async fn every_refusal_carries_the_protective_headers_and_grants_no_cross_origin_read() {
    let (site, _upstream) = plain_site().await;
    let padded = format!("{{}}{}", " ".repeat(64 * 1024));
    for _ in 0..5 {
        site.send_from("127.0.0.2", get("/api/status").signed_in(WRONG_PASSWORD))
            .await;
    }

    let refusals = [
        (401, site.send_as_is(get("/api/status")).await),
        (
            403,
            site.send_as_is(
                get("/api/lists")
                    .header("Host", "evil.example")
                    .signed_in(ADMIN),
            )
            .await,
        ),
        (404, site.send_as_is(get("/nope").signed_in(ADMIN)).await),
        (
            405,
            site.send_as_is(get("/api/pause").signed_in(ADMIN)).await,
        ),
        (
            413,
            site.send_as_is(post("/api/settings", &padded).signed_in(ADMIN))
                .await,
        ),
        (
            429,
            site.send_from("127.0.0.2", get("/api/status").signed_in(ADMIN))
                .await,
        ),
    ];

    for (status, reply) in refusals {
        assert_eq!(reply.status, status, "{}", reply.body);
        assert_eq!(reply.header("cache-control"), Some("no-store"), "{status}");
        assert_eq!(
            reply.header("x-content-type-options"),
            Some("nosniff"),
            "{status}"
        );
        assert_eq!(reply.header("x-frame-options"), Some("DENY"), "{status}");
        assert_eq!(
            reply.header("content-security-policy"),
            Some(PAGE_CSP),
            "{status}"
        );
        assert_no_cross_origin_grant(&reply, &status.to_string());
    }
}

#[tokio::test]
async fn a_preflight_is_not_answered_with_a_cross_origin_grant() {
    let (site, _upstream) = plain_site().await;
    let preflight = Request {
        method: "OPTIONS",
        ..get("/api/pause")
            .header("Origin", "http://evil.example")
            .header("Access-Control-Request-Method", "POST")
            .signed_in(ADMIN)
    };

    let reply = site.send_as_is(preflight).await;

    assert_no_cross_origin_grant(&reply, "OPTIONS");
    assert!(!site.is_paused());
}

fn assert_no_cross_origin_grant(reply: &Reply, what: &str) {
    for (name, _) in &reply.headers {
        assert!(!name.starts_with("access-control-allow-"), "{what}: {name}");
    }
}

#[tokio::test]
async fn a_password_hash_opens_the_api_with_basic_auth() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let site = site(hashed_config(&upstream, "s3cret", 1000)).await;

    let wrong = site
        .send_as_is(get("/api/status").signed_in(WRONG_PASSWORD))
        .await;
    assert_eq!(wrong.status, 401);

    let right = site.send_as_is(get("/api/status").signed_in(ADMIN)).await;
    assert_eq!(right.status, 200);
    assert!(right.json().get("limited").is_none(), "{}", right.body);
}

#[tokio::test]
async fn repeated_basic_auth_with_a_hash_does_not_pay_the_hash_each_time() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let config = hashed_config(&upstream, "s3cret", 100_000);
    let hash = config.web.password_hash.clone().unwrap();
    let site = site(config).await;
    let started = Instant::now();
    assert!(hash.verify(b"s3cret"));
    let one = started.elapsed();

    let wrong = site
        .send_as_is(get("/api/status").signed_in(WRONG_PASSWORD))
        .await;
    assert_eq!(wrong.status, 401);
    let first = site.send_as_is(get("/api/status").signed_in(ADMIN)).await;
    assert_eq!(first.status, 200);
    assert!(first.json().get("limited").is_none());

    let started = Instant::now();
    for _ in 0..100 {
        let reply = site.send_as_is(get("/api/status").signed_in(ADMIN)).await;
        assert_eq!(reply.status, 200);
    }
    let hundred = started.elapsed();

    // Uncached, they would take `one * 100`.
    assert!(
        hundred < one * 10,
        "one hash {one:?}, 100 requests {hundred:?}"
    );
}

#[tokio::test]
async fn a_slow_password_check_holds_up_neither_dns_nor_the_page() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let site = Arc::new(site(hashed_config(&upstream, "s3cret", 2_000_000)).await);

    let slow = tokio::spawn({
        let site = Arc::clone(&site);

        async move {
            site.send_from("127.0.0.2", get("/api/status").signed_in(WRONG_PASSWORD))
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let answers = async {
        ask(&site.dns, "ok.example.", RecordType::A).await;
        site.send_as_is(get("/")).await
    };
    let page = tokio::time::timeout(Duration::from_secs(2), answers)
        .await
        .expect("DNS and the page answer while a password is hashed");
    assert_eq!(page.status, 200);
    assert!(!slow.is_finished(), "the hash ended before DNS was asked");

    assert_eq!(slow.await.unwrap().status, 401);
}

const WRONG_USER_OR_PASSWORD: &str = "{\"error\":\"wrong user or password\"}";
const SIGNED_OUT: &str = "picoguard_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict";

#[tokio::test]
async fn signing_in_sets_a_strict_http_only_cookie_that_opens_the_api() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;

    for config in [
        local_config(&upstream),
        hashed_config(&upstream, "s3cret", 1000),
    ] {
        let site = site(config).await;
        ask(&site.dns, "ads.example.", RecordType::A).await;

        let reply = site.send_as_is(login("admin", "s3cret")).await;
        assert_eq!(reply.status, 200, "{}", reply.body);
        assert_eq!(reply.body, "{}");
        let cookie = reply.header("set-cookie").unwrap();
        assert!(cookie.starts_with("picoguard_session="), "{cookie}");
        for attribute in [
            "; Max-Age=2592000",
            "; Path=/",
            "; HttpOnly",
            "; SameSite=Strict",
        ] {
            assert!(cookie.contains(attribute), "{cookie} lacks {attribute}");
        }
        let token = reply.session().unwrap();

        let status = site
            .send_as_is(get("/api/status").with_session(&token))
            .await;
        assert_eq!(status.status, 200);
        assert!(status.json().get("top_queried").is_some());

        let paused = site
            .send_as_is(post("/api/pause", "{\"minutes\": 5}").with_session(&token))
            .await;
        assert_eq!(paused.status, 200);
        assert!(site.is_paused());

        let spaced = post(
            "/api/login",
            " \n {\"user\": \"admin\", \"password\": \"s3cret\"}",
        );
        let reply = site.send_as_is(spaced).await;
        assert_eq!(reply.status, 200);
        assert!(reply.session().is_some());
    }
}

#[tokio::test]
async fn a_wrong_user_and_a_wrong_password_get_the_same_answer() {
    let (site, _upstream) = plain_site().await;
    let attempts = [("other", "s3cret"), ("admin", "wrong"), ("other", "wrong")];

    for (index, (user, password)) in attempts.into_iter().enumerate() {
        let from = format!("127.0.1.{}", 1 + index);
        let reply = site.send_from(&from, login(user, password)).await;
        assert_eq!(reply.status, 401);
        assert_eq!(reply.body, WRONG_USER_OR_PASSWORD);
        assert_eq!(reply.header("set-cookie"), None);
        assert_eq!(
            reply.header("www-authenticate"),
            Some("Basic realm=\"picoguard\"")
        );

        let from = format!("127.0.2.{}", 1 + index);
        let reply = site.send_from(&from, login(user, password).by_page()).await;
        assert_eq!(reply.status, 401);
        assert_eq!(reply.body, WRONG_USER_OR_PASSWORD);
        assert_eq!(reply.header("set-cookie"), None);
        assert_eq!(reply.header("www-authenticate"), None);
    }
}

/// `token` with the character at `index` changed to another digit.
fn changed_at(token: &str, index: usize) -> String {
    let mut bytes = token.as_bytes().to_vec();
    bytes[index] = if bytes[index] == b'1' { b'2' } else { b'1' };

    String::from_utf8(bytes).unwrap()
}

#[tokio::test]
async fn a_changed_or_foreign_cookie_is_treated_as_none() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let site = site(local_config(&upstream)).await;
    let mut other_config = local_config(&upstream);
    other_config.web.password = Some("other".to_string());
    let other = self::site(other_config).await;
    let token = site
        .send_as_is(login("admin", "s3cret"))
        .await
        .session()
        .unwrap();
    let foreign = other
        .send_as_is(login("admin", "other"))
        .await
        .session()
        .unwrap();

    for bad in [
        changed_at(&token, 0),
        changed_at(&token, token.len() - 1),
        format!("{token}0"),
        foreign,
    ] {
        let reply = site.send_as_is(get("/api/status").with_session(&bad)).await;
        assert_eq!(reply.status, 401, "{bad}");
    }

    assert_eq!(site.send_as_is(get("/")).await.status, 200);
    let good = site
        .send_as_is(get("/api/status").with_session(&token))
        .await;
    assert_eq!(good.status, 200);
}

async fn status_with(site: &Site, token: &str) -> u16 {
    site.send_as_is(get("/api/status").with_session(token))
        .await
        .status
}

#[tokio::test]
async fn a_cookie_outlives_a_restart_and_ends_with_a_new_password_user_or_hash() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let config = local_config(&upstream);
    let first = site(config.clone()).await;
    let token = first
        .send_as_is(login("admin", "s3cret"))
        .await
        .session()
        .unwrap();

    let restarted = site(config.clone()).await;
    assert_eq!(status_with(&restarted, &token).await, 200);

    let mut new_password = config.clone();
    new_password.web.password = Some("changed".to_string());
    assert_eq!(status_with(&site(new_password).await, &token).await, 401);

    let mut new_user = config.clone();
    new_user.web.user = Some("other".to_string());
    assert_eq!(status_with(&site(new_user).await, &token).await, 401);

    let hash_a = hashed_config(&upstream, "s3cret", 1000);
    let hash_b = hashed_config(&upstream, "s3cret", 1000);
    let token = site(hash_a.clone())
        .await
        .send_as_is(login("admin", "s3cret"))
        .await
        .session()
        .unwrap();
    assert_eq!(status_with(&site(hash_a).await, &token).await, 200);
    assert_eq!(status_with(&site(hash_b).await, &token).await, 401);
}

#[tokio::test]
async fn signing_out_clears_the_cookie_and_needs_a_sign_in() {
    let (site, _upstream) = plain_site().await;
    let token = site
        .send_as_is(login("admin", "s3cret"))
        .await
        .session()
        .unwrap();

    let reply = site
        .send_as_is(post("/api/logout", "{}").with_session(&token))
        .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, "{}");
    assert_eq!(reply.header("set-cookie"), Some(SIGNED_OUT));

    let anonymous = site.send_as_is(post("/api/logout", "{}")).await;
    assert_eq!(anonymous.status, 401);

    // A copy of the token stays valid until it expires (documented).
    assert_eq!(status_with(&site, &token).await, 200);
}

#[tokio::test]
async fn failed_form_logins_count_with_basic_auth_and_lock_one_address() {
    let (site, _upstream) = plain_site().await;

    for _ in 0..5 {
        let reply = site.send_from("127.0.0.2", login("admin", "wrong")).await;
        assert_eq!(reply.status, 401);
    }
    let limited = site.send_from("127.0.0.2", login("admin", "s3cret")).await;
    assert_eq!(limited.status, 429);
    assert_eq!(limited.body, TOO_MANY_ATTEMPTS);
    assert_eq!(limited.header("set-cookie"), None);

    let elsewhere = site.send_from("127.0.0.3", login("admin", "s3cret")).await;
    assert_eq!(elsewhere.status, 200);
    let token = elsewhere.session().unwrap();

    for _ in 0..3 {
        let reply = site
            .send_from("127.0.0.4", get("/api/status").signed_in(WRONG_PASSWORD))
            .await;
        assert_eq!(reply.status, 401);
    }
    for _ in 0..2 {
        let reply = site.send_from("127.0.0.4", login("admin", "wrong")).await;
        assert_eq!(reply.status, 401);
    }
    let mixed = site.send_from("127.0.0.4", login("admin", "s3cret")).await;
    assert_eq!(mixed.status, 429);

    // A cookie is not a password check.
    let with_cookie = site
        .send_from("127.0.0.2", get("/api/status").with_session(&token))
        .await;
    assert_eq!(with_cookie.status, 200);

    let malformed = [
        "{\"user\": \"admin\"}",
        "{\"user\": \"admin\", \"password\": \"wrong\", \"extra\": 1}",
        "[\"admin\", \"s3cret\"]",
        "not json",
    ];
    for body in malformed.iter().cycle().take(6) {
        let reply = site.send_from("127.0.0.5", post("/api/login", body)).await;
        assert_eq!(reply.status, 400, "{body}");
    }
    let after = site.send_from("127.0.0.5", login("admin", "s3cret")).await;
    assert_eq!(after.status, 200);
}

#[tokio::test]
async fn either_a_valid_cookie_or_valid_basic_auth_is_enough() {
    let (site, _upstream) = plain_site().await;
    let token = site
        .send_as_is(login("admin", "s3cret"))
        .await
        .session()
        .unwrap();

    for _ in 0..6 {
        let both = get("/api/status")
            .signed_in(WRONG_PASSWORD)
            .header("Cookie", &format!("picoguard_session={token}"));
        assert_eq!(site.send_from("127.0.0.6", both).await.status, 200);
    }
    let reply = site.send_from("127.0.0.6", login("admin", "s3cret")).await;
    assert_eq!(reply.status, 200, "the basic header was never checked");

    let tampered = get("/api/status").signed_in(ADMIN).header(
        "Cookie",
        &format!("picoguard_session={}", changed_at(&token, 0)),
    );
    assert_eq!(site.send_as_is(tampered).await.status, 200);
}

#[tokio::test]
async fn the_host_may_be_a_configured_name_with_or_without_a_port() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    config.web.hostnames = vec!["picoguard.lan".to_string()];
    let site = site(config).await;

    for host in [
        "picoguard.lan",
        "PicoGuard.LAN:8080",
        "10.1.2.3",
        "[::1]:8080",
    ] {
        let reply = site.send(get("/api/lists").header("Host", host)).await;
        assert_eq!(reply.status, 200, "{host}");
    }

    for host in [
        "evil.picoguard.lan",
        "picoguard.lan.evil.example",
        "localhost",
        "",
    ] {
        let reply = site.send(get("/api/lists").header("Host", host)).await;
        assert_eq!(reply.status, 403, "{host:?}");
        assert!(!reply.body.contains("lists"));
    }

    let own_origin = post("/api/pause", "{\"minutes\": 5}")
        .header("Host", "picoguard.lan")
        .header("Origin", "http://picoguard.lan");
    assert_eq!(site.send(own_origin).await.status, 200);
}

#[tokio::test]
async fn the_page_itself_may_post_with_its_own_origin() {
    let (site, _upstream) = plain_site().await;
    let own = format!("http://{}", site.web);

    let reply = site
        .send(post("/api/pause", "{\"minutes\": 5}").header("Origin", &own))
        .await;

    assert_eq!(reply.status, 200);
    assert!(site.is_paused());
}

#[tokio::test]
async fn a_request_without_a_host_is_refused() {
    let (site, _upstream) = plain_site().await;

    let bytes = exchange(site.web, b"GET /api/status HTTP/1.0\r\n\r\n").await;

    assert_eq!(parse_reply(&bytes).map(|reply| reply.status), Some(403));
}

#[tokio::test]
async fn oversized_request_heads_are_refused() {
    let (site, _upstream) = plain_site().await;
    let long_value = "x".repeat(20 * 1024);
    let many_headers: Vec<(String, String)> = (0..100)
        .map(|index| (format!("X-Header-{index}"), "v".to_string()))
        .collect();

    let mut with_long = get("/api/status").signed_in(ADMIN);
    with_long = with_long.header("X-Long", &long_value);
    let mut with_many = get("/api/status").signed_in(ADMIN);
    with_many.headers.extend(many_headers);

    for (what, request) in [("a long header", with_long), ("many headers", with_many)] {
        let bytes = exchange(site.web, &request.bytes(site.web)).await;
        let status = parse_reply(&bytes).map(|reply| reply.status);

        // Signed in, so only the head limit can refuse it: the status route would answer 200.
        assert!(status == Some(431), "{what}: {status:?}");
    }

    let after = site.send(get("/api/status")).await;
    assert_eq!(after.status, 200, "the server still answers");
}

/// How many connections the page serves at once, how many of them one client may hold, and how
/// long one may take to send its head and its body: `MAX_CONNECTIONS`,
/// `MAX_CONNECTIONS_PER_CLIENT`, `HEAD_TIMEOUT` and `BODY_TIMEOUT` in `src/web.rs`.
const PAGE_CONNECTIONS: usize = 16;
const PAGE_CONNECTIONS_PER_CLIENT: usize = 4;

async fn connect_from(web: SocketAddr, from: &str) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket
        .bind(SocketAddr::new(from.parse().unwrap(), 0))
        .unwrap();

    socket.connect(web).await.unwrap()
}

async fn closes_within(stream: &mut TcpStream, wait: Duration) -> bool {
    let mut chunk = [0u8; 64];

    matches!(
        tokio::time::timeout(wait, stream.read(&mut chunk)).await,
        Ok(Ok(0) | Err(_))
    )
}

#[tokio::test]
async fn connections_that_send_no_head_cannot_hold_the_page_down() {
    let (site, _upstream) = plain_site().await;
    let mut idle = Vec::new();
    for index in 0..PAGE_CONNECTIONS {
        let from = format!("127.0.0.{}", 1 + index / PAGE_CONNECTIONS_PER_CLIENT);
        let mut stream = connect_from(site.web, &from).await;
        if index % 2 == 1 {
            stream
                .write_all(b"GET /api/status HTTP/1.1\r\nHost: x\r\n")
                .await
                .unwrap();
        }

        idle.push(stream);
    }

    assert!(
        site.is_ignored(get("/api/status")).await,
        "a connection past the limit was served"
    );
    assert_eq!(
        ask(&site.dns, "ok.example.", RecordType::A)
            .await
            .response_code,
        ResponseCode::NoError
    );

    for (index, mut stream) in idle.into_iter().enumerate() {
        assert!(
            closes_within(&mut stream, Duration::from_secs(15)).await,
            "connection {index} was still open after 15 s"
        );
    }

    let after = site.send(get("/api/status")).await;
    assert_eq!(after.status, 200, "the page answers again");
}

#[tokio::test]
async fn one_client_cannot_hold_more_than_its_share_of_the_page_connections() {
    let (site, _upstream) = plain_site().await;
    let stalled_login = "POST /api/login HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                         Content-Type: application/json\r\nContent-Length: 1000\r\n\r\n{";
    let mut stalled = Vec::new();
    for _ in 0..PAGE_CONNECTIONS_PER_CLIENT {
        let mut stream = connect_from(site.web, "127.0.0.1").await;
        stream.write_all(stalled_login.as_bytes()).await.unwrap();
        stalled.push(stream);
    }

    let mut fifth = connect_from(site.web, "127.0.0.1").await;

    assert!(
        closes_within(&mut fifth, Duration::from_secs(1)).await,
        "a fifth connection from one client was kept"
    );
    let other = exchange_from(
        site.web,
        "127.0.0.2".parse().unwrap(),
        &get("/api/status").bytes(site.web),
    )
    .await;
    assert!(
        parse_reply(&other).is_some_and(|reply| reply.status == 200 || reply.status == 401),
        "another client was not answered: {other:?}"
    );
}

#[tokio::test]
async fn a_body_that_is_not_sent_in_time_is_answered_with_408() {
    let (site, _upstream) = plain_site().await;
    let request = "POST /api/login HTTP/1.1\r\nHost: 127.0.0.1\r\n\
                   Content-Type: application/json\r\nContent-Length: 1000\r\n\r\n{";

    let mut stream = TcpStream::connect(site.web).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), stream.read_to_end(&mut reply))
        .await
        .expect("the server kept the connection open")
        .unwrap();

    assert_eq!(parse_reply(&reply).unwrap().status, 408);
}

#[tokio::test]
async fn a_peer_outside_allow_from_gets_nothing_from_reads_or_changes() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    config.web.allow_from = vec!["10.0.0.0/8".parse().unwrap()];
    let site = site(config).await;

    assert!(site.is_ignored(get("/")).await);
    assert!(site.is_ignored(get("/api/status")).await);
    assert!(site.is_ignored(get("/api/querylog")).await);
    assert!(site.is_ignored(get("/api/lists")).await);
    assert!(
        site.is_ignored(post("/api/pause", "{\"minutes\": 5}"))
            .await
    );
    assert!(site.is_ignored(post("/api/resume", "")).await);
    assert!(site.is_ignored(post("/api/lists/refresh", "")).await);
    assert!(site.is_ignored(post("/api/update", UPDATE_BODY)).await);
    assert!(site.is_ignored(login("admin", "s3cret")).await);
    assert!(site.is_ignored(post("/api/logout", "{}")).await);
    assert!(site.is_ignored(post("/api/cache/clear", "{}")).await);
    assert!(site.is_ignored(get("/api/rules")).await);
    assert!(site.is_ignored(get("/api/explain?name=ads.example")).await);
    assert!(site.is_ignored(post("/api/rules", RULE_BODY)).await);
    assert!(
        site.is_ignored(post("/api/rules/remove", REMOVE_BODY))
            .await
    );
    assert!(!site.is_paused());
    assert!(no_page_rules(&site).await);
    assert_nothing_was_started(&site, "a peer outside allow_from");
}

#[tokio::test]
async fn an_ipv6_peer_outside_allow_from_gets_nothing_and_one_inside_is_served() {
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        return;
    }

    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    config.web.bind = vec!["::1".parse().unwrap()];
    config.web.allow_from = vec![
        "10.0.0.0/8".parse().unwrap(),
        "2001:db8::/32".parse().unwrap(),
    ];
    let outside = site(config.clone()).await;

    assert!(outside.is_ignored(get("/api/status")).await);
    assert!(
        outside
            .is_ignored(post("/api/pause", "{\"minutes\": 5}"))
            .await
    );
    assert!(outside.is_ignored(post("/api/update", UPDATE_BODY)).await);
    assert!(!outside.is_paused());
    assert_nothing_was_started(&outside, "an IPv6 peer outside allow_from");

    config.web.allow_from = vec!["::1/128".parse().unwrap()];
    let inside = site(config).await;

    let reply = inside.send(get("/api/status")).await;
    assert_eq!(reply.status, 200);
    let paused = inside.send(post("/api/pause", "{\"minutes\": 5}")).await;
    assert_eq!(paused.status, 200);
}

async fn status_of(site: &Site) -> Value {
    site.send(get("/api/status")).await.json()["update"].clone()
}

async fn until_status(site: &Site, what: &str, mut done: impl FnMut(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);

    loop {
        let update = status_of(site).await;

        if done(&update) {
            return update;
        }

        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}: {update}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn update_site(kind: SiteKind) -> (Site, common::harness::FakeUpstream) {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let site = site_with(local_config(&upstream), kind).await;
    site.updates.show(Some(offered()));

    (site, upstream)
}

const RELEASE: SiteKind = SiteKind {
    build: Build::Release,
    installer: true,
    release_target: true,
};

#[tokio::test]
async fn the_update_route_answers_400_409_and_202() {
    let (site, _upstream) = update_site(RELEASE).await;

    for (what, body) in [
        ("an empty object", "{}"),
        ("a number", "{\"version\": 3}"),
        ("an array", "[\"9.9.9\"]"),
        ("an unknown field", "{\"version\": \"9.9.9\", \"x\": 1}"),
        (
            "a repeated field",
            "{\"version\": \"9.9.9\", \"version\": \"9.9.9\"}",
        ),
        ("an empty version", "{\"version\": \"\"}"),
        ("a v prefix", "{\"version\": \"v9.9.9\"}"),
        ("two numbers", "{\"version\": \"9.9\"}"),
        ("a pre-release", "{\"version\": \"9.9.9-rc.1\"}"),
        ("not JSON", "9.9.9"),
    ] {
        let reply = site.send(post("/api/update", body)).await;

        assert_eq!(reply.status, 400, "{what}");
        assert!(reply.json()["error"].as_str().unwrap().starts_with("send "));
        assert_nothing_was_started(&site, what);
    }

    let wrong = site
        .send(post("/api/update", "{\"version\": \"9.9.8\"}"))
        .await;
    assert_eq!(wrong.status, 409);
    assert_eq!(wrong.json()["error"], "that is not the newest release");
    assert_nothing_was_started(&site, "another version");

    let started = site.send(post("/api/update", UPDATE_BODY)).await;
    assert_eq!(started.status, 202);
    assert_eq!(started.json(), serde_json::json!({"install": "started"}));

    let again = site.send(post("/api/update", UPDATE_BODY)).await;
    assert_eq!(again.status, 409);
    assert_eq!(again.json()["error"], "an update is already in progress");
}

#[tokio::test]
async fn an_update_that_cannot_be_installed_from_the_page_answers_409() {
    for (what, kind) in [
        (
            "a source build",
            SiteKind {
                build: Build::Source,
                installer: true,
                release_target: true,
            },
        ),
        (
            "a Docker build",
            SiteKind {
                build: Build::Docker,
                installer: true,
                release_target: true,
            },
        ),
        (
            "no installer",
            SiteKind {
                build: Build::Release,
                installer: false,
                release_target: true,
            },
        ),
        (
            "a target without a release",
            SiteKind {
                build: Build::Release,
                installer: true,
                release_target: false,
            },
        ),
    ] {
        let (site, _upstream) = update_site(kind).await;

        let reply = site.send(post("/api/update", UPDATE_BODY)).await;

        assert_eq!(reply.status, 409, "{what}");
        assert_eq!(
            reply.json()["error"],
            "this build is updated with the command shown",
            "{what}"
        );
        assert_nothing_was_started(&site, what);
    }

    let (site, _upstream) = update_site(RELEASE).await;
    site.updates.show(None);

    let reply = site.send(post("/api/update", UPDATE_BODY)).await;

    assert_eq!(reply.status, 409);
    assert_eq!(reply.json()["error"], "that is not the newest release");
    assert_nothing_was_started(&site, "no newer version");
}

#[tokio::test]
async fn can_install_follows_every_condition() {
    let (full, _upstream) = update_site(RELEASE).await;
    assert_eq!(status_of(&full).await["can_install"], true);

    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    without_credentials(&mut config);
    let open = site_with(config, RELEASE).await;
    open.updates.show(Some(offered()));
    assert_eq!(status_of(&open).await["can_install"], false);

    for (what, kind) in [
        (
            "a source build",
            SiteKind {
                build: Build::Source,
                installer: true,
                release_target: true,
            },
        ),
        (
            "no installer",
            SiteKind {
                build: Build::Release,
                installer: false,
                release_target: true,
            },
        ),
        (
            "a target without a release",
            SiteKind {
                build: Build::Release,
                installer: true,
                release_target: false,
            },
        ),
    ] {
        let (site, _upstream) = update_site(kind).await;

        assert_eq!(status_of(&site).await["can_install"], false, "{what}");
    }

    let (site, _upstream) = update_site(RELEASE).await;
    site.updates.show(None);
    assert_eq!(status_of(&site).await["can_install"], false);

    site.updates.show(Some(offered()));
    assert_eq!(status_of(&site).await["can_install"], true);
    assert_eq!(
        site.send(post("/api/update", UPDATE_BODY)).await.status,
        202
    );
    let update = until_status(&site, "waiting", |update| {
        update["install"]["state"] == "waiting"
    })
    .await;

    assert_eq!(update["can_install"], false);
}

#[tokio::test]
async fn progress_is_shown_with_and_without_a_password() {
    let big: Vec<u8> = (0..300_000u32).map(|index| (index % 253) as u8).collect();
    let files = Files::good(OFFERED, &big);

    let (site, _upstream) = update_site(RELEASE).await;
    site.release.serve_slowly(
        &format!("/download/v{OFFERED}/picoguard-{TARGET}"),
        big.clone(),
        16 * 1024,
        Duration::from_millis(25),
    );
    serve_release_small_files(&site.release, &files);

    assert_eq!(
        site.send(post("/api/update", UPDATE_BODY)).await.status,
        202
    );
    let mut sizes = Vec::new();
    let mut early = false;
    let update = until_status(&site, "waiting", |update| {
        match update["install"]["state"].as_str() {
            Some("checking") => early = true,
            Some("downloading") => {
                early = true;
                sizes.push(update["install"]["bytes"].as_u64().unwrap());
            }
            _ => {}
        }

        update["install"]["state"] == "waiting"
    })
    .await;

    assert!(early, "neither checking nor downloading was seen");
    assert!(
        sizes.windows(2).any(|pair| pair[1] > pair[0]),
        "the bytes did not grow: {sizes:?}"
    );
    assert_eq!(update["install"]["version"], OFFERED);

    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    without_credentials(&mut config);
    let open = site_with(config, RELEASE).await;
    open.updates.show(Some(offered()));
    open.stager.start(OFFERED).unwrap();

    let update = until_status(&open, "waiting", |update| {
        update["install"]["state"] == "waiting"
    })
    .await;

    assert_eq!(update["can_install"], false);
    assert_eq!(update["install"]["version"], OFFERED);
}

fn serve_release_small_files(server: &ListServer, files: &Files) {
    let base = format!("/download/v{OFFERED}");
    server.serve_bytes(&format!("{base}/SHA256SUMS"), files.sums.clone());
    server.serve_bytes(&format!("{base}/SHA256SUMS.sig"), files.signature.clone());
}

#[tokio::test]
async fn a_hanging_download_holds_up_neither_dns_nor_the_page() {
    let (site, _upstream) = update_site(RELEASE).await;
    site.release.serve_slowly(
        &format!("/download/v{OFFERED}/picoguard-{TARGET}"),
        release_binary(),
        1024,
        Duration::from_secs(30),
    );

    assert_eq!(
        site.send(post("/api/update", UPDATE_BODY)).await.status,
        202
    );
    until_status(&site, "downloading", |update| {
        update["install"]["state"] == "downloading"
    })
    .await;

    let answers = async {
        ask(&site.dns, "ok.example.", RecordType::A).await;
        site.send(get("/api/status")).await
    };
    let status = tokio::time::timeout(Duration::from_secs(2), answers)
        .await
        .expect("DNS and the page answer while the download hangs");

    assert_eq!(status.status, 200);
}

fn addresses(reply: &hickory_proto::op::Message) -> Vec<String> {
    reply
        .answers
        .iter()
        .map(|record| record.data.to_string())
        .collect()
}

fn rule_body(name: &str, action: &str) -> String {
    serde_json::json!({ "name": name, "action": action }).to_string()
}

fn remove_body(name: &str) -> String {
    serde_json::json!({ "name": name }).to_string()
}

#[tokio::test]
async fn a_block_answers_the_next_query_with_the_null_ip_even_from_the_cache() {
    let (site, upstream) = plain_site().await;
    let before = ask(&site.dns, "www.example.org.", RecordType::A).await;
    assert_eq!(addresses(&before), ["9.9.9.9"]);
    let asked = upstream.count();

    let reply = site
        .send(post("/api/rules", &rule_body(" Example.ORG. ", "block")))
        .await;

    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.body,
        "{\"rules\":[{\"name\":\"example.org\",\"action\":\"block\"}],\"config_rules\":[\"||ads.example^\"],\"max\":500}"
    );
    for name in ["www.example.org.", "example.org."] {
        let after = ask(&site.dns, name, RecordType::A).await;
        assert_eq!(addresses(&after), ["0.0.0.0"], "{name}");
    }

    assert_eq!(upstream.count(), asked, "the cached reply was judged again");
}

#[tokio::test]
async fn an_allow_lets_a_list_blocked_name_resolve() {
    let (site, _upstream) = plain_site().await;
    let blocked = ask(&site.dns, "ads.example.", RecordType::A).await;
    assert_eq!(addresses(&blocked), ["0.0.0.0"]);

    let reply = site
        .send(post("/api/rules", &rule_body("ads.example", "allow")))
        .await;

    assert_eq!(reply.status, 200);
    let allowed = ask(&site.dns, "ads.example.", RecordType::A).await;
    assert_eq!(addresses(&allowed), ["9.9.9.9"]);
}

#[tokio::test]
async fn get_lists_page_rules_in_order_with_config_rules_and_remove_restores() {
    let (site, _upstream) = plain_site().await;
    for (name, action) in [
        ("a.example", "block"),
        ("b.example", "allow"),
        ("c.example", "block"),
    ] {
        let reply = site
            .send(post("/api/rules", &rule_body(name, action)))
            .await;
        assert_eq!(reply.status, 200, "{name}");
    }

    let listed = site.send(get("/api/rules")).await;

    assert_eq!(listed.status, 200);
    assert_eq!(
        listed.json(),
        serde_json::json!({
            "rules": [
                {"name": "a.example", "action": "block"},
                {"name": "b.example", "action": "allow"},
                {"name": "c.example", "action": "block"},
            ],
            "config_rules": ["||ads.example^"],
            "max": 500,
        })
    );

    let removed = site
        .send(post("/api/rules/remove", &remove_body("b.example")))
        .await;

    assert_eq!(removed.status, 200);
    assert_eq!(
        removed.json()["rules"],
        serde_json::json!([
            {"name": "a.example", "action": "block"},
            {"name": "c.example", "action": "block"},
        ])
    );

    let again = site
        .send(post("/api/rules/remove", &remove_body("b.example")))
        .await;

    assert_eq!(again.status, 404);
    assert_eq!(again.body, "{\"error\":\"no such rule\"}");
}

#[tokio::test]
async fn a_page_allow_beats_important_blocks_and_answer_checks() {
    let upstream = fake_upstream(|query| {
        let owner = query.queries[0].name().to_string();
        let answers = if owner == "cloaked.example." {
            vec![
                hickory_proto::rr::Record::from_rdata(
                    name("cloaked.example."),
                    300,
                    hickory_proto::rr::RData::CNAME(hickory_proto::rr::rdata::CNAME(name(
                        "cdn.tracker.example.",
                    ))),
                ),
                a_record("cdn.tracker.example.", 300, [9, 9, 9, 9]),
            ]
        } else {
            vec![a_record(&owner, 300, [9, 9, 9, 9])]
        };

        vec![(Duration::ZERO, reply_to(query, answers))]
    })
    .await;
    let mut config = local_config(&upstream);
    config.rules = vec![
        "||tracker.example^".to_string(),
        "||imp.example^$important".to_string(),
        "@@||cfg.example^".to_string(),
    ]
    .into();
    let site = site(config).await;
    let cloaked = ask(&site.dns, "cloaked.example.", RecordType::A).await;
    assert_eq!(
        addresses(&cloaked),
        ["0.0.0.0"],
        "blocked through its answer"
    );

    for (name, action) in [
        ("cloaked.example", "allow"),
        ("imp.example", "allow"),
        ("cfg.example", "block"),
    ] {
        let reply = site
            .send(post("/api/rules", &rule_body(name, action)))
            .await;
        assert_eq!(reply.status, 200, "{name}");
    }

    let cloaked = ask(&site.dns, "cloaked.example.", RecordType::A).await;
    assert_eq!(addresses(&cloaked), ["cdn.tracker.example.", "9.9.9.9"]);
    let important = ask(&site.dns, "imp.example.", RecordType::A).await;
    assert_eq!(addresses(&important), ["9.9.9.9"]);
    let allowed_by_config = ask(&site.dns, "cfg.example.", RecordType::A).await;
    assert_eq!(addresses(&allowed_by_config), ["0.0.0.0"]);
}

const NOT_A_DOMAIN_NAME: &str = "{\"error\":\"not a domain name\"}";

#[tokio::test]
async fn bad_names_and_bodies_are_400_and_the_501st_name_is_409() {
    let (site, _upstream) = plain_site().await;
    let too_long = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(63),
        "b".repeat(62)
    );
    let long_label = format!("{}.example", "a".repeat(64));

    for bad in [
        "a",
        "-x.com",
        &too_long,
        "x..y",
        &long_label,
        "",
        ".",
        "x.com..",
        "x.com^",
        "x.com^$badfilter",
        "x com",
        "%41.com",
        "*.x.com",
        "ünï.com",
    ] {
        let added = site
            .send(post("/api/rules", &rule_body(bad, "block")))
            .await;
        let removed = site
            .send(post("/api/rules/remove", &remove_body(bad)))
            .await;

        assert_eq!(added.status, 400, "{bad:?}");
        assert_eq!(added.body, NOT_A_DOMAIN_NAME, "{bad:?}");
        assert_eq!(removed.status, 400, "{bad:?}");
        assert_eq!(removed.body, NOT_A_DOMAIN_NAME, "{bad:?}");
    }

    for body in [
        "{\"name\":\"x.com\"}",
        "{\"name\":\"x.com\",\"action\":\"drop\"}",
        "[\"x.com\",\"block\"]",
        "{\"name\":\"x.com\",\"action\":\"block\",\"extra\":1}",
    ] {
        let reply = site.send(post("/api/rules", body)).await;

        assert_eq!(reply.status, 400, "{body}");
        assert_eq!(
            reply.json()["error"],
            "send {\"name\": \"...\", \"action\": \"block\" or \"allow\"}",
            "{body}"
        );
    }

    for body in ["[\"x.com\"]", "{\"name\":\"x.com\",\"extra\":1}", "{}"] {
        let reply = site.send(post("/api/rules/remove", body)).await;

        assert_eq!(reply.status, 400, "{body}");
        assert_eq!(reply.json()["error"], "send {\"name\": \"...\"}", "{body}");
    }

    assert!(no_page_rules(&site).await);

    for index in 0..500 {
        site.control
            .add_button_rule(&format!("name{index}.example"), Action::Block)
            .await
            .unwrap();
    }

    let full = site
        .send(post("/api/rules", &rule_body("name500.example", "block")))
        .await;
    let replaced = site
        .send(post("/api/rules", &rule_body("name1.example", "allow")))
        .await;

    assert_eq!(full.status, 409);
    assert_eq!(
        full.body,
        "{\"error\":\"too many rules (500); remove some first\"}"
    );
    assert_eq!(replaced.status, 200);
    assert_eq!(replaced.json()["rules"][1]["action"], "allow");
}

#[tokio::test]
async fn explain_answers_list_and_rule_and_ignores_pause() {
    let (site, _upstream) = plain_site().await;

    let config_rule = site.send(get("/api/explain?name=Ads.Example.")).await;

    assert_eq!(config_rule.status, 200);
    assert_eq!(
        config_rule.body,
        "{\"name\":\"ads.example\",\"decision\":\"blocked\",\"list\":\"config rules\",\"rule\":\"||ads.example^\"}"
    );

    let added = site
        .send(post("/api/rules", &rule_body("b.example", "block")))
        .await;
    assert_eq!(added.status, 200);
    let page_rule = site.send(get("/api/explain?name=b.example")).await.json();

    assert_eq!(page_rule["decision"], "blocked");
    assert_eq!(page_rule["list"], "your rules");
    assert_eq!(page_rule["rule"], "||b.example^$important");

    let none = site
        .send(get("/api/explain?name=other.example"))
        .await
        .json();

    assert_eq!(
        none,
        serde_json::json!({
            "name": "other.example",
            "decision": "none",
            "list": null,
            "rule": null,
        })
    );

    let paused = site.send(post("/api/pause", "{\"minutes\": 5}")).await;
    assert_eq!(paused.status, 200);
    let while_paused = site.send(get("/api/explain?name=ads.example")).await.json();

    assert_eq!(while_paused["decision"], "blocked");

    for query in ["?name=a", "?name=x%2Ecom", "", "?other=ads.example"] {
        let reply = site.send(get(&format!("/api/explain{query}"))).await;

        assert_eq!(reply.status, 400, "{query}");
        assert_eq!(reply.body, NOT_A_DOMAIN_NAME, "{query}");
    }
}

#[tokio::test]
async fn a_change_while_paused_is_kept_and_applies_on_resume() {
    let (site, _upstream) = plain_site().await;
    let paused = site.send(post("/api/pause", "{\"minutes\": 5}")).await;
    assert_eq!(paused.status, 200);

    let added = site
        .send(post("/api/rules", &rule_body("b.example", "block")))
        .await;

    assert_eq!(added.status, 200);
    let during = ask(&site.dns, "b.example.", RecordType::A).await;
    assert_eq!(addresses(&during), ["9.9.9.9"]);

    let resumed = site.send(post("/api/resume", "")).await;
    assert_eq!(resumed.status, 200);
    let after = ask(&site.dns, "b.example.", RecordType::A).await;
    assert_eq!(addresses(&after), ["0.0.0.0"]);
}

fn saved_settings(site: &Site) -> Option<Value> {
    let text = std::fs::read_to_string(site.state.join(settings::FILE_NAME)).ok()?;

    Some(serde_json::from_str(&text).unwrap())
}

#[tokio::test]
async fn a_rule_from_the_page_is_saved_for_the_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let (site, _upstream) = plain_site().await;

    let reply = site
        .send(post("/api/rules", &rule_body("saved.example", "block")))
        .await;

    assert_eq!(reply.status, 200);
    assert_eq!(
        saved_settings(&site).unwrap(),
        serde_json::json!({
            "version": 1,
            "page_rules": [{"name": "saved.example", "action": "block"}],
        })
    );
    let mode = std::fs::metadata(site.state.join(settings::FILE_NAME))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[tokio::test]
async fn a_rule_that_cannot_be_saved_answers_503_and_changes_nothing() {
    let (site, _upstream) = plain_site().await;
    std::fs::remove_dir_all(&site.state).unwrap();

    let reply = site
        .send(post("/api/rules", &rule_body("kept.example", "block")))
        .await;

    assert_eq!(reply.status, 503, "{}", reply.body);
    assert!(
        reply.json()["error"]
            .as_str()
            .unwrap()
            .starts_with("could not save settings: "),
        "{}",
        reply.body
    );
    assert!(no_page_rules(&site).await);
    let answer = ask(&site.dns, "kept.example.", RecordType::A).await;
    assert_eq!(addresses(&answer), ["9.9.9.9"]);
}

#[tokio::test]
async fn a_client_that_leaves_during_a_save_leaves_the_file_and_the_rules_in_agreement() {
    let (site, _upstream) = plain_site().await;
    // The save says when its file is written, then waits to be let rename it. Every wait is
    // bounded, and a failed test drops `release`, which lets the save go on at once.
    let (reached, reached_here) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let released = Mutex::new(released);
    site.control.saved().run_before_rename(move || {
        let _ = reached.send(());
        let _ = released
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(10));
    });
    let request = post("/api/rules", &rule_body("left.example", "block")).signed_in(ADMIN);
    let mut stream = TcpStream::connect(site.web).await.unwrap();
    stream.write_all(&request.bytes(site.web)).await.unwrap();

    tokio::task::spawn_blocking(move || reached_here.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap()
        .expect("the save never reached the rename");
    drop(stream);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let before = ask(&site.dns, "left.example.", RecordType::A).await;
    assert_eq!(
        addresses(&before),
        ["9.9.9.9"],
        "in force before it was saved"
    );
    release.send(()).unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    while no_page_rules(&site).await {
        assert!(Instant::now() < deadline, "the change was dropped");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let in_force = site.send(get("/api/rules")).await.json()["rules"].clone();
    assert_eq!(
        in_force,
        serde_json::json!([{"name": "left.example", "action": "block"}])
    );
    assert_eq!(saved_settings(&site).unwrap()["page_rules"], in_force);
    let answer = ask(&site.dns, "left.example.", RecordType::A).await;
    assert_eq!(addresses(&answer), ["0.0.0.0"]);
}

/// A site with a password whose state folder holds `saved` before it starts.
async fn site_with_saved(saved: &str) -> (Site, common::harness::FakeUpstream) {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let kind = SiteKind {
        build: Build::current(),
        installer: true,
        release_target: true,
    };
    let site = site_saving(local_config(&upstream), kind, Some(saved)).await;

    (site, upstream)
}

#[tokio::test]
async fn the_settings_show_each_value_with_where_it_comes_from_and_no_web_value() {
    let (site, upstream) = site_with_saved(
        "{\"version\": 1, \"safe_search\": true, \"stats\": {\"retention_days\": 90}, \"cache\": {\"max_entries\": 500, \
         \"max_bytes\": 1048576, \"min_ttl\": 5, \"max_ttl\": 600, \"optimistic\": false}}",
    )
    .await;

    let reply = site.send(get("/api/settings")).await;

    assert_eq!(reply.status, 200);
    let file = site.state.join(settings::FILE_NAME);
    assert_eq!(
        reply.json(),
        serde_json::json!({
            "file": file.display().to_string(),
            "error": null,
            "can_save": true,
            "upstream": {
                "servers": [format!("udp://{}", upstream.address)],
                "bootstrap": ["9.9.9.9", "1.1.1.1"],
                "from": "file",
            },
            "cache": {
                "max_entries": 500,
                "max_bytes": 1048576,
                "min_ttl": 5,
                "max_ttl": 600,
                "optimistic": false,
                "from": "page",
            },
            "rewrites": {"entries": [], "from": "file"},
            "safe_search": {"on": true, "from": "page"},
            "services": {"block": [], "from": "file"},
            "stats": {"retention_days": 90, "from": "page"},
            "memory": {
                "estimate_bytes": site.control.memory().estimate_bytes,
                "budget_bytes": 48 * 1024 * 1024,
            },
        })
    );
    for secret in ["s3cret", "admin", "password", "user"] {
        assert!(!reply.body.contains(secret), "{secret}: {}", reply.body);
    }
}

#[tokio::test]
async fn the_settings_say_why_the_saved_file_is_not_used_until_a_save_replaces_it() {
    let (site, _upstream) = site_with_saved("{\"version\": 1, \"safe_search\": tru").await;

    let reply = site.send(get("/api/settings")).await.json();

    assert!(
        reply["error"]
            .as_str()
            .is_some_and(|error| error.contains("EOF while parsing")),
        "{reply}"
    );
    assert_eq!(
        reply["safe_search"],
        serde_json::json!({"on": false, "from": "file"})
    );

    let added = site
        .send(post("/api/rules", &rule_body("ads.example", "allow")))
        .await;

    assert_eq!(added.status, 200);
    let reply = site.send(get("/api/settings")).await.json();
    assert_eq!(reply["error"], Value::Null);
    assert_eq!(
        saved_settings(&site).unwrap(),
        serde_json::json!({
            "version": 1,
            "page_rules": [{"name": "ads.example", "action": "allow"}],
        })
    );
}

#[tokio::test]
async fn a_settings_change_that_is_not_valid_is_refused_and_nothing_is_written() {
    let (site, _upstream) = plain_site().await;

    for body in [
        "{\"services\": [\"a b\"]}",
        "{\"services\": [\"tiktok\", \"tiktok\"]}",
        "{\"services\": \"tiktok\"}",
        "{\"web\": {}}",
        "{\"page_rules\": []}",
        "{\"lists\": null}",
        "{\"safe_search\": \"yes\"}",
        "[]",
        "",
    ] {
        let reply = site.send(post("/api/settings", body)).await;

        assert_eq!(reply.status, 400, "{body}: {}", reply.body);
    }

    assert!(saved_settings(&site).is_none());
}

#[tokio::test]
async fn only_the_settings_route_takes_a_body_of_64_kib() {
    let (site, _upstream) = plain_site().await;
    let padded = |length: usize| format!("{{}}{}", " ".repeat(length - 2));

    for length in [2048, 64 * 1024] {
        let reply = site.send(post("/api/settings", &padded(length))).await;

        assert_eq!(reply.status, 200, "{length}: {}", reply.body);
    }

    let over = site
        .send(post("/api/settings", &padded(64 * 1024 + 1)))
        .await;
    let chunked = padded(64 * 1024 + 1);
    let over_unannounced = site
        .send(Request {
            headers: vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ],
            body: format!("{:x}\r\n{chunked}\r\n0\r\n\r\n", chunked.len()).into_bytes(),
            ..post("/api/settings", "")
        })
        .await;
    let rule = site
        .send(post(
            "/api/rules",
            &format!(
                "{{\"name\": \"a.example\", \"action\": \"block\"}}{}",
                " ".repeat(1024)
            ),
        ))
        .await;

    for reply in [&over, &over_unannounced] {
        assert_eq!(reply.status, 413);
        assert_eq!(reply.json()["error"], "the body is limited to 64 KiB");
    }

    assert_eq!(rule.status, 413);
    assert_eq!(rule.json()["error"], "the body is limited to 1 KiB");
    assert!(no_page_rules(&site).await);
}

fn rewrite_body(entries: &[(&str, &str)]) -> String {
    let entries: Vec<Value> = entries
        .iter()
        .map(|(name, answer)| serde_json::json!({"name": name, "answer": answer}))
        .collect();

    serde_json::json!({ "rewrites": entries }).to_string()
}

#[tokio::test]
async fn rewrites_and_safe_search_apply_at_once_and_a_reset_goes_back_to_the_config_file() {
    let (site, upstream) = plain_site().await;
    let body = serde_json::json!({
        "rewrites": [
            {"name": " NAS.lan. ", "answer": "192.168.1.10"},
            {"name": "*.NAS.lan", "answer": "FD00:0::10"},
        ],
        "safe_search": true,
    })
    .to_string();

    let changed = site.send(post("/api/settings", &body)).await;

    assert_eq!(changed.status, 200, "{}", changed.body);
    let kept = serde_json::json!([
        {"name": "nas.lan", "answer": "192.168.1.10"},
        {"name": "*.nas.lan", "answer": "fd00::10"},
    ]);
    assert_eq!(
        changed.json()["rewrites"],
        serde_json::json!({"entries": kept, "from": "page"})
    );
    assert_eq!(
        changed.json()["safe_search"],
        serde_json::json!({"on": true, "from": "page"})
    );
    let saved = saved_settings(&site).unwrap();
    assert_eq!(saved["rewrites"], kept);
    assert_eq!(saved["safe_search"], true);
    let answer = ask(&site.dns, "nas.lan.", RecordType::A).await;
    assert_eq!(addresses(&answer), ["192.168.1.10"]);
    let answer = ask(&site.dns, "tv.nas.lan.", RecordType::AAAA).await;
    assert_eq!(addresses(&answer), ["fd00::10"]);
    let answer = ask(&site.dns, "www.google.com.", RecordType::A).await;
    assert_eq!(addresses(&answer), ["9.9.9.9"]);
    let asked: Vec<String> = upstream
        .received()
        .iter()
        .map(|query| query.queries[0].name().to_string())
        .collect();
    assert_eq!(asked, ["forcesafesearch.google.com."]);

    let explained = site.send(get("/api/explain?name=nas.lan")).await.json();
    assert_eq!(
        explained,
        serde_json::json!({"name": "nas.lan", "decision": "rewritten", "list": "your rewrites",
                           "rule": "rewritten to 192.168.1.10 (your rewrite)"})
    );
    let explained = site.send(get("/api/explain?name=google.de")).await.json();
    assert_eq!(explained["list"], "SafeSearch");
    assert_eq!(
        explained["rule"],
        "rewritten to forcesafesearch.google.com (SafeSearch)"
    );

    let reset = site
        .send(post(
            "/api/settings",
            "{\"rewrites\": null, \"safe_search\": null}",
        ))
        .await;

    assert_eq!(reset.status, 200, "{}", reset.body);
    assert_eq!(reset.json()["rewrites"]["from"], "file");
    assert_eq!(reset.json()["safe_search"]["on"], false);
    assert_eq!(
        saved_settings(&site).unwrap(),
        serde_json::json!({"version": 1})
    );
    let answer = ask(&site.dns, "nas.lan.", RecordType::A).await;
    assert_eq!(addresses(&answer), ["9.9.9.9"]);
    let explained = site.send(get("/api/explain?name=google.de")).await.json();
    assert_eq!(explained["decision"], "none");
}

#[tokio::test]
async fn rewrites_that_cannot_be_used_are_refused_with_the_reason_and_nothing_changes() {
    let (site, _upstream) = plain_site().await;
    let too_many: Vec<(String, &str)> = (0..1001)
        .map(|index| (format!("n{index}.lan"), "10.0.0.1"))
        .collect();
    let too_many: Vec<(&str, &str)> = too_many
        .iter()
        .map(|(name, answer)| (name.as_str(), *answer))
        .collect();

    for (body, expected) in [
        (
            rewrite_body(&[("nas", "10.0.0.1")]),
            "rewrites[0].name must be a domain name",
        ),
        (
            rewrite_body(&[("nas.lan", "nas.lan")]),
            "rewrites[0] points nas.lan at itself",
        ),
        (
            rewrite_body(&[("a.lan", "10.0.0.1"), ("a.lan", "b.lan")]),
            "rewrites[1]: a.lan has addresses and a name",
        ),
        (
            rewrite_body(&[("a.lan", "192.168.001.10")]),
            "rewrites[0].answer must be an IP address or a domain name",
        ),
        (rewrite_body(&too_many), "rewrites: at most 1000 entries"),
    ] {
        let reply = site.send(post("/api/settings", &body)).await;

        assert_eq!(reply.status, 400, "{expected}: {}", reply.body);
        assert!(
            reply.json()["error"].as_str().unwrap().contains(expected),
            "{expected}: {}",
            reply.body
        );
    }

    for body in [
        "{\"rewrites\": [{\"name\": \"a.lan\"}]}",
        "{\"rewrites\": [{\"name\": \"a.lan\", \"answer\": \"10.0.0.1\", \"ttl\": 5}]}",
        "{\"safe_search\": \"yes\"}",
    ] {
        let reply = site.send(post("/api/settings", body)).await;

        assert_eq!(reply.status, 400, "{body}: {}", reply.body);
    }

    assert!(saved_settings(&site).is_none());
    let settings = site.send(get("/api/settings")).await.json();
    assert_eq!(settings["rewrites"]["from"], "file");
    let answer = ask(&site.dns, "a.lan.", RecordType::A).await;
    assert_eq!(addresses(&answer), ["9.9.9.9"]);
}

fn upstream_body(servers: &[String]) -> String {
    serde_json::json!({"upstream": {"servers": servers, "bootstrap": ["9.9.9.9"]}}).to_string()
}

fn udp(upstream: &common::harness::FakeUpstream) -> String {
    format!("udp://{}", upstream.address)
}

fn upstream_counts(status: &Value) -> Vec<(String, u64)> {
    upstream_entries(status)
        .iter()
        .map(|entry| {
            (
                entry["label"].as_str().unwrap().to_string(),
                entry["answered"].as_u64().unwrap(),
            )
        })
        .collect()
}

#[tokio::test]
async fn new_upstream_servers_answer_at_once_and_a_reset_goes_back_to_the_config_file() {
    let (site, first) = plain_site().await;
    let second = answering_upstream([8, 8, 8, 8], Duration::ZERO).await;
    let before = ask(&site.dns, "one.example.", RecordType::A).await;
    assert_eq!(addresses(&before), ["9.9.9.9"]);

    let changed = site
        .send(post(
            "/api/settings",
            &upstream_body(&[udp(&second), udp(&first)]),
        ))
        .await;

    assert_eq!(changed.status, 200, "{}", changed.body);
    assert_eq!(
        changed.json()["upstream"],
        serde_json::json!({
            "servers": [udp(&second), udp(&first)],
            "bootstrap": ["9.9.9.9"],
            "from": "page",
        })
    );
    assert_eq!(
        saved_settings(&site).unwrap()["upstream"],
        serde_json::json!({"servers": [udp(&second), udp(&first)], "bootstrap": ["9.9.9.9"]})
    );
    let status = site.send(get("/api/status")).await.json();
    assert_eq!(
        upstream_counts(&status),
        [(udp(&second), 0), (udp(&first), 1)],
        "a server kept keeps its counts"
    );
    for index in 0..20 {
        let reply = ask(&site.dns, &format!("n{index}.example."), RecordType::A).await;
        assert_eq!(reply.response_code, ResponseCode::NoError);
    }
    assert!(second.count() > 0, "the new server is used");

    let reset = site
        .send(post("/api/settings", "{\"upstream\": null}"))
        .await;

    assert_eq!(reset.status, 200, "{}", reset.body);
    assert_eq!(reset.json()["upstream"]["from"], "file");
    assert_eq!(
        saved_settings(&site).unwrap(),
        serde_json::json!({"version": 1})
    );
    let asked = second.count();
    for index in 0..5 {
        let reply = ask(&site.dns, &format!("back{index}.example."), RecordType::A).await;
        assert_eq!(addresses(&reply), ["9.9.9.9"]);
    }
    assert_eq!(second.count(), asked);
}

#[tokio::test]
async fn a_server_that_cannot_be_used_is_refused_with_the_reason_and_nothing_changes() {
    let (site, first) = plain_site().await;

    for (body, expected) in [
        (upstream_body(&[]), "upstream.servers: 1 to 8 servers"),
        (
            upstream_body(&["9.9.9.9".to_string()]),
            "upstream.servers[0] must start with one of",
        ),
        (
            serde_json::json!({"upstream": {"servers": [udp(&first)], "bootstrap": ["x"]}})
                .to_string(),
            "",
        ),
        (
            serde_json::json!({"cache": {"max_entries": 100, "max_bytes": 1024, "min_ttl": 0,
                                         "max_ttl": 60, "optimistic": true}})
            .to_string(),
            "cache.max_bytes must be from 262144 to 16777216",
        ),
    ] {
        let reply = site.send(post("/api/settings", &body)).await;

        assert_eq!(reply.status, 400, "{body}: {}", reply.body);
        assert!(
            reply.json()["error"].as_str().unwrap().contains(expected),
            "{body}: {}",
            reply.body
        );
    }

    assert!(saved_settings(&site).is_none());
    let settings = site.send(get("/api/settings")).await.json();
    assert_eq!(settings["upstream"]["from"], "file");
    assert_eq!(settings["cache"]["from"], "file");
}

fn cache_of_size(max_bytes: usize) -> String {
    serde_json::json!({"cache": {"max_entries": 10000, "max_bytes": max_bytes, "min_ttl": 0,
                                 "max_ttl": 86400, "optimistic": true}})
    .to_string()
}

#[tokio::test]
async fn a_larger_cache_that_would_pass_the_memory_budget_is_refused_and_a_smaller_one_is_not() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let probe = site(local_config(&upstream)).await;
    let estimate = probe.control.memory().estimate_bytes;
    let mut config = local_config(&upstream);
    // Room for the default cache and about 2 MiB more.
    config.limits.memory_mb = estimate / (1024 * 1024) + 2;
    let site = site(config).await;

    let larger = site
        .send(post("/api/settings", &cache_of_size(16 * 1024 * 1024)))
        .await;

    assert_eq!(larger.status, 400, "{}", larger.body);
    let error = larger.json()["error"].as_str().unwrap().to_string();
    assert!(
        error
            .starts_with("a cache of 16.0 MB would pass the memory budget: the estimate would be "),
        "{error}"
    );
    assert!(saved_settings(&site).is_none());
    let memory = site.send(get("/api/settings")).await.json()["memory"].clone();
    assert_eq!(memory["estimate_bytes"], estimate);

    let smaller = site
        .send(post("/api/settings", &cache_of_size(1024 * 1024)))
        .await;

    assert_eq!(smaller.status, 200, "{}", smaller.body);
    let memory = &smaller.json()["memory"];
    assert!(memory["estimate_bytes"].as_u64().unwrap() < estimate as u64);
    assert!(memory["estimate_bytes"].as_u64() <= memory["budget_bytes"].as_u64());
}

#[tokio::test]
async fn the_file_is_written_only_when_a_setting_in_force_changes() {
    let (site, first) = plain_site().await;
    let upstreams = upstream_body(&[udp(&first)]);
    let rewrites = rewrite_body(&[("nas.lan", "192.168.1.10")]);
    let normalized_rewrites = rewrite_body(&[("NAS.lan.", " 192.168.1.10")]);
    let file = site.state.join(settings::FILE_NAME);

    // Nothing is in force twice: the second round sets rewrites, so a reset of them would write.
    for (set, unchanged) in [
        (
            &upstreams,
            vec![
                upstreams.as_str(),
                "{}",
                "{\"cache\": null}",
                "{\"rewrites\": null, \"safe_search\": null, \"services\": null}",
            ],
        ),
        (
            &rewrites,
            vec![
                rewrites.as_str(),
                normalized_rewrites.as_str(),
                "{\"safe_search\": null}",
            ],
        ),
    ] {
        assert_eq!(site.send(post("/api/settings", set)).await.status, 200);
        assert!(file.exists());
        std::fs::remove_file(&file).unwrap();

        for body in unchanged {
            let reply = site.send(post("/api/settings", body)).await;

            assert_eq!(reply.status, 200, "{body}: {}", reply.body);
            assert!(!file.exists(), "{body} wrote the file");
        }
    }
}

/// Upstreams that answer after a while, so queries are still waiting when the servers change.
async fn slow_upstreams() -> [common::harness::FakeUpstream; 2] {
    [
        answering_upstream([1, 1, 1, 1], Duration::from_millis(1500)).await,
        answering_upstream([2, 2, 2, 2], Duration::from_millis(1500)).await,
    ]
}

fn ask_later(site: &Site, name: String) -> tokio::task::JoinHandle<hickory_proto::op::Message> {
    let dns = site.dns.clone();

    tokio::spawn(async move { ask(&dns, &name, RecordType::A).await })
}

#[tokio::test]
async fn queries_waiting_through_upstream_changes_all_get_their_answer() {
    let upstreams = slow_upstreams().await;
    let mut config = local_config(&upstreams[0]);
    // A busy test machine must not turn a slow answer into a timeout.
    config.upstream.timeout_ms = 6000;
    let site = site(config).await;
    let generations = || site.dns.pipeline.upstreams().generations();
    let mut waiting = Vec::new();

    for round in 0..2 {
        waiting.extend((0..5).map(|index| ask_later(&site, format!("r{round}-{index}.example."))));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let next = upstream_body(&[udp(&upstreams[(round + 1) % 2])]);

        assert_eq!(site.send(post("/api/settings", &next)).await.status, 200);
    }

    assert_eq!(generations(), 3);
    let refused = site
        .send(post("/api/settings", &upstream_body(&[udp(&upstreams[1])])))
        .await;
    assert_eq!(refused.status, 409, "{}", refused.body);
    assert_eq!(
        refused.json()["error"],
        "the previous upstream change is still finishing; try again in a few seconds"
    );

    for round in 2..8 {
        waiting.extend((0..3).map(|index| ask_later(&site, format!("r{round}-{index}.example."))));
        let next = upstream_body(&[udp(&upstreams[round % 2])]);
        loop {
            let reply = site.send(post("/api/settings", &next)).await;
            assert!(generations() <= 3);
            if reply.status == 200 {
                break;
            }

            assert_eq!(reply.status, 409, "{}", reply.body);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    let total = waiting.len();
    for query in waiting {
        let reply = query.await.unwrap();
        assert_eq!(reply.response_code, ResponseCode::NoError);
        assert_eq!(reply.answers.len(), 1);
    }

    assert_eq!(total, 28);
    let deadline = Instant::now() + Duration::from_secs(3);
    while generations() > 1 {
        assert!(Instant::now() < deadline, "replaced pools are still alive");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn cache_body(min_ttl: u32) -> String {
    serde_json::json!({"cache": {"max_entries": 500, "max_bytes": 1048576, "min_ttl": min_ttl,
                                  "max_ttl": 86400, "optimistic": false}})
    .to_string()
}

#[tokio::test]
async fn a_cache_change_empties_the_cache_and_its_ttls_apply_at_once() {
    let (site, upstream) = plain_site().await;
    let first = ask(&site.dns, "ttl.example.", RecordType::A).await;
    assert_eq!(first.answers[0].ttl, 300);
    assert_eq!(site.dns.pipeline.cache_size().entries, 1);

    let changed = site.send(post("/api/settings", &cache_body(900))).await;

    assert_eq!(changed.status, 200, "{}", changed.body);
    assert_eq!(
        changed.json()["cache"],
        serde_json::json!({"max_entries": 500, "max_bytes": 1048576, "min_ttl": 900,
                           "max_ttl": 86400, "optimistic": false, "from": "page"})
    );
    assert_eq!(saved_settings(&site).unwrap()["cache"]["min_ttl"], 900);
    assert_eq!(site.dns.pipeline.cache_size().entries, 0);
    let asked = upstream.count();
    let again = ask(&site.dns, "ttl.example.", RecordType::A).await;
    assert_eq!(upstream.count(), asked + 1, "the old answer is gone");
    assert_eq!(again.answers[0].ttl, 900);

    let reset = site.send(post("/api/settings", "{\"cache\": null}")).await;

    assert_eq!(reset.status, 200, "{}", reset.body);
    assert_eq!(reset.json()["cache"]["from"], "file");
    assert_eq!(site.dns.pipeline.cache_size().entries, 0);
    let after = ask(&site.dns, "ttl.example.", RecordType::A).await;
    assert_eq!(after.answers[0].ttl, 300);
}

#[tokio::test]
async fn a_settings_change_that_cannot_be_saved_answers_503_and_keeps_what_is_in_force() {
    let (site, first) = plain_site().await;
    let second = answering_upstream([8, 8, 8, 8], Duration::ZERO).await;
    ask(&site.dns, "kept.example.", RecordType::A).await;
    std::fs::remove_dir_all(&site.state).unwrap();

    let body = serde_json::json!({
        "upstream": {"servers": [udp(&second)], "bootstrap": []},
        "cache": {"max_entries": 10, "max_bytes": 262144, "min_ttl": 0, "max_ttl": 60,
                  "optimistic": false},
    })
    .to_string();
    let reply = site.send(post("/api/settings", &body)).await;

    assert_eq!(reply.status, 503, "{}", reply.body);
    assert_eq!(site.dns.pipeline.cache_size().entries, 1);
    let settings = site.send(get("/api/settings")).await.json();
    assert_eq!(
        settings["upstream"]["servers"],
        serde_json::json!([udp(&first)])
    );
    assert_eq!(settings["cache"]["from"], "file");
    let answer = ask(&site.dns, "other.example.", RecordType::A).await;
    assert_eq!(addresses(&answer), ["9.9.9.9"]);
    assert_eq!(second.count(), 0);
}

/// A site with no list of the config file, and a server for the lists the page adds.
async fn list_site(
    configure: impl FnOnce(&mut Config),
) -> (Site, ListServer, common::harness::FakeUpstream) {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    configure(&mut config);
    let site = site(config).await;

    (site, ListServer::start().await, upstream)
}

fn add_body(name: &str, url: &str) -> String {
    serde_json::json!({"role": "block", "name": name, "url": url, "refresh_hours": 12}).to_string()
}

/// `/api/lists` once the add in flight has ended.
async fn after_the_add(site: &Site) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let lists = site.send(get("/api/lists")).await.json();
        if lists["pending"]["state"] != "checking" {
            return lists;
        }

        assert!(Instant::now() < deadline, "the add never ended");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn a_list_added_from_the_page_is_checked_then_added_and_blocks() {
    let (site, server, _upstream) = list_site(|_| {}).await;
    server.serve("/list.txt", "||added.example^\n", None);
    server.set_delay(Duration::from_millis(300));
    let url = server.url("/list.txt");

    let reply = site
        .send(post("/api/lists/add", &add_body("Added", &url)))
        .await;

    assert_eq!(reply.status, 202, "{}", reply.body);
    assert_eq!(reply.json(), serde_json::json!({"list": "checking"}));
    let checking = site.send(get("/api/lists")).await.json();
    assert_eq!(
        checking["pending"],
        serde_json::json!({"kind": "blocklist", "name": "Added", "source": url, "state": "checking"})
    );
    let second = site
        .send(post(
            "/api/lists/add",
            &add_body("Second", &server.url("/b.txt")),
        ))
        .await;
    assert_eq!(second.status, 409, "{}", second.body);

    let lists = after_the_add(&site).await;

    assert_eq!(lists["pending"]["state"], "added");
    let row = &lists["lists"][0];
    assert_eq!(row["name"], "Added");
    assert_eq!(row["source"], url);
    assert_eq!(row["enabled"], true);
    assert_eq!(row["refresh_hours"], 12);
    assert_eq!(row["editable"], true);
    assert_eq!(row["from"], "page");
    assert_eq!(row["rules"], 1);
    assert!(row["heap_bytes"].as_u64().unwrap() > 0);
    let memory = &lists["memory"];
    assert!(memory["estimate_bytes"].as_u64() <= memory["budget_bytes"].as_u64());
    let answer = ask(&site.dns, "added.example.", RecordType::A).await;
    assert_eq!(addresses(&answer), ["0.0.0.0"]);
    assert_eq!(
        saved_settings(&site).unwrap()["lists"],
        serde_json::json!([{"role": "block", "name": "Added", "url": url, "refresh_hours": 12, "enabled": true}])
    );
}

#[tokio::test]
async fn an_add_that_would_pass_the_budget_or_cannot_be_downloaded_says_why_and_saves_nothing() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let estimate = site(local_config(&upstream))
        .await
        .control
        .memory()
        .estimate_bytes;
    let (site, server, _upstream) =
        list_site(|config| config.limits.memory_mb = estimate / (1024 * 1024) + 1).await;
    let big: String = (0..200_000)
        .map(|index| format!("||n{index}.example^\n"))
        .collect();
    server.serve("/big.txt", &big, None);
    server.fail("/gone.txt", 404);

    site.send(post(
        "/api/lists/add",
        &add_body("Big", &server.url("/big.txt")),
    ))
    .await;
    let refused = after_the_add(&site).await;
    site.send(post(
        "/api/lists/add",
        &add_body("Gone", &server.url("/gone.txt")),
    ))
    .await;
    let failed = after_the_add(&site).await;

    let refused = refused["pending"]["state"].as_str().unwrap().to_string();
    assert!(
        refused.starts_with("refused: Big needs more than ") && refused.contains(" MB left of "),
        "{refused}"
    );
    let failed = failed["pending"]["state"].as_str().unwrap().to_string();
    assert!(
        failed.starts_with("failed: Gone: ") && failed.contains("404"),
        "{failed}"
    );
    assert!(saved_settings(&site).is_none());
    assert_eq!(
        site.send(get("/api/lists")).await.json()["lists"],
        serde_json::json!([])
    );
}

#[tokio::test]
async fn a_list_change_from_the_page_never_sets_a_path_redirects_or_anything_unknown() {
    let local = scratch("web-e2e-path-list").join("mine.txt");
    std::fs::write(&local, "||mine.example^\n").unwrap();
    let path = local.clone();
    let (site, server, _upstream) = list_site(move |config| {
        config.lists = vec![ListConfig {
            name: Some("Mine".to_string()),
            path: Some(path),
            ..ListConfig::default()
        }];
    })
    .await;
    let url = server.url("/a.txt");

    for (body, status) in [
        (
            serde_json::json!({"role": "block", "url": url, "refresh_hours": 12, "allow_redirects": true}),
            400,
        ),
        (
            serde_json::json!({"role": "block", "path": "/etc/passwd", "refresh_hours": 12}),
            400,
        ),
        (
            serde_json::json!({"role": "block", "url": "file:///etc/passwd", "refresh_hours": 12}),
            400,
        ),
        (
            serde_json::json!({"role": "block", "url": url, "refresh_hours": 0}),
            400,
        ),
        (
            serde_json::json!({"role": "block", "url": url, "refresh_hours": 169}),
            400,
        ),
        (
            serde_json::json!({"role": "deny", "url": url, "refresh_hours": 12}),
            400,
        ),
    ] {
        let reply = site.send(post("/api/lists/add", &body.to_string())).await;

        assert_eq!(reply.status, status, "{body}: {}", reply.body);
    }

    let source = local.display().to_string();
    let edit = site
        .send(post(
            "/api/lists/edit",
            &serde_json::json!({"role": "block", "source": source, "enabled": false}).to_string(),
        ))
        .await;
    let remove = site
        .send(post(
            "/api/lists/remove",
            &serde_json::json!({"role": "block", "source": source}).to_string(),
        ))
        .await;
    let missing = site
        .send(post(
            "/api/lists/remove",
            &serde_json::json!({"role": "block", "source": url}).to_string(),
        ))
        .await;

    assert_eq!(edit.status, 409, "{}", edit.body);
    assert_eq!(remove.status, 409, "{}", remove.body);
    assert_eq!(missing.status, 404, "{}", missing.body);
    assert!(saved_settings(&site).is_none());
    let lists = site.send(get("/api/lists")).await.json();
    assert_eq!(lists["lists"][0]["editable"], false);
    assert_eq!(lists["lists"][0]["from"], "file");
    assert_eq!(server.requests(), 0);
}

#[tokio::test]
async fn a_list_name_from_the_page_is_at_most_100_characters_without_control_characters() {
    const REFUSED: &str = "a list name has at most 100 characters and no control characters";
    let (site, server, _upstream) = list_site(|_| {}).await;
    server.serve("/a.txt", "||a.example^\n", None);
    server.serve("/b.txt", "||b.example^\n", None);
    server.serve("/c.txt", "||c.example^\n", None);
    let (a, b, c) = (
        server.url("/a.txt"),
        server.url("/b.txt"),
        server.url("/c.txt"),
    );
    let at_the_limit = "\u{e9}".repeat(100);
    let bad_names = [
        "x".repeat(101),
        "\u{e9}".repeat(101),
        "in\nside".to_string(),
        "in\u{0}side".to_string(),
        "in\u{7f}side".to_string(),
        "tab\tinside".to_string(),
    ];

    for name in &bad_names {
        let reply = site.send(post("/api/lists/add", &add_body(name, &a))).await;

        assert_eq!(reply.status, 400, "{name:?}: {}", reply.body);
        assert!(reply.body.contains(REFUSED), "{}", reply.body);
    }

    assert_eq!(server.requests(), 0, "a refused add downloaded the list");
    assert!(saved_settings(&site).is_none());
    assert!(site.control.pending_list().is_none());

    site.send(post("/api/lists/add", &add_body(&at_the_limit, &a)))
        .await;
    let lists = after_the_add(&site).await;
    assert_eq!(lists["pending"]["state"], "added");
    assert_eq!(lists["lists"][0]["name"], at_the_limit.as_str());

    let edit = |source: &str, name: &str| {
        post(
            "/api/lists/edit",
            &serde_json::json!({"role": "block", "source": source, "name": name}).to_string(),
        )
    };
    for name in &bad_names {
        let reply = site.send(edit(&a, name)).await;

        assert_eq!(reply.status, 400, "{name:?}: {}", reply.body);
        assert!(reply.body.contains(REFUSED), "{}", reply.body);
    }

    let lists = site.send(get("/api/lists")).await.json();
    assert_eq!(lists["lists"][0]["name"], at_the_limit.as_str());
    assert_eq!(
        saved_settings(&site).unwrap()["lists"][0]["name"],
        at_the_limit.as_str()
    );

    let renamed = site.send(edit(&a, "  Renamed  ")).await;
    assert_eq!(renamed.status, 200, "{}", renamed.body);
    assert_eq!(renamed.json()["lists"][0]["name"], "Renamed");
    assert_eq!(
        saved_settings(&site).unwrap()["lists"][0]["name"],
        "Renamed"
    );

    let cleared = site.send(edit(&a, " \t ")).await;
    assert_eq!(cleared.status, 200, "{}", cleared.body);
    assert_eq!(cleared.json()["lists"][0]["name"], a.as_str());

    site.send(post("/api/lists/add", &add_body("   ", &b)))
        .await;
    assert_eq!(after_the_add(&site).await["pending"]["state"], "added");
    site.send(post("/api/lists/add", &add_body("  Padded  ", &c)))
        .await;
    let lists = after_the_add(&site).await;
    assert_eq!(lists["pending"]["state"], "added");
    let names: Vec<&str> = lists["lists"]
        .as_array()
        .unwrap()
        .iter()
        .map(|list| list["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, [a.as_str(), b.as_str(), "Padded"]);
}

#[tokio::test]
async fn a_list_url_from_the_page_has_no_user_name_or_password_but_may_hold_an_at_sign_later() {
    let (site, server, _upstream) = list_site(|_| {}).await;
    server.serve("/p@th/list.txt", "||path.example^\n", None);
    server.serve("/query.txt?token=a@b", "||query.example^\n", None);
    let host = server.url("/").trim_end_matches('/').to_string();
    let with = |userinfo: &str| host.replacen("://", &format!("://{userinfo}@"), 1) + "/list.txt";

    for url in [with("user:secret"), with("user"), with(":")] {
        let reply = site
            .send(post("/api/lists/add", &add_body("Private", &url)))
            .await;

        assert_eq!(reply.status, 400, "{url}: {}", reply.body);
        assert!(
            reply
                .body
                .contains("the list URL must not contain a user name or password"),
            "{}",
            reply.body
        );
        assert!(!reply.body.contains("secret"), "{}", reply.body);
    }

    assert_eq!(server.requests(), 0);
    assert!(saved_settings(&site).is_none());
    assert!(site.control.pending_list().is_none());

    for path in ["/p@th/list.txt", "/query.txt?token=a@b"] {
        let reply = site
            .send(post("/api/lists/add", &add_body("At", &server.url(path))))
            .await;

        assert_eq!(reply.status, 202, "{path}: {}", reply.body);
        assert_eq!(
            after_the_add(&site).await["pending"]["state"],
            "added",
            "{path}"
        );
    }
}

#[tokio::test]
async fn page_lists_are_edited_removed_and_reset_through_the_api() {
    let (site, server, _upstream) = list_site(|_| {}).await;
    server.serve("/list.txt", "||edited.example^\n", None);
    let url = server.url("/list.txt");
    site.send(post("/api/lists/add", &add_body("Edited", &url)))
        .await;
    assert_eq!(after_the_add(&site).await["pending"]["state"], "added");

    let off = site
        .send(post(
            "/api/lists/edit",
            &serde_json::json!({"role": "block", "source": url, "enabled": false, "name": "Off", "refresh_hours": 3})
                .to_string(),
        ))
        .await;

    assert_eq!(off.status, 200, "{}", off.body);
    let row = &off.json()["lists"][0];
    assert_eq!(
        (
            &row["name"],
            &row["enabled"],
            &row["refresh_hours"],
            &row["rules"]
        ),
        (
            &Value::from("Off"),
            &Value::from(false),
            &Value::from(3),
            &Value::from(0)
        )
    );
    let answer = ask(&site.dns, "edited.example.", RecordType::A).await;
    assert_eq!(addresses(&answer), ["9.9.9.9"]);

    let removed = site
        .send(post(
            "/api/lists/remove",
            &serde_json::json!({"role": "block", "source": url}).to_string(),
        ))
        .await;
    assert_eq!(removed.status, 200, "{}", removed.body);
    assert_eq!(removed.json()["lists"], serde_json::json!([]));
    assert_eq!(removed.json()["from"], "page", "no lists, set on the page");
    assert_eq!(
        saved_settings(&site).unwrap()["lists"],
        serde_json::json!([])
    );

    let reset = site.send(post("/api/lists/reset", "{}")).await;
    assert_eq!(reset.status, 200, "{}", reset.body);
    assert_eq!(reset.json()["from"], "file");
    assert_eq!(
        saved_settings(&site).unwrap(),
        serde_json::json!({"version": 1})
    );
}

#[tokio::test]
async fn an_add_a_refresh_and_a_larger_cache_at_once_near_the_budget_never_pass_it() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let idle = site(local_config(&upstream))
        .await
        .control
        .memory()
        .estimate_bytes;
    let (site, server, _upstream) =
        list_site(|config| config.limits.memory_mb = idle / (1024 * 1024) + 2).await;
    let rules = |prefix: &str| -> String {
        (0..40_000)
            .map(|index| format!("||{prefix}{index}.example^\n"))
            .collect()
    };
    server.serve("/a.txt", "||a.example^\n", None);
    server.serve("/b.txt", &rules("b"), None);
    site.send(post(
        "/api/lists/add",
        &add_body("A", &server.url("/a.txt")),
    ))
    .await;
    assert_eq!(after_the_add(&site).await["pending"]["state"], "added");
    server.serve("/a.txt", &rules("a"), None);
    let control = Arc::clone(&site.control);
    let sampling = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let sampler = {
        let sampling = Arc::clone(&sampling);
        tokio::spawn(async move {
            let mut most = 0;
            while sampling.load(Ordering::Relaxed) {
                let memory = control.memory();
                assert!(memory.estimate_bytes <= memory.budget_bytes, "{memory:?}");
                most = most.max(memory.estimate_bytes);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }

            most
        })
    };

    let (added, refreshed, cache) = tokio::join!(
        site.send(post(
            "/api/lists/add",
            &add_body("B", &server.url("/b.txt"))
        )),
        site.send(post("/api/lists/refresh", "")),
        site.send(post("/api/settings", &cache_of_size(5 * 1024 * 1024))),
    );
    assert_eq!(added.status, 202, "{}", added.body);
    assert_eq!(refreshed.status, 202, "{}", refreshed.body);
    assert!(cache.status == 200 || cache.status == 400, "{}", cache.body);
    let lists = after_the_add(&site).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let a = &site.control.statuses()[0];
        if a.rules > 1 || a.last_error.is_some() {
            break;
        }

        assert!(Instant::now() < deadline, "the refresh never ended");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    sampling.store(false, Ordering::Relaxed);
    let most = sampler.await.unwrap();
    let memory = site.control.memory();
    eprintln!(
        "add: {}, cache: {}, list a: {:?}; most {most} of {} bytes",
        lists["pending"]["state"],
        cache.status,
        site.control.statuses()[0].last_error,
        memory.budget_bytes
    );
    assert!(memory.estimate_bytes <= memory.budget_bytes);
}

// ---- Blocked services (plan D8) ----

/// A small catalog in the shape of AdGuard's `services.json`, written for these tests.
const CATALOG: &str = r#"{
  "blocked_services": [
    {"id": "chat", "name": "Chat", "group": "messenger", "icon_svg": "<svg>chat</svg>",
     "rules": ["||chat.example^", "||chatcdn.example^"]},
    {"id": "video", "name": "Video", "group": "streaming", "icon_svg": "<svg>video</svg>",
     "rules": ["||video.example^"]},
    {"id": "games", "name": "Games", "group": "gaming", "rules": ["||games.example^"]}
  ],
  "groups": [{"id": "messenger"}, {"id": "streaming"}, {"id": "gaming"}]
}"#;

const CATALOG_PATH: &str = "/services.json";

fn fast_timing() -> Timing {
    Timing {
        hour: Duration::from_millis(300),
        retries: [Duration::from_millis(200); 4],
        first_check: Duration::from_secs(3600),
    }
}

/// A site whose catalog of services is served by the returned server.
async fn services_site(
    block: &[&str],
    timing: Timing,
    change: impl FnOnce(&mut Config),
) -> (Site, ListServer, common::harness::FakeUpstream) {
    let catalog = ListServer::start().await;
    catalog.serve(CATALOG_PATH, CATALOG, None);
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    config.services.catalog_url = catalog.url(CATALOG_PATH);
    config.services.block = block.iter().map(|id| id.to_string()).collect();
    change(&mut config);
    let kind = SiteKind {
        build: Build::current(),
        installer: true,
        release_target: true,
    };
    let site = site_timed(config, kind, None, timing).await;

    (site, catalog, upstream)
}

async fn is_blocked(site: &Site, name: &str) -> bool {
    addresses(&ask(&site.dns, name, RecordType::A).await) == ["0.0.0.0"]
}

/// Waits until `name` is blocked or not, as `blocked` says.
async fn wait_until_blocked(site: &Site, name: &str, blocked: bool) {
    for _ in 0..400 {
        if is_blocked(site, name).await == blocked {
            return;
        }

        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    panic!(
        "{name} never became {}",
        if blocked { "blocked" } else { "allowed" }
    );
}

/// `GET /api/services` once it is no longer loading.
async fn loaded_services(site: &Site) -> Value {
    for _ in 0..400 {
        let reply = site.send(get("/api/services")).await;
        assert_eq!(reply.status, 200, "{}", reply.body);
        let services = reply.json();
        if services["loading"] == false {
            return services;
        }

        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    panic!("the services never loaded");
}

fn switched_on(services: &Value) -> Vec<String> {
    services["services"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|service| service["on"] == true)
        .map(|service| service["id"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn blocked_services_are_switched_on_and_off_and_reset_from_the_page() {
    let (site, catalog, _upstream) = services_site(&[], day_long_timing(), |_| {}).await;

    let services = loaded_services(&site).await;
    assert_eq!(
        services["services"],
        serde_json::json!([
            {"id": "chat", "name": "Chat", "group": "messenger", "on": false},
            {"id": "video", "name": "Video", "group": "streaming", "on": false},
            {"id": "games", "name": "Games", "group": "gaming", "on": false},
        ])
    );
    assert!(services["loaded_at"].as_u64().unwrap() > 1_700_000_000);
    assert_eq!(services["error"], Value::Null);
    assert!(!services.to_string().contains("svg"));
    assert_eq!(catalog.requested(CATALOG_PATH), 1);
    assert!(!is_blocked(&site, "chat.example.").await);

    let reply = site
        .send(post("/api/settings", "{\"services\": [\"chat\"]}"))
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(
        reply.json()["services"],
        serde_json::json!({"block": ["chat"], "from": "page"})
    );
    assert_eq!(catalog.requested(CATALOG_PATH), 2);
    for name in ["chat.example.", "www.chat.example.", "chatcdn.example."] {
        assert!(is_blocked(&site, name).await, "{name}");
    }
    assert!(!is_blocked(&site, "video.example.").await);
    let explained = site
        .send(get("/api/explain?name=chat.example"))
        .await
        .json();
    assert_eq!(explained["decision"], "blocked");
    assert_eq!(explained["list"], "Blocked service: Chat");
    assert_eq!(switched_on(&loaded_services(&site).await), ["chat"]);
    assert_eq!(
        saved_settings(&site).unwrap()["services"],
        serde_json::json!(["chat"])
    );

    let reply = site
        .send(post(
            "/api/settings",
            "{\"services\": [\"chat\", \"video\"]}",
        ))
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(is_blocked(&site, "video.example.").await);
    assert!(is_blocked(&site, "chat.example.").await);
    assert_eq!(catalog.requested(CATALOG_PATH), 3);
    let file = site.state.join(settings::FILE_NAME);
    std::fs::remove_file(&file).unwrap();
    let reply = site
        .send(post(
            "/api/settings",
            "{\"services\": [\"chat\", \"video\"]}",
        ))
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(!file.exists(), "the same services again write nothing");
    assert_eq!(catalog.requested(CATALOG_PATH), 3);

    let reply = site
        .send(post("/api/settings", "{\"services\": [\"video\"]}"))
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(!is_blocked(&site, "chat.example.").await);
    assert!(is_blocked(&site, "video.example.").await);
    assert_eq!(
        catalog.requested(CATALOG_PATH),
        3,
        "switching off downloads nothing"
    );

    let before = saved_settings(&site);
    let reply = site
        .send(post(
            "/api/settings",
            "{\"services\": [\"video\", \"nope\"]}",
        ))
        .await;
    assert_eq!(reply.status, 400, "{}", reply.body);
    assert_eq!(
        reply.json()["error"],
        "there is no service \"nope\" in the catalog"
    );
    assert_eq!(saved_settings(&site), before);
    assert_eq!(
        catalog.requested(CATALOG_PATH),
        3,
        "an unknown id downloads nothing"
    );

    let reply = site
        .send(post("/api/settings", "{\"services\": null}"))
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(
        reply.json()["services"],
        serde_json::json!({"block": [], "from": "file"})
    );
    assert!(!is_blocked(&site, "video.example.").await);
    assert!(saved_settings(&site).unwrap().get("services").is_none());
    assert_eq!(catalog.requested(CATALOG_PATH), 3);
}

#[tokio::test]
async fn services_from_the_config_file_are_loaded_once_at_start_and_pause_turns_them_off() {
    let (site, catalog, _upstream) = {
        let catalog_delay = Duration::from_millis(300);
        let (site, catalog, upstream) = services_site(&["video"], day_long_timing(), |_| {}).await;
        catalog.set_delay(catalog_delay);

        (site, catalog, upstream)
    };

    wait_until_blocked(&site, "video.example.", true).await;
    let services = loaded_services(&site).await;
    assert_eq!(switched_on(&services), ["video"]);
    let settings = site.send(get("/api/settings")).await.json();
    assert_eq!(
        settings["services"],
        serde_json::json!({"block": ["video"], "from": "file"})
    );
    assert_eq!(catalog.requested(CATALOG_PATH), 1);

    let reply = site.send(post("/api/pause", "{\"minutes\": 5}")).await;
    assert_eq!(reply.status, 200);
    assert!(!is_blocked(&site, "video.example.").await);
    let reply = site.send(post("/api/resume", "{}")).await;
    assert_eq!(reply.status, 200);
    assert!(is_blocked(&site, "video.example.").await);

    assert!(saved_settings(&site).is_none(), "nothing was written");
}

#[tokio::test]
async fn until_the_catalog_is_read_the_page_says_loading() {
    let catalog = ListServer::start().await;
    catalog.serve(CATALOG_PATH, CATALOG, None);
    catalog.set_delay(Duration::from_millis(500));
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    config.services.catalog_url = catalog.url(CATALOG_PATH);
    config.services.block = vec!["chat".to_string()];
    let site = site(config).await;

    let services = site.send(get("/api/services")).await.json();

    assert_eq!(services["loading"], true);
    assert_eq!(services["services"], serde_json::json!([]));
    assert!(!is_blocked(&site, "chat.example.").await);
    wait_until_blocked(&site, "chat.example.", true).await;
    assert_eq!(loaded_services(&site).await["loading"], false);
}

#[tokio::test]
async fn a_failed_refresh_keeps_the_service_lists_and_no_refresh_writes_a_file() {
    let (site, catalog, _upstream) = services_site(&["chat"], fast_timing(), |config| {
        config.services.refresh_hours = 1;
    })
    .await;
    wait_until_blocked(&site, "chat.example.", true).await;

    catalog.fail(CATALOG_PATH, 503);
    let failed_once = catalog.requested(CATALOG_PATH) + 2;
    for _ in 0..400 {
        if catalog.requested(CATALOG_PATH) >= failed_once {
            break;
        }

        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(catalog.requested(CATALOG_PATH) >= failed_once);
    let services = site.send(get("/api/services")).await.json();
    assert!(
        services["error"].as_str().unwrap().contains("503"),
        "{services}"
    );
    assert!(is_blocked(&site, "chat.example.").await, "the lists stay");

    catalog.serve(
        CATALOG_PATH,
        &CATALOG.replace("||chatcdn.example^", "||chat2.example^"),
        None,
    );
    wait_until_blocked(&site, "chat2.example.", true).await;
    assert!(!is_blocked(&site, "chatcdn.example.").await);
    assert_eq!(
        site.send(get("/api/services")).await.json()["error"],
        Value::Null
    );

    let written: Vec<_> = std::fs::read_dir(&site.state).unwrap().collect();
    assert!(written.is_empty(), "{written:?}");
}

/// Waits until the services view reports an error that names `id`.
async fn wait_for_services_error_naming(site: &Site, id: &str) -> Value {
    for _ in 0..400 {
        let services = site.send(get("/api/services")).await.json();
        if services["error"]
            .as_str()
            .is_some_and(|error| error.contains(id))
        {
            return services;
        }

        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    panic!("the services view never named {id} in its error");
}

/// A service stays switched on, and blocking, after a refreshed catalog stops offering usable
/// rules for it; the page keeps it listed as on and says why.
async fn assert_video_stays_blocked_after(catalog_without_usable_video: &str) {
    let (site, catalog, _upstream) = services_site(&["chat", "video"], fast_timing(), |config| {
        config.services.refresh_hours = 1;
    })
    .await;
    wait_until_blocked(&site, "chat.example.", true).await;
    wait_until_blocked(&site, "video.example.", true).await;

    catalog.serve(CATALOG_PATH, catalog_without_usable_video, None);
    let services = wait_for_services_error_naming(&site, "video").await;

    let video = services["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["id"] == "video")
        .unwrap_or_else(|| panic!("video is not listed: {services}"));
    assert_eq!(video["on"], true, "{services}");
    assert!(is_blocked(&site, "chat.example.").await);
    assert!(
        is_blocked(&site, "video.example.").await,
        "video is still switched on but no longer blocked"
    );
    let settings = site.send(get("/api/settings")).await.json();
    assert_eq!(
        settings["services"]["block"],
        serde_json::json!(["chat", "video"])
    );
}

#[tokio::test]
async fn a_service_missing_from_the_new_catalog_keeps_its_list() {
    let video = "{\"id\": \"video\", \"name\": \"Video\", \"group\": \"streaming\", \"icon_svg\": \"<svg>video</svg>\",\n     \"rules\": [\"||video.example^\"]},";
    let without_video = CATALOG.replace(video, "");
    assert!(!without_video.contains("\"video\""));

    assert_video_stays_blocked_after(&without_video).await;
}

#[tokio::test]
async fn a_service_grown_over_the_rule_cap_keeps_its_list() {
    let many_rules = (0..2001)
        .map(|index| format!("\"||video{index}.example^\""))
        .collect::<Vec<_>>()
        .join(",");
    let video = "\"rules\": [\"||video.example^\"]},";
    let grown = CATALOG.replace(video, &format!("\"rules\": [{many_rules}]}},"));
    assert!(grown.contains("video2000.example"));

    assert_video_stays_blocked_after(&grown).await;
}

#[tokio::test]
async fn no_catalog_is_downloaded_without_a_service_switched_on() {
    let (site, catalog, _upstream) = services_site(&[], fast_timing(), |config| {
        config.services.refresh_hours = 1;
    })
    .await;

    let reply = site.send(post("/api/settings", "{\"services\": []}")).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(
        saved_settings(&site).unwrap()["services"],
        serde_json::json!([])
    );
    let reply = site.send(post("/api/lists/refresh", "{}")).await;
    assert_eq!(reply.status, 202);
    tokio::time::sleep(Duration::from_millis(1000)).await;

    assert_eq!(catalog.requests(), 0);
}

#[tokio::test]
async fn services_that_would_pass_the_memory_budget_are_refused_and_the_lists_stay() {
    let big: Vec<String> = (0..2000)
        .map(|n| format!("\"||n{n}.big.example^\""))
        .collect();
    let catalog_text = CATALOG.replace(
        "\"rules\": [\"||games.example^\"]",
        &format!("\"rules\": [{}]", big.join(", ")),
    );
    let (probe, _catalog, _upstream) = services_site(&[], day_long_timing(), |_| {}).await;
    let memory = probe.control.memory();
    drop(probe);
    // A cache that leaves 20 KB of the budget: room for the small services, not for 2000
    // rules.
    let left = 20 * 1024;
    let budget = memory.budget_bytes;
    let cache_max_bytes =
        Config::default().cache.max_bytes + (budget - memory.estimate_bytes - left) / 125 * 100;
    let (site, catalog, _upstream) = services_site(&["chat"], day_long_timing(), |config| {
        config.cache.max_bytes = cache_max_bytes;
    })
    .await;
    catalog.serve(CATALOG_PATH, &catalog_text, None);
    wait_until_blocked(&site, "chat.example.", true).await;
    let memory = site.control.memory();
    assert!(
        memory.budget_bytes - memory.estimate_bytes < 40 * 1024,
        "{memory:?}"
    );

    let reply = site
        .send(post(
            "/api/settings",
            "{\"services\": [\"chat\", \"games\"]}",
        ))
        .await;

    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(
        reply.json()["error"]
            .as_str()
            .unwrap()
            .starts_with("the blocked services would pass the memory budget"),
        "{}",
        reply.body
    );
    assert!(!is_blocked(&site, "n1.big.example.").await);
    assert!(is_blocked(&site, "chat.example.").await);
    assert!(saved_settings(&site).is_none());
    assert_eq!(site.control.memory(), memory);
}

/// A catalog of `count` services `s0`, `s1`, ..., each with `rules` rules.
fn catalog_of(count: usize, rules: usize) -> String {
    let entries: Vec<String> = (0..count)
        .map(|service| {
            let rules: Vec<String> = (0..rules)
                .map(|rule| format!("\"||r{rule}.s{service}.example^\""))
                .collect();

            format!(
                "{{\"id\": \"s{service}\", \"name\": \"S{service}\", \"group\": \"g\", \
                 \"rules\": [{}]}}",
                rules.join(", ")
            )
        })
        .collect();

    format!("{{\"blocked_services\": [{}]}}", entries.join(", "))
}

fn services_body(ids: std::ops::Range<usize>) -> String {
    let ids: Vec<String> = ids.map(|id| format!("\"s{id}\"")).collect();

    format!("{{\"services\": [{}]}}", ids.join(", "))
}

#[tokio::test]
async fn services_switched_on_one_change_at_a_time_stay_within_20000_rules() {
    let (site, catalog, _upstream) = services_site(&[], day_long_timing(), |_| {}).await;
    catalog.serve(CATALOG_PATH, &catalog_of(11, 2000), None);
    let refused = |reply: &Reply| {
        assert_eq!(reply.status, 400, "{}", reply.body);
        assert_eq!(
            reply.json()["error"],
            "the services switched on would hold 22000 rules, more than 20000"
        );
    };

    refused(
        &site
            .send(post("/api/settings", &services_body(0..11)))
            .await,
    );
    assert!(saved_settings(&site).is_none());

    let reply = site.send(post("/api/settings", &services_body(0..9))).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let reply = site
        .send(post("/api/settings", &services_body(0..10)))
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(is_blocked(&site, "r1999.s9.example.").await);
    let memory = site.control.memory();
    let before = saved_settings(&site);

    refused(
        &site
            .send(post("/api/settings", &services_body(0..11)))
            .await,
    );
    assert!(!is_blocked(&site, "r0.s10.example.").await);
    assert!(is_blocked(&site, "r0.s0.example.").await);
    assert_eq!(saved_settings(&site), before);
    assert_eq!(site.control.memory(), memory);
    assert_eq!(loaded_services(&site).await["error"], Value::Null);

    let reply = site
        .send(post("/api/settings", &services_body(1..11)))
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(is_blocked(&site, "r0.s10.example.").await);
    assert!(!is_blocked(&site, "r0.s0.example.").await);
}

#[tokio::test]
async fn a_larger_cache_and_services_in_one_change_must_fit_the_budget_together() {
    let big: Vec<String> = (0..2000)
        .map(|n| format!("\"||n{n}.big.example^\""))
        .collect();
    let catalog_text = CATALOG.replace(
        "\"rules\": [\"||games.example^\"]",
        &format!("\"rules\": [{}]", big.join(", ")),
    );
    let (probe, _catalog, _upstream) = services_site(&[], day_long_timing(), |_| {}).await;
    // A budget that leaves about 8 MiB, so the larger cache stays within its 16 MiB cap.
    let memory_mb = probe.control.memory().estimate_bytes / (1024 * 1024) + 8;
    drop(probe);
    let (probe, probe_catalog, _upstream) = services_site(&[], day_long_timing(), |config| {
        config.limits.memory_mb = memory_mb;
    })
    .await;
    probe_catalog.serve(CATALOG_PATH, &catalog_text, None);
    let without = probe.control.memory();
    let reply = probe
        .send(post("/api/settings", "{\"services\": [\"games\"]}"))
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let services = probe.control.memory().estimate_bytes - without.estimate_bytes;
    drop(probe);
    // Room for the services, or for a cache that counts as much more, but not for both.
    let room = services * 3 / 2;
    let cache_max_bytes = Config::default().cache.max_bytes
        + (without.budget_bytes - without.estimate_bytes - room) / 125 * 100;
    let larger_cache = cache_max_bytes + services / 125 * 100;
    let (site, catalog, _upstream) = services_site(&[], day_long_timing(), |config| {
        config.limits.memory_mb = memory_mb;
        config.cache.max_bytes = cache_max_bytes;
    })
    .await;
    catalog.serve(CATALOG_PATH, &catalog_text, None);
    let memory = site.control.memory();
    let mut both: Value = serde_json::from_str(&cache_of_size(larger_cache)).unwrap();
    both["services"] = serde_json::json!(["games"]);

    let reply = site.send(post("/api/settings", &both.to_string())).await;

    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(
        reply.json()["error"]
            .as_str()
            .unwrap()
            .starts_with("the blocked services and a cache of "),
        "{}",
        reply.body
    );
    assert!(!is_blocked(&site, "n1.big.example.").await);
    assert!(saved_settings(&site).is_none());
    assert_eq!(site.control.memory(), memory);

    let reply = site
        .send(post("/api/settings", "{\"services\": [\"games\"]}"))
        .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(is_blocked(&site, "n1.big.example.").await);
    both["services"] = serde_json::json!([]);
    let reply = site.send(post("/api/settings", &both.to_string())).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(!is_blocked(&site, "n1.big.example.").await);
    assert!(site.control.memory().estimate_bytes <= memory.budget_bytes);
}

#[tokio::test]
async fn a_refresh_with_a_service_that_cannot_be_used_keeps_every_service_list() {
    let (site, catalog, _upstream) = services_site(&["chat", "video"], fast_timing(), |config| {
        config.services.refresh_hours = 1;
    })
    .await;
    wait_until_blocked(&site, "chat.example.", true).await;
    wait_until_blocked(&site, "video.example.", true).await;

    catalog.serve(
        CATALOG_PATH,
        &CATALOG
            .replace(
                "\"||chatcdn.example^\"",
                "\"||chatcdn.example^\", \"||com^\"",
            )
            .replace("||video.example^", "||video2.example^"),
        None,
    );
    let refused_twice = catalog.requested(CATALOG_PATH) + 2;
    for _ in 0..400 {
        if catalog.requested(CATALOG_PATH) >= refused_twice {
            break;
        }

        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(catalog.requested(CATALOG_PATH) >= refused_twice);

    let services = site.send(get("/api/services")).await.json();
    assert_eq!(
        services["error"], "blocked service Chat: compile failed: BlocksCanary",
        "{services}"
    );
    assert_eq!(switched_on(&services), ["chat", "video"]);
    assert!(is_blocked(&site, "chat.example.").await);
    assert!(is_blocked(&site, "video.example.").await);
    assert!(!is_blocked(&site, "video2.example.").await);
    assert!(!is_blocked(&site, "other.com.").await);

    catalog.serve(
        CATALOG_PATH,
        &CATALOG.replace("||video.example^", "||video2.example^"),
        None,
    );
    wait_until_blocked(&site, "video2.example.", true).await;
    assert!(is_blocked(&site, "chat.example.").await);
    assert_eq!(
        site.send(get("/api/services")).await.json()["error"],
        Value::Null
    );

    catalog.serve(
        CATALOG_PATH,
        &CATALOG.replace("\"||games.example^\"", "\"||games.example^\", \"||com^\""),
        None,
    );
    let reply = site
        .send(post(
            "/api/settings",
            "{\"services\": [\"chat\", \"video\", \"games\"]}",
        ))
        .await;
    assert_eq!(reply.status, 502, "{}", reply.body);
    assert_eq!(
        reply.json()["error"],
        "blocked service Games: compile failed: BlocksCanary"
    );
    assert!(!is_blocked(&site, "games.example.").await);
    assert!(is_blocked(&site, "chat.example.").await);
    assert!(saved_settings(&site).is_none());
}

/// The last day of a history answer, which is today in the zone of the request.
fn today_of(history: &Value) -> &Value {
    history["days"].as_array().unwrap().last().unwrap()
}

#[tokio::test]
async fn the_history_has_a_bucket_per_day_in_the_zone_asked_for() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    config.stats.retention_days = 90;
    without_credentials(&mut config);
    let site = site(config).await;
    for name in ["a.example.", "b.example.", "ads.example."] {
        ask(&site.dns, name, RecordType::A).await;
    }

    for days in [7, 30, 90] {
        let reply = site.send(get(&format!("/api/history?days={days}"))).await;
        let history = reply.json();

        assert_eq!(reply.status, 200, "{}", reply.body);
        assert_eq!(history["days"].as_array().unwrap().len(), days);
        assert_eq!(history["retention_days"], 90);
    }

    let utc = site.send(get("/api/history?days=7&offset=0")).await.json();
    let default = site.send(get("/api/history?days=7")).await.json();
    let today = today_of(&utc);
    assert_eq!(today["total"], 3);
    assert_eq!(today["blocked"], 1);
    assert_eq!(utc, default);
    assert_eq!(today["day_start"].as_u64().unwrap() % 86_400, 0);
    let earlier: u64 = utc["days"]
        .as_array()
        .unwrap()
        .iter()
        .map(|day| day["total"].as_u64().unwrap())
        .sum();
    assert_eq!(earlier, 3);

    let east = site.send(get("/api/history?days=7&offset=60")).await.json();
    assert_eq!(
        (today_of(&east)["day_start"].as_u64().unwrap() + 3600) % 86_400,
        0
    );
    let west = site
        .send(get("/api/history?days=7&offset=-300"))
        .await
        .json();
    assert_eq!(
        (today_of(&west)["day_start"].as_u64().unwrap() - 300 * 60) % 86_400,
        0
    );

    for beyond in ["841", "100000", "-841", "-100000"] {
        let clamped = site
            .send(get(&format!("/api/history?days=7&offset={beyond}")))
            .await
            .json();
        let limit = if beyond.starts_with('-') {
            "-840"
        } else {
            "840"
        };
        let at_limit = site
            .send(get(&format!("/api/history?days=7&offset={limit}")))
            .await
            .json();

        assert_eq!(clamped, at_limit, "{beyond}");
    }
}

#[tokio::test]
async fn the_history_is_cut_to_the_retention_and_refuses_other_ranges() {
    let (site, _upstream) = plain_site().await;
    ask(&site.dns, "a.example.", RecordType::A).await;

    let long = site.send(get("/api/history?days=90&offset=0")).await.json();

    assert_eq!(long["retention_days"], 30);
    assert_eq!(long["days"].as_array().unwrap().len(), 30);
    for bad in [
        "",
        "?days=1",
        "?days=8",
        "?days=0",
        "?days=-7",
        "?days=abc",
        "?days=7.5",
        "?days=",
        "?offset=0",
        "?days=7&offset=abc",
        "?days=7&offset=1.5",
        "?days=7&offset=",
        "?days=7&offset=99999999999",
        "?days=7&days=abc",
    ] {
        let reply = site.send(get(&format!("/api/history{bad}"))).await;

        assert_eq!(reply.status, 400, "{bad}: {}", reply.body);
        assert!(reply.json()["error"].is_string(), "{bad}");
    }

    let wrong_method = site.send(post("/api/history", "{}")).await;
    assert_eq!(wrong_method.status, 405);
    assert_eq!(wrong_method.header("allow"), Some("GET"));
}

#[tokio::test]
async fn the_history_needs_no_password_when_none_is_set_and_a_sign_in_when_one_is() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut open = local_config(&upstream);
    without_credentials(&mut open);
    let open = site(open).await;
    let (closed, _upstream) = plain_site().await;

    assert_eq!(open.send(get("/api/history?days=7")).await.status, 200);
    assert_eq!(
        closed.send_as_is(get("/api/history?days=7")).await.status,
        401
    );
    assert_eq!(closed.send(get("/api/history?days=7")).await.status, 200);
}

#[tokio::test]
async fn the_status_has_the_start_for_everyone_and_the_saving_state_for_a_signed_in_user() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut open = local_config(&upstream);
    without_credentials(&mut open);
    let open = site(open).await;
    let (closed, _upstream) = plain_site().await;
    let mut unsaved = local_config(&upstream);
    unsaved.stats.persist = false;
    let unsaved = site(unsaved).await;

    let read = open.send(get("/api/status")).await.json();
    assert!(read["since"].as_u64().unwrap() > 1_700_000_000);
    assert_eq!(read["retention_days"], 30);
    assert!(read.get("stats_saving").is_none(), "{read}");

    let signed_in = closed.send(get("/api/status")).await.json();
    assert!(signed_in["since"].as_u64().unwrap() > 1_700_000_000);
    assert_eq!(
        signed_in["stats_saving"],
        serde_json::json!({"enabled": true, "last_saved": null, "error": null})
    );

    let off = unsaved.send(get("/api/status")).await.json();
    assert_eq!(off["stats_saving"]["enabled"], false);
}

#[tokio::test]
async fn clearing_the_statistics_starts_again_from_zero_saves_at_once_and_keeps_the_query_log() {
    let (site, _upstream) = plain_site().await;
    for name in ["a.example.", "a.example.", "ads.example."] {
        ask(&site.dns, name, RecordType::A).await;
    }

    let before = site.send(get("/api/status")).await.json();
    assert_eq!(before["counters"]["total"], 3);
    assert_eq!(before["top_queried"]["entries"][0]["key"], "a.example");
    assert!(before["upstreams"][0]["answered"].as_u64().unwrap() >= 1);
    let stats_file = site.state.join("stats.json");
    assert!(!stats_file.exists());
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let cleared = site.send(post("/api/stats/clear", "{}")).await;

    assert_eq!(cleared.status, 200);
    assert_eq!(cleared.body, "{\"cleared\":true,\"save_error\":null}");
    let after = site.send(get("/api/status")).await.json();
    assert_eq!(after["counters"]["total"], 0);
    assert_eq!(after["counters"]["blocked_request"], 0);
    assert!(after["since"].as_u64().unwrap() > before["since"].as_u64().unwrap());
    assert!(
        after["top_queried"]["entries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        after["top_clients"]["entries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(after["upstreams"][0]["answered"], 0);
    assert!(
        after["hourly"]
            .as_array()
            .unwrap()
            .iter()
            .all(|bucket| bucket["total"] == 0)
    );
    assert!(after["stats_saving"]["last_saved"].is_u64());
    let saved: Value = serde_json::from_slice(&std::fs::read(&stats_file).unwrap()).unwrap();
    assert_eq!(saved["counters"]["total"], 0);
    assert_eq!(saved["since"], after["since"]);
    assert!(saved["top_queried"].as_array().unwrap().is_empty());
    let log = site.send(get("/api/querylog")).await.json();
    assert_eq!(log["entries"].as_array().unwrap().len(), 3);

    ask(&site.dns, "b.example.", RecordType::A).await;
    let counting = site.send(get("/api/status")).await.json();
    assert_eq!(counting["counters"]["total"], 1);
}

#[tokio::test]
async fn clearing_the_statistics_with_saving_off_writes_nothing() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    config.stats.persist = false;
    let site = site(config).await;
    ask(&site.dns, "a.example.", RecordType::A).await;

    let cleared = site.send(post("/api/stats/clear", "{}")).await;

    assert_eq!(cleared.status, 200);
    assert_eq!(
        site.send(get("/api/status")).await.json()["counters"]["total"],
        0
    );
    assert!(!site.state.join("stats.json").exists());
}

#[tokio::test]
async fn clearing_the_statistics_says_when_the_file_could_not_be_written() {
    let (site, _upstream) = plain_site().await;
    ask(&site.dns, "a.example.", RecordType::A).await;
    let stats_file = site.state.join("stats.json");
    std::fs::create_dir(&stats_file).unwrap();

    let cleared = site.send(post("/api/stats/clear", "{}")).await;

    assert_eq!(cleared.status, 200);
    assert!(cleared.json()["save_error"].is_string(), "{}", cleared.body);
    let status = site.send(get("/api/status")).await.json();
    assert_eq!(status["counters"]["total"], 0);
    assert!(status["stats_saving"]["error"].is_string());
}

#[tokio::test]
async fn clearing_the_query_log_empties_it_and_leaves_the_statistics() {
    let (site, _upstream) = plain_site().await;
    for name in ["a.example.", "b.example."] {
        ask(&site.dns, name, RecordType::A).await;
    }
    let log = site.send(get("/api/querylog")).await.json();
    assert_eq!(log["entries"].as_array().unwrap().len(), 2);

    let cleared = site.send(post("/api/querylog/clear", "{}")).await;

    assert_eq!(cleared.status, 200);
    assert_eq!(cleared.body, "{\"cleared\":true}");
    let log = site.send(get("/api/querylog")).await.json();
    assert!(log["entries"].as_array().unwrap().is_empty());
    let status = site.send(get("/api/status")).await.json();
    assert_eq!(status["counters"]["total"], 2);
    assert!(!site.state.join("stats.json").exists());

    ask(&site.dns, "c.example.", RecordType::A).await;
    let log = site.send(get("/api/querylog")).await.json();
    assert_eq!(log["entries"][0]["qname"], "c.example");
}

#[tokio::test]
async fn the_clear_routes_refuse_without_a_password_or_a_sign_in_and_change_nothing() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut open = local_config(&upstream);
    without_credentials(&mut open);
    let open = site(open).await;
    let (closed, _upstream) = plain_site().await;

    for site in [&open, &closed] {
        ask(&site.dns, "a.example.", RecordType::A).await;
    }

    for path in ["/api/stats/clear", "/api/querylog/clear"] {
        assert_eq!(open.send(post(path, "{}")).await.status, 403, "{path}");
        assert_eq!(
            closed.send_as_is(post(path, "{}")).await.status,
            401,
            "{path}"
        );
        assert_eq!(closed.send(get(path)).await.status, 405, "{path}");
    }

    for site in [&open, &closed] {
        let status = site.send(get("/api/status")).await.json();
        assert_eq!(status["counters"]["total"], 1);
    }

    assert!(!open.state.join("stats.json").exists());
    assert!(!closed.state.join("stats.json").exists());
    assert_eq!(
        closed.send(get("/api/querylog")).await.json()["entries"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

/// Statistics saved with `queries` in the hour of each of the days ago.
fn saved_hours(days_ago: &[(u64, u64)]) -> picoguard::stats_store::SavedStats {
    use picoguard::stats::Counters;
    use picoguard::stats_store::SavedStats;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    SavedStats {
        version: SavedStats::VERSION,
        since: now - 90 * 86_400,
        counters: Counters::default(),
        hours: days_ago
            .iter()
            .map(|(days, queries)| (now / 3600 - days * 24, *queries, 0))
            .collect(),
        top_queried: Vec::new(),
        top_blocked: Vec::new(),
        top_clients: Vec::new(),
        upstreams: Vec::new(),
    }
}

async fn ninety_days(site: &Site) -> Value {
    site.send(get("/api/history?days=90&offset=0")).await.json()
}

fn history_total(history: &Value) -> u64 {
    history["days"]
        .as_array()
        .unwrap()
        .iter()
        .map(|day| day["total"].as_u64().unwrap())
        .sum()
}

#[tokio::test]
async fn the_retention_set_on_the_page_applies_at_once_and_goes_back_to_the_config_file() {
    let (site, _upstream) = plain_site().await;
    let settings_file = site.state.join(settings::FILE_NAME);
    site.dns.pipeline.stats().set_retention(90);
    site.dns
        .pipeline
        .restore_stats(&saved_hours(&[(60, 40), (3, 7)]));

    let settings = site.send(get("/api/settings")).await.json();
    assert_eq!(
        settings["stats"],
        serde_json::json!({"retention_days": 30, "from": "file"})
    );
    let history = ninety_days(&site).await;
    assert_eq!(history["retention_days"], 90);
    assert_eq!(history_total(&history), 47);
    assert_eq!(history["days"].as_array().unwrap().len(), 90);

    let page = site
        .send(post(
            "/api/settings",
            "{\"stats\": {\"retention_days\": 7}}",
        ))
        .await;

    assert_eq!(page.status, 200, "{}", page.body);
    assert_eq!(
        page.json()["stats"],
        serde_json::json!({"retention_days": 7, "from": "page"})
    );
    let history = ninety_days(&site).await;
    assert_eq!(history["retention_days"], 7);
    assert_eq!(history["days"].as_array().unwrap().len(), 7);
    assert_eq!(history_total(&history), 7);
    let written: Value = serde_json::from_slice(&std::fs::read(&settings_file).unwrap()).unwrap();
    assert_eq!(written["stats"], serde_json::json!({"retention_days": 7}));

    let longer = site
        .send(post(
            "/api/settings",
            "{\"stats\": {\"retention_days\": 90}}",
        ))
        .await;
    assert_eq!(longer.status, 200);
    let history = ninety_days(&site).await;
    assert_eq!(history["days"].as_array().unwrap().len(), 90);
    assert_eq!(history_total(&history), 7, "what was dropped stays dropped");

    let unchanged = std::fs::read(&settings_file).unwrap();
    let again = site
        .send(post(
            "/api/settings",
            "{\"stats\": {\"retention_days\": 90}}",
        ))
        .await;
    assert_eq!(again.status, 200);
    assert_eq!(std::fs::read(&settings_file).unwrap(), unchanged);

    let reset = site.send(post("/api/settings", "{\"stats\": null}")).await;
    assert_eq!(reset.status, 200);
    assert_eq!(
        reset.json()["stats"],
        serde_json::json!({"retention_days": 30, "from": "file"})
    );
    let history = ninety_days(&site).await;
    assert_eq!(history["retention_days"], 30);
    assert_eq!(history["days"].as_array().unwrap().len(), 30);
    let written: Value = serde_json::from_slice(&std::fs::read(&settings_file).unwrap()).unwrap();
    assert!(written.get("stats").is_none(), "{written}");
}

#[tokio::test]
async fn a_retention_the_page_does_not_offer_is_refused_and_changes_nothing() {
    let (site, _upstream) = plain_site().await;

    for body in [
        "{\"stats\": {\"retention_days\": 14}}",
        "{\"stats\": {\"retention_days\": 0}}",
        "{\"stats\": {\"retention_days\": 91}}",
    ] {
        let reply = site.send(post("/api/settings", body)).await;

        assert_eq!(reply.status, 400, "{body}: {}", reply.body);
        assert_eq!(
            reply.json()["error"],
            "stats.retention_days must be 1, 7, 30 or 90"
        );
    }

    for body in [
        "{\"stats\": {}}",
        "{\"stats\": {\"retention_days\": \"7\"}}",
        "{\"stats\": {\"retention_days\": 7, \"top_k\": 5}}",
        "{\"stats\": 7}",
    ] {
        let reply = site.send(post("/api/settings", body)).await;

        assert_eq!(reply.status, 400, "{body}: {}", reply.body);
    }

    let settings = site.send(get("/api/settings")).await.json();
    assert_eq!(settings["stats"]["from"], "file");
    assert!(!site.state.join(settings::FILE_NAME).exists());
}
