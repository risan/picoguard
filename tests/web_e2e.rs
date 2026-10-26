//! The status page and its API over real sockets: each endpoint, basic auth, the access policy
//! (peer, `Host`, `Origin`, content type, body size, method), pause and the manual refresh.
//! Nothing leaves the machine.

mod common;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::harness::{Running, answering_upstream, ask, config_for, start_with_policy};
use common::http::ListServer;
use common::release::{Files, TARGET, scratch, test_key};
use hickory_proto::rr::RecordType;
use picoguard::config::{Config, ListConfig, ListFormat};
use picoguard::filter::compile::CompileWorker;
use picoguard::filter::snapshot::SnapshotStore;
use picoguard::lists::Downloader;
use picoguard::policy::Policy;
use picoguard::scheduler::{Scheduler, Timing};
use picoguard::stage::{StageSetup, StageTiming, Stager};
use picoguard::update::{self, Build, CheckTiming, Latest, Updates};
use picoguard::upstream::tls::Tls;
use picoguard::web::{self, Web, WebListeners};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
    let Ok(mut stream) = TcpStream::connect(address).await else {
        return Vec::new();
    };
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
    updates: Arc<Updates>,
    /// The fake of the release downloads the stager reads.
    release: ListServer,
    stager: Arc<Stager>,
    /// Sends the administrator's credentials with every request that has none of its own.
    signs_in: bool,
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
        Arc::new(|_| Box::pin(async { Err(io::Error::other("no DNS in this test")) })),
        Arc::new(Tls::with_webpki_roots()),
    )
}

fn local_config(upstream: &common::harness::FakeUpstream) -> Config {
    let mut config = config_for(upstream);
    config.lists = Vec::new();
    config.rules = vec!["||ads.example^".to_string()];
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

/// A release build with an installer and a newer version known: the button is offered
/// whenever a password is set.
async fn full_site(config: Config) -> Site {
    let site = site_with(
        config,
        SiteKind {
            build: Build::Release,
            installer: true,
            release_target: true,
        },
    )
    .await;
    site.updates.show(Some(offered()));

    site
}

async fn site_with(config: Config, kind: SiteKind) -> Site {
    let scheduler = Scheduler::boot(
        &config,
        CompileWorker::spawn().unwrap(),
        Arc::new(SnapshotStore::disabled()),
        day_long_timing(),
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
    let root = scratch(&format!("web-e2e-{}", SITES.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir(root.join("state")).unwrap();
    if kind.installer {
        std::fs::create_dir(root.join("installer")).unwrap();
    }

    let release = ListServer::start().await;
    serve_release(&release, &Files::good(OFFERED, &release_binary()));
    let stager = Stager::new(
        StageSetup {
            target: kind.release_target.then_some(TARGET),
            base_url: release.url("/download"),
            state_dir: root.join("state"),
            installer_dir: root.join("installer"),
            key: test_key(),
            max_binary_bytes: 1024 * 1024,
            timing: StageTiming {
                poll: Duration::from_millis(20),
                wait: Duration::from_secs(5),
            },
        },
        Arc::clone(&updates),
        Arc::new(|_| Box::pin(async { Err(io::Error::other("no DNS in this test")) })),
        Arc::new(Tls::with_webpki_roots()),
    );
    let web_state = Web::new(
        &config,
        Arc::clone(dns.pipeline.stats()),
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
        updates,
        release,
        stager,
        signs_in: config.web.password.is_some(),
    }
}

async fn plain_site() -> (Site, common::harness::FakeUpstream) {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let site = site(local_config(&upstream)).await;

    (site, upstream)
}

#[tokio::test]
async fn the_page_is_served_with_protective_headers() {
    let (site, _upstream) = plain_site().await;

    let reply = site.send(get("/")).await;

    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert!(reply.body.contains("<title>picoguard"), "{}", reply.body);
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(reply.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(reply.header("x-frame-options"), Some("DENY"));
    assert!(
        reply
            .header("content-security-policy")
            .is_some_and(|policy| policy.contains("connect-src 'self'") && !policy.contains("http"))
    );
    // No answer ever grants a cross-origin read.
    assert!(reply.header("access-control-allow-origin").is_none());
}

/// The page before the install button, for the growth budget.
const PAGE_BYTES_BEFORE_INSTALL: usize = 12905;

#[tokio::test]
async fn the_page_is_small_self_contained_and_fits_phone_and_dark_mode() {
    let (site, _upstream) = plain_site().await;

    let page = site.send(get("/")).await.body;

    assert!(page.len() < 15 * 1024, "{} bytes", page.len());
    assert!(
        page.len() <= PAGE_BYTES_BEFORE_INSTALL + 1600,
        "the install button may add 1600 bytes, not {}",
        page.len() - PAGE_BYTES_BEFORE_INSTALL
    );
    for external in [
        "src=", "href=", "http://", "https://", "url(", "@import", "<link",
    ] {
        assert!(!page.contains(external), "the page refers to {external}");
    }

    for needed in [
        "prefers-color-scheme: dark",
        "name=\"viewport\"",
        "/api/status",
        "/api/querylog",
        "/api/pause",
        "/api/resume",
        "/api/lists/refresh",
        "/api/update",
        "setInterval(update, 5000)",
        "id=\"version\"",
        "id=\"update\"",
        "id=\"update-how\"",
        "id=\"install\"",
        "id=\"install-state\"",
        "showUpdate(status)",
        "showInstall(",
        "confirm(",
    ] {
        assert!(page.contains(needed), "the page lacks {needed}");
    }

    for minutes in ["5", "30", "60", "1440"] {
        assert!(
            page.contains(&format!("data-minutes=\"{minutes}\"")),
            "{minutes}"
        );
    }

    // Names come from the network: the page never builds markup from them.
    assert!(!page.contains("innerHTML") && !page.contains("insertAdjacentHTML"));
}

/// No browser here: the button is hidden by a style rule, so the rule is what is checked.
#[tokio::test]
async fn the_resume_button_is_shown_only_while_blocking_is_paused() {
    let (site, _upstream) = plain_site().await;

    let page = site.send(get("/")).await.body;

    assert!(page.contains("#resume { display: none; }"));
    assert!(page.contains(".paused #resume { display: inline-block; }"));
}

/// No browser here, so the page source is checked for what hides the notice and what fills it.
#[tokio::test]
async fn the_update_notice_is_hidden_until_a_newer_version_is_known() {
    let (site, _upstream) = plain_site().await;

    let page = site.send(get("/")).await.body;

    assert!(page.contains("<section id=\"update\" hidden>"));
    assert!(
        page.contains("$(\"update\").hidden = !status.update.latest && !status.update.install;")
    );
    for filled_as_text in [
        "$(\"version\").textContent",
        "$(\"update-text\").textContent",
        "$(\"update-notes\").textContent",
        "$(\"update-how\").textContent",
        "$(\"install-state\").textContent",
    ] {
        assert!(page.contains(filled_as_text), "{filled_as_text}");
    }

    assert!(page.contains("\"update available: v\""));
}

/// No browser here: the click handler's source must ask before it posts.
#[tokio::test]
async fn the_install_button_asks_before_it_posts() {
    let (site, _upstream) = plain_site().await;

    let page = site.send(get("/")).await.body;
    let handler = &page[page
        .find("$(\"install\").addEventListener(")
        .expect("a click handler")..];
    let asks = handler.find("confirm(").expect("the handler asks");
    let posts = handler.find("\"/api/update\"").expect("the handler posts");

    assert!(asks < posts);
    assert!(page.contains("$(\"install\").hidden = !update.can_install;"));
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

fn rejected_mutations() -> Vec<(&'static str, Request, u16)> {
    let big = format!("{{\"minutes\": 5, \"padding\": \"{}\"}}", "x".repeat(1100));
    let chunked_big = format!("{:x}\r\n{}\r\n0\r\n\r\n", big.len(), big);

    vec![
        (
            "another origin",
            post("/api/pause", "{\"minutes\": 5}").header("Origin", "http://evil.example"),
            403,
        ),
        (
            "same host, other port",
            post("/api/pause", "{\"minutes\": 5}").header("Origin", "http://127.0.0.1:1"),
            403,
        ),
        (
            "https origin",
            post("/api/resume", "").header("Origin", "https://127.0.0.1"),
            403,
        ),
        (
            "null origin",
            post("/api/lists/refresh", "").header("Origin", "null"),
            403,
        ),
        (
            "a name that is not configured",
            post("/api/pause", "{\"minutes\": 5}").header("Host", "evil.example"),
            403,
        ),
        (
            "a rebound name with the right port",
            post("/api/pause", "{\"minutes\": 5}").header("Host", "localhost:8080"),
            403,
        ),
        (
            "plain text",
            post("/api/pause", "{\"minutes\": 5}").header("Content-Type", "text/plain"),
            415,
        ),
        (
            "a form",
            post("/api/pause", "minutes=5")
                .header("Content-Type", "application/x-www-form-urlencoded"),
            415,
        ),
        (
            "no content type",
            Request {
                headers: Vec::new(),
                ..post("/api/pause", "{\"minutes\": 5}")
            },
            415,
        ),
        ("a body over 1 KiB", post("/api/pause", &big), 413),
        (
            "a body over 1 KiB without a length",
            Request {
                headers: vec![
                    ("Content-Type".to_string(), "application/json".to_string()),
                    ("Transfer-Encoding".to_string(), "chunked".to_string()),
                ],
                body: chunked_big.into_bytes(),
                ..post("/api/pause", "")
            },
            413,
        ),
        ("a get of pause", get("/api/pause"), 405),
        ("a get of resume", get("/api/resume"), 405),
        ("a get of refresh", get("/api/lists/refresh"), 405),
        (
            "a get of pause with a body",
            Request {
                body: b"{\"minutes\": 5}".to_vec(),
                ..get("/api/pause")
            },
            405,
        ),
        (
            "a put",
            Request {
                method: "PUT",
                ..post("/api/pause", "{\"minutes\": 5}")
            },
            405,
        ),
        (
            "an update from another origin",
            post("/api/update", UPDATE_BODY).header("Origin", "http://evil.example"),
            403,
        ),
        (
            "an update from a null origin",
            post("/api/update", UPDATE_BODY).header("Origin", "null"),
            403,
        ),
        (
            "an update for a name that is not configured",
            post("/api/update", UPDATE_BODY).header("Host", "evil.example"),
            403,
        ),
        (
            "an update as plain text",
            post("/api/update", UPDATE_BODY).header("Content-Type", "text/plain"),
            415,
        ),
        (
            "an update without a content type",
            Request {
                headers: Vec::new(),
                ..post("/api/update", UPDATE_BODY)
            },
            415,
        ),
        (
            "an update body over 1 KiB",
            post(
                "/api/update",
                &format!(
                    "{{\"version\": \"9.9.9\", \"padding\": \"{}\"}}",
                    "x".repeat(1100)
                ),
            ),
            413,
        ),
        ("a get of update", get("/api/update"), 405),
        (
            "a put of update",
            Request {
                method: "PUT",
                ..post("/api/update", UPDATE_BODY)
            },
            405,
        ),
        ("a post of a read", post("/api/status", "{}"), 405),
        ("a post of the page", post("/", "{}"), 405),
    ]
}

async fn assert_mutations_are_rejected(site: &Site, credentials: Option<&str>) {
    for (what, request, status) in rejected_mutations() {
        let request = match credentials {
            Some(credentials) => request.signed_in(credentials),
            None => request,
        };

        let reply = site.send(request).await;

        assert_eq!(reply.status, status, "{what}");
        assert!(!site.is_paused(), "{what} paused blocking");
        assert_nothing_was_started(site, what);
    }
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
async fn status_shows_the_version_with_and_without_a_password() {
    let (with_password, _upstream) = plain_site().await;
    let (without_password, _other) = open_site().await;

    for site in [&with_password, &without_password] {
        let status = site.send(get("/api/status")).await.json();

        assert_eq!(status["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(status["update"]["build"], Build::current().name());
        for absent in ["latest", "notes", "how"] {
            assert!(status["update"].get(absent).is_none(), "{absent}");
        }
    }
}

#[tokio::test]
async fn status_shows_a_newer_version_with_notes_and_command() {
    let (with_password, _upstream) = plain_site().await;
    let (without_password, _other) = open_site().await;

    for site in [&with_password, &without_password] {
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
        Arc::new(|_| Box::pin(async { Err(io::Error::other("no DNS in this test")) })),
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

const SET_A_PASSWORD: &str = "set web.user and web.password to use this";

#[tokio::test]
async fn without_a_password_the_page_shows_totals_and_lists_and_nothing_else() {
    let (site, _upstream) = open_site().await;
    ask(&site.dns, "ads.example.", RecordType::A).await;
    ask(&site.dns, "ok.example.", RecordType::A).await;

    assert_eq!(site.send(get("/")).await.status, 200);
    assert_eq!(site.send(get("/api/lists")).await.status, 200);

    let reply = site.send(get("/api/status")).await;
    let status = reply.json();

    assert_eq!(reply.status, 200);
    assert_eq!(status["counters"]["total"], 2);
    assert_eq!(status["blocked_percent"], 50.0);
    assert!(status["lists"].is_array());
    assert_eq!(status["limited"], SET_A_PASSWORD);
    for private in ["top_queried", "top_blocked", "top_clients"] {
        assert!(status.get(private).is_none(), "{private}");
    }
    assert!(!reply.body.contains("ads.example"));
}

#[tokio::test]
async fn without_a_password_the_log_and_every_change_are_forbidden() {
    let (site, _upstream) = open_site().await;
    ask(&site.dns, "ads.example.", RecordType::A).await;

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

    for (what, request) in [
        ("pause", post("/api/pause", "{\"minutes\": 5}")),
        ("resume", post("/api/resume", "")),
        ("refresh", post("/api/lists/refresh", "")),
        ("update", post("/api/update", UPDATE_BODY)),
        ("a get of pause", get("/api/pause")),
    ] {
        let reply = site.send(request).await;

        assert_eq!(reply.status, 403, "{what}");
        assert_eq!(reply.json()["error"], SET_A_PASSWORD, "{what}");
    }

    assert!(!site.is_paused());
}

#[tokio::test]
async fn with_a_password_the_status_keeps_its_top_lists_and_is_not_limited() {
    let (site, _upstream) = plain_site().await;
    ask(&site.dns, "ads.example.", RecordType::A).await;

    let status = site.send(get("/api/status")).await.json();

    assert!(status.get("limited").is_none());
    for private in ["top_queried", "top_blocked", "top_clients"] {
        assert!(status.get(private).is_some(), "{private}");
    }
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
    let site = full_site(config).await;

    for (what, request, _) in rejected_mutations() {
        let target = request.path.clone();
        let reply = site.send(request).await;

        // A path that no password guards keeps its own answer for a bad method.
        let expected = if matches!(target.as_str(), "/api/status" | "/") {
            405
        } else {
            403
        };
        assert_eq!(reply.status, expected, "{what}");
        assert!(!site.is_paused(), "{what} paused blocking");
        assert_nothing_was_started(&site, what);
    }
}

#[tokio::test]
async fn unsafe_mutations_are_rejected_with_a_password_and_valid_credentials() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    with_credentials(&mut config);
    let site = full_site(config).await;

    assert_mutations_are_rejected(&site, Some(ADMIN)).await;
}

#[tokio::test]
async fn a_get_of_a_mutation_names_the_method_that_works() {
    let (site, _upstream) = plain_site().await;

    let reply = site.send(get("/api/pause")).await;
    let read = site.send(post("/api/status", "{}")).await;

    assert_eq!(reply.header("allow"), Some("POST"));
    assert_eq!(read.header("allow"), Some("GET"));
}

#[tokio::test]
async fn the_page_and_every_endpoint_need_the_password_when_one_is_set() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    with_credentials(&mut config);
    let mut site = site(config).await;
    site.signs_in = false;
    let reads = ["/", "/api/status", "/api/querylog", "/api/lists"];
    let changes = [
        ("/api/pause", "{\"minutes\": 5}"),
        ("/api/resume", ""),
        ("/api/lists/refresh", ""),
        ("/api/update", UPDATE_BODY),
    ];

    let sign_in_attempts = [
        None,
        Some(WRONG_PASSWORD),
        Some(OTHER_USER),
        Some("YWRtaW46czNjcmU="),
        Some("YWRtaW46czNjcmV0eA=="),
        Some(""),
    ];
    for attempt in sign_in_attempts {
        let signed = |request: Request| match attempt {
            Some(credentials) => request.signed_in(credentials),
            None => request,
        };

        for path in reads {
            let reply = site.send(signed(get(path))).await;
            assert_eq!(reply.status, 401, "{path} {attempt:?}");
            assert_eq!(
                reply.header("www-authenticate"),
                Some("Basic realm=\"picoguard\"")
            );
            assert!(!reply.body.contains("counters") && !reply.body.contains("<html"));
        }

        for (path, body) in changes {
            let reply = site.send(signed(post(path, body))).await;
            assert_eq!(reply.status, 401, "{path} {attempt:?}");
        }
    }

    assert!(!site.is_paused());

    for path in reads {
        let reply = site.send(get(path).signed_in(ADMIN)).await;
        assert_eq!(reply.status, 200, "{path}");
    }

    let lowercase_scheme = get("/api/status").header("Authorization", &format!("basic {ADMIN}"));
    assert_eq!(site.send(lowercase_scheme).await.status, 200);

    let paused = site
        .send(post("/api/pause", "{\"minutes\": 5}").signed_in(ADMIN))
        .await;
    assert_eq!(paused.status, 200);
    assert!(site.is_paused());
    let resumed = site.send(post("/api/resume", "").signed_in(ADMIN)).await;
    assert_eq!(resumed.status, 200);
    assert!(!site.is_paused());
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

    let reply = parse_reply(&bytes);
    assert!(reply.is_none_or(|reply| reply.status == 403 || reply.status == 400));
}

#[tokio::test]
async fn oversized_request_heads_are_refused() {
    let (site, _upstream) = plain_site().await;
    let long_value = "x".repeat(20 * 1024);
    let many_headers: Vec<(String, String)> = (0..100)
        .map(|index| (format!("X-Header-{index}"), "v".to_string()))
        .collect();

    let mut with_long = get("/api/status");
    with_long = with_long.header("X-Long", &long_value);
    let mut with_many = get("/api/status");
    with_many.headers.extend(many_headers);

    for (what, request) in [("a long header", with_long), ("many headers", with_many)] {
        let bytes = exchange(site.web, &request.bytes(site.web)).await;
        let status = parse_reply(&bytes).map(|reply| reply.status);

        assert!(
            status.is_none_or(|status| status >= 400),
            "{what}: {status:?}"
        );
    }

    let after = site.send(get("/api/status")).await;
    assert_eq!(after.status, 200, "the server still answers");
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
    assert!(!site.is_paused());
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
