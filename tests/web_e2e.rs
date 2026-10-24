//! The status page and its API over real sockets: each endpoint, basic auth, the access policy
//! (peer, `Host`, `Origin`, content type, body size, method), pause and the manual refresh.
//! Nothing leaves the machine.

mod common;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::harness::{Running, answering_upstream, ask, config_for, start_with_policy};
use common::http::ListServer;
use hickory_proto::rr::RecordType;
use picoguard::config::{Config, ListConfig, ListFormat};
use picoguard::filter::compile::CompileWorker;
use picoguard::filter::snapshot::SnapshotStore;
use picoguard::lists::Downloader;
use picoguard::policy::Policy;
use picoguard::scheduler::{Scheduler, Timing};
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
}

impl Site {
    async fn send(&self, request: Request) -> Reply {
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

    config
}

fn with_credentials(config: &mut Config) {
    config.web.user = Some("admin".to_string());
    config.web.password = Some("s3cret".to_string());
}

/// A scheduler that refreshes nothing by itself for a day, so a refresh is always asked for.
fn day_long_timing() -> Timing {
    Timing {
        hour: Duration::from_secs(3600),
        retries: [Duration::from_secs(3600); 4],
        first_check: Duration::from_secs(3600 * 1000),
    }
}

async fn site(config: Config) -> Site {
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
    let web_state = Web::new(
        &config,
        Arc::clone(dns.pipeline.stats()),
        Arc::clone(&policy),
        Arc::clone(&control),
    )
    .unwrap();
    web::spawn(listeners, Arc::new(web_state));

    Site {
        web: address,
        dns,
        policy,
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

#[tokio::test]
async fn the_page_is_small_self_contained_and_fits_phone_and_dark_mode() {
    let (site, _upstream) = plain_site().await;

    let page = site.send(get("/")).await.body;

    assert!(page.len() < 15 * 1024, "{} bytes", page.len());
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
        "setInterval(update, 5000)",
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
    }
}

#[tokio::test]
async fn unsafe_mutations_are_rejected_without_a_password() {
    let (site, _upstream) = plain_site().await;

    assert_mutations_are_rejected(&site, None).await;
}

#[tokio::test]
async fn unsafe_mutations_are_rejected_with_a_password_and_valid_credentials() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    with_credentials(&mut config);
    let site = site(config).await;

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
    let site = site(config).await;
    let reads = ["/", "/api/status", "/api/querylog", "/api/lists"];
    let changes = [
        ("/api/pause", "{\"minutes\": 5}"),
        ("/api/resume", ""),
        ("/api/lists/refresh", ""),
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
    assert!(!site.is_paused());
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
    assert!(!outside.is_paused());

    config.web.allow_from = vec!["::1/128".parse().unwrap()];
    let inside = site(config).await;

    let reply = inside.send(get("/api/status")).await;
    assert_eq!(reply.status, 200);
    let paused = inside.send(post("/api/pause", "{\"minutes\": 5}")).await;
    assert_eq!(paused.status, 200);
}
