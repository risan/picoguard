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
use picoguard::lists::Downloader;
use picoguard::password::PasswordHash;
use picoguard::policy::Policy;
use picoguard::scheduler::{Action, ListControl, Scheduler, Timing};
use picoguard::settings;
use picoguard::stage::{StageSetup, StageTiming, Stager};
use picoguard::stats::{Event, QueryResult};
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
        Arc::new(|_| Box::pin(async { Err(io::Error::other("no DNS in this test")) })),
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
    site_saving(config, kind, None).await
}

/// A site whose state folder holds `saved` as its settings file before it starts. The state
/// folder is the stager's, as in the server.
async fn site_saving(mut config: Config, kind: SiteKind, saved: Option<&str>) -> Site {
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
        Arc::new(|_| Box::pin(async { Err(io::Error::other("no DNS in this test")) })),
        Arc::new(Tls::with_webpki_roots()),
    );
    let web_state = Web::new(
        &config,
        Arc::clone(&dns.pipeline),
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
    assert_eq!(
        reply.header("content-security-policy"),
        Some(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
             connect-src 'self'"
        )
    );
    // No answer ever grants a cross-origin read.
    assert!(reply.header("access-control-allow-origin").is_none());
}

/// The page's ceiling for release 2, raised on purpose for the settings: static bytes in the
/// binary, no memory at run time.
const PAGE_HARD_CAP_BYTES: usize = 64 * 1024;

/// This part, the settings tab; a later part raises it on purpose, never past the cap.
const PAGE_BUDGET_BYTES: usize = 34 * 1024;

#[tokio::test]
async fn the_page_is_small_self_contained_and_fits_phone_and_dark_mode() {
    let (site, _upstream) = plain_site().await;

    let page = site.send(get("/")).await.body;

    assert!(
        page.len() <= PAGE_BUDGET_BYTES,
        "this slice's budget is {PAGE_BUDGET_BYTES} bytes, the page has {}",
        page.len()
    );
    assert!(
        page.len() <= PAGE_HARD_CAP_BYTES,
        "the hard cap is {PAGE_HARD_CAP_BYTES} bytes, the page has {}",
        page.len()
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
        "/api/login",
        "/api/logout",
        "/api/cache/clear",
        "/api/rules",
        "/api/rules/remove",
        "/api/explain?name=",
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

/// No browser here: the sign-in flow is checked as source, and in the build's browser check.
#[tokio::test]
async fn the_page_signs_in_with_its_own_form_and_never_asks_for_the_browser_prompt() {
    let (site, _upstream) = plain_site().await;

    let page = site.send_as_is(get("/")).await.body;

    for needed in [
        "id=\"login-form\"",
        "id=\"login-user\"",
        "id=\"login-password\"",
        "type=\"password\"",
        "autocomplete=\"current-password\"",
        "id=\"login-note\"",
        "id=\"logout\"",
        "class=\"signed-out\"",
        "\"X-Requested-With\": \"picoguard\"",
        "authEpoch",
        "authBusy",
        "\"Session ended, sign in again.\"",
    ] {
        assert!(page.contains(needed), "the page lacks {needed}");
    }
}

/// No browser here: the tab code is checked as source. A tab is a `[data-tab]` button and a
/// `[data-panel]` panel, and no element id equals a tab name, so a fragment never scrolls.
#[tokio::test]
async fn the_page_has_four_tabs_kept_in_the_url_fragment() {
    let (site, _upstream) = plain_site().await;

    let page = site.send(get("/")).await.body;

    for needed in ["role=\"tablist\"", "aria-selected", "\"hashchange\""] {
        assert!(page.contains(needed), "the page lacks {needed}");
    }

    for tab in ["dashboard", "log", "lists", "settings"] {
        assert!(page.contains(&format!("data-tab=\"{tab}\"")), "{tab}");
        assert!(page.contains(&format!("id=\"panel-{tab}\"")), "{tab}");
        assert!(
            !page.contains(&format!("id=\"{tab}\"")),
            "{tab} is a fragment target"
        );
    }
}

/// No browser here: the Upstreams card is checked as source. The read-only view leaves the
/// field out, so the card is hidden there with the top lists.
#[tokio::test]
async fn the_dashboard_has_an_upstreams_card_drawn_as_text() {
    let (site, _upstream) = plain_site().await;

    let page = site.send(get("/")).await.body;

    for needed in [
        "id=\"upstreams\"",
        "id=\"upstream-table\"",
        "showUpstreams(status.upstreams)",
        "\"local: \"",
        "\"\\u2014\"",
        "th:not(:first-child)",
        "[\"pause\", \"tops\", \"upstreams\"",
    ] {
        assert!(page.contains(needed), "the page lacks {needed}");
    }
}

#[tokio::test]
async fn the_dashboard_has_a_cache_card_with_a_confirmed_clear_button() {
    let (site, _upstream) = plain_site().await;

    let page = site.send(get("/")).await.body;

    for needed in [
        "id=\"cache\"",
        "id=\"cache-size\"",
        "id=\"clear-cache\"",
        "id=\"cache-note\"",
        "\"/api/cache/clear\"",
        "showCache(status.cache)",
        "\"Cache cleared (\"",
        "\"Clear the DNS cache?",
        "\"upstreams\", \"cache\"",
    ] {
        assert!(page.contains(needed), "the page lacks {needed}");
    }
}

/// No browser here: the names are checked as source, and in the build's browser check. The
/// ban on `innerHTML` in the page test covers markup.
#[tokio::test]
async fn the_clients_show_their_name_beside_the_ip_as_text() {
    let (site, _upstream) = plain_site().await;

    let page = site.send(get("/")).await.body;

    for needed in [
        "function who(",
        "who(e.name, e.key)",
        "who(e.name, e.client)",
        ".ip {",
    ] {
        assert!(page.contains(needed), "the page lacks {needed}");
    }
}

#[tokio::test]
async fn the_query_log_rows_offer_block_allow_and_why() {
    let (site, _upstream) = plain_site().await;

    let page = site.send(get("/")).await.body;

    for needed in [
        "data-act",
        "\"Block\"",
        "\"Allow\"",
        "\"Why\"",
        "blocked_response",
        "\"/api/rules\"",
        "location.hash = \"lists\"",
        "checkName(",
    ] {
        assert!(page.contains(needed), "the page lacks {needed}");
    }
}

#[tokio::test]
async fn the_lists_tab_has_your_rules_and_a_name_check() {
    let (site, _upstream) = plain_site().await;

    let page = site.send(get("/")).await.body;

    for id in [
        "rules",
        "rule-count",
        "rule-table",
        "config-rules",
        "check",
        "check-form",
        "check-name",
        "check-result",
    ] {
        assert!(
            page.contains(&format!("id=\"{id}\"")),
            "the page lacks #{id}"
        );
    }

    for needed in [
        "\"/api/rules/remove\"",
        "\"/api/explain?name=\" + encodeURIComponent(",
        "Saved on this device.",
        "\"refresh-row\", \"rules\", \"check\"]",
    ] {
        assert!(page.contains(needed), "the page lacks {needed}");
    }
}

/// No browser here: the tab is checked as source. Its cards come with the parts that apply
/// them; this part shows where settings are saved and why a saved file is not used.
#[tokio::test]
async fn the_settings_tab_says_where_settings_are_saved_and_why_they_are_not_used() {
    let (site, _upstream) = plain_site().await;

    let page = site.send(get("/")).await.body;

    for id in [
        "tab-settings",
        "settings-note",
        "settings-file",
        "rules-note",
    ] {
        assert!(
            page.contains(&format!("id=\"{id}\"")),
            "the page lacks #{id}"
        );
    }

    for needed in [
        "api(\"/api/settings\")",
        "showSettings(",
        "\"Saved settings could not be used: \"",
        "\". Saving from this page replaces them.\"",
        "s.can_save",
        "\"tab-log\", \"tab-settings\"",
        "#settings-file { overflow-wrap: anywhere; }",
    ] {
        assert!(page.contains(needed), "the page lacks {needed}");
    }
}

/// No browser here: the chart is checked as source. The SVG namespace is read from the markup,
/// because its literal contains `http://`, which the page must never contain.
#[tokio::test]
async fn the_chart_is_inline_svg_drawn_with_create_element_ns() {
    let (site, _upstream) = plain_site().await;

    let page = site.send(get("/")).await.body;

    for needed in [
        "<svg id=\"chart\"",
        "createElementNS(",
        ".namespaceURI",
        "id=\"chart-readout\"",
    ] {
        assert!(page.contains(needed), "the page lacks {needed}");
    }
}

/// No browser here: the form's source is checked. `pause_takes_one_to_1440_minutes_and_nothing_else`
/// pins the same limits on the server.
#[tokio::test]
async fn the_pause_form_sends_only_whole_minutes_from_1_to_1440() {
    let (site, _upstream) = plain_site().await;

    let page = site.send(get("/")).await.body;

    for needed in [
        "id=\"pause-form\"",
        "novalidate",
        "id=\"pause-minutes\"",
        "type=\"number\"",
        "min=\"1\"",
        "max=\"1440\"",
        "Number.isInteger(",
        "\"1 to 1440 minutes\"",
    ] {
        assert!(page.contains(needed), "the page lacks {needed}");
    }
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

fn upstream_entries(status: &Value) -> &Vec<Value> {
    status["upstreams"].as_array().unwrap()
}

#[tokio::test]
async fn a_failed_over_query_counts_a_failure_on_the_first_server_and_an_answer_on_the_second() {
    let dead = fake_upstream(|_| Vec::new()).await;
    let slow = answering_upstream([9, 9, 9, 9], Duration::from_millis(80)).await;
    let mut config = local_config(&slow);
    config.upstream.servers = vec![
        format!("udp://{}", dead.address),
        format!("udp://{}", slow.address),
    ];
    config.upstream.timeout_ms = 1000;
    let site = site(config).await;

    // Which server goes first is a weighted draw; the dead one is the first try often enough.
    let mut asked = 0;
    let started = Instant::now();
    while dead.count() == 0 {
        assert!(asked < 40, "the dead server was never tried");

        ask(&site.dns, &format!("n{asked}.example."), RecordType::A).await;
        asked += 1;
    }
    let asking_ms = started.elapsed().as_secs_f64() * 1000.0;

    let status = site.send(get("/api/status")).await.json();
    let servers = upstream_entries(&status);

    assert_eq!(servers[0]["label"], format!("udp://{}", dead.address));
    assert_eq!(servers[0]["answered"], 0);
    assert_eq!(servers[0]["failed"], 1);
    assert!(servers[0]["avg_ms"].is_null());
    assert_eq!(servers[1]["answered"], asked);
    assert_eq!(servers[1]["failed"], 0);
    let average = servers[1]["avg_ms"].as_f64().unwrap();
    // Each try at the dead server takes at least 500 ms (half the 1000 ms timeout) of the wall
    // time that the answered exchanges share it with, however loaded the machine is. A time that
    // counted those tries too would not leave that much out.
    let answered_ms = average * asked as f64;
    assert!(average >= 80.0, "{average}");
    assert!(
        answered_ms < asking_ms - 400.0,
        "{answered_ms} answered of {asking_ms}"
    );
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
async fn the_cache_size_is_shown_only_when_signed_in() {
    let (with_password, _upstream) = plain_site().await;
    let (without_password, _other) = open_site().await;

    let signed_in = with_password.send(get("/api/status")).await.json();
    let read_only = without_password.send(get("/api/status")).await.json();

    let mut keys: Vec<&str> = signed_in["cache"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["bytes", "entries"]);
    assert!(read_only.get("cache").is_none());
}

#[tokio::test]
async fn the_upstreams_show_with_a_password_and_are_left_out_without_one() {
    let (with_password, upstream) = plain_site().await;
    let (without_password, _other) = open_site().await;

    let signed_in = with_password.send(get("/api/status")).await.json();
    let read_only = without_password.send(get("/api/status")).await;

    assert!(signed_in.get("limited").is_none());
    assert_eq!(
        upstream_entries(&signed_in)[0]["label"],
        format!("udp://{}", upstream.address)
    );
    assert_eq!(read_only.json()["limited"], SET_A_PASSWORD);
    assert!(read_only.json().get("upstreams").is_none());
    assert!(!read_only.body.contains("udp://"));
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
async fn loopback_and_public_clients_are_never_looked_up() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let router = fake_upstream(|query| {
        let owner = query.queries[0].name().clone();
        let data = RData::PTR(PTR(name("any.lan.")));

        vec![(
            Duration::ZERO,
            reply_to(query, vec![Record::from_rdata(owner, 600, data)]),
        )]
    })
    .await;
    let mut config = local_config(&upstream);
    config.local.resolver = Some(router.address);
    let site = site(config).await;
    for client in ["8.8.8.8", "2001:db8::1", "::ffff:8.8.8.8", "::1"] {
        record_client(&site, client, "a.example.");
    }

    ask(&site.dns, "ok.example.", RecordType::A).await;

    for _ in 0..3 {
        let (status, log) = status_and_log(&site).await;

        assert_eq!(
            status["top_clients"]["entries"].as_array().unwrap().len(),
            5
        );
        assert_every_name_is_null(&status, &log);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert_eq!(router.count(), 0);
}

#[tokio::test]
async fn ten_polls_of_one_client_send_one_lookup() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let router = router(&[]).await;
    let mut config = local_config(&upstream);
    config.local.resolver = Some(router.address);
    let site = site(config).await;
    record_client(&site, "192.168.110.50", "a.example.");

    for _ in 0..10 {
        let (status, log) = status_and_log(&site).await;

        assert_every_name_is_null(&status, &log);
    }

    let started = Instant::now();
    while router.count() == 0 {
        assert!(started.elapsed() < Duration::from_secs(3), "no lookup");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(router.count(), 1);
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
        (
            "a login from another origin",
            login("admin", "s3cret").header("Origin", "http://evil.example"),
            403,
        ),
        (
            "a login from a null origin",
            login("admin", "s3cret").header("Origin", "null"),
            403,
        ),
        (
            "a login for a name that is not configured",
            login("admin", "s3cret").header("Host", "evil.example"),
            403,
        ),
        (
            "a login as plain text",
            login("admin", "s3cret").header("Content-Type", "text/plain"),
            415,
        ),
        (
            "a login without a content type",
            Request {
                headers: Vec::new(),
                ..login("admin", "s3cret")
            },
            415,
        ),
        (
            "a login body over 1 KiB",
            post(
                "/api/login",
                &format!(
                    "{{\"user\": \"admin\", \"password\": \"s3cret\", \"padding\": \"{}\"}}",
                    "x".repeat(1100)
                ),
            ),
            413,
        ),
        (
            "a get of login",
            Request {
                method: "GET",
                ..login("admin", "s3cret")
            },
            405,
        ),
        (
            "a put of login",
            Request {
                method: "PUT",
                ..login("admin", "s3cret")
            },
            405,
        ),
        (
            "a logout from another origin",
            post("/api/logout", "{}").header("Origin", "http://evil.example"),
            403,
        ),
        (
            "a logout from a null origin",
            post("/api/logout", "{}").header("Origin", "null"),
            403,
        ),
        (
            "a logout for a name that is not configured",
            post("/api/logout", "{}").header("Host", "evil.example"),
            403,
        ),
        (
            "a logout as plain text",
            post("/api/logout", "{}").header("Content-Type", "text/plain"),
            415,
        ),
        (
            "a logout without a content type",
            Request {
                headers: Vec::new(),
                ..post("/api/logout", "{}")
            },
            415,
        ),
        ("a logout body over 1 KiB", post("/api/logout", &big), 413),
        ("a get of logout", get("/api/logout"), 405),
        (
            "a put of logout",
            Request {
                method: "PUT",
                ..post("/api/logout", "{}")
            },
            405,
        ),
        (
            "a cache clear from another origin",
            post("/api/cache/clear", "{}").header("Origin", "http://evil.example"),
            403,
        ),
        (
            "a cache clear from a null origin",
            post("/api/cache/clear", "{}").header("Origin", "null"),
            403,
        ),
        (
            "a cache clear to a name that is not configured",
            post("/api/cache/clear", "{}").header("Host", "evil.example"),
            403,
        ),
        (
            "a cache clear as plain text",
            post("/api/cache/clear", "{}").header("Content-Type", "text/plain"),
            415,
        ),
        (
            "a cache clear without a content type",
            Request {
                headers: Vec::new(),
                ..post("/api/cache/clear", "{}")
            },
            415,
        ),
        (
            "a cache clear body over 1 KiB",
            post("/api/cache/clear", &big),
            413,
        ),
        ("a get of cache clear", get("/api/cache/clear"), 405),
        (
            "a put of cache clear",
            Request {
                method: "PUT",
                ..post("/api/cache/clear", "{}")
            },
            405,
        ),
        (
            "a rule from another origin",
            post("/api/rules", RULE_BODY).header("Origin", "http://evil.example"),
            403,
        ),
        (
            "a rule from a null origin",
            post("/api/rules", RULE_BODY).header("Origin", "null"),
            403,
        ),
        (
            "a rule for a name that is not configured",
            post("/api/rules", RULE_BODY).header("Host", "evil.example"),
            403,
        ),
        (
            "a rule as plain text",
            post("/api/rules", RULE_BODY).header("Content-Type", "text/plain"),
            415,
        ),
        (
            "a rule without a content type",
            Request {
                headers: Vec::new(),
                ..post("/api/rules", RULE_BODY)
            },
            415,
        ),
        (
            "a rule body over 1 KiB",
            post(
                "/api/rules",
                &format!(
                    "{{\"name\": \"x.example\", \"action\": \"block\", \"padding\": \"{}\"}}",
                    "x".repeat(1100)
                ),
            ),
            413,
        ),
        (
            "a put of rules",
            Request {
                method: "PUT",
                ..post("/api/rules", RULE_BODY)
            },
            405,
        ),
        (
            "a removal from another origin",
            post("/api/rules/remove", REMOVE_BODY).header("Origin", "http://evil.example"),
            403,
        ),
        (
            "a removal from a null origin",
            post("/api/rules/remove", REMOVE_BODY).header("Origin", "null"),
            403,
        ),
        (
            "a removal for a name that is not configured",
            post("/api/rules/remove", REMOVE_BODY).header("Host", "evil.example"),
            403,
        ),
        (
            "a removal as plain text",
            post("/api/rules/remove", REMOVE_BODY).header("Content-Type", "text/plain"),
            415,
        ),
        (
            "a removal without a content type",
            Request {
                headers: Vec::new(),
                ..post("/api/rules/remove", REMOVE_BODY)
            },
            415,
        ),
        (
            "a removal body over 1 KiB",
            post(
                "/api/rules/remove",
                &format!(
                    "{{\"name\": \"x.example\", \"padding\": \"{}\"}}",
                    "x".repeat(1100)
                ),
            ),
            413,
        ),
        ("a get of removal", get("/api/rules/remove"), 405),
        (
            "a put of removal",
            Request {
                method: "PUT",
                ..post("/api/rules/remove", REMOVE_BODY)
            },
            405,
        ),
    ]
}

const RULE_BODY: &str = "{\"name\":\"x.example\",\"action\":\"block\"}";
const REMOVE_BODY: &str = "{\"name\":\"x.example\"}";

/// True when no rule was added from the page.
async fn no_page_rules(site: &Site) -> bool {
    site.control.with_button_rules(<[_]>::is_empty).await
}

async fn assert_mutations_are_rejected(site: &Site, sign_in: impl Fn(Request) -> Request) {
    let cached = cache_one_answer(site).await;

    for (what, request, status) in rejected_mutations() {
        let reply = site.send_as_is(sign_in(request)).await;

        assert_eq!(reply.status, status, "{what}");
        assert_eq!(reply.header("set-cookie"), None, "{what} set a cookie");
        assert!(!site.is_paused(), "{what} paused blocking");
        assert_nothing_was_started(site, what);
        assert_cache_kept(site, cached, what);
        assert!(no_page_rules(site).await, "{what} added a rule");
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

const SET_A_PASSWORD: &str = "set web.user and web.password_hash (or web.password) to use this";

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
    let cached = cache_one_answer(&site).await;

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
        ("login", login("admin", "s3cret")),
        ("logout", post("/api/logout", "{}")),
        ("clear cache", post("/api/cache/clear", "{}")),
        ("add a rule", post("/api/rules", RULE_BODY)),
        ("remove a rule", post("/api/rules/remove", REMOVE_BODY)),
        ("the rules", get("/api/rules")),
        ("explain", get("/api/explain?name=ads.example")),
        ("the settings", get("/api/settings")),
        ("a settings change", post("/api/settings", "{}")),
    ] {
        let reply = site.send(request).await;

        assert_eq!(reply.status, 403, "{what}");
        assert_eq!(reply.json()["error"], SET_A_PASSWORD, "{what}");
    }

    assert!(!site.is_paused());
    assert_cache_kept(&site, cached, "a forbidden change");
    assert!(no_page_rules(&site).await);
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
    let cached = cache_one_answer(&site).await;

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
        assert_cache_kept(&site, cached, what);
        assert!(no_page_rules(&site).await, "{what} added a rule");
    }
}

#[tokio::test]
async fn unsafe_mutations_are_rejected_with_a_password_and_valid_credentials() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut config = local_config(&upstream);
    with_credentials(&mut config);
    let site = full_site(config).await;

    assert_mutations_are_rejected(&site, |request| request.signed_in(ADMIN)).await;
}

#[tokio::test]
async fn unsafe_mutations_are_rejected_with_a_session_cookie() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let site = full_site(local_config(&upstream)).await;
    let token = site
        .send_as_is(login("admin", "s3cret"))
        .await
        .session()
        .unwrap();

    assert_mutations_are_rejected(&site, |request| request.with_session(&token)).await;
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
    let (site, _upstream) = plain_site().await;
    let reads = [
        "/api/status",
        "/api/querylog",
        "/api/lists",
        "/api/rules",
        "/api/explain?name=ads.example",
    ];
    let changes = [
        ("/api/pause", "{\"minutes\": 5}"),
        ("/api/resume", ""),
        ("/api/lists/refresh", ""),
        ("/api/update", UPDATE_BODY),
        ("/api/cache/clear", "{}"),
        ("/api/rules", RULE_BODY),
        ("/api/rules/remove", REMOVE_BODY),
    ];
    let requests = || {
        reads
            .iter()
            .map(|path| get(path))
            .chain(changes.iter().map(|(path, body)| post(path, body)))
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

    assert!(!site.is_paused());
    assert!(no_page_rules(&site).await);

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
    // Met twice by the save: once when the file is written, once to let it be renamed.
    let rename = Arc::new(std::sync::Barrier::new(2));
    let hook = Arc::clone(&rename);
    site.control.saved().run_before_rename(move || {
        hook.wait();
        hook.wait();
    });
    let meet = || {
        let rename = Arc::clone(&rename);
        tokio::task::spawn_blocking(move || {
            rename.wait();
        })
    };
    let request = post("/api/rules", &rule_body("left.example", "block")).signed_in(ADMIN);
    let mut stream = TcpStream::connect(site.web).await.unwrap();
    stream.write_all(&request.bytes(site.web)).await.unwrap();

    tokio::time::timeout(Duration::from_secs(5), meet())
        .await
        .expect("the save never reached the rename")
        .unwrap();
    drop(stream);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let before = ask(&site.dns, "left.example.", RecordType::A).await;
    assert_eq!(
        addresses(&before),
        ["9.9.9.9"],
        "in force before it was saved"
    );
    meet().await.unwrap();

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
        "{\"version\": 1, \"safe_search\": true, \"cache\": {\"max_entries\": 500, \
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
async fn a_settings_change_of_a_key_not_editable_yet_is_refused_and_nothing_is_written() {
    let (site, _upstream) = plain_site().await;

    for (key, value) in [
        (
            "upstream",
            serde_json::json!({"servers": ["https://9.9.9.9/dns-query"], "bootstrap": []}),
        ),
        (
            "cache",
            serde_json::json!({"max_entries": 1, "max_bytes": 262144, "min_ttl": 0,
                               "max_ttl": 60, "optimistic": true}),
        ),
        (
            "rewrites",
            serde_json::json!([{"name": "nas.lan", "answer": "10.0.0.1"}]),
        ),
        ("safe_search", serde_json::json!(true)),
        ("services", serde_json::json!(["tiktok"])),
        ("safe_search", Value::Null),
    ] {
        let body = serde_json::json!({ key: value }).to_string();

        let reply = site.send(post("/api/settings", &body)).await;

        assert_eq!(reply.status, 409, "{body}: {}", reply.body);
        assert_eq!(
            reply.json()["error"],
            format!("{key} is not editable yet"),
            "{body}"
        );
    }

    for body in [
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
async fn a_settings_change_of_nothing_writes_nothing_and_answers_the_settings() {
    let (site, _upstream) = plain_site().await;

    let changed = site.send(post("/api/settings", "{}")).await;

    assert_eq!(changed.status, 200);
    assert_eq!(changed.json(), site.send(get("/api/settings")).await.json());
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
