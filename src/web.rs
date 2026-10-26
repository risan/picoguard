//! The status page and its JSON API (plan D16). One HTML page, five reads and three
//! mutations. A web page on another device of the LAN must not be able to pause blocking, so
//! every request passes the access policy before it reaches a handler:
//!
//! - a peer outside `web.allow_from` is closed before a byte is read;
//! - `Host` must be an IP address or a configured name, which defeats DNS rebinding;
//! - with a password configured, `Authorization` must match, compared in constant time;
//! - without a password the page is read-only and shows totals and list status only: the
//!   query log, the top lists and every change answer 403;
//! - a mutation must be `POST` with `Content-Type: application/json` (which a cross-site form
//!   cannot send, and a cross-site script can only send after a CORS preflight that is never
//!   answered), carry no `Origin` other than the page's own, and have a body of at most 1 KiB.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use ring::hmac;
use ring::rand::SystemRandom;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use crate::config::{Cidr, Config, ListFormat, WebConfig, is_allowed};
use crate::policy::Policy;
use crate::scheduler::{ListControl, ListStatus, Role};
use crate::server::bind_tcp;
use crate::stats::{Counters, HourlyBucket, QueryLogEntry, Stats, TopEntry};
use crate::update::{UpdateView, Updates};

const PAGE: &str = include_str!("web/index.html");

const MAX_BODY_BYTES: usize = 1024;
const MAX_CONNECTIONS: usize = 16;
/// The smallest buffer hyper accepts; it bounds the request line and headers together.
const MAX_HEAD_BYTES: usize = 8 * 1024;
const MAX_HEADERS: usize = 32;
const HEAD_TIMEOUT: Duration = Duration::from_secs(5);
/// A request and its response, slow clients included; one request per connection.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(100);

const MIN_PAUSE_MINUTES: u32 = 1;
const MAX_PAUSE_MINUTES: u32 = 24 * 60;
const DEFAULT_QUERY_LOG_LIMIT: usize = 100;
const PASSWORD_NEEDED: &str = "set web.user and web.password to use this";

/// Everything the handlers read or change.
pub struct Web {
    stats: Arc<Stats>,
    policy: Arc<Policy>,
    lists: Arc<ListControl>,
    updates: Arc<Updates>,
    allow_from: Vec<Cidr>,
    hostnames: Vec<String>,
    /// The `Authorization` credentials a client must send; `None` when no password is set.
    credentials: Option<Credentials>,
    query_log_entries: usize,
}

impl Web {
    pub fn new(
        config: &Config,
        stats: Arc<Stats>,
        policy: Arc<Policy>,
        lists: Arc<ListControl>,
        updates: Arc<Updates>,
    ) -> Result<Web, String> {
        let web = &config.web;
        let credentials = match (&web.user, &web.password) {
            (Some(user), Some(password)) => Some(Credentials::new(&base64(
                format!("{user}:{password}").as_bytes(),
            ))?),
            _ => None,
        };
        if credentials.is_none() {
            log::warn!(
                "the status page has no password: it shows totals and list status only. \
                 Set web.user and web.password for the query log, the top lists and pause."
            );
        }

        Ok(Web {
            stats,
            policy,
            lists,
            updates,
            allow_from: web.allow_from.clone(),
            hostnames: web.hostnames.clone(),
            credentials,
            query_log_entries: config.stats.query_log_entries,
        })
    }
}

pub struct WebListeners(Vec<TcpListener>);

impl WebListeners {
    /// Opens a listener on every configured address. An IPv6 address that cannot be used is
    /// skipped with a warning, like the DNS listeners; any other failure is an error.
    pub fn bind(web: &WebConfig) -> Result<WebListeners, String> {
        let mut listeners = Vec::new();

        for ip in &web.bind {
            let address = SocketAddr::new(*ip, web.port);

            match bind_tcp(address) {
                Ok(listener) => {
                    listeners.push(listener);
                }

                Err(error) if address.is_ipv6() => {
                    log::warn!("skipping {address} for the status page: {error}");
                }

                Err(error) => {
                    return Err(format!(
                        "cannot listen on {address} for the status page: {error}"
                    ));
                }
            }
        }

        if listeners.is_empty() {
            return Err("no address to serve the status page on".to_string());
        }

        Ok(WebListeners(listeners))
    }

    pub fn addresses(&self) -> Vec<SocketAddr> {
        self.0
            .iter()
            .filter_map(|listener| listener.local_addr().ok())
            .collect()
    }
}

/// Starts serving on the current runtime and returns at once.
pub fn spawn(listeners: WebListeners, web: Arc<Web>) {
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    for listener in listeners.0 {
        tokio::spawn(serve(listener, Arc::clone(&web), Arc::clone(&connections)));
    }
}

async fn serve(listener: TcpListener, web: Arc<Web>, connections: Arc<Semaphore>) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            tokio::time::sleep(ACCEPT_ERROR_PAUSE).await;

            continue;
        };

        // Dropping the stream closes it before a byte is read.
        if !is_allowed(&web.allow_from, peer.ip()) {
            continue;
        }

        let Ok(slot) = Arc::clone(&connections).try_acquire_owned() else {
            continue;
        };

        tokio::spawn(serve_connection(stream, Arc::clone(&web), slot));
    }
}

async fn serve_connection(stream: TcpStream, web: Arc<Web>, _slot: OwnedSemaphorePermit) {
    let service = service_fn(move |request| {
        let web = Arc::clone(&web);

        async move { Ok::<_, Infallible>(web.respond(request).await) }
    });

    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEAD_TIMEOUT)
        .max_buf_size(MAX_HEAD_BYTES)
        .max_headers(MAX_HEADERS)
        .keep_alive(false)
        .serve_connection(TokioIo::new(stream), service);

    let _ = timeout(CONNECTION_TIMEOUT, connection).await;
}

/// Answered to `GET`.
#[derive(Clone, Copy)]
enum Read {
    Page,
    Status,
    QueryLog,
    Lists,
}

/// Answered to `POST` only.
#[derive(Clone, Copy)]
enum Change {
    Pause,
    Resume,
    RefreshLists,
}

enum Route {
    Read(Read),
    Change(Change),
}

impl Route {
    fn of(path: &str) -> Option<Route> {
        match path {
            "/" => Some(Route::Read(Read::Page)),
            "/api/status" => Some(Route::Read(Read::Status)),
            "/api/querylog" => Some(Route::Read(Read::QueryLog)),
            "/api/lists" => Some(Route::Read(Read::Lists)),
            "/api/pause" => Some(Route::Change(Change::Pause)),
            "/api/resume" => Some(Route::Change(Change::Resume)),
            "/api/lists/refresh" => Some(Route::Change(Change::RefreshLists)),
            _ => None,
        }
    }

    /// Whether the page shows this only to a signed-in user: the query log, the top lists
    /// and every change.
    fn needs_password(&self) -> bool {
        match self {
            Route::Read(Read::QueryLog) | Route::Change(_) => true,
            Route::Read(Read::Page | Read::Status | Read::Lists) => false,
        }
    }
}

/// A request that is answered with an error and nothing else.
struct Rejection {
    status: StatusCode,
    message: &'static str,
    header: Option<(HeaderName, &'static str)>,
}

impl Rejection {
    fn new(status: StatusCode, message: &'static str) -> Rejection {
        Rejection {
            status,
            message,
            header: None,
        }
    }

    fn with_header(mut self, name: HeaderName, value: &'static str) -> Rejection {
        self.header = Some((name, value));

        self
    }

    fn into_response(self) -> Response<Full<Bytes>> {
        #[derive(Serialize)]
        struct Body {
            error: &'static str,
        }

        let mut response = json(
            self.status,
            &Body {
                error: self.message,
            },
        );
        if let Some((name, value)) = self.header {
            response
                .headers_mut()
                .insert(name, HeaderValue::from_static(value));
        }

        response
    }
}

impl Web {
    async fn respond(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        let response = match self.try_respond(request).await {
            Ok(response) => response,
            Err(rejection) => rejection.into_response(),
        };

        with_protective_headers(response)
    }

    async fn try_respond(
        &self,
        request: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Rejection> {
        let (head, body) = request.into_parts();
        let host = self.checked_host(&head.headers)?;
        self.check_credentials(&head.headers)?;

        let route = Route::of(head.uri.path())
            .ok_or_else(|| Rejection::new(StatusCode::NOT_FOUND, "no such page"))?;
        if route.needs_password() && self.credentials.is_none() {
            return Err(Rejection::new(StatusCode::FORBIDDEN, PASSWORD_NEEDED));
        }

        match route {
            Route::Read(read) => {
                if head.method != Method::GET {
                    return Err(method_not_allowed("GET"));
                }

                self.read(read, head.uri.query())
            }

            Route::Change(change) => {
                if head.method != Method::POST {
                    return Err(method_not_allowed("POST"));
                }

                check_origin(&head.headers, host)?;
                check_json_content_type(&head.headers)?;
                let body = read_body(&head.headers, body).await?;

                self.change(change, &body)
            }
        }
    }

    /// The `Host` header, if it names this server the way a client that knows its address
    /// would: an IP address or a configured name, with an optional port.
    fn checked_host<'a>(&self, headers: &'a HeaderMap) -> Result<&'a str, Rejection> {
        let host = headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .filter(|host| self.is_known_host(host));

        host.ok_or_else(|| {
            Rejection::new(
                StatusCode::FORBIDDEN,
                "use the address of this server, or a name listed in web.hostnames",
            )
        })
    }

    fn is_known_host(&self, authority: &str) -> bool {
        if let Some(rest) = authority.strip_prefix('[') {
            let Some((address, after)) = rest.split_once(']') else {
                return false;
            };

            return address.parse::<Ipv6Addr>().is_ok() && is_port_suffix(after);
        }

        let (host, suffix) = match authority.find(':') {
            Some(colon) => authority.split_at(colon),
            None => (authority, ""),
        };

        let is_known_name = host.parse::<Ipv4Addr>().is_ok()
            || self
                .hostnames
                .iter()
                .any(|name| name.eq_ignore_ascii_case(host));

        is_known_name && is_port_suffix(suffix)
    }

    fn check_credentials(&self, headers: &HeaderMap) -> Result<(), Rejection> {
        let Some(expected) = &self.credentials else {
            return Ok(());
        };

        let sent = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
            .map(|(_, credentials)| credentials.trim());

        if sent.is_some_and(|sent| expected.accepts(sent)) {
            return Ok(());
        }

        Err(Rejection::new(StatusCode::UNAUTHORIZED, "sign in")
            .with_header(header::WWW_AUTHENTICATE, "Basic realm=\"picoguard\""))
    }

    fn read(&self, read: Read, query: Option<&str>) -> Result<Response<Full<Bytes>>, Rejection> {
        match read {
            Read::Page => Ok(Response::builder()
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(Full::new(Bytes::from_static(PAGE.as_bytes())))
                .expect("static response is valid")),

            Read::Status => {
                let snapshot = self.stats.snapshot();
                let view = self.policy.view(Instant::now());
                let is_open = self.credentials.is_some();

                Ok(json(
                    StatusCode::OK,
                    &StatusView {
                        version: env!("CARGO_PKG_VERSION"),
                        update: self.updates.view(),
                        counters: &snapshot.counters,
                        blocked_percent: blocked_percent(&snapshot.counters),
                        hourly: &snapshot.hourly,
                        limited: (!is_open).then_some(PASSWORD_NEEDED),
                        top_queried: is_open.then(|| TopList::of(&snapshot.top_queried)),
                        top_blocked: is_open.then(|| TopList::of(&snapshot.top_blocked)),
                        top_clients: is_open.then(|| TopList::of(&snapshot.top_clients)),
                        lists: self.list_views(),
                        generation: view.generation,
                        pause: self.pause_view(),
                    },
                ))
            }

            Read::QueryLog => {
                let limit = self.query_log_limit(query)?;

                Ok(json(
                    StatusCode::OK,
                    &QueryLogView {
                        entries: self.stats.query_log(limit),
                    },
                ))
            }

            Read::Lists => Ok(json(
                StatusCode::OK,
                &ListsView {
                    lists: self.list_views(),
                },
            )),
        }
    }

    fn change(&self, change: Change, body: &[u8]) -> Result<Response<Full<Bytes>>, Rejection> {
        match change {
            Change::Pause => {
                let request: PauseRequest = serde_json::from_slice(body).map_err(|_| {
                    Rejection::new(StatusCode::BAD_REQUEST, "send {\"minutes\": 1 to 1440}")
                })?;
                if !(MIN_PAUSE_MINUTES..=MAX_PAUSE_MINUTES).contains(&request.minutes) {
                    return Err(Rejection::new(
                        StatusCode::BAD_REQUEST,
                        "minutes must be from 1 to 1440",
                    ));
                }

                let duration = Duration::from_secs(u64::from(request.minutes) * 60);
                self.policy.pause(duration, Instant::now());

                Ok(json(StatusCode::OK, &self.pause_view()))
            }

            Change::Resume => {
                self.policy.resume();

                Ok(json(StatusCode::OK, &self.pause_view()))
            }

            Change::RefreshLists => {
                self.lists.refresh_all();

                Ok(json(
                    StatusCode::ACCEPTED,
                    &RefreshView {
                        refresh: "requested",
                    },
                ))
            }
        }
    }

    fn query_log_limit(&self, query: Option<&str>) -> Result<usize, Rejection> {
        let mut limit = DEFAULT_QUERY_LOG_LIMIT;

        for pair in query.unwrap_or_default().split('&') {
            if let Some(value) = pair.strip_prefix("limit=") {
                limit = value.parse().map_err(|_| {
                    Rejection::new(StatusCode::BAD_REQUEST, "limit must be a number")
                })?;
            }
        }

        Ok(limit.min(self.query_log_entries))
    }

    fn pause_view(&self) -> PauseView {
        let Some(left) = self.policy.pause_remaining(Instant::now()) else {
            return PauseView {
                paused: false,
                seconds_left: None,
                until: None,
            };
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        PauseView {
            paused: true,
            seconds_left: Some(left.as_secs()),
            until: Some((now + left).as_secs()),
        }
    }

    fn list_views(&self) -> Vec<ListView> {
        self.lists
            .statuses()
            .into_iter()
            .map(ListView::of)
            .collect()
    }
}

/// Empty, or a colon and a port number.
fn is_port_suffix(suffix: &str) -> bool {
    match suffix.strip_prefix(':') {
        None => suffix.is_empty(),
        Some(port) => {
            port.bytes().all(|digit| digit.is_ascii_digit()) && port.parse::<u16>().is_ok()
        }
    }
}

/// The page is served over plain HTTP from `Host`, so that is the only origin it can have.
fn check_origin(headers: &HeaderMap, host: &str) -> Result<(), Rejection> {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return Ok(());
    };

    let is_own_origin = origin
        .to_str()
        .ok()
        .and_then(|origin| origin.strip_prefix("http://"))
        .is_some_and(|origin_host| origin_host.eq_ignore_ascii_case(host));

    if is_own_origin {
        return Ok(());
    }

    Err(Rejection::new(
        StatusCode::FORBIDDEN,
        "requests from another origin are refused",
    ))
}

fn check_json_content_type(headers: &HeaderMap) -> Result<(), Rejection> {
    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"));

    if is_json {
        return Ok(());
    }

    Err(Rejection::new(
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "send Content-Type: application/json",
    ))
}

async fn read_body(headers: &HeaderMap, body: Incoming) -> Result<Bytes, Rejection> {
    let too_large = || {
        Rejection::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "the body is limited to 1 KiB",
        )
    };

    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if declared.is_some_and(|length| length > MAX_BODY_BYTES) {
        return Err(too_large());
    }

    match Limited::new(body, MAX_BODY_BYTES).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),

        Err(error) if error.downcast_ref::<LengthLimitError>().is_some() => Err(too_large()),

        Err(_) => Err(Rejection::new(
            StatusCode::BAD_REQUEST,
            "the body could not be read",
        )),
    }
}

fn method_not_allowed(allowed: &'static str) -> Rejection {
    Rejection::new(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
        .with_header(header::ALLOW, allowed)
}

/// The expected `Authorization` credentials, kept as an HMAC-SHA256 tag under a key drawn at
/// startup. Tags have one size, so neither what is stored nor the comparison depends on the
/// length of the secret, and `hmac::verify` does not stop at the first difference.
struct Credentials {
    key: hmac::Key,
    tag: hmac::Tag,
}

impl Credentials {
    fn new(credentials: &str) -> Result<Credentials, String> {
        let key = hmac::Key::generate(hmac::HMAC_SHA256, &SystemRandom::new())
            .map_err(|_| "cannot draw a random key for the web credentials".to_string())?;
        let tag = hmac::sign(&key, credentials.as_bytes());

        Ok(Credentials { key, tag })
    }

    fn accepts(&self, sent: &str) -> bool {
        hmac::verify(&self.key, sent.as_bytes(), self.tag.as_ref()).is_ok()
    }
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let group = chunk.iter().enumerate().fold(0u32, |group, (index, byte)| {
            group | u32::from(*byte) << (16 - 8 * index)
        });

        for index in 0..4 {
            if index <= chunk.len() {
                text.push(ALPHABET[(group >> (18 - 6 * index) & 0x3f) as usize] as char);
            } else {
                text.push('=');
            }
        }
    }

    text
}

fn json<T: Serialize>(status: StatusCode, value: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(value).unwrap_or_default();

    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("static response is valid")
}

/// No caching, no sniffing, no framing, and a page that talks only to its own server.
fn with_protective_headers(mut response: Response<Full<Bytes>>) -> Response<Full<Bytes>> {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'",
        ),
    );

    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PauseRequest {
    minutes: u32,
}

#[derive(Serialize)]
struct PauseView {
    paused: bool,
    seconds_left: Option<u64>,
    /// Unix seconds.
    until: Option<u64>,
}

#[derive(Serialize)]
struct RefreshView {
    refresh: &'static str,
}

/// A top list is a Space-Saving summary: counts may be too high by up to `max_error`.
#[derive(Serialize)]
struct TopList<'a, K> {
    approximate: bool,
    entries: &'a [TopEntry<K>],
}

impl<'a, K> TopList<'a, K> {
    fn of(entries: &'a [TopEntry<K>]) -> TopList<'a, K> {
        TopList {
            approximate: true,
            entries,
        }
    }
}

#[derive(Serialize)]
struct ListView {
    name: String,
    kind: Role,
    format: Option<ListFormat>,
    rules: usize,
    /// Seconds since the copy in force was loaded or last confirmed current.
    age_seconds: Option<u64>,
    last_error: Option<String>,
}

impl ListView {
    fn of(status: ListStatus) -> ListView {
        ListView {
            name: status.name,
            kind: status.role,
            format: status.format,
            rules: status.rules,
            age_seconds: status.checked.map(|checked| checked.elapsed().as_secs()),
            last_error: status.last_error,
        }
    }
}

#[derive(Serialize)]
struct ListsView {
    lists: Vec<ListView>,
}

#[derive(Serialize)]
struct QueryLogView {
    entries: Vec<QueryLogEntry>,
}

#[derive(Serialize)]
struct StatusView<'a> {
    version: &'static str,
    update: UpdateView,
    counters: &'a Counters,
    /// Of answered queries, blocked by a request or a response rule; one decimal.
    blocked_percent: f64,
    /// Oldest first; the last bucket is the current UTC hour.
    hourly: &'a [HourlyBucket],
    /// Why the top lists are left out: set only while no password is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    limited: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_queried: Option<TopList<'a, Box<str>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_blocked: Option<TopList<'a, Box<str>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_clients: Option<TopList<'a, IpAddr>>,
    lists: Vec<ListView>,
    generation: u64,
    pause: PauseView,
}

fn blocked_percent(counters: &Counters) -> f64 {
    if counters.total == 0 {
        return 0.0;
    }

    let blocked = counters.blocked_request + counters.blocked_response;

    (blocked as f64 * 1000.0 / counters.total as f64).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update::Build;

    fn web_with_names(names: &[&str]) -> Web {
        let mut config = Config::default();
        config.web.hostnames = names.iter().map(|name| name.to_string()).collect();
        let policy = Arc::new(Policy::new());
        let lists = Arc::new(ListControl::default());

        Web::new(
            &config,
            Arc::new(Stats::new(Default::default())),
            policy,
            lists,
            Arc::new(Updates::new(Build::current())),
        )
        .unwrap()
    }

    #[test]
    fn host_must_be_an_ip_literal_or_a_configured_name() {
        let web = web_with_names(&["Picoguard.lan"]);

        for good in [
            "192.168.1.2",
            "192.168.1.2:8080",
            "127.0.0.1:1",
            "[::1]",
            "[fe80::1]:8080",
            "[2001:db8::1]:65535",
            "picoguard.lan",
            "PICOGUARD.LAN:8080",
        ] {
            assert!(web.is_known_host(good), "{good}");
        }

        for bad in [
            "",
            "evil.example",
            "evil.example:8080",
            "picoguard.lan.evil.example",
            "192.168.1.2:",
            "192.168.1.2:80:80",
            "192.168.1.2:http",
            "192.168.1.2:65536",
            "192.168.1.2.evil.example",
            "0x7f.1",
            "1.2.3",
            "::1",
            "[::1",
            "[::1]x",
            "[::1]:",
            "[evil]:80",
            "[fe80::1%eth0]",
            "localhost",
        ] {
            assert!(!web.is_known_host(bad), "{bad}");
        }
    }

    #[test]
    fn the_origin_must_be_the_page_itself() {
        let check = |origin: Option<&str>, host: &str| {
            let mut headers = HeaderMap::new();
            if let Some(origin) = origin {
                headers.insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
            }

            check_origin(&headers, host).is_ok()
        };

        assert!(check(None, "192.168.1.2:8080"));
        assert!(check(Some("http://192.168.1.2:8080"), "192.168.1.2:8080"));
        assert!(check(Some("http://Picoguard.lan"), "picoguard.lan"));
        assert!(!check(Some("http://evil.example"), "192.168.1.2:8080"));
        assert!(!check(Some("http://192.168.1.2:8081"), "192.168.1.2:8080"));
        assert!(!check(Some("https://192.168.1.2:8080"), "192.168.1.2:8080"));
        assert!(!check(Some("null"), "192.168.1.2:8080"));
        assert!(!check(Some(""), "192.168.1.2:8080"));
    }

    #[test]
    fn json_is_the_only_accepted_content_type() {
        let check = |content_type: Option<&str>| {
            let mut headers = HeaderMap::new();
            if let Some(content_type) = content_type {
                headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_str(content_type).unwrap(),
                );
            }

            check_json_content_type(&headers).is_ok()
        };

        assert!(check(Some("application/json")));
        assert!(check(Some("Application/JSON; charset=utf-8")));
        assert!(!check(None));
        assert!(!check(Some("text/plain")));
        assert!(!check(Some("application/x-www-form-urlencoded")));
        assert!(!check(Some("multipart/form-data; boundary=x")));
        assert!(!check(Some("application/jsonp")));
    }

    #[test]
    fn base64_matches_the_standard_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
            ("admin:s3cret", "YWRtaW46czNjcmV0"),
        ] {
            assert_eq!(base64(plain.as_bytes()), encoded, "{plain}");
        }
    }

    #[test]
    fn credentials_are_accepted_only_when_every_byte_is_equal() {
        let credentials = Credentials::new("abc").unwrap();

        assert!(credentials.accepts("abc"));
        assert!(!credentials.accepts("abd"));
        assert!(!credentials.accepts("abcd"));
        assert!(!credentials.accepts("ab"));
        assert!(!credentials.accepts(""));
        assert!(Credentials::new("").unwrap().accepts(""));
    }

    #[test]
    fn what_is_kept_of_the_credentials_has_the_same_size_whatever_their_length() {
        let short = Credentials::new("a").unwrap();
        let long = Credentials::new(&"a".repeat(5000)).unwrap();

        assert_eq!(short.tag.as_ref().len(), long.tag.as_ref().len());
        assert_eq!(std::mem::size_of_val(&short), std::mem::size_of_val(&long));
        assert!(!short.accepts(&"a".repeat(5000)));
        assert!(long.accepts(&"a".repeat(5000)));
    }

    #[test]
    fn the_blocked_share_has_one_decimal() {
        let share = |blocked_request, blocked_response, total| {
            blocked_percent(&Counters {
                blocked_request,
                blocked_response,
                total,
                ..Counters::default()
            })
        };

        assert_eq!(share(0, 0, 0), 0.0);
        assert_eq!(share(1, 0, 3), 33.3);
        assert_eq!(share(1, 1, 3), 66.7);
        assert_eq!(share(5, 5, 10), 100.0);
    }
}
