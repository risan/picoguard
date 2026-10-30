//! The status page and its JSON API (plan D16). One HTML page, six reads, seven mutations, and
//! sign-in and sign-out. A web page on another device of the LAN must not be able to pause
//! blocking, so every request passes the access policy before it reaches a handler:
//!
//! - a peer outside `web.allow_from` is closed before a byte is read;
//! - `Host` must be an IP address or a configured name, which defeats DNS rebinding;
//! - with a password configured, every route but the page and the sign-in needs a valid session
//!   cookie or a matching `Authorization: Basic`, compared in constant time; failed password
//!   checks are limited per address;
//! - without a password the page is read-only and shows totals and list status only: the
//!   status leaves out the top lists, the upstream servers and the cache size, and the query
//!   log and every change answer 403;
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
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use self::auth::{Attempt, Auth, Check, SIGNED_OUT_COOKIE};
use crate::config::{Cidr, Config, ListFormat, WebConfig, is_allowed};
use crate::pipeline::{CacheSize, Pipeline, ServerKind, ServerTally};
use crate::policy::Policy;
use crate::scheduler::{
    Action, ButtonRule, ListControl, ListStatus, MAX_BUTTON_RULES, Role, RuleError, normalized_name,
};
use crate::server::bind_tcp;
use crate::stage::{Refused, Stager};
use crate::stats::{Counters, HourlyBucket, QueryLogEntry, TopEntry};
use crate::update::{Tag, UpdateView, Updates, parse_tag};

mod auth;

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
const PASSWORD_NEEDED: &str = "set web.user and web.password_hash (or web.password) to use this";
const NOT_A_DOMAIN_NAME: &str = "not a domain name";

/// Everything the handlers read or change.
pub struct Web {
    pipeline: Arc<Pipeline>,
    policy: Arc<Policy>,
    lists: Arc<ListControl>,
    updates: Arc<Updates>,
    stager: Arc<Stager>,
    allow_from: Vec<Cidr>,
    hostnames: Vec<String>,
    /// What a client is checked against; `None` when no password is set.
    auth: Option<Auth>,
    query_log_entries: usize,
    /// The config's `rules`, shown read-only beside the page's own.
    config_rules: Arc<[String]>,
}

impl Web {
    pub fn new(
        config: &Config,
        pipeline: Arc<Pipeline>,
        policy: Arc<Policy>,
        lists: Arc<ListControl>,
        updates: Arc<Updates>,
        stager: Arc<Stager>,
    ) -> Result<Web, String> {
        let web = &config.web;
        let auth = Auth::new(web)?;
        if auth.is_none() {
            log::warn!(
                "the status page has no password: it shows totals and list status only. \
                 Set web.user and web.password_hash (or web.password) for the query log, the top \
                 lists and pause."
            );
        }

        Ok(Web {
            pipeline,
            policy,
            lists,
            updates,
            stager,
            allow_from: web.allow_from.clone(),
            hostnames: web.hostnames.clone(),
            auth,
            query_log_entries: config.stats.query_log_entries,
            config_rules: Arc::clone(&config.rules),
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

        tokio::spawn(serve_connection(stream, peer.ip(), Arc::clone(&web), slot));
    }
}

async fn serve_connection(
    stream: TcpStream,
    peer: IpAddr,
    web: Arc<Web>,
    _slot: OwnedSemaphorePermit,
) {
    let service = service_fn(move |request| {
        let web = Arc::clone(&web);

        async move { Ok::<_, Infallible>(web.respond(request, peer).await) }
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
    Rules,
    Explain,
}

/// Answered to `POST` only.
#[derive(Clone, Copy)]
enum Change {
    Pause,
    Resume,
    RefreshLists,
    ClearCache,
    Install,
    Login,
    Logout,
    AddRule,
    RemoveRule,
}

enum Route {
    Read(Read),
    Change(Change),
}

impl Route {
    /// `/api/rules` is the one path with a read and a change: `GET` lists, `POST` adds.
    fn of(path: &str, method: &Method) -> Option<Route> {
        match path {
            "/api/rules" if method == Method::POST => Some(Route::Change(Change::AddRule)),
            "/api/rules" => Some(Route::Read(Read::Rules)),
            "/api/rules/remove" => Some(Route::Change(Change::RemoveRule)),
            "/api/explain" => Some(Route::Read(Read::Explain)),
            "/" => Some(Route::Read(Read::Page)),
            "/api/status" => Some(Route::Read(Read::Status)),
            "/api/querylog" => Some(Route::Read(Read::QueryLog)),
            "/api/lists" => Some(Route::Read(Read::Lists)),
            "/api/pause" => Some(Route::Change(Change::Pause)),
            "/api/resume" => Some(Route::Change(Change::Resume)),
            "/api/lists/refresh" => Some(Route::Change(Change::RefreshLists)),
            "/api/cache/clear" => Some(Route::Change(Change::ClearCache)),
            "/api/update" => Some(Route::Change(Change::Install)),
            "/api/login" => Some(Route::Change(Change::Login)),
            "/api/logout" => Some(Route::Change(Change::Logout)),
            _ => None,
        }
    }

    /// What a 405 names in `Allow`.
    fn allowed_methods(&self) -> &'static str {
        match self {
            Route::Read(Read::Rules) | Route::Change(Change::AddRule) => "GET, POST",
            Route::Read(_) => "GET",
            Route::Change(_) => "POST",
        }
    }

    /// Open without a sign-in even when a password is set: the page shows its own form, which
    /// posts to the sign-in.
    fn is_public(&self) -> bool {
        matches!(self, Route::Read(Read::Page) | Route::Change(Change::Login))
    }

    /// Whether the page shows this only to a signed-in user: the query log, the top lists,
    /// the page's rules, the name check and every change.
    fn needs_password(&self) -> bool {
        match self {
            Route::Read(Read::QueryLog | Read::Rules | Read::Explain) | Route::Change(_) => true,
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
    async fn respond(&self, request: Request<Incoming>, peer: IpAddr) -> Response<Full<Bytes>> {
        let response = match self.try_respond(request, peer).await {
            Ok(response) => response,
            Err(rejection) => rejection.into_response(),
        };

        with_protective_headers(response)
    }

    async fn try_respond(
        &self,
        request: Request<Incoming>,
        peer: IpAddr,
    ) -> Result<Response<Full<Bytes>>, Rejection> {
        let (head, body) = request.into_parts();
        let host = self.checked_host(&head.headers)?;

        // An unknown path is not public, so it answers 401 before 404.
        let route = Route::of(head.uri.path(), &head.method);
        if let Some(auth) = &self.auth
            && !route.as_ref().is_some_and(Route::is_public)
        {
            authenticate(auth, &head.headers, peer).await?;
        }

        let route = route.ok_or_else(|| Rejection::new(StatusCode::NOT_FOUND, "no such page"))?;
        if route.needs_password() && self.auth.is_none() {
            return Err(Rejection::new(StatusCode::FORBIDDEN, PASSWORD_NEEDED));
        }

        let allowed = route.allowed_methods();
        match route {
            Route::Read(read) => {
                if head.method != Method::GET {
                    return Err(method_not_allowed(allowed));
                }

                self.read(read, head.uri.query()).await
            }

            Route::Change(change) => {
                if head.method != Method::POST {
                    return Err(method_not_allowed(allowed));
                }

                check_origin(&head.headers, host)?;
                check_json_content_type(&head.headers)?;
                let body = read_body(&head.headers, body).await?;

                self.change(change, &body, &head.headers, peer).await
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

    async fn read(
        &self,
        read: Read,
        query: Option<&str>,
    ) -> Result<Response<Full<Bytes>>, Rejection> {
        match read {
            Read::Page => Ok(Response::builder()
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(Full::new(Bytes::from_static(PAGE.as_bytes())))
                .expect("static response is valid")),

            Read::Status => {
                let snapshot = self.pipeline.stats().snapshot();
                let view = self.policy.view(Instant::now());
                let is_open = self.auth.is_some();

                Ok(json(
                    StatusCode::OK,
                    &StatusView {
                        version: env!("CARGO_PKG_VERSION"),
                        update: self.update_view(),
                        counters: &snapshot.counters,
                        blocked_percent: blocked_percent(&snapshot.counters),
                        hourly: &snapshot.hourly,
                        limited: (!is_open).then_some(PASSWORD_NEEDED),
                        top_queried: is_open.then(|| TopList::of(&snapshot.top_queried)),
                        top_blocked: is_open.then(|| TopList::of(&snapshot.top_blocked)),
                        top_clients: is_open.then(|| TopList::of(&snapshot.top_clients)),
                        upstreams: is_open.then(|| {
                            self.pipeline
                                .upstream_tallies()
                                .into_iter()
                                .map(UpstreamView::of)
                                .collect()
                        }),
                        cache: is_open.then(|| self.pipeline.cache_size()),
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
                        entries: self.pipeline.stats().query_log(limit),
                    },
                ))
            }

            Read::Lists => Ok(json(
                StatusCode::OK,
                &ListsView {
                    lists: self.list_views(),
                },
            )),

            Read::Rules => Ok(self.rules_response().await),

            Read::Explain => {
                let name = name_param(query)
                    .ok_or_else(|| Rejection::new(StatusCode::BAD_REQUEST, NOT_A_DOMAIN_NAME))?;
                let explained = self.lists.explain(&name).await;
                let decision = match &explained {
                    Some(explained) if explained.allowed => "allowed",
                    Some(_) => "blocked",
                    None => "none",
                };
                let (list, rule) = explained
                    .map(|explained| (explained.list, explained.rule))
                    .unzip();

                Ok(json(
                    StatusCode::OK,
                    &ExplainView {
                        name,
                        decision,
                        list,
                        rule,
                    },
                ))
            }
        }
    }

    /// The page's rules and the config's, written while the rules are borrowed under the
    /// lock: no copy of them is made.
    async fn rules_response(&self) -> Response<Full<Bytes>> {
        self.lists
            .with_button_rules(|rules| {
                json(
                    StatusCode::OK,
                    &RulesView {
                        rules,
                        config_rules: &self.config_rules,
                        max: MAX_BUTTON_RULES,
                    },
                )
            })
            .await
    }

    async fn change(
        &self,
        change: Change,
        body: &[u8],
        headers: &HeaderMap,
        peer: IpAddr,
    ) -> Result<Response<Full<Bytes>>, Rejection> {
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

            Change::ClearCache => Ok(json(
                StatusCode::OK,
                &ClearedView {
                    cleared: self.pipeline.clear_cache(),
                },
            )),

            Change::Install => {
                let version = install_version(body).ok_or_else(|| {
                    Rejection::new(StatusCode::BAD_REQUEST, "send {\"version\": \"X.Y.Z\"}")
                })?;

                self.stager.start(&version).map_err(|refused| {
                    Rejection::new(
                        StatusCode::CONFLICT,
                        match refused {
                            Refused::CannotInstall => {
                                "this build is updated with the command shown"
                            }
                            Refused::InProgress => "an update is already in progress",
                            Refused::NotNewest => "that is not the newest release",
                        },
                    )
                })?;

                Ok(json(
                    StatusCode::ACCEPTED,
                    &InstallStarted { install: "started" },
                ))
            }

            Change::Login => {
                let auth = self.required_auth()?;
                let request = login_request(body).ok_or_else(|| {
                    Rejection::new(
                        StatusCode::BAD_REQUEST,
                        "send {\"user\": \"...\", \"password\": \"...\"}",
                    )
                })?;
                let attempt = Attempt::Form {
                    user: &request.user,
                    password: &request.password,
                };

                match auth.check(peer, attempt).await {
                    Check::Accepted => Ok(with_cookie(
                        json(StatusCode::OK, &Empty {}),
                        &auth.session_cookie(unix_now()),
                    )),
                    Check::Refused => Err(unauthorized(headers, "wrong user or password")),
                    Check::Limited => Err(too_many_attempts()),
                }
            }

            Change::Logout => Ok(with_cookie(
                json(StatusCode::OK, &Empty {}),
                SIGNED_OUT_COOKIE,
            )),

            Change::AddRule => {
                let request = rule_request(body).ok_or_else(|| {
                    Rejection::new(
                        StatusCode::BAD_REQUEST,
                        "send {\"name\": \"...\", \"action\": \"block\" or \"allow\"}",
                    )
                })?;
                self.lists
                    .add_button_rule(&request.name, request.action)
                    .await
                    .map_err(rule_rejection)?;

                Ok(self.rules_response().await)
            }

            Change::RemoveRule => {
                let request = remove_request(body).ok_or_else(|| {
                    Rejection::new(StatusCode::BAD_REQUEST, "send {\"name\": \"...\"}")
                })?;
                self.lists
                    .remove_button_rule(&request.name)
                    .await
                    .map_err(rule_rejection)?;

                Ok(self.rules_response().await)
            }
        }
    }

    /// Every change needs a password, so a change handler always has one.
    fn required_auth(&self) -> Result<&Auth, Rejection> {
        self.auth
            .as_ref()
            .ok_or_else(|| Rejection::new(StatusCode::FORBIDDEN, PASSWORD_NEEDED))
    }

    /// The button is offered only to a signed-in user: the route needs the password too.
    fn update_view(&self) -> UpdateView {
        let mut view = self.updates.view();
        view.can_install = self.auth.is_some() && self.stager.can_install();
        view.install = self.stager.view();

        view
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

/// A valid session cookie is enough. Without one, a Basic header is a password check, and a
/// request with neither counts nothing.
async fn authenticate(auth: &Auth, headers: &HeaderMap, peer: IpAddr) -> Result<(), Rejection> {
    if auth.has_session(headers, unix_now()) {
        return Ok(());
    }

    let sent = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
        .map(|(_, credentials)| credentials.trim());

    let Some(sent) = sent else {
        return Err(unauthorized(headers, "sign in"));
    };

    match auth.check(peer, Attempt::Basic(sent)).await {
        Check::Accepted => Ok(()),
        Check::Refused => Err(unauthorized(headers, "sign in")),
        Check::Limited => Err(too_many_attempts()),
    }
}

/// A Basic challenge makes a browser show its own prompt, even for `fetch`, so the page's
/// script, which says who it is, gets none. Clients that send credentials only after a
/// challenge (GNU wget) still get it.
fn unauthorized(headers: &HeaderMap, message: &'static str) -> Rejection {
    let rejection = Rejection::new(StatusCode::UNAUTHORIZED, message);
    let is_page = headers
        .get("x-requested-with")
        .is_some_and(|value| value == "picoguard");

    if is_page {
        return rejection;
    }

    rejection.with_header(header::WWW_AUTHENTICATE, "Basic realm=\"picoguard\"")
}

fn too_many_attempts() -> Rejection {
    Rejection::new(
        StatusCode::TOO_MANY_REQUESTS,
        "too many attempts, try again later",
    )
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
struct LoginRequest {
    user: String,
    password: String,
}

/// `{"user": "...", "password": "..."}` and nothing else; like `install_version`, the first byte
/// must open an object.
fn login_request(body: &[u8]) -> Option<LoginRequest> {
    if body.trim_ascii_start().first() != Some(&b'{') {
        return None;
    }

    serde_json::from_slice(body).ok()
}

#[derive(Serialize)]
struct Empty {}

fn with_cookie(mut response: Response<Full<Bytes>>, cookie: &str) -> Response<Full<Bytes>> {
    if let Ok(cookie) = HeaderValue::from_str(cookie) {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }

    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PauseRequest {
    minutes: u32,
}

/// The version to install: `{"version": "X.Y.Z"}` and nothing else. A JSON array would also
/// fill the struct, so the first byte must open an object.
fn install_version(body: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct InstallRequest {
        version: String,
    }

    if body.trim_ascii_start().first() != Some(&b'{') {
        return None;
    }

    let request: InstallRequest = serde_json::from_slice(body).ok()?;

    match parse_tag(&request.version) {
        Tag::Release(_) if !request.version.starts_with('v') => Some(request.version),
        Tag::Release(_) | Tag::Suffixed | Tag::Invalid => None,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleRequest {
    name: String,
    action: Action,
}

/// `{"name": "...", "action": "block" | "allow"}` and nothing else; the first byte must open an
/// object, as for `install_version`.
fn rule_request(body: &[u8]) -> Option<RuleRequest> {
    if body.trim_ascii_start().first() != Some(&b'{') {
        return None;
    }

    serde_json::from_slice(body).ok()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveRequest {
    name: String,
}

fn remove_request(body: &[u8]) -> Option<RemoveRequest> {
    if body.trim_ascii_start().first() != Some(&b'{') {
        return None;
    }

    serde_json::from_slice(body).ok()
}

fn rule_rejection(error: RuleError) -> Rejection {
    match error {
        RuleError::NotADomainName => Rejection::new(StatusCode::BAD_REQUEST, NOT_A_DOMAIN_NAME),
        RuleError::TooMany => Rejection::new(
            StatusCode::CONFLICT,
            "too many rules (500); remove some first",
        ),
        RuleError::NoSuchRule => Rejection::new(StatusCode::NOT_FOUND, "no such rule"),
        RuleError::NotApplied => Rejection::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the change could not be applied",
        ),
    }
}

/// The `name` of the query, normalized; `None` when missing or not a domain name. The value is
/// used as sent: a valid name never needs percent-encoding, so a `%` or `+` makes it invalid.
fn name_param(query: Option<&str>) -> Option<String> {
    query?
        .split('&')
        .find_map(|pair| pair.strip_prefix("name="))
        .and_then(normalized_name)
}

#[derive(Serialize)]
struct RulesView<'a> {
    rules: &'a [ButtonRule],
    config_rules: &'a [String],
    max: usize,
}

#[derive(Serialize)]
struct ExplainView {
    name: String,
    /// `blocked`, `allowed` or `none`.
    decision: &'static str,
    list: Option<String>,
    rule: Option<String>,
}

#[derive(Serialize)]
struct InstallStarted {
    install: &'static str,
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

#[derive(Serialize)]
struct ClearedView {
    cleared: usize,
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
struct UpstreamView {
    label: String,
    kind: ServerKind,
    answered: u64,
    failed: u64,
    /// Milliseconds over the answers; `null` before the first one.
    avg_ms: Option<f64>,
}

impl UpstreamView {
    fn of(server: ServerTally) -> UpstreamView {
        UpstreamView {
            label: server.label,
            kind: server.kind,
            answered: server.tally.answered,
            failed: server.tally.failed,
            avg_ms: server.tally.average_ms(),
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
    /// Left out with the top lists: a DoH address can carry a private provider profile ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    upstreams: Option<Vec<UpstreamView>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache: Option<CacheSize>,
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
    use std::path::PathBuf;

    use super::*;
    use crate::stage::{StageSetup, StageTiming};
    use crate::update::Build;
    use crate::upstream::tls::Tls;

    fn web_with_names(names: &[&str]) -> Web {
        let mut config = Config::default();
        config.web.hostnames = names.iter().map(|name| name.to_string()).collect();

        web_for(&config)
    }

    fn web_for(config: &Config) -> Web {
        let policy = Arc::new(Policy::new());
        let lists = Arc::new(ListControl::new(Arc::clone(&policy)));
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
            Arc::new(|_| Box::pin(async { Err(std::io::Error::other("no DNS in this test")) })),
            Arc::new(Tls::with_webpki_roots()),
        );

        Web::new(
            config,
            Pipeline::new(config, Arc::clone(&policy)).unwrap(),
            policy,
            lists,
            updates,
            stager,
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
    fn config_rules_are_shared_with_the_config() {
        let config = Config {
            rules: (0..1000)
                .map(|index| format!("||rule{index}.example^"))
                .collect::<Vec<_>>()
                .into(),
            ..Config::default()
        };

        let web = web_for(&config);

        assert!(Arc::ptr_eq(&web.config_rules, &config.rules));
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
