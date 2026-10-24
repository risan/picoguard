//! Getting list text: HTTP(S) download with redirects, conditional requests and caps
//! (plan D12), and local files. Both hand the text to the compile worker as pieces of at most
//! 64 KiB over a bounded channel (D13), so the raw text is never held in full.

use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::future::Future;
use std::io::{self, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::header::{
    ACCEPT, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, ETAG, HOST, HeaderMap, HeaderName,
    HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LOCATION, TRANSFER_ENCODING,
    USER_AGENT,
};
use http::{Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::filter::compile::{CompileError, CompileOptions, CompileWorker, Compiled};
use crate::upstream::tls::{Alpn, Tls, lacks_shared_cipher};

pub const MAX_PIECE_BYTES: usize = 64 * 1024;

/// Pieces queued between the download and the compile worker.
pub const PIECE_QUEUE: usize = 4;

/// Response head and read buffer limit of the HTTP client.
const HTTP_BUFFER_BYTES: usize = 16 * 1024;

/// A validator longer than this is not worth sending back.
const MAX_VALIDATOR_BYTES: usize = 1024;

/// What the compile worker receives. Dropping the sender before `End` means the text is
/// incomplete and the list must not be used.
pub enum Piece {
    Data(Vec<u8>),
    End,
}

pub type PieceSender = mpsc::Sender<Piece>;

/// What a server told us about the copy we got, sent back on the next request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Validators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl Validators {
    fn is_empty(&self) -> bool {
        self.etag.is_none() && self.last_modified.is_none()
    }

    fn of_response(headers: &HeaderMap) -> Validators {
        let text = |name| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .filter(|value| value.len() <= MAX_VALIDATOR_BYTES)
                .map(str::to_string)
        };

        Validators {
            etag: text(ETAG),
            last_modified: text(LAST_MODIFIED),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_body_bytes: u64,
    /// How long connecting, the response head and each piece of the body may take.
    pub idle_timeout: Duration,
    pub max_redirects: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_body_bytes: 64 * 1024 * 1024,
            idle_timeout: Duration::from_secs(30),
            max_redirects: 5,
        }
    }
}

#[derive(Debug)]
pub enum FetchError {
    BadUrl(String),
    Resolve(String),
    Connect(io::Error),
    Tls(io::Error),
    Timeout,
    Http(hyper::Error),
    Status(u16),
    TooManyRedirects,
    BadRedirect(String),
    InsecureRedirect,
    BodyTooLarge,
    UnsupportedEncoding(String),
    Io(io::Error),
    /// The compile worker stopped listening.
    SinkClosed,
}

impl fmt::Display for FetchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::BadUrl(url) => {
                write!(formatter, "invalid list URL {url:?}")
            }

            FetchError::Resolve(message) => {
                write!(formatter, "cannot resolve {message}")
            }

            FetchError::Connect(error) => {
                write!(formatter, "cannot connect: {error}")
            }

            FetchError::Tls(error) => {
                write!(formatter, "TLS failed: {error}")
            }

            FetchError::Timeout => {
                write!(formatter, "timed out")
            }

            FetchError::Http(error) => {
                write!(formatter, "HTTP error: {error}")
            }

            FetchError::Status(status) => {
                write!(formatter, "HTTP status {status}")
            }

            FetchError::TooManyRedirects => {
                write!(formatter, "too many redirects")
            }

            FetchError::BadRedirect(location) => {
                write!(formatter, "invalid redirect to {location:?}")
            }

            FetchError::InsecureRedirect => {
                write!(formatter, "redirect from https to http")
            }

            FetchError::BodyTooLarge => {
                write!(formatter, "list is larger than the size limit")
            }

            FetchError::UnsupportedEncoding(encoding) => {
                write!(formatter, "unsupported content encoding {encoding:?}")
            }

            FetchError::Io(error) => {
                write!(formatter, "{error}")
            }

            FetchError::SinkClosed => {
                write!(formatter, "the compile worker stopped")
            }
        }
    }
}

impl std::error::Error for FetchError {}

/// Resolves a host name to addresses. In production this asks picoguard's own upstreams
/// without filtering; the system resolver is never used.
pub type ResolveFuture = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>>;
pub type Resolver = Arc<dyn Fn(String) -> ResolveFuture + Send + Sync>;

/// A parsed `http://` or `https://` URL.
#[derive(Debug, Clone)]
struct Target {
    https: bool,
    host: String,
    port: u16,
    /// Path and query, always starting with `/`.
    path: String,
}

impl Target {
    fn parse(url: &str) -> Result<Target, FetchError> {
        let bad = || FetchError::BadUrl(url.to_string());
        let uri: Uri = url.parse().map_err(|_| bad())?;
        let https = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => return Err(bad()),
        };
        let host = uri.host().ok_or_else(bad)?;
        let host = host
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(host);
        let has_userinfo = uri
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'));
        if host.is_empty() || has_userinfo {
            return Err(bad());
        }

        Ok(Target {
            https,
            host: host.to_string(),
            port: uri.port_u16().unwrap_or(if https { 443 } else { 80 }),
            path: uri
                .path_and_query()
                .map_or("/", |path| path.as_str())
                .to_string(),
        })
    }

    /// Resolves the `Location` of a redirect against this URL.
    fn redirect(&self, location: &str) -> Result<Target, FetchError> {
        let bad = || FetchError::BadRedirect(location.to_string());
        let location = location.split('#').next().unwrap_or_default();
        if location.is_empty() {
            return Err(bad());
        }

        let scheme = if self.https { "https" } else { "http" };
        let target = if let Some(rest) = location.strip_prefix("//") {
            Target::parse(&format!("{scheme}://{rest}")).map_err(|_| bad())?
        } else if location.starts_with('/') {
            self.with_path(location)
        } else if has_scheme(location) {
            Target::parse(location).map_err(|_| bad())?
        } else if location.starts_with('?') {
            let current = self.path.split('?').next().unwrap_or("/");

            self.with_path(&format!("{current}{location}"))
        } else {
            let current = self.path.split('?').next().unwrap_or("/");
            let directory = &current[..current.rfind('/').map_or(0, |at| at + 1)];

            self.with_path(&format!("{directory}{location}"))
        };

        if self.https && !target.https {
            return Err(FetchError::InsecureRedirect);
        }

        Ok(target)
    }

    fn with_path(&self, path: &str) -> Target {
        Target {
            path: remove_dot_segments(path),
            ..self.clone()
        }
    }

    fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default_port = if self.https { 443 } else { 80 };

        if self.port == default_port {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

fn has_scheme(location: &str) -> bool {
    location.split_once("://").is_some_and(|(scheme, _)| {
        !scheme.is_empty()
            && scheme
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    })
}

fn remove_dot_segments(path_and_query: &str) -> String {
    let (path, query) = match path_and_query.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path_and_query, None),
    };

    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/').skip(1) {
        match segment {
            "." => {}

            ".." => {
                segments.pop();
            }

            other => {
                segments.push(other);
            }
        }
    }

    let mut result = format!("/{}", segments.join("/"));
    let ends_in_dot_segment = path.ends_with("/.") || path.ends_with("/..");
    if ends_in_dot_segment && !segments.is_empty() {
        result.push('/');
    }

    if let Some(query) = query {
        result.push('?');
        result.push_str(query);
    }

    result
}

pub struct Downloader {
    resolver: Resolver,
    tls: Arc<Tls>,
    /// Hosts that refused the ChaCha20-only offer of a CPU without AES (plan D10).
    full_suites: Mutex<HashSet<String>>,
}

pub enum Fetch {
    NotModified,
    Modified(Download),
}

/// A 200 response whose body has not been read yet.
pub struct Download {
    pub validators: Validators,
    body: Incoming,
    limits: Limits,
    _connection: ConnectionTask,
}

struct ConnectionTask(JoinHandle<()>);

impl Drop for ConnectionTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Downloader {
    pub fn new(resolver: Resolver, tls: Arc<Tls>) -> Downloader {
        Downloader {
            resolver,
            tls,
            full_suites: Mutex::new(HashSet::new()),
        }
    }

    /// Follows redirects and returns at the first 200 or 304 response, before its body.
    /// `previous` makes the request conditional.
    pub async fn fetch(
        &self,
        url: &str,
        previous: &Validators,
        limits: &Limits,
    ) -> Result<Fetch, FetchError> {
        let mut target = Target::parse(url)?;

        for redirects in 0..=limits.max_redirects {
            let (head, body, connection) = self.request(&target, previous, limits).await?;

            if head.status == StatusCode::OK {
                return download(head, body, connection, limits);
            }

            if head.status == StatusCode::NOT_MODIFIED && !previous.is_empty() {
                return Ok(Fetch::NotModified);
            }

            if !head.status.is_redirection() || head.status == StatusCode::NOT_MODIFIED {
                return Err(FetchError::Status(head.status.as_u16()));
            }

            if redirects == limits.max_redirects {
                return Err(FetchError::TooManyRedirects);
            }

            let location = head
                .headers
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| FetchError::BadRedirect(String::new()))?;
            target = target.redirect(location)?;
        }

        Err(FetchError::TooManyRedirects)
    }

    async fn request(
        &self,
        target: &Target,
        previous: &Validators,
        limits: &Limits,
    ) -> Result<(http::response::Parts, Incoming, ConnectionTask), FetchError> {
        let request = build_request(target, previous)?;
        let idle = limits.idle_timeout;

        if target.https {
            let stream = self.connect_tls(target, idle).await?;

            return exchange(stream, request, idle).await;
        }

        let stream = timeout(idle, self.connect_tcp(&target.host, target.port))
            .await
            .map_err(|_| FetchError::Timeout)??;

        exchange(stream, request, idle).await
    }

    async fn connect_tcp(&self, host: &str, port: u16) -> Result<TcpStream, FetchError> {
        let addresses = match host.parse::<IpAddr>() {
            Ok(address) => vec![address],

            Err(_) => (self.resolver)(host.to_string())
                .await
                .map_err(|error| FetchError::Resolve(format!("{host}: {error}")))?,
        };

        let mut last_error = FetchError::Resolve(format!("{host}: no addresses"));
        for address in addresses {
            match TcpStream::connect((address, port)).await {
                Ok(stream) => return Ok(stream),

                Err(error) => {
                    last_error = FetchError::Connect(error);
                }
            }
        }

        Err(last_error)
    }

    async fn connect_tls(
        &self,
        target: &Target,
        idle: Duration,
    ) -> Result<TlsStream<TcpStream>, FetchError> {
        let full_suites = self.full_suites.lock().unwrap().contains(&target.host);

        match self.handshake(target, full_suites, idle).await {
            Err(FetchError::Tls(error)) if !full_suites && lacks_shared_cipher(&error) => {
                let first_time = self.full_suites.lock().unwrap().insert(target.host.clone());
                if first_time {
                    log::warn!(
                        "{} has no ChaCha20-Poly1305 suite, offering all suites to it from now on",
                        target.host
                    );
                }

                self.handshake(target, true, idle).await
            }

            result => result,
        }
    }

    async fn handshake(
        &self,
        target: &Target,
        full_suites: bool,
        idle: Duration,
    ) -> Result<TlsStream<TcpStream>, FetchError> {
        let name = ServerName::try_from(target.host.clone())
            .map_err(|_| FetchError::BadUrl(target.host.clone()))?;
        let connector = TlsConnector::from(self.tls.config(Alpn::Http1, full_suites));

        let connect = async {
            let tcp = self.connect_tcp(&target.host, target.port).await?;

            connector.connect(name, tcp).await.map_err(FetchError::Tls)
        };

        timeout(idle, connect)
            .await
            .map_err(|_| FetchError::Timeout)?
    }
}

fn build_request(
    target: &Target,
    previous: &Validators,
) -> Result<Request<Empty<Bytes>>, FetchError> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(&target.path)
        .header(HOST, target.host_header())
        .header(USER_AGENT, concat!("picoguard/", env!("CARGO_PKG_VERSION")))
        .header(ACCEPT, "*/*")
        .header(CONNECTION, "close");

    let validators = [
        (IF_NONE_MATCH, &previous.etag),
        (IF_MODIFIED_SINCE, &previous.last_modified),
    ];
    for (name, value) in validators {
        if let Some(value) = value.as_deref().and_then(|v| HeaderValue::from_str(v).ok()) {
            builder = builder.header(name, value);
        }
    }

    builder
        .body(Empty::new())
        .map_err(|_| FetchError::BadUrl(target.path.clone()))
}

async fn exchange<S>(
    stream: S,
    request: Request<Empty<Bytes>>,
    idle: Duration,
) -> Result<(http::response::Parts, Incoming, ConnectionTask), FetchError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let handshake = http1::Builder::new()
        .max_buf_size(HTTP_BUFFER_BYTES)
        .handshake(TokioIo::new(stream));
    let (mut sender, connection) = timeout(idle, handshake)
        .await
        .map_err(|_| FetchError::Timeout)?
        .map_err(FetchError::Http)?;
    let connection = ConnectionTask(tokio::spawn(async move {
        let _ = connection.await;
    }));

    let response = timeout(idle, sender.send_request(request))
        .await
        .map_err(|_| FetchError::Timeout)?
        .map_err(FetchError::Http)?;
    let (head, body) = response.into_parts();

    Ok((head, body, connection))
}

/// The comma-separated values of every field named `name`, without empty items.
fn header_tokens(headers: &HeaderMap, name: &HeaderName) -> impl Iterator<Item = String> {
    headers
        .get_all(name)
        .into_iter()
        .flat_map(|value| {
            String::from_utf8_lossy(value.as_bytes())
                .split(',')
                .map(|token| token.trim().to_string())
                .collect::<Vec<_>>()
        })
        .filter(|token| !token.is_empty())
}

fn download(
    head: http::response::Parts,
    body: Incoming,
    connection: ConnectionTask,
    limits: &Limits,
) -> Result<Fetch, FetchError> {
    if let Some(coding) = header_tokens(&head.headers, &CONTENT_ENCODING)
        .find(|coding| !coding.eq_ignore_ascii_case("identity"))
    {
        return Err(FetchError::UnsupportedEncoding(coding));
    }

    // hyper removes the chunked framing only; any other transfer coding stays in the body.
    if let Some(coding) = header_tokens(&head.headers, &TRANSFER_ENCODING)
        .find(|coding| !coding.eq_ignore_ascii_case("chunked"))
    {
        return Err(FetchError::UnsupportedEncoding(coding));
    }

    let announced = head
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());
    if announced.is_some_and(|length| length > limits.max_body_bytes) {
        return Err(FetchError::BodyTooLarge);
    }

    Ok(Fetch::Modified(Download {
        validators: Validators::of_response(&head.headers),
        body,
        limits: limits.clone(),
        _connection: connection,
    }))
}

impl Download {
    /// Reads the body and sends it as pieces followed by `End`. On an error the caller drops
    /// the sender, which tells the compile worker to throw the partial text away.
    pub async fn pump(mut self, sink: &PieceSender) -> Result<(), FetchError> {
        let mut piece = Vec::with_capacity(MAX_PIECE_BYTES);
        let mut total = 0u64;

        loop {
            let frame = timeout(self.limits.idle_timeout, self.body.frame())
                .await
                .map_err(|_| FetchError::Timeout)?;
            let Some(frame) = frame else {
                break;
            };
            let Ok(data) = frame.map_err(FetchError::Http)?.into_data() else {
                continue;
            };

            total += data.len() as u64;
            if total > self.limits.max_body_bytes {
                return Err(FetchError::BodyTooLarge);
            }

            let mut rest: &[u8] = &data;
            while !rest.is_empty() {
                let taken = (MAX_PIECE_BYTES - piece.len()).min(rest.len());
                piece.extend_from_slice(&rest[..taken]);
                rest = &rest[taken..];

                if piece.len() == MAX_PIECE_BYTES {
                    let full = std::mem::replace(&mut piece, Vec::with_capacity(MAX_PIECE_BYTES));
                    send(sink, Piece::Data(full)).await?;
                }
            }
        }

        if !piece.is_empty() {
            send(sink, Piece::Data(piece)).await?;
        }

        send(sink, Piece::End).await
    }
}

async fn send(sink: &PieceSender, piece: Piece) -> Result<(), FetchError> {
    sink.send(piece).await.map_err(|_| FetchError::SinkClosed)
}

/// What a refresh found.
pub enum Refresh {
    NotModified,
    Updated(Box<Updated>),
}

pub struct Updated {
    pub compiled: Compiled,
    /// What the server said about this copy; keep it with the snapshot.
    pub validators: Validators,
}

#[derive(Debug)]
pub enum RefreshError {
    Fetch(FetchError),
    Compile(CompileError),
}

impl fmt::Display for RefreshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RefreshError::Fetch(error) => {
                write!(formatter, "{error}")
            }

            RefreshError::Compile(error) => {
                write!(formatter, "compile failed: {error:?}")
            }
        }
    }
}

impl std::error::Error for RefreshError {}

impl Downloader {
    /// Downloads the list at `url` into a compile job on the worker. Answers
    /// `NotModified` without compiling when the server says so.
    pub async fn refresh(
        &self,
        worker: &CompileWorker,
        url: &str,
        previous: &Validators,
        limits: &Limits,
        options: CompileOptions,
    ) -> Result<Refresh, RefreshError> {
        let Fetch::Modified(download) = self
            .fetch(url, previous, limits)
            .await
            .map_err(RefreshError::Fetch)?
        else {
            return Ok(Refresh::NotModified);
        };

        let validators = download.validators.clone();
        let compiled = compile_with(
            worker,
            options,
            |sink| async move { download.pump(&sink).await },
        )
        .await?;

        Ok(Refresh::Updated(Box::new(Updated {
            compiled,
            validators,
        })))
    }
}

/// Starts a compile job and lets `produce` feed it. A failed `produce` drops its sender
/// without `End`, so the worker discards the partial text.
async fn compile_with<F, Fut>(
    worker: &CompileWorker,
    options: CompileOptions,
    produce: F,
) -> Result<Compiled, RefreshError>
where
    F: FnOnce(PieceSender) -> Fut,
    Fut: Future<Output = Result<(), FetchError>>,
{
    let compilation = worker.start(options);
    produce(compilation.pieces.clone())
        .await
        .map_err(RefreshError::Fetch)?;

    compilation.result().await.map_err(RefreshError::Compile)
}

/// Reads the list in a local file into a compile job on the worker.
pub async fn refresh_file(
    worker: &CompileWorker,
    path: PathBuf,
    max_bytes: u64,
    options: CompileOptions,
) -> Result<Compiled, RefreshError> {
    compile_with(worker, options, |sink| async move {
        read_file(path, max_bytes, &sink).await
    })
    .await
}

/// Sends a local file as pieces followed by `End`. The reading runs on a blocking thread.
pub async fn read_file(
    path: PathBuf,
    max_bytes: u64,
    sink: &PieceSender,
) -> Result<(), FetchError> {
    let sink = sink.clone();

    tokio::task::spawn_blocking(move || read_file_blocking(&path, max_bytes, &sink))
        .await
        .map_err(|error| FetchError::Io(io::Error::other(error)))?
}

fn read_file_blocking(path: &Path, max_bytes: u64, sink: &PieceSender) -> Result<(), FetchError> {
    let mut file = File::open(path).map_err(FetchError::Io)?;
    let length = file.metadata().map_err(FetchError::Io)?.len();
    if length > max_bytes {
        return Err(FetchError::BodyTooLarge);
    }

    let mut total = 0u64;
    loop {
        let mut piece = vec![0; MAX_PIECE_BYTES];
        let filled = read_up_to(&mut file, &mut piece).map_err(FetchError::Io)?;
        total += filled as u64;
        if total > max_bytes {
            return Err(FetchError::BodyTooLarge);
        }

        piece.truncate(filled);
        if filled > 0 {
            sink.blocking_send(Piece::Data(piece))
                .map_err(|_| FetchError::SinkClosed)?;
        }

        if filled < MAX_PIECE_BYTES {
            break;
        }
    }

    sink.blocking_send(Piece::End)
        .map_err(|_| FetchError::SinkClosed)
}

/// Reads until `buffer` is full or the file ends.
fn read_up_to(file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;

    while filled < buffer.len() {
        match file.read(&mut buffer[filled..]) {
            Ok(0) => break,

            Ok(count) => {
                filled += count;
            }

            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}

            Err(error) => return Err(error),
        }
    }

    Ok(filled)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use rustls::RootCertStore;
    use rustls::crypto::ring::{self, cipher_suite};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::test_dir::TestDir;
    use crate::upstream::test_tls::{TestPki, TlsServer};

    #[derive(Clone, Debug)]
    struct Request {
        path: String,
        headers: HashMap<String, String>,
        /// The address the server listens on, for building `Location` values.
        server: SocketAddr,
    }

    async fn read_request<S: AsyncRead + Unpin>(stream: &mut S, server: SocketAddr) -> Request {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }

        let head = String::from_utf8(head).unwrap();
        let mut lines = head.lines();
        let path = lines.next().unwrap().split(' ').nth(1).unwrap().to_string();
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_lowercase(), value.trim().to_string()))
            .collect();

        Request {
            path,
            headers,
            server,
        }
    }

    async fn respond<S: AsyncWrite + Unpin>(
        stream: &mut S,
        status: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) {
        let mut head = format!("HTTP/1.1 {status}\r\nConnection: close\r\n");
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }

        if !headers.iter().any(|(name, _)| *name == "Transfer-Encoding") {
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }

        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        stream.flush().await.unwrap();
    }

    struct Server {
        address: SocketAddr,
        requests: Arc<Mutex<Vec<Request>>>,
        task: JoinHandle<()>,
    }

    impl Server {
        /// `handler(index, request, stream)` answers the `index`th request.
        async fn start<H, F>(handler: H) -> Server
        where
            H: Fn(usize, Request, TcpStream) -> F + Send + Sync + 'static,
            F: Future<Output = ()> + Send + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let log = Arc::clone(&requests);

            let task = tokio::spawn(async move {
                let handler = Arc::new(handler);
                let mut count = 0;

                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        break;
                    };
                    let request = read_request(&mut stream, address).await;
                    log.lock().unwrap().push(request.clone());
                    let handler = Arc::clone(&handler);
                    let index = count;
                    count += 1;

                    tokio::spawn(async move {
                        handler(index, request, stream).await;
                    });
                }
            });

            Server {
                address,
                requests,
                task,
            }
        }

        fn url(&self, path: &str) -> String {
            format!("http://{}{path}", self.address)
        }

        fn request_count(&self) -> usize {
            self.requests.lock().unwrap().len()
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn never_resolve() -> Resolver {
        Arc::new(|name| Box::pin(async move { panic!("the resolver was asked for {name}") }))
    }

    fn downloader(resolver: Resolver) -> Downloader {
        let roots = Arc::new(RootCertStore::empty());

        Downloader::new(resolver, Arc::new(Tls::with_roots(roots, true)))
    }

    fn quick() -> Limits {
        Limits {
            idle_timeout: Duration::from_millis(300),
            ..Limits::default()
        }
    }

    struct Pumped {
        result: Result<(), FetchError>,
        pieces: Vec<Vec<u8>>,
        ended: bool,
    }

    impl Pumped {
        fn text(&self) -> Vec<u8> {
            self.pieces.concat()
        }
    }

    async fn pump(download: Download) -> Pumped {
        let (sink, mut receiver) = mpsc::channel(PIECE_QUEUE);
        let producer = async move { download.pump(&sink).await };
        let consumer = async {
            let mut pieces = Vec::new();
            let mut ended = false;
            while let Some(piece) = receiver.recv().await {
                match piece {
                    Piece::Data(bytes) => {
                        pieces.push(bytes);
                    }

                    Piece::End => {
                        ended = true;
                    }
                }
            }

            (pieces, ended)
        };
        let (result, (pieces, ended)) = tokio::join!(producer, consumer);

        Pumped {
            result,
            pieces,
            ended,
        }
    }

    async fn fetch_body(downloader: &Downloader, url: &str, limits: &Limits) -> Pumped {
        match downloader.fetch(url, &Validators::default(), limits).await {
            Ok(Fetch::Modified(download)) => pump(download).await,
            Ok(Fetch::NotModified) => panic!("{url} was not modified"),
            Err(error) => Pumped {
                result: Err(error),
                pieces: Vec::new(),
                ended: false,
            },
        }
    }

    async fn fetch_error(downloader: &Downloader, url: &str, limits: &Limits) -> FetchError {
        let pumped = fetch_body(downloader, url, limits).await;

        pumped.result.expect_err("the download should fail")
    }

    fn sample(length: usize) -> Vec<u8> {
        (0..length).map(|i| (i % 251) as u8).collect()
    }

    fn local() -> Downloader {
        downloader(never_resolve())
    }

    #[tokio::test]
    async fn a_body_arrives_in_pieces_of_at_most_64_kib() {
        let body = sample(200_000);
        let sent = body.clone();
        let server = Server::start(move |_, _, mut stream| {
            let body = sent.clone();
            async move {
                respond(
                    &mut stream,
                    "200 OK",
                    &[
                        ("ETag", "\"v1\""),
                        ("Last-Modified", "Sat, 24 Oct 2026 01:02:03 GMT"),
                    ],
                    &body,
                )
                .await;
            }
        })
        .await;

        let fetch = local()
            .fetch(
                &server.url("/list.txt"),
                &Validators::default(),
                &Limits::default(),
            )
            .await
            .unwrap();
        let Fetch::Modified(download) = fetch else {
            panic!("expected a body");
        };
        assert_eq!(download.validators.etag.as_deref(), Some("\"v1\""));
        assert_eq!(
            download.validators.last_modified.as_deref(),
            Some("Sat, 24 Oct 2026 01:02:03 GMT")
        );

        let pumped = pump(download).await;
        assert!(pumped.result.is_ok());
        assert!(pumped.ended);
        assert_eq!(pumped.text(), body);
        assert!(
            pumped
                .pieces
                .iter()
                .all(|piece| piece.len() <= MAX_PIECE_BYTES)
        );
        assert_eq!(pumped.pieces.len(), 4);
        assert_eq!(server.requests.lock().unwrap()[0].path, "/list.txt");
    }

    #[tokio::test]
    async fn a_chunked_body_is_decoded() {
        let server = Server::start(|_, _, mut stream| async move {
            respond(
                &mut stream,
                "200 OK",
                &[("Transfer-Encoding", "chunked")],
                b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
            )
            .await;
        })
        .await;

        let pumped = fetch_body(&local(), &server.url("/"), &Limits::default()).await;

        assert!(pumped.result.is_ok());
        assert_eq!(pumped.text(), b"hello world");
    }

    #[tokio::test]
    async fn an_empty_body_is_just_the_end() {
        let server = Server::start(|_, _, mut stream| async move {
            respond(&mut stream, "200 OK", &[], b"").await;
        })
        .await;

        let pumped = fetch_body(&local(), &server.url("/"), &Limits::default()).await;

        assert!(pumped.result.is_ok());
        assert!(pumped.pieces.is_empty());
        assert!(pumped.ended);
    }

    #[tokio::test]
    async fn previous_validators_are_sent_and_304_means_not_modified() {
        let server = Server::start(|_, _, mut stream| async move {
            respond(&mut stream, "304 Not Modified", &[], b"").await;
        })
        .await;
        let previous = Validators {
            etag: Some("\"v1\"".to_string()),
            last_modified: Some("Sat, 24 Oct 2026 01:02:03 GMT".to_string()),
        };

        let fetch = local()
            .fetch(&server.url("/"), &previous, &Limits::default())
            .await
            .unwrap();

        assert!(matches!(fetch, Fetch::NotModified));
        let request = server.requests.lock().unwrap()[0].clone();
        assert_eq!(request.headers["if-none-match"], "\"v1\"");
        assert_eq!(
            request.headers["if-modified-since"],
            "Sat, 24 Oct 2026 01:02:03 GMT"
        );
    }

    #[tokio::test]
    async fn no_validators_means_no_conditional_headers_and_a_304_is_an_error() {
        let server = Server::start(|_, _, mut stream| async move {
            respond(&mut stream, "304 Not Modified", &[], b"").await;
        })
        .await;

        let error = fetch_error(&local(), &server.url("/"), &Limits::default()).await;

        assert!(matches!(error, FetchError::Status(304)), "{error:?}");
        let request = server.requests.lock().unwrap()[0].clone();
        assert!(!request.headers.contains_key("if-none-match"));
        assert!(!request.headers.contains_key("if-modified-since"));
        assert!(request.headers["user-agent"].starts_with("picoguard/"));
    }

    #[tokio::test]
    async fn other_statuses_are_errors() {
        let server = Server::start(|_, request, mut stream| async move {
            let status = if request.path == "/missing" {
                "404 Not Found"
            } else {
                "503 Service Unavailable"
            };
            respond(&mut stream, status, &[], b"sorry").await;
        })
        .await;

        let missing = fetch_error(&local(), &server.url("/missing"), &Limits::default()).await;
        let broken = fetch_error(&local(), &server.url("/broken"), &Limits::default()).await;

        assert!(matches!(missing, FetchError::Status(404)), "{missing:?}");
        assert!(matches!(broken, FetchError::Status(503)), "{broken:?}");
    }

    #[tokio::test]
    async fn redirects_are_followed_absolute_and_relative() {
        let server = Server::start(|_, request, mut stream| async move {
            let absolute = format!("http://{}/second/step", request.server);
            match request.path.as_str() {
                "/first" => {
                    respond(
                        &mut stream,
                        "301 Moved Permanently",
                        &[("Location", &absolute)],
                        b"",
                    )
                    .await;
                }

                "/second/step" => {
                    respond(
                        &mut stream,
                        "302 Found",
                        &[("Location", "final.txt?x=1")],
                        b"",
                    )
                    .await;
                }

                "/second/final.txt?x=1" => {
                    respond(
                        &mut stream,
                        "307 Temporary Redirect",
                        &[("Location", "/third")],
                        b"",
                    )
                    .await;
                }

                "/third" => {
                    respond(&mut stream, "200 OK", &[], b"arrived").await;
                }

                other => panic!("unexpected path {other}"),
            }
        })
        .await;

        let pumped = fetch_body(&local(), &server.url("/first"), &Limits::default()).await;

        assert!(pumped.result.is_ok());
        assert_eq!(pumped.text(), b"arrived");
        assert_eq!(server.request_count(), 4);
    }

    #[tokio::test]
    async fn validators_travel_with_every_hop_and_a_304_after_a_redirect_counts() {
        let server = Server::start(|_, request, mut stream| async move {
            if request.path == "/old" {
                respond(&mut stream, "302 Found", &[("Location", "/new")], b"").await;
            } else {
                respond(&mut stream, "304 Not Modified", &[], b"").await;
            }
        })
        .await;
        let previous = Validators {
            etag: Some("\"v1\"".to_string()),
            last_modified: None,
        };

        let fetch = local()
            .fetch(&server.url("/old"), &previous, &Limits::default())
            .await
            .unwrap();

        assert!(matches!(fetch, Fetch::NotModified));
        let requests = server.requests.lock().unwrap().clone();
        assert!(
            requests
                .iter()
                .all(|r| r.headers["if-none-match"] == "\"v1\"")
        );
    }

    fn redirecting(
        count: usize,
    ) -> impl Fn(usize, Request, TcpStream) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        move |_, request, mut stream| {
            Box::pin(async move {
                let step: usize = request.path.trim_start_matches('/').parse().unwrap();
                if step < count {
                    let next = format!("/{}", step + 1);
                    respond(&mut stream, "302 Found", &[("Location", &next)], b"").await;
                } else {
                    respond(&mut stream, "200 OK", &[], b"done").await;
                }
            })
        }
    }

    #[tokio::test]
    async fn five_redirects_are_followed() {
        let server = Server::start(redirecting(5)).await;

        let pumped = fetch_body(&local(), &server.url("/0"), &Limits::default()).await;

        assert!(pumped.result.is_ok());
        assert_eq!(pumped.text(), b"done");
        assert_eq!(server.request_count(), 6);
    }

    #[tokio::test]
    async fn a_sixth_redirect_is_refused() {
        let server = Server::start(redirecting(6)).await;

        let error = fetch_error(&local(), &server.url("/0"), &Limits::default()).await;

        assert!(matches!(error, FetchError::TooManyRedirects), "{error:?}");
        assert_eq!(server.request_count(), 6);
    }

    #[tokio::test]
    async fn a_redirect_without_location_is_an_error() {
        let server = Server::start(|_, _, mut stream| async move {
            respond(&mut stream, "302 Found", &[], b"").await;
        })
        .await;

        let error = fetch_error(&local(), &server.url("/"), &Limits::default()).await;

        assert!(matches!(error, FetchError::BadRedirect(_)), "{error:?}");
    }

    #[test]
    fn redirect_targets_are_resolved_against_the_current_url() {
        let base = Target::parse("https://lists.example:8443/a/b/list.txt?v=1").unwrap();
        let join = |location: &str| {
            let target = base.redirect(location).unwrap();
            format!(
                "{} {} {} {}",
                target.https, target.host, target.port, target.path
            )
        };

        assert_eq!(
            join("https://cdn.example/x.txt"),
            "true cdn.example 443 /x.txt"
        );
        assert_eq!(join("//cdn.example:9/x"), "true cdn.example 9 /x");
        assert_eq!(join("/root.txt"), "true lists.example 8443 /root.txt");
        assert_eq!(join("next.txt"), "true lists.example 8443 /a/b/next.txt");
        assert_eq!(
            join("../up.txt?q=2#frag"),
            "true lists.example 8443 /a/up.txt?q=2"
        );
        assert_eq!(
            join("?only=query"),
            "true lists.example 8443 /a/b/list.txt?only=query"
        );
    }

    #[test]
    fn dot_segments_at_the_root_never_produce_a_double_slash() {
        let base = Target::parse("https://lists.example/list.txt").unwrap();
        let join = |location: &str| base.redirect(location).unwrap().path;

        for (location, expected) in [
            (".", "/"),
            ("./", "/"),
            ("..", "/"),
            ("../", "/"),
            ("/..", "/"),
            ("/.", "/"),
            ("../../x.txt", "/x.txt"),
            ("/a/../../b", "/b"),
            ("/../../../c?q=1", "/c?q=1"),
            ("/a/..", "/"),
            ("/a/.", "/a/"),
            ("/a/b/..", "/a/"),
            ("/a/./b/../c.txt", "/a/c.txt"),
            ("./x.txt", "/x.txt"),
        ] {
            assert_eq!(join(location), expected, "{location}");
        }
    }

    #[test]
    fn urls_parse_with_defaults_and_ipv6() {
        let target = Target::parse("http://[::1]:8080/p?q=1").unwrap();
        assert_eq!(
            (target.https, target.host.as_str(), target.port),
            (false, "::1", 8080)
        );
        assert_eq!(target.path, "/p?q=1");
        assert_eq!(target.host_header(), "[::1]:8080");

        let target = Target::parse("https://example.com").unwrap();
        assert_eq!(
            (target.https, target.port, target.path.as_str()),
            (true, 443, "/")
        );
        assert_eq!(target.host_header(), "example.com");

        for bad in [
            "ftp://example.com/x",
            "example.com/x",
            "http:///x",
            "http://",
        ] {
            assert!(Target::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_redirect_from_https_to_http_is_refused() {
        let base = Target::parse("https://lists.example/list.txt").unwrap();

        let error = base.redirect("http://lists.example/list.txt").unwrap_err();

        assert!(matches!(error, FetchError::InsecureRedirect), "{error:?}");
        assert!(base.redirect("https://other.example/").is_ok());
        let plain = Target::parse("http://lists.example/list.txt").unwrap();
        assert!(plain.redirect("https://lists.example/list.txt").is_ok());
        assert!(plain.redirect("http://other.example/").is_ok());
    }

    #[tokio::test]
    async fn a_body_that_stalls_times_out() {
        let server = Server::start(|_, _, mut stream| async move {
            let head = "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n";
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(&sample(100)).await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        })
        .await;

        let started = std::time::Instant::now();
        let pumped = fetch_body(&local(), &server.url("/"), &quick()).await;

        assert!(
            matches!(pumped.result, Err(FetchError::Timeout)),
            "{:?}",
            pumped.result
        );
        assert!(!pumped.ended);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_server_that_never_answers_times_out() {
        let server = Server::start(|_, _, stream| async move {
            let _held_open = stream;
            tokio::time::sleep(Duration::from_secs(30)).await;
        })
        .await;

        let error = fetch_error(&local(), &server.url("/"), &quick()).await;

        assert!(matches!(error, FetchError::Timeout), "{error:?}");
    }

    #[tokio::test]
    async fn a_trickling_body_is_fine_while_pieces_keep_coming() {
        let server = Server::start(|_, _, mut stream| async move {
            let head = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n";
            stream.write_all(head.as_bytes()).await.unwrap();
            for byte in b"abcdef" {
                stream.write_all(&[*byte]).await.unwrap();
                stream.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;

        let pumped = fetch_body(&local(), &server.url("/"), &quick()).await;

        assert!(pumped.result.is_ok(), "{:?}", pumped.result);
        assert_eq!(pumped.text(), b"abcdef");
    }

    #[tokio::test]
    async fn a_truncated_body_is_an_error_without_end() {
        let server = Server::start(|_, _, mut stream| async move {
            let head = "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n";
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(&sample(500)).await.unwrap();
            stream.shutdown().await.unwrap();
        })
        .await;

        let pumped = fetch_body(&local(), &server.url("/"), &Limits::default()).await;

        assert!(
            matches!(pumped.result, Err(FetchError::Http(_))),
            "{:?}",
            pumped.result
        );
        assert!(!pumped.ended);
    }

    #[tokio::test]
    async fn a_truncated_chunked_body_is_an_error() {
        let server = Server::start(|_, _, mut stream| async move {
            let reply = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
            stream.write_all(reply.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        })
        .await;

        let pumped = fetch_body(&local(), &server.url("/"), &Limits::default()).await;

        assert!(
            matches!(pumped.result, Err(FetchError::Http(_))),
            "{:?}",
            pumped.result
        );
        assert!(!pumped.ended);
    }

    fn capped(bytes: u64) -> Limits {
        Limits {
            max_body_bytes: bytes,
            ..Limits::default()
        }
    }

    #[tokio::test]
    async fn an_announced_length_over_the_cap_is_refused_before_any_data() {
        let server = Server::start(|_, _, mut stream| async move {
            respond(&mut stream, "200 OK", &[], &sample(1000)).await;
        })
        .await;

        let pumped = fetch_body(&local(), &server.url("/"), &capped(999)).await;

        assert!(
            matches!(pumped.result, Err(FetchError::BodyTooLarge)),
            "{:?}",
            pumped.result
        );
        assert!(pumped.pieces.is_empty());
    }

    #[tokio::test]
    async fn an_unannounced_body_over_the_cap_is_cut() {
        let server = Server::start(|_, _, mut stream| async move {
            let mut reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            for _ in 0..10 {
                reply.extend_from_slice(b"64\r\n");
                reply.extend_from_slice(&[b'x'; 100]);
                reply.extend_from_slice(b"\r\n");
            }
            reply.extend_from_slice(b"0\r\n\r\n");
            let _ = stream.write_all(&reply).await;
        })
        .await;

        let pumped = fetch_body(&local(), &server.url("/"), &capped(999)).await;

        assert!(
            matches!(pumped.result, Err(FetchError::BodyTooLarge)),
            "{:?}",
            pumped.result
        );
        assert!(!pumped.ended);
    }

    #[tokio::test]
    async fn a_body_exactly_at_the_cap_is_accepted() {
        let server = Server::start(|_, _, mut stream| async move {
            respond(&mut stream, "200 OK", &[], &sample(1000)).await;
        })
        .await;

        let pumped = fetch_body(&local(), &server.url("/"), &capped(1000)).await;

        assert!(pumped.result.is_ok(), "{:?}", pumped.result);
        assert_eq!(pumped.text(), sample(1000));
    }

    #[tokio::test]
    async fn a_compressed_body_is_refused() {
        let server = Server::start(|_, _, mut stream| async move {
            respond(
                &mut stream,
                "200 OK",
                &[("Content-Encoding", "gzip")],
                b"\x1f\x8b",
            )
            .await;
        })
        .await;

        let error = fetch_error(&local(), &server.url("/"), &Limits::default()).await;

        assert!(
            matches!(error, FetchError::UnsupportedEncoding(_)),
            "{error:?}"
        );
    }

    /// The server writes `head_lines` (after the status line) and `body` as they are.
    async fn raw_reply(head_lines: &'static str, body: &'static [u8]) -> Server {
        Server::start(move |_, _, mut stream| async move {
            let head = format!("HTTP/1.1 200 OK\r\nConnection: close\r\n{head_lines}\r\n");
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
            stream.flush().await.unwrap();
        })
        .await
    }

    #[tokio::test]
    async fn every_content_encoding_field_and_value_is_checked() {
        for head in [
            "Content-Encoding: identity\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n",
            "Content-Encoding: gzip\r\nContent-Encoding: identity\r\nContent-Length: 2\r\n",
            "Content-Encoding: identity, gzip\r\nContent-Length: 2\r\n",
            "Content-Encoding: gzip, identity\r\nContent-Length: 2\r\n",
            "Content-Encoding: GZip ,\r\nContent-Length: 2\r\n",
            "Content-Encoding: br\r\nContent-Length: 2\r\n",
        ] {
            let server = raw_reply(head, b"ab").await;

            let error = fetch_error(&local(), &server.url("/"), &Limits::default()).await;

            assert!(
                matches!(error, FetchError::UnsupportedEncoding(_)),
                "{head:?}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn identity_content_encodings_are_accepted() {
        for head in [
            "Content-Encoding: identity\r\nContent-Length: 2\r\n",
            "Content-Encoding: identity, Identity\r\nContent-Encoding: identity\r\nContent-Length: 2\r\n",
            "Content-Encoding:\r\nContent-Length: 2\r\n",
        ] {
            let server = raw_reply(head, b"ab").await;

            let pumped = fetch_body(&local(), &server.url("/"), &Limits::default()).await;

            assert!(pumped.result.is_ok(), "{head:?}: {:?}", pumped.result);
            assert_eq!(pumped.text(), b"ab");
        }
    }

    #[tokio::test]
    async fn a_transfer_coding_other_than_chunked_is_refused() {
        let chunked_body = b"2\r\nab\r\n0\r\n\r\n";
        for head in [
            "Transfer-Encoding: gzip, chunked\r\n",
            "Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n",
            "Transfer-Encoding: deflate,chunked\r\n",
            "Transfer-Encoding: chunked, gzip\r\n",
        ] {
            let server = raw_reply(head, chunked_body).await;

            let error = fetch_error(&local(), &server.url("/"), &Limits::default()).await;

            assert!(
                matches!(error, FetchError::UnsupportedEncoding(_)),
                "{head:?}: {error:?}"
            );
        }

        let server = raw_reply("Transfer-Encoding: chunked\r\n", chunked_body).await;
        let pumped = fetch_body(&local(), &server.url("/"), &Limits::default()).await;
        assert!(pumped.result.is_ok(), "{:?}", pumped.result);
        assert_eq!(pumped.text(), b"ab");
    }

    #[tokio::test]
    async fn the_queue_holds_four_pieces_and_the_download_waits_for_the_consumer() {
        let server = Server::start(|_, _, mut stream| async move {
            respond(&mut stream, "200 OK", &[], &sample(2 * 1024 * 1024)).await;
        })
        .await;
        let Fetch::Modified(download) = local()
            .fetch(&server.url("/"), &Validators::default(), &Limits::default())
            .await
            .unwrap()
        else {
            panic!("expected a body");
        };
        let (sink, mut receiver) = mpsc::channel(PIECE_QUEUE);

        let stalled = tokio::time::timeout(Duration::from_millis(300), download.pump(&sink)).await;

        assert!(stalled.is_err(), "the pump should be waiting for room");
        assert_eq!(sink.capacity(), 0);
        let mut queued = 0;
        while receiver.try_recv().is_ok() {
            queued += 1;
        }
        assert_eq!(queued, PIECE_QUEUE);
    }

    fn fake_resolver(answers: Vec<IpAddr>, asked: Arc<Mutex<Vec<String>>>) -> Resolver {
        Arc::new(move |name| {
            asked.lock().unwrap().push(name.clone());
            let answers = answers.clone();

            Box::pin(async move {
                if name == "nowhere.test" {
                    return Err(io::Error::other("no such host"));
                }

                Ok(answers)
            })
        })
    }

    #[tokio::test]
    async fn host_names_go_through_the_given_resolver_and_the_next_address_is_tried() {
        let server = Server::start(|_, _, mut stream| async move {
            respond(&mut stream, "200 OK", &[], b"by name").await;
        })
        .await;
        let asked = Arc::new(Mutex::new(Vec::new()));
        // Nothing listens on 127.0.0.2 at the server's port, so that address is refused.
        let resolver = fake_resolver(
            vec!["127.0.0.2".parse().unwrap(), "127.0.0.1".parse().unwrap()],
            Arc::clone(&asked),
        );
        let url = format!("http://lists.test:{}/x", server.address.port());

        let pumped = fetch_body(&downloader(resolver), &url, &Limits::default()).await;

        assert!(pumped.result.is_ok(), "{:?}", pumped.result);
        assert_eq!(pumped.text(), b"by name");
        assert_eq!(*asked.lock().unwrap(), ["lists.test"]);
        assert_eq!(
            server.requests.lock().unwrap()[0].headers["host"],
            format!("lists.test:{}", server.address.port())
        );
    }

    #[tokio::test]
    async fn a_failed_resolution_is_an_error() {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let resolver = fake_resolver(Vec::new(), asked);

        let error = fetch_error(
            &downloader(resolver),
            "http://nowhere.test/x",
            &Limits::default(),
        )
        .await;

        assert!(matches!(error, FetchError::Resolve(_)), "{error:?}");
    }

    #[tokio::test]
    async fn a_refused_connection_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        drop(listener);

        let error = fetch_error(&local(), &url, &Limits::default()).await;

        assert!(matches!(error, FetchError::Connect(_)), "{error:?}");
    }

    struct Negotiated {
        alpn: Option<Vec<u8>>,
        suite: rustls::CipherSuite,
    }

    struct HttpsServer {
        server: TlsServer,
        seen: Arc<Mutex<Vec<Negotiated>>>,
    }

    async fn https_server(pki: &TestPki, provider: rustls::crypto::CryptoProvider) -> HttpsServer {
        let config = pki.server_config(&["http/1.1"], provider);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let server = TlsServer::start(config, move |mut stream| {
            let log = Arc::clone(&log);
            async move {
                let connection = stream.get_ref().1;
                log.lock().unwrap().push(Negotiated {
                    alpn: connection.alpn_protocol().map(<[u8]>::to_vec),
                    suite: connection.negotiated_cipher_suite().unwrap().suite(),
                });
                let address = stream.get_ref().0.local_addr().unwrap();
                let _ = read_request(&mut stream, address).await;
                respond(&mut stream, "200 OK", &[], b"secure").await;
            }
        })
        .await;

        HttpsServer { server, seen }
    }

    fn localhost_resolver() -> Resolver {
        fake_resolver(
            vec!["127.0.0.1".parse().unwrap()],
            Arc::new(Mutex::new(Vec::new())),
        )
    }

    fn https_downloader(pki: &TestPki, has_aes: bool) -> Downloader {
        Downloader::new(
            localhost_resolver(),
            Arc::new(Tls::with_roots(pki.roots(), has_aes)),
        )
    }

    #[tokio::test]
    async fn https_lists_negotiate_http_1_1_and_the_certificate_is_checked() {
        let pki = TestPki::new();
        let https = https_server(&pki, ring::default_provider()).await;
        let url = format!("https://localhost:{}/list", https.server.address.port());

        let pumped = fetch_body(&https_downloader(&pki, true), &url, &Limits::default()).await;

        assert!(pumped.result.is_ok(), "{:?}", pumped.result);
        assert_eq!(pumped.text(), b"secure");
        assert_eq!(
            https.seen.lock().unwrap()[0].alpn.as_deref(),
            Some(&b"http/1.1"[..])
        );

        let untrusted = Downloader::new(
            localhost_resolver(),
            Arc::new(Tls::with_roots(Arc::new(RootCertStore::empty()), true)),
        );
        let error = fetch_error(&untrusted, &url, &Limits::default()).await;
        assert!(matches!(error, FetchError::Tls(_)), "{error:?}");
    }

    #[tokio::test]
    async fn https_to_an_ip_address_uses_the_ip_certificate() {
        let pki = TestPki::new();
        let https = https_server(&pki, ring::default_provider()).await;
        let url = format!("https://127.0.0.1:{}/list", https.server.address.port());

        let pumped = fetch_body(&https_downloader(&pki, true), &url, &Limits::default()).await;

        assert!(pumped.result.is_ok(), "{:?}", pumped.result);
    }

    #[tokio::test]
    async fn without_aes_a_list_download_offers_chacha_first() {
        let pki = TestPki::new();
        let https = https_server(&pki, ring::default_provider()).await;
        let url = format!("https://localhost:{}/list", https.server.address.port());

        let pumped = fetch_body(&https_downloader(&pki, false), &url, &Limits::default()).await;

        assert!(pumped.result.is_ok(), "{:?}", pumped.result);
        assert_eq!(
            https.seen.lock().unwrap()[0].suite,
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        );
    }

    #[tokio::test]
    async fn a_server_without_chacha_gets_the_full_list_once_and_is_remembered() {
        let pki = TestPki::new();
        let mut provider = ring::default_provider();
        provider.cipher_suites = vec![cipher_suite::TLS13_AES_128_GCM_SHA256];
        let https = https_server(&pki, provider).await;
        let url = format!("https://localhost:{}/list", https.server.address.port());
        let downloader = https_downloader(&pki, false);

        let first = fetch_body(&downloader, &url, &Limits::default()).await;
        let second = fetch_body(&downloader, &url, &Limits::default()).await;

        assert!(first.result.is_ok(), "{:?}", first.result);
        assert!(second.result.is_ok(), "{:?}", second.result);
        assert_eq!(https.server.connections.load(Ordering::SeqCst), 3);
        assert_eq!(https.seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_file_is_sent_in_pieces_of_at_most_64_kib() {
        let dir = TestDir::new("lists-file");
        let path = dir.path().join("list.txt");
        let content = sample(150_000);
        std::fs::write(&path, &content).unwrap();
        let (sink, mut receiver) = mpsc::channel(PIECE_QUEUE);

        let reader = async { read_file(path, 1 << 20, &sink).await };
        let collector = async {
            let mut pieces = Vec::new();
            loop {
                match receiver.recv().await.unwrap() {
                    Piece::Data(bytes) => {
                        pieces.push(bytes);
                    }

                    Piece::End => {
                        return pieces;
                    }
                }
            }
        };
        let (result, pieces) = tokio::join!(reader, collector);

        assert!(result.is_ok());
        assert_eq!(pieces.concat(), content);
        assert_eq!(pieces.len(), 3);
        assert!(pieces.iter().all(|piece| piece.len() <= MAX_PIECE_BYTES));
    }

    #[tokio::test]
    async fn a_file_over_the_cap_or_missing_is_an_error() {
        let dir = TestDir::new("lists-file");
        let path = dir.path().join("list.txt");
        std::fs::write(&path, sample(1000)).unwrap();
        let (sink, mut receiver) = mpsc::channel(PIECE_QUEUE);

        let too_big = read_file(path.clone(), 999, &sink).await;
        let missing = read_file(dir.path().join("none.txt"), 999, &sink).await;
        let exact = read_file(path, 1000, &sink).await;

        assert!(
            matches!(too_big, Err(FetchError::BodyTooLarge)),
            "{too_big:?}"
        );
        assert!(matches!(missing, Err(FetchError::Io(_))), "{missing:?}");
        assert!(exact.is_ok());
        let mut ended = 0;
        while let Ok(piece) = receiver.try_recv() {
            if matches!(piece, Piece::End) {
                ended += 1;
            }
        }
        assert_eq!(ended, 1);
    }

    fn compile_options() -> CompileOptions {
        CompileOptions {
            format: crate::filter::parse::ListFormat::Auto,
            max_rules: 1000,
        }
    }

    fn blocks(compiled: &Compiled, name: &str) -> bool {
        use crate::filter::engine::{Decision, Engine, TYPE_A};

        let engine = Engine::new(vec![Arc::clone(&compiled.list)], Vec::new());

        matches!(engine.check(name, TYPE_A, false), Decision::Block { .. })
    }

    #[tokio::test]
    async fn a_refresh_downloads_into_the_compile_worker() {
        let worker = CompileWorker::spawn().unwrap();
        let mut list = String::new();
        for n in 0..20_000 {
            list.push_str(&format!("||host{n}.example^\n"));
        }
        let body = list.clone().into_bytes();
        let server = Server::start(move |_, _, mut stream| {
            let body = body.clone();
            async move {
                respond(&mut stream, "200 OK", &[("ETag", "\"v7\"")], &body).await;
            }
        })
        .await;
        let options = CompileOptions {
            max_rules: 100_000,
            ..compile_options()
        };

        let refresh = local()
            .refresh(
                &worker,
                &server.url("/list"),
                &Validators::default(),
                &Limits::default(),
                options,
            )
            .await
            .unwrap();

        let Refresh::Updated(updated) = refresh else {
            panic!("expected a new list");
        };
        assert_eq!(updated.validators.etag.as_deref(), Some("\"v7\""));
        assert_eq!(updated.compiled.list.rule_count(), 20_000);
        assert_eq!(
            updated.compiled.content_hash,
            xxhash_rust::xxh3::xxh3_128(list.as_bytes())
        );
        assert!(blocks(&updated.compiled, "sub.host19999.example"));
    }

    #[tokio::test]
    async fn a_refresh_that_is_not_modified_compiles_nothing() {
        let worker = CompileWorker::spawn().unwrap();
        let server = Server::start(|_, _, mut stream| async move {
            respond(&mut stream, "304 Not Modified", &[], b"").await;
        })
        .await;
        let previous = Validators {
            etag: Some("\"v7\"".to_string()),
            last_modified: None,
        };

        let refresh = local()
            .refresh(
                &worker,
                &server.url("/"),
                &previous,
                &Limits::default(),
                compile_options(),
            )
            .await
            .unwrap();

        assert!(matches!(refresh, Refresh::NotModified));
    }

    #[tokio::test]
    async fn a_failed_download_gives_no_list_and_the_worker_goes_on() {
        let worker = CompileWorker::spawn().unwrap();
        let server = Server::start(|index, _, mut stream| async move {
            if index == 0 {
                let head = "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n||a.example^\n";
                stream.write_all(head.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            } else {
                respond(&mut stream, "200 OK", &[], b"||a.example^\n").await;
            }
        })
        .await;
        let downloader = local();
        let url = server.url("/");
        let (previous, limits) = (Validators::default(), Limits::default());
        let refresh = || downloader.refresh(&worker, &url, &previous, &limits, compile_options());

        let truncated = refresh().await;
        let complete = refresh().await;

        assert!(
            matches!(truncated, Err(RefreshError::Fetch(FetchError::Http(_)))),
            "{:?}",
            truncated.err()
        );
        let Ok(Refresh::Updated(updated)) = complete else {
            panic!("the second download should work");
        };
        assert!(blocks(&updated.compiled, "a.example"));
    }

    #[tokio::test]
    async fn a_file_refresh_compiles_the_file() {
        let worker = CompileWorker::spawn().unwrap();
        let dir = TestDir::new("lists-refresh");
        let path = dir.path().join("mine.txt");
        std::fs::write(&path, "0.0.0.0 mine.example\n||other.example^\n").unwrap();

        let compiled = refresh_file(&worker, path.clone(), 1 << 20, compile_options())
            .await
            .unwrap();

        assert!(blocks(&compiled, "mine.example"));
        assert!(blocks(&compiled, "www.other.example"));
        let too_big = refresh_file(&worker, path, 10, compile_options()).await;
        assert!(
            matches!(too_big, Err(RefreshError::Fetch(FetchError::BodyTooLarge))),
            "{:?}",
            too_big.err()
        );
    }
}
