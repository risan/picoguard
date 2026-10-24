//! DNS over HTTPS (RFC 8484): POST with `application/dns-message` bodies over
//! one long-lived HTTP/2 connection per upstream. The query ID is 0 on the
//! wire, as the RFC asks for cache friendliness, and restored in the reply.

use std::io;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::header::{ACCEPT, CONTENT_TYPE};
use http::{Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Incoming};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::time::{Instant, timeout_at};

use super::tls::TlsDialer;
use super::{Charged, UpstreamError, is_answer_to};
use crate::budget::Budget;
use crate::config::LimitsConfig;

pub(super) const DNS_MESSAGE: &str = "application/dns-message";

type Sender = http2::SendRequest<Full<Bytes>>;

/// A usable HTTP/2 connection. `generation` tells connections apart, so a
/// failed request only drops the connection it ran on.
struct Connection {
    sender: Sender,
    generation: u64,
    /// Opened for this very request, as opposed to reused.
    fresh: bool,
}

struct Current {
    sender: Option<Sender>,
    generation: u64,
}

pub struct DohUpstream {
    dialer: TlsDialer,
    uri: Uri,
    stream_window: u32,
    connection_window: u32,
    max_header_list: u32,
    max_reply: usize,
    current: Mutex<Current>,
    /// Lets one request at a time open the connection while the others wait for it.
    connect_lock: tokio::sync::Mutex<()>,
}

impl DohUpstream {
    /// `uri` is the full `https://authority/path` of the DoH endpoint.
    pub fn new(dialer: TlsDialer, uri: Uri, limits: &LimitsConfig) -> DohUpstream {
        DohUpstream {
            dialer,
            uri,
            stream_window: limits.h2_stream_window,
            connection_window: limits.h2_connection_window,
            max_header_list: limits.h2_max_header_list,
            max_reply: limits.upstream_reply_max,
            current: Mutex::new(Current {
                sender: None,
                generation: 0,
            }),
            connect_lock: tokio::sync::Mutex::new(()),
        }
    }

    #[cfg(test)]
    async fn query(&self, request: &[u8], deadline: Instant) -> Result<Vec<u8>, UpstreamError> {
        let unlimited = Budget::new(usize::MAX);

        Ok(self.query_charged(request, &unlimited, deadline).await?.0)
    }

    /// Sends `request` with ID 0 and returns the reply carrying the ID that
    /// `request` has. The bytes of the reply are charged to `budget` while
    /// they are read, so partial bodies count too, and the charge goes to
    /// the caller with the reply.
    pub async fn query_charged(
        &self,
        request: &[u8],
        budget: &Arc<Budget>,
        deadline: Instant,
    ) -> Result<Charged, UpstreamError> {
        let mut body = request.to_vec();
        body[0..2].fill(0);
        let body = Bytes::from(body);

        let mut connection = self.connection(deadline).await?;
        let mut result = self.post(&connection, body.clone(), budget, deadline).await;

        // A reused connection may have been closed by the server since its
        // last use, which only shows when a request goes out on it.
        let connection_failed = matches!(result, Err(UpstreamError::Closed | UpstreamError::Io(_)));
        if connection_failed && !connection.fresh {
            self.discard(connection.generation);
            connection = self.connection(deadline).await?;
            result = self.post(&connection, body, budget, deadline).await;
        }

        if let Err(UpstreamError::Timeout | UpstreamError::Closed | UpstreamError::Io(_)) = result {
            self.discard(connection.generation);
        }

        let (mut reply, charge) = result?;
        let Some(id) = reply.get_mut(0..2) else {
            return Err(UpstreamError::BadReply);
        };
        id.copy_from_slice(&request[0..2]);

        if !is_answer_to(request, &reply) {
            return Err(UpstreamError::BadReply);
        }

        Ok((reply, charge))
    }

    async fn post(
        &self,
        connection: &Connection,
        body: Bytes,
        budget: &Arc<Budget>,
        deadline: Instant,
    ) -> Result<Charged, UpstreamError> {
        let request = Request::post(self.uri.clone())
            .header(CONTENT_TYPE, DNS_MESSAGE)
            .header(ACCEPT, DNS_MESSAGE)
            .body(Full::new(body))
            .expect("the URI and headers are valid");
        let mut sender = connection.sender.clone();

        let exchange = async {
            let response = sender.send_request(request).await.map_err(from_hyper)?;

            self.read_reply(response, budget).await
        };

        let Ok(result) = timeout_at(deadline, exchange).await else {
            return Err(UpstreamError::Timeout);
        };

        result
    }

    async fn read_reply(
        &self,
        response: Response<Incoming>,
        budget: &Arc<Budget>,
    ) -> Result<Charged, UpstreamError> {
        if response.status() != StatusCode::OK {
            return Err(UpstreamError::HttpStatus(response.status().as_u16()));
        }

        let is_dns_message = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(DNS_MESSAGE));
        if !is_dns_message {
            return Err(UpstreamError::BadReply);
        }

        let mut body = response.into_body();
        let announced = body.size_hint().lower();
        if announced > self.max_reply as u64 {
            return Err(UpstreamError::ReplyTooLarge);
        }

        // The charge comes first and is released by dropping it, which also
        // covers a request that is cancelled in the middle of the body.
        let mut charge = budget
            .try_charge(announced as usize)
            .ok_or(UpstreamError::BudgetExhausted)?;
        let mut reply = Vec::with_capacity(announced as usize);
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(from_hyper)?;
            let Ok(data) = frame.into_data() else {
                continue;
            };

            let length = reply.len() + data.len();
            if length > self.max_reply {
                return Err(UpstreamError::ReplyTooLarge);
            }

            if length > charge.bytes() && !charge.grow(length - charge.bytes()) {
                return Err(UpstreamError::BudgetExhausted);
            }

            reply.extend_from_slice(&data);
        }

        Ok((reply, charge))
    }

    async fn connection(&self, deadline: Instant) -> Result<Connection, UpstreamError> {
        if let Some(connection) = self.open_connection() {
            return Ok(connection);
        }

        let Ok(_serialize_connects) = timeout_at(deadline, self.connect_lock.lock()).await else {
            return Err(UpstreamError::Timeout);
        };
        if let Some(connection) = self.open_connection() {
            return Ok(connection);
        }

        let sender = self.connect(deadline).await?;
        let mut current = self.current.lock().unwrap();
        current.generation += 1;
        current.sender = Some(sender.clone());

        Ok(Connection {
            sender,
            generation: current.generation,
            fresh: true,
        })
    }

    fn open_connection(&self) -> Option<Connection> {
        let current = self.current.lock().unwrap();
        let sender = current
            .sender
            .as_ref()
            .filter(|sender| !sender.is_closed())?;

        Some(Connection {
            sender: sender.clone(),
            generation: current.generation,
            fresh: false,
        })
    }

    /// Forgets the connection after a failure on it, so the next request
    /// opens a new one. Requests still running on it finish or fail on their own.
    fn discard(&self, generation: u64) {
        let mut current = self.current.lock().unwrap();
        if current.generation == generation {
            current.sender = None;
        }
    }

    async fn connect(&self, deadline: Instant) -> Result<Sender, UpstreamError> {
        let stream = self.dialer.connect(deadline).await?;

        let mut builder = http2::Builder::new(TokioExecutor::new());
        builder
            .initial_stream_window_size(self.stream_window)
            .initial_connection_window_size(self.connection_window)
            .max_header_list_size(self.max_header_list);

        let Ok(handshake) = timeout_at(deadline, builder.handshake(TokioIo::new(stream))).await
        else {
            return Err(UpstreamError::Timeout);
        };
        let (sender, connection) = handshake.map_err(from_hyper)?;

        tokio::spawn(async move {
            if let Err(error) = connection.await {
                log::debug!("DoH connection ended: {error}");
            }
        });

        Ok(sender)
    }
}

fn from_hyper(error: hyper::Error) -> UpstreamError {
    if error.is_closed() || error.is_canceled() {
        return UpstreamError::Closed;
    }

    UpstreamError::Io(io::Error::other(error))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use http::request::Parts;
    use rustls::pki_types::ServerName;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    use super::*;
    use crate::upstream::endpoint::Remote;
    use crate::upstream::test_dns::{ANSWER_MARKER, address_of, answer, query_for};
    use crate::upstream::test_doh::{
        Reaction, Release, Unannounced, dns_message, doh_config, doh_server, gated_response,
        respond_with_answer, serve_doh,
    };
    use crate::upstream::test_tls::{TestPki, TlsServer};
    use crate::upstream::tls::{Alpn, Tls};

    fn upstream_for(pki: &TestPki, address: SocketAddr, limits: &LimitsConfig) -> DohUpstream {
        let tls = Arc::new(Tls::with_roots(pki.roots(), true));
        let name = ServerName::try_from("localhost").unwrap();
        let dialer = TlsDialer::new(tls, Alpn::H2, name, Remote::at(address), "test".to_string());
        let uri: Uri = "https://localhost/dns-query".parse().unwrap();

        DohUpstream::new(dialer, uri, limits)
    }

    fn upstream(pki: &TestPki, server: &TlsServer) -> DohUpstream {
        upstream_for(pki, server.address, &LimitsConfig::default())
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    fn with_id(mut query: Vec<u8>, id: u16) -> Vec<u8> {
        query[0..2].copy_from_slice(&id.to_be_bytes());

        query
    }

    #[tokio::test]
    async fn a_query_is_posted_with_id_zero_and_the_reply_gets_the_callers_id() {
        let pki = TestPki::new();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let server = doh_server(&pki, move |parts, body| {
            let content_type = parts.headers.get(CONTENT_TYPE).cloned();
            let accept = parts.headers.get(ACCEPT).cloned();
            recorder.lock().unwrap().push((
                parts.method.clone(),
                parts.uri.path().to_string(),
                content_type,
                accept,
                body[0..2].to_vec(),
            ));

            // The server answers with ID 0 as well.
            respond_with_answer(body)
        })
        .await;
        let upstream = upstream(&pki, &server);
        let query = with_id(query_for("example.com."), 0xBEEF);

        let reply = upstream.query(&query, deadline()).await.unwrap();

        assert_eq!(reply[0..2], [0xBE, 0xEF]);
        assert_eq!(address_of(&reply), ANSWER_MARKER);
        let seen = seen.lock().unwrap();
        let (method, path, content_type, accept, wire_id) = &seen[0];
        assert_eq!(method, "POST");
        assert_eq!(path, "/dns-query");
        assert_eq!(content_type.as_ref().unwrap(), DNS_MESSAGE);
        assert_eq!(accept.as_ref().unwrap(), DNS_MESSAGE);
        assert_eq!(wire_id, &[0, 0]);
    }

    #[tokio::test]
    async fn a_hundred_queries_share_one_handshake() {
        let pki = TestPki::new();
        let server = doh_server(&pki, |_, body| respond_with_answer(body)).await;
        let upstream = Arc::new(upstream(&pki, &server));

        for _ in 0..50 {
            upstream
                .query(&query_for("example.com."), deadline())
                .await
                .unwrap();
        }

        let mut tasks = Vec::new();
        for _ in 0..50 {
            let upstream = Arc::clone(&upstream);
            tasks.push(tokio::spawn(async move {
                upstream.query(&query_for("example.com."), deadline()).await
            }));
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }

        server.wait_for_handshakes(1).await;
        assert_eq!(server.handshakes.load(Ordering::SeqCst), 1);
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn the_connection_is_reopened_after_the_server_restarts() {
        let pki = TestPki::new();
        let server = doh_server(&pki, |_, body| respond_with_answer(body)).await;
        let upstream = upstream(&pki, &server);
        upstream
            .query(&query_for("example.com."), deadline())
            .await
            .unwrap();

        let address = server.stop().await;
        let listener = TcpListener::bind(address).await.unwrap();
        let behavior = Arc::new(|_: &Parts, body: &[u8]| respond_with_answer(body));
        let restarted = TlsServer::start_on(listener, doh_config(&pki), serve_doh(behavior));

        let reply = upstream.query(&query_for("example.com."), deadline()).await;

        assert_eq!(address_of(&reply.unwrap()), ANSWER_MARKER);
        restarted.wait_for_handshakes(1).await;
        assert_eq!(restarted.handshakes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_down_server_is_an_error_and_a_later_start_is_picked_up() {
        let pki = TestPki::new();
        let server = doh_server(&pki, |_, body| respond_with_answer(body)).await;
        let upstream = upstream(&pki, &server);
        let address = server.stop().await;

        let down = upstream.query(&query_for("example.com."), deadline()).await;

        assert!(matches!(down, Err(UpstreamError::Io(_))));
        let listener = TcpListener::bind(address).await.unwrap();
        let behavior = Arc::new(|_: &Parts, body: &[u8]| respond_with_answer(body));
        let _restarted = TlsServer::start_on(listener, doh_config(&pki), serve_doh(behavior));
        assert!(
            upstream
                .query(&query_for("example.com."), deadline())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_slow_server_times_out_and_the_next_query_gets_a_new_connection() {
        let pki = TestPki::new();
        let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let server = doh_server(&pki, move |_, body| {
            let mut reaction = respond_with_answer(body);
            if first.swap(false, Ordering::SeqCst) {
                reaction.delay = Duration::from_secs(10);
            }

            reaction
        })
        .await;
        let upstream = upstream(&pki, &server);
        let soon = Instant::now() + Duration::from_millis(150);

        let slow = upstream.query(&query_for("example.com."), soon).await;
        let next = upstream.query(&query_for("example.com."), deadline()).await;

        assert!(matches!(slow, Err(UpstreamError::Timeout)));
        assert!(next.is_ok());
        server.wait_for_handshakes(2).await;
        assert_eq!(server.handshakes.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_reply_over_the_cap_is_rejected_whether_announced_or_not() {
        let pki = TestPki::new();
        let announced = doh_server(&pki, |_, _| Reaction {
            delay: Duration::ZERO,
            response: dns_message(vec![0; 64 * 1024 + 1]),
        })
        .await;
        let unannounced = doh_server(&pki, |_, _| Reaction {
            delay: Duration::ZERO,
            response: Response::builder()
                .header(CONTENT_TYPE, DNS_MESSAGE)
                .body(Unannounced { chunks: 5 }.boxed())
                .unwrap(),
        })
        .await;

        let first = upstream(&pki, &announced)
            .query(&query_for("example.com."), deadline())
            .await;
        let second = upstream(&pki, &unannounced)
            .query(&query_for("example.com."), deadline())
            .await;

        assert!(
            matches!(first, Err(UpstreamError::ReplyTooLarge)),
            "{first:?}"
        );
        assert!(
            matches!(second, Err(UpstreamError::ReplyTooLarge)),
            "{second:?}"
        );
    }

    #[tokio::test]
    async fn a_reply_exactly_at_the_cap_is_read_in_full() {
        let pki = TestPki::new();
        let server = doh_server(&pki, |_, body| {
            let mut reply = answer(body, ANSWER_MARKER, false);
            reply.resize(64 * 1024, 0);

            Reaction {
                delay: Duration::ZERO,
                response: dns_message(reply),
            }
        })
        .await;

        let reply = upstream(&pki, &server)
            .query(&query_for("example.com."), deadline())
            .await
            .unwrap();

        assert_eq!(reply.len(), 64 * 1024);
    }

    #[tokio::test]
    async fn the_reply_cap_comes_from_the_limits() {
        let pki = TestPki::new();
        let server = doh_server(&pki, |_, body| respond_with_answer(body)).await;
        let limits = LimitsConfig {
            upstream_reply_max: 20,
            ..LimitsConfig::default()
        };

        let result = upstream_for(&pki, server.address, &limits)
            .query(&query_for("example.com."), deadline())
            .await;

        assert!(matches!(result, Err(UpstreamError::ReplyTooLarge)));
    }

    #[tokio::test]
    async fn other_http_statuses_are_upstream_errors_and_keep_the_connection() {
        let pki = TestPki::new();
        let server = doh_server(&pki, |_, _| Reaction {
            delay: Duration::ZERO,
            response: Response::builder()
                .status(503)
                .header(CONTENT_TYPE, DNS_MESSAGE)
                .body(Full::new(Bytes::new()).boxed())
                .unwrap(),
        })
        .await;
        let upstream = upstream(&pki, &server);

        let first = upstream.query(&query_for("example.com."), deadline()).await;
        let second = upstream.query(&query_for("example.com."), deadline()).await;

        assert!(
            matches!(first, Err(UpstreamError::HttpStatus(503))),
            "{first:?}"
        );
        assert!(matches!(second, Err(UpstreamError::HttpStatus(503))));
        server.wait_for_handshakes(1).await;
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_wrong_or_missing_content_type_is_a_bad_reply() {
        let pki = TestPki::new();
        let html = doh_server(&pki, |_, body| Reaction {
            delay: Duration::ZERO,
            response: Response::builder()
                .header(CONTENT_TYPE, "text/html")
                .body(Full::new(Bytes::from(answer(body, ANSWER_MARKER, false))).boxed())
                .unwrap(),
        })
        .await;
        let untyped = doh_server(&pki, |_, body| Reaction {
            delay: Duration::ZERO,
            response: Response::new(
                Full::new(Bytes::from(answer(body, ANSWER_MARKER, false))).boxed(),
            ),
        })
        .await;

        let first = upstream(&pki, &html)
            .query(&query_for("example.com."), deadline())
            .await;
        let second = upstream(&pki, &untyped)
            .query(&query_for("example.com."), deadline())
            .await;

        assert!(matches!(first, Err(UpstreamError::BadReply)));
        assert!(matches!(second, Err(UpstreamError::BadReply)));
    }

    #[tokio::test]
    async fn content_type_parameters_and_letter_case_are_accepted() {
        let pki = TestPki::new();
        let server = doh_server(&pki, |_, body| Reaction {
            delay: Duration::ZERO,
            response: Response::builder()
                .header(CONTENT_TYPE, "Application/DNS-Message; charset=binary")
                .body(Full::new(Bytes::from(answer(body, ANSWER_MARKER, false))).boxed())
                .unwrap(),
        })
        .await;

        let reply = upstream(&pki, &server)
            .query(&query_for("example.com."), deadline())
            .await;

        assert!(reply.is_ok());
    }

    #[tokio::test]
    async fn a_reply_to_another_question_or_with_garbage_is_a_bad_reply() {
        let pki = TestPki::new();
        let other = doh_server(&pki, |_, _| Reaction {
            delay: Duration::ZERO,
            response: dns_message(answer(&query_for("other.example."), ANSWER_MARKER, false)),
        })
        .await;
        let garbage = doh_server(&pki, |_, _| Reaction {
            delay: Duration::ZERO,
            response: dns_message(vec![1, 2, 3]),
        })
        .await;

        let first = upstream(&pki, &other)
            .query(&query_for("example.com."), deadline())
            .await;
        let second = upstream(&pki, &garbage)
            .query(&query_for("example.com."), deadline())
            .await;

        assert!(matches!(first, Err(UpstreamError::BadReply)));
        assert!(matches!(second, Err(UpstreamError::BadReply)));
    }

    /// A server whose replies are `size` bytes long, announced in full, of
    /// which only the first `first` bytes are sent until the returned
    /// releases are used.
    async fn server_with_stalled_replies(
        pki: &TestPki,
        size: usize,
        first: usize,
    ) -> (TlsServer, Arc<Mutex<Vec<Release>>>) {
        let stalled = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&stalled);
        let server = doh_server(pki, move |_, body| {
            let mut message = answer(body, ANSWER_MARKER, false);
            message.resize(size, 0);
            let (response, release) = gated_response(message, first);
            recorder.lock().unwrap().push(release);

            Reaction {
                delay: Duration::ZERO,
                response,
            }
        })
        .await;

        (server, stalled)
    }

    async fn until(mut condition: impl FnMut() -> bool) {
        for _ in 0..400 {
            if condition() {
                return;
            }

            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        panic!("the condition did not become true");
    }

    #[tokio::test]
    async fn partial_bodies_in_flight_never_hold_more_than_the_budget() {
        let pki = TestPki::new();
        let (server, stalled) = server_with_stalled_replies(&pki, 30_000, 10_000).await;
        let upstream = Arc::new(upstream(&pki, &server));
        let budget = Budget::new(100_000);
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let (upstream, budget) = (Arc::clone(&upstream), Arc::clone(&budget));
            tasks.push(tokio::spawn(async move {
                upstream
                    .query_charged(&query_for("example.com."), &budget, deadline())
                    .await
            }));
        }

        until(|| tasks.iter().filter(|task| task.is_finished()).count() == 5).await;

        assert_eq!(budget.used(), 90_000, "three announced replies fit");
        let mut refused = 0;
        let mut waiting = Vec::new();
        for task in tasks {
            if task.is_finished() {
                let result = task.await.unwrap();
                assert!(
                    matches!(result, Err(UpstreamError::BudgetExhausted)),
                    "{result:?}"
                );
                refused += 1;
            } else {
                waiting.push(task);
            }
        }
        assert_eq!(refused, 5);

        until(|| stalled.lock().unwrap().len() == 8).await;
        for release in stalled.lock().unwrap().drain(..) {
            release.send_rest();
        }
        let mut held = Vec::new();
        for task in waiting {
            let (reply, charge) = task.await.unwrap().unwrap();
            assert_eq!(reply.len(), 30_000);
            assert_eq!(charge.bytes(), 30_000);
            held.push(charge);
        }
        assert_eq!(budget.used(), 90_000, "the charges went to the callers");

        drop(held);

        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn a_timeout_in_the_middle_of_a_body_frees_the_charge() {
        let pki = TestPki::new();
        let (server, _stalled) = server_with_stalled_replies(&pki, 30_000, 10_000).await;
        let upstream = upstream(&pki, &server);
        let budget = Budget::new(100_000);

        let result = upstream
            .query_charged(
                &query_for("example.com."),
                &budget,
                Instant::now() + Duration::from_millis(300),
            )
            .await;

        assert!(matches!(result, Err(UpstreamError::Timeout)), "{result:?}");
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn dropping_the_query_in_the_middle_of_a_body_frees_the_charge() {
        let pki = TestPki::new();
        let (server, stalled) = server_with_stalled_replies(&pki, 30_000, 10_000).await;
        let upstream = Arc::new(upstream(&pki, &server));
        let budget = Budget::new(100_000);
        let (task_upstream, task_budget) = (Arc::clone(&upstream), Arc::clone(&budget));
        let task = tokio::spawn(async move {
            task_upstream
                .query_charged(&query_for("example.com."), &task_budget, deadline())
                .await
        });
        until(|| budget.used() == 30_000 && stalled.lock().unwrap().len() == 1).await;

        task.abort();
        let _ = task.await;

        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn a_body_without_a_length_is_charged_as_it_arrives() {
        let pki = TestPki::new();
        let server = doh_server(&pki, |_, _| Reaction {
            delay: Duration::ZERO,
            response: Response::builder()
                .header(CONTENT_TYPE, DNS_MESSAGE)
                .body(Unannounced { chunks: 3 }.boxed())
                .unwrap(),
        })
        .await;
        let upstream = upstream(&pki, &server);
        let budget = Budget::new(40_000);

        let result = upstream
            .query_charged(&query_for("example.com."), &budget, deadline())
            .await;

        assert!(
            matches!(result, Err(UpstreamError::BudgetExhausted)),
            "{result:?}"
        );
        assert_eq!(budget.used(), 0, "the failed reply gave everything back");
    }

    #[tokio::test]
    async fn a_failed_reply_gives_its_bytes_back() {
        let pki = TestPki::new();
        let server = doh_server(&pki, |_, _| Reaction {
            delay: Duration::ZERO,
            response: dns_message(vec![7; 500]),
        })
        .await;
        let budget = Budget::new(100_000);

        let result = upstream(&pki, &server)
            .query_charged(&query_for("example.com."), &budget, deadline())
            .await;

        assert!(matches!(result, Err(UpstreamError::BadReply)));
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn a_reply_that_does_not_fit_is_refused_before_it_is_read() {
        let pki = TestPki::new();
        let (server, _stalled) = server_with_stalled_replies(&pki, 30_000, 10_000).await;
        let budget = Budget::new(20_000);

        let result = upstream(&pki, &server)
            .query_charged(&query_for("example.com."), &budget, deadline())
            .await;

        assert!(
            matches!(result, Err(UpstreamError::BudgetExhausted)),
            "{result:?}"
        );
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn a_server_without_h2_gets_no_http_bytes() {
        let pki = TestPki::new();
        let (received, bytes_seen) = tokio::sync::mpsc::unbounded_channel();
        let server = TlsServer::start(
            pki.server_config(&[], rustls::crypto::ring::default_provider()),
            move |mut stream| {
                let received = received.clone();

                async move {
                    let mut buffer = Vec::new();
                    let _ = stream.read_to_end(&mut buffer).await;
                    let _ = received.send(buffer.len());
                }
            },
        )
        .await;
        let mut bytes_seen = bytes_seen;

        let result = upstream(&pki, &server)
            .query(&query_for("example.com."), deadline())
            .await;

        assert!(matches!(result, Err(UpstreamError::Io(_))), "{result:?}");
        assert_eq!(bytes_seen.recv().await, Some(0));
    }

    #[tokio::test]
    async fn the_h2_window_and_header_settings_are_sent_to_the_server() {
        let pki = TestPki::new();
        let (found, seen) = tokio::sync::oneshot::channel();
        let found = Mutex::new(Some(found));
        let server = TlsServer::start(doh_config(&pki), move |mut stream| {
            let found = found.lock().unwrap().take();

            async move {
                let Some(found) = found else {
                    return;
                };

                let mut preface = [0u8; 24];
                stream.read_exact(&mut preface).await.unwrap();
                let mut frames = Vec::new();
                loop {
                    let mut header = [0u8; 9];
                    stream.read_exact(&mut header).await.unwrap();
                    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]);
                    let mut payload = vec![0u8; length as usize];
                    stream.read_exact(&mut payload).await.unwrap();
                    let frame_type = header[3];
                    frames.push((frame_type, payload));
                    if frame_type == 1 {
                        break;
                    }
                }

                let _ = found.send(frames);
                std::future::pending::<()>().await;
            }
        })
        .await;
        let upstream = upstream(&pki, &server);

        let _ = upstream
            .query(
                &query_for("example.com."),
                Instant::now() + Duration::from_millis(300),
            )
            .await;

        let frames = seen.await.unwrap();
        let settings: Vec<(u16, u32)> = frames
            .iter()
            .find(|(frame_type, _)| *frame_type == 4)
            .unwrap()
            .1
            .chunks(6)
            .map(|pair| {
                (
                    u16::from_be_bytes([pair[0], pair[1]]),
                    u32::from_be_bytes([pair[2], pair[3], pair[4], pair[5]]),
                )
            })
            .collect();
        let window_update = &frames
            .iter()
            .find(|(frame_type, _)| *frame_type == 8)
            .unwrap()
            .1;
        let increment = u32::from_be_bytes(window_update[0..4].try_into().unwrap());
        assert!(settings.contains(&(0x4, 64 * 1024)), "{settings:?}");
        assert!(settings.contains(&(0x6, 16 * 1024)), "{settings:?}");
        assert_eq!(increment, 128 * 1024 - 65_535);
    }
}
