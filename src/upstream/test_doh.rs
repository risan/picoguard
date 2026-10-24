//! A DoH server for tests: hyper's HTTP/2 server behind the test TLS server.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::header::CONTENT_TYPE;
use http::request::Parts;
use http::{Request, Response};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::crypto::ring;

use super::doh::DNS_MESSAGE;
use super::test_dns::{ANSWER_MARKER, answer};
use super::test_tls::{TestPki, TlsServer};

pub type ReplyBody = BoxBody<Bytes, Infallible>;
type ServerStream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
type Handled = Pin<Box<dyn Future<Output = ()> + Send>>;

/// What a test server does with one request.
pub struct Reaction {
    pub delay: Duration,
    pub response: Response<ReplyBody>,
}

pub fn dns_message(bytes: Vec<u8>) -> Response<ReplyBody> {
    Response::builder()
        .header(CONTENT_TYPE, DNS_MESSAGE)
        .body(Full::new(Bytes::from(bytes)).boxed())
        .unwrap()
}

pub fn respond_with_answer(body: &[u8]) -> Reaction {
    Reaction {
        delay: Duration::ZERO,
        response: dns_message(answer(body, ANSWER_MARKER, false)),
    }
}

/// A chunked body of `chunks` times 16 KiB that announces no length.
pub struct Unannounced {
    pub chunks: usize,
}

impl Body for Unannounced {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if self.chunks == 0 {
            return Poll::Ready(None);
        }

        self.chunks -= 1;

        Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![0u8; 16 * 1024])))))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

pub fn doh_config(pki: &TestPki) -> rustls::ServerConfig {
    pki.server_config(&["h2"], ring::default_provider())
}

pub async fn doh_server(
    pki: &TestPki,
    behavior: impl Fn(&Parts, &[u8]) -> Reaction + Send + Sync + 'static,
) -> TlsServer {
    let behavior = Arc::new(behavior);

    TlsServer::start(doh_config(pki), serve_doh(behavior)).await
}

pub fn serve_doh<B>(behavior: Arc<B>) -> impl Fn(ServerStream) -> Handled + Send + Sync + 'static
where
    B: Fn(&Parts, &[u8]) -> Reaction + Send + Sync + 'static,
{
    move |stream| {
        let behavior = Arc::clone(&behavior);

        Box::pin(async move {
            let service = service_fn(move |request: Request<Incoming>| {
                let behavior = Arc::clone(&behavior);

                async move {
                    let (parts, body) = request.into_parts();
                    let body = body.collect().await.unwrap().to_bytes();
                    let reaction = behavior(&parts, &body);
                    tokio::time::sleep(reaction.delay).await;

                    Ok::<_, Infallible>(reaction.response)
                }
            });

            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        })
    }
}
