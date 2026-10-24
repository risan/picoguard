//! A local HTTP/1.1 server for blocklists: conditional GET, error statuses, a delay, and
//! counters for requests and for connections open at the same time. Nothing leaves the
//! machine.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[derive(Clone)]
enum Page {
    Text {
        body: String,
        etag: Option<String>,
        content_type: Option<String>,
    },
    Status(u16),
}

#[derive(Default)]
struct State {
    pages: Mutex<HashMap<String, Page>>,
    delay: Mutex<Duration>,
    requests: AtomicUsize,
    not_modified: AtomicUsize,
    active: AtomicUsize,
    most_active: AtomicUsize,
}

pub struct ListServer {
    pub address: SocketAddr,
    state: Arc<State>,
    task: JoinHandle<()>,
}

impl ListServer {
    pub async fn start() -> ListServer {
        ListServer::bind("127.0.0.1:0".parse().unwrap()).await
    }

    /// Starts on a given address, to come back where a stopped server was.
    pub async fn bind(address: SocketAddr) -> ListServer {
        let listener = TcpListener::bind(address).await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(State::default());
        let served = Arc::clone(&state);
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let state = Arc::clone(&served);

                tokio::spawn(async move {
                    let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
                    state.most_active.fetch_max(active, Ordering::SeqCst);

                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        let Ok(byte) = stream.read_u8().await else {
                            state.active.fetch_sub(1, Ordering::SeqCst);

                            return;
                        };

                        head.push(byte);
                    }

                    state.requests.fetch_add(1, Ordering::SeqCst);
                    let delay = *state.delay.lock().unwrap();
                    tokio::time::sleep(delay).await;

                    let reply = answer(&state, &String::from_utf8_lossy(&head));
                    let _ = stream.write_all(&reply).await;
                    let _ = stream.shutdown().await;
                    state.active.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });

        ListServer {
            address,
            state,
            task,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    /// Serves `body` at `path`, with an ETag when given.
    pub fn serve(&self, path: &str, body: &str, etag: Option<&str>) {
        self.serve_typed(path, body, etag, None);
    }

    /// Like `serve`, with a `Content-Type` when given.
    pub fn serve_typed(
        &self,
        path: &str,
        body: &str,
        etag: Option<&str>,
        content_type: Option<&str>,
    ) {
        self.state.pages.lock().unwrap().insert(
            path.to_string(),
            Page::Text {
                body: body.to_string(),
                etag: etag.map(str::to_string),
                content_type: content_type.map(str::to_string),
            },
        );
    }

    /// Answers `path` with an error status.
    pub fn fail(&self, path: &str, status: u16) {
        self.state
            .pages
            .lock()
            .unwrap()
            .insert(path.to_string(), Page::Status(status));
    }

    pub fn set_delay(&self, delay: Duration) {
        *self.state.delay.lock().unwrap() = delay;
    }

    pub fn requests(&self) -> usize {
        self.state.requests.load(Ordering::SeqCst)
    }

    pub fn not_modified(&self) -> usize {
        self.state.not_modified.load(Ordering::SeqCst)
    }

    /// The most connections that were open at the same moment.
    pub fn most_active(&self) -> usize {
        self.state.most_active.load(Ordering::SeqCst)
    }

    /// Closes the listener; the address is refused until `bind` takes it again.
    pub async fn stop(self) -> SocketAddr {
        self.task.abort();
        let _ = self.task.await;

        self.address
    }
}

fn answer(state: &State, head: &str) -> Vec<u8> {
    let mut lines = head.lines();
    let path = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .unwrap_or("/")
        .to_string();
    let if_none_match = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("if-none-match"))
        .map(|(_, value)| value.trim().to_string());
    let page = state.pages.lock().unwrap().get(&path).cloned();

    match page {
        Some(Page::Text {
            body,
            etag,
            content_type,
        }) => {
            if etag.is_some() && etag == if_none_match {
                state.not_modified.fetch_add(1, Ordering::SeqCst);

                return b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_vec();
            }

            let etag = etag
                .map(|etag| format!("ETag: {etag}\r\n"))
                .unwrap_or_default();
            let content_type = content_type
                .map(|content_type| format!("Content-Type: {content_type}\r\n"))
                .unwrap_or_default();
            let mut reply = format!(
                "HTTP/1.1 200 OK\r\nConnection: close\r\n{etag}{content_type}Content-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            reply.extend_from_slice(body.as_bytes());

            reply
        }

        Some(Page::Status(status)) => {
            format!("HTTP/1.1 {status} Error\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .into_bytes()
        }

        None => {
            b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".to_vec()
        }
    }
}
