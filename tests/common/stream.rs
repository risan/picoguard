//! A local HTTP/1.1 server for memory tests. It never holds a whole body in memory: a body is a
//! 16 KiB pattern written over and over, or a file read in 16 KiB pieces, so the server does not
//! inflate the memory of the process it runs in.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ring::digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

pub const PIECE_BYTES: usize = 16 * 1024;

pub fn pattern() -> Vec<u8> {
    (0..PIECE_BYTES)
        .map(|index| (index * 31 % 251) as u8)
        .collect()
}

/// The SHA-256 of `size` bytes of the pattern, computed piece by piece.
pub fn pattern_hash(size: u64) -> [u8; 32] {
    let pattern = pattern();
    let mut context = digest::Context::new(&digest::SHA256);
    let mut left = size;

    while left > 0 {
        let piece = (left as usize).min(PIECE_BYTES);
        context.update(&pattern[..piece]);
        left -= piece as u64;
    }

    context.finish().as_ref().try_into().unwrap()
}

#[derive(Clone)]
pub enum Route {
    Bytes(Vec<u8>),
    /// `size` bytes of the pattern. With `hold_at_half` the server stops at half the size
    /// and goes on only when the gate is opened.
    Pattern {
        size: u64,
        hold_at_half: bool,
    },
    File(PathBuf),
}

pub struct StreamServer {
    pub address: SocketAddr,
    routes: Arc<Mutex<HashMap<String, Route>>>,
    gate: watch::Sender<bool>,
}

impl StreamServer {
    pub async fn start() -> StreamServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let routes: Arc<Mutex<HashMap<String, Route>>> = Arc::default();
        let (gate, _) = watch::channel(false);
        let pattern = Arc::new(pattern());
        let served = Arc::clone(&routes);
        let opened = gate.clone();

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(
                    stream,
                    Arc::clone(&served),
                    Arc::clone(&pattern),
                    opened.subscribe(),
                ));
            }
        });

        StreamServer {
            address,
            routes,
            gate,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    pub fn set(&self, path: &str, route: Route) {
        self.routes.lock().unwrap().insert(path.to_string(), route);
    }

    /// Lets the bodies that hold at half go on.
    pub fn release(&self) {
        self.gate.send_replace(true);
    }
}

async fn serve(
    mut stream: TcpStream,
    routes: Arc<Mutex<HashMap<String, Route>>>,
    pattern: Arc<Vec<u8>>,
    mut gate: watch::Receiver<bool>,
) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];

    while !head.ends_with(b"\r\n\r\n") {
        if stream.read_exact(&mut byte).await.is_err() {
            return;
        }

        head.push(byte[0]);
    }

    let path = String::from_utf8_lossy(&head)
        .split(' ')
        .nth(1)
        .unwrap_or("/")
        .to_string();
    let route = routes.lock().unwrap().get(&path).cloned();
    let _ = reply(&mut stream, route, &pattern, &mut gate).await;
    let _ = stream.shutdown().await;
}

async fn reply(
    stream: &mut TcpStream,
    route: Option<Route>,
    pattern: &[u8],
    gate: &mut watch::Receiver<bool>,
) -> std::io::Result<()> {
    let head = |length: u64| {
        format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {length}\r\n\r\n")
    };

    match route {
        None => {
            stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await
        }

        Some(Route::Bytes(body)) => {
            stream.write_all(head(body.len() as u64).as_bytes()).await?;
            stream.write_all(&body).await
        }

        Some(Route::Pattern { size, hold_at_half }) => {
            stream.write_all(head(size).as_bytes()).await?;
            let mut left = size;
            let mut held = !hold_at_half;

            while left > 0 {
                if !held && left <= size / 2 {
                    held = true;
                    let _ = gate.wait_for(|open| *open).await;
                }

                let piece = (left as usize).min(pattern.len());
                stream.write_all(&pattern[..piece]).await?;
                left -= piece as u64;
            }

            Ok(())
        }

        Some(Route::File(path)) => {
            let mut file = std::fs::File::open(&path)?;
            let length = file.metadata()?.len();
            stream.write_all(head(length).as_bytes()).await?;
            let mut buffer = vec![0u8; PIECE_BYTES];

            loop {
                let read = std::io::Read::read(&mut file, &mut buffer)?;

                if read == 0 {
                    return Ok(());
                }

                stream.write_all(&buffer[..read]).await?;
            }
        }
    }
}
