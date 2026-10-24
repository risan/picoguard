//! UDP and TCP listeners in front of the pipeline, with the access policy and
//! the connection limits of D21.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::timeout;

use crate::budget::{Budget, Charge};
use crate::config::{Cidr, Config, ServerConfig, is_allowed};
use crate::dns::build::Protocol;
use crate::pipeline::{Pipeline, Quick};

const UDP_RECEIVE_BUFFER: usize = 4096;
const TCP_BACKLOG: i32 = 128;
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(100);

pub struct Listeners {
    udp: Vec<UdpSocket>,
    tcp: Vec<TcpListener>,
}

impl Listeners {
    /// Opens a UDP socket and a TCP listener on every configured address. An
    /// IPv6 address that cannot be used (a kernel without IPv6, say) is
    /// skipped with a warning; any other failure is an error.
    pub fn bind(server: &ServerConfig) -> Result<Listeners, String> {
        let mut listeners = Listeners {
            udp: Vec::new(),
            tcp: Vec::new(),
        };

        for ip in &server.bind {
            let address = SocketAddr::new(*ip, server.port);

            match bind_both(address) {
                Ok((udp, tcp)) => {
                    listeners.udp.push(udp);
                    listeners.tcp.push(tcp);
                }

                Err(error) if address.is_ipv6() => {
                    log::warn!("skipping {address}: {error}");
                }

                Err(error) => {
                    return Err(format!("cannot listen on {address}: {error}"));
                }
            }
        }

        if listeners.udp.is_empty() {
            return Err("no address to listen on".to_string());
        }

        Ok(listeners)
    }

    pub fn udp_addresses(&self) -> Vec<SocketAddr> {
        self.udp
            .iter()
            .filter_map(|socket| socket.local_addr().ok())
            .collect()
    }

    pub fn tcp_addresses(&self) -> Vec<SocketAddr> {
        self.tcp
            .iter()
            .filter_map(|listener| listener.local_addr().ok())
            .collect()
    }
}

fn bind_both(address: SocketAddr) -> io::Result<(UdpSocket, TcpListener)> {
    Ok((bind_udp(address)?, bind_tcp(address)?))
}

// IPV6_V6ONLY keeps `::` from also taking IPv4, so `0.0.0.0` and `::` can
// share a port.
fn bind_udp(address: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(SocketProtocol::UDP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }

    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;

    UdpSocket::from_std(socket.into())
}

fn bind_tcp(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::STREAM,
        Some(SocketProtocol::TCP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }

    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(TCP_BACKLOG)?;

    TcpListener::from_std(socket.into())
}

struct TcpSettings {
    max_connections: usize,
    idle: Duration,
    read_buffer: usize,
    queue_replies: usize,
    queue_bytes: usize,
    write_timeout: Duration,
}

/// Starts serving on the current runtime and returns at once.
pub fn spawn(listeners: Listeners, pipeline: Arc<Pipeline>, config: &Config) {
    let allowed: Arc<[Cidr]> = config.server.allow_from.clone().into();
    let settings = Arc::new(TcpSettings {
        max_connections: config.limits.tcp_max_connections,
        idle: Duration::from_secs(config.limits.tcp_idle_secs),
        read_buffer: config.limits.tcp_read_buffer,
        queue_replies: config.limits.tcp_queue_replies,
        queue_bytes: config.limits.tcp_queue_bytes,
        write_timeout: Duration::from_secs(config.limits.tcp_write_timeout_secs),
    });

    for socket in listeners.udp {
        tokio::spawn(serve_udp(
            socket,
            Arc::clone(&pipeline),
            Arc::clone(&allowed),
        ));
    }

    let connections = Arc::new(Semaphore::new(settings.max_connections));
    for listener in listeners.tcp {
        tokio::spawn(serve_tcp(
            listener,
            Arc::clone(&pipeline),
            Arc::clone(&allowed),
            Arc::clone(&settings),
            Arc::clone(&connections),
        ));
    }
}

async fn serve_udp(socket: UdpSocket, pipeline: Arc<Pipeline>, allowed: Arc<[Cidr]>) {
    let socket = Arc::new(socket);
    let mut buffer = vec![0u8; UDP_RECEIVE_BUFFER];
    let mut out = Vec::with_capacity(512);

    loop {
        let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
            tokio::time::sleep(ACCEPT_ERROR_PAUSE).await;

            continue;
        };

        if !is_allowed(&allowed, peer.ip()) {
            continue;
        }

        let request = &buffer[..length];
        match pipeline.answer_quickly(request, Protocol::Udp, &mut out) {
            Quick::Replied => {
                let _ = socket.send_to(&out, peer).await;
            }

            Quick::Dropped => {}

            Quick::NeedsUpstream => {
                tokio::spawn(answer_udp(
                    Arc::clone(&pipeline),
                    Arc::clone(&socket),
                    request.to_vec(),
                    peer,
                ));
            }
        }
    }
}

async fn answer_udp(
    pipeline: Arc<Pipeline>,
    socket: Arc<UdpSocket>,
    request: Vec<u8>,
    peer: SocketAddr,
) {
    let mut out = Vec::new();

    if pipeline.answer(&request, Protocol::Udp, &mut out).await {
        let _ = socket.send_to(&out, peer).await;
    }
}

async fn serve_tcp(
    listener: TcpListener,
    pipeline: Arc<Pipeline>,
    allowed: Arc<[Cidr]>,
    settings: Arc<TcpSettings>,
    connections: Arc<Semaphore>,
) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            tokio::time::sleep(ACCEPT_ERROR_PAUSE).await;

            continue;
        };

        // Dropping the stream closes it before a byte is read.
        if !is_allowed(&allowed, peer.ip()) {
            continue;
        }

        let Ok(slot) = Arc::clone(&connections).try_acquire_owned() else {
            continue;
        };

        tokio::spawn(serve_connection(
            stream,
            Arc::clone(&pipeline),
            Arc::clone(&settings),
            slot,
        ));
    }
}

/// A framed reply waiting for the writer. It holds its share of the byte
/// budgets and its pipelining slot until it has been written.
struct QueuedReply {
    frame: Vec<u8>,
    _charges: Option<(Charge, Charge)>,
    _slot: OwnedSemaphorePermit,
}

async fn serve_connection(
    stream: TcpStream,
    pipeline: Arc<Pipeline>,
    settings: Arc<TcpSettings>,
    connection_slot: OwnedSemaphorePermit,
) {
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::with_capacity(settings.read_buffer, read_half);
    let slots = Arc::new(Semaphore::new(settings.queue_replies));
    let queue_budget = Budget::new(settings.queue_bytes);
    let (queue, replies) = mpsc::unbounded_channel();
    let write_timeout = settings.write_timeout;
    let mut writer = tokio::spawn(async move {
        write_replies(write_half, replies, write_timeout).await;
        drop(connection_slot);
    });

    loop {
        // At most `queue_replies` queries are in progress or queued, so a
        // client that does not read its replies stops being read from.
        let Ok(slot) = Arc::clone(&slots).acquire_owned().await else {
            break;
        };

        let message = tokio::select! {
            _ = &mut writer => {
                break;
            }

            message = timeout(settings.idle, read_message(&mut reader, settings.read_buffer)) => {
                message
            }
        };
        let Ok(Ok(Some(request))) = message else {
            break;
        };

        tokio::spawn(answer_tcp(
            Arc::clone(&pipeline),
            request,
            slot,
            queue.clone(),
            Arc::clone(&queue_budget),
        ));
    }
}

/// Reads one length-prefixed message. `None` means the client closed the
/// connection or sent an empty message. The buffer grows with the bytes that
/// arrive, so announcing 64 KiB costs nothing until it is sent.
async fn read_message<R>(reader: &mut R, initial_capacity: usize) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut length = [0u8; 2];
    if reader.read_exact(&mut length).await.is_err() {
        return Ok(None);
    }

    let length = usize::from(u16::from_be_bytes(length));
    let mut message = Vec::with_capacity(length.min(initial_capacity));
    reader.take(length as u64).read_to_end(&mut message).await?;

    if length == 0 || message.len() < length {
        return Ok(None);
    }

    Ok(Some(message))
}

async fn answer_tcp(
    pipeline: Arc<Pipeline>,
    request: Vec<u8>,
    slot: OwnedSemaphorePermit,
    queue: mpsc::UnboundedSender<QueuedReply>,
    queue_budget: Arc<Budget>,
) {
    let mut out = Vec::new();
    if !pipeline.answer(&request, Protocol::Tcp, &mut out).await {
        return;
    }

    let mut frame = frame_of(&out);
    let charges = pipeline
        .budget()
        .try_charge(frame.len())
        .zip(queue_budget.try_charge(frame.len()));

    // A reply that does not fit is replaced by a SERVFAIL of a few dozen
    // bytes, which is not charged.
    if charges.is_none() {
        if !pipeline.servfail(&request, Protocol::Tcp, &mut out) {
            return;
        }

        frame = frame_of(&out);
    }

    let _ = queue.send(QueuedReply {
        frame,
        _charges: charges,
        _slot: slot,
    });
}

fn frame_of(message: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(message.len() + 2);
    frame.extend_from_slice(&(message.len() as u16).to_be_bytes());
    frame.extend_from_slice(message);

    frame
}

/// Writes queued replies in order. A write that takes longer than
/// `write_timeout`, or fails, ends the connection: the receiver is dropped and
/// with it everything still queued.
async fn write_replies<W>(
    mut writer: W,
    mut replies: mpsc::UnboundedReceiver<QueuedReply>,
    write_timeout: Duration,
) where
    W: AsyncWrite + Unpin,
{
    while let Some(reply) = replies.recv().await {
        let written = timeout(write_timeout, writer.write_all(&reply.frame)).await;

        if !matches!(written, Ok(Ok(()))) {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    fn ipv6_available() -> bool {
        std::net::UdpSocket::bind("[::1]:0").is_ok()
    }

    fn free_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn server_config(bind: &[&str], port: u16) -> ServerConfig {
        ServerConfig {
            bind: bind
                .iter()
                .map(|address| address.parse().unwrap())
                .collect(),
            port,
            ..ServerConfig::default()
        }
    }

    #[tokio::test]
    async fn listeners_open_udp_and_tcp_on_the_requested_address() {
        let listeners = Listeners::bind(&server_config(&["127.0.0.1"], 0)).unwrap();

        assert_eq!(listeners.udp_addresses().len(), 1);
        assert_eq!(listeners.tcp_addresses().len(), 1);
        assert!(listeners.udp_addresses()[0].ip().is_loopback());
    }

    #[tokio::test]
    async fn wildcard_ipv4_and_ipv6_share_one_port() {
        if !ipv6_available() {
            return;
        }

        let port = free_port();

        let listeners = Listeners::bind(&server_config(&["0.0.0.0", "::"], port)).unwrap();

        assert_eq!(listeners.udp_addresses().len(), 2);
        assert_eq!(listeners.tcp_addresses().len(), 2);
    }

    #[tokio::test]
    async fn an_address_in_use_is_an_error_that_names_it() {
        let taken = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = taken.local_addr().unwrap().port();

        let error = Listeners::bind(&server_config(&["127.0.0.1"], port))
            .err()
            .unwrap();

        assert!(error.contains(&format!("127.0.0.1:{port}")), "{error}");
    }

    #[tokio::test]
    async fn an_unusable_ipv6_address_is_skipped_when_another_one_works() {
        let unassigned = "2001:db8:ffff::1";

        let listeners = Listeners::bind(&server_config(&["127.0.0.1", unassigned], 0)).unwrap();

        assert_eq!(listeners.udp_addresses().len(), 1);
    }

    #[tokio::test]
    async fn having_no_usable_address_is_an_error() {
        let error = Listeners::bind(&server_config(&["2001:db8:ffff::1"], 0))
            .err()
            .unwrap();

        assert!(error.contains("no address"), "{error}");
    }

    fn queued(frame: Vec<u8>) -> QueuedReply {
        let slot = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();

        QueuedReply {
            frame,
            _charges: None,
            _slot: slot,
        }
    }

    #[tokio::test]
    async fn replies_are_written_in_order() {
        let (writer, mut peer) = duplex(4096);
        let (queue, replies) = mpsc::unbounded_channel();
        queue.send(queued(vec![1, 2, 3])).unwrap();
        queue.send(queued(vec![4, 5])).unwrap();
        drop(queue);

        write_replies(writer, replies, Duration::from_secs(1)).await;

        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, [1, 2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn a_client_that_stops_reading_hits_the_write_deadline_and_frees_the_queue() {
        let (writer, _peer_that_never_reads) = duplex(8);
        let (queue, replies) = mpsc::unbounded_channel();
        queue.send(queued(vec![0; 1000])).unwrap();
        queue.send(queued(vec![0; 1000])).unwrap();
        let started = std::time::Instant::now();

        write_replies(writer, replies, Duration::from_millis(100)).await;

        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(queue.send(queued(vec![1])).is_err(), "receiver was dropped");
    }

    #[tokio::test]
    async fn messages_are_read_with_their_length_prefix() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&3u16.to_be_bytes());
        bytes.extend_from_slice(&[7, 8, 9]);
        bytes.extend_from_slice(&2u16.to_be_bytes());
        bytes.extend_from_slice(&[1, 2]);
        let mut reader = &bytes[..];

        let first = read_message(&mut reader, 2048).await.unwrap();
        let second = read_message(&mut reader, 2048).await.unwrap();
        let end = read_message(&mut reader, 2048).await.unwrap();

        assert_eq!(first, Some(vec![7, 8, 9]));
        assert_eq!(second, Some(vec![1, 2]));
        assert_eq!(end, None);
    }

    #[tokio::test]
    async fn empty_and_cut_off_messages_end_the_connection() {
        let empty = 0u16.to_be_bytes();
        let mut cut_off = 10u16.to_be_bytes().to_vec();
        cut_off.extend_from_slice(&[1, 2, 3]);

        assert_eq!(read_message(&mut &empty[..], 2048).await.unwrap(), None);
        assert_eq!(read_message(&mut &cut_off[..], 2048).await.unwrap(), None);
    }
}
