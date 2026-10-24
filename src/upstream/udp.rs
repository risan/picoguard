use std::net::SocketAddr;

use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout_at};

use super::{UpstreamError, is_answer_to, random_u64};

// Larger than the EDNS size we announce, so an oversized datagram shows up as
// a parse failure instead of silently cut data.
const RECEIVE_BUFFER: usize = 4096;

/// Sends `request` from a fresh socket (so every query has its own source
/// port) and returns the first datagram that answers it. Datagrams with a
/// wrong ID or question are ignored until the deadline. An answer longer than
/// `max_reply` is an error.
pub async fn exchange(
    server: SocketAddr,
    request: &mut [u8],
    max_reply: usize,
    deadline: Instant,
) -> Result<Vec<u8>, UpstreamError> {
    let local: SocketAddr = if server.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    let socket = UdpSocket::bind(local).await?;
    socket.connect(server).await?;

    request[0..2].copy_from_slice(&(random_u64() as u16).to_be_bytes());
    socket.send(request).await?;

    let mut buffer = vec![0u8; RECEIVE_BUFFER];
    loop {
        let Ok(received) = timeout_at(deadline, socket.recv(&mut buffer)).await else {
            return Err(UpstreamError::Timeout);
        };
        let length = received?;

        if is_answer_to(request, &buffer[..length]) {
            if length > max_reply {
                return Err(UpstreamError::ReplyTooLarge);
            }

            buffer.truncate(length);
            buffer.shrink_to_fit();

            return Ok(buffer);
        }
    }
}
