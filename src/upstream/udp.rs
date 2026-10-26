use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout_at};

use super::{UpstreamError, is_answer_to, random_u64};

thread_local! {
    // Every query on the runtime thread receives into this one buffer, so no reply maps and
    // unmaps a fresh 64 KiB block. Only the pages a datagram actually fills become resident.
    static RECEIVE_BUFFER: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

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

    loop {
        let Ok(readable) = timeout_at(deadline, socket.readable()).await else {
            return Err(UpstreamError::Timeout);
        };

        readable?;

        if let Some(reply) = receive_answer(&socket, request, max_reply)? {
            return Ok(reply);
        }
    }
}

/// Reads one datagram if there is one. `None` means nothing to read yet, or a datagram that
/// does not answer `request`.
fn receive_answer(
    socket: &UdpSocket,
    request: &[u8],
    max_reply: usize,
) -> Result<Option<Vec<u8>>, UpstreamError> {
    RECEIVE_BUFFER.with_borrow_mut(|buffer| {
        // Room for one byte more than `max_reply`, so a datagram over the cap is seen as
        // such instead of arriving cut to the buffer size.
        buffer.clear();
        buffer.reserve(max_reply + 1);

        match socket.try_recv_buf(buffer) {
            Ok(_) => {}

            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok(None);
            }

            Err(error) => {
                return Err(error.into());
            }
        }

        if !is_answer_to(request, buffer) {
            return Ok(None);
        }

        if buffer.len() > max_reply {
            return Err(UpstreamError::ReplyTooLarge);
        }

        Ok(Some(buffer.clone()))
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::upstream::test_dns::{ANSWER_MARKER, answer, query_for};

    const LIMIT: usize = 64 * 1024;
    // Loopback drops UDP datagrams that need fragmenting (over 1472 bytes) on
    // some machines, so the socket tests stay below that.
    const DATAGRAM: usize = 1200;

    /// A UDP server that answers every datagram with a reply of `size` bytes.
    async fn server_replying_with(size: usize) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
                let mut reply = answer(&buffer[..length], ANSWER_MARKER, false);
                reply.resize(size, 0);
                let _ = socket.send_to(&reply, peer).await;
            }
        });

        address
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }

    fn receive_buffer_address_and_capacity() -> (usize, usize) {
        RECEIVE_BUFFER.with_borrow(|buffer| (buffer.as_ptr() as usize, buffer.capacity()))
    }

    #[tokio::test]
    async fn queries_share_one_receive_buffer_that_holds_the_cap_and_one_byte_more() {
        let server = server_replying_with(DATAGRAM).await;

        exchange(server, &mut query_for("example.com."), LIMIT, soon())
            .await
            .unwrap();
        let (address, capacity) = receive_buffer_address_and_capacity();
        exchange(server, &mut query_for("example.org."), LIMIT, soon())
            .await
            .unwrap();

        assert!(capacity > LIMIT);
        assert_eq!(receive_buffer_address_and_capacity(), (address, capacity));
    }

    #[tokio::test]
    async fn a_returned_reply_owns_exactly_its_bytes_and_survives_the_next_query() {
        let server = server_replying_with(DATAGRAM).await;

        let first = exchange(server, &mut query_for("example.com."), LIMIT, soon())
            .await
            .unwrap();
        let copy = first.clone();
        exchange(server, &mut query_for("other.example."), LIMIT, soon())
            .await
            .unwrap();

        assert_eq!(first.capacity(), first.len());
        assert_eq!(first, copy);
    }

    #[tokio::test]
    async fn a_reply_is_returned_whole() {
        let server = server_replying_with(DATAGRAM).await;

        let reply = exchange(server, &mut query_for("example.com."), LIMIT, soon())
            .await
            .unwrap();

        assert_eq!(reply.len(), DATAGRAM);
    }

    #[tokio::test]
    async fn a_reply_one_byte_over_the_cap_is_rejected_not_cut_short() {
        let server = server_replying_with(DATAGRAM).await;

        let result = exchange(server, &mut query_for("example.com."), DATAGRAM - 1, soon()).await;

        assert!(
            matches!(result, Err(UpstreamError::ReplyTooLarge)),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn a_reply_exactly_at_the_cap_is_accepted() {
        let server = server_replying_with(DATAGRAM).await;

        let reply = exchange(server, &mut query_for("example.com."), DATAGRAM, soon())
            .await
            .unwrap();

        assert_eq!(reply.len(), DATAGRAM);
    }
}
