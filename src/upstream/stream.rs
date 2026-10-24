//! DNS over a byte stream (RFC 7766 framing): a 2-byte length before every
//! message, many queries in flight on one connection, replies matched by ID.
//! Plain TCP uses it now; DoT reuses it over TLS.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, timeout, timeout_at};

use super::{UpstreamError, random_u64};

const READ_CHUNK: usize = 4096;
const OUTGOING_QUEUE: usize = 32;
const ID_ATTEMPTS: usize = 16;
const MIN_MESSAGE_LEN: usize = 12;

struct State {
    writer: Option<mpsc::Sender<Vec<u8>>>,
    pending: HashMap<u16, oneshot::Sender<Vec<u8>>>,
    /// Which connection the writer and pending queries belong to.
    epoch: u64,
}

/// One logical connection to an upstream that is reopened by `attach`.
pub struct StreamClient {
    state: Arc<Mutex<State>>,
    max_reply: usize,
    write_timeout: Duration,
}

impl StreamClient {
    pub fn new(max_reply: usize, write_timeout: Duration) -> StreamClient {
        StreamClient {
            state: Arc::new(Mutex::new(State {
                writer: None,
                pending: HashMap::new(),
                epoch: 0,
            })),
            max_reply,
            write_timeout,
        }
    }

    pub fn is_connected(&self) -> bool {
        let state = self.state.lock().unwrap();

        state
            .writer
            .as_ref()
            .is_some_and(|writer| !writer.is_closed())
    }

    /// Starts serving queries over `stream` and drops any previous connection.
    pub fn attach<S>(&self, stream: S)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (writer, outgoing) = mpsc::channel(OUTGOING_QUEUE);
        let epoch = {
            let mut state = self.state.lock().unwrap();
            state.epoch += 1;
            state.writer = Some(writer);
            state.pending.clear();

            state.epoch
        };

        let session = Session {
            state: Arc::clone(&self.state),
            epoch,
            max_reply: self.max_reply,
            write_timeout: self.write_timeout,
        };
        tokio::spawn(session.run(stream, outgoing));
    }

    /// Sends `request` (its ID is replaced) and waits for the matching reply.
    pub async fn query(
        &self,
        request: &mut [u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, UpstreamError> {
        let (reply_sender, reply) = oneshot::channel();
        let (id, writer, epoch) = self.register(reply_sender)?;
        let _unregister = Unregister {
            state: &self.state,
            id,
            epoch,
        };

        request[0..2].copy_from_slice(&id.to_be_bytes());
        let mut frame = Vec::with_capacity(request.len() + 2);
        frame.extend_from_slice(&(request.len() as u16).to_be_bytes());
        frame.extend_from_slice(request);

        match timeout_at(deadline, writer.send(frame)).await {
            Ok(Ok(())) => {}

            Ok(Err(_)) => {
                return Err(UpstreamError::Closed);
            }

            Err(_) => {
                return Err(UpstreamError::Timeout);
            }
        }

        match timeout_at(deadline, reply).await {
            Ok(Ok(bytes)) => Ok(bytes),

            Ok(Err(_)) => Err(UpstreamError::Closed),

            Err(_) => Err(UpstreamError::Timeout),
        }
    }

    fn register(
        &self,
        reply_sender: oneshot::Sender<Vec<u8>>,
    ) -> Result<(u16, mpsc::Sender<Vec<u8>>, u64), UpstreamError> {
        let mut state = self.state.lock().unwrap();
        let writer = state.writer.clone().ok_or(UpstreamError::Closed)?;

        for _ in 0..ID_ATTEMPTS {
            let id = random_u64() as u16;
            if let Entry::Vacant(slot) = state.pending.entry(id) {
                slot.insert(reply_sender);

                return Ok((id, writer, state.epoch));
            }
        }

        Err(UpstreamError::Closed)
    }
}

struct Unregister<'a> {
    state: &'a Mutex<State>,
    id: u16,
    epoch: u64,
}

impl Drop for Unregister<'_> {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap();
        if state.epoch == self.epoch {
            state.pending.remove(&self.id);
        }
    }
}

struct Session {
    state: Arc<Mutex<State>>,
    epoch: u64,
    max_reply: usize,
    write_timeout: Duration,
}

impl Session {
    async fn run<S>(self, stream: S, mut outgoing: mpsc::Receiver<Vec<u8>>)
    where
        S: AsyncRead + AsyncWrite,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let mut scratch = [0u8; READ_CHUNK];
        let mut buffered = Vec::new();

        loop {
            tokio::select! {
                read = reader.read(&mut scratch) => {
                    match read {
                        Ok(0) | Err(_) => {
                            break;
                        }

                        Ok(count) => {
                            buffered.extend_from_slice(&scratch[..count]);
                            if self.dispatch_frames(&mut buffered).is_err() {
                                break;
                            }
                        }
                    }
                }

                frame = outgoing.recv() => {
                    let Some(frame) = frame else {
                        break;
                    };

                    if write_frame(&mut writer, &frame, self.write_timeout).await.is_err() {
                        break;
                    }
                }
            }
        }

        self.close();
    }

    /// Hands every complete frame in `buffered` to its waiting query.
    fn dispatch_frames(&self, buffered: &mut Vec<u8>) -> Result<(), UpstreamError> {
        let mut consumed = 0;

        while let Some(length_bytes) = buffered.get(consumed..consumed + 2) {
            let length = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
            if length < MIN_MESSAGE_LEN || length > self.max_reply {
                return Err(UpstreamError::BadReply);
            }

            let Some(message) = buffered.get(consumed + 2..consumed + 2 + length) else {
                break;
            };

            self.deliver(message);
            consumed += 2 + length;
        }

        buffered.drain(..consumed);

        Ok(())
    }

    fn deliver(&self, message: &[u8]) {
        let id = u16::from_be_bytes([message[0], message[1]]);
        let waiting = {
            let mut state = self.state.lock().unwrap();

            state.pending.remove(&id)
        };

        if let Some(waiting) = waiting {
            let _ = waiting.send(message.to_vec());
        }
    }

    fn close(&self) {
        let mut state = self.state.lock().unwrap();
        if state.epoch == self.epoch {
            state.writer = None;
            state.pending.clear();
        }
    }
}

async fn write_frame<W>(writer: &mut W, frame: &[u8], limit: Duration) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match timeout(limit, async {
        writer.write_all(frame).await?;
        writer.flush().await
    })
    .await
    {
        Ok(result) => result,

        Err(_) => Err(io::ErrorKind::TimedOut.into()),
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{DuplexStream, duplex};

    use super::*;
    use crate::dns::test_util::QuerySpec;

    const SHORT: Duration = Duration::from_millis(500);

    fn request(name: &str) -> Vec<u8> {
        let mut bytes = QuerySpec::new(name, hickory_proto::rr::RecordType::A).bytes();
        bytes[0] = 0;
        bytes[1] = 0;

        bytes
    }

    fn client() -> StreamClient {
        StreamClient::new(64 * 1024, SHORT)
    }

    fn deadline() -> Instant {
        Instant::now() + SHORT
    }

    async fn read_frame(stream: &mut DuplexStream) -> Vec<u8> {
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.unwrap();
        let mut message = vec![0; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut message).await.unwrap();

        message
    }

    async fn write_reply(stream: &mut DuplexStream, id: [u8; 2], tail: &[u8]) {
        let mut message = id.to_vec();
        message.extend_from_slice(&[0x81, 0x80]);
        message.extend_from_slice(&[0; 8]);
        message.extend_from_slice(tail);
        let mut frame = (message.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(&message);
        stream.write_all(&frame).await.unwrap();
    }

    #[tokio::test]
    async fn a_query_without_a_connection_fails_fast() {
        let client = client();

        let result = client.query(&mut request("a.example."), deadline()).await;

        assert!(matches!(result, Err(UpstreamError::Closed)));
        assert!(!client.is_connected());
    }

    #[tokio::test]
    async fn a_reply_is_matched_by_the_id_the_client_chose() {
        let client = client();
        let (ours, mut server) = duplex(4096);
        client.attach(ours);

        let server_task = tokio::spawn(async move {
            let received = read_frame(&mut server).await;
            write_reply(&mut server, [received[0], received[1]], b"ok").await;
            server
        });
        let reply = client
            .query(&mut request("a.example."), deadline())
            .await
            .unwrap();

        assert_eq!(&reply[12..], b"ok");
        drop(server_task.await.unwrap());
    }

    #[tokio::test]
    async fn replies_may_arrive_out_of_order_on_one_connection() {
        let client = Arc::new(client());
        let (ours, mut server) = duplex(4096);
        client.attach(ours);

        let server_task = tokio::spawn(async move {
            let first = read_frame(&mut server).await;
            let second = read_frame(&mut server).await;
            write_reply(&mut server, [second[0], second[1]], b"second").await;
            write_reply(&mut server, [first[0], first[1]], b"first").await;
            server
        });
        let first = {
            let client = Arc::clone(&client);
            tokio::spawn(async move { client.query(&mut request("a.example."), deadline()).await })
        };
        tokio::task::yield_now().await;
        let second = {
            let client = Arc::clone(&client);
            tokio::spawn(async move { client.query(&mut request("b.example."), deadline()).await })
        };

        let first = first.await.unwrap().unwrap();
        let second = second.await.unwrap().unwrap();

        assert_eq!(&first[12..], b"first");
        assert_eq!(&second[12..], b"second");
        drop(server_task.await.unwrap());
    }

    #[tokio::test]
    async fn a_reply_split_across_writes_is_reassembled() {
        let client = client();
        let (ours, mut server) = duplex(4096);
        client.attach(ours);

        tokio::spawn(async move {
            let received = read_frame(&mut server).await;
            let mut message = vec![received[0], received[1], 0x81, 0x80];
            message.extend_from_slice(&[0; 8]);
            message.extend_from_slice(b"split");
            let mut frame = (message.len() as u16).to_be_bytes().to_vec();
            frame.extend_from_slice(&message);
            for byte in frame {
                server.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
            server
        });

        let reply = client
            .query(&mut request("a.example."), deadline())
            .await
            .unwrap();

        assert_eq!(&reply[12..], b"split");
    }

    #[tokio::test]
    async fn closing_the_connection_fails_waiting_queries_and_disconnects() {
        let client = client();
        let (ours, mut server) = duplex(4096);
        client.attach(ours);

        tokio::spawn(async move {
            read_frame(&mut server).await;
            drop(server);
        });
        let result = client.query(&mut request("a.example."), deadline()).await;

        assert!(matches!(result, Err(UpstreamError::Closed)));
        tokio::task::yield_now().await;
        assert!(!client.is_connected());
    }

    #[tokio::test]
    async fn a_silent_server_times_out_and_leaves_no_pending_query() {
        let client = client();
        let (ours, _server) = duplex(4096);
        client.attach(ours);

        let result = client
            .query(
                &mut request("a.example."),
                Instant::now() + Duration::from_millis(50),
            )
            .await;

        assert!(matches!(result, Err(UpstreamError::Timeout)));
        assert!(client.state.lock().unwrap().pending.is_empty());
    }

    #[tokio::test]
    async fn an_oversized_frame_closes_the_connection() {
        let client = StreamClient::new(100, SHORT);
        let (ours, mut server) = duplex(4096);
        client.attach(ours);

        tokio::spawn(async move {
            read_frame(&mut server).await;
            server.write_all(&200u16.to_be_bytes()).await.unwrap();
            server.write_all(&[0; 200]).await.unwrap();
            server
        });
        let result = client.query(&mut request("a.example."), deadline()).await;

        assert!(matches!(result, Err(UpstreamError::Closed)));
    }

    #[tokio::test]
    async fn attaching_a_new_connection_replaces_the_old_one() {
        let client = client();
        let (first, _first_server) = duplex(4096);
        client.attach(first);
        let (second, mut second_server) = duplex(4096);
        client.attach(second);

        tokio::spawn(async move {
            let received = read_frame(&mut second_server).await;
            write_reply(&mut second_server, [received[0], received[1]], b"new").await;
            second_server
        });
        let reply = client
            .query(&mut request("a.example."), deadline())
            .await
            .unwrap();

        assert_eq!(&reply[12..], b"new");
    }
}
