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
    pending: HashMap<u16, Pending>,
    /// Which connection the writer and pending queries belong to.
    epoch: u64,
    next_token: u64,
}

struct Registration {
    id: u16,
    writer: mpsc::Sender<Vec<u8>>,
    epoch: u64,
    token: u64,
}

struct Pending {
    /// Tells this registration apart from a later one that reuses the ID.
    token: u64,
    reply: oneshot::Sender<Vec<u8>>,
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
                next_token: 0,
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
        let registration = self.register(reply_sender)?;
        let id = registration.id;
        let _unregister = Unregister {
            state: &self.state,
            id,
            epoch: registration.epoch,
            token: registration.token,
        };
        let writer = registration.writer;

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

        let Ok(received) = timeout_at(deadline, reply).await else {
            return Err(UpstreamError::Timeout);
        };

        received.map_err(|_| UpstreamError::Closed)
    }

    fn register(
        &self,
        reply_sender: oneshot::Sender<Vec<u8>>,
    ) -> Result<Registration, UpstreamError> {
        let mut state = self.state.lock().unwrap();
        let writer = state.writer.clone().ok_or(UpstreamError::Closed)?;
        let token = state.next_token;

        for _ in 0..ID_ATTEMPTS {
            let id = random_u64() as u16;
            if let Entry::Vacant(slot) = state.pending.entry(id) {
                slot.insert(Pending {
                    token,
                    reply: reply_sender,
                });
                state.next_token += 1;

                return Ok(Registration {
                    id,
                    writer,
                    epoch: state.epoch,
                    token,
                });
            }
        }

        Err(UpstreamError::Closed)
    }
}

struct Unregister<'a> {
    state: &'a Mutex<State>,
    id: u16,
    epoch: u64,
    token: u64,
}

impl Drop for Unregister<'_> {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap();
        let is_ours = state
            .pending
            .get(&self.id)
            .is_some_and(|pending| pending.token == self.token);
        if state.epoch == self.epoch && is_ours {
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
    /// Reads and writes independently: a write stuck on a server that is not
    /// reading must not stop us from reading what that server sends. Whichever
    /// side ends first ends the session.
    async fn run<S>(self, stream: S, outgoing: mpsc::Receiver<Vec<u8>>)
    where
        S: AsyncRead + AsyncWrite,
    {
        let (reader, writer) = tokio::io::split(stream);

        tokio::select! {
            () = self.read_frames(reader) => {}
            () = self.write_frames(writer, outgoing) => {}
        }

        self.close();
    }

    async fn read_frames<R>(&self, mut reader: R)
    where
        R: AsyncRead + Unpin,
    {
        let mut scratch = [0u8; READ_CHUNK];
        let mut buffered = Vec::new();

        loop {
            let Ok(count @ 1..) = reader.read(&mut scratch).await else {
                return;
            };

            buffered.extend_from_slice(&scratch[..count]);
            if self.dispatch_frames(&mut buffered).is_err() {
                return;
            }
        }
    }

    async fn write_frames<W>(&self, mut writer: W, mut outgoing: mpsc::Receiver<Vec<u8>>)
    where
        W: AsyncWrite + Unpin,
    {
        while let Some(frame) = outgoing.recv().await {
            if write_frame(&mut writer, &frame, self.write_timeout)
                .await
                .is_err()
            {
                return;
            }
        }
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
            let _ = waiting.reply.send(message.to_vec());
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
    let written = timeout(limit, async {
        writer.write_all(frame).await?;
        writer.flush().await
    })
    .await;

    let Ok(result) = written else {
        return Err(io::ErrorKind::TimedOut.into());
    };

    result
}

#[cfg(test)]
mod tests {
    use tokio::io::{DuplexStream, duplex};
    use tokio::sync::oneshot;

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

    #[tokio::test]
    async fn an_id_reused_after_delivery_is_not_unregistered_by_the_old_query() {
        let client = client();
        let (ours, _server) = duplex(4096);
        client.attach(ours);
        let (old_sender, _old_reply) = oneshot::channel();
        let old = client.register(old_sender).unwrap();
        let (id, epoch, old_token) = (old.id, old.epoch, old.token);
        // The reply was delivered, which removes the entry before the query's
        // guard runs; a new query then draws the same ID.
        client.state.lock().unwrap().pending.remove(&id);
        let (new_sender, _new_reply) = oneshot::channel();
        let new_token = old_token + 100;
        client.state.lock().unwrap().pending.insert(
            id,
            Pending {
                token: new_token,
                reply: new_sender,
            },
        );

        drop(Unregister {
            state: &client.state,
            id,
            epoch,
            token: old_token,
        });

        let state = client.state.lock().unwrap();
        assert_eq!(
            state.pending.get(&id).map(|pending| pending.token),
            Some(new_token)
        );
    }

    #[tokio::test]
    async fn a_blocked_write_does_not_stop_reading_the_servers_reply() {
        let client = client();
        let (ours, mut server) = duplex(256);
        client.attach(ours);

        // The server answers before it has read the whole query, so both
        // directions are full at the same time: the query is larger than the
        // pipe and so is the reply.
        let server_task = tokio::spawn(async move {
            let mut start = [0u8; 4];
            server.read_exact(&mut start).await.unwrap();
            write_reply(&mut server, [start[2], start[3]], &[7; 2000]).await;
            let mut rest = vec![0u8; 1000 + 12 - 2];
            server.read_exact(&mut rest).await.unwrap();
            server
        });
        let mut query = vec![0u8; 12 + 1000];

        let reply = client.query(&mut query, deadline()).await.unwrap();

        assert_eq!(reply.len(), 12 + 2000);
        drop(server_task.await.unwrap());
    }
}
