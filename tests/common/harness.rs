//! A scripted UDP upstream and a picoguard server on 127.0.0.1 with a random port, for the
//! end-to-end tests of filtering. Nothing leaves the machine.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use picoguard::config::Config;
use picoguard::filter::engine::{CompiledList, Engine};
use picoguard::filter::parse::ListFormat;
use picoguard::pipeline::Pipeline;
use picoguard::policy::Policy;
use picoguard::server::{self, Listeners};
use tokio::net::UdpSocket;

pub const PATIENT: Duration = Duration::from_secs(3);

/// The upstream's answer to a query: every `(delay, message)` is sent after its delay.
pub type Handler = dyn Fn(&Message) -> Vec<(Duration, Message)> + Send + Sync;

pub struct FakeUpstream {
    pub address: SocketAddr,
    received: Arc<Mutex<Vec<Message>>>,
}

impl FakeUpstream {
    /// How many queries reached the upstream.
    pub fn count(&self) -> usize {
        self.received.lock().unwrap().len()
    }
}

pub async fn fake_upstream(
    handler: impl Fn(&Message) -> Vec<(Duration, Message)> + Send + Sync + 'static,
) -> FakeUpstream {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = socket.local_addr().unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let handler: Arc<Handler> = Arc::new(handler);
    let seen = Arc::clone(&received);

    tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
            let Ok(query) = Message::from_vec(&buffer[..length]) else {
                continue;
            };

            seen.lock().unwrap().push(query.clone());
            let replies = handler(&query);
            let socket = Arc::clone(&socket);
            tokio::spawn(async move {
                for (delay, reply) in replies {
                    tokio::time::sleep(delay).await;
                    let _ = socket.send_to(&reply.to_vec().unwrap(), peer).await;
                }
            });
        }
    });

    FakeUpstream { address, received }
}

/// A response to `query` with the given answers and no flags beyond RD and RA.
pub fn reply_to(query: &Message, answers: Vec<Record>) -> Message {
    let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    reply.metadata.recursion_desired = query.metadata.recursion_desired;
    reply.metadata.recursion_available = true;
    reply.add_query(query.queries[0].clone());
    reply.add_answers(answers);

    reply
}

pub fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

pub fn a_record(owner: &str, ttl: u32, address: [u8; 4]) -> Record {
    Record::from_rdata(name(owner), ttl, RData::A(A(Ipv4Addr::from(address))))
}

/// An upstream that answers every A question with `address` after `delay`.
pub async fn answering_upstream(address: [u8; 4], delay: Duration) -> FakeUpstream {
    fake_upstream(move |query| {
        let owner = query.queries[0].name().to_string();

        vec![(delay, reply_to(query, vec![a_record(&owner, 300, address)]))]
    })
    .await
}

pub fn engine_of(main: &[&str], allow: &[&str]) -> Arc<Engine> {
    let compile = |text: &&str| Arc::new(CompiledList::from_text(ListFormat::Adblock, text).0);

    Arc::new(Engine::new(
        main.iter().map(compile).collect(),
        allow.iter().map(compile).collect(),
    ))
}

#[derive(Clone)]
pub struct Running {
    pub udp: SocketAddr,
    pub policy: Arc<Policy>,
}

pub fn config_for(upstream: &FakeUpstream) -> Config {
    let mut config = Config::default();
    config.server.bind = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
    config.server.port = 0;
    config.upstream.servers = vec![format!("udp://{}", upstream.address)];
    config.upstream.timeout_ms = 1500;

    config
}

pub async fn start(config: &Config, engine: Arc<Engine>) -> Running {
    let policy = Arc::new(Policy::with_engine(engine));
    let pipeline = Pipeline::new(config, Arc::clone(&policy)).unwrap();
    let listeners = Listeners::bind(&config.server).unwrap();
    let udp = listeners.udp_addresses()[0];
    server::spawn(listeners, pipeline, config);

    Running { udp, policy }
}

/// Sends one UDP query (RD set, no EDNS) and returns the reply.
pub async fn ask(server: &Running, text: &str, rtype: RecordType) -> Message {
    let mut query = Message::query();
    query.metadata.id = 0x2222;
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(name(text), rtype));

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&query.to_vec().unwrap(), server.udp)
        .await
        .unwrap();
    let mut buffer = vec![0u8; 8192];
    let (length, _) = tokio::time::timeout(PATIENT, socket.recv_from(&mut buffer))
        .await
        .unwrap_or_else(|_| panic!("no reply to {text} {rtype}"))
        .unwrap();

    Message::from_vec(&buffer[..length]).unwrap()
}
