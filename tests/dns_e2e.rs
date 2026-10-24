//! The whole DNS path on 127.0.0.1 and ::1 with random ports and fake
//! upstreams written here. Nothing leaves the machine.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};
use hickory_proto::rr::rdata::{A, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use picoguard::config::Config;
use picoguard::pipeline::Pipeline;
use picoguard::policy::Policy;
use picoguard::server::{self, Listeners};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const QUIET: Duration = Duration::from_millis(400);
const PATIENT: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------- messages

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

struct Ask {
    id: u16,
    name: String,
    rtype: RecordType,
    class: DNSClass,
    recursion_desired: bool,
    edns: Option<Edns>,
}

impl Ask {
    fn new(text: &str, rtype: RecordType) -> Ask {
        Ask {
            id: 0x2222,
            name: text.to_string(),
            rtype,
            class: DNSClass::IN,
            recursion_desired: true,
            edns: None,
        }
    }

    fn with_id(mut self, id: u16) -> Ask {
        self.id = id;

        self
    }

    fn with_edns(mut self, udp_size: u16) -> Ask {
        let mut edns = Edns::new();
        edns.set_max_payload(udp_size);
        self.edns = Some(edns);

        self
    }

    fn bytes(&self) -> Vec<u8> {
        let mut message = Message::query();
        message.metadata.id = self.id;
        message.metadata.recursion_desired = self.recursion_desired;
        let mut query = Query::query(name(&self.name), self.rtype);
        query.set_query_class(self.class);
        message.add_query(query);
        if let Some(edns) = &self.edns {
            message.set_edns(edns.clone());
        }

        message.to_vec().unwrap()
    }
}

fn answer_a(query: &Message, ttl: u32) -> Message {
    let mut reply = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    reply.metadata.recursion_desired = query.metadata.recursion_desired;
    reply.metadata.recursion_available = true;
    reply.add_query(query.queries[0].clone());
    reply.add_answer(Record::from_rdata(
        query.queries[0].name().clone(),
        ttl,
        RData::A(A(ANSWER)),
    ));

    reply
}

/// About 1.3 KB: over 512 and 1232, and under what this machine's loopback
/// delivers without fragmenting UDP.
fn big_txt(query: &Message) -> Message {
    let mut reply = answer_a(query, 60);
    reply.answers.clear();
    let strings = (0..5).map(|_| "x".repeat(255)).collect();
    reply.add_answer(Record::from_rdata(
        query.queries[0].name().clone(),
        60,
        RData::TXT(TXT::new(strings)),
    ));

    reply
}

// --------------------------------------------------------- fake upstream

type Handler = dyn Fn(&Message) -> Vec<(Duration, Message)> + Send + Sync;

struct FakeUpstream {
    address: SocketAddr,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

impl FakeUpstream {
    fn count(&self) -> usize {
        self.received.lock().unwrap().len()
    }

    fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }

    fn last_query(&self) -> Message {
        Message::from_vec(self.received.lock().unwrap().last().unwrap()).unwrap()
    }
}

async fn fake_upstream(
    handler: impl Fn(&Message) -> Vec<(Duration, Message)> + Send + Sync + 'static,
) -> FakeUpstream {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = socket.local_addr().unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let handler: Arc<Handler> = Arc::new(handler);
    let (seen, in_flight, highest) = (
        Arc::clone(&received),
        Arc::clone(&active),
        Arc::clone(&peak),
    );

    tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        while let Ok((length, peer)) = socket.recv_from(&mut buffer).await {
            seen.lock().unwrap().push(buffer[..length].to_vec());
            let Ok(query) = Message::from_vec(&buffer[..length]) else {
                continue;
            };
            let replies = handler(&query);
            let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            highest.fetch_max(now, Ordering::SeqCst);
            let (socket, in_flight) = (Arc::clone(&socket), Arc::clone(&in_flight));
            tokio::spawn(async move {
                for (delay, reply) in replies {
                    tokio::time::sleep(delay).await;
                    let _ = socket.send_to(&reply.to_vec().unwrap(), peer).await;
                }
                in_flight.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });

    FakeUpstream {
        address,
        received,
        active,
        peak,
    }
}

async fn answering_upstream() -> FakeUpstream {
    fake_upstream(|query| vec![(Duration::ZERO, answer_a(query, 300))]).await
}

async fn slow_upstream(delay: Duration) -> FakeUpstream {
    fake_upstream(move |query| vec![(delay, answer_a(query, 300))]).await
}

async fn silent_upstream() -> FakeUpstream {
    fake_upstream(|_| Vec::new()).await
}

// --------------------------------------------------------------- server

struct TestServer {
    udp: SocketAddr,
    tcp: SocketAddr,
}

fn config_for(upstream: &FakeUpstream) -> Config {
    let mut config = Config::default();
    config.server.bind = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
    config.server.port = 0;
    config.upstream.servers = vec![format!("udp://{}", upstream.address)];
    config.upstream.timeout_ms = 1500;

    config
}

async fn start(config: Config) -> TestServer {
    let pipeline = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();
    let listeners = Listeners::bind(&config.server).unwrap();
    let server = TestServer {
        udp: listeners.udp_addresses()[0],
        tcp: listeners.tcp_addresses()[0],
    };
    server::spawn(listeners, pipeline, &config);

    server
}

async fn udp_exchange(server: SocketAddr, request: &[u8], wait: Duration) -> Option<Vec<u8>> {
    let local = if server.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    };
    let socket = UdpSocket::bind(local).await.unwrap();
    socket.send_to(request, server).await.unwrap();
    let mut buffer = vec![0u8; 8192];
    let received = tokio::time::timeout(wait, socket.recv_from(&mut buffer)).await;

    received.ok().map(|result| {
        let (length, _) = result.unwrap();
        buffer.truncate(length);

        buffer
    })
}

async fn udp_ask(server: &TestServer, ask: &Ask) -> Option<Message> {
    udp_exchange(server.udp, &ask.bytes(), PATIENT)
        .await
        .map(|bytes| Message::from_vec(&bytes).unwrap())
}

async fn write_framed(stream: &mut TcpStream, request: &[u8]) {
    stream
        .write_all(&(request.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(request).await.unwrap();
}

async fn read_framed(stream: &mut TcpStream) -> Option<Message> {
    let mut length = [0u8; 2];
    tokio::time::timeout(PATIENT, stream.read_exact(&mut length))
        .await
        .ok()?
        .ok()?;
    let mut reply = vec![0u8; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut reply).await.ok()?;

    Some(Message::from_vec(&reply).unwrap())
}

async fn tcp_ask(server: &TestServer, ask: &Ask) -> Option<Message> {
    let mut stream = TcpStream::connect(server.tcp).await.unwrap();
    write_framed(&mut stream, &ask.bytes()).await;

    read_framed(&mut stream).await
}

fn first_a(message: &Message) -> Ipv4Addr {
    let RData::A(address) = &message.answers[0].data else {
        panic!("expected an A record in {message:?}");
    };

    address.0
}

// ------------------------------------------------------------- forwarding

#[tokio::test]
async fn queries_are_forwarded_over_udp_and_tcp() {
    let upstream = answering_upstream().await;
    let server = start(config_for(&upstream)).await;

    let udp = udp_ask(
        &server,
        &Ask::new("one.example.", RecordType::A).with_id(0xAAAA),
    )
    .await
    .unwrap();
    let tcp = tcp_ask(
        &server,
        &Ask::new("two.example.", RecordType::A).with_id(0xBBBB),
    )
    .await
    .unwrap();

    assert_eq!(udp.metadata.id, 0xAAAA);
    assert_eq!(tcp.metadata.id, 0xBBBB);
    assert_eq!(first_a(&udp), ANSWER);
    assert_eq!(first_a(&tcp), ANSWER);
    assert!(udp.metadata.recursion_available);
    assert_eq!(upstream.count(), 2);
}

#[tokio::test]
async fn the_answer_keeps_the_clients_letter_case_from_the_upstream_and_from_the_cache() {
    let upstream = answering_upstream().await;
    let server = start(config_for(&upstream)).await;
    let ask = Ask::new("MiXeD.Example.COM.", RecordType::A);

    let fresh = udp_ask(&server, &ask).await.unwrap();
    let cached = udp_ask(&server, &ask).await.unwrap();

    for reply in [fresh, cached] {
        assert_eq!(reply.queries[0].name().to_ascii(), "MiXeD.Example.COM.");
    }
    assert_eq!(upstream.count(), 1);
    assert_eq!(
        upstream.last_query().queries[0].name().to_ascii(),
        "mixed.example.com."
    );
}

#[tokio::test]
async fn repeated_queries_come_from_the_cache_with_an_aged_ttl() {
    let upstream = answering_upstream().await;
    let server = start(config_for(&upstream)).await;
    let ask = Ask::new("cached.example.", RecordType::A);

    let first = udp_ask(&server, &ask).await.unwrap();
    let second = tcp_ask(&server, &ask).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let third = udp_ask(&server, &ask).await.unwrap();

    assert_eq!(first.answers[0].ttl, 300);
    assert_eq!(second.answers[0].ttl, 300);
    assert_eq!(third.answers[0].ttl, 299);
    assert_eq!(upstream.count(), 1);
}

#[tokio::test]
async fn an_upstream_that_never_answers_gives_servfail() {
    let upstream = silent_upstream().await;
    let mut config = config_for(&upstream);
    config.upstream.timeout_ms = 300;
    let server = start(config).await;

    let reply = udp_ask(&server, &Ask::new("dead.example.", RecordType::A))
        .await
        .unwrap();

    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(upstream.count(), 2, "one retry");
}

#[tokio::test]
async fn an_empty_answer_without_a_soa_is_passed_on_but_not_cached() {
    let upstream = fake_upstream(|query| {
        let mut reply = answer_a(query, 300);
        reply.answers.clear();
        vec![(Duration::ZERO, reply)]
    })
    .await;
    let server = start(config_for(&upstream)).await;

    let ask = Ask::new("empty.example.", RecordType::A);

    let reply = udp_ask(&server, &ask).await.unwrap();
    udp_ask(&server, &ask).await.unwrap();

    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert!(reply.answers.is_empty());
    assert_eq!(upstream.count(), 2);
}

// ------------------------------------------------------------- truncation

#[tokio::test]
async fn a_big_answer_is_truncated_over_udp_and_complete_over_tcp() {
    let upstream = fake_upstream(|query| vec![(Duration::ZERO, big_txt(query))]).await;
    let server = start(config_for(&upstream)).await;
    let plain = Ask::new("big.example.", RecordType::TXT);
    let edns = Ask::new("big.example.", RecordType::TXT).with_edns(1232);

    let udp_plain = udp_ask(&server, &plain).await.unwrap();
    let udp_edns = udp_ask(&server, &edns).await.unwrap();
    let tcp_plain = tcp_ask(&server, &plain).await.unwrap();
    let tcp_edns = tcp_ask(&server, &edns).await.unwrap();

    for truncated in [&udp_plain, &udp_edns] {
        assert!(truncated.metadata.truncation);
        assert!(truncated.answers.is_empty());
    }
    for complete in [&tcp_plain, &tcp_edns] {
        assert!(!complete.metadata.truncation);
        assert_eq!(complete.answers.len(), 1);
    }
    assert_eq!(upstream.count(), 1, "the TCP retry is a cache hit");
}

#[tokio::test]
async fn a_tcp_upstream_answer_truncated_over_udp_is_fetched_over_tcp() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(address).await.unwrap();
    let tcp_queries = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&tcp_queries);
    tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        while let Ok((length, peer)) = udp.recv_from(&mut buffer).await {
            let query = Message::from_vec(&buffer[..length]).unwrap();
            let mut reply = answer_a(&query, 60);
            reply.answers.clear();
            reply.metadata.truncation = true;
            let _ = udp.send_to(&reply.to_vec().unwrap(), peer).await;
        }
    });
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = tcp.accept().await {
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut length = [0u8; 2];
                stream.read_exact(&mut length).await.unwrap();
                let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
                stream.read_exact(&mut query).await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                let reply = big_txt(&Message::from_vec(&query).unwrap())
                    .to_vec()
                    .unwrap();
                write_framed(&mut stream, &reply).await;
            });
        }
    });
    let mut config = Config::default();
    config.server.bind = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
    config.server.port = 0;
    config.upstream.servers = vec![format!("udp://{address}")];
    let server = start(config).await;

    let reply = tcp_ask(&server, &Ask::new("huge.example.", RecordType::TXT))
        .await
        .unwrap();

    assert_eq!(reply.answers.len(), 1);
    assert_eq!(tcp_queries.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_truncated_reply_from_a_tcp_upstream_reaches_the_client_marked_truncated_and_is_not_cached()
 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let queries = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&queries);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                loop {
                    let mut length = [0u8; 2];
                    if stream.read_exact(&mut length).await.is_err() {
                        return;
                    }

                    let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
                    stream.read_exact(&mut query).await.unwrap();
                    counter.fetch_add(1, Ordering::SeqCst);
                    let mut reply = answer_a(&Message::from_vec(&query).unwrap(), 60);
                    reply.metadata.truncation = true;
                    write_framed(&mut stream, &reply.to_vec().unwrap()).await;
                }
            });
        }
    });
    let mut config = Config::default();
    config.server.bind = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
    config.server.port = 0;
    config.upstream.servers = vec![format!("tcp://{address}")];
    let server = start(config).await;
    let ask = Ask::new("cut.example.", RecordType::A);

    let first = tcp_ask(&server, &ask).await.unwrap();
    let second = tcp_ask(&server, &ask).await.unwrap();

    assert!(first.metadata.truncation);
    assert!(second.metadata.truncation);
    assert_eq!(queries.load(Ordering::SeqCst), 2, "not cached");
}

// ------------------------------------------------------------- coalescing

#[tokio::test]
async fn identical_queries_in_flight_share_one_upstream_query() {
    let upstream = slow_upstream(Duration::from_millis(300)).await;
    let server = Arc::new(start(config_for(&upstream)).await);

    let mut clients = Vec::new();
    for id in 0..20u16 {
        let server = Arc::clone(&server);
        clients.push(tokio::spawn(async move {
            udp_ask(
                &server,
                &Ask::new("same.example.", RecordType::A).with_id(id),
            )
            .await
        }));
    }

    for (id, client) in clients.into_iter().enumerate() {
        let reply = client.await.unwrap().unwrap();

        assert_eq!(reply.metadata.id, id as u16);
        assert_eq!(first_a(&reply), ANSWER);
    }
    assert_eq!(upstream.count(), 1);
}

#[tokio::test]
async fn queries_with_different_rd_are_not_coalesced() {
    let upstream = slow_upstream(Duration::from_millis(300)).await;
    let server = Arc::new(start(config_for(&upstream)).await);

    let mut clients = Vec::new();
    for index in 0..6u16 {
        let server = Arc::clone(&server);
        clients.push(tokio::spawn(async move {
            let mut ask = Ask::new("rd.example.", RecordType::A).with_id(index);
            ask.recursion_desired = index % 2 == 0;

            udp_ask(&server, &ask).await
        }));
    }
    for client in clients {
        assert!(client.await.unwrap().is_some());
    }

    assert_eq!(upstream.count(), 2);
}

// ---------------------------------------------------------- special cases

#[tokio::test]
async fn any_queries_get_notimp_and_blocked_hosts_get_refused() {
    let upstream = answering_upstream().await;
    let server = start(config_for(&upstream)).await;
    let mut version = Ask::new("version.bind.", RecordType::TXT);
    version.class = DNSClass::CH;

    let any = udp_ask(&server, &Ask::new("example.com.", RecordType::ANY))
        .await
        .unwrap();
    let blocked = udp_ask(&server, &version).await.unwrap();
    let blocked_over_tcp = tcp_ask(&server, &Ask::new("ID.server.", RecordType::TXT))
        .await
        .unwrap();

    assert_eq!(any.metadata.response_code, ResponseCode::NotImp);
    assert_eq!(blocked.metadata.response_code, ResponseCode::Refused);
    assert_eq!(
        blocked_over_tcp.metadata.response_code,
        ResponseCode::Refused
    );
    assert_eq!(upstream.count(), 0);
}

#[tokio::test]
async fn any_is_forwarded_when_refuse_any_is_off() {
    let upstream = answering_upstream().await;
    let mut config = config_for(&upstream);
    config.refuse_any = false;
    let server = start(config).await;

    let reply = udp_ask(&server, &Ask::new("example.com.", RecordType::ANY))
        .await
        .unwrap();

    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(upstream.count(), 1);
}

#[tokio::test]
async fn private_reverse_lookups_without_a_local_resolver_get_nxdomain() {
    let upstream = answering_upstream().await;
    let server = start(config_for(&upstream)).await;

    let reply = udp_ask(
        &server,
        &Ask::new("4.3.2.10.in-addr.arpa.", RecordType::PTR),
    )
    .await
    .unwrap();

    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(upstream.count(), 0);
}

#[tokio::test]
async fn private_reverse_lookups_and_local_domains_go_to_the_local_resolver() {
    let upstream = answering_upstream().await;
    let router = fake_upstream(|query| {
        let mut reply = answer_a(query, 30);
        reply.metadata.response_code = ResponseCode::NoError;
        vec![(Duration::ZERO, reply)]
    })
    .await;
    let mut config = config_for(&upstream);
    config.local.resolver = Some(router.address);
    config.local.domains = vec!["lan".to_string()];
    let server = start(config).await;

    udp_ask(
        &server,
        &Ask::new("9.1.168.192.in-addr.arpa.", RecordType::PTR),
    )
    .await
    .unwrap();
    udp_ask(&server, &Ask::new("Printer.LAN.", RecordType::A))
        .await
        .unwrap();
    tcp_ask(&server, &Ask::new("nas.lan.", RecordType::AAAA))
        .await
        .unwrap();
    udp_ask(&server, &Ask::new("8.8.8.8.in-addr.arpa.", RecordType::PTR))
        .await
        .unwrap();
    udp_ask(&server, &Ask::new("example.com.", RecordType::A))
        .await
        .unwrap();

    assert_eq!(router.count(), 3);
    assert_eq!(upstream.count(), 2);
}

// ----------------------------------------------------------- normalization

#[tokio::test]
async fn client_subnet_and_other_edns_options_are_not_forwarded() {
    let upstream = answering_upstream().await;
    let server = start(config_for(&upstream)).await;
    let mut ask = Ask::new("ecs.example.", RecordType::A).with_edns(4096);
    let edns = ask.edns.as_mut().unwrap();
    edns.set_dnssec_ok(true);
    edns.options_mut()
        .insert(EdnsOption::Subnet(ClientSubnet::new(
            "203.0.113.0".parse().unwrap(),
            24,
            0,
        )));
    edns.options_mut()
        .insert(EdnsOption::Unknown(10, vec![1, 2, 3, 4, 5, 6, 7, 8]));
    ask.recursion_desired = false;

    let reply = udp_ask(&server, &ask).await.unwrap();

    let forwarded = upstream.last_query();
    let forwarded_edns = forwarded.edns.unwrap();
    assert!(forwarded_edns.options().as_ref().is_empty());
    assert_eq!(forwarded_edns.max_payload(), 1232);
    assert!(forwarded_edns.flags().dnssec_ok, "DO is kept");
    assert!(!forwarded.metadata.recursion_desired, "RD is copied");
    let reply_edns = reply.edns.unwrap();
    assert_eq!(reply_edns.max_payload(), 1232);
    assert!(reply_edns.flags().dnssec_ok);
}

#[tokio::test]
async fn a_client_without_edns_still_gets_an_edns_query_upstream_and_no_opt_back() {
    let upstream = fake_upstream(|query| {
        let mut reply = answer_a(query, 300);
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        reply.set_edns(edns);

        vec![(Duration::ZERO, reply)]
    })
    .await;
    let server = start(config_for(&upstream)).await;

    let reply = udp_ask(&server, &Ask::new("plain.example.", RecordType::A))
        .await
        .unwrap();

    assert!(upstream.last_query().edns.is_some());
    assert!(reply.edns.is_none());
    assert_eq!(first_a(&reply), ANSWER);
}

// ------------------------------------------------------------ bad packets

#[tokio::test]
async fn garbage_and_responses_get_no_answer_and_bad_queries_get_formerr() {
    let upstream = answering_upstream().await;
    let server = start(config_for(&upstream)).await;
    let mut response = Ask::new("example.com.", RecordType::A).bytes();
    response[2] |= 0x80;
    let mut no_question = Ask::new("example.com.", RecordType::A).bytes();
    no_question[5] = 0;
    let mut update = Ask::new("example.com.", RecordType::A).bytes();
    update[2] |= 5 << 3;

    assert!(udp_exchange(server.udp, &[1, 2, 3], QUIET).await.is_none());
    assert!(udp_exchange(server.udp, &response, QUIET).await.is_none());
    let formerr = udp_exchange(server.udp, &no_question, PATIENT)
        .await
        .unwrap();
    let notimp = udp_exchange(server.udp, &update, PATIENT).await.unwrap();

    assert_eq!(formerr[0..2], no_question[0..2]);
    assert_eq!(formerr[3] & 0x0F, 1);
    assert_eq!(notimp[3] & 0x0F, 4);
    assert_eq!(upstream.count(), 0);
}

// ---------------------------------------------------------- access policy

#[tokio::test]
async fn a_client_outside_allow_from_gets_no_answer_over_udp_or_tcp() {
    let upstream = answering_upstream().await;
    let mut config = config_for(&upstream);
    config.server.allow_from = vec!["10.0.0.0/8".parse().unwrap()];
    let server = start(config).await;
    let ask = Ask::new("denied.example.", RecordType::A);

    let udp = udp_exchange(server.udp, &ask.bytes(), QUIET).await;
    let mut stream = TcpStream::connect(server.tcp).await.unwrap();
    let _ = stream.write_all(&[0, 0]).await;
    let mut byte = [0u8; 1];
    let tcp_read = tokio::time::timeout(PATIENT, stream.read(&mut byte)).await;

    assert!(udp.is_none());
    assert!(
        matches!(tcp_read, Ok(Ok(0)) | Ok(Err(_))),
        "the connection must be closed without data: {tcp_read:?}"
    );
    assert_eq!(upstream.count(), 0);
}

#[tokio::test]
async fn an_ipv6_client_outside_allow_from_is_refused_and_inside_is_served() {
    if std::net::UdpSocket::bind("[::1]:0").is_err() {
        return;
    }

    let upstream = answering_upstream().await;
    let mut config = config_for(&upstream);
    config.server.bind = vec!["::1".parse().unwrap()];
    config.server.allow_from = vec!["127.0.0.0/8".parse().unwrap()];
    let denied = start(config.clone()).await;
    config.server.allow_from = vec!["::1/128".parse().unwrap()];
    let allowed = start(config).await;
    let ask = Ask::new("six.example.", RecordType::A);

    let from_denied = udp_exchange(denied.udp, &ask.bytes(), QUIET).await;
    let from_allowed = udp_exchange(allowed.udp, &ask.bytes(), PATIENT).await;

    assert!(from_denied.is_none());
    assert!(from_allowed.is_some());
}

// ------------------------------------------------------------- overload

#[tokio::test]
async fn too_many_queries_in_flight_are_dropped_over_udp() {
    let upstream = slow_upstream(Duration::from_millis(400)).await;
    let mut config = config_for(&upstream);
    config.limits.max_inflight_queries = 2;
    let server = Arc::new(start(config).await);

    let mut clients = Vec::new();
    for index in 0..4 {
        let server = Arc::clone(&server);
        clients.push(tokio::spawn(async move {
            let ask = Ask::new(&format!("n{index}.example."), RecordType::A);

            udp_ask(&server, &ask).await
        }));
    }
    let mut answered = 0;
    for client in clients {
        answered += usize::from(client.await.unwrap().is_some());
    }

    assert_eq!(answered, 2);
    assert_eq!(upstream.count(), 2);
}

#[tokio::test]
async fn too_many_waiting_clients_are_dropped_over_udp_even_when_coalesced() {
    let upstream = slow_upstream(Duration::from_millis(400)).await;
    let mut config = config_for(&upstream);
    config.limits.max_waiting_clients = 3;
    let server = Arc::new(start(config).await);

    let mut clients = Vec::new();
    for id in 0..5u16 {
        let server = Arc::clone(&server);
        clients.push(tokio::spawn(async move {
            udp_ask(
                &server,
                &Ask::new("crowd.example.", RecordType::A).with_id(id),
            )
            .await
        }));
    }
    let mut answered = 0;
    for client in clients {
        answered += usize::from(client.await.unwrap().is_some());
    }

    assert_eq!(answered, 3);
    assert_eq!(upstream.count(), 1);
}

#[tokio::test]
async fn over_the_limits_tcp_clients_get_servfail() {
    let upstream = slow_upstream(Duration::from_millis(500)).await;
    let mut config = config_for(&upstream);
    config.limits.max_inflight_queries = 1;
    let server = start(config).await;
    let mut first = TcpStream::connect(server.tcp).await.unwrap();
    write_framed(&mut first, &Ask::new("a.example.", RecordType::A).bytes()).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let second = tcp_ask(&server, &Ask::new("b.example.", RecordType::A))
        .await
        .unwrap();
    let first_reply = read_framed(&mut first).await.unwrap();

    assert_eq!(second.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(first_reply.metadata.response_code, ResponseCode::NoError);
}

#[tokio::test]
async fn an_exhausted_pending_bytes_budget_means_servfail_for_tcp_and_silence_for_udp() {
    let upstream = fake_upstream(|query| vec![(Duration::ZERO, big_txt(query))]).await;
    let mut config = config_for(&upstream);
    config.limits.pending_bytes = 1000;
    let server = start(config).await;

    let udp = udp_exchange(
        server.udp,
        &Ask::new("held.example.", RecordType::TXT).bytes(),
        QUIET,
    )
    .await;
    let tcp = tcp_ask(&server, &Ask::new("held2.example.", RecordType::TXT))
        .await
        .unwrap();

    assert!(udp.is_none());
    assert_eq!(tcp.metadata.response_code, ResponseCode::ServFail);
}

#[tokio::test]
async fn the_budget_is_released_after_delivery() {
    let upstream = answering_upstream().await;
    let mut config = config_for(&upstream);
    config.limits.pending_bytes = 200;
    let server = start(config).await;

    for index in 0..10 {
        let ask = Ask::new(&format!("r{index}.example."), RecordType::A);
        let reply = udp_ask(&server, &ask).await.unwrap();

        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NoError,
            "query {index}"
        );
    }
}

#[tokio::test]
async fn tcp_connections_over_the_limit_are_closed_at_once() {
    let upstream = answering_upstream().await;
    let mut config = config_for(&upstream);
    config.limits.tcp_max_connections = 2;
    let server = start(config).await;
    let mut first = TcpStream::connect(server.tcp).await.unwrap();
    let mut second = TcpStream::connect(server.tcp).await.unwrap();
    write_framed(&mut first, &Ask::new("c1.example.", RecordType::A).bytes()).await;
    write_framed(&mut second, &Ask::new("c2.example.", RecordType::A).bytes()).await;
    assert!(read_framed(&mut first).await.is_some());
    assert!(read_framed(&mut second).await.is_some());

    let mut third = TcpStream::connect(server.tcp).await.unwrap();
    let _ = third
        .write_all(&Ask::new("c3.example.", RecordType::A).bytes())
        .await;
    let mut byte = [0u8; 1];
    let third_read = tokio::time::timeout(PATIENT, third.read(&mut byte)).await;

    assert!(
        matches!(third_read, Ok(Ok(0)) | Ok(Err(_))),
        "{third_read:?}"
    );
    drop(first);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        tcp_ask(&server, &Ask::new("c4.example.", RecordType::A))
            .await
            .is_some()
    );
}

#[tokio::test]
async fn idle_tcp_connections_are_closed() {
    let upstream = answering_upstream().await;
    let mut config = config_for(&upstream);
    config.limits.tcp_idle_secs = 1;
    let server = start(config).await;
    let mut stream = TcpStream::connect(server.tcp).await.unwrap();
    let started = std::time::Instant::now();

    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(4), stream.read(&mut byte)).await;

    assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "{read:?}");
    assert!(started.elapsed() >= Duration::from_millis(900));
}

#[tokio::test]
async fn pipelined_tcp_queries_are_limited_per_connection() {
    let upstream = slow_upstream(Duration::from_millis(200)).await;
    let mut config = config_for(&upstream);
    config.limits.tcp_queue_replies = 2;
    let server = start(config).await;
    let mut stream = TcpStream::connect(server.tcp).await.unwrap();
    for index in 0..6u16 {
        let ask = Ask::new(&format!("p{index}.example."), RecordType::A).with_id(index);
        write_framed(&mut stream, &ask.bytes()).await;
    }

    let mut ids = Vec::new();
    for _ in 0..6 {
        ids.push(read_framed(&mut stream).await.unwrap().metadata.id);
    }
    ids.sort_unstable();

    assert_eq!(ids, [0, 1, 2, 3, 4, 5]);
    assert_eq!(upstream.peak(), 2);
    assert_eq!(upstream.active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_tcp_client_can_send_several_queries_on_one_connection() {
    let upstream = answering_upstream().await;
    let server = start(config_for(&upstream)).await;
    let mut stream = TcpStream::connect(server.tcp).await.unwrap();

    for index in 0..3u16 {
        let ask = Ask::new(&format!("s{index}.example."), RecordType::A).with_id(index);
        write_framed(&mut stream, &ask.bytes()).await;
        let reply = read_framed(&mut stream).await.unwrap();

        assert_eq!(reply.metadata.id, index);
    }
}
