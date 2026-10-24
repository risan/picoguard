//! The statistics against a scripted sequence of queries through the whole pipeline: every
//! answered query is counted once, with the right result, upstream, client and name.

mod common;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use common::harness::{
    Running, a_record, ask, config_for, engine_of, fake_upstream, name, reply_to, start,
};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::RecordType;
use picoguard::dns::build::Protocol;
use picoguard::stats::{QueryResult, StatsSnapshot};
use tokio::net::UdpSocket;

const LOCALHOST: &str = "127.0.0.1";

fn snapshot_of(server: &Running) -> StatsSnapshot {
    server.pipeline.stats().snapshot()
}

/// An upstream that answers every name with 1.1.1.1, `evil.example` with a blocked address,
/// `slow.example` late and `silent.example` never.
async fn scripted_upstream() -> common::harness::FakeUpstream {
    fake_upstream(|query| {
        let owner = query.queries[0].name().to_string();
        let record = |address| a_record(&owner, 300, address);

        match owner.as_str() {
            "silent.example." => Vec::new(),

            "slow.example." => vec![(
                Duration::from_millis(400),
                reply_to(query, vec![record([1, 1, 1, 1])]),
            )],

            "evil.example." => vec![(Duration::ZERO, reply_to(query, vec![record([6, 6, 6, 6])]))],

            _ => vec![(Duration::ZERO, reply_to(query, vec![record([1, 1, 1, 1])]))],
        }
    })
    .await
}

#[tokio::test]
async fn counts_match_a_scripted_sequence_of_queries() {
    let upstream = scripted_upstream().await;
    let mut config = config_for(&upstream);
    config.upstream.timeout_ms = 200;
    let engine = engine_of(&["||ads.example^\n||6.6.6.6^\n"], &[]);
    let server = start(&config, engine).await;

    ask(&server, "ads.example.", RecordType::A).await;
    ask(&server, "ads.example.", RecordType::AAAA).await;
    ask(&server, "ok.example.", RecordType::A).await;
    ask(&server, "ok.example.", RecordType::A).await;
    ask(&server, "ok.example.", RecordType::A).await;
    ask(&server, "evil.example.", RecordType::A).await;
    ask(&server, "evil.example.", RecordType::A).await;
    ask(&server, "silent.example.", RecordType::A).await;

    let snapshot = snapshot_of(&server);
    let counters = snapshot.counters;
    assert_eq!(counters.total, 8);
    assert_eq!(counters.blocked_request, 2);
    // The first lookup of evil.example. fetches and blocks the reply; the second is a cache hit
    // that is blocked again by the memoized decision.
    assert_eq!(counters.blocked_response, 2);
    assert_eq!(counters.upstream, 1);
    assert_eq!(counters.cached, 2);
    assert_eq!(counters.errors, 1);
    assert_eq!(counters.dropped, 0);

    let current_hour = snapshot.hourly.last().unwrap();
    assert_eq!((current_hour.total, current_hour.blocked), (8, 4));

    let blocked: Vec<(&str, u64)> = snapshot
        .top_blocked
        .iter()
        .map(|entry| (&*entry.key, entry.count))
        .collect();
    assert_eq!(blocked, [("ads.example", 2), ("evil.example", 2)]);
    assert_eq!(snapshot.top_queried[0].key.as_ref(), "ok.example");
    assert_eq!(snapshot.top_queried[0].count, 3);
    assert_eq!(snapshot.top_clients.len(), 1);
    assert_eq!(
        snapshot.top_clients[0].key,
        LOCALHOST.parse::<IpAddr>().unwrap()
    );
    assert_eq!(snapshot.top_clients[0].count, 8);
}

#[tokio::test]
async fn the_query_log_names_the_result_type_upstream_and_client_of_each_query() {
    let upstream = scripted_upstream().await;
    let mut config = config_for(&upstream);
    config.upstream.timeout_ms = 200;
    let server = start(&config, engine_of(&["||ads.example^\n"], &[])).await;

    ask(&server, "ads.example.", RecordType::AAAA).await;
    ask(&server, "ok.example.", RecordType::A).await;
    ask(&server, "ok.example.", RecordType::A).await;
    ask(&server, "silent.example.", RecordType::A).await;

    let log = server.pipeline.stats().query_log(10);
    let seen: Vec<(&str, u16, QueryResult, Option<u8>)> = log
        .iter()
        .map(|entry| (&*entry.qname, entry.qtype, entry.result, entry.upstream))
        .collect();

    assert_eq!(
        seen,
        [
            ("silent.example", 1, QueryResult::Error, None),
            ("ok.example", 1, QueryResult::Cached, None),
            ("ok.example", 1, QueryResult::Pass, Some(0)),
            ("ads.example", 28, QueryResult::BlockedRequest, None),
        ]
    );
    assert!(
        log.iter()
            .all(|entry| entry.client == LOCALHOST.parse::<IpAddr>().unwrap())
    );
    // The query that waited for the upstream took longer than the one answered at once.
    assert!(log[0].latency_us > log[3].latency_us);
}

async fn send(socket: &UdpSocket, to: SocketAddr, text: &str) {
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(name(text), RecordType::A));

    socket.send_to(&query.to_vec().unwrap(), to).await.unwrap();
}

#[tokio::test]
async fn a_query_shed_under_overload_is_counted_as_dropped_and_not_as_answered() {
    let upstream = scripted_upstream().await;
    let mut config = config_for(&upstream);
    config.limits.max_inflight_queries = 1;
    let server = start(&config, engine_of(&[], &[])).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    send(&socket, server.udp, "slow.example.").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    send(&socket, server.udp, "shed.example.").await;
    tokio::time::sleep(Duration::from_millis(600)).await;

    let counters = snapshot_of(&server).counters;
    assert_eq!(counters.dropped, 1);
    assert_eq!(counters.total, 1);
    assert_eq!(counters.upstream, 1);
}

#[tokio::test]
async fn a_queued_stream_reply_is_counted_when_it_is_written_and_only_once() {
    let upstream = scripted_upstream().await;
    let server = start(&config_for(&upstream), engine_of(&[], &[])).await;
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(name("ok.example."), RecordType::A));
    let pipeline = &server.pipeline;

    let prepared = pipeline
        .prepare(
            query.to_vec().unwrap(),
            Protocol::Tcp,
            LOCALHOST.parse().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(snapshot_of(&server).counters.total, 0);

    let mut out = Vec::new();
    assert!(pipeline.finish(&prepared, &mut out).await);

    let counters = snapshot_of(&server).counters;
    assert_eq!((counters.total, counters.upstream), (1, 1));
}
