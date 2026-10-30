//! Optimistic caching through the whole server: an expired answer comes at once with the
//! answer TTL under the policy of now, and the background refresh behind it.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::harness::{
    FakeUpstream, a_record, ask, config_for, engine_of, fake_upstream, reply_to, start,
};
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};

const ANSWER_TTL: u32 = 30;
const BLOCKED_TTL: u32 = 10;
const FIRST: [u8; 4] = [192, 0, 2, 1];
const LATER: [u8; 4] = [192, 0, 2, 2];

/// The first query is answered at once with 192.0.2.1 and TTL 1; every later one after
/// `later` with 192.0.2.2 and TTL 300.
async fn ttl_one_then(later: Duration) -> FakeUpstream {
    let calls = AtomicUsize::new(0);

    fake_upstream(move |query| {
        let owner = query.queries[0].name().to_string();
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            return vec![(
                Duration::ZERO,
                reply_to(query, vec![a_record(&owner, 1, FIRST)]),
            )];
        }

        vec![(later, reply_to(query, vec![a_record(&owner, 300, LATER)]))]
    })
    .await
}

fn addresses(reply: &Message) -> Vec<[u8; 4]> {
    reply
        .answers
        .iter()
        .map(|record| match &record.data {
            RData::A(address) => address.0.octets(),
            other => panic!("unexpected {other:?}"),
        })
        .collect()
}

fn ttls(reply: &Message) -> Vec<u32> {
    reply.answers.iter().map(|record| record.ttl).collect()
}

#[tokio::test]
async fn a_stale_answer_comes_at_once_with_the_answer_ttl() {
    let refresh_delay = Duration::from_secs(2);
    let upstream = ttl_one_then(refresh_delay).await;
    let server = start(&config_for(&upstream), engine_of(&[], &[])).await;

    ask(&server, "stale.example.", RecordType::A).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let asked = Instant::now();
    let reply = ask(&server, "stale.example.", RecordType::A).await;
    let took = asked.elapsed();

    assert_eq!(addresses(&reply), [FIRST]);
    assert_eq!(ttls(&reply), [ANSWER_TTL]);
    // The upstream's answer would take `refresh_delay` and carry the other address, so the
    // address alone proves the answer did not wait; the bound only reports a slow reply.
    assert!(took < refresh_delay, "took {took:?}");
}

#[tokio::test]
async fn with_optimism_off_an_expired_answer_waits_for_the_upstream() {
    let refresh_delay = Duration::from_millis(400);
    let upstream = ttl_one_then(refresh_delay).await;
    let mut config = config_for(&upstream);
    config.cache.optimistic = false;
    let server = start(&config, engine_of(&[], &[])).await;

    ask(&server, "stale.example.", RecordType::A).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let asked = Instant::now();
    let reply = ask(&server, "stale.example.", RecordType::A).await;
    let took = asked.elapsed();

    assert!(took >= Duration::from_millis(350), "took {took:?}");
    assert_eq!(addresses(&reply), [LATER]);
    assert_eq!(ttls(&reply), [300]);
    assert_eq!(upstream.count(), 2);
}

#[tokio::test]
async fn a_stale_answer_follows_the_pause_and_the_rules_of_now() {
    let upstream = ttl_one_then(Duration::from_secs(3)).await;
    let server = start(&config_for(&upstream), engine_of(&[], &[])).await;

    ask(&server, "stale.example.", RecordType::A).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;

    server
        .policy
        .pause(Duration::from_secs(60), server.policy.now());
    let reply = ask(&server, "stale.example.", RecordType::A).await;
    assert_eq!(addresses(&reply), [FIRST]);
    assert_eq!(ttls(&reply), [ANSWER_TTL]);

    server.policy.resume();
    server
        .policy
        .swap_engine(engine_of(&["||192.0.2.1^\n"], &[]));
    let reply = ask(&server, "stale.example.", RecordType::A).await;
    assert_eq!(addresses(&reply), [[0, 0, 0, 0]]);
    assert_eq!(ttls(&reply), [BLOCKED_TTL]);

    server
        .policy
        .swap_engine(engine_of(&["||stale.example^\n"], &[]));
    let reply = ask(&server, "stale.example.", RecordType::A).await;
    assert_eq!(addresses(&reply), [[0, 0, 0, 0]]);
    assert_eq!(ttls(&reply), [BLOCKED_TTL]);
    assert_eq!(
        server.pipeline.stats().snapshot().counters.blocked_request,
        1
    );
}
