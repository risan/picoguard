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
use picoguard::stats::QueryResult;

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

#[tokio::test]
async fn twenty_concurrent_stale_queries_start_one_refresh_and_the_next_query_gets_its_answer() {
    let refresh_delay = Duration::from_millis(1500);
    let upstream = ttl_one_then(refresh_delay).await;
    let mut config = config_for(&upstream);
    // The first try gets half the timeout; it must outlast the upstream's delay, so the
    // refresh is one exchange and not a retry.
    config.upstream.timeout_ms = 5000;
    let server = start(&config, engine_of(&[], &[])).await;

    ask(&server, "stale.example.", RecordType::A).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let asks: Vec<_> = (0..20)
        .map(|_| {
            let server = server.clone();

            tokio::spawn(async move {
                let asked = Instant::now();
                let reply = ask(&server, "stale.example.", RecordType::A).await;

                (reply, asked.elapsed())
            })
        })
        .collect();
    for task in asks {
        let (reply, took) = task.await.unwrap();

        assert_eq!(addresses(&reply), [FIRST]);
        assert_eq!(ttls(&reply), [ANSWER_TTL]);
        assert!(took < refresh_delay, "took {took:?}");
    }

    let deadline = Instant::now() + Duration::from_secs(1);
    while upstream.count() < 2 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(upstream.count(), 2);

    let deadline = Instant::now() + Duration::from_secs(3);
    let refreshed = loop {
        let reply = ask(&server, "stale.example.", RecordType::A).await;
        if addresses(&reply) == [LATER] {
            break reply;
        }

        assert!(Instant::now() < deadline, "the refresh never landed");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    assert!((299..=300).contains(&refreshed.answers[0].ttl));
    assert_eq!(upstream.count(), 2);
}

#[tokio::test]
async fn with_the_upstream_down_stale_answers_last_until_the_max_age_then_the_query_fails() {
    let calls = AtomicUsize::new(0);
    let upstream = fake_upstream(move |query| {
        if calls.fetch_add(1, Ordering::SeqCst) > 0 {
            return Vec::new();
        }

        let owner = query.queries[0].name().to_string();

        vec![(
            Duration::ZERO,
            reply_to(query, vec![a_record(&owner, 1, FIRST)]),
        )]
    })
    .await;
    let mut config = config_for(&upstream);
    config.cache.optimistic_max_age_secs = 1;
    config.upstream.timeout_ms = 300;
    let server = start(&config, engine_of(&[], &[])).await;
    let counters = || server.pipeline.stats().snapshot().counters;
    let failed = || server.pipeline.upstream_tallies()[0].tally.failed;
    let t0 = tokio::time::Instant::now();

    ask(&server, "down.example.", RecordType::A).await;

    // Ages 1 and 2: inside the one-second window past the one-second lifetime.
    for at in [1200, 2300] {
        tokio::time::sleep_until(t0 + Duration::from_millis(at)).await;
        let reply = ask(&server, "down.example.", RecordType::A).await;

        assert_eq!(addresses(&reply), [FIRST], "at {at} ms");
        assert_eq!(ttls(&reply), [ANSWER_TTL], "at {at} ms");
    }

    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(counters().errors, 0);
    assert!(failed() >= 2, "{} failed", failed());

    // Age 3: past the window, so a normal miss that the silent upstream fails.
    tokio::time::sleep_until(t0 + Duration::from_millis(3300)).await;
    let reply = ask(&server, "down.example.", RecordType::A).await;

    assert_eq!(u16::from(reply.metadata.response_code), 2);
    assert_eq!(counters().errors, 1);
}

#[tokio::test]
async fn the_refresh_adds_nothing_to_the_totals_or_the_query_log() {
    let upstream = ttl_one_then(Duration::ZERO).await;
    let server = start(&config_for(&upstream), engine_of(&[], &[])).await;
    let stats = server.pipeline.stats();

    ask(&server, "seven.example.", RecordType::A).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let before = stats.snapshot().counters;

    let reply = ask(&server, "seven.example.", RecordType::A).await;
    assert_eq!(ttls(&reply), [ANSWER_TTL]);

    let deadline = Instant::now() + Duration::from_secs(3);
    while server.pipeline.upstream_tallies()[0].tally.answered < 2 {
        assert!(Instant::now() < deadline, "the refresh never landed");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    let snapshot = stats.snapshot();
    let after = snapshot.counters;
    assert_eq!(after.total, before.total + 1);
    assert_eq!(after.cached, before.cached + 1);
    assert_eq!(after.upstream, before.upstream);
    assert_eq!(after.errors, before.errors);

    let results: Vec<QueryResult> = stats
        .query_log(100)
        .into_iter()
        .filter(|entry| &*entry.qname == "seven.example")
        .map(|entry| entry.result)
        .collect();
    assert_eq!(results, [QueryResult::Cached, QueryResult::Pass]);

    let seven = snapshot
        .top_queried
        .iter()
        .find(|entry| &*entry.key == "seven.example")
        .unwrap();
    assert_eq!(seven.count, 2);
}
