//! Filtering through the whole pipeline: blocked replies per type, the policy generation
//! (swap between send and reply, memo reuse), and pause.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::harness::{
    FakeUpstream, Running, a_record, answering_upstream, ask, config_for, engine_of, fake_upstream,
    name, reply_to, start,
};
use hickory_proto::op::{Message, Query as DnsQuery};
use hickory_proto::rr::{RData, Record, RecordType};
use picoguard::dns::build::Protocol;
use picoguard::filter::engine::Engine;
use picoguard::pipeline::Pipeline;
use picoguard::policy::Policy;

const BLOCKED_TTL: u32 = 10;

fn answer_addresses(reply: &Message) -> Vec<String> {
    reply
        .answers
        .iter()
        .map(|record| match &record.data {
            RData::A(address) => address.0.to_string(),
            RData::AAAA(address) => address.0.to_string(),
            RData::CNAME(target) => target.0.to_string(),
            other => panic!("unexpected {other:?}"),
        })
        .collect()
}

fn is_blocked_a(reply: &Message) -> bool {
    answer_addresses(reply) == ["0.0.0.0"] && reply.answers[0].ttl == BLOCKED_TTL
}

#[tokio::test]
async fn blocked_replies_follow_the_query_type() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let engine = engine_of(
        &["||blocked.example^\n1.2.3.4 host4.example\n2001:db8::1 host6.example\n"],
        &[],
    );
    let server = start(&config_for(&upstream), engine).await;

    let reply = ask(&server, "blocked.example.", RecordType::A).await;
    assert_eq!(answer_addresses(&reply), ["0.0.0.0"]);
    assert_eq!(reply.answers[0].ttl, BLOCKED_TTL);

    let reply = ask(&server, "sub.blocked.example.", RecordType::AAAA).await;
    assert_eq!(answer_addresses(&reply), ["::"]);

    let reply = ask(&server, "blocked.example.", RecordType::HTTPS).await;
    assert_eq!(u16::from(reply.metadata.response_code), 0);
    assert!(reply.answers.is_empty() && reply.authorities.is_empty());

    for rtype in [RecordType::TXT, RecordType::MX, RecordType::NS] {
        let reply = ask(&server, "blocked.example.", rtype).await;
        assert_eq!(u16::from(reply.metadata.response_code), 0);
        assert!(reply.answers.is_empty());
        assert!(
            matches!(&reply.authorities[..], [record] if record.record_type() == RecordType::SOA && record.ttl == BLOCKED_TTL)
        );
    }

    let reply = ask(&server, "host4.example.", RecordType::A).await;
    assert_eq!(answer_addresses(&reply), ["1.2.3.4"]);

    // A host rule of the other address family blocks with the null address.
    let reply = ask(&server, "host4.example.", RecordType::AAAA).await;
    assert_eq!(answer_addresses(&reply), ["::"]);

    let reply = ask(&server, "host6.example.", RecordType::AAAA).await;
    assert_eq!(answer_addresses(&reply), ["2001:db8::1"]);
    let reply = ask(&server, "host6.example.", RecordType::A).await;
    assert_eq!(answer_addresses(&reply), ["0.0.0.0"]);

    assert_eq!(
        upstream.count(),
        0,
        "blocked requests never reach the upstream"
    );
}

#[tokio::test]
async fn a_conditional_badfilter_disables_its_target_for_one_type_only() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let engine = engine_of(&["||x.example^\n||x.example^$badfilter,dnstype=A\n"], &[]);
    let server = start(&config_for(&upstream), engine).await;

    let for_a = ask(&server, "x.example.", RecordType::A).await;
    let for_aaaa = ask(&server, "x.example.", RecordType::AAAA).await;

    assert_eq!(answer_addresses(&for_a), ["9.9.9.9"]);
    assert_eq!(answer_addresses(&for_aaaa), ["::"]);
}

#[tokio::test]
async fn the_allowlist_engine_is_asked_first() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let engine = engine_of(&["||x.example^$important\n"], &["||x.example^\n"]);
    let server = start(&config_for(&upstream), engine).await;

    let reply = ask(&server, "x.example.", RecordType::A).await;

    assert_eq!(answer_addresses(&reply), ["9.9.9.9"]);
}

async fn late_answer(
    server: &Running,
    engine_during_flight: impl FnOnce() -> Arc<Engine>,
) -> Message {
    let waiting = {
        let server = server.clone();

        tokio::spawn(async move { ask(&server, "late.example.", RecordType::A).await })
    };

    tokio::time::sleep(Duration::from_millis(150)).await;
    server.policy.swap_engine(engine_during_flight());

    waiting.await.unwrap()
}

#[tokio::test]
async fn a_generation_change_between_send_and_reply_filters_the_reply_again() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::from_millis(500)).await;

    // Allowed when the query went out, blocked by the time the reply arrives.
    let server = start(&config_for(&upstream), engine_of(&[], &[])).await;
    let reply = late_answer(&server, || engine_of(&["||9.9.9.9^\n"], &[])).await;
    assert!(is_blocked_a(&reply), "{:?}", answer_addresses(&reply));

    // The other way round: the engine that would block is gone when the reply arrives.
    let server = start(&config_for(&upstream), engine_of(&["||9.9.9.9^\n"], &[])).await;
    let reply = late_answer(&server, || engine_of(&[], &[])).await;
    assert_eq!(answer_addresses(&reply), ["9.9.9.9"]);
}

fn ask_in_background(server: &Running, text: &'static str) -> tokio::task::JoinHandle<Message> {
    let server = server.clone();

    tokio::spawn(async move { ask(&server, text, RecordType::A).await })
}

/// Waits until the upstream has seen `count` queries, so a test acts relative to what
/// happened and not to a clock that a busy machine can stretch.
async fn wait_for_queries(upstream: &FakeUpstream, count: usize) {
    for _ in 0..600 {
        if upstream.count() >= count {
            return;
        }

        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    panic!("the upstream never saw {count} queries");
}

/// The wait for a slow reply must not end in a retry, which would be a second query.
fn patient_config(upstream: &FakeUpstream) -> picoguard::config::Config {
    let mut config = config_for(upstream);
    config.upstream.timeout_ms = 10_000;

    config
}

#[tokio::test]
async fn a_rule_added_for_the_question_during_the_wait_blocks_every_waiting_client() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::from_millis(900)).await;
    let server = start(&patient_config(&upstream), engine_of(&[], &[])).await;

    let first = ask_in_background(&server, "late.example.");
    wait_for_queries(&upstream, 1).await;
    let coalesced = ask_in_background(&server, "late.example.");
    tokio::time::sleep(Duration::from_millis(150)).await;
    server
        .policy
        .swap_engine(engine_of(&["||late.example^\n"], &[]));

    let first = first.await.unwrap();
    let coalesced = coalesced.await.unwrap();

    assert!(is_blocked_a(&first), "{:?}", answer_addresses(&first));
    assert!(
        is_blocked_a(&coalesced),
        "{:?}",
        answer_addresses(&coalesced)
    );
    assert_eq!(upstream.count(), 1, "the two clients shared one query");
}

#[tokio::test]
async fn a_request_admitted_during_a_pause_is_blocked_when_the_reply_comes_after_it() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::from_millis(1200)).await;
    let server = start(
        &patient_config(&upstream),
        engine_of(&["||late.example^\n"], &[]),
    )
    .await;

    server
        .policy
        .pause(Duration::from_millis(700), Instant::now());
    let first = ask_in_background(&server, "late.example.");
    wait_for_queries(&upstream, 1).await;
    let coalesced = ask_in_background(&server, "late.example.");

    let first = first.await.unwrap();
    let coalesced = coalesced.await.unwrap();

    assert!(is_blocked_a(&first), "{:?}", answer_addresses(&first));
    assert!(
        is_blocked_a(&coalesced),
        "{:?}",
        answer_addresses(&coalesced)
    );
    assert_eq!(upstream.count(), 1);
}

#[tokio::test]
async fn a_request_still_paused_when_the_reply_comes_is_answered() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::from_millis(300)).await;
    let server = start(
        &config_for(&upstream),
        engine_of(&["||late.example^\n"], &[]),
    )
    .await;

    server.policy.pause(Duration::from_secs(60), Instant::now());
    let reply = ask(&server, "late.example.", RecordType::A).await;

    assert_eq!(answer_addresses(&reply), ["9.9.9.9"]);
}

#[tokio::test]
async fn a_cached_reply_is_filtered_again_after_a_swap() {
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let server = start(&config_for(&upstream), engine_of(&[], &[])).await;

    let first = ask(&server, "cached.example.", RecordType::A).await;
    let second = ask(&server, "cached.example.", RecordType::A).await;
    assert_eq!(answer_addresses(&first), ["9.9.9.9"]);
    assert_eq!(answer_addresses(&second), ["9.9.9.9"]);
    assert_eq!(upstream.count(), 1);

    server.policy.swap_engine(engine_of(&["||9.9.9.9^\n"], &[]));
    let third = ask(&server, "cached.example.", RecordType::A).await;
    assert!(is_blocked_a(&third));
    assert_eq!(upstream.count(), 1, "the blocked reply came from the cache");

    server.policy.swap_engine(engine_of(&[], &[]));
    let fourth = ask(&server, "cached.example.", RecordType::A).await;
    assert_eq!(answer_addresses(&fourth), ["9.9.9.9"]);
}

#[tokio::test]
async fn pausing_skips_filtering_until_the_deadline_and_resume_ends_it_at_once() {
    let upstream = answering_upstream([5, 5, 5, 5], Duration::ZERO).await;
    let server = start(
        &config_for(&upstream),
        engine_of(&["||blocked.example^\n"], &[]),
    )
    .await;

    server
        .policy
        .pause(Duration::from_millis(600), Instant::now());
    let during = ask(&server, "blocked.example.", RecordType::A).await;
    assert_eq!(answer_addresses(&during), ["5.5.5.5"]);

    tokio::time::sleep(Duration::from_millis(700)).await;
    let after = ask(&server, "blocked.example.", RecordType::A).await;
    assert!(is_blocked_a(&after));

    server.policy.pause(Duration::from_secs(60), Instant::now());
    let paused = ask(&server, "blocked.example.", RecordType::A).await;
    assert_eq!(answer_addresses(&paused), ["5.5.5.5"]);

    server.policy.resume();
    let resumed = ask(&server, "blocked.example.", RecordType::A).await;
    assert!(is_blocked_a(&resumed));
}

fn cloaked(owner: &str, target: &str, address: [u8; 4]) -> Vec<Record> {
    vec![
        Record::from_rdata(
            name(owner),
            300,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(name(target))),
        ),
        a_record(target, 300, address),
    ]
}

#[tokio::test]
async fn a_cached_reply_served_during_a_pause_is_blocked_on_the_first_hit_after_it() {
    let upstream = fake_upstream(|query| {
        vec![(
            Duration::ZERO,
            reply_to(
                query,
                cloaked("cloaked.example.", "cdn.tracker.example.", [9, 9, 9, 9]),
            ),
        )]
    })
    .await;
    let server = start(
        &config_for(&upstream),
        engine_of(&["||tracker.example^\n"], &[]),
    )
    .await;

    server
        .policy
        .pause(Duration::from_millis(600), Instant::now());
    let during = ask(&server, "cloaked.example.", RecordType::A).await;
    assert_eq!(
        answer_addresses(&during),
        ["cdn.tracker.example.", "9.9.9.9"]
    );
    let cached = ask(&server, "cloaked.example.", RecordType::A).await;
    assert_eq!(answer_addresses(&cached).len(), 2);
    assert_eq!(upstream.count(), 1);

    tokio::time::sleep(Duration::from_millis(700)).await;
    let after = ask(&server, "cloaked.example.", RecordType::A).await;

    assert!(is_blocked_a(&after), "{:?}", answer_addresses(&after));
    assert_eq!(upstream.count(), 1, "the block came from the cached reply");
}

#[tokio::test]
async fn the_answer_address_of_a_reply_is_checked_with_the_go_text_form() {
    // AAAA ::ffff:203.0.113.7 is the text 203.0.113.7 for AdGuard Home.
    let upstream = fake_upstream(|query| {
        let mapped: std::net::Ipv6Addr = "::ffff:203.0.113.7".parse().unwrap();
        let record = Record::from_rdata(
            query.queries[0].name().clone(),
            300,
            RData::AAAA(hickory_proto::rr::rdata::AAAA(mapped)),
        );

        vec![(Duration::ZERO, reply_to(query, vec![record]))]
    })
    .await;
    let server = start(
        &config_for(&upstream),
        engine_of(&["||203.0.113.7^\n"], &[]),
    )
    .await;

    let reply = ask(&server, "mapped.example.", RecordType::AAAA).await;

    assert_eq!(answer_addresses(&reply), ["::"]);
}

/// One name mapped to the most addresses a list may have (1,024) is more than a reply gets:
/// the collection stops one past the cap and the reply is TC (UDP) or SERVFAIL (TCP).
#[tokio::test]
async fn a_name_with_the_most_host_addresses_is_answered_fast_with_tc_or_servfail() {
    const ADDRESSES: u32 = 1024;
    let hosts: String = (0..ADDRESSES)
        .map(|index| {
            let [a, b, c, d] = (0x0A00_0000 + index).to_be_bytes();

            format!("{a}.{b}.{c}.{d} big.example\n")
        })
        .collect();
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let engine = engine_of(&[&hosts, "||plain.example^\n"], &[]);
    let config = config_for(&upstream);
    let server = start(&config, Arc::clone(&engine)).await;
    let started = Instant::now();

    let mut udp_replies = Vec::new();
    for _ in 0..20 {
        udp_replies.push(ask(&server, "big.example.", RecordType::A).await);
    }

    for reply in &udp_replies {
        assert!(reply.metadata.truncation);
        assert!(reply.answers.is_empty());
    }

    let pipeline = Pipeline::new(&config, Arc::new(Policy::with_engine(engine))).unwrap();
    let mut query = Message::query();
    query.add_query(DnsQuery::query(name("big.example."), RecordType::A));
    let query = query.to_vec().unwrap();
    let mut out = Vec::new();
    for _ in 0..20 {
        assert!(
            pipeline
                .answer(query.clone(), Protocol::Tcp, &mut out)
                .await
        );
        let reply = Message::from_vec(&out).unwrap();
        assert_eq!(u16::from(reply.metadata.response_code), 2, "SERVFAIL");
    }

    assert!(
        started.elapsed() < Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(
        upstream.count(),
        0,
        "a blocked name never reaches the upstream"
    );
}
