//! DNS rewrites and SafeSearch through the whole pipeline (plan D7): answers from addresses,
//! answers flattened from a target name, their place before the block lists and `[local]`, and
//! pause.

mod common;

use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::harness::{
    FakeUpstream, Running, a_record, ask, config_for, engine_of, fake_upstream, name, reply_to,
    start,
};
use hickory_proto::op::{Edns, Message, Query as DnsQuery, ResponseCode};
use hickory_proto::rr::rdata::{AAAA, CNAME};
use hickory_proto::rr::{RData, Record, RecordType};
use picoguard::config::{Config, Rewrite};
use picoguard::dns::build::Protocol;
use picoguard::filter::engine::Engine;
use picoguard::pipeline::Prepared;
use picoguard::rewrites::Rewrites;
use picoguard::stats::QueryResult;

const SAFE_GOOGLE: [u8; 4] = [216, 239, 38, 120];
const ANY_OTHER: [u8; 4] = [9, 9, 9, 9];
/// How long the scripted upstream takes for a name that starts with "slow".
const SLOW: Duration = Duration::from_millis(300);

fn rewrites(entries: &[(&str, &str)]) -> Vec<Rewrite> {
    entries
        .iter()
        .map(|(name, answer)| Rewrite {
            name: name.to_string(),
            answer: answer.to_string(),
        })
        .collect()
}

fn cname_record(owner: &str, ttl: u32, target: &str) -> Record {
    Record::from_rdata(name(owner), ttl, RData::CNAME(CNAME(name(target))))
}

fn aaaa_record(owner: &str, ttl: u32, address: &str) -> Record {
    let address: Ipv6Addr = address.parse().unwrap();

    Record::from_rdata(name(owner), ttl, RData::AAAA(AAAA(address)))
}

fn values(reply: &Message) -> Vec<String> {
    reply
        .answers
        .iter()
        .map(|record| {
            assert!(
                matches!(record.record_type(), RecordType::A | RecordType::AAAA),
                "only addresses: {record:?}"
            );

            record.data.to_string()
        })
        .collect()
}

fn ttls(reply: &Message) -> Vec<u32> {
    reply.answers.iter().map(|record| record.ttl).collect()
}

fn is_nodata(reply: &Message) -> bool {
    reply.metadata.response_code == ResponseCode::NoError
        && reply.answers.is_empty()
        && reply.authorities.is_empty()
}

fn asked_names(upstream: &FakeUpstream) -> Vec<String> {
    upstream
        .received()
        .iter()
        .map(|query| query.queries[0].name().to_string())
        .collect()
}

/// Answers by question name, as a scripted upstream; any other A question gets `ANY_OTHER`.
/// A name that starts with "slow" is answered after `SLOW`, and `silent.example` never.
async fn scripted_upstream() -> FakeUpstream {
    fake_upstream(|query| {
        let question = &query.queries[0];
        let owner = question.name().to_string();
        let is_aaaa = question.query_type() == RecordType::AAAA;
        let answers = match owner.as_str() {
            "forcesafesearch.google.com." => vec![a_record(&owner, 300, SAFE_GOOGLE)],
            "strict.bing.com." => vec![a_record(&owner, 300, [204, 79, 197, 220])],
            "web.example." if is_aaaa => vec![
                cname_record(&owner, 200, "a.cdn.example."),
                cname_record("a.cdn.example.", 100, "b.cdn.example."),
                aaaa_record("b.cdn.example.", 250, "2001:db8::1"),
            ],
            "web.example." => vec![
                cname_record(&owner, 200, "a.cdn.example."),
                cname_record("a.cdn.example.", 100, "b.cdn.example."),
                a_record("b.cdn.example.", 250, [1, 2, 3, 4]),
                a_record("other.example.", 10, [6, 6, 6, 6]),
                a_record("b.cdn.example.", 250, [1, 2, 3, 5]),
            ],
            "long.example." => vec![a_record(&owner, 3600, [7, 7, 7, 7])],
            "short.example." => vec![a_record(&owner, 1, [8, 8, 8, 8])],
            "empty.example." => Vec::new(),
            "loop.example." => vec![
                cname_record(&owner, 60, "loop2.example."),
                cname_record("loop2.example.", 60, "loop.example."),
            ],
            _ if is_aaaa => Vec::new(),
            _ => vec![a_record(&owner, 300, ANY_OTHER)],
        };
        let mut reply = reply_to(query, answers);
        match owner.as_str() {
            "gone.example." => {
                reply.metadata.response_code = ResponseCode::NXDomain;
            }

            "broken.example." => {
                reply.metadata.response_code = ResponseCode::ServFail;
            }

            "cut.example." => {
                reply.metadata.truncation = true;
            }

            "badvers.example." => {
                reply.metadata.response_code = ResponseCode::BADVERS;
                reply.set_edns(Edns::new());
            }

            _ => {}
        }

        if owner == "silent.example." {
            return Vec::new();
        }

        let delay = if owner.starts_with("slow") {
            SLOW
        } else {
            Duration::ZERO
        };

        vec![(delay, reply)]
    })
    .await
}

async fn start_with(
    upstream: &FakeUpstream,
    entries: &[(&str, &str)],
    safe_search: bool,
    engine: Arc<Engine>,
    change: impl FnOnce(&mut Config),
) -> Running {
    let mut config = config_for(upstream);
    config.rewrites = rewrites(entries);
    config.safe_search = safe_search;
    change(&mut config);

    start(&config, engine).await
}

/// A TCP query prepared now, to be finished later with `finish_tcp`.
async fn prepare_tcp(server: &Running, text: &str, rtype: RecordType) -> Prepared {
    let mut query = Message::query();
    query.metadata.id = 0x4444;
    query.metadata.recursion_desired = true;
    query.add_query(DnsQuery::query(name(text), rtype));

    server
        .pipeline
        .prepare(
            query.to_vec().unwrap(),
            Protocol::Tcp,
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .expect("a prepared query")
}

async fn finish_tcp(server: &Running, prepared: Prepared) -> (Message, QueryResult) {
    let mut out = Vec::new();
    let finished = server
        .pipeline
        .finish(&prepared, &mut out)
        .await
        .expect("a reply");
    server.pipeline.count(&prepared, finished);
    let result = results(server).last().unwrap().1;

    (Message::from_vec(&out).unwrap(), result)
}

fn table(entries: &[(&str, &str)]) -> Arc<Rewrites> {
    Arc::new(Rewrites::new(&rewrites(entries)).unwrap())
}

/// Through `Pipeline::answer` over TCP: the query is prepared, then finished.
async fn ask_tcp(server: &Running, text: &str, rtype: RecordType) -> Message {
    let mut query = Message::query();
    query.metadata.id = 0x3333;
    query.metadata.recursion_desired = true;
    query.add_query(DnsQuery::query(name(text), rtype));
    let mut out = Vec::new();

    let answered = server
        .pipeline
        .answer(
            query.to_vec().unwrap(),
            Protocol::Tcp,
            "127.0.0.1".parse().unwrap(),
            &mut out,
        )
        .await;

    assert!(answered, "no reply to {text} {rtype}");

    Message::from_vec(&out).unwrap()
}

fn results(server: &Running) -> Vec<(String, QueryResult)> {
    let mut entries: Vec<(String, QueryResult)> = server
        .pipeline
        .stats()
        .query_log(100)
        .into_iter()
        .map(|entry| (entry.qname.to_string(), entry.result))
        .collect();
    entries.reverse();

    entries
}

#[tokio::test]
async fn addresses_answer_a_and_aaaa_by_family_and_every_other_type_with_no_records() {
    let upstream = scripted_upstream().await;
    let server = start_with(
        &upstream,
        &[
            ("nas.lan", "192.168.1.10"),
            ("NAS.lan", "FD00::10"),
            ("v4.lan", "10.0.0.1"),
            ("*.nas.lan", "192.168.1.20"),
        ],
        false,
        engine_of(&[], &[]),
        |_| {},
    )
    .await;

    let reply = ask(&server, "Nas.Lan.", RecordType::A).await;
    assert_eq!(values(&reply), ["192.168.1.10"]);
    assert_eq!(ttls(&reply), [60]);
    assert_eq!(reply.answers[0].name.to_ascii(), "Nas.Lan.");
    assert!(reply.metadata.recursion_available && reply.metadata.recursion_desired);
    assert!(!reply.metadata.authentic_data && !reply.metadata.authoritative);

    assert_eq!(
        values(&ask(&server, "nas.lan.", RecordType::AAAA).await),
        ["fd00::10"]
    );
    assert_eq!(
        values(&ask(&server, "tv.nas.lan.", RecordType::A).await),
        ["192.168.1.20"]
    );
    assert!(is_nodata(&ask(&server, "v4.lan.", RecordType::AAAA).await));
    for rtype in [RecordType::MX, RecordType::TXT, RecordType::HTTPS] {
        assert!(is_nodata(&ask(&server, "nas.lan.", rtype).await), "{rtype}");
    }

    assert_eq!(
        values(&ask_tcp(&server, "nas.lan.", RecordType::A).await),
        ["192.168.1.10"]
    );
    assert_eq!(upstream.count(), 0);
    assert_eq!(server.pipeline.stats().snapshot().counters.rewritten, 8);
    assert!(
        results(&server)
            .iter()
            .all(|(_, result)| *result == QueryResult::Rewritten)
    );
}

#[tokio::test]
async fn a_rewritten_name_under_the_local_domains_is_answered_without_a_local_resolver() {
    let upstream = scripted_upstream().await;
    let server = start_with(
        &upstream,
        &[
            ("nas.lan", "192.168.1.10"),
            ("alias.example", "printer.lan"),
        ],
        false,
        engine_of(&[], &[]),
        |config| config.local.domains = vec!["lan".to_string()],
    )
    .await;

    assert_eq!(
        values(&ask(&server, "nas.lan.", RecordType::A).await),
        ["192.168.1.10"]
    );
    let other = ask(&server, "printer.lan.", RecordType::A).await;
    assert_eq!(other.metadata.response_code, ResponseCode::NXDomain);
    // A target no resolver can answer does not exist here: no records.
    assert!(is_nodata(
        &ask(&server, "alias.example.", RecordType::A).await
    ));
    assert_eq!(upstream.count(), 0);
}

#[tokio::test]
async fn a_rewrite_beats_the_block_lists_and_its_target_is_looked_up_without_them() {
    let upstream = scripted_upstream().await;
    let server = start_with(
        &upstream,
        &[
            ("nas.example", "10.0.0.5"),
            ("alias.example", "ads.example"),
        ],
        false,
        engine_of(&["||nas.example^\n||ads.example^\n||9.9.9.9^\n"], &[]),
        |_| {},
    )
    .await;

    assert_eq!(
        values(&ask(&server, "nas.example.", RecordType::A).await),
        ["10.0.0.5"]
    );
    assert_eq!(
        values(&ask_tcp(&server, "nas.example.", RecordType::A).await),
        ["10.0.0.5"]
    );
    assert_eq!(
        values(&ask(&server, "alias.example.", RecordType::A).await),
        ["9.9.9.9"]
    );
    assert_eq!(
        values(&ask_tcp(&server, "alias.example.", RecordType::A).await),
        ["9.9.9.9"]
    );

    assert_eq!(
        values(&ask(&server, "ads.example.", RecordType::A).await),
        ["0.0.0.0"],
        "the target asked for itself is still blocked"
    );
    assert_eq!(asked_names(&upstream), ["ads.example."]);
}

#[tokio::test]
async fn a_target_name_is_followed_through_its_cname_chain_with_the_smallest_ttl() {
    let upstream = scripted_upstream().await;
    let server = start_with(
        &upstream,
        &[
            ("site.lan", "web.example"),
            ("long.lan", "long.example"),
            ("*.site.lan", "web.example"),
        ],
        false,
        engine_of(&[], &[]),
        |_| {},
    )
    .await;

    let reply = ask(&server, "Site.lan.", RecordType::A).await;
    assert_eq!(values(&reply), ["1.2.3.4", "1.2.3.5"]);
    assert_eq!(ttls(&reply), [100, 100]);
    assert!(
        reply
            .answers
            .iter()
            .all(|record| record.name.to_ascii() == "Site.lan.")
    );
    assert!(!reply.metadata.authentic_data);

    let reply = ask_tcp(&server, "site.lan.", RecordType::AAAA).await;
    assert_eq!(values(&reply), ["2001:db8::1"]);
    assert_eq!(ttls(&reply), [100]);

    assert_eq!(
        ttls(&ask(&server, "long.lan.", RecordType::A).await),
        [300],
        "capped"
    );
    assert!(is_nodata(&ask(&server, "site.lan.", RecordType::TXT).await));
    assert_eq!(upstream.count(), 3);

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let aged = ask(&server, "x.site.lan.", RecordType::A).await;
    assert_eq!(values(&aged), ["1.2.3.4", "1.2.3.5"]);
    assert!(
        ttls(&aged).iter().all(|ttl| *ttl < 100),
        "{:?}",
        ttls(&aged)
    );
    let aged = ask_tcp(&server, "site.lan.", RecordType::A).await;
    assert!(
        ttls(&aged).iter().all(|ttl| *ttl < 100),
        "{:?}",
        ttls(&aged)
    );

    let direct = ask(&server, "web.example.", RecordType::A).await;
    assert_eq!(direct.answers.len(), 5, "the target's own reply, cached");
    assert_eq!(
        upstream.count(),
        3,
        "every lookup after the first is cached"
    );
    assert_eq!(
        results(&server)
            .iter()
            .map(|(_, result)| *result)
            .collect::<Vec<_>>(),
        [
            QueryResult::Rewritten,
            QueryResult::Rewritten,
            QueryResult::Rewritten,
            QueryResult::Rewritten,
            QueryResult::Rewritten,
            QueryResult::Rewritten,
            QueryResult::Cached,
        ]
    );
}

#[tokio::test]
async fn a_stale_target_answers_with_the_optimistic_ttl_and_is_refreshed() {
    let upstream = scripted_upstream().await;
    let server = start_with(
        &upstream,
        &[("quick.lan", "short.example")],
        false,
        engine_of(&[], &[]),
        |_| {},
    )
    .await;

    assert_eq!(ttls(&ask(&server, "quick.lan.", RecordType::A).await), [1]);
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let stale = ask(&server, "quick.lan.", RecordType::A).await;

    assert_eq!(values(&stale), ["8.8.8.8"]);
    assert_eq!(ttls(&stale), [30]);
    let deadline = Instant::now() + Duration::from_secs(3);
    while upstream.count() < 2 {
        assert!(Instant::now() < deadline, "the target was not refreshed");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(asked_names(&upstream), ["short.example.", "short.example."]);
}

#[tokio::test]
async fn a_target_that_does_not_exist_gives_no_records_and_one_that_fails_servfail() {
    let upstream = scripted_upstream().await;
    let server = start_with(
        &upstream,
        &[
            ("gone.lan", "gone.example"),
            ("empty.lan", "empty.example"),
            ("broken.lan", "broken.example"),
            ("cut.lan", "cut.example"),
            ("loop.lan", "loop.example"),
            ("badvers.lan", "badvers.example"),
        ],
        false,
        engine_of(&[], &[]),
        |_| {},
    )
    .await;

    for nodata in ["gone.lan.", "empty.lan."] {
        assert!(
            is_nodata(&ask(&server, nodata, RecordType::A).await),
            "{nodata}"
        );
        assert!(
            is_nodata(&ask_tcp(&server, nodata, RecordType::A).await),
            "{nodata}"
        );
    }

    for failed in ["broken.lan.", "cut.lan.", "loop.lan.", "badvers.lan."] {
        let reply = ask(&server, failed, RecordType::A).await;
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::ServFail,
            "{failed}"
        );
        assert!(reply.answers.is_empty(), "{failed}");
        let reply = ask_tcp(&server, failed, RecordType::A).await;
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::ServFail,
            "{failed}"
        );
    }

    let counters = server.pipeline.stats().snapshot().counters;
    assert_eq!(counters.rewritten, 4);
    assert_eq!(counters.errors, 8);
}

#[tokio::test]
async fn safe_search_answers_with_the_safe_names_addresses_and_a_rewrite_of_the_user_wins() {
    let upstream = scripted_upstream().await;
    let server = start_with(
        &upstream,
        &[("www.bing.com", "10.0.0.9")],
        true,
        engine_of(&[], &[]),
        |_| {},
    )
    .await;

    let reply = ask(&server, "www.google.com.", RecordType::A).await;
    assert_eq!(values(&reply), ["216.239.38.120"]);
    assert_eq!(reply.answers[0].name.to_ascii(), "www.google.com.");
    assert_eq!(
        values(&ask_tcp(&server, "google.co.uk.", RecordType::A).await),
        ["216.239.38.120"]
    );
    assert_eq!(
        values(&ask(&server, "bing.com.", RecordType::A).await),
        ["204.79.197.220"]
    );
    assert_eq!(
        values(&ask(&server, "www.bing.com.", RecordType::A).await),
        ["10.0.0.9"]
    );
    assert_eq!(
        asked_names(&upstream),
        ["forcesafesearch.google.com.", "strict.bing.com."]
    );

    let off_upstream = scripted_upstream().await;
    let off = start_with(&off_upstream, &[], false, engine_of(&[], &[]), |_| {}).await;
    assert_eq!(
        values(&ask(&off, "www.google.com.", RecordType::A).await),
        ["9.9.9.9"]
    );
    assert_eq!(asked_names(&off_upstream), ["www.google.com."]);
}

#[tokio::test]
async fn rewrites_of_the_user_apply_while_paused_and_safe_search_does_not() {
    let upstream = scripted_upstream().await;
    let server = start_with(
        &upstream,
        &[("nas.lan", "192.168.1.10")],
        true,
        engine_of(&[], &[]),
        |_| {},
    )
    .await;
    server
        .policy
        .pause(Duration::from_secs(60), server.policy.now());

    assert_eq!(
        values(&ask(&server, "nas.lan.", RecordType::A).await),
        ["192.168.1.10"]
    );
    assert_eq!(
        values(&ask(&server, "www.google.com.", RecordType::A).await),
        ["9.9.9.9"]
    );
    assert_eq!(
        values(&ask_tcp(&server, "www.youtube.com.", RecordType::A).await),
        ["9.9.9.9"]
    );

    server.policy.resume();

    assert_eq!(
        values(&ask(&server, "google.de.", RecordType::A).await),
        ["216.239.38.120"]
    );
    assert_eq!(
        asked_names(&upstream),
        [
            "www.google.com.",
            "www.youtube.com.",
            "forcesafesearch.google.com."
        ]
    );
}

#[tokio::test]
async fn a_target_with_an_address_rewrite_is_answered_from_it_and_a_name_rewrite_is_not_followed() {
    let upstream = scripted_upstream().await;
    let server = start_with(
        &upstream,
        &[
            ("*.nas.lan", "nas.lan"),
            ("nas.lan", "192.168.1.10"),
            ("alias.lan", "long.example"),
            ("long.example", "short.example"),
        ],
        false,
        engine_of(&[], &[]),
        |_| {},
    )
    .await;

    for reply in [
        ask(&server, "a.nas.lan.", RecordType::A).await,
        ask_tcp(&server, "b.nas.lan.", RecordType::A).await,
    ] {
        assert_eq!(values(&reply), ["192.168.1.10"]);
        assert_eq!(ttls(&reply), [60]);
    }

    assert!(is_nodata(
        &ask(&server, "a.nas.lan.", RecordType::AAAA).await
    ));
    assert_eq!(upstream.count(), 0);

    assert_eq!(
        values(&ask(&server, "alias.lan.", RecordType::A).await),
        ["7.7.7.7"],
        "a target's own name rewrite is not followed"
    );
    assert_eq!(asked_names(&upstream), ["long.example."]);
}

#[tokio::test]
async fn a_reply_prepared_while_paused_is_rewritten_by_safe_search_once_the_pause_ends() {
    let upstream = scripted_upstream().await;
    let server = start_with(&upstream, &[], true, engine_of(&[], &[]), |_| {}).await;
    server
        .policy
        .pause(Duration::from_secs(60), server.policy.now());
    let prepared = prepare_tcp(&server, "www.google.com.", RecordType::A).await;
    server.policy.resume();

    let (reply, result) = finish_tcp(&server, prepared).await;

    assert_eq!(values(&reply), ["216.239.38.120"]);
    assert_eq!(result, QueryResult::Rewritten);
    assert_eq!(
        asked_names(&upstream),
        ["www.google.com.", "forcesafesearch.google.com."]
    );
}

#[tokio::test]
async fn a_safe_search_target_prepared_before_a_pause_is_not_delivered_during_it() {
    let upstream = scripted_upstream().await;
    let server = start_with(&upstream, &[], true, engine_of(&[], &[]), |_| {}).await;
    let prepared = prepare_tcp(&server, "www.google.com.", RecordType::A).await;
    server
        .policy
        .pause(Duration::from_secs(60), server.policy.now());

    let (reply, result) = finish_tcp(&server, prepared).await;

    assert_eq!(values(&reply), ["9.9.9.9"]);
    assert_eq!(result, QueryResult::Pass);
    assert_eq!(
        asked_names(&upstream),
        ["forcesafesearch.google.com.", "www.google.com."]
    );
}

#[tokio::test]
async fn a_target_prepared_before_a_rewrite_change_is_answered_by_the_rewrite_in_force() {
    let upstream = scripted_upstream().await;
    let server = start_with(
        &upstream,
        &[("alias.lan", "long.example")],
        false,
        engine_of(&[], &[]),
        |_| {},
    )
    .await;
    let prepared = |server| prepare_tcp(server, "alias.lan.", RecordType::A);

    let waiting = prepared(&server).await;
    let replaced = server
        .pipeline
        .replace_rewrites(table(&[("alias.lan", "short.example")]));
    drop(replaced);
    let (reply, result) = finish_tcp(&server, waiting).await;
    assert_eq!(values(&reply), ["8.8.8.8"]);
    assert_eq!(result, QueryResult::Rewritten);

    let waiting = prepared(&server).await;
    drop(
        server
            .pipeline
            .replace_rewrites(table(&[("alias.lan", "10.0.0.9")])),
    );
    let (reply, result) = finish_tcp(&server, waiting).await;
    assert_eq!(values(&reply), ["10.0.0.9"]);
    assert_eq!(result, QueryResult::Rewritten);

    drop(
        server
            .pipeline
            .replace_rewrites(table(&[("alias.lan", "short.example")])),
    );
    let waiting = prepared(&server).await;
    drop(server.pipeline.replace_rewrites(table(&[])));
    let (reply, result) = finish_tcp(&server, waiting).await;
    assert_eq!(values(&reply), ["9.9.9.9"]);
    assert_eq!(result, QueryResult::Pass);

    assert_eq!(
        asked_names(&upstream),
        ["long.example.", "short.example.", "alias.lan."]
    );
}

#[tokio::test]
async fn a_reply_prepared_before_a_rewrite_was_added_is_answered_by_the_rewrite() {
    let upstream = scripted_upstream().await;
    let server = start_with(&upstream, &[], false, engine_of(&[], &[]), |_| {}).await;
    let prepared = prepare_tcp(&server, "plain.example.", RecordType::A).await;
    drop(
        server
            .pipeline
            .replace_rewrites(table(&[("plain.example", "10.1.1.1")])),
    );

    let (reply, result) = finish_tcp(&server, prepared).await;

    assert_eq!(values(&reply), ["10.1.1.1"]);
    assert_eq!(result, QueryResult::Rewritten);
}

#[tokio::test]
async fn a_rewrite_changed_while_the_new_target_is_looked_up_answers_by_the_latest() {
    let upstream = scripted_upstream().await;
    let server = start_with(
        &upstream,
        &[("alias.lan", "long.example")],
        false,
        engine_of(&[], &[]),
        |_| {},
    )
    .await;
    let waiting = prepare_tcp(&server, "alias.lan.", RecordType::A).await;
    drop(
        server
            .pipeline
            .replace_rewrites(table(&[("alias.lan", "slow-1.example")])),
    );

    let change = async {
        tokio::time::sleep(SLOW / 6).await;
        drop(
            server
                .pipeline
                .replace_rewrites(table(&[("alias.lan", "10.0.0.7")])),
        );
    };
    let ((reply, result), ()) = tokio::join!(finish_tcp(&server, waiting), change);

    assert_eq!(values(&reply), ["10.0.0.7"]);
    assert_eq!(result, QueryResult::Rewritten);
    assert_eq!(asked_names(&upstream), ["long.example.", "slow-1.example."]);
}

#[tokio::test]
async fn a_rewrite_added_while_the_name_itself_is_looked_up_answers_by_it() {
    let upstream = scripted_upstream().await;
    let server = start_with(
        &upstream,
        &[("slow-2.example", "long.example")],
        false,
        engine_of(&[], &[]),
        |_| {},
    )
    .await;
    let waiting = prepare_tcp(&server, "slow-2.example.", RecordType::A).await;
    drop(server.pipeline.replace_rewrites(table(&[])));

    let change = async {
        tokio::time::sleep(SLOW / 6).await;
        drop(
            server
                .pipeline
                .replace_rewrites(table(&[("slow-2.example", "10.0.0.8")])),
        );
    };
    let ((reply, result), ()) = tokio::join!(finish_tcp(&server, waiting), change);

    assert_eq!(values(&reply), ["10.0.0.8"]);
    assert_eq!(result, QueryResult::Rewritten);
}

#[tokio::test]
async fn a_rewrite_that_keeps_changing_while_it_waits_ends_in_servfail_after_three_lookups() {
    let upstream = scripted_upstream().await;
    let server = start_with(
        &upstream,
        &[("alias.lan", "long.example")],
        false,
        engine_of(&[], &[]),
        |config| {
            config.upstream.timeout_ms = 3000;
        },
    )
    .await;
    let waiting = prepare_tcp(&server, "alias.lan.", RecordType::A).await;
    drop(
        server
            .pipeline
            .replace_rewrites(table(&[("alias.lan", "slow-0.example")])),
    );
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let changing = {
        let pipeline = Arc::clone(&server.pipeline);
        let done = Arc::clone(&done);
        tokio::spawn(async move {
            for round in 1.. {
                tokio::time::sleep(SLOW / 6).await;
                if done.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }

                let target = format!("slow-{round}.example");
                drop(pipeline.replace_rewrites(table(&[("alias.lan", &target)])));
            }
        })
    };

    let started = Instant::now();
    let (reply, result) = finish_tcp(&server, waiting).await;
    let took = started.elapsed();
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    changing.await.unwrap();

    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(result, QueryResult::Error);
    assert!(took < Duration::from_millis(3000), "{took:?}");
    let slow_lookups = asked_names(&upstream)
        .iter()
        .filter(|name| name.starts_with("slow"))
        .count();
    assert_eq!(slow_lookups, 3, "{:?}", asked_names(&upstream));
}

#[tokio::test]
async fn a_query_that_got_no_answer_is_answered_by_a_rewrite_added_since() {
    let upstream = scripted_upstream().await;
    let server = start_with(&upstream, &[], false, engine_of(&[], &[]), |config| {
        config.upstream.timeout_ms = 300;
    })
    .await;
    let failed = prepare_tcp(&server, "silent.example.", RecordType::A).await;
    let (reply, result) = finish_tcp(&server, failed).await;
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(result, QueryResult::Error);

    let failed = prepare_tcp(&server, "silent.example.", RecordType::A).await;
    drop(
        server
            .pipeline
            .replace_rewrites(table(&[("silent.example", "10.0.0.9")])),
    );
    let (reply, result) = finish_tcp(&server, failed).await;

    assert_eq!(values(&reply), ["10.0.0.9"]);
    assert_eq!(result, QueryResult::Rewritten);
}
