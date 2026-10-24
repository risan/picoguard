//! A failing upstream must not write a log line per failed query (plan D19: SD card).
//! This file has its own test binary because it installs the logger.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::harness::{a_record, config_for, fake_upstream, name, reply_to};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::RecordType;
use picoguard::dns::build::Protocol;
use picoguard::pipeline::Pipeline;
use picoguard::policy::Policy;

static LINES: Mutex<Vec<(log::Level, String)>> = Mutex::new(Vec::new());

struct Capture;

impl log::Log for Capture {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &log::Record) {
        LINES
            .lock()
            .unwrap()
            .push((record.level(), record.args().to_string()));
    }

    fn flush(&self) {}
}

fn query_for(text: &str) -> Vec<u8> {
    let mut message = Message::query();
    message.add_query(Query::query(name(text), RecordType::A));

    message.to_vec().unwrap()
}

/// Every other query gets no answer, so the upstream fails and works again and again: one
/// log line per failure would repeat for as long as this goes on.
#[tokio::test]
async fn an_upstream_that_fails_by_turns_logs_one_warning() {
    log::set_logger(&Capture).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    let received = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&received);
    let upstream = fake_upstream(move |query| {
        if counter.fetch_add(1, Ordering::SeqCst).is_multiple_of(2) {
            return Vec::new();
        }

        let owner = query.queries[0].name().to_string();

        vec![(
            Duration::ZERO,
            reply_to(query, vec![a_record(&owner, 300, [9, 9, 9, 9])]),
        )]
    })
    .await;
    let mut config = config_for(&upstream);
    config.upstream.timeout_ms = 30;
    let pipeline = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();
    let mut failures = 0;

    for index in 0..40 {
        let mut out = Vec::new();
        let request = query_for(&format!("name{index}.example."));
        assert!(
            pipeline
                .answer(
                    request,
                    Protocol::Udp,
                    "127.0.0.1".parse().unwrap(),
                    &mut out
                )
                .await
        );

        if out[3] & 0x0F == 2 {
            failures += 1;
        }
    }

    let lines = LINES.lock().unwrap();
    let warnings = lines
        .iter()
        .filter(|(level, line)| *level == log::Level::Warn && line.contains("failed"))
        .count();
    assert!(
        received.load(Ordering::SeqCst) > failures + 5,
        "the upstream answered some queries and dropped others"
    );
    assert_eq!(warnings, 1, "{lines:?}");
}
