//! Background refreshes that fail must not write a log line per query (SD card).
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

const NAMES: usize = 20;

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

async fn answer_all(pipeline: &Arc<Pipeline>, names: &[String]) {
    for text in names {
        let mut out = Vec::new();
        let request = query_for(text);

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
        assert_eq!(out[3] & 0x0F, 0, "{text} was answered");
    }
}

/// Every name is answered once with TTL 1; then the upstream goes silent, so every stale
/// answer starts a refresh that fails.
#[tokio::test]
async fn failing_refreshes_log_no_line_per_query() {
    log::set_logger(&Capture).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    let received = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&received);
    let upstream = fake_upstream(move |query| {
        if counter.fetch_add(1, Ordering::SeqCst) >= NAMES {
            return Vec::new();
        }

        let owner = query.queries[0].name().to_string();

        vec![(
            Duration::ZERO,
            reply_to(query, vec![a_record(&owner, 1, [192, 0, 2, 1])]),
        )]
    })
    .await;
    let mut config = config_for(&upstream);
    config.upstream.timeout_ms = 250;
    let pipeline = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();
    let names: Vec<String> = (0..NAMES)
        .map(|index| format!("refresh{index}.example."))
        .collect();

    answer_all(&pipeline, &names).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    answer_all(&pipeline, &names).await;
    tokio::time::sleep(Duration::from_millis(600)).await;

    assert!(
        received.load(Ordering::SeqCst) > NAMES,
        "the stale answers started refreshes"
    );

    let lines = LINES.lock().unwrap();
    let warnings = lines
        .iter()
        .filter(|(level, line)| *level == log::Level::Warn && line.contains("failed"))
        .count();
    assert!(warnings <= 1, "{lines:?}");

    let bare_names: Vec<&str> = names
        .iter()
        .map(|text| text.trim_end_matches('.'))
        .collect();
    for (_, line) in lines.iter() {
        assert!(!bare_names.iter().any(|bare| line.contains(bare)), "{line}");
    }
}
