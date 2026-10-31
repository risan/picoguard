//! Device-name lookups that fail must not write a log line per lookup (SD card).
//! This file has its own test binary because it installs the logger.

mod common;

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::harness::{config_for, fake_upstream};
use picoguard::pipeline::{Pipeline, ServerKind};
use picoguard::policy::Policy;

const CLIENTS: [&str; 4] = ["192.168.1.21", "192.168.1.22", "10.0.0.23", "fd00::24"];
const REVERSE_NAMES: [&str; 4] = [
    "21.1.168.192.in-addr.arpa",
    "22.1.168.192.in-addr.arpa",
    "23.0.0.10.in-addr.arpa",
    "4.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa",
];

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

fn local_failures(pipeline: &Pipeline) -> u64 {
    pipeline
        .upstream_tallies()
        .into_iter()
        .find(|server| server.kind == ServerKind::Local)
        .unwrap()
        .tally
        .failed
}

#[tokio::test]
async fn failing_device_name_lookups_log_no_line_per_lookup() {
    log::set_logger(&Capture).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    let router = fake_upstream(|_| Vec::new()).await;
    let mut config = config_for(&router);
    config.upstream.servers = vec!["udp://127.0.0.1:9".to_string()];
    config.local.resolver = Some(router.address);
    let pipeline = Pipeline::new(&config, Arc::new(Policy::new())).unwrap();

    for client in CLIENTS {
        let address: IpAddr = client.parse().unwrap();
        assert_eq!(pipeline.device_name(address), None);
    }

    let started = Instant::now();
    while local_failures(&pipeline) < 8 {
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "the lookups did not fail twice each"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_eq!(router.count(), 8);

    let lines = LINES.lock().unwrap();
    let warnings = lines
        .iter()
        .filter(|(level, line)| *level == log::Level::Warn && line.contains("failed"))
        .count();
    assert!(warnings <= 1, "{lines:?}");

    for (_, line) in lines.iter() {
        for named in CLIENTS.iter().chain(&REVERSE_NAMES) {
            assert!(!line.contains(named), "{line}");
        }
    }
}
