//! The saved statistics against the built binary: a clean stop writes `stats.json`, the next
//! start reads it back, a file that cannot be used never stops the start, and with
//! `persist = false` the file is neither read nor written.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::harness::{FakeUpstream, answering_upstream, name};
use common::process::{Running, exit_within, send_signal, start_with_web_port};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::RecordType;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// `admin` and `s3cret`.
const ADMIN: &str = "YWRtaW46czNjcmV0";

/// Kills and reaps the server when a failed assertion ends the test early.
struct Daemon {
    running: Running,
    web_port: u16,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.running.child.kill();
        let _ = self.running.child.wait();
    }
}

impl Daemon {
    async fn ask(&self, text: &str) {
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(name(text), RecordType::A));
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(&query.to_vec().unwrap(), ("127.0.0.1", self.running.port))
            .await
            .unwrap();
        let mut buffer = [0u8; 512];

        tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buffer))
            .await
            .unwrap_or_else(|_| panic!("no reply to {text}"))
            .unwrap();
    }

    async fn status(&self) -> serde_json::Value {
        let mut stream = TcpStream::connect(("127.0.0.1", self.web_port))
            .await
            .unwrap();
        let request = format!(
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic {ADMIN}\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        let (head, body) = reply.split_once("\r\n\r\n").expect("a reply with a body");
        assert!(head.starts_with("HTTP/1.1 200"), "{reply}");

        serde_json::from_str(body).unwrap_or_else(|error| panic!("{error}: {reply}"))
    }

    async fn total(&self) -> u64 {
        self.status().await["counters"]["total"].as_u64().unwrap()
    }

    /// A clean stop; the exit code must be 0.
    async fn stop(mut self) {
        send_signal(&self.running.child, "TERM");

        let status = exit_within(&mut self.running.child, Duration::from_secs(15)).await;
        assert_eq!(status.and_then(|status| status.code()), Some(0));
    }
}

struct State(PathBuf);

impl State {
    fn new(label: &str) -> State {
        State(common::release::scratch(label))
    }

    fn stats_file(&self) -> PathBuf {
        self.0.join("stats.json")
    }

    fn saved(&self) -> serde_json::Value {
        serde_json::from_slice(&fs::read(self.stats_file()).unwrap()).unwrap()
    }
}

fn start(label: &str, state: &Path, upstream: &FakeUpstream, persist: bool) -> Daemon {
    let (running, web_port) = start_with_web_port(&format!("{label}.toml"), |port, web_port| {
        format!(
            "lists = []\n\
             [server]\nbind = [\"127.0.0.1\"]\nport = {port}\n\
             [upstream]\nservers = [\"udp://{}\"]\n\
             [update]\ncheck = false\n\
             [web]\nuser = \"admin\"\npassword = \"s3cret\"\nbind = [\"127.0.0.1\"]\nport = {web_port}\n\
             [stats]\npersist = {persist}\n\
             [state]\ndir = {state:?}\n",
            upstream.address
        )
    });

    Daemon { running, web_port }
}

const MINIMAL: &str = r#"{"version":1,"since":1700000000,"counters":{"total":1000,"blocked_request":0,
    "blocked_response":0,"cached":0,"upstream":9,"rewritten":0,"errors":0,"dropped":0},
    "hours":[],"top_queried":[],"top_blocked":[],"top_clients":[],"upstreams":[]}"#;

/// The binary's own start-up probe is counted as a query, so totals are compared with what
/// was read a moment before rather than with fixed numbers.
#[tokio::test]
async fn a_restart_keeps_the_counters_and_the_top_names() {
    let state = State::new("persist-restart");
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let first = start("persist-restart-1", &state.0, &upstream, true);
    first.ask("a.example.").await;
    for _ in 0..5 {
        first.ask("b.example.").await;
    }

    let before = first.status().await;
    assert!(
        !state.stats_file().exists(),
        "nothing is written while it runs"
    );
    first.stop().await;

    let saved = state.saved();
    assert_eq!(saved["version"], 1);
    assert_eq!(saved["counters"], before["counters"]);
    assert!(!state.0.join("stats.json.part").exists());
    let second = start("persist-restart-2", &state.0, &upstream, true);

    let after = second.status().await;
    let total = before["counters"]["total"].as_u64().unwrap();
    assert!(after["counters"]["total"].as_u64().unwrap() >= total);
    assert_eq!(after["top_queried"]["entries"][0]["key"], "b.example");
    assert_eq!(after["top_queried"]["entries"][0]["count"], 5);
    assert_eq!(
        after["upstreams"][0]["answered"],
        before["upstreams"][0]["answered"]
    );
    assert!(before["upstreams"][0]["answered"].as_u64().unwrap() >= 1);
    second.ask("d.example.").await;
    assert!(second.total().await > total);
    second.stop().await;

    assert!(state.saved()["counters"]["total"].as_u64().unwrap() > total);
}

#[tokio::test]
async fn a_file_that_cannot_be_used_starts_with_empty_statistics() {
    let oversized = format!(
        "{{\"version\":1,\"pad\":\"{}\"}}",
        "x".repeat(3 * 1024 * 1024)
    );
    let cases = [
        ("broken", "{\"version\":1,\"counters\":".to_string()),
        ("garbage", "\u{0}\u{1}not json".to_string()),
        (
            "other-version",
            MINIMAL.replace("\"version\":1", "\"version\":2"),
        ),
        ("oversized", oversized),
    ];

    for (label, text) in cases {
        let state = State::new(&format!("persist-bad-{label}"));
        fs::write(state.stats_file(), &text).unwrap();
        let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
        let daemon = start(&format!("persist-bad-{label}"), &state.0, &upstream, true);

        let total = daemon.total().await;
        assert!(total < 100, "{label}: {total}");
        daemon.ask("a.example.").await;
        assert_eq!(daemon.total().await, total + 1, "{label}");
        assert_eq!(
            fs::read_to_string(state.stats_file()).unwrap(),
            text,
            "{label}"
        );
        daemon.stop().await;

        assert_eq!(state.saved()["counters"]["total"], total + 1, "{label}");
    }
}

#[tokio::test]
async fn with_saving_off_the_file_is_neither_read_nor_written() {
    let state = State::new("persist-off");
    fs::write(state.stats_file(), MINIMAL).unwrap();
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let daemon = start("persist-off", &state.0, &upstream, false);

    let total = daemon.total().await;
    assert!(total < 100, "{total}");
    daemon.ask("a.example.").await;
    assert_eq!(daemon.total().await, total + 1);
    daemon.stop().await;

    assert_eq!(fs::read_to_string(state.stats_file()).unwrap(), MINIMAL);
}

#[tokio::test]
async fn the_status_page_shows_the_restored_history() {
    let state = State::new("persist-history");
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let first = start("persist-history-1", &state.0, &upstream, true);
    first.ask("a.example.").await;
    let asked = first.total().await;
    first.stop().await;
    let second = start("persist-history-2", &state.0, &upstream, true);

    let hourly = second.status().await["hourly"].clone();

    let queries: u64 = hourly
        .as_array()
        .unwrap()
        .iter()
        .map(|bucket| bucket["total"].as_u64().unwrap())
        .sum();
    assert!(queries >= asked, "{queries} < {asked}");
}
