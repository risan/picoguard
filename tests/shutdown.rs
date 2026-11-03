//! SIGTERM and SIGINT against the built binary: the refresh in progress finishes and its
//! snapshot is written, then the process exits with code 0.

mod common;

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::harness::{a_record, answering_upstream, fake_upstream, name, reply_to};
use common::http::ListServer;
use common::process::{Running, exit_within, send_signal, start};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::RecordType;
use tokio::net::UdpSocket;

/// Kills and reaps the server when a failed assertion ends the test early.
struct Reaped(Running);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.child.kill();
        let _ = self.0.child.wait();
    }
}

const LIST: &str = "||ads.example^\n";

struct StateDir(PathBuf);

impl StateDir {
    fn new(name: &str) -> StateDir {
        let path =
            std::env::temp_dir().join(format!("picoguard-shutdown-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();

        StateDir(path)
    }

    fn snapshots(&self) -> usize {
        fs::read_dir(self.0.join("lists")).map_or(0, |entries| entries.count())
    }

    /// Every file under `lists/`, by name, with its bytes.
    fn snapshot_files(&self) -> Vec<(String, Vec<u8>)> {
        let mut files: Vec<_> = fs::read_dir(self.0.join("lists"))
            .map(|entries| {
                entries
                    .map(|entry| {
                        let entry = entry.unwrap();

                        (
                            entry.file_name().to_string_lossy().to_string(),
                            fs::read(entry.path()).unwrap(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        files.sort();

        files
    }
}

impl Drop for StateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn config(port: u16, state: &StateDir, lists: &str) -> String {
    format!(
        "{lists}\n[server]\nbind = [\"127.0.0.1\"]\nport = {port}\n\
         [upstream]\nservers = [\"udp://127.0.0.1:9\"]\n\
         [state]\ndir = {:?}\n",
        state.0
    )
}

#[tokio::test]
async fn sigterm_and_sigint_stop_an_idle_server_with_exit_code_zero() {
    for signal in ["TERM", "INT"] {
        let state = StateDir::new(&format!("idle-{signal}"));
        let mut server = start(&format!("shutdown-idle-{signal}.toml"), |port| {
            config(port, &state, "lists = []")
        });

        send_signal(&server.child, signal);

        let status = exit_within(&mut server.child, Duration::from_secs(10)).await;
        assert_eq!(status.and_then(|status| status.code()), Some(0), "{signal}");
    }
}

#[tokio::test]
async fn sigterm_lets_the_refresh_in_progress_finish_and_save_its_list() {
    let state = StateDir::new("refreshing");
    let list_server = ListServer::start().await;
    list_server.serve("/l.txt", LIST, Some("\"v1\""));
    list_server.set_delay(Duration::from_millis(800));
    let url = list_server.url("/l.txt");
    let list = format!("[[lists]]\nurl = {url:?}\nformat = \"adblock\"\n");
    let mut server = start("shutdown-refreshing.toml", |port| {
        config(port, &state, &list)
    });

    // The download is under way: the server has the request and is holding the answer.
    while list_server.requests() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    send_signal(&server.child, "TERM");

    let status = exit_within(&mut server.child, Duration::from_secs(15)).await;
    assert_eq!(status.and_then(|status| status.code()), Some(0));
    assert_eq!(
        state.snapshots(),
        1,
        "the list that was downloading was saved"
    );
    assert_eq!(list_server.requests(), 1);
}

/// Sends one A query for `text` to the server on `port` and waits for the reply.
async fn ask_udp(port: u16, text: &str) -> Message {
    let mut query = Message::query();
    query.metadata.id = 0x3333;
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(name(text), RecordType::A));
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&query.to_vec().unwrap(), ("127.0.0.1", port))
        .await
        .unwrap();
    let mut buffer = [0u8; 512];
    let (length, _) = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buffer))
        .await
        .unwrap_or_else(|_| panic!("no reply to {text}"))
        .unwrap();

    Message::from_vec(&buffer[..length]).unwrap()
}

#[tokio::test]
async fn sigterm_stops_at_once_while_a_refresh_waits_on_a_silent_upstream() {
    let state = StateDir::new("stale-refresh");
    let calls = AtomicUsize::new(0);
    let upstream = fake_upstream(move |query| {
        if calls.fetch_add(1, Ordering::SeqCst) > 0 {
            return Vec::new();
        }

        let owner = query.queries[0].name().to_string();

        vec![(
            Duration::ZERO,
            reply_to(query, vec![a_record(&owner, 1, [192, 0, 2, 1])]),
        )]
    })
    .await;
    // `[web] enabled = false` keeps this server off port 8080, which the others here use.
    let mut server = start("shutdown-stale-refresh.toml", |port| {
        format!(
            "lists = []\n[server]\nbind = [\"127.0.0.1\"]\nport = {port}\n\
             [upstream]\nservers = [\"udp://{}\"]\ntimeout_ms = 20000\n\
             [web]\nenabled = false\n[state]\ndir = {:?}\n",
            upstream.address, state.0
        )
    });

    ask_udp(server.port, "stale.example.").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let reply = ask_udp(server.port, "stale.example.").await;
    assert_eq!(reply.answers.len(), 1);

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while upstream.count() < 2 {
        if std::time::Instant::now() >= deadline {
            // A child left running would hold the test's output open.
            let _ = server.child.kill();
            let _ = server.child.wait();
            panic!("the refresh never reached the upstream");
        }

        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    send_signal(&server.child, "TERM");

    let status = exit_within(&mut server.child, Duration::from_secs(5)).await;
    assert_eq!(status.and_then(|status| status.code()), Some(0));
}

/// The shutdown allowance in `main.rs` (`SHUTDOWN_WAIT`) is 10 seconds.
#[tokio::test]
async fn sigterm_exits_within_the_allowance_while_a_download_stalls_and_keeps_the_last_snapshot() {
    let state = StateDir::new("stalled-download");
    let list_server = ListServer::start().await;
    list_server.serve("/l.txt", LIST, Some("\"v1\""));
    let url = list_server.url("/l.txt");
    let config_with = |port: u16, format: &str| {
        format!(
            "[[lists]]\nurl = {url:?}\nformat = {format:?}\n\
             [server]\nbind = [\"127.0.0.1\"]\nport = {port}\n\
             [upstream]\nservers = [\"udp://127.0.0.1:9\"]\n\
             [web]\nenabled = false\n[state]\ndir = {:?}\n",
            state.0
        )
    };
    {
        let mut server = start("shutdown-stalled-first.toml", |port| {
            config_with(port, "adblock")
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        while state.snapshots() == 0 {
            assert!(Instant::now() < deadline, "the first snapshot never came");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        send_signal(&server.child, "TERM");

        let status = exit_within(&mut server.child, Duration::from_secs(15)).await;
        assert_eq!(status.and_then(|status| status.code()), Some(0));
    }

    let last_good = state.snapshot_files();
    assert_eq!(last_good.len(), 1);
    // The snapshot no longer fits the config, so the list is downloaded at once, and the
    // download never answers.
    list_server.set_delay(Duration::from_secs(120));
    let requests = list_server.requests();
    let mut server = Reaped(start("shutdown-stalled-second.toml", |port| {
        config_with(port, "hosts")
    }));
    let deadline = Instant::now() + Duration::from_secs(10);
    while list_server.requests() == requests {
        assert!(
            server.0.child.try_wait().unwrap().is_none(),
            "the server exited before it asked for the list"
        );
        assert!(Instant::now() < deadline, "the list was never asked for");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    send_signal(&server.0.child, "TERM");
    let stopping = Instant::now();

    let status = exit_within(&mut server.0.child, Duration::from_secs(15)).await;
    assert_eq!(status.and_then(|status| status.code()), Some(0));
    assert!(
        stopping.elapsed() < Duration::from_secs(13),
        "{:?}",
        stopping.elapsed()
    );
    assert_eq!(state.snapshot_files(), last_good);
}

#[tokio::test]
async fn sigterm_saves_the_statistics_within_the_allowance_while_a_download_stalls() {
    let state = StateDir::new("stalled-stats");
    let list_server = ListServer::start().await;
    list_server.serve("/l.txt", LIST, Some("\"v1\""));
    list_server.set_delay(Duration::from_secs(120));
    let url = list_server.url("/l.txt");
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut server = Reaped(start("shutdown-stalled-stats.toml", |port| {
        format!(
            "[[lists]]\nurl = {url:?}\nformat = \"adblock\"\n\
             [server]\nbind = [\"127.0.0.1\"]\nport = {port}\n\
             [upstream]\nservers = [\"udp://{}\"]\n\
             [web]\nenabled = false\n[state]\ndir = {:?}\n",
            upstream.address, state.0
        )
    }));
    let deadline = Instant::now() + Duration::from_secs(10);
    while list_server.requests() == 0 {
        assert!(Instant::now() < deadline, "the list was never asked for");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    ask_udp(server.0.port, "one.example.").await;
    ask_udp(server.0.port, "two.example.").await;
    assert!(!state.0.join("stats.json").exists());

    send_signal(&server.0.child, "TERM");
    let stopping = Instant::now();

    let status = exit_within(&mut server.0.child, Duration::from_secs(15)).await;
    assert_eq!(status.and_then(|status| status.code()), Some(0));
    assert!(
        stopping.elapsed() < Duration::from_secs(10),
        "{:?}",
        stopping.elapsed()
    );
    let saved: serde_json::Value =
        serde_json::from_slice(&fs::read(state.0.join("stats.json")).unwrap()).unwrap();
    assert!(saved["counters"]["total"].as_u64().unwrap() >= 2, "{saved}");
    assert!(!state.0.join("stats.json.part").exists());
}
