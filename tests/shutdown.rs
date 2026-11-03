//! SIGTERM and SIGINT against the built binary: the refresh in progress finishes and its
//! snapshot is written, then the process exits with code 0.

mod common;

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::harness::{a_record, answering_upstream, fake_upstream, name, reply_to};
use common::http::ListServer;
use common::process::{Running, exit_within, send_signal, start};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::RecordType;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

/// Kills and reaps the server when a failed assertion ends the test early.
struct Reaped(Running);

impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.child.kill();
        let _ = self.0.child.wait();
    }
}

/// The server's log lines as they come. The reader thread keeps the pipe drained until the
/// server exits, so a log write never meets a closed pipe.
struct LogLines(UnboundedReceiver<String>);

impl LogLines {
    fn watch(child: &mut Child) -> LogLines {
        let stderr = child.stderr.take().unwrap();
        let (sender, receiver) = unbounded_channel();

        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = sender.send(line);
            }
        });

        LogLines(receiver)
    }

    /// Reads lines until `wanted` comes. The line shows that the server got past that point.
    async fn until(&mut self, wanted: &str) {
        let reading = async {
            while let Some(line) = self.0.recv().await {
                if line == wanted {
                    return;
                }
            }

            panic!("the server stopped logging before {wanted:?}");
        };

        tokio::time::timeout(Duration::from_secs(10), reading)
            .await
            .unwrap_or_else(|_| panic!("no log line {wanted:?}"));
    }

    /// Every line from now until the server has exited and its pipe is empty.
    async fn rest(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        let reading = async {
            while let Some(line) = self.0.recv().await {
                lines.push(line);
            }
        };

        tokio::time::timeout(Duration::from_secs(5), reading)
            .await
            .expect("the log never ended");

        lines
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
         [state]\ndir = {:?}\n[log]\nlevel = \"info\"\n",
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
async fn sigterm_lets_the_refresh_in_progress_finish_and_more_signals_change_nothing() {
    let state = StateDir::new("refreshing");
    let list_server = ListServer::start().await;
    list_server.serve("/l.txt", LIST, Some("\"v1\""));
    list_server.set_delay(Duration::from_millis(800));
    let url = list_server.url("/l.txt");
    let list = format!("[[lists]]\nurl = {url:?}\nformat = \"adblock\"\n");
    let mut server = Reaped(start("shutdown-refreshing.toml", |port| {
        config(port, &state, &list)
    }));
    let mut log = LogLines::watch(&mut server.0.child);

    // The download is under way: the server has the request and is holding the answer.
    while list_server.requests() == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    send_signal(&server.0.child, "TERM");
    log.until("INFO stopping").await;
    // The server is now waiting for the refresh. Neither signal may cut that short or kill it.
    send_signal(&server.0.child, "TERM");
    send_signal(&server.0.child, "INT");

    let status = exit_within(&mut server.0.child, Duration::from_secs(15)).await;
    assert_eq!(status.and_then(|status| status.code()), Some(0));
    assert_eq!(
        state.snapshots(),
        1,
        "the list that was downloading was saved"
    );
    assert_eq!(list_server.requests(), 1);
    let rest = log.rest().await;
    assert!(!rest.contains(&"INFO stopping".to_string()), "{rest:?}");
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

/// The shutdown allowance in `main.rs` (`SHUTDOWN_WAIT`) is 10 seconds. One run waits it
/// out, so everything that needs a stalled download at stop is checked in it.
#[tokio::test]
async fn sigterm_exits_within_the_allowance_while_a_download_stalls_keeping_the_snapshot_and_saving_the_statistics()
 {
    let state = StateDir::new("stalled-download");
    let list_server = ListServer::start().await;
    list_server.serve("/l.txt", LIST, Some("\"v1\""));
    let url = list_server.url("/l.txt");
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let config_with = |port: u16, format: &str| {
        format!(
            "[[lists]]\nurl = {url:?}\nformat = {format:?}\n\
             [server]\nbind = [\"127.0.0.1\"]\nport = {port}\n\
             [upstream]\nservers = [\"udp://{}\"]\n\
             [web]\nenabled = false\n[state]\ndir = {:?}\n",
            upstream.address, state.0
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
    let mut log = LogLines::watch(&mut server.0.child);
    let deadline = Instant::now() + Duration::from_secs(10);
    while list_server.requests() == requests {
        assert!(
            server.0.child.try_wait().unwrap().is_none(),
            "the server exited before it asked for the list"
        );
        assert!(Instant::now() < deadline, "the list was never asked for");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    ask_udp(server.0.port, "one.example.").await;
    ask_udp(server.0.port, "two.example.").await;

    send_signal(&server.0.child, "TERM");
    let stopping = Instant::now();

    let status = exit_within(&mut server.0.child, Duration::from_secs(15)).await;
    assert_eq!(status.and_then(|status| status.code()), Some(0));
    assert!(
        stopping.elapsed() < Duration::from_secs(10),
        "{:?}",
        stopping.elapsed()
    );
    assert_eq!(state.snapshot_files(), last_good);
    let saved: serde_json::Value =
        serde_json::from_slice(&fs::read(state.0.join("stats.json")).unwrap()).unwrap();
    assert!(saved["counters"]["total"].as_u64().unwrap() >= 2, "{saved}");
    assert!(!state.0.join("stats.json.part").exists());
    let rest = log.rest().await;
    assert!(
        rest.contains(&"WARN the list refresh did not finish in time, stopping it".to_string()),
        "{rest:?}"
    );
}

#[tokio::test]
async fn a_statistics_save_that_fails_at_stop_still_exits_with_code_zero() {
    let state = StateDir::new("stats-fail");
    fs::create_dir(state.0.join("stats.json")).unwrap();
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut server = Reaped(start("shutdown-stats-fail.toml", |port| {
        format!(
            "lists = []\n[server]\nbind = [\"127.0.0.1\"]\nport = {port}\n\
             [upstream]\nservers = [\"udp://{}\"]\n\
             [web]\nenabled = false\n[state]\ndir = {:?}\n",
            upstream.address, state.0
        )
    }));
    let mut log = LogLines::watch(&mut server.0.child);
    ask_udp(server.0.port, "one.example.").await;

    send_signal(&server.0.child, "TERM");

    let status = exit_within(&mut server.0.child, Duration::from_secs(15)).await;
    assert_eq!(status.and_then(|status| status.code()), Some(0));
    assert!(state.0.join("stats.json").is_dir());
    assert!(!state.0.join("stats.json.part").exists());
    let rest = log.rest().await;
    assert!(
        rest.iter()
            .any(|line| line.starts_with("WARN cannot save the statistics")),
        "{rest:?}"
    );
}

#[tokio::test]
async fn a_state_dir_that_is_a_file_does_not_stop_the_server_from_exiting_with_code_zero() {
    let state = StateDir::new("state-is-a-file");
    let file = state.0.join("not-a-dir");
    fs::write(&file, "x").unwrap();
    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let mut server = Reaped(start("shutdown-state-file.toml", |port| {
        format!(
            "lists = []\n[server]\nbind = [\"127.0.0.1\"]\nport = {port}\n\
             [upstream]\nservers = [\"udp://{}\"]\n\
             [web]\nenabled = false\n[state]\ndir = {file:?}\n",
            upstream.address
        )
    }));
    ask_udp(server.0.port, "one.example.").await;

    send_signal(&server.0.child, "TERM");

    let status = exit_within(&mut server.0.child, Duration::from_secs(15)).await;
    assert_eq!(status.and_then(|status| status.code()), Some(0));
    assert_eq!(fs::read(&file).unwrap(), b"x");
}
