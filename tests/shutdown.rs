//! SIGTERM and SIGINT against the built binary: the refresh in progress finishes and its
//! snapshot is written, then the process exits with code 0.

mod common;

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use common::http::ListServer;
use common::process::{exit_within, send_signal, start};

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
