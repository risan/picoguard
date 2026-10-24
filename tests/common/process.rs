//! Runs the built `picoguard` binary on a free UDP/TCP port of 127.0.0.1.

use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const ATTEMPTS: usize = 5;

/// Tests of one binary run in parallel threads. Only one at a time picks a port and waits
/// for its server to bind it, so two of them never pick the same port.
static STARTING: Mutex<()> = Mutex::new(());

pub struct Running {
    pub child: Child,
    pub port: u16,
}

pub fn write_config(name: &str, content: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("picoguard-cli-{}-{name}", std::process::id()));
    std::fs::write(&path, content).unwrap();

    path
}

/// Starts the binary with the config `config_for(port)` and returns once it answers on
/// `port`. The port is picked free; if another process takes it first the server exits
/// and the start is tried again with another port.
pub fn start(name: &str, config_for: impl Fn(u16) -> String) -> Running {
    let _starting = STARTING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    for _ in 0..ATTEMPTS {
        let port = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let path = write_config(name, &config_for(port));
        let mut child = Command::new(env!("CARGO_BIN_EXE_picoguard"))
            .args(["-c", path.to_str().unwrap()])
            .stderr(Stdio::piped())
            .spawn()
            .expect("picoguard binary should start");

        if wait_for_refused_version_bind(port, &mut child) {
            return Running { child, port };
        }

        let _ = child.kill();
        let _ = child.wait();
    }

    panic!("picoguard never answered on a free port");
}

/// `version.bind` is refused without any upstream, which makes it a probe. False when the
/// server exits first or never answers.
fn wait_for_refused_version_bind(port: u16, child: &mut Child) -> bool {
    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(b"\x07version\x04bind\x00");
    query.extend_from_slice(&[0, 16, 0, 3]);
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();

    for _ in 0..50 {
        if child.try_wait().unwrap().is_some() {
            return false;
        }

        socket.send_to(&query, ("127.0.0.1", port)).unwrap();
        let mut reply = [0u8; 512];
        if let Ok((length, _)) = socket.recv_from(&mut reply)
            && length >= 12
        {
            return reply[3] & 0x0F == 5;
        }
    }

    false
}

pub fn send_signal(child: &Child, signal: &str) {
    let status = Command::new("kill")
        .args([format!("-{signal}"), child.id().to_string()])
        .status()
        .unwrap();

    assert!(status.success());
}

/// Polls for the exit of `child` without blocking the thread for long.
pub async fn exit_within(child: &mut Child, limit: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    None
}
