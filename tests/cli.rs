use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

fn picoguard(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_picoguard"))
        .args(args)
        .output()
        .expect("picoguard binary should start")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn write_config(name: &str, content: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("picoguard-cli-{}-{name}", std::process::id()));
    std::fs::write(&path, content).unwrap();

    path
}

fn example_config() -> String {
    format!("{}/dist/picoguard.toml", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn check_accepts_the_example_config() {
    let output = picoguard(&["--check", "-c", &example_config()]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(text(&output.stdout).trim(), "OK");
}

#[test]
fn check_accepts_the_long_config_flag_in_any_order() {
    let output = picoguard(&["--config", &example_config(), "--check"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(text(&output.stdout).trim(), "OK");
}

#[test]
fn check_rejects_an_invalid_value_and_names_the_field() {
    let path = write_config("invalid-value.toml", "[cache]\nmax_entries = 0\n");

    let output = picoguard(&["--check", "-c", path.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stdout).is_empty());
    assert!(
        text(&output.stderr).contains("cache.max_entries must be > 0"),
        "{}",
        text(&output.stderr)
    );
}

#[test]
fn check_rejects_an_unknown_key() {
    let path = write_config("unknown-key.toml", "blocked_tll = 5\n");

    let output = picoguard(&["--check", "-c", path.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("blocked_tll"));
}

#[test]
fn check_rejects_a_missing_file() {
    let output = picoguard(&["--check", "-c", "/nonexistent/picoguard.toml"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("/nonexistent/picoguard.toml"));
}

/// Runs the server on a free port until it answers, then stops it and
/// returns what it wrote to stderr.
fn run_until_ready(name: &str, log_level: &str) -> (u16, String) {
    let port = {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap().port()
    };
    let config = format!(
        "[server]\nbind = [\"127.0.0.1\"]\nport = {port}\n\
         [upstream]\nservers = [\"udp://127.0.0.1:9\"]\n\
         [log]\nlevel = \"{log_level}\"\n"
    );
    let path = write_config(name, &config);
    let mut child = Command::new(env!("CARGO_BIN_EXE_picoguard"))
        .args(["-c", path.to_str().unwrap()])
        .stderr(Stdio::piped())
        .spawn()
        .expect("picoguard binary should start");

    let ready = wait_for_refused_version_bind(port);
    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(ready, "the server never answered");

    (port, text(&output.stderr))
}

/// `version.bind` is refused without any upstream, which makes it a probe.
fn wait_for_refused_version_bind(port: u16) -> bool {
    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(b"\x07version\x04bind\x00");
    query.extend_from_slice(&[0, 16, 0, 3]);
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();

    for _ in 0..50 {
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

#[test]
fn running_logs_the_listening_address_at_info_level() {
    let (port, stderr) = run_until_ready("info-level.toml", "info");

    assert!(
        stderr.lines().all(|line| line.starts_with("INFO ")),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!("listening on 127.0.0.1:{port}")),
        "{stderr}"
    );
}

#[test]
fn running_at_the_default_log_level_prints_nothing() {
    let (_, stderr) = run_until_ready("warn-level.toml", "warn");

    assert!(stderr.is_empty(), "{stderr}");
}

#[test]
fn running_with_a_host_name_upstream_and_no_bootstrap_exits_one() {
    let path = write_config(
        "https-host-upstream.toml",
        "[server]\nbind = [\"127.0.0.1\"]\nport = 0\n\
         [upstream]\nservers = [\"https://dns.example/dns-query\"]\n",
    );

    let output = picoguard(&["-c", path.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("upstream.bootstrap"));
}

#[test]
fn running_with_the_default_encrypted_upstreams_starts() {
    let port = {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap().port()
    };
    let config = format!("[server]\nbind = [\"127.0.0.1\"]\nport = {port}\n");
    let path = write_config("default-upstreams.toml", &config);
    let mut child = Command::new(env!("CARGO_BIN_EXE_picoguard"))
        .args(["-c", path.to_str().unwrap()])
        .stderr(Stdio::piped())
        .spawn()
        .expect("picoguard binary should start");

    let ready = wait_for_refused_version_bind(port);
    child.kill().unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(ready, "the server never answered");
    assert!(output.stderr.is_empty(), "{}", text(&output.stderr));
}

#[test]
fn running_with_a_port_in_use_exits_one() {
    let taken = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let config = format!(
        "[server]\nbind = [\"127.0.0.1\"]\nport = {port}\n\
         [upstream]\nservers = [\"udp://127.0.0.1:9\"]\n"
    );
    let path = write_config("port-in-use.toml", &config);

    let output = picoguard(&["-c", path.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains(&format!("127.0.0.1:{port}")));
}

#[test]
fn running_with_a_bad_config_exits_one() {
    let path = write_config("bad-run.toml", "[cache]\nmax_bytes = 0\n");

    let output = picoguard(&["-c", path.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("cache.max_bytes must be > 0"));
}

#[test]
fn version_prints_name_and_version() {
    let output = picoguard(&["--version"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        text(&output.stdout).trim(),
        format!("picoguard {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn help_lists_the_options() {
    let output = picoguard(&["--help"]);

    assert_eq!(output.status.code(), Some(0));
    let stdout = text(&output.stdout);
    for option in ["--config", "--check", "--version", "--help"] {
        assert!(stdout.contains(option), "{stdout}");
    }
}

#[test]
fn unknown_option_is_a_usage_error() {
    let output = picoguard(&["--frobnicate"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(text(&output.stderr).contains("--frobnicate"));
}

#[test]
fn config_flag_without_a_value_is_a_usage_error() {
    let output = picoguard(&["-c"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(text(&output.stderr).contains("-c"));
}
