mod common;

use std::net::UdpSocket;
use std::process::{Command, Output};

use common::process::{start, write_config};

fn picoguard(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_picoguard"))
        .args(args)
        .output()
        .expect("picoguard binary should start")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
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
fn check_rejects_an_unknown_update_key() {
    let path = write_config("unknown-update-key.toml", "[update]\nbogus = 1\n");

    let output = picoguard(&["--check", "-c", path.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("bogus"));
}

#[test]
fn check_rejects_an_upstream_that_cannot_be_built() {
    let path = write_config(
        "check-bad-upstream.toml",
        "[upstream]\nservers = [\"https://dns.example/dns-query\"]\nbootstrap = []\n",
    );

    let output = picoguard(&["--check", "-c", path.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("upstream.bootstrap"));
}

#[test]
fn check_accepts_a_host_name_upstream_with_the_default_bootstrap() {
    let path = write_config(
        "check-host-upstream.toml",
        "[upstream]\nservers = [\"https://unfiltered.adguard-dns.com/dns-query\"]\n",
    );

    let output = picoguard(&["--check", "-c", path.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(0));
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
    let mut server = start(name, |port| {
        format!(
            "lists = []\n[server]\nbind = [\"127.0.0.1\"]\nport = {port}\n\
             [upstream]\nservers = [\"udp://127.0.0.1:9\"]\n\
             [web]\nenabled = false\n\
             [log]\nlevel = \"{log_level}\"\n"
        )
    });
    server.child.kill().unwrap();
    let output = server.child.wait_with_output().unwrap();

    (server.port, text(&output.stderr))
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

fn stderr_of_a_run_with_the_status_page(name: &str, credentials: &str) -> String {
    let web_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut server = start(name, |port| {
        format!(
            "lists = []\n[server]\nbind = [\"127.0.0.1\"]\nport = {port}\n\
             [upstream]\nservers = [\"udp://127.0.0.1:9\"]\n\
             [update]\ncheck = false\n\
             [web]\nbind = [\"127.0.0.1\"]\nport = {web_port}\n{credentials}"
        )
    });
    server.child.kill().unwrap();

    text(&server.child.wait_with_output().unwrap().stderr)
}

#[test]
fn running_the_status_page_without_a_password_logs_one_warning() {
    let stderr = stderr_of_a_run_with_the_status_page("web-open.toml", "");

    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.starts_with("WARN "), "{stderr}");
    assert!(stderr.contains("web.password"), "{stderr}");
}

#[test]
fn running_the_status_page_with_a_password_logs_nothing() {
    let stderr = stderr_of_a_run_with_the_status_page(
        "web-password.toml",
        "user = \"admin\"\npassword = \"s3cret\"\n",
    );

    assert!(stderr.is_empty(), "{stderr}");
}

#[test]
fn running_with_a_host_name_upstream_and_no_bootstrap_exits_one() {
    let path = write_config(
        "https-host-upstream.toml",
        "[server]\nbind = [\"127.0.0.1\"]\nport = 0\n\
         [upstream]\nservers = [\"https://dns.example/dns-query\"]\nbootstrap = []\n",
    );

    let output = picoguard(&["-c", path.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("upstream.bootstrap"));
}

#[test]
fn running_with_the_default_encrypted_upstreams_starts() {
    let mut server = start("default-upstreams.toml", |port| {
        format!(
            "lists = []\n[server]\nbind = [\"127.0.0.1\"]\nport = {port}\n\
             [web]\nenabled = false\n"
        )
    });
    server.child.kill().unwrap();
    let output = server.child.wait_with_output().unwrap();

    assert!(text(&output.stderr).is_empty(), "{}", text(&output.stderr));
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
