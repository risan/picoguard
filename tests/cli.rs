mod common;

use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::process::{Command, Output, Stdio};
use std::str::FromStr;
use std::time::{Duration, Instant};

use common::process::{start, write_config};
use picoguard::password::PasswordHash;
use regex::Regex;

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

const HASH: &str = "pbkdf2-sha256$1000$000102030405060708090a0b0c0d0e0f$33a78c377ca7b6590fa1b215cc970fba516076f108ecb68af58ec95d86021701";

#[test]
fn check_rejects_a_password_and_a_password_hash_together() {
    let path = write_config(
        "password-and-hash.toml",
        &format!("[web]\nuser = \"admin\"\npassword = \"s3cret\"\npassword_hash = \"{HASH}\"\n"),
    );

    let output = picoguard(&["--check", "-c", path.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        text(&output.stderr).contains("not both"),
        "{}",
        text(&output.stderr)
    );
}

#[test]
fn check_rejects_a_malformed_password_hash() {
    let path = write_config(
        "malformed-hash.toml",
        "[web]\nuser = \"admin\"\npassword_hash = \"pbkdf2-sha256$1000$00$00\"\n",
    );

    let output = picoguard(&["--check", "-c", path.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        text(&output.stderr).contains("password_hash"),
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
    for option in [
        "--config",
        "--check",
        "--version",
        "--help",
        "--hash-password",
        "dns-check",
    ] {
        assert!(stdout.contains(option), "{stdout}");
    }
}

fn hash_password_with(input: &str, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_picoguard"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("picoguard binary should start");
    // A usage error exits before it reads, which closes the pipe under this write.
    let _ = child.stdin.take().unwrap().write_all(input.as_bytes());

    child.wait_with_output().unwrap()
}

#[test]
fn hash_password_prints_one_config_line_that_verifies() {
    let line =
        Regex::new(r#"^password_hash = "(pbkdf2-sha256\$600000\$[0-9a-f]{32}\$[0-9a-f]{64})"\n$"#)
            .unwrap();
    let mut hashes = Vec::new();

    for _ in 0..2 {
        let output = hash_password_with("pw\n", &["--hash-password"]);

        assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
        let stdout = text(&output.stdout);
        let captures = line.captures(&stdout).expect(&stdout);
        let hash = PasswordHash::from_str(&captures[1]).unwrap();
        assert!(hash.verify(b"pw"));
        assert!(!hash.verify(b"px"));
        hashes.push(hash);
    }

    assert_ne!(hashes[0], hashes[1]);
}

#[test]
fn hash_password_refuses_an_empty_password() {
    let output = hash_password_with("\n", &["--hash-password"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stdout).is_empty());
    assert!(
        text(&output.stderr).contains("must not be empty"),
        "{}",
        text(&output.stderr)
    );
}

#[test]
fn hash_password_with_an_argument_is_a_usage_error() {
    let output = hash_password_with("pw\n", &["--hash-password", "pw"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(text(&output.stdout).is_empty());
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

#[test]
fn verify_update_needs_two_directories() {
    let scratch =
        std::env::temp_dir().join(format!("picoguard-verify-args-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir(&scratch).unwrap();
    let staged = scratch.join("staged");
    let into = scratch.join("into");
    let (staged, into) = (staged.to_str().unwrap(), into.to_str().unwrap());

    for args in [
        vec!["verify-update"],
        vec!["verify-update", staged],
        vec!["verify-update", staged, into, "extra"],
    ] {
        let output = picoguard(&args);

        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(text(&output.stderr).contains("verify-update"), "{args:?}");
        assert!(text(&output.stdout).is_empty(), "{args:?}");
    }

    assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn verify_update_refuses_what_the_built_in_key_did_not_sign() {
    let root = common::release::scratch("cli-verify-update");
    let staged =
        common::release::stage_dir(&root, "9.9.9", &common::release::script("9.9.9"), |_| {});
    let into = root.join("into");

    let output = picoguard(&[
        "verify-update",
        staged.to_str().unwrap(),
        into.to_str().unwrap(),
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(text(&output.stderr).trim().lines().count(), 1);
    assert!(!into.exists());
}

const QR: u8 = 0x80;
const NOERROR: u8 = 0;
const NXDOMAIN: u8 = 3;
const SERVFAIL: u8 = 2;
const REFUSED: u8 = 5;

/// A reply to `query`: the same id and question, QR set, and `rcode`.
fn reply_to(query: &[u8], rcode: u8) -> Vec<u8> {
    let mut reply = query.to_vec();
    reply[2] |= QR;
    reply[3] = (reply[3] & 0xF0) | rcode;

    reply
}

fn with_another_id(mut reply: Vec<u8>) -> Vec<u8> {
    reply[0] ^= 0xFF;

    reply
}

fn with_another_question(mut reply: Vec<u8>) -> Vec<u8> {
    let at = reply
        .windows(3)
        .position(|window| window == b"com")
        .expect("the query names example.com");
    reply[at..at + 3].copy_from_slice(b"org");

    reply
}

/// Binds `bind`, answers the first datagram with every datagram `replies` makes of it, in
/// order, and returns the address. The thread ends after that one query.
fn responder(
    bind: &str,
    replies: impl FnOnce(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
) -> Option<SocketAddr> {
    let socket = UdpSocket::bind(bind).ok()?;
    let address = socket.local_addr().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    std::thread::spawn(move || {
        let mut query = [0u8; 512];

        if let Ok((length, peer)) = socket.recv_from(&mut query) {
            for reply in replies(&query[..length]) {
                socket.send_to(&reply, peer).unwrap();
            }
        }
    });

    Some(address)
}

fn dns_check(address: SocketAddr) -> Output {
    picoguard(&[
        "dns-check",
        &address.ip().to_string(),
        &address.port().to_string(),
    ])
}

#[test]
fn dns_check_accepts_noerror_and_nxdomain() {
    for rcode in [NOERROR, NXDOMAIN] {
        let address = responder("127.0.0.1:0", move |query| vec![reply_to(query, rcode)]).unwrap();

        let output = dns_check(address);

        assert_eq!(output.status.code(), Some(0), "rcode {rcode}");
        assert!(text(&output.stderr).is_empty(), "{}", text(&output.stderr));
    }
}

#[test]
fn dns_check_refuses_servfail_refused_and_another_question() {
    type MakeReply = fn(&[u8]) -> Vec<u8>;
    let cases: [(&str, MakeReply); 3] = [
        ("SERVFAIL", |query| reply_to(query, SERVFAIL)),
        ("REFUSED", |query| reply_to(query, REFUSED)),
        ("question", |query| {
            with_another_question(reply_to(query, NOERROR))
        }),
    ];

    for (name, make) in cases {
        let address = responder("127.0.0.1:0", move |query| vec![make(query)]).unwrap();

        let output = dns_check(address);

        assert_eq!(output.status.code(), Some(1), "{name}");
        assert_eq!(text(&output.stderr).trim().lines().count(), 1, "{name}");
        assert!(
            text(&output.stderr).contains(name),
            "{name}: {}",
            text(&output.stderr)
        );
    }
}

#[test]
fn dns_check_skips_another_id_and_takes_the_right_one() {
    let address = responder("127.0.0.1:0", |query| {
        vec![
            with_another_id(reply_to(query, SERVFAIL)),
            reply_to(query, NOERROR),
        ]
    })
    .unwrap();

    assert_eq!(dns_check(address).status.code(), Some(0));
}

#[test]
fn dns_check_gives_up_when_only_another_id_answers() {
    let address = responder("127.0.0.1:0", |query| {
        vec![with_another_id(reply_to(query, NOERROR))]
    })
    .unwrap();
    let started = Instant::now();

    let output = dns_check(address);

    assert_eq!(output.status.code(), Some(1));
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(text(&output.stderr).trim().lines().count(), 1);
}

#[test]
fn dns_check_gives_up_on_silence() {
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    let started = Instant::now();

    let output = dns_check(silent.local_addr().unwrap());

    assert_eq!(output.status.code(), Some(1));
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(text(&output.stderr).trim().lines().count(), 1);
}

#[test]
fn dns_check_needs_an_address_and_a_port() {
    for args in [
        vec!["dns-check"],
        vec!["dns-check", "127.0.0.1"],
        vec!["dns-check", "127.0.0.1", "53", "extra"],
        vec!["dns-check", "x", "53"],
        vec!["dns-check", "127.0.0.1", "0"],
        vec!["dns-check", "127.0.0.1", "70000"],
    ] {
        let output = picoguard(&args);

        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(text(&output.stderr).contains("dns-check"), "{args:?}");
        assert!(text(&output.stdout).is_empty(), "{args:?}");
    }
}

#[test]
fn dns_check_asks_a_running_picoguard() {
    let mut server = start("dns-check-running.toml", |port| {
        format!(
            "lists = []\nrules = [\"127.0.0.1 example.com\"]\n\
             [server]\nbind = [\"127.0.0.1\"]\nport = {port}\n\
             [upstream]\nservers = [\"udp://127.0.0.1:9\"]\n\
             [web]\nenabled = false\n"
        )
    });

    let output = picoguard(&["dns-check", "127.0.0.1", &server.port.to_string()]);
    server.child.kill().unwrap();
    server.child.wait().unwrap();

    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
}

#[test]
fn dns_check_over_ipv6_loopback() {
    let Some(address) = responder("[::1]:0", |query| vec![reply_to(query, NOERROR)]) else {
        eprintln!("skipped: ::1 cannot be bound here");

        return;
    };

    assert_eq!(dns_check(address).status.code(), Some(0));
}
