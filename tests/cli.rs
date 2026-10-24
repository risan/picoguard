use std::path::PathBuf;
use std::process::{Command, Output};

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

#[test]
fn running_with_a_good_config_logs_one_info_line_and_exits_zero() {
    let path = write_config("info-level.toml", "[log]\nlevel = \"info\"\n");

    let output = picoguard(&["-c", path.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(0));
    let stderr = text(&output.stderr);
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.starts_with("INFO "), "{stderr}");
}

#[test]
fn running_at_the_default_log_level_prints_nothing() {
    let output = picoguard(&["-c", &example_config()]);

    assert_eq!(output.status.code(), Some(0));
    assert!(text(&output.stderr).is_empty());
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
