//! The daily "is there a newer release" check (plan D1-D13). The check asks GitHub for the
//! latest release, keeps only the newest version and a short summary of its notes for the
//! status page, and logs once per change of outcome. A failure never touches DNS, the lists or
//! the page: the last known result stays.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, sleep_until};

use crate::config::Config;
use crate::lists::{Downloader, Fetch, FetchError, Limits, Names, PIECE_QUEUE, Piece, Validators};
use crate::scheduler::{jittered, unit_random};
use crate::stage::InstallView;
use crate::upstream::tls::Tls;

pub const RELEASES_URL: &str = "https://api.github.com/repos/risan/picoguard/releases/latest";

/// The answer of the releases API is about 20 KiB; anything over this is not one.
const MAX_ANSWER_BYTES: u64 = 256 * 1024;

const UPDATE_COMMAND_RELEASE: &str =
    "curl -fsSL https://github.com/risan/picoguard/releases/latest/download/install.sh | sudo sh";
const UPDATE_COMMAND_DOCKER: &str = "git pull && docker compose up -d --build";
const UPDATE_COMMAND_SOURCE: &str = "cargo install --locked picoguard";

const SUMMARY_CHARS: usize = 200;

/// How this binary was built, which decides how it is updated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Build {
    Release,
    Docker,
    Source,
}

impl Build {
    pub fn current() -> Build {
        Build::from_marker(option_env!("PICOGUARD_BUILD"))
    }

    pub fn from_marker(marker: Option<&str>) -> Build {
        match marker {
            Some("release") => Build::Release,
            Some("docker") => Build::Docker,
            _ => Build::Source,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Build::Release => "release",
            Build::Docker => "docker",
            Build::Source => "source",
        }
    }

    pub fn how(self) -> &'static str {
        match self {
            Build::Release => UPDATE_COMMAND_RELEASE,
            Build::Docker => UPDATE_COMMAND_DOCKER,
            Build::Source => UPDATE_COMMAND_SOURCE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    /// The running version carries a `-` suffix such as `-rc.1`.
    pre: bool,
}

impl fmt::Display for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    Release(Version),
    /// A pre-release or build suffix (`-rc.1`, `+meta`): never offered as an update.
    Suffixed,
    Invalid,
}

/// `[v]MAJOR.MINOR.PATCH` and what follows it.
fn split_numbers(text: &str) -> Option<(Version, &str)> {
    let mut rest = text.strip_prefix('v').unwrap_or(text);
    let mut numbers = [0u64; 3];

    for (index, number) in numbers.iter_mut().enumerate() {
        if index > 0 {
            rest = rest.strip_prefix('.')?;
        }

        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        *number = rest[..digits].parse().ok()?;
        rest = &rest[digits..];
    }

    let [major, minor, patch] = numbers;

    Some((
        Version {
            major,
            minor,
            patch,
            pre: false,
        },
        rest,
    ))
}

pub fn parse_tag(text: &str) -> Tag {
    match split_numbers(text) {
        Some((version, "")) => Tag::Release(version),
        Some((_, rest)) if rest.starts_with(['-', '+']) => Tag::Suffixed,
        _ => Tag::Invalid,
    }
}

/// The version of this binary: the same grammar as a tag, where a `-` suffix marks a
/// pre-release.
pub fn parse_running(text: &str) -> Option<Version> {
    let (version, rest) = split_numbers(text)?;

    match rest {
        "" => Some(version),
        _ if rest.starts_with('+') => Some(version),
        _ if rest.starts_with('-') => Some(Version {
            pre: true,
            ..version
        }),
        _ => None,
    }
}

pub fn is_newer(latest: Version, running: Version) -> bool {
    let latest_numbers = (latest.major, latest.minor, latest.patch);
    let running_numbers = (running.major, running.minor, running.patch);

    latest_numbers > running_numbers || (latest_numbers == running_numbers && running.pre)
}

/// The release notes as one line of plain text: no URL, white space squeezed, at most
/// `SUMMARY_CHARS` characters.
pub fn summarize(notes: &str) -> String {
    // One character more than the summary holds shows that the text was cut.
    let mut line: String = notes
        .split_whitespace()
        .filter(|word| !word.contains("://"))
        .flat_map(|word| std::iter::once(' ').chain(word.chars()))
        .skip(1)
        .take(SUMMARY_CHARS + 1)
        .collect();

    match line.char_indices().nth(SUMMARY_CHARS) {
        Some((end, _)) => {
            line.truncate(end);
            line.push('…');

            line
        }
        None => line,
    }
}

/// The clock of the check. Tests shrink it.
#[derive(Debug, Clone)]
pub struct CheckTiming {
    pub first_min: Duration,
    pub first_max: Duration,
    pub every: Duration,
}

impl Default for CheckTiming {
    fn default() -> CheckTiming {
        CheckTiming {
            first_min: Duration::from_secs(300),
            first_max: Duration::from_secs(600),
            every: Duration::from_secs(24 * 3600),
        }
    }
}

impl CheckTiming {
    pub fn first_delay(&self) -> Duration {
        self.first_min + (self.first_max - self.first_min).mul_f64(unit_random())
    }

    pub fn next_delay(&self) -> Duration {
        jittered(self.every)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Network,
    Status(u16),
    Invalid,
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Network => write!(formatter, "network error"),
            Failure::Status(status) => write!(formatter, "HTTP status {status}"),
            Failure::Invalid => write!(formatter, "invalid answer"),
        }
    }
}

/// What one check ended in. It carries no diagnostic text, so what the loop keeps between
/// checks stays a few bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    UpToDate,
    Newer(String),
    NotFound,
    Failed(Failure),
}

/// The line to log when `now` differs from the `previous` check's outcome. `detail` is the
/// diagnostic of a failure.
pub fn log_line(previous: &Outcome, now: &Outcome, detail: &str) -> Option<(log::Level, String)> {
    if previous == now {
        return None;
    }

    let line = match now {
        Outcome::UpToDate => (log::Level::Info, "update check: up to date".to_string()),
        Outcome::Newer(version) => (
            log::Level::Info,
            format!("update check: version {version} is available"),
        ),
        Outcome::NotFound => (
            log::Level::Info,
            "update check: no release found (404)".to_string(),
        ),
        Outcome::Failed(failure) if detail.is_empty() => {
            (log::Level::Warn, format!("update check failed: {failure}"))
        }
        Outcome::Failed(failure) => (
            log::Level::Warn,
            format!("update check failed: {failure}: {detail}"),
        ),
    };

    Some(line)
}

/// The newest release known, in the form the page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Latest {
    pub version: String,
    pub notes: String,
}

/// What `/api/status` says about updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdateView {
    pub build: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub how: Option<&'static str>,
    /// Whether this request may install from the page. `Updates` cannot tell: the status page
    /// fills it in from the password and the stager.
    pub can_install: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install: Option<InstallView>,
}

/// The result of the check, shared with the status page.
pub struct Updates {
    build: Build,
    latest: Mutex<Option<Latest>>,
}

impl Updates {
    pub fn new(build: Build) -> Updates {
        Updates {
            build,
            latest: Mutex::new(None),
        }
    }

    pub fn view(&self) -> UpdateView {
        let latest = self.latest.lock().unwrap().clone();
        let Some(latest) = latest else {
            return UpdateView {
                build: self.build.name(),
                latest: None,
                notes: None,
                how: None,
                can_install: false,
                install: None,
            };
        };

        UpdateView {
            build: self.build.name(),
            latest: Some(latest.version),
            notes: Some(latest.notes).filter(|notes| !notes.is_empty()),
            how: Some(self.build.how()),
            can_install: false,
            install: None,
        }
    }

    pub fn show(&self, latest: Option<Latest>) {
        *self.latest.lock().unwrap() = latest;
    }

    pub fn build(&self) -> Build {
        self.build
    }

    /// The newest version the check knows of, `X.Y.Z`.
    pub fn latest_version(&self) -> Option<String> {
        self.latest
            .lock()
            .unwrap()
            .as_ref()
            .map(|latest| latest.version.clone())
    }
}

/// The fields of GitHub's release answer that the check reads.
#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    body: Option<String>,
}

pub struct Checker {
    downloader: Downloader,
    url: String,
    running: Option<Version>,
    /// The ETag of the last 200 answer that arrived in full, with the outcome it gave, so a
    /// 304 repeats that outcome.
    cached: Option<(String, Outcome)>,
}

impl Checker {
    pub fn new(downloader: Downloader, url: &str) -> Checker {
        Checker {
            downloader,
            url: url.to_string(),
            running: parse_running(env!("CARGO_PKG_VERSION")),
            cached: None,
        }
    }

    /// Asks once and updates what `updates` shows. The second item is the diagnostic for the
    /// log line; it is not kept.
    pub async fn check(&mut self, updates: &Updates) -> (Outcome, String) {
        let previous = Validators {
            etag: self.cached.as_ref().map(|(etag, _)| etag.clone()),
            last_modified: None,
        };
        let limits = Limits {
            max_body_bytes: MAX_ANSWER_BYTES,
            idle_timeout: Duration::from_secs(30),
            total_timeout: Duration::from_secs(60),
            max_redirects: 5,
        };

        let download = match self.downloader.fetch(&self.url, &previous, &limits).await {
            Ok(Fetch::Modified(download)) => download,

            Ok(Fetch::NotModified) => {
                return match &self.cached {
                    Some((_, outcome)) => (outcome.clone(), String::new()),
                    None => (
                        Outcome::Failed(Failure::Invalid),
                        "not modified, but no answer is kept".to_string(),
                    ),
                };
            }

            Err(error) => return (outcome_of(&error), error.to_string()),
        };

        let etag = download.validators.etag.clone();
        let (sender, mut receiver) = mpsc::channel(PIECE_QUEUE);
        // The pumping future owns the only sender, so the channel closes on any exit and the
        // collector below cannot wait for ever.
        let pumping = async move {
            let result = download.pump(&sender).await;
            drop(sender);

            result
        };
        let collecting = async {
            let mut body = Vec::new();

            while let Some(piece) = receiver.recv().await {
                match piece {
                    Piece::Data(data) => body.extend_from_slice(&data),
                    Piece::End => return (body, true),
                }
            }

            (body, false)
        };
        let (pumped, (body, complete)) = tokio::join!(pumping, collecting);

        if let Err(error) = pumped {
            return (outcome_of(&error), error.to_string());
        }

        if !complete {
            return (
                Outcome::Failed(Failure::Network),
                "the answer ended early".to_string(),
            );
        }

        let (outcome, detail) = self.read_answer(&body, updates);
        self.cached = etag.map(|etag| (etag, outcome.clone()));

        (outcome, detail)
    }

    fn read_answer(&self, body: &[u8], updates: &Updates) -> (Outcome, String) {
        let release = match serde_json::from_slice::<Release>(body) {
            Ok(release) => release,
            Err(error) => return (Outcome::Failed(Failure::Invalid), error.to_string()),
        };

        if release.draft || release.prerelease {
            return (current_outcome(updates), String::new());
        }

        let version = match parse_tag(&release.tag_name) {
            Tag::Release(version) => version,
            Tag::Suffixed => return (current_outcome(updates), String::new()),
            Tag::Invalid => {
                return (
                    Outcome::Failed(Failure::Invalid),
                    format!("{:?} is not a version", release.tag_name),
                );
            }
        };

        let is_newer = self
            .running
            .is_some_and(|running| is_newer(version, running));

        if !is_newer {
            updates.show(None);

            return (Outcome::UpToDate, String::new());
        }

        updates.show(Some(Latest {
            version: version.to_string(),
            notes: summarize(release.body.as_deref().unwrap_or_default()),
        }));

        (Outcome::Newer(version.to_string()), String::new())
    }
}

/// What the check says while it leaves the shown result as it is.
fn current_outcome(updates: &Updates) -> Outcome {
    match updates.latest_version() {
        Some(version) => Outcome::Newer(version),
        None => Outcome::UpToDate,
    }
}

fn outcome_of(error: &FetchError) -> Outcome {
    match error {
        FetchError::Status(404) => Outcome::NotFound,

        FetchError::Status(status) => Outcome::Failed(Failure::Status(*status)),

        FetchError::BodyTooLarge
        | FetchError::HtmlPage
        | FetchError::UnsupportedEncoding(_)
        | FetchError::TooManyRedirects
        | FetchError::BadRedirect(_)
        | FetchError::InsecureRedirect
        | FetchError::LocalRedirect(_) => Outcome::Failed(Failure::Invalid),

        FetchError::BadUrl(_)
        | FetchError::Resolve(_)
        | FetchError::Connect(_)
        | FetchError::Tls(_)
        | FetchError::Timeout
        | FetchError::DeadlinePassed
        | FetchError::Http(_)
        | FetchError::Io(_)
        | FetchError::SinkClosed => Outcome::Failed(Failure::Network),
    }
}

/// Starts the daily check, or nothing when it is off or when the status page, the only place
/// that shows the result, is off. The task is never awaited: stopping picoguard drops it.
pub fn start(
    config: &Config,
    url: &str,
    names: Names,
    tls: Arc<Tls>,
    updates: Arc<Updates>,
    timing: CheckTiming,
) -> Option<JoinHandle<()>> {
    if !config.update.check || !config.web.enabled {
        return None;
    }

    let checker = Checker::new(Downloader::new(names, tls), url);

    Some(tokio::spawn(run(checker, updates, timing)))
}

async fn run(mut checker: Checker, updates: Arc<Updates>, timing: CheckTiming) {
    sleep(timing.first_delay()).await;
    let mut previous = Outcome::UpToDate;

    loop {
        let started = Instant::now();

        previous = check_and_log(&mut checker, &updates, &previous).await;
        sleep_until(started + timing.next_delay()).await;
    }
}

/// A separate function, so the diagnostic is dropped before the long sleep.
async fn check_and_log(checker: &mut Checker, updates: &Updates, previous: &Outcome) -> Outcome {
    let (outcome, detail) = checker.check(updates).await;

    if let Some((level, line)) = log_line(previous, &outcome, &detail) {
        log::log!(level, "{line}");
    }

    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(text: &str) -> Version {
        match parse_tag(text) {
            Tag::Release(version) => version,
            other => panic!("{text} is not a plain release: {other:?}"),
        }
    }

    fn newer(latest: &str, running: &str) -> bool {
        is_newer(release(latest), parse_running(running).unwrap())
    }

    #[test]
    fn newer_versions_follow_semantic_precedence() {
        assert!(newer("v0.3.0", "0.2.0"));
        assert!(!newer("0.2.0", "0.2.0"));
        assert!(!newer("0.9.0", "0.10.0"));
        assert!(!newer("0.10.0", "0.10.0"));
        assert!(newer("0.10.0", "0.9.0"));
        assert!(newer("1.0.0", "0.99.99"));
        assert!(!newer("0.1.9", "0.2.0"));
        assert!(newer("0.3.0", "0.3.0-rc.1"));
        assert!(!newer("0.3.0", "0.3.0+build"));
        assert_eq!(release("v0.3.0"), release("0.3.0"));
    }

    #[test]
    fn tags_with_a_suffix_are_ignored_and_others_are_invalid() {
        for text in ["v0.3.0-rc.1", "v1.0.0+meta", "0.3.0-"] {
            assert_eq!(parse_tag(text), Tag::Suffixed, "{text}");
        }

        for text in [
            "v0.3",
            "nightly",
            "v0.3.0.1",
            "",
            "v",
            "vv0.3.0",
            "0.3.x",
            "0.3.0 ",
            "0..1",
            "-1.0.0",
            "99999999999999999999.0.0",
        ] {
            assert_eq!(parse_tag(text), Tag::Invalid, "{text:?}");
        }
    }

    #[test]
    fn the_running_version_parses() {
        assert!(matches!(
            parse_tag(env!("CARGO_PKG_VERSION")),
            Tag::Release(_) | Tag::Suffixed
        ));
        assert!(parse_running(env!("CARGO_PKG_VERSION")).is_some());
    }

    #[test]
    fn the_summary_drops_urls_and_squeezes_white_space() {
        assert_eq!(
            summarize("Fixes\n\n a   bug\tand\r\nmore"),
            "Fixes a bug and more"
        );
        assert_eq!(
            summarize("See https://example.com/x for (http://a.b) details"),
            "See for details"
        );
        assert_eq!(summarize("  \n\t "), "");
        assert_eq!(summarize(""), "");

        let long = "a".repeat(500);
        let cut = summarize(&long);
        assert_eq!(cut, format!("{}…", "a".repeat(200)));

        let exact = "b".repeat(200);
        assert_eq!(summarize(&exact), exact);

        let wide = "é".repeat(300);
        assert_eq!(summarize(&wide), format!("{}…", "é".repeat(200)));

        let many_words = "a ".repeat(100_000);
        assert_eq!(summarize(&many_words), format!("{}…", "a ".repeat(100)));
    }

    #[test]
    fn each_build_kind_has_its_update_command() {
        let cases = [
            (
                Some("release"),
                "release",
                "curl -fsSL https://github.com/risan/picoguard/releases/latest/download/install.sh | sudo sh",
            ),
            (
                Some("docker"),
                "docker",
                "git pull && docker compose up -d --build",
            ),
            (None, "source", "cargo install --locked picoguard"),
            (Some("other"), "source", "cargo install --locked picoguard"),
        ];

        for (marker, name, how) in cases {
            let build = Build::from_marker(marker);

            assert_eq!(build.name(), name, "{marker:?}");
            assert_eq!(build.how(), how, "{marker:?}");
        }
    }

    #[test]
    fn the_first_check_comes_five_to_ten_minutes_after_start() {
        let timing = CheckTiming::default();

        let delays: Vec<Duration> = (0..1000).map(|_| timing.first_delay()).collect();

        assert!(
            delays
                .iter()
                .all(|delay| *delay >= Duration::from_secs(300)
                    && *delay <= Duration::from_secs(600))
        );
        assert!(delays.iter().any(|delay| *delay < Duration::from_secs(400)));
        assert!(delays.iter().any(|delay| *delay > Duration::from_secs(500)));
    }

    #[test]
    fn the_next_check_comes_about_a_day_later() {
        let timing = CheckTiming::default();

        let delays: Vec<Duration> = (0..1000).map(|_| timing.next_delay()).collect();

        assert!(delays.iter().all(|delay| {
            *delay >= Duration::from_secs(77_760) && *delay <= Duration::from_secs(95_040)
        }));
        assert!(
            delays
                .iter()
                .any(|delay| *delay < Duration::from_secs(82_000))
        );
        assert!(
            delays
                .iter()
                .any(|delay| *delay > Duration::from_secs(91_000))
        );
    }

    #[test]
    fn only_a_change_of_outcome_is_logged() {
        use log::Level::{Info, Warn};

        let newer = || Outcome::Newer("0.3.0".to_string());
        let sequence = [
            Outcome::Failed(Failure::Status(500)),
            Outcome::Failed(Failure::Status(500)),
            Outcome::UpToDate,
            Outcome::NotFound,
            Outcome::NotFound,
            Outcome::Failed(Failure::Network),
            newer(),
            newer(),
        ];

        let mut previous = Outcome::UpToDate;
        let mut levels = Vec::new();

        for now in sequence {
            levels.push(log_line(&previous, &now, "detail").map(|(level, _)| level));
            previous = now;
        }

        assert_eq!(
            levels,
            [
                Some(Warn),
                None,
                Some(Info),
                Some(Info),
                None,
                Some(Warn),
                Some(Info),
                None
            ]
        );
    }

    #[test]
    fn the_first_up_to_date_answer_logs_nothing() {
        assert!(log_line(&Outcome::UpToDate, &Outcome::UpToDate, "").is_none());
    }

    #[test]
    fn a_newer_version_after_another_newer_one_is_logged_again() {
        let first = Outcome::Newer("0.3.0".to_string());
        let second = Outcome::Newer("0.4.0".to_string());

        let (level, line) = log_line(&first, &second, "").unwrap();

        assert_eq!(level, log::Level::Info);
        assert!(line.contains("0.4.0"), "{line}");
    }

    #[test]
    fn a_failure_line_names_the_class_and_the_detail() {
        let (level, line) = log_line(
            &Outcome::UpToDate,
            &Outcome::Failed(Failure::Status(403)),
            "rate limited",
        )
        .unwrap();

        assert_eq!(level, log::Level::Warn);
        assert!(line.contains("403"), "{line}");
        assert!(line.contains("rate limited"), "{line}");
    }
}
