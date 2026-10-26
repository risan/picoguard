//! Downloading, verifying and staging an update (plan D9-D14). The daemon fetches the signed
//! `SHA256SUMS`, checks the signature with the built-in key, streams the binary to disk while
//! hashing it, and leaves four files in `<state.dir>/update/` for the root installer. It
//! never holds the binary in memory, and every file operation runs on a thread of its own so
//! a slow disk can neither stall DNS nor hold up shutdown.

use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use ring::digest;
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};

pub use crate::release::{MAX_BINARY_BYTES, MAX_SUMS_BYTES};

use crate::lists::{
    Downloader, Fetch, FetchError, Limits, PIECE_QUEUE, Piece, Resolver, Validators,
};
use crate::release::{
    InstallerResult, Outcome, Reading, Request, SumsError, asset, expected_hash, read_regular,
    verify_sums,
};
use crate::update::{Build, Updates};
use crate::upstream::tls::Tls;

pub const RELEASE_DOWNLOAD_URL: &str = "https://github.com/risan/picoguard/releases/download";

/// Made by `install.sh` together with the installer; its presence says an installer is there.
pub const INSTALLER_DIR: &str = "/var/lib/picoguard-update";

const SIGNATURE_CAP_BYTES: u64 = 1024;
const SMALL_FILE_TOTAL: Duration = Duration::from_secs(60);
const BINARY_TOTAL: Duration = Duration::from_secs(10 * 60);
const IDLE: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 5;
const UPDATE_DIR: &str = "update";
const REQUEST_MAX_BYTES: u64 = 256;
const RESULT_MAX_BYTES: u64 = 1024;
const NO_ANSWER: &str = "the installer did not answer within 10 minutes";
const UNREADABLE_ANSWER: &str = "the installer's answer could not be read";

/// The clock of the wait for the installer. Tests shrink it.
#[derive(Debug, Clone)]
pub struct StageTiming {
    /// How often the result file is looked at.
    pub poll: Duration,
    /// How long the installer may take, counted from when the request was written.
    pub wait: Duration,
}

impl Default for StageTiming {
    fn default() -> StageTiming {
        StageTiming {
            poll: Duration::from_secs(2),
            wait: Duration::from_secs(600),
        }
    }
}

pub struct StageSetup {
    /// `None` for a build that is not one of the three release builds.
    pub target: Option<&'static str>,
    pub base_url: String,
    pub state_dir: PathBuf,
    pub installer_dir: PathBuf,
    /// The public key that must have signed `SHA256SUMS`. Production passes the built-in key
    /// and nothing else.
    pub key: [u8; 32],
    pub max_binary_bytes: u64,
    pub timing: StageTiming,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Install {
    Checking { version: String },
    Downloading { version: String, bytes: u64 },
    Verifying { version: String },
    Waiting { version: String },
    Updated { version: String },
    RolledBack { version: String, reason: String },
    Failed { version: String, reason: String },
}

impl Install {
    fn is_final(&self) -> bool {
        matches!(
            self,
            Install::Updated { .. } | Install::RolledBack { .. } | Install::Failed { .. }
        )
    }

    fn view(&self) -> InstallView {
        let (state, version, bytes, reason) = match self {
            Install::Checking { version } => ("checking", version, None, None),
            Install::Downloading { version, bytes } => ("downloading", version, Some(*bytes), None),
            Install::Verifying { version } => ("verifying", version, None, None),
            Install::Waiting { version } => ("waiting", version, None, None),
            Install::Updated { version } => ("updated", version, None, None),
            Install::RolledBack { version, reason } => ("rolled_back", version, None, Some(reason)),
            Install::Failed { version, reason } => ("failed", version, None, Some(reason)),
        };

        InstallView {
            state,
            version: version.clone(),
            bytes,
            reason: reason.cloned(),
        }
    }
}

/// What `/api/status` says about the update in progress or just ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallView {
    pub state: &'static str,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// A source or Docker build, a target without a release, or no installer.
    CannotInstall,
    InProgress,
    NotNewest,
}

/// The update of one click. `id` is the id of its request.
struct Attempt {
    id: String,
    install: Install,
}

/// Why an update failed, in the words the page shows (plan D12).
#[derive(Debug)]
enum StageError {
    Signature,
    NoBinary(&'static str),
    Ambiguous(&'static str),
    BadHash(&'static str),
    Status { file: &'static str, status: u16 },
    Network(&'static str),
    Invalid(&'static str),
    TooLarge(u64),
    HashMismatch,
    Disk(io::ErrorKind),
}

impl fmt::Display for StageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StageError::Signature => {
                write!(
                    formatter,
                    "signature: SHA256SUMS is not signed by the release key"
                )
            }
            StageError::NoBinary(target) => {
                write!(formatter, "the release has no binary for {target}")
            }
            StageError::Ambiguous(target) => {
                write!(
                    formatter,
                    "SHA256SUMS lists {} more than once",
                    asset(target)
                )
            }
            StageError::BadHash(target) => {
                write!(formatter, "SHA256SUMS has a bad hash for {}", asset(target))
            }
            StageError::Status { file, status } => {
                write!(formatter, "{file}: HTTP status {status}")
            }
            StageError::Network(file) => write!(formatter, "{file}: network error"),
            StageError::Invalid(file) => write!(formatter, "{file}: invalid answer"),
            StageError::TooLarge(cap) => {
                write!(formatter, "the binary is larger than {}", size_text(*cap))
            }
            StageError::HashMismatch => {
                write!(formatter, "the binary does not match SHA256SUMS")
            }
            StageError::Disk(kind) => write!(formatter, "disk: {kind}"),
        }
    }
}

impl From<io::Error> for StageError {
    fn from(error: io::Error) -> StageError {
        StageError::Disk(error.kind())
    }
}

fn size_text(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;

    if bytes.is_multiple_of(MIB) {
        format!("{} MiB", bytes / MIB)
    } else if bytes.is_multiple_of(1024) {
        format!("{} KiB", bytes / 1024)
    } else {
        format!("{bytes} bytes")
    }
}

/// A failure of the download itself. A body over the cap is told apart by the caller, which
/// knows which file it was.
fn network_error(file: &'static str, error: &FetchError) -> StageError {
    match error {
        FetchError::Status(status) => StageError::Status {
            file,
            status: *status,
        },

        FetchError::BodyTooLarge
        | FetchError::HtmlPage
        | FetchError::UnsupportedEncoding(_)
        | FetchError::TooManyRedirects
        | FetchError::BadRedirect(_)
        | FetchError::InsecureRedirect
        | FetchError::LocalRedirect(_)
        | FetchError::BadUrl(_) => StageError::Invalid(file),

        FetchError::Resolve(_)
        | FetchError::Connect(_)
        | FetchError::Tls(_)
        | FetchError::Timeout
        | FetchError::DeadlinePassed
        | FetchError::Http(_)
        | FetchError::Io(_)
        | FetchError::SinkClosed => StageError::Network(file),
    }
}

/// Started by the status page, shared with it.
pub struct Stager {
    setup: StageSetup,
    updates: Arc<Updates>,
    downloader: Downloader,
    installer_present: bool,
    state: Mutex<Option<Attempt>>,
}

impl Stager {
    pub fn new(
        setup: StageSetup,
        updates: Arc<Updates>,
        resolver: Resolver,
        tls: Arc<Tls>,
    ) -> Arc<Stager> {
        let installer_present = fs::metadata(&setup.installer_dir)
            .map(|metadata| metadata.is_dir())
            .unwrap_or(false);

        Arc::new(Stager {
            setup,
            updates,
            downloader: Downloader::new(resolver, tls),
            installer_present,
            state: Mutex::new(None),
        })
    }

    /// Whether this build and this machine can install from the page at all.
    fn can_run(&self) -> bool {
        self.updates.build() == Build::Release
            && self.setup.target.is_some()
            && self.installer_present
    }

    fn is_running(&self) -> bool {
        self.state
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|attempt| !attempt.install.is_final())
    }

    /// Every condition for the button but the password, which the page adds.
    pub fn can_install(&self) -> bool {
        self.can_run() && self.updates.latest_version().is_some() && !self.is_running()
    }

    pub fn view(&self) -> Option<InstallView> {
        self.state
            .lock()
            .unwrap()
            .as_ref()
            .map(|attempt| attempt.install.view())
    }

    /// Starts the update to `version` in the background. Two calls never start two updates.
    pub fn start(self: &Arc<Self>, version: &str) -> Result<(), Refused> {
        let (true, Some(target)) = (self.can_run(), self.setup.target) else {
            return Err(Refused::CannotInstall);
        };

        let request = {
            let mut state = self.state.lock().unwrap();

            if state
                .as_ref()
                .is_some_and(|attempt| !attempt.install.is_final())
            {
                return Err(Refused::InProgress);
            }

            if self.updates.latest_version().as_deref() != Some(version) {
                return Err(Refused::NotNewest);
            }

            let request = Request::new_random(version);
            *state = Some(Attempt {
                id: request.id.clone(),
                install: Install::Checking {
                    version: version.to_string(),
                },
            });

            request
        };

        tokio::spawn(Arc::clone(self).run(request, target));

        Ok(())
    }

    /// Looks for the installer's answer to `request`: a result with its id.
    fn installer_answer(&self, request: &Request) -> Option<Install> {
        let bytes =
            read_regular(&self.setup.installer_dir.join("result"), RESULT_MAX_BYTES).ok()?;
        let version = request.version.clone();

        match InstallerResult::parse(&bytes) {
            Reading::Answer(result) if result.id == request.id => Some(match result.outcome {
                Outcome::Updated => Install::Updated { version },
                Outcome::RolledBack(reason) => Install::RolledBack { version, reason },
                Outcome::Failed(reason) => Install::Failed { version, reason },
            }),

            Reading::Unreadable { id: Some(id) } if id == request.id => Some(Install::Failed {
                version,
                reason: UNREADABLE_ANSWER.to_string(),
            }),

            Reading::Answer(_) | Reading::Unreadable { .. } => None,
        }
    }

    /// Waits for the installer's result on the calling thread (plan D13), then removes the
    /// staged files, request first, and only then shows the end, so a new update never starts
    /// while this cleanup runs. The thread sleeps instead of using the runtime so that
    /// stopping picoguard never waits for it.
    fn wait_for_installer(self: &Arc<Self>, request: &Request, written: SystemTime) {
        let timing = &self.setup.timing;
        let deadline = Instant::now() + wait_left(timing.wait, written, SystemTime::now());

        let ended = loop {
            std::thread::sleep(timing.poll);

            if let Some(answer) = self.installer_answer(request) {
                break answer;
            }

            if Instant::now() >= deadline {
                break Install::Failed {
                    version: request.version.clone(),
                    reason: NO_ANSWER.to_string(),
                };
            }
        };

        self.clear_and_show(request, ended);
    }

    fn clear_and_show(&self, request: &Request, ended: Install) {
        if let Err(error) = empty_dir(&self.setup.state_dir.join(UPDATE_DIR)) {
            log::warn!("cannot remove the staged update: {error}");
        }

        log::info!("update to {}: {}", request.version, ended.view().state);
        self.set(&request.id, ended);
    }

    /// Cleans up what an earlier run left in `<state.dir>/update` and picks up an update that
    /// is waiting for the installer. It only removes: a start never writes anything new.
    pub fn resume(self: &Arc<Self>) {
        let staging = self.setup.state_dir.join(UPDATE_DIR);
        let Ok(metadata) = fs::symlink_metadata(&staging) else {
            return;
        };

        if !metadata.is_dir() {
            if let Err(error) = fs::remove_file(&staging) {
                log::warn!("cannot remove {}: {error}", staging.display());
            }

            return;
        }

        let request_path = staging.join("request");
        let request = read_regular(&request_path, REQUEST_MAX_BYTES)
            .ok()
            .and_then(|bytes| Request::parse(&bytes));
        let Some(request) = request else {
            self.remove_leftovers(&staging);

            return;
        };
        let written = fs::metadata(&request_path)
            .and_then(|metadata| metadata.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let version = request.version.clone();

        let ended = match self.installer_answer(&request) {
            Some(answer) => answer,

            None if wait_left(self.setup.timing.wait, written, SystemTime::now()).is_zero() => {
                Install::Failed {
                    version,
                    reason: NO_ANSWER.to_string(),
                }
            }

            None => {
                self.wait_in_background(request, written);

                return;
            }
        };

        self.remove_leftovers(&staging);
        self.show(&request.id, ended);
    }

    fn wait_in_background(self: &Arc<Self>, request: Request, written: SystemTime) {
        let version = request.version.clone();

        self.show(
            &request.id,
            Install::Waiting {
                version: version.clone(),
            },
        );
        let stager = Arc::clone(self);
        let waiting = request.clone();
        let spawned = std::thread::Builder::new()
            .name("picoguard-update".to_string())
            .spawn(move || stager.wait_for_installer(&waiting, written));

        if let Err(error) = spawned {
            log::warn!("cannot wait for the installer: {error}");
            self.clear_and_show(
                &request,
                Install::Failed {
                    version,
                    reason: format!("cannot wait for the installer: {}", error.kind()),
                },
            );
        }
    }

    fn remove_leftovers(&self, staging: &Path) {
        if let Err(error) = empty_dir(staging) {
            log::warn!("cannot remove what an update left behind: {error}");
        }
    }

    /// Shows the state of an update found at start, when no attempt of this run exists.
    fn show(&self, id: &str, install: Install) {
        *self.state.lock().unwrap() = Some(Attempt {
            id: id.to_string(),
            install,
        });
    }

    /// Changes the state of the attempt `id`, unless it has ended or another one has begun.
    fn set(&self, id: &str, install: Install) {
        let mut state = self.state.lock().unwrap();

        if let Some(attempt) = state.as_mut()
            && attempt.id == id
            && !attempt.install.is_final()
        {
            attempt.install = install;
        }
    }

    async fn run(self: Arc<Self>, request: Request, target: &'static str) {
        let version = request.version.clone();

        match self.stage(&request, target).await {
            Ok(()) => {
                log::info!("update to {version}: staged, waiting for the installer");
                self.set(&request.id, Install::Waiting { version });
            }

            Err(error) => {
                log::warn!("update to {version} failed: {error}");
                self.set(
                    &request.id,
                    Install::Failed {
                        version,
                        reason: error.to_string(),
                    },
                );
            }
        }
    }

    /// The network side. It ends after the files are staged, or the update has failed and
    /// nothing is left on disk.
    async fn stage(
        self: &Arc<Self>,
        request: &Request,
        target: &'static str,
    ) -> Result<(), StageError> {
        let version = &request.version;
        let base = format!("{}/v{version}", self.setup.base_url);

        let sums = self
            .fetch_small(&format!("{base}/SHA256SUMS"), "SHA256SUMS", MAX_SUMS_BYTES)
            .await?;
        let signature = self
            .fetch_small(
                &format!("{base}/SHA256SUMS.sig"),
                "SHA256SUMS.sig",
                SIGNATURE_CAP_BYTES,
            )
            .await?;

        if !verify_sums(&sums, &signature, &self.setup.key) {
            return Err(StageError::Signature);
        }

        let expected = expected_hash(&sums, target).map_err(|error| match error {
            SumsError::NoBinary => StageError::NoBinary(target),
            SumsError::Ambiguous => StageError::Ambiguous(target),
            SumsError::Malformed => StageError::BadHash(target),
        })?;

        self.set(
            &request.id,
            Install::Downloading {
                version: version.clone(),
                bytes: 0,
            },
        );

        let (sender, receiver) = mpsc::channel(PIECE_QUEUE);
        let (report, reported) = oneshot::channel();
        let writer = Writer {
            stager: Arc::clone(self),
            request: request.clone(),
            sums,
            signature,
            expected,
        };

        std::thread::Builder::new()
            .name("picoguard-update".to_string())
            .spawn(move || writer.run(receiver, report))
            .map_err(|error| StageError::Disk(error.kind()))?;

        let url = format!("{base}/{}", asset(target));
        let limits = Limits {
            max_body_bytes: self.setup.max_binary_bytes,
            idle_timeout: IDLE,
            total_timeout: BINARY_TOTAL,
            max_redirects: MAX_REDIRECTS,
        };
        let downloading = async {
            let fetched = self
                .downloader
                .fetch(&url, &Validators::default(), &limits)
                .await?;

            match fetched {
                Fetch::Modified(download) => download.pump(&sender).await,
                Fetch::NotModified => Err(FetchError::Status(304)),
            }
        };

        // When the writer stops reading (a disk error), its receiver is dropped and the
        // download is dropped with it, which closes the connection.
        let downloaded = tokio::select! {
            result = downloading => Some(result),
            () = sender.closed() => None,
        };
        drop(sender);

        // `SinkClosed` only says the writer stopped first; its own reason is the one to show.
        let download_error = match downloaded {
            Some(Err(FetchError::SinkClosed)) | Some(Ok(())) | None => None,
            Some(Err(error)) => Some(error),
        };
        let written = reported.await;

        if let Some(error) = download_error {
            return Err(match error {
                FetchError::BodyTooLarge => StageError::TooLarge(self.setup.max_binary_bytes),
                other => network_error("picoguard", &other),
            });
        }

        written.unwrap_or(Err(StageError::Disk(io::ErrorKind::Other)))
    }

    /// A small file, collected in memory like the update check's answer.
    async fn fetch_small(
        &self,
        url: &str,
        file: &'static str,
        cap: u64,
    ) -> Result<Vec<u8>, StageError> {
        let limits = Limits {
            max_body_bytes: cap,
            idle_timeout: IDLE,
            total_timeout: SMALL_FILE_TOTAL,
            max_redirects: MAX_REDIRECTS,
        };
        let download = match self
            .downloader
            .fetch(url, &Validators::default(), &limits)
            .await
        {
            Ok(Fetch::Modified(download)) => download,
            Ok(Fetch::NotModified) => return Err(StageError::Invalid(file)),
            Err(error) => return Err(network_error(file, &error)),
        };

        let (sender, mut receiver) = mpsc::channel(PIECE_QUEUE);
        // The pumping future owns the only sender, so the collector cannot wait for ever.
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

        pumped.map_err(|error| network_error(file, &error))?;

        if !complete {
            return Err(StageError::Network(file));
        }

        Ok(body)
    }
}

/// Everything the update thread needs. All of its file operations are here.
struct Writer {
    stager: Arc<Stager>,
    request: Request,
    sums: Vec<u8>,
    signature: Vec<u8>,
    expected: [u8; 32],
}

impl Writer {
    fn run(self, receiver: mpsc::Receiver<Piece>, report: oneshot::Sender<Result<(), StageError>>) {
        let staging = self.stager.setup.state_dir.join(UPDATE_DIR);
        let written = self
            .clear_staging()
            .map_err(StageError::from)
            .and_then(|()| self.write_files(&staging, receiver));

        if written.is_err() {
            let _ = empty_dir(&staging);
        }

        let staged = written.is_ok();
        let _ = report.send(written);

        if staged {
            let written_at = fs::metadata(staging.join("request"))
                .and_then(|metadata| metadata.modified())
                .unwrap_or_else(|_| SystemTime::now());

            self.stager.wait_for_installer(&self.request, written_at);
        }
    }

    /// Leaves `<state.dir>/update` an empty real directory, or fails. A link or file in its
    /// place is removed, never followed.
    fn clear_staging(&self) -> io::Result<()> {
        let state_dir = &self.stager.setup.state_dir;
        let staging = state_dir.join(UPDATE_DIR);

        match fs::symlink_metadata(&staging) {
            Ok(metadata) if metadata.is_dir() => {
                empty_dir(&staging)?;

                return fs::set_permissions(&staging, fs::Permissions::from_mode(0o700));
            }

            Ok(_) => fs::remove_file(&staging)?,

            Err(error) if error.kind() == io::ErrorKind::NotFound => {}

            Err(error) => return Err(error),
        }

        DirBuilder::new().mode(0o700).create(&staging)?;

        sync_dir(state_dir)
    }

    /// The binary as it arrives, then the three small files, the request last.
    fn write_files(
        &self,
        staging: &Path,
        mut receiver: mpsc::Receiver<Piece>,
    ) -> Result<(), StageError> {
        let id = &self.request.id;
        let version = &self.request.version;
        let part = staging.join("picoguard.part");
        let mut file = create_new(&part, 0o700)?;
        let mut hash = digest::Context::new(&digest::SHA256);
        let mut bytes = 0u64;

        loop {
            match receiver.blocking_recv() {
                Some(Piece::Data(data)) => {
                    hash.update(&data);
                    file.write_all(&data)?;
                    bytes += data.len() as u64;
                    self.stager.set(
                        id,
                        Install::Downloading {
                            version: version.clone(),
                            bytes,
                        },
                    );
                }

                Some(Piece::End) => break,

                None => return Err(StageError::Network("picoguard")),
            }
        }

        drop(receiver);
        self.stager.set(
            id,
            Install::Verifying {
                version: version.clone(),
            },
        );

        if hash.finish().as_ref() != self.expected {
            return Err(StageError::HashMismatch);
        }

        file.sync_all()?;
        drop(file);
        fs::rename(&part, staging.join("picoguard"))?;
        sync_dir(staging)?;

        write_whole(staging, "SHA256SUMS", &self.sums)?;
        write_whole(staging, "SHA256SUMS.sig", &self.signature)?;
        write_whole(staging, "request", self.request.format().as_bytes())?;

        Ok(sync_dir(staging)?)
    }
}

/// How much of `wait` is left for a request written at `written`. A request from the future
/// has not aged, and one older than `wait` has nothing left: a slow sync or a clock jump
/// must give a passed deadline, never a subtraction that panics.
fn wait_left(wait: Duration, written: SystemTime, now: SystemTime) -> Duration {
    let age = now.duration_since(written).unwrap_or(Duration::ZERO);

    wait.saturating_sub(age)
}

fn create_new(path: &Path, mode: u32) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
}

/// A file that appears whole or not at all: written as `<name>.part`, synced, renamed.
fn write_whole(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let part = dir.join(format!("{name}.part"));
    let mut file = create_new(&part, 0o600)?;

    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    fs::rename(&part, dir.join(name))
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Removes everything in `dir`, the request first so the installer never sees a request
/// without its files; when the request cannot be removed nothing else is. Links are removed,
/// never followed, and `dir` itself must be a real directory: a link in its place is refused,
/// so cleaning up can never reach outside the staging directory.
fn empty_dir(dir: &Path) -> io::Result<()> {
    if !fs::symlink_metadata(dir)?.is_dir() {
        return Err(io::Error::other("not a directory"));
    }

    match fs::remove_file(dir.join("request")) {
        Ok(()) => {}

        Err(error) if error.kind() == io::ErrorKind::NotFound => {}

        Err(error) => return Err(error),
    }

    for entry in fs::read_dir(dir)? {
        let path = entry?.path();

        if fs::symlink_metadata(&path)?.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::time::SystemTime;

    use super::*;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("picoguard-stage-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        dir
    }

    #[test]
    fn cleaning_never_follows_a_link_in_place_of_the_directory() {
        let root = scratch_dir("link");
        let outside = root.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("request"), b"kept").unwrap();
        fs::write(outside.join("other"), b"kept").unwrap();
        symlink(&outside, root.join("update")).unwrap();

        assert!(empty_dir(&root.join("update")).is_err());
        assert_eq!(fs::read(outside.join("request")).unwrap(), b"kept");
        assert_eq!(fs::read(outside.join("other")).unwrap(), b"kept");

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn cleaning_empties_a_real_directory_and_leaves_links_unfollowed() {
        let root = scratch_dir("real");
        let outside = root.join("outside");
        let staging = root.join("update");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("file"), b"kept").unwrap();
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("request"), b"x").unwrap();
        fs::write(staging.join("picoguard.part"), b"x").unwrap();
        fs::create_dir(staging.join("sub")).unwrap();
        fs::write(staging.join("sub/inner"), b"x").unwrap();
        symlink(&outside, staging.join("link")).unwrap();

        empty_dir(&staging).unwrap();

        assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
        assert_eq!(fs::read(outside.join("file")).unwrap(), b"kept");

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_wait_left_never_underflows() {
        let wait = Duration::from_secs(600);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000);
        let written = |age: Duration| now - age;

        assert_eq!(wait_left(wait, now + Duration::from_secs(5), now), wait);
        assert_eq!(wait_left(wait, written(Duration::ZERO), now), wait);
        assert_eq!(
            wait_left(wait, written(Duration::from_secs(100)), now),
            Duration::from_secs(500)
        );
        assert_eq!(wait_left(wait, written(wait), now), Duration::ZERO);
        assert_eq!(
            wait_left(wait, written(wait + Duration::from_secs(1)), now),
            Duration::ZERO
        );
        assert_eq!(
            wait_left(wait, written(Duration::from_secs(24 * 3600)), now),
            Duration::ZERO
        );
    }
}
