//! What the daemon and the root installer share about a release (plan D2-D8): the built-in
//! key, the target and asset names, `SHA256SUMS` and signature checks, and the request and
//! result files that carry an update between them.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ring::digest;
use ring::signature::{ED25519, UnparsedPublicKey};

use crate::update::{Tag, is_newer, parse_running, parse_tag};
use crate::upstream::random_u64;

const KEY_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The array type makes a file of another length a compile error.
const KEY_DER: &[u8; 44] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/dist/release-key.der"));

const _: () = assert!(
    has_key_prefix(KEY_DER),
    "dist/release-key.der is not an Ed25519 public key in DER form"
);

/// The one key that signs releases. Nothing at run time can replace it.
pub const RELEASE_KEY: [u8; 32] = raw_key(KEY_DER);

const fn has_key_prefix(der: &[u8; 44]) -> bool {
    let mut index = 0;

    while index < KEY_PREFIX.len() {
        if der[index] != KEY_PREFIX[index] {
            return false;
        }

        index += 1;
    }

    true
}

const fn raw_key(der: &[u8; 44]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut index = 0;

    while index < key.len() {
        key[index] = der[KEY_PREFIX.len() + index];
        index += 1;
    }

    key
}

pub const MAX_BINARY_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_SUMS_BYTES: u64 = 16 * 1024;
const SIGNATURE_BYTES: u64 = 64;

const VERSION_RUN_LIMIT: Duration = Duration::from_secs(10);
const VERSION_POLL: Duration = Duration::from_millis(50);
const VERSION_OUTPUT_BYTES: u64 = 256;
/// `ETXTBSY`: another thread's `fork` can briefly hold the file we just wrote open.
const TEXT_FILE_BUSY: i32 = 26;
const SPAWN_ATTEMPTS: usize = 5;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

const REQUEST_MAX_BYTES: usize = 256;
const RESULT_MAX_BYTES: usize = 1024;
const REASON_MAX_CHARS: usize = 200;
const ID_LENGTH: usize = 16;

pub fn target_for(arch: &str, env: &str, os: &str) -> Option<&'static str> {
    match (arch, env, os) {
        ("x86_64", "musl", "linux") => Some("x86_64-unknown-linux-musl"),
        ("aarch64", "musl", "linux") => Some("aarch64-unknown-linux-musl"),
        ("arm", "musl", "linux") => Some("armv7-unknown-linux-musleabihf"),
        _ => None,
    }
}

/// The release target this binary was compiled for, when it is one of the three that
/// `scripts/build-release.sh` makes.
pub fn target() -> Option<&'static str> {
    const ENV: &str = if cfg!(target_env = "musl") {
        "musl"
    } else if cfg!(target_env = "gnu") {
        "gnu"
    } else {
        ""
    };

    target_for(std::env::consts::ARCH, ENV, std::env::consts::OS)
}

/// The file name of a release binary, in the download URL and in `SHA256SUMS`.
pub fn asset(target: &str) -> String {
    format!("picoguard-{target}")
}

pub fn verify_sums(sums: &[u8], signature: &[u8], key: &[u8; 32]) -> bool {
    signature.len() == 64
        && UnparsedPublicKey::new(&ED25519, key)
            .verify(sums, signature)
            .is_ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SumsError {
    NoBinary,
    Ambiguous,
}

/// The hash `SHA256SUMS` gives for this target's binary. A line is 64 hex digits, two
/// spaces or a space and `*`, and the name; lines for other names are not looked at.
pub fn expected_hash(sums: &[u8], target: &str) -> Result<[u8; 32], SumsError> {
    let name = asset(target);
    let mut found = None;

    for line in sums.split(|byte| *byte == b'\n') {
        let Some(hash) = hash_of_line(line, name.as_bytes()) else {
            continue;
        };

        if found.replace(hash).is_some() {
            return Err(SumsError::Ambiguous);
        }
    }

    found.ok_or(SumsError::NoBinary)
}

fn hash_of_line(line: &[u8], name: &[u8]) -> Option<[u8; 32]> {
    let (hex, rest) = line.split_at_checked(64)?;
    let rest = rest
        .strip_prefix(b"  ")
        .or_else(|| rest.strip_prefix(b" *"))?;

    if rest != name {
        return None;
    }

    let mut hash = [0u8; 32];

    let (pairs, _) = hex.as_chunks::<2>();

    for (byte, [high, low]) in hash.iter_mut().zip(pairs) {
        *byte = hex_digit(*high)? << 4 | hex_digit(*low)?;
    }

    Some(hash)
}

fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// `S/update/request`: which update the installer is asked to install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub id: String,
    pub version: String,
}

impl Request {
    pub fn new_random(version: &str) -> Request {
        Request {
            id: format!("{:016x}", random_u64()),
            version: version.to_string(),
        }
    }

    pub fn format(&self) -> String {
        format!("id={}\nversion={}\n", self.id, self.version)
    }

    /// Exactly the two lines of the contract and nothing else.
    pub fn parse(bytes: &[u8]) -> Option<Request> {
        if bytes.len() > REQUEST_MAX_BYTES {
            return None;
        }

        let text = std::str::from_utf8(bytes).ok()?;
        let rest = text.strip_prefix("id=")?;
        let (id, rest) = rest.split_once('\n')?;
        let version = rest.strip_prefix("version=")?.strip_suffix('\n')?;

        if !is_id(id) || version.contains('\n') || version.starts_with('v') {
            return None;
        }

        match parse_tag(version) {
            Tag::Release(_) => Some(Request {
                id: id.to_string(),
                version: version.to_string(),
            }),
            Tag::Suffixed | Tag::Invalid => None,
        }
    }
}

fn is_id(text: &str) -> bool {
    text.len() == ID_LENGTH
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// What the installer says happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Updated,
    RolledBack(String),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallerResult {
    pub id: String,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reading {
    Answer(InstallerResult),
    /// The file is not a result. It still has an `id` to fail when exactly one well-formed
    /// `id` line was found, so the update it answers does not wait for ever.
    Unreadable {
        id: Option<String>,
    },
}

impl InstallerResult {
    /// `key=value` lines; keys this version does not know are ignored, but no key may
    /// repeat.
    pub fn parse(bytes: &[u8]) -> Reading {
        if bytes.len() > RESULT_MAX_BYTES {
            return Reading::Unreadable { id: None };
        }

        let mut seen: Vec<&[u8]> = Vec::new();
        let mut id_lines = 0;
        let mut id = None;
        let mut outcome = None;
        let mut reason = None;
        let mut has_repeat = false;

        for line in bytes.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }

            let Some(split) = line.iter().position(|byte| *byte == b'=') else {
                has_repeat = true;

                continue;
            };
            let (key, value) = (&line[..split], &line[split + 1..]);

            has_repeat |= seen.contains(&key);
            seen.push(key);

            match key {
                b"id" => {
                    id_lines += 1;
                    id = Some(value);
                }
                b"outcome" => outcome = Some(value),
                b"reason" => reason = Some(value),
                _ => {}
            }
        }

        let id = id
            .filter(|_| id_lines == 1)
            .and_then(|value| std::str::from_utf8(value).ok())
            .filter(|value| is_id(value))
            .map(str::to_string);
        let unreadable = |id: Option<String>| Reading::Unreadable { id };

        if has_repeat {
            return unreadable(id);
        }

        let Some(id) = id else {
            return unreadable(None);
        };
        let reason = reason
            .map(printable_reason)
            .filter(|reason| !reason.is_empty());

        let outcome = match (outcome, reason) {
            (Some(b"updated"), _) => Outcome::Updated,
            (Some(b"rolled-back"), Some(reason)) => Outcome::RolledBack(reason),
            (Some(b"failed"), Some(reason)) => Outcome::Failed(reason),
            _ => return unreadable(Some(id)),
        };

        Reading::Answer(InstallerResult { id, outcome })
    }
}

/// One line of printable ASCII, cut to the length the page shows.
fn printable_reason(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(REASON_MAX_CHARS)
        .map(|byte| match byte {
            0x20..=0x7e => *byte as char,
            _ => '?',
        })
        .collect()
}

/// Opens a file that an untrusted user may have changed. A symbolic link as the last
/// component is refused, and a FIFO opens at once instead of waiting for a writer, so what
/// passes is a regular file of at most `cap` bytes whenever it was opened.
pub fn open_regular(path: &Path, cap: u64) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;

    if !metadata.is_file() {
        return Err(io::Error::other("not a regular file"));
    }

    if metadata.len() > cap {
        return Err(io::Error::other("larger than allowed"));
    }

    Ok(file)
}

/// The whole of a file `open_regular` accepts. It reads at most one byte past `cap`, so a file
/// that grew after the check is refused too.
pub fn read_regular(path: &Path, cap: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    open_regular(path, cap)?
        .take(cap + 1)
        .read_to_end(&mut bytes)?;

    if bytes.len() as u64 > cap {
        return Err(io::Error::other("larger than allowed"));
    }

    Ok(bytes)
}

pub struct VerifySetup {
    pub key: [u8; 32],
    /// `None` for a build that is not one of the three release builds.
    pub target: Option<&'static str>,
    /// The version of the binary that runs `verify-update`.
    pub running: &'static str,
}

#[derive(Debug)]
pub struct Refusal {
    /// One line of printable ASCII, at most 200 characters, never file content.
    pub reason: String,
    /// The staged request, when it was valid.
    pub request: Option<Request>,
}

impl Refusal {
    fn new(reason: &str, request: Option<&Request>) -> Refusal {
        Refusal {
            reason: one_line(reason),
            request: request.cloned(),
        }
    }
}

fn one_line(text: &str) -> String {
    printable_reason(text.as_bytes())
}

/// Copies a staged update out of a directory that the daemon's user can change, into a new
/// directory of ours, and checks the copy (spec: `verify-update`, steps 1-6).
pub fn verify_update(staged: &Path, into: &Path, setup: &VerifySetup) -> Result<Request, Refusal> {
    let Some(target) = setup.target else {
        return Err(Refusal::new("this build cannot verify updates", None));
    };

    let request_bytes = read_regular(&staged.join("request"), REQUEST_MAX_BYTES as u64)
        .map_err(|error| Refusal::new(&format!("request: {error}"), None))?;
    let request = Request::parse(&request_bytes)
        .ok_or_else(|| Refusal::new("request: not in the expected form", None))?;
    let refuse = |reason: String| Refusal::new(&reason, Some(&request));

    let into = destination(into).map_err(refuse)?;

    if let Err(error) = DirBuilder::new().mode(0o700).create(&into) {
        return Err(refuse(format!("into-dir: cannot create it: {error}")));
    }

    match copy_and_check(staged, &into, &request_bytes, &request, setup, target) {
        Ok(()) => Ok(request),

        Err(reason) => {
            let _ = fs::remove_dir_all(&into);

            Err(refuse(reason))
        }
    }
}

/// The path to create: absolute, not there yet, and below directories that nobody but root
/// or this user can rename or replace. Only the path returned here is used afterwards, so a
/// symbolic link in the caller's spelling cannot be re-pointed to redirect the writes, the
/// run and the cleanup.
fn destination(into: &Path) -> Result<PathBuf, String> {
    let into = std::path::absolute(into).map_err(|error| format!("into-dir: {error}"))?;

    if fs::symlink_metadata(&into).is_ok() {
        return Err("into-dir: already exists".to_string());
    }

    let (Some(parent), Some(name)) = (into.parent(), into.file_name()) else {
        return Err("into-dir: has no parent directory".to_string());
    };
    let parent = fs::canonicalize(parent)
        .map_err(|error| format!("into-dir: the parent directory: {error}"))?;
    let uid = caller_uid().map_err(|error| format!("into-dir: cannot tell the user: {error}"))?;

    for directory in parent.ancestors() {
        let metadata = fs::metadata(directory)
            .map_err(|error| format!("into-dir: a directory above it: {error}"))?;
        let is_ours = metadata.uid() == 0 || metadata.uid() == uid;

        if !metadata.is_dir() || !is_ours || metadata.mode() & 0o022 != 0 {
            return Err(
                "into-dir: the parent or a directory above it can be changed by others".to_string(),
            );
        }
    }

    Ok(parent.join(name))
}

/// The effective user id: the second number of the `Uid:` line.
fn caller_uid() -> io::Result<u32> {
    let status = fs::read_to_string("/proc/self/status")?;

    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|numbers| numbers.split_whitespace().nth(1))
        .and_then(|number| number.parse().ok())
        .ok_or_else(|| io::Error::other("no Uid line in /proc/self/status"))
}

fn create_private(path: &Path, mode: u32) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
}

fn copy_small(staged: &Path, into: &Path, name: &str, cap: u64) -> Result<Vec<u8>, String> {
    let bytes =
        read_regular(&staged.join(name), cap).map_err(|error| format!("{name}: {error}"))?;
    let mut file =
        create_private(&into.join(name), 0o600).map_err(|error| format!("{name}: {error}"))?;
    file.write_all(&bytes)
        .map_err(|error| format!("{name}: {error}"))?;

    Ok(bytes)
}

fn copy_and_check(
    staged: &Path,
    into: &Path,
    request_bytes: &[u8],
    request: &Request,
    setup: &VerifySetup,
    target: &str,
) -> Result<(), String> {
    create_private(&into.join("request"), 0o600)
        .and_then(|mut file| file.write_all(request_bytes))
        .map_err(|error| format!("request: {error}"))?;
    let sums = copy_small(staged, into, "SHA256SUMS", MAX_SUMS_BYTES)?;
    let signature = copy_small(staged, into, "SHA256SUMS.sig", SIGNATURE_BYTES)?;
    let binary_hash = copy_binary(&staged.join("picoguard"), &into.join("picoguard"))?;

    let offered = match parse_tag(&request.version) {
        Tag::Release(version) => version,
        Tag::Suffixed | Tag::Invalid => return Err("request: not a version".to_string()),
    };
    let running = parse_running(setup.running)
        .ok_or_else(|| "version: this binary's own version is not readable".to_string())?;

    if !is_newer(offered, running) {
        return Err(format!(
            "version: {offered} is not newer than {}",
            setup.running
        ));
    }

    if !verify_sums(&sums, &signature, &setup.key) {
        return Err("signature: SHA256SUMS is not signed by the release key".to_string());
    }

    let expected = expected_hash(&sums, target).map_err(|error| match error {
        SumsError::NoBinary => format!("the release has no binary for {target}"),
        SumsError::Ambiguous => format!("SHA256SUMS lists {} more than once", asset(target)),
    })?;

    if binary_hash.as_ref() != expected {
        return Err("the binary does not match SHA256SUMS".to_string());
    }

    run_version(&into.join("picoguard"), &request.version)
}

/// Copies the binary in pieces and returns the hash of the bytes it wrote.
fn copy_binary(from: &Path, to: &Path) -> Result<digest::Digest, String> {
    let fail = |error: io::Error| format!("picoguard: {error}");

    let source = open_regular(from, MAX_BINARY_BYTES).map_err(fail)?;
    let mut source = source.take(MAX_BINARY_BYTES + 1);
    let mut target = create_private(to, 0o700).map_err(fail)?;
    let mut hash = digest::Context::new(&digest::SHA256);
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    let mut total = 0u64;

    loop {
        let read = source.read(&mut buffer).map_err(fail)?;

        if read == 0 {
            break;
        }

        total += read as u64;

        if total > MAX_BINARY_BYTES {
            return Err("picoguard: larger than allowed".to_string());
        }

        hash.update(&buffer[..read]);
        target.write_all(&buffer[..read]).map_err(fail)?;
    }

    target.flush().map_err(fail)?;

    Ok(hash.finish())
}

/// The copy must print its own version: a genuine release of another version, signed and
/// served under a newer tag, fails here.
fn run_version(binary: &Path, version: &str) -> Result<(), String> {
    let mut child = spawn_version(binary)?;
    let deadline = Instant::now() + VERSION_RUN_LIMIT;

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,

            Ok(None) if Instant::now() < deadline => std::thread::sleep(VERSION_POLL),

            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();

                return Err("picoguard --version did not finish within 10 seconds".to_string());
            }

            Err(error) => return Err(format!("picoguard --version: {error}")),
        }
    };

    let mut output = Vec::new();

    if let Some(stdout) = child.stdout.take() {
        stdout
            .take(VERSION_OUTPUT_BYTES + 1)
            .read_to_end(&mut output)
            .map_err(|error| format!("picoguard --version: {error}"))?;
    }

    if status.success() && output == format!("picoguard {version}\n").as_bytes() {
        return Ok(());
    }

    Err("picoguard --version printed another version or failed".to_string())
}

fn spawn_version(binary: &Path) -> Result<std::process::Child, String> {
    let mut attempt = 1;

    loop {
        let spawned = Command::new(binary)
            .arg("--version")
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();

        match spawned {
            Ok(child) => return Ok(child),

            Err(error)
                if error.raw_os_error() == Some(TEXT_FILE_BUSY) && attempt < SPAWN_ATTEMPTS =>
            {
                attempt += 1;
                std::thread::sleep(VERSION_POLL);
            }

            Err(error) => return Err(format!("picoguard --version: {error}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::*;

    fn test_pair(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
    }

    fn public_key(pair: &Ed25519KeyPair) -> [u8; 32] {
        pair.public_key().as_ref().try_into().unwrap()
    }

    const TARGET: &str = "x86_64-unknown-linux-musl";

    fn hex(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    #[test]
    fn the_built_in_key_is_the_key_file() {
        let key_file = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/dist/release-key.der"));

        assert_eq!(RELEASE_KEY, key_file[12..]);
        assert_ne!(RELEASE_KEY, public_key(&test_pair(7)));
    }

    #[test]
    fn only_a_signature_by_the_key_over_the_exact_sums_verifies() {
        let pair = test_pair(7);
        let key = public_key(&pair);
        let sums = b"abc  picoguard\n";
        let signature = pair.sign(sums);

        assert!(verify_sums(sums, signature.as_ref(), &key));
        assert!(!verify_sums(b"abd  picoguard\n", signature.as_ref(), &key));
        assert!(!verify_sums(sums, test_pair(8).sign(sums).as_ref(), &key));
        assert!(!verify_sums(sums, &signature.as_ref()[..63], &key));

        let mut longer = signature.as_ref().to_vec();
        longer.push(0);
        assert!(!verify_sums(sums, &longer, &key));
    }

    #[test]
    fn sums_give_one_hash_per_asset() {
        let asset = asset(TARGET);
        let hash = |byte: u8| [byte; 32];

        assert_eq!(
            expected_hash(format!("{}  {asset}\n", hex(1)).as_bytes(), TARGET),
            Ok(hash(1))
        );
        assert_eq!(
            expected_hash(format!("{} *{asset}\n", hex(2)).as_bytes(), TARGET),
            Ok(hash(2))
        );
        assert_eq!(
            expected_hash(
                format!("{}  {asset}\n", hex(0xab).to_uppercase()).as_bytes(),
                TARGET
            ),
            Ok(hash(0xab))
        );
        assert_eq!(
            expected_hash(
                format!("{}  other\n{}  {asset}\nnot a line\n", hex(9), hex(3)).as_bytes(),
                TARGET
            ),
            Ok(hash(3))
        );
        assert_eq!(
            expected_hash(format!("{}  other\n", hex(1)).as_bytes(), TARGET),
            Err(SumsError::NoBinary)
        );
        assert_eq!(
            expected_hash(
                format!("{}  {asset}\n{} *{asset}\n", hex(1), hex(2)).as_bytes(),
                TARGET
            ),
            Err(SumsError::Ambiguous)
        );
        assert_eq!(
            expected_hash(format!("{}  {asset}\n", &hex(1)[1..]).as_bytes(), TARGET),
            Err(SumsError::NoBinary)
        );
        assert_eq!(
            expected_hash(format!("{}  {asset}x\n", hex(1)).as_bytes(), TARGET),
            Err(SumsError::NoBinary)
        );
    }

    #[test]
    fn targets_cover_the_three_release_builds() {
        assert_eq!(
            target_for("x86_64", "musl", "linux"),
            Some("x86_64-unknown-linux-musl")
        );
        assert_eq!(
            target_for("aarch64", "musl", "linux"),
            Some("aarch64-unknown-linux-musl")
        );
        assert_eq!(
            target_for("arm", "musl", "linux"),
            Some("armv7-unknown-linux-musleabihf")
        );
        assert_eq!(target_for("x86_64", "gnu", "linux"), None);
        assert_eq!(target_for("riscv64", "musl", "linux"), None);
        assert_eq!(target_for("x86_64", "musl", "macos"), None);
        assert_eq!(
            asset("x86_64-unknown-linux-musl"),
            "picoguard-x86_64-unknown-linux-musl"
        );
    }

    #[test]
    fn requests_are_written_and_read_strictly() {
        let request = Request::new_random("0.3.0");

        assert_eq!(request.version, "0.3.0");
        assert_eq!(request.id.len(), 16);
        assert_eq!(Request::parse(request.format().as_bytes()), Some(request));

        let good = "id=0123456789abcdef\nversion=0.3.0\n";
        assert!(Request::parse(good.as_bytes()).is_some());

        for bad in [
            "id=0123456789abcdef\nversion=0.3.0\nextra=1\n",
            "id=0123456789abcdef\nversion=0.3.0",
            "id=0123456789abcdef\r\nversion=0.3.0\r\n",
            "id=0123456789ABCDEF\nversion=0.3.0\n",
            "id=0123456789abcde\nversion=0.3.0\n",
            "id=0123456789abcdef\nversion=v0.3.0\n",
            "id=0123456789abcdef\nversion=0.3\n",
            "id=0123456789abcdef\nversion=0.3.0-rc.1\n",
            "version=0.3.0\nid=0123456789abcdef\n",
            "",
        ] {
            assert_eq!(Request::parse(bad.as_bytes()), None, "{bad:?}");
        }

        let fits = format!("id=0123456789abcdef\nversion=0.3.{}\n", "0".repeat(223));
        assert_eq!(fits.len(), 256);
        assert!(Request::parse(fits.as_bytes()).is_some());
        let too_long = format!("id=0123456789abcdef\nversion=0.3.{}\n", "0".repeat(224));
        assert_eq!(too_long.len(), 257);
        assert_eq!(Request::parse(too_long.as_bytes()), None);
    }

    fn read(text: &str) -> Reading {
        InstallerResult::parse(text.as_bytes())
    }

    fn answer(id: &str, outcome: Outcome) -> Reading {
        Reading::Answer(InstallerResult {
            id: id.to_string(),
            outcome,
        })
    }

    const ID: &str = "0123456789abcdef";

    #[test]
    fn results_are_read_by_id_and_outcome() {
        assert_eq!(
            read(&format!("id={ID}\noutcome=updated\n")),
            answer(ID, Outcome::Updated)
        );
        assert_eq!(
            read(&format!(
                "id={ID}\noutcome=rolled-back\nreason=the DNS check failed\n"
            )),
            answer(ID, Outcome::RolledBack("the DNS check failed".to_string()))
        );
        assert_eq!(
            read(&format!("id={ID}\noutcome=failed\nreason=no space\n")),
            answer(ID, Outcome::Failed("no space".to_string()))
        );
        assert_eq!(
            read(&format!("id={ID}\noutcome=updated\nfuture=1\n")),
            answer(ID, Outcome::Updated)
        );

        let unreadable_with_id = Reading::Unreadable {
            id: Some(ID.to_string()),
        };
        assert_eq!(
            read(&format!("id={ID}\noutcome=failed\n")),
            unreadable_with_id
        );
        assert_eq!(
            read(&format!("id={ID}\noutcome=maybe\n")),
            unreadable_with_id
        );
        assert_eq!(read(&format!("id={ID}\n")), unreadable_with_id);
        assert_eq!(
            read(&format!("id={ID}\noutcome=updated\nfuture=1\nfuture=2\n")),
            unreadable_with_id
        );
        assert_eq!(
            read(&format!("id={ID}\nid={ID}\noutcome=updated\n")),
            Reading::Unreadable { id: None }
        );
        assert_eq!(read("outcome=updated\n"), Reading::Unreadable { id: None });

        let exact = format!(
            "id={ID}\noutcome=updated\nfuture={}\n",
            "x".repeat(1024 - 44)
        );
        assert_eq!(exact.len(), 1024);
        assert_eq!(read(&exact), answer(ID, Outcome::Updated));
        assert!(matches!(
            read(&format!("{exact}\n")),
            Reading::Unreadable { .. }
        ));

        assert_eq!(
            read(&format!(
                "id={ID}\noutcome=failed\nreason={}\n",
                "r".repeat(300)
            )),
            answer(ID, Outcome::Failed("r".repeat(200)))
        );
        assert_eq!(
            InstallerResult::parse(
                format!("id={ID}\noutcome=failed\nreason=a\u{1}b\u{e9}c\n").as_bytes()
            ),
            answer(ID, Outcome::Failed("a?b??c".to_string()))
        );
    }
}
