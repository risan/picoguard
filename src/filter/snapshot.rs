//! Snapshot files: the compiled form of a list on disk (plan D14).
//!
//! A snapshot holds the sorted hash arrays of one list, so a restart skips the download and
//! the compile. The file is written only when the list's fingerprint changed, through a
//! temporary file, `fsync`, rename and a sync of the directory, by a thread of its own.
//!
//! Layout, all integers little-endian:
//!
//! ```text
//! magic[8] file_version u32
//! body: fingerprint u128, content_hash u128, compiler_version u32, configured_format u8,
//!       effective_format u8, max_rules u32, source, etag?, last_modified?,
//!       counters (u64 each), first_invalid?, regex_failed u64,
//!       6 plain-rule arrays (u64 length, u64 hashes),
//!       host groups (u32 count; IP text, u64 length, u64 hashes),
//!       slow rules (u32 count; flags u8, content types u32, pattern, record types,
//!       deny-allow names, client and tag keys)
//! checksum u128   -- xxh3-128 of the body
//! ```
//!
//! Strings are a u32 length and UTF-8 text. Every length is checked against the limits of
//! plan D12 before anything is allocated.

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{mpsc, oneshot};
use xxhash_rust::xxh3::{Xxh3, xxh3_64, xxh3_128};

use super::compile::{COMPILER_VERSION, CompileOptions, Compiled, SlowRuleBudget};
use super::engine::{CompiledList, FAST_KINDS, HostGroup, SlowRule};
use super::parse::{Counters, ListFormat, MAX_LINE_BYTES, NetworkRule};
use crate::lists::Validators;

pub const FILE_VERSION: u32 = 1;

const MAGIC: [u8; 8] = *b"PICOSNAP";
const PREAMBLE_BYTES: u64 = 12;
const CHECKSUM_BYTES: u64 = 16;
const IO_BUFFER_BYTES: usize = 64 * 1024;

/// Longest source URL, validator or key. Rule text is limited by the line cap instead.
const MAX_TEXT_BYTES: usize = 16 * 1024;

const COUNTERS: usize = 23;
const WHITELIST: u8 = 1;
const IMPORTANT: u8 = 2;
const BADFILTER: u8 = 4;

#[derive(Debug)]
pub enum SnapshotError {
    Io(io::Error),
    BadMagic,
    BadVersion(u32),
    /// Written by another compiler version, so its meaning may differ.
    OldCompiler(u32),
    Truncated,
    /// A length field above the limits of plan D12.
    TooLarge(&'static str),
    Corrupt(&'static str),
    BadChecksum,
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotError::Io(error) => {
                write!(formatter, "{error}")
            }

            SnapshotError::BadMagic => {
                write!(formatter, "not a snapshot file")
            }

            SnapshotError::BadVersion(version) => {
                write!(formatter, "unknown snapshot file version {version}")
            }

            SnapshotError::OldCompiler(version) => {
                write!(formatter, "made by compiler version {version}")
            }

            SnapshotError::Truncated => {
                write!(formatter, "file is too short")
            }

            SnapshotError::TooLarge(what) => {
                write!(formatter, "{what} is over its limit")
            }

            SnapshotError::Corrupt(what) => {
                write!(formatter, "corrupt: {what}")
            }

            SnapshotError::BadChecksum => {
                write!(formatter, "checksum mismatch")
            }
        }
    }
}

impl std::error::Error for SnapshotError {}

impl From<io::Error> for SnapshotError {
    fn from(error: io::Error) -> SnapshotError {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            return SnapshotError::Truncated;
        }

        SnapshotError::Io(error)
    }
}

/// What a snapshot is keyed by, and what the next request needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub fingerprint: u128,
    pub content_hash: u128,
    pub compiler_version: u32,
    /// The `format` of the list config (possibly `auto`) and the format that was used.
    pub configured_format: ListFormat,
    pub effective_format: ListFormat,
    pub max_rules: u32,
    /// URL or path of the list.
    pub source: String,
    pub validators: Validators,
}

pub struct Snapshot {
    pub meta: Meta,
    pub list: Arc<CompiledList>,
    pub counters: Counters,
}

/// The fingerprint of plan D14: source content, effective format, per-list options
/// (configured format and rule cap) and the compiler version.
pub fn fingerprint(
    content_hash: u128,
    configured_format: ListFormat,
    effective_format: ListFormat,
    max_rules: u32,
    compiler_version: u32,
) -> u128 {
    let mut parts = Vec::with_capacity(26);
    parts.extend_from_slice(&content_hash.to_le_bytes());
    parts.push(format_code(configured_format));
    parts.push(format_code(effective_format));
    parts.extend_from_slice(&max_rules.to_le_bytes());
    parts.extend_from_slice(&compiler_version.to_le_bytes());

    xxh3_128(&parts)
}

fn format_code(format: ListFormat) -> u8 {
    match format {
        ListFormat::Auto => 0,
        ListFormat::Adblock => 1,
        ListFormat::Hosts => 2,
        ListFormat::Domains => 3,
        ListFormat::Wildcard => 4,
        ListFormat::Dnsmasq => 5,
        ListFormat::Rpz => 6,
    }
}

fn format_from_code(code: u8) -> Result<ListFormat, SnapshotError> {
    match code {
        0 => Ok(ListFormat::Auto),
        1 => Ok(ListFormat::Adblock),
        2 => Ok(ListFormat::Hosts),
        3 => Ok(ListFormat::Domains),
        4 => Ok(ListFormat::Wildcard),
        5 => Ok(ListFormat::Dnsmasq),
        6 => Ok(ListFormat::Rpz),
        _ => Err(SnapshotError::Corrupt("unknown list format")),
    }
}

impl Snapshot {
    pub fn new(
        compiled: &Compiled,
        options: &CompileOptions,
        source: &str,
        validators: Validators,
    ) -> Snapshot {
        Snapshot {
            meta: Meta {
                fingerprint: compiled.fingerprint,
                content_hash: compiled.content_hash,
                compiler_version: COMPILER_VERSION,
                configured_format: options.format,
                effective_format: compiled.summary.format,
                max_rules: options.max_rules,
                source: source.to_string(),
                validators,
            },
            list: Arc::clone(&compiled.list),
            counters: compiled.summary.counters.clone(),
        }
    }

    /// True when this snapshot was made for the list as the config describes it now, so it
    /// can serve until the next download.
    pub fn fits(&self, source: &str, options: &CompileOptions) -> bool {
        self.meta.source == source
            && self.meta.configured_format == options.format
            && self.meta.max_rules == options.max_rules
    }
}

fn counter_values(counters: &Counters) -> [u64; COUNTERS] {
    [
        counters.lines,
        counters.empty,
        counters.comments,
        counters.cosmetic,
        counters.headers,
        counters.host_names,
        counters.unmatchable_hosts,
        counters.block_sub,
        counters.block_exact,
        counters.allow_sub,
        counters.allow_exact,
        counters.strict_sub_block,
        counters.strict_sub_allow,
        counters.slow_rules,
        counters.regex_rules,
        counters.badfilter_rules,
        counters.not_dns,
        counters.unsupported,
        counters.invalid,
        counters.non_utf8,
        counters.too_long,
        counters.rpz_skipped,
        counters.over_cap,
    ]
}

fn counters_from(values: [u64; COUNTERS], first_invalid: Option<String>) -> Counters {
    let [
        lines,
        empty,
        comments,
        cosmetic,
        headers,
        host_names,
        unmatchable_hosts,
        block_sub,
        block_exact,
        allow_sub,
        allow_exact,
        strict_sub_block,
        strict_sub_allow,
        slow_rules,
        regex_rules,
        badfilter_rules,
        not_dns,
        unsupported,
        invalid,
        non_utf8,
        too_long,
        rpz_skipped,
        over_cap,
    ] = values;

    Counters {
        lines,
        empty,
        comments,
        cosmetic,
        headers,
        host_names,
        unmatchable_hosts,
        block_sub,
        block_exact,
        allow_sub,
        allow_exact,
        strict_sub_block,
        strict_sub_allow,
        slow_rules,
        regex_rules,
        badfilter_rules,
        not_dns,
        unsupported,
        invalid,
        non_utf8,
        too_long,
        rpz_skipped,
        over_cap,
        first_invalid,
    }
}

// ---- Writing ----

struct Encoder<W: Write> {
    out: W,
    hasher: Xxh3,
    bytes: u64,
}

impl<W: Write> Encoder<W> {
    fn raw(&mut self, data: &[u8]) -> io::Result<()> {
        self.out.write_all(data)?;
        self.hasher.update(data);
        self.bytes += data.len() as u64;

        Ok(())
    }

    fn u8(&mut self, value: u8) -> io::Result<()> {
        self.raw(&[value])
    }

    fn u32(&mut self, value: u32) -> io::Result<()> {
        self.raw(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> io::Result<()> {
        self.raw(&value.to_le_bytes())
    }

    fn u128(&mut self, value: u128) -> io::Result<()> {
        self.raw(&value.to_le_bytes())
    }

    fn text(&mut self, text: &str) -> io::Result<()> {
        self.u32(text.len() as u32)?;

        self.raw(text.as_bytes())
    }

    fn optional_text(&mut self, text: &Option<String>) -> io::Result<()> {
        match text {
            Some(text) => {
                self.u8(1)?;

                self.text(text)
            }

            None => self.u8(0),
        }
    }

    fn u16s(&mut self, values: &[u16]) -> io::Result<()> {
        self.u32(values.len() as u32)?;
        for value in values {
            self.raw(&value.to_le_bytes())?;
        }

        Ok(())
    }

    fn texts(&mut self, values: &[String]) -> io::Result<()> {
        self.u32(values.len() as u32)?;
        for value in values {
            self.text(value)?;
        }

        Ok(())
    }

    fn u64s(&mut self, values: &[u64]) -> io::Result<()> {
        self.u64(values.len() as u64)?;

        let mut buffer = [0u8; 8192];
        for chunk in values.chunks(buffer.len() / 8) {
            for (slot, value) in buffer.as_chunks_mut::<8>().0.iter_mut().zip(chunk) {
                slot.copy_from_slice(&value.to_le_bytes());
            }

            self.raw(&buffer[..chunk.len() * 8])?;
        }

        Ok(())
    }

    fn rule(&mut self, rule: &NetworkRule) -> io::Result<()> {
        let mut flags = 0;
        for (set, flag) in [
            (rule.whitelist, WHITELIST),
            (rule.important, IMPORTANT),
            (rule.badfilter, BADFILTER),
        ] {
            if set {
                flags |= flag;
            }
        }

        self.u8(flags)?;
        self.u32(rule.restricted_types)?;
        self.text(&rule.pattern)?;
        self.u16s(&rule.dns_permitted)?;
        self.u16s(&rule.dns_restricted)?;
        self.texts(&rule.denyallow)?;
        self.text(&rule.client_key)?;

        self.text(&rule.ctag_key)
    }
}

/// Writes the whole file and returns its size.
fn encode<W: Write>(snapshot: &Snapshot, mut out: W) -> io::Result<u64> {
    out.write_all(&MAGIC)?;
    out.write_all(&FILE_VERSION.to_le_bytes())?;

    let mut encoder = Encoder {
        out,
        hasher: Xxh3::new(),
        bytes: 0,
    };
    let meta = &snapshot.meta;
    encoder.u128(meta.fingerprint)?;
    encoder.u128(meta.content_hash)?;
    encoder.u32(meta.compiler_version)?;
    encoder.u8(format_code(meta.configured_format))?;
    encoder.u8(format_code(meta.effective_format))?;
    encoder.u32(meta.max_rules)?;
    encoder.text(&meta.source)?;
    encoder.optional_text(&meta.validators.etag)?;
    encoder.optional_text(&meta.validators.last_modified)?;

    for value in counter_values(&snapshot.counters) {
        encoder.u64(value)?;
    }

    encoder.optional_text(&snapshot.counters.first_invalid)?;

    let list = &snapshot.list;
    encoder.u64(list.regex_failed)?;
    for array in &list.fast {
        encoder.u64s(array)?;
    }

    encoder.u32(list.hosts.len() as u32)?;
    for group in &list.hosts {
        encoder.text(&group.ip.to_string())?;
        encoder.u64s(&group.names)?;
    }

    encoder.u32(list.slow.len() as u32)?;
    for slow in &list.slow {
        encoder.rule(&slow.rule)?;
    }

    let checksum = encoder.hasher.digest128();
    encoder.out.write_all(&checksum.to_le_bytes())?;
    encoder.out.flush()?;

    Ok(PREAMBLE_BYTES + encoder.bytes + CHECKSUM_BYTES)
}

// ---- Reading ----

struct Decoder<R: Read> {
    input: R,
    hasher: Xxh3,
    /// Body bytes the file still holds; no length field may ask for more.
    remaining: u64,
    /// Rules the list may still hold under its cap.
    rules_left: u64,
    slow_budget: SlowRuleBudget,
}

impl<R: Read> Decoder<R> {
    fn raw(&mut self, buffer: &mut [u8]) -> Result<(), SnapshotError> {
        if buffer.len() as u64 > self.remaining {
            return Err(SnapshotError::Truncated);
        }

        self.input.read_exact(buffer)?;
        self.hasher.update(buffer);
        self.remaining -= buffer.len() as u64;

        Ok(())
    }

    fn u8(&mut self) -> Result<u8, SnapshotError> {
        let mut bytes = [0u8; 1];
        self.raw(&mut bytes)?;

        Ok(bytes[0])
    }

    fn u16(&mut self) -> Result<u16, SnapshotError> {
        let mut bytes = [0u8; 2];
        self.raw(&mut bytes)?;

        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, SnapshotError> {
        let mut bytes = [0u8; 4];
        self.raw(&mut bytes)?;

        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, SnapshotError> {
        let mut bytes = [0u8; 8];
        self.raw(&mut bytes)?;

        Ok(u64::from_le_bytes(bytes))
    }

    fn u128(&mut self) -> Result<u128, SnapshotError> {
        let mut bytes = [0u8; 16];
        self.raw(&mut bytes)?;

        Ok(u128::from_le_bytes(bytes))
    }

    fn text(&mut self, limit: usize, what: &'static str) -> Result<String, SnapshotError> {
        let length = self.u32()? as usize;
        if length > limit {
            return Err(SnapshotError::TooLarge(what));
        }

        if length as u64 > self.remaining {
            return Err(SnapshotError::Truncated);
        }

        let mut bytes = vec![0u8; length];
        self.raw(&mut bytes)?;

        String::from_utf8(bytes).map_err(|_| SnapshotError::Corrupt("text is not UTF-8"))
    }

    fn optional_text(&mut self, what: &'static str) -> Result<Option<String>, SnapshotError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.text(MAX_TEXT_BYTES, what).map(Some),
            _ => Err(SnapshotError::Corrupt("bad presence flag")),
        }
    }

    /// A count of at most a rule line's worth of items.
    fn small_count(&mut self, what: &'static str) -> Result<usize, SnapshotError> {
        let count = self.u32()? as usize;
        if count > MAX_LINE_BYTES {
            return Err(SnapshotError::TooLarge(what));
        }

        Ok(count)
    }

    fn u16s(&mut self, what: &'static str) -> Result<Vec<u16>, SnapshotError> {
        let count = self.small_count(what)?;
        (0..count).map(|_| self.u16()).collect()
    }

    fn texts(&mut self, what: &'static str) -> Result<Vec<String>, SnapshotError> {
        let count = self.small_count(what)?;
        (0..count)
            .map(|_| self.text(MAX_LINE_BYTES, what))
            .collect()
    }

    /// Takes `count` rules from the budget of the list's cap.
    fn charge(&mut self, count: u64, what: &'static str) -> Result<(), SnapshotError> {
        if count > self.rules_left {
            return Err(SnapshotError::TooLarge(what));
        }

        self.rules_left -= count;

        Ok(())
    }

    fn u64s(&mut self, what: &'static str) -> Result<Vec<u64>, SnapshotError> {
        let length = self.u64()?;
        self.charge(length, what)?;
        if length.saturating_mul(8) > self.remaining {
            return Err(SnapshotError::Truncated);
        }

        let mut values = Vec::with_capacity(length as usize);
        let mut buffer = [0u8; 8192];
        let mut left = length as usize;
        while left > 0 {
            let count = left.min(buffer.len() / 8);
            self.raw(&mut buffer[..count * 8])?;
            values.extend(
                buffer[..count * 8]
                    .as_chunks::<8>()
                    .0
                    .iter()
                    .map(|bytes| u64::from_le_bytes(*bytes)),
            );
            left -= count;
        }

        Ok(values)
    }

    fn rule(&mut self) -> Result<SlowRule, SnapshotError> {
        let flags = self.u8()?;
        let restricted_types = self.u32()?;
        let rule = NetworkRule {
            whitelist: flags & WHITELIST != 0,
            important: flags & IMPORTANT != 0,
            badfilter: flags & BADFILTER != 0,
            restricted_types,
            pattern: self.text(MAX_LINE_BYTES, "rule pattern")?,
            dns_permitted: self.u16s("record types")?,
            dns_restricted: self.u16s("record types")?,
            denyallow: self.texts("deny-allow names")?,
            client_key: self.text(MAX_LINE_BYTES, "client key")?,
            ctag_key: self.text(MAX_LINE_BYTES, "tag key")?,
        };

        self.slow_budget
            .charge(&rule)
            .map_err(|_| SnapshotError::TooLarge("slow rule memory"))?;

        SlowRule::compile(rule).map_err(|()| SnapshotError::Corrupt("a rule does not compile"))
    }
}

/// Reads and checks a snapshot file against the caps of the list's options.
pub fn load(path: &Path, options: &CompileOptions) -> Result<Snapshot, SnapshotError> {
    let file = File::open(path)?;
    let length = file.metadata()?.len();
    if length < PREAMBLE_BYTES + CHECKSUM_BYTES {
        return Err(SnapshotError::Truncated);
    }

    let mut input = BufReader::with_capacity(IO_BUFFER_BYTES, file);
    let mut preamble = [0u8; PREAMBLE_BYTES as usize];
    input.read_exact(&mut preamble)?;
    if preamble[..8] != MAGIC {
        return Err(SnapshotError::BadMagic);
    }

    let version = u32::from_le_bytes(preamble[8..].try_into().expect("4 bytes"));
    if version != FILE_VERSION {
        return Err(SnapshotError::BadVersion(version));
    }

    let mut decoder = Decoder {
        input,
        hasher: Xxh3::new(),
        remaining: length - PREAMBLE_BYTES - CHECKSUM_BYTES,
        rules_left: u64::from(options.max_rules),
        slow_budget: SlowRuleBudget::new(options.slow_rule_budget),
    };
    let stored_fingerprint = decoder.u128()?;
    let content_hash = decoder.u128()?;
    let compiler_version = decoder.u32()?;
    let configured_format = format_from_code(decoder.u8()?)?;
    let effective_format = format_from_code(decoder.u8()?)?;
    let meta_max_rules = decoder.u32()?;
    let source = decoder.text(MAX_TEXT_BYTES, "source")?;
    let etag = decoder.optional_text("ETag")?;
    let last_modified = decoder.optional_text("Last-Modified")?;

    let mut values = [0u64; COUNTERS];
    for value in values.iter_mut() {
        *value = decoder.u64()?;
    }

    let first_invalid = decoder.optional_text("invalid line")?;
    let regex_failed = decoder.u64()?;

    let mut fast: [Vec<u64>; FAST_KINDS] = Default::default();
    for array in fast.iter_mut() {
        *array = decoder.u64s("plain rule array")?;
    }

    let group_count = decoder.u32()?;
    decoder.charge(u64::from(group_count), "host groups")?;
    let mut hosts = Vec::with_capacity(group_count as usize);
    for _ in 0..group_count {
        let ip: IpAddr = decoder
            .text(64, "host address")?
            .parse()
            .map_err(|_| SnapshotError::Corrupt("host address"))?;
        hosts.push(HostGroup {
            ip,
            names: decoder.u64s("host name array")?,
        });
    }

    let slow_count = decoder.u32()?;
    decoder.charge(u64::from(slow_count), "slow rules")?;
    let mut slow = Vec::with_capacity((slow_count as usize).min(decoder.remaining as usize));
    for _ in 0..slow_count {
        slow.push(decoder.rule()?);
    }

    if decoder.remaining != 0 {
        return Err(SnapshotError::Corrupt("data after the last rule"));
    }

    let mut stored = [0u8; CHECKSUM_BYTES as usize];
    decoder.input.read_exact(&mut stored)?;
    if u128::from_le_bytes(stored) != decoder.hasher.digest128() {
        return Err(SnapshotError::BadChecksum);
    }

    if compiler_version != COMPILER_VERSION {
        return Err(SnapshotError::OldCompiler(compiler_version));
    }

    let expected = fingerprint(
        content_hash,
        configured_format,
        effective_format,
        meta_max_rules,
        compiler_version,
    );
    if stored_fingerprint != expected {
        return Err(SnapshotError::Corrupt("fingerprint"));
    }

    Ok(Snapshot {
        meta: Meta {
            fingerprint: stored_fingerprint,
            content_hash,
            compiler_version,
            configured_format,
            effective_format,
            max_rules: meta_max_rules,
            source,
            validators: Validators {
                etag,
                last_modified,
            },
        },
        list: Arc::new(CompiledList {
            fast,
            hosts,
            slow,
            regex_failed,
        }),
        counters: counters_from(values, first_invalid),
    })
}

/// True when `path` is a complete, intact snapshot with this fingerprint. Reading is not
/// writing: this is how an unchanged list costs no write, and how a damaged file is noticed.
fn holds_fingerprint(path: &Path, fingerprint: u128) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let Ok(length) = file.metadata().map(|metadata| metadata.len()) else {
        return false;
    };
    if length < PREAMBLE_BYTES + 16 + CHECKSUM_BYTES {
        return false;
    }

    let mut preamble = [0u8; PREAMBLE_BYTES as usize];
    if file.read_exact(&mut preamble).is_err()
        || preamble[..8] != MAGIC
        || preamble[8..] != FILE_VERSION.to_le_bytes()
    {
        return false;
    }

    let mut hasher = Xxh3::new();
    let mut buffer = vec![0u8; IO_BUFFER_BYTES];
    let mut left = length - PREAMBLE_BYTES - CHECKSUM_BYTES;
    let mut stored_fingerprint = None;
    while left > 0 {
        let count = left.min(buffer.len() as u64) as usize;
        if file.read_exact(&mut buffer[..count]).is_err() {
            return false;
        }

        if stored_fingerprint.is_none() {
            let bytes: [u8; 16] = buffer[..16].try_into().expect("a first block of 16 bytes");
            stored_fingerprint = Some(u128::from_le_bytes(bytes));
        }

        hasher.update(&buffer[..count]);
        left -= count as u64;
    }

    let mut trailer = [0u8; CHECKSUM_BYTES as usize];
    file.read_exact(&mut trailer).is_ok()
        && u128::from_le_bytes(trailer) == hasher.digest128()
        && stored_fingerprint == Some(fingerprint)
}

// ---- The disk writer ----

enum WriteJob {
    Write {
        path: PathBuf,
        snapshot: Box<Snapshot>,
    },
    Barrier(oneshot::Sender<()>),
}

/// Where snapshots live and the thread that writes them. With persistence off it does
/// nothing and nothing is ever read or written.
pub struct SnapshotStore {
    directory: Option<PathBuf>,
    writer: Option<mpsc::Sender<WriteJob>>,
    written: Arc<AtomicU64>,
}

impl SnapshotStore {
    /// `state.persist_lists = false`.
    pub fn disabled() -> SnapshotStore {
        SnapshotStore {
            directory: None,
            writer: None,
            written: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Snapshots go to `<state_dir>/lists/`, created when the first one is written.
    pub fn open(state_dir: &Path) -> io::Result<SnapshotStore> {
        let (writer, jobs) = mpsc::channel(1);
        let written = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&written);
        std::thread::Builder::new()
            .name("picoguard-disk".to_string())
            .spawn(move || write_loop(jobs, &counter))?;

        Ok(SnapshotStore {
            directory: Some(state_dir.join("lists")),
            writer: Some(writer),
            written,
        })
    }

    /// The file for the list at `source`, or `None` with persistence off.
    pub fn path_for(&self, source: &str) -> Option<PathBuf> {
        let name = format!("{:016x}.pgs", xxh3_64(source.as_bytes()));

        self.directory
            .as_ref()
            .map(|directory| directory.join(name))
    }

    /// Queues the snapshot (one waiting at most, so this waits while the writer is busy).
    /// The writer writes it only if the file does not already hold its fingerprint.
    pub async fn save(&self, snapshot: Snapshot) {
        let (Some(writer), Some(path)) = (&self.writer, self.path_for(&snapshot.meta.source))
        else {
            return;
        };

        if writer
            .send(WriteJob::Write {
                path,
                snapshot: Box::new(snapshot),
            })
            .await
            .is_err()
        {
            log::warn!("the snapshot writer stopped");
        }
    }

    /// Returns when everything saved so far is on disk or has failed.
    pub async fn flush(&self) {
        let Some(writer) = &self.writer else {
            return;
        };

        let (done, wait) = oneshot::channel();
        if writer.send(WriteJob::Barrier(done)).await.is_ok() {
            let _ = wait.await;
        }
    }

    /// Bytes written to snapshot files since the store was opened.
    pub fn bytes_written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }
}

fn write_loop(mut jobs: mpsc::Receiver<WriteJob>, written: &AtomicU64) {
    while let Some(job) = jobs.blocking_recv() {
        match job {
            WriteJob::Write { path, snapshot } => match write_if_changed(&path, &snapshot) {
                Ok(bytes) => {
                    written.fetch_add(bytes, Ordering::Relaxed);
                }

                Err(error) => {
                    log::warn!("cannot write {}: {error}", path.display());
                }
            },

            WriteJob::Barrier(done) => {
                let _ = done.send(());
            }
        }
    }
}

/// Returns the bytes written: none when the file already holds the snapshot.
fn write_if_changed(path: &Path, snapshot: &Snapshot) -> io::Result<u64> {
    if holds_fingerprint(path, snapshot.meta.fingerprint) {
        return Ok(0);
    }

    let directory = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(directory)?;

    let temporary = path.with_extension("pgs.tmp");
    let written = write_synced(&temporary, snapshot)
        .and_then(|bytes| fs::rename(&temporary, path).map(|()| bytes));
    let bytes = match written {
        Ok(bytes) => bytes,

        Err(error) => {
            let _ = fs::remove_file(&temporary);

            return Err(error);
        }
    };

    File::open(directory)?.sync_all()?;

    Ok(bytes)
}

fn write_synced(path: &Path, snapshot: &Snapshot) -> io::Result<u64> {
    let mut out = BufWriter::with_capacity(IO_BUFFER_BYTES, File::create(path)?);
    let bytes = encode(snapshot, &mut out)?;
    out.into_inner()
        .map_err(|error| error.into_error())?
        .sync_all()?;

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::filter::compile::{CompileWorker, slow_rule_cost};
    use crate::filter::engine::{Decision, Engine, TYPE_A, TYPE_AAAA};
    use crate::lists::Piece;
    use crate::test_dir::TestDir;

    const SOURCE: &str = "https://lists.example/list.txt";

    /// Every kind of rule: plain, host groups for two IPs, slow rules with every modifier
    /// the snapshot has to carry, a regex and a rule that fails to compile.
    const MIXED: &str = "\
||ads.example^
|exact.example^
@@||ok.ads.example^
@@|exact-ok.example^
||Upper.example^
0.0.0.0 blocked.example other.example
127.0.0.1 local.example
2001:db8::1 six.example
||dns.example^$dnstype=A|AAAA
||deny.example^$denyallow=fine.example|good.example
||imp.example^$important
@@||imp.example^
||bad.example^$badfilter
||bad.example^$badfilter,dnstype=~A
||client.example^$client=~192.168.0.1
/track[0-9]+\\.example/
/(?=x)/
ads.*.tracker
";

    fn options(format: ListFormat) -> CompileOptions {
        CompileOptions::new(format, 5000)
    }

    /// The options of `snapshot_of` with the default format, for loading.
    fn caps() -> CompileOptions {
        options(ListFormat::Auto)
    }

    fn capped(max_rules: u32) -> CompileOptions {
        CompileOptions {
            max_rules,
            ..caps()
        }
    }

    async fn compile(worker: &CompileWorker, text: &str, options: CompileOptions) -> Compiled {
        let compilation = worker.start(options);
        for piece in text.as_bytes().chunks(50) {
            compilation
                .pieces
                .send(Piece::Data(piece.to_vec()))
                .await
                .unwrap();
        }

        compilation.pieces.send(Piece::End).await.unwrap();

        compilation.result().await.unwrap()
    }

    async fn snapshot_of(worker: &CompileWorker, text: &str, format: ListFormat) -> Snapshot {
        let options = options(format);
        let compiled = compile(worker, text, options).await;
        let validators = Validators {
            etag: Some("\"tag\"".to_string()),
            last_modified: Some("Sat, 24 Oct 2026 01:02:03 GMT".to_string()),
        };

        Snapshot::new(&compiled, &options, SOURCE, validators)
    }

    fn files_in(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(directory)
            .map(|entries| {
                entries
                    .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();

        names
    }

    fn lists_dir(state: &TestDir) -> PathBuf {
        state.path().join("lists")
    }

    /// The same checksum after a test patched the body, so only the patched field is wrong.
    fn fix_checksum(bytes: &mut [u8]) {
        let end = bytes.len() - CHECKSUM_BYTES as usize;
        let sum = xxh3_128(&bytes[PREAMBLE_BYTES as usize..end]);
        bytes[end..].copy_from_slice(&sum.to_le_bytes());
    }

    fn assert_same_list(a: &CompiledList, b: &CompiledList) {
        assert_eq!(a.fast, b.fast);
        assert_eq!(a.hosts.len(), b.hosts.len());
        for (x, y) in a.hosts.iter().zip(&b.hosts) {
            assert_eq!((x.ip, &x.names), (y.ip, &y.names));
        }

        assert_eq!(a.slow.len(), b.slow.len());
        for (x, y) in a.slow.iter().zip(&b.slow) {
            assert_eq!(x.rule, y.rule);
            assert_eq!(x.identity, y.identity);
        }

        assert_eq!(a.regex_failed, b.regex_failed);
    }

    #[tokio::test]
    async fn a_written_snapshot_loads_back_identical() {
        let worker = CompileWorker::spawn().unwrap();
        let state = TestDir::new("snap");
        let store = SnapshotStore::open(state.path()).unwrap();
        let snapshot = snapshot_of(&worker, MIXED, ListFormat::Auto).await;
        assert!(snapshot.list.slow_rule_count() > 5);
        assert_eq!(snapshot.list.regex_failed(), 1);
        assert_eq!(snapshot.list.hosts.len(), 3);

        store.save(clone_of(&snapshot)).await;
        store.flush().await;

        let path = store.path_for(SOURCE).unwrap();
        let loaded = load(&path, &caps()).unwrap();
        assert_eq!(loaded.meta, snapshot.meta);
        assert_eq!(loaded.counters, snapshot.counters);
        assert_same_list(&loaded.list, &snapshot.list);
        assert_eq!(loaded.meta.validators.etag.as_deref(), Some("\"tag\""));
        assert!(loaded.fits(SOURCE, &options(ListFormat::Auto)));
    }

    fn clone_of(snapshot: &Snapshot) -> Snapshot {
        Snapshot {
            meta: snapshot.meta.clone(),
            list: Arc::clone(&snapshot.list),
            counters: snapshot.counters.clone(),
        }
    }

    #[tokio::test]
    async fn a_loaded_snapshot_decides_like_the_compiled_list() {
        let worker = CompileWorker::spawn().unwrap();
        let state = TestDir::new("snap");
        let store = SnapshotStore::open(state.path()).unwrap();
        let snapshot = snapshot_of(&worker, MIXED, ListFormat::Auto).await;
        store.save(clone_of(&snapshot)).await;
        store.flush().await;
        let loaded = load(&store.path_for(SOURCE).unwrap(), &caps()).unwrap();

        let compiled = Engine::new(vec![Arc::clone(&snapshot.list)], Vec::new());
        let reloaded = Engine::new(vec![loaded.list], Vec::new());
        let names = [
            "ads.example",
            "x.ads.example",
            "ok.ads.example",
            "exact.example",
            "sub.exact.example",
            "blocked.example",
            "other.example",
            "local.example",
            "six.example",
            "upper.example",
            "dns.example",
            "deny.example",
            "fine.example",
            "imp.example",
            "bad.example",
            "client.example",
            "track12.example",
            "ads.x.tracker",
            "nothing.example",
        ];
        let mut blocked = 0;
        for name in names {
            for record_type in [TYPE_A, TYPE_AAAA, 15] {
                let expected = compiled.check(name, record_type, false);
                assert_eq!(reloaded.check(name, record_type, false), expected, "{name}");
                if matches!(expected, Decision::Block { .. }) {
                    blocked += 1;
                }
            }
        }

        assert!(blocked > 10);
    }

    #[tokio::test]
    async fn unchanged_content_writes_nothing() {
        let worker = CompileWorker::spawn().unwrap();
        let state = TestDir::new("snap");
        let store = SnapshotStore::open(state.path()).unwrap();
        let first = snapshot_of(&worker, MIXED, ListFormat::Auto).await;
        store.save(clone_of(&first)).await;
        store.flush().await;
        let path = store.path_for(SOURCE).unwrap();
        let written = store.bytes_written();
        let before = fs::metadata(&path).unwrap();
        assert_eq!(written, before.len());

        // The same text downloaded again, even with a new ETag.
        let mut again = snapshot_of(&worker, MIXED, ListFormat::Auto).await;
        again.meta.validators.etag = Some("\"other\"".to_string());
        store.save(again).await;
        store.flush().await;

        let after = fs::metadata(&path).unwrap();
        assert_eq!(store.bytes_written(), written);
        assert_eq!(after.modified().unwrap(), before.modified().unwrap());
        assert_eq!(
            std::os::unix::fs::MetadataExt::ino(&after),
            std::os::unix::fs::MetadataExt::ino(&before)
        );
        assert_eq!(files_in(&lists_dir(&state)).len(), 1);
    }

    #[tokio::test]
    async fn a_new_text_is_written_atomically_and_leaves_no_temporary_file() {
        let worker = CompileWorker::spawn().unwrap();
        let state = TestDir::new("snap");
        let store = SnapshotStore::open(state.path()).unwrap();
        store
            .save(snapshot_of(&worker, "||a.example^\n", ListFormat::Auto).await)
            .await;
        store.flush().await;
        let first = store.bytes_written();

        store
            .save(snapshot_of(&worker, "||a.example^\n||b.example^\n", ListFormat::Auto).await)
            .await;
        store.flush().await;

        assert!(store.bytes_written() > first);
        let path = store.path_for(SOURCE).unwrap();
        let loaded = load(&path, &caps()).unwrap();
        assert_eq!(loaded.list.rule_count(), 2);
        assert_eq!(
            files_in(&lists_dir(&state)),
            [path.file_name().unwrap().to_str().unwrap()]
        );
    }

    #[tokio::test]
    async fn a_format_change_with_the_same_content_is_recompiled_and_rewritten() {
        let worker = CompileWorker::spawn().unwrap();
        let state = TestDir::new("snap");
        let store = SnapshotStore::open(state.path()).unwrap();
        let text = "a.example\nb.example\n";
        let adguard = snapshot_of(&worker, text, ListFormat::Auto).await;
        store.save(clone_of(&adguard)).await;
        store.flush().await;
        let written = store.bytes_written();

        let domains = snapshot_of(&worker, text, ListFormat::Domains).await;
        assert_eq!(domains.meta.content_hash, adguard.meta.content_hash);
        assert_ne!(domains.meta.fingerprint, adguard.meta.fingerprint);
        assert!(!adguard.fits(SOURCE, &options(ListFormat::Domains)));
        store.save(domains).await;
        store.flush().await;

        assert!(store.bytes_written() > written);
        let loaded = load(&store.path_for(SOURCE).unwrap(), &caps()).unwrap();
        assert_eq!(loaded.meta.effective_format, ListFormat::Domains);
        assert_eq!(loaded.meta.configured_format, ListFormat::Domains);
    }

    #[tokio::test]
    async fn a_format_change_is_noticed_across_a_restart() {
        let state = TestDir::new("snap");
        let text = "a.example\nb.example\n";
        {
            let worker = CompileWorker::spawn().unwrap();
            let store = SnapshotStore::open(state.path()).unwrap();
            store
                .save(snapshot_of(&worker, text, ListFormat::Auto).await)
                .await;
            store.flush().await;
        }

        // A new process: the config now says `domains`.
        let worker = CompileWorker::spawn().unwrap();
        let store = SnapshotStore::open(state.path()).unwrap();
        let path = store.path_for(SOURCE).unwrap();
        let old = worker.load(path.clone(), caps()).await.unwrap();
        assert!(old.fits(SOURCE, &options(ListFormat::Auto)));
        assert!(!old.fits(SOURCE, &options(ListFormat::Domains)));
        assert_eq!(store.bytes_written(), 0);

        let recompiled = snapshot_of(&worker, text, ListFormat::Domains).await;
        assert_ne!(recompiled.meta.fingerprint, old.meta.fingerprint);
        store.save(recompiled).await;
        store.flush().await;

        assert!(store.bytes_written() > 0);
        let loaded = load(&path, &caps()).unwrap();
        assert_eq!(loaded.meta.effective_format, ListFormat::Domains);
    }

    #[tokio::test]
    async fn another_source_or_rule_cap_does_not_fit() {
        let worker = CompileWorker::spawn().unwrap();
        let snapshot = snapshot_of(&worker, MIXED, ListFormat::Auto).await;

        assert!(snapshot.fits(SOURCE, &options(ListFormat::Auto)));
        assert!(!snapshot.fits("https://other.example/list.txt", &options(ListFormat::Auto)));
        assert!(!snapshot.fits(SOURCE, &capped(10)));
    }

    #[tokio::test]
    async fn persistence_off_never_writes_or_reads() {
        let worker = CompileWorker::spawn().unwrap();
        let state = TestDir::new("snap");
        let store = SnapshotStore::disabled();

        store
            .save(snapshot_of(&worker, MIXED, ListFormat::Auto).await)
            .await;
        store.flush().await;

        assert!(store.path_for(SOURCE).is_none());
        assert_eq!(store.bytes_written(), 0);
        assert!(files_in(state.path()).is_empty());
    }

    #[tokio::test]
    async fn nothing_is_created_until_the_first_write() {
        let state = TestDir::new("snap");

        let _store = SnapshotStore::open(state.path()).unwrap();

        assert!(files_in(state.path()).is_empty());
    }

    async fn saved_bytes(state: &TestDir, text: &str) -> (PathBuf, Vec<u8>) {
        let worker = CompileWorker::spawn().unwrap();
        let store = SnapshotStore::open(state.path()).unwrap();
        store
            .save(snapshot_of(&worker, text, ListFormat::Auto).await)
            .await;
        store.flush().await;
        let path = store.path_for(SOURCE).unwrap();

        (path.clone(), fs::read(path).unwrap())
    }

    fn rejected(path: &Path) -> SnapshotError {
        load(path, &caps())
            .err()
            .expect("the file should be refused")
    }

    #[tokio::test]
    async fn a_damaged_header_is_refused() {
        let state = TestDir::new("snap");
        let (path, good) = saved_bytes(&state, MIXED).await;

        let mut bad = good.clone();
        bad[0] ^= 0xff;
        fs::write(&path, &bad).unwrap();
        assert!(matches!(rejected(&path), SnapshotError::BadMagic));

        let mut bad = good.clone();
        bad[8] = 99;
        fs::write(&path, &bad).unwrap();
        assert!(matches!(rejected(&path), SnapshotError::BadVersion(99)));

        fs::write(&path, &good[..good.len() / 2]).unwrap();
        assert!(matches!(
            rejected(&path),
            SnapshotError::Truncated | SnapshotError::BadChecksum
        ));

        fs::write(&path, &good[..5]).unwrap();
        assert!(matches!(rejected(&path), SnapshotError::Truncated));

        fs::write(&path, b"").unwrap();
        assert!(matches!(rejected(&path), SnapshotError::Truncated));

        // A field inside the header: the checksum catches it.
        let mut bad = good.clone();
        bad[PREAMBLE_BYTES as usize + 40] ^= 1;
        fs::write(&path, &bad).unwrap();
        assert!(matches!(rejected(&path), SnapshotError::BadChecksum));

        fs::write(&path, &good).unwrap();
        assert!(load(&path, &caps()).is_ok());
    }

    #[tokio::test]
    async fn an_older_compiler_version_is_refused() {
        let state = TestDir::new("snap");
        let (path, mut bytes) = saved_bytes(&state, MIXED).await;
        let at = PREAMBLE_BYTES as usize + 32;
        bytes[at..at + 4].copy_from_slice(&(COMPILER_VERSION + 1).to_le_bytes());
        fix_checksum(&mut bytes);
        fs::write(&path, &bytes).unwrap();

        assert!(matches!(rejected(&path), SnapshotError::OldCompiler(_)));
    }

    #[tokio::test]
    async fn a_flipped_byte_inside_an_array_fails_the_checksum() {
        let state = TestDir::new("snap");
        let list: String = (0..2000).map(|i| format!("||host{i}.example^\n")).collect();
        let (path, mut bytes) = saved_bytes(&state, &list).await;

        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x01;
        fs::write(&path, &bytes).unwrap();

        assert!(matches!(rejected(&path), SnapshotError::BadChecksum));
    }

    /// The offset of the length field of the first plain-rule array of a one-rule list.
    fn first_array_length_offset(bytes: &[u8]) -> usize {
        let mut pattern = 1u64.to_le_bytes().to_vec();
        pattern.extend_from_slice(&xxh3_64(b"a.example").to_le_bytes());

        bytes
            .windows(pattern.len())
            .position(|window| window == pattern)
            .expect("the array is in the file")
    }

    #[tokio::test]
    async fn length_fields_over_the_caps_are_refused_even_with_a_valid_checksum() {
        let state = TestDir::new("snap");
        let (path, good) = saved_bytes(&state, "||a.example^\n").await;
        let array = first_array_length_offset(&good);

        // An array longer than the rule cap, and longer than the file.
        for claimed in [5001u64, 1 << 40, u64::MAX] {
            let mut bad = good.clone();
            bad[array..array + 8].copy_from_slice(&claimed.to_le_bytes());
            fix_checksum(&mut bad);
            fs::write(&path, &bad).unwrap();
            let error = rejected(&path);
            assert!(
                matches!(error, SnapshotError::TooLarge(_)),
                "{claimed}: {error:?}"
            );
        }

        // A source text longer than the limit; it starts after the header fields.
        let source_length = PREAMBLE_BYTES as usize + 16 + 16 + 4 + 1 + 1 + 4;
        let mut bad = good.clone();
        bad[source_length..source_length + 4].copy_from_slice(&(1u32 << 30).to_le_bytes());
        fix_checksum(&mut bad);
        fs::write(&path, &bad).unwrap();
        assert!(matches!(rejected(&path), SnapshotError::TooLarge(_)));

        // The caps come from the config: a list now capped below its size is refused.
        fs::write(&path, &good).unwrap();
        assert!(load(&path, &capped(1)).is_ok());
        assert!(matches!(
            load(&path, &capped(0)).err(),
            Some(SnapshotError::TooLarge(_))
        ));
    }

    #[tokio::test]
    async fn slow_rule_counts_and_texts_over_the_line_cap_are_refused() {
        let state = TestDir::new("snap");
        let (path, good) = saved_bytes(&state, "x*y\n").await;
        let pattern = good
            .windows(3)
            .position(|window| window == b"x*y")
            .expect("the pattern is in the file");

        let mut bad = good.clone();
        bad[pattern - 4..pattern].copy_from_slice(&(MAX_LINE_BYTES as u32 + 1).to_le_bytes());
        fix_checksum(&mut bad);
        fs::write(&path, &bad).unwrap();

        assert!(matches!(rejected(&path), SnapshotError::TooLarge(_)));
    }

    #[tokio::test]
    async fn the_slow_rule_budget_of_the_compiler_applies_to_a_snapshot_load() {
        let state = TestDir::new("snap");
        let text: String = (0..20).map(|i| format!("a{i}*b\n")).collect();
        let (path, _) = saved_bytes(&state, &text).await;
        let loaded = load(&path, &caps()).unwrap();
        let total: usize = loaded
            .list
            .slow
            .iter()
            .map(|slow| slow_rule_cost(&slow.rule))
            .sum();
        let budget = |slow_rule_budget| CompileOptions {
            slow_rule_budget,
            ..caps()
        };

        assert_eq!(loaded.list.slow_rule_count(), 20);
        assert!(load(&path, &budget(total)).is_ok());
        let error = load(&path, &budget(total - 1))
            .err()
            .expect("over the budget");

        assert!(matches!(error, SnapshotError::TooLarge(_)), "{error:?}");
    }

    #[tokio::test]
    async fn a_damaged_file_is_replaced_by_the_same_snapshot() {
        let worker = CompileWorker::spawn().unwrap();
        let state = TestDir::new("snap");
        let store = SnapshotStore::open(state.path()).unwrap();
        let list: String = (0..2000).map(|i| format!("||host{i}.example^\n")).collect();
        let snapshot = snapshot_of(&worker, &list, ListFormat::Auto).await;
        store.save(clone_of(&snapshot)).await;
        store.flush().await;
        let path = store.path_for(SOURCE).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x01;
        fs::write(&path, &bytes).unwrap();
        let before = store.bytes_written();

        store.save(clone_of(&snapshot)).await;
        store.flush().await;

        assert!(store.bytes_written() > before);
        assert!(load(&path, &caps()).is_ok());
    }

    #[tokio::test]
    async fn a_failed_write_leaves_no_file_and_the_writer_keeps_going() {
        let worker = CompileWorker::spawn().unwrap();
        let state = TestDir::new("snap");
        // `lists` is a file, so the directory cannot be created.
        fs::write(state.path().join("lists"), b"in the way").unwrap();
        let store = SnapshotStore::open(state.path()).unwrap();

        store
            .save(snapshot_of(&worker, MIXED, ListFormat::Auto).await)
            .await;
        store.flush().await;
        assert_eq!(store.bytes_written(), 0);

        fs::remove_file(state.path().join("lists")).unwrap();
        store
            .save(snapshot_of(&worker, MIXED, ListFormat::Auto).await)
            .await;
        store.flush().await;
        assert!(store.bytes_written() > 0);
        assert!(load(&store.path_for(SOURCE).unwrap(), &caps()).is_ok());
    }

    #[test]
    fn each_source_has_its_own_stable_file() {
        let state = TestDir::new("snap");
        let store = SnapshotStore::open(state.path()).unwrap();

        let a = store.path_for("https://a.example/list").unwrap();
        let b = store.path_for("https://b.example/list").unwrap();

        assert_ne!(a, b);
        assert_eq!(a, store.path_for("https://a.example/list").unwrap());
        assert_eq!(a.parent().unwrap(), lists_dir(&state));
        assert_eq!(a.extension().unwrap(), "pgs");
    }

    #[test]
    fn the_fingerprint_depends_on_every_part() {
        let base = fingerprint(1, ListFormat::Auto, ListFormat::Adblock, 10, 1);
        let all: HashMap<&str, u128> = HashMap::from([
            (
                "content",
                fingerprint(2, ListFormat::Auto, ListFormat::Adblock, 10, 1),
            ),
            (
                "configured",
                fingerprint(1, ListFormat::Hosts, ListFormat::Adblock, 10, 1),
            ),
            (
                "effective",
                fingerprint(1, ListFormat::Auto, ListFormat::Hosts, 10, 1),
            ),
            (
                "cap",
                fingerprint(1, ListFormat::Auto, ListFormat::Adblock, 11, 1),
            ),
            (
                "compiler",
                fingerprint(1, ListFormat::Auto, ListFormat::Adblock, 10, 2),
            ),
        ]);

        for (part, value) in all {
            assert_ne!(value, base, "{part}");
        }

        assert_eq!(
            base,
            fingerprint(1, ListFormat::Auto, ListFormat::Adblock, 10, 1)
        );
    }
}
