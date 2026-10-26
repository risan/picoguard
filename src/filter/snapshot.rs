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
//!       effective_format u8, max_rules u32, allow_redirects u8, source, etag?, last_modified?,
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

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use xxhash_rust::xxh3::{Xxh3, xxh3_64, xxh3_128};

use super::compile::{
    COMPILER_VERSION, CompileOptions, Compiled, NAME_OVERHEAD_BYTES, SlowRuleBudget, TEXT_BYTE_COST,
};
use super::engine::{CompiledList, FAST_KINDS, HostRules, MAX_HOST_GROUPS, SlowRule};
use super::parse::{ClientSet, Counters, ListFormat, MAX_LINE_BYTES, NetworkRule};
use crate::lists::Validators;

pub const FILE_VERSION: u32 = 4;

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

/// The most bytes a snapshot of a list under `options` can take: no valid file is larger, so
/// a larger one is refused before a byte of it is read. The parts are the fixed fields (a
/// source, two validators and one invalid line, each up to `MAX_TEXT_BYTES`), 8 bytes for
/// each rule the cap allows, the host groups, and half the slow-rule budget (a slow rule is
/// charged 512 bytes and 4 per text byte, and takes less than half of that in the file).
pub fn max_file_bytes(options: &CompileOptions) -> u64 {
    const FIXED_BYTES: u64 = 4 * (MAX_TEXT_BYTES as u64 + 5) + 1024;
    const HOST_GROUP_FILE_BYTES: u64 = 4 + 64;

    let parts = [
        PREAMBLE_BYTES,
        CHECKSUM_BYTES,
        FIXED_BYTES,
        u64::from(options.max_rules).saturating_mul(8),
        (MAX_HOST_GROUPS as u64).saturating_mul(HOST_GROUP_FILE_BYTES),
        (options.slow_rule_budget as u64) / 2,
    ];

    parts
        .into_iter()
        .try_fold(0u64, u64::checked_add)
        .unwrap_or(u64::MAX)
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
    pub allow_redirects: bool,
    /// URL or path of the list.
    pub source: String,
    pub validators: Validators,
}

#[derive(Clone)]
pub struct Snapshot {
    pub meta: Meta,
    pub list: Arc<CompiledList>,
    pub counters: Counters,
}

/// The fingerprint of plan D14: source content, effective format, per-list options
/// (configured format, rule cap and whether host rules may redirect) and the compiler
/// version.
pub fn fingerprint(
    content_hash: u128,
    configured_format: ListFormat,
    effective_format: ListFormat,
    max_rules: u32,
    allow_redirects: bool,
    compiler_version: u32,
) -> u128 {
    let mut parts = Vec::with_capacity(27);
    parts.extend_from_slice(&content_hash.to_le_bytes());
    parts.push(format_code(configured_format));
    parts.push(format_code(effective_format));
    parts.extend_from_slice(&max_rules.to_le_bytes());
    parts.push(u8::from(allow_redirects));
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
                allow_redirects: options.allow_redirects,
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
            && self.meta.allow_redirects == options.allow_redirects
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
}

impl<W: Write> Encoder<W> {
    fn raw(&mut self, data: &[u8]) -> io::Result<()> {
        self.out.write_all(data)?;
        self.hasher.update(data);

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
        self.texts(&rule.restricted_clients.entries())?;

        self.texts(&rule.restricted_ctags)
    }
}

/// Writes the whole file.
fn encode<W: Write>(snapshot: &Snapshot, mut out: W) -> io::Result<()> {
    out.write_all(&MAGIC)?;
    out.write_all(&FILE_VERSION.to_le_bytes())?;

    let mut encoder = Encoder {
        out,
        hasher: Xxh3::new(),
    };
    let meta = &snapshot.meta;
    encoder.u128(meta.fingerprint)?;
    encoder.u128(meta.content_hash)?;
    encoder.u32(meta.compiler_version)?;
    encoder.u8(format_code(meta.configured_format))?;
    encoder.u8(format_code(meta.effective_format))?;
    encoder.u32(meta.max_rules)?;
    encoder.u8(u8::from(meta.allow_redirects))?;
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

    encoder.u32(list.hosts.ips.len() as u32)?;
    for ip in &list.hosts.ips {
        encoder.text(&ip.to_string())?;
    }

    encoder.u64s(&list.hosts.entries)?;

    encoder.u32(list.slow.len() as u32)?;
    for slow in &list.slow {
        encoder.rule(&slow.rule)?;
    }

    let checksum = encoder.hasher.digest128();
    encoder.out.write_all(&checksum.to_le_bytes())?;
    encoder.out.flush()?;

    Ok(())
}

// ---- Reading ----

/// The least bytes one host group and one slow rule take in the file: a length field that
/// promises more of them than the file holds is refused before anything is reserved.
const MIN_HOST_GROUP_BYTES: u64 = 4 + 2;
const MIN_SLOW_RULE_BYTES: u64 = 1 + 4 + 6 * 4;

/// Decodes the body of a file whose checksum already matched, so damage by accident is
/// ruled out; the length checks still guard against a file made on purpose.
struct Decoder<R: Read> {
    input: R,
    /// Body bytes the file still holds; no length field may ask for more.
    remaining: u64,
    /// The rule cap of the list: no count of anything may exceed it.
    max_rules: u64,
    /// Rules (plain, host names and slow rules) the list may still hold under its cap.
    rules_left: u64,
    slow_budget: SlowRuleBudget,
    /// What the modifier names of the rule being decoded may still cost: each name is
    /// charged before it is allocated, as `slow_rule_cost` charges it afterwards.
    name_allowance: usize,
}

impl<R: Read> Decoder<R> {
    fn raw(&mut self, buffer: &mut [u8]) -> Result<(), SnapshotError> {
        if buffer.len() as u64 > self.remaining {
            return Err(SnapshotError::Truncated);
        }

        self.input.read_exact(buffer)?;
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

        self.text_of(length, limit, what)
    }

    /// The text of a length that has been read already.
    fn text_of(
        &mut self,
        length: usize,
        limit: usize,
        what: &'static str,
    ) -> Result<String, SnapshotError> {
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

    /// Names of a modifier. Each is charged to `name_allowance` from its length, before the
    /// text is read.
    fn names(&mut self, what: &'static str) -> Result<Vec<String>, SnapshotError> {
        let count = self.small_count(what)?;
        let mut names = Vec::new();
        for _ in 0..count {
            let length = self.u32()? as usize;
            let cost = length
                .checked_add(NAME_OVERHEAD_BYTES)
                .and_then(|bytes| bytes.checked_mul(TEXT_BYTE_COST))
                .ok_or(SnapshotError::TooLarge(what))?;
            self.name_allowance = self
                .name_allowance
                .checked_sub(cost)
                .ok_or(SnapshotError::TooLarge(what))?;
            names.push(self.text_of(length, MAX_LINE_BYTES, what)?);
        }

        Ok(names)
    }

    /// Takes `count` rules from the budget of the list's cap.
    fn charge(&mut self, count: u64, what: &'static str) -> Result<(), SnapshotError> {
        if count > self.rules_left {
            return Err(SnapshotError::TooLarge(what));
        }

        self.rules_left -= count;

        Ok(())
    }

    /// A count of items that take at least `least_bytes` each in the rest of the file.
    fn count_within_file(
        &mut self,
        least_bytes: u64,
        what: &'static str,
    ) -> Result<u64, SnapshotError> {
        let count = u64::from(self.u32()?);
        if count > self.max_rules {
            return Err(SnapshotError::TooLarge(what));
        }

        match count.checked_mul(least_bytes) {
            Some(bytes) if bytes <= self.remaining => Ok(count),
            _ => Err(SnapshotError::Truncated),
        }
    }

    fn u64s(&mut self, what: &'static str) -> Result<Vec<u64>, SnapshotError> {
        let length = self.u64()?;
        self.charge(length, what)?;
        match length.checked_mul(8) {
            Some(bytes) if bytes <= self.remaining => {}
            _ => return Err(SnapshotError::Truncated),
        }

        let mut values = Vec::new();
        values
            .try_reserve_exact(length as usize)
            .map_err(|_| SnapshotError::Io(io::ErrorKind::OutOfMemory.into()))?;
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
        self.name_allowance = self.slow_budget.remaining();
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
            denyallow: self.names("deny-allow names")?,
            restricted_clients: ClientSet::new(&self.names("client entries")?),
            restricted_ctags: self.names("tag entries")?,
        };

        self.charge(1, "slow rules")?;
        let slow = SlowRule::compile(rule)
            .map_err(|()| SnapshotError::Corrupt("a rule does not compile"))?;
        self.slow_budget
            .charge(&slow)
            .map_err(|_| SnapshotError::TooLarge("slow rule memory"))?;

        Ok(slow)
    }
}

/// Hashes the body between the preamble and the trailing checksum and compares the two.
/// The file position is left at the end of the file.
fn body_checksum_matches(file: &mut File, body_bytes: u64) -> io::Result<bool> {
    file.seek(SeekFrom::Start(PREAMBLE_BYTES))?;
    let mut hasher = Xxh3::new();
    let mut buffer = vec![0u8; IO_BUFFER_BYTES];
    let mut left = body_bytes;
    while left > 0 {
        let count = left.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..count])?;
        hasher.update(&buffer[..count]);
        left -= count as u64;
    }

    let mut trailer = [0u8; CHECKSUM_BYTES as usize];
    file.read_exact(&mut trailer)?;

    Ok(u128::from_le_bytes(trailer) == hasher.digest128())
}

/// Reads the magic and the file version, and returns the size of the body.
fn check_preamble(file: &mut File) -> Result<u64, SnapshotError> {
    let length = file.metadata()?.len();
    if length < PREAMBLE_BYTES + CHECKSUM_BYTES {
        return Err(SnapshotError::Truncated);
    }

    let mut preamble = [0u8; PREAMBLE_BYTES as usize];
    file.read_exact(&mut preamble)?;
    if preamble[..8] != MAGIC {
        return Err(SnapshotError::BadMagic);
    }

    let version = u32::from_le_bytes(preamble[8..].try_into().expect("4 bytes"));
    if version != FILE_VERSION {
        return Err(SnapshotError::BadVersion(version));
    }

    Ok(length - PREAMBLE_BYTES - CHECKSUM_BYTES)
}

/// Reads and checks a snapshot file against the caps of the list's options. The checksum is
/// verified in a pass of its own before anything is decoded, so no count of a damaged file
/// is ever acted on.
pub fn load(path: &Path, options: &CompileOptions) -> Result<Snapshot, SnapshotError> {
    let mut file = File::open(path)?;
    if file.metadata()?.len() > max_file_bytes(options) {
        return Err(SnapshotError::TooLarge("snapshot file"));
    }

    let body_bytes = check_preamble(&mut file)?;
    if !body_checksum_matches(&mut file, body_bytes)? {
        return Err(SnapshotError::BadChecksum);
    }

    file.seek(SeekFrom::Start(PREAMBLE_BYTES))?;
    let mut decoder = Decoder {
        input: BufReader::with_capacity(IO_BUFFER_BYTES, file),
        remaining: body_bytes,
        max_rules: u64::from(options.max_rules),
        rules_left: u64::from(options.max_rules),
        slow_budget: SlowRuleBudget::new(options.slow_rule_budget),
        name_allowance: 0,
    };
    let stored_fingerprint = decoder.u128()?;
    let content_hash = decoder.u128()?;
    let compiler_version = decoder.u32()?;
    let configured_format = format_from_code(decoder.u8()?)?;
    let effective_format = format_from_code(decoder.u8()?)?;
    let meta_max_rules = decoder.u32()?;
    let meta_allow_redirects = match decoder.u8()? {
        0 => false,
        1 => true,
        _ => return Err(SnapshotError::Corrupt("bad redirect flag")),
    };
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

    // Host groups are not rules: the names mapped to them are charged, the groups are bounded
    // by their own cap and memory charge. The vector is not reserved up front, so a count the
    // file cannot back costs nothing.
    let group_count = decoder.count_within_file(MIN_HOST_GROUP_BYTES, "host groups")?;
    let mut host_ips = Vec::new();
    for _ in 0..group_count {
        decoder
            .slow_budget
            .charge_host_group()
            .map_err(|_| SnapshotError::TooLarge("host groups"))?;
        let ip: IpAddr = decoder
            .text(64, "host address")?
            .parse()
            .map_err(|_| SnapshotError::Corrupt("host address"))?;
        host_ips.push(ip);
    }

    let hosts = HostRules {
        ips: host_ips,
        entries: decoder.u64s("host name array")?,
    };
    if !hosts.groups_exist() {
        return Err(SnapshotError::Corrupt("host name without a group"));
    }

    let slow_count = decoder.count_within_file(MIN_SLOW_RULE_BYTES, "slow rules")?;
    let mut slow = Vec::new();
    for _ in 0..slow_count {
        slow.push(decoder.rule()?);
    }

    slow.shrink_to_fit();

    if decoder.remaining != 0 {
        return Err(SnapshotError::Corrupt("data after the last rule"));
    }

    if compiler_version != COMPILER_VERSION {
        return Err(SnapshotError::OldCompiler(compiler_version));
    }

    let expected = fingerprint(
        content_hash,
        configured_format,
        effective_format,
        meta_max_rules,
        meta_allow_redirects,
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
            allow_redirects: meta_allow_redirects,
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
    let Ok(body_bytes) = check_preamble(&mut file) else {
        return false;
    };
    if body_bytes < 16 || !body_checksum_matches(&mut file, body_bytes).unwrap_or(false) {
        return false;
    }

    let mut stored = [0u8; 16];
    file.seek(SeekFrom::Start(PREAMBLE_BYTES)).is_ok()
        && file.read_exact(&mut stored).is_ok()
        && u128::from_le_bytes(stored) == fingerprint
}

// ---- The disk writer ----

/// The file system calls of the writer, so that tests can watch them and make them fail.
trait Files: Send + Sync {
    /// Creates one directory; its parent exists.
    fn create_dir(&self, path: &Path) -> io::Result<()>;
    fn create_file(&self, path: &Path) -> io::Result<Box<dyn OpenFile>>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    /// `fsync` of a directory: makes the entries created in it durable.
    fn sync_dir(&self, path: &Path) -> io::Result<()>;
}

trait OpenFile: Write + Send {
    fn sync_all(&mut self) -> io::Result<()>;
}

impl OpenFile for File {
    fn sync_all(&mut self) -> io::Result<()> {
        File::sync_all(self)
    }
}

struct DiskFiles;

impl Files for DiskFiles {
    fn create_dir(&self, path: &Path) -> io::Result<()> {
        fs::create_dir(path)
    }

    fn create_file(&self, path: &Path) -> io::Result<Box<dyn OpenFile>> {
        Ok(Box::new(File::create(path)?))
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }

    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        File::open(path)?.sync_all()
    }
}

/// Counts the bytes that reach the file, also those of a write that fails later.
struct CountingFile<'a> {
    file: Box<dyn OpenFile>,
    written: &'a AtomicU64,
}

impl Write for CountingFile<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let count = self.file.write(data)?;
        self.written.fetch_add(count as u64, Ordering::Relaxed);

        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

enum WriteJob {
    Write {
        path: PathBuf,
        snapshot: Box<Snapshot>,
        /// Sent after the writer let go of the snapshot, with how the write went.
        done: oneshot::Sender<io::Result<()>>,
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
        SnapshotStore::open_with(state_dir, Arc::new(DiskFiles))
    }

    fn open_with(state_dir: &Path, files: Arc<dyn Files>) -> io::Result<SnapshotStore> {
        let (writer, jobs) = mpsc::channel(1);
        let written = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&written);
        std::thread::Builder::new()
            .name("picoguard-disk".to_string())
            .spawn(move || write_loop(jobs, files.as_ref(), &counter))?;

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

    /// Writes the snapshot unless the file already holds its fingerprint, and returns when
    /// that is done or has failed. A failure names the file; the caller decides when to try
    /// again. When this returns the writer holds no reference to the list any more, so a
    /// caller that awaits it before it starts the next refresh has at most the current list
    /// and the one being built in memory. Do not cancel the future: the write goes on
    /// without the caller. With persistence off nothing is written and this succeeds.
    pub async fn save(&self, snapshot: Snapshot) -> io::Result<()> {
        let (Some(writer), Some(path)) = (&self.writer, self.path_for(&snapshot.meta.source))
        else {
            return Ok(());
        };

        let (done, finished) = oneshot::channel();
        let job = WriteJob::Write {
            path,
            snapshot: Box::new(snapshot),
            done,
        };
        if writer.send(job).await.is_err() {
            return Err(io::Error::other("the snapshot writer stopped"));
        }

        finished
            .await
            .unwrap_or_else(|_| Err(io::Error::other("the snapshot writer stopped")))
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

    /// Like `flush`, but gives up after `wait`. Returns false when the writer was still busy
    /// (a stuck disk); what it holds then is lost if the process exits.
    pub async fn drain(&self, wait: Duration) -> bool {
        tokio::time::timeout(wait, self.flush()).await.is_ok()
    }

    /// Bytes written to snapshot files since the store was opened.
    pub fn bytes_written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }
}

fn write_loop(mut jobs: mpsc::Receiver<WriteJob>, files: &dyn Files, written: &AtomicU64) {
    let mut unsynced = BTreeSet::new();

    while let Some(job) = jobs.blocking_recv() {
        match job {
            WriteJob::Write {
                path,
                snapshot,
                done,
            } => {
                let result = write_if_changed(files, written, &path, &snapshot, &mut unsynced)
                    .map_err(|error| {
                        io::Error::new(error.kind(), format!("{}: {error}", path.display()))
                    });
                drop(snapshot);

                let _ = done.send(result);
            }

            WriteJob::Barrier(done) => {
                let _ = done.send(());
            }
        }
    }
}

fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Creates `directory` and the missing directories above it, outermost first. The parent of
/// each one created is added to `unsynced` at once, so a failure further down forgets none.
fn create_missing_directories(
    files: &dyn Files,
    directory: &Path,
    unsynced: &mut BTreeSet<PathBuf>,
) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut current = directory;
    while !current.is_dir() {
        missing.push(current);
        let parent = parent_of(current);
        if parent == current {
            break;
        }

        current = parent;
    }

    for path in missing.into_iter().rev() {
        match files.create_dir(path) {
            Ok(()) => {
                unsynced.insert(parent_of(path).to_path_buf());
            }

            Err(error) if error.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => {}

            Err(error) => return Err(error),
        }
    }

    Ok(())
}

/// Syncs the directories whose entries are not known to be durable yet. One that fails stays
/// in `unsynced` for the next call, so a retry finishes the work even when the file is
/// already in place.
fn sync_owed_directories(files: &dyn Files, unsynced: &mut BTreeSet<PathBuf>) -> io::Result<()> {
    // Parents sort before their children.
    while let Some(directory) = unsynced.first().cloned() {
        match files.sync_dir(&directory) {
            Ok(()) => {}

            // Removed since: there is nothing left to make durable.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}

            Err(error) => return Err(error),
        }

        unsynced.remove(&directory);
    }

    Ok(())
}

/// Writes the snapshot unless the file already holds it, then syncs the directories whose
/// entries it created (a new directory is only durable once its parent is synced, and a new
/// file once its directory is; without that the snapshot could vanish after a power loss).
/// Bytes are counted into `written` as they reach the file, whether or not the write
/// succeeds.
fn write_if_changed(
    files: &dyn Files,
    written: &AtomicU64,
    path: &Path,
    snapshot: &Snapshot,
    unsynced: &mut BTreeSet<PathBuf>,
) -> io::Result<()> {
    if holds_fingerprint(path, snapshot.meta.fingerprint) {
        return sync_owed_directories(files, unsynced);
    }

    let directory = parent_of(path);
    create_missing_directories(files, directory, unsynced)?;
    sync_owed_directories(files, unsynced)?;

    let temporary = path.with_extension("pgs.tmp");
    let result = write_synced(files, written, &temporary, snapshot)
        .and_then(|()| files.rename(&temporary, path));
    if let Err(error) = result {
        let _ = files.remove_file(&temporary);

        return Err(error);
    }

    unsynced.insert(directory.to_path_buf());

    sync_owed_directories(files, unsynced)
}

fn write_synced(
    files: &dyn Files,
    written: &AtomicU64,
    path: &Path,
    snapshot: &Snapshot,
) -> io::Result<()> {
    let file = CountingFile {
        file: files.create_file(path)?,
        written,
    };
    let mut out = BufWriter::with_capacity(IO_BUFFER_BYTES, file);
    encode(snapshot, &mut out)?;
    let mut file = out.into_inner().map_err(|error| error.into_error())?;

    file.file.sync_all()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::filter::compile::{CompileWorker, HOST_GROUP_BYTES, slow_rule_cost};
    use crate::filter::engine::MAX_HOST_GROUPS;
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
        assert_eq!(a.hosts.ips, b.hosts.ips);
        assert_eq!(a.hosts.entries, b.hosts.entries);

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
        assert_eq!(snapshot.list.hosts.ips.len(), 3);

        store.save(clone_of(&snapshot)).await.unwrap();
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
        store.save(clone_of(&snapshot)).await.unwrap();
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
        store.save(clone_of(&first)).await.unwrap();
        store.flush().await;
        let path = store.path_for(SOURCE).unwrap();
        let written = store.bytes_written();
        let before = fs::metadata(&path).unwrap();
        assert_eq!(written, before.len());

        // The same text downloaded again, even with a new ETag.
        let mut again = snapshot_of(&worker, MIXED, ListFormat::Auto).await;
        again.meta.validators.etag = Some("\"other\"".to_string());
        store.save(again).await.unwrap();
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
            .await
            .unwrap();
        store.flush().await;
        let first = store.bytes_written();

        store
            .save(snapshot_of(&worker, "||a.example^\n||b.example^\n", ListFormat::Auto).await)
            .await
            .unwrap();
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
        store.save(clone_of(&adguard)).await.unwrap();
        store.flush().await;
        let written = store.bytes_written();

        let domains = snapshot_of(&worker, text, ListFormat::Domains).await;
        assert_eq!(domains.meta.content_hash, adguard.meta.content_hash);
        assert_ne!(domains.meta.fingerprint, adguard.meta.fingerprint);
        assert!(!adguard.fits(SOURCE, &options(ListFormat::Domains)));
        store.save(domains).await.unwrap();
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
                .await
                .unwrap();
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
        store.save(recompiled).await.unwrap();
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
            .await
            .unwrap();
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
            .await
            .unwrap();
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

    /// Compiles `text` with a rule cap of exactly its rules, saves it and loads it back.
    async fn reloads_at_its_exact_rule_cap(text: &str, format: ListFormat, rules: u32) {
        let worker = CompileWorker::spawn().unwrap();
        let state = TestDir::new("snap");
        let store = SnapshotStore::open(state.path()).unwrap();
        let options = CompileOptions::new(format, rules);
        let compiled = compile(&worker, text, options).await;
        assert_eq!(compiled.summary.counters.over_cap, 0, "{text:?}");
        assert_eq!(compiled.list.rule_count(), rules as usize, "{text:?}");
        let snapshot = Snapshot::new(&compiled, &options, SOURCE, Validators::default());
        store.save(snapshot).await.unwrap();
        store.flush().await;
        let path = store.path_for(SOURCE).unwrap();

        let loaded = load(&path, &options).unwrap_or_else(|error| panic!("{text:?}: {error}"));

        assert_eq!(loaded.list.rule_count(), rules as usize, "{text:?}");
        let one_less = CompileOptions {
            max_rules: rules - 1,
            ..options
        };
        assert!(
            matches!(
                load(&path, &one_less).err(),
                Some(SnapshotError::TooLarge(_))
            ),
            "{text:?}"
        );
    }

    #[tokio::test]
    async fn a_list_reloads_at_exactly_its_rule_cap_whatever_its_groups_and_names() {
        // One hosts line: one group, one rule.
        reloads_at_its_exact_rule_cap("0.0.0.0 a.example\n", ListFormat::Hosts, 1).await;
        // Bare domains.
        reloads_at_its_exact_rule_cap("a.example\nb.example\nc.example\n", ListFormat::Domains, 3)
            .await;
        // Plain rules only.
        reloads_at_its_exact_rule_cap("||a.example^\n|b.example^\n", ListFormat::Adblock, 2).await;
        // Three groups, a plain rule and a slow rule: six rules in all.
        let mixed = "||a.example^\n0.0.0.0 b.example c.example\n127.0.0.1 d.example\n\
                     2001:db8::1 e.example\nx*y\n";
        reloads_at_its_exact_rule_cap(mixed, ListFormat::Adblock, 6).await;
    }

    /// A file whose body ends with the counts of a list without host or slow rules: the
    /// number of host groups, the length of the host entries (8 bytes) and the number of slow
    /// rules.
    fn with_counts(good: &[u8], groups: u32, slow: u32, fix: bool) -> Vec<u8> {
        let mut bytes = good.to_vec();
        let end = bytes.len() - CHECKSUM_BYTES as usize;
        bytes[end - 16..end - 12].copy_from_slice(&groups.to_le_bytes());
        bytes[end - 4..end].copy_from_slice(&slow.to_le_bytes());
        if fix {
            fix_checksum(&mut bytes);
        }

        bytes
    }

    #[tokio::test]
    async fn counts_the_file_cannot_back_are_refused_with_a_valid_checksum() {
        let state = TestDir::new("snap");
        let (path, good) = saved_bytes(&state, "||a.example^\n").await;
        let generous = CompileOptions::new(ListFormat::Auto, 3_000_000);

        // Within the rule cap, but far more groups or rules than the bytes left could hold.
        for (groups, slow) in [(2_000_000, 0), (0, 2_000_000), (1, 0), (0, 1)] {
            fs::write(&path, with_counts(&good, groups, slow, true)).unwrap();
            let error = load(&path, &generous).err().expect("refused");

            // A group count that fits the bytes left is read as far as it goes: the data that
            // follows is not an address.
            assert!(
                matches!(error, SnapshotError::Truncated | SnapshotError::Corrupt(_)),
                "{groups}/{slow}: {error:?}"
            );
        }

        // Over the rule cap.
        for (groups, slow) in [(u32::MAX, 0), (0, u32::MAX), (5001, 0), (0, 5001)] {
            fs::write(&path, with_counts(&good, groups, slow, true)).unwrap();
            let error = load(&path, &caps()).err().expect("refused");

            assert!(
                matches!(error, SnapshotError::TooLarge(_)),
                "{groups}/{slow}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_file_over_the_largest_possible_snapshot_is_refused_before_it_is_read() {
        let state = TestDir::new("snap");
        let path = state.path().join("sparse.pgs");
        let options = capped(10);
        let limit = max_file_bytes(&options);
        let sparse = |length: u64| {
            let mut file = File::create(&path).unwrap();
            file.write_all(&MAGIC).unwrap();
            file.write_all(&FILE_VERSION.to_le_bytes()).unwrap();
            file.set_len(length).unwrap();
        };

        sparse(limit + 1);
        let started = std::time::Instant::now();
        let over = load(&path, &options).err().expect("refused");
        sparse(1 << 40);
        let huge = load(&path, &options).err().expect("refused");

        assert!(matches!(over, SnapshotError::TooLarge(_)), "{over:?}");
        assert!(matches!(huge, SnapshotError::TooLarge(_)), "{huge:?}");
        assert!(started.elapsed() < Duration::from_secs(2));
        sparse(limit);
        let at_the_limit = load(&path, &options).err().expect("refused");
        assert!(matches!(at_the_limit, SnapshotError::BadChecksum));
    }

    #[tokio::test]
    async fn the_largest_possible_snapshot_is_never_smaller_than_a_real_one() {
        let worker = CompileWorker::spawn().unwrap();
        let state = TestDir::new("snap");
        let store = SnapshotStore::open(state.path()).unwrap();
        let snapshot = snapshot_of(&worker, MIXED, ListFormat::Auto).await;
        store.save(clone_of(&snapshot)).await.unwrap();
        store.flush().await;
        let path = store.path_for(SOURCE).unwrap();

        let size = fs::metadata(&path).unwrap().len();

        assert!(size <= max_file_bytes(&options(ListFormat::Auto)));
        assert!(load(&path, &options(ListFormat::Auto)).is_ok());
    }

    #[tokio::test]
    async fn the_checksum_is_checked_before_any_count_is_read() {
        let state = TestDir::new("snap");
        let (path, good) = saved_bytes(&state, "||a.example^\n").await;
        let generous = CompileOptions::new(ListFormat::Auto, 3_000_000);

        // Counts that would fail every other check; only the checksum can be the answer.
        for (groups, slow) in [(1, 0), (0, 1), (2_000_000, 2_000_000), (u32::MAX, u32::MAX)] {
            fs::write(&path, with_counts(&good, groups, slow, false)).unwrap();
            let error = load(&path, &generous).err().expect("refused");

            assert!(
                matches!(error, SnapshotError::BadChecksum),
                "{groups}/{slow}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_slow_rule_budget_of_the_compiler_applies_to_a_snapshot_load() {
        let state = TestDir::new("snap");
        let text: String = (0..20).map(|i| format!("a{i}*b\n")).collect();
        let (path, _) = saved_bytes(&state, &text).await;
        let loaded = load(&path, &caps()).unwrap();
        let total: usize = loaded.list.slow.iter().map(slow_rule_cost).sum();
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
    async fn host_groups_are_charged_to_the_budget_when_a_snapshot_loads() {
        let state = TestDir::new("snap");
        let text: String = (0..10)
            .map(|i| format!("10.0.0.{i} a{i}.example\n"))
            .collect();
        let (path, _) = saved_bytes(&state, &text).await;
        let budget = |slow_rule_budget| CompileOptions {
            slow_rule_budget,
            ..caps()
        };

        assert!(load(&path, &budget(10 * HOST_GROUP_BYTES)).is_ok());
        let error = load(&path, &budget(10 * HOST_GROUP_BYTES - 1))
            .err()
            .expect("over the budget");

        assert!(matches!(error, SnapshotError::TooLarge(_)), "{error:?}");
    }

    #[tokio::test]
    async fn a_snapshot_with_more_host_groups_than_the_cap_is_refused() {
        let worker = CompileWorker::spawn().unwrap();
        let state = TestDir::new("snap");
        let store = SnapshotStore::open(state.path()).unwrap();
        let mut snapshot = snapshot_of(&worker, "||a.example^\n", ListFormat::Auto).await;
        let group_ip = |index: u32| IpAddr::from((0x0A00_0000 + index).to_be_bytes());
        let list_with_groups = |count: u32| {
            Arc::new(CompiledList {
                fast: Default::default(),
                hosts: HostRules {
                    ips: (0..count).map(group_ip).collect(),
                    entries: Vec::new(),
                },
                slow: Vec::new(),
                regex_failed: 0,
            })
        };
        let unlimited = CompileOptions {
            slow_rule_budget: usize::MAX / 2,
            ..caps()
        };

        snapshot.list = list_with_groups(MAX_HOST_GROUPS as u32);
        store.save(clone_of(&snapshot)).await.unwrap();
        store.flush().await;
        let path = store.path_for(SOURCE).unwrap();
        assert!(load(&path, &unlimited).is_ok());

        snapshot.meta.fingerprint += 1;
        snapshot.list = list_with_groups(MAX_HOST_GROUPS as u32 + 1);
        store.save(clone_of(&snapshot)).await.unwrap();
        store.flush().await;
        let error = load(&path, &unlimited).err().expect("over the cap");

        assert!(matches!(error, SnapshotError::TooLarge(_)), "{error:?}");
    }

    #[tokio::test]
    async fn a_damaged_file_is_replaced_by_the_same_snapshot() {
        let worker = CompileWorker::spawn().unwrap();
        let state = TestDir::new("snap");
        let store = SnapshotStore::open(state.path()).unwrap();
        let list: String = (0..2000).map(|i| format!("||host{i}.example^\n")).collect();
        let snapshot = snapshot_of(&worker, &list, ListFormat::Auto).await;
        store.save(clone_of(&snapshot)).await.unwrap();
        store.flush().await;
        let path = store.path_for(SOURCE).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x01;
        fs::write(&path, &bytes).unwrap();
        let before = store.bytes_written();

        store.save(clone_of(&snapshot)).await.unwrap();
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

        let error = store
            .save(snapshot_of(&worker, MIXED, ListFormat::Auto).await)
            .await
            .unwrap_err();
        store.flush().await;
        assert!(error.to_string().contains("lists"), "{error}");
        assert_eq!(store.bytes_written(), 0);

        fs::remove_file(state.path().join("lists")).unwrap();
        store
            .save(snapshot_of(&worker, MIXED, ListFormat::Auto).await)
            .await
            .unwrap();
        store.flush().await;
        assert!(store.bytes_written() > 0);
        assert!(load(&store.path_for(SOURCE).unwrap(), &caps()).is_ok());
    }

    // ---- The writer with a fake disk ----

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        CreateDir(PathBuf),
        SyncDir(PathBuf),
        Rename,
        RemoveFile,
    }

    #[derive(Default)]
    struct Faults {
        /// The file takes this many bytes, then every write fails.
        fail_write_after: Option<usize>,
        fail_rename: bool,
        fail_file_sync: bool,
        fail_dir_sync: bool,
    }

    /// The real disk, watched, with failures on demand and a gate that holds the writer
    /// before it opens its file.
    struct TestFiles {
        calls: std::sync::Mutex<Vec<Call>>,
        faults: std::sync::Mutex<Faults>,
        gate_open: std::sync::Mutex<bool>,
        gate_changed: std::sync::Condvar,
    }

    impl TestFiles {
        fn new() -> Arc<TestFiles> {
            Arc::new(TestFiles {
                calls: std::sync::Mutex::new(Vec::new()),
                faults: std::sync::Mutex::new(Faults::default()),
                gate_open: std::sync::Mutex::new(true),
                gate_changed: std::sync::Condvar::new(),
            })
        }

        fn calls(&self) -> Vec<Call> {
            std::mem::take(&mut *self.calls.lock().unwrap())
        }

        fn set_faults(&self, faults: Faults) {
            *self.faults.lock().unwrap() = faults;
        }

        fn set_gate(&self, open: bool) {
            *self.gate_open.lock().unwrap() = open;
            self.gate_changed.notify_all();
        }

        fn record(&self, call: Call) {
            self.calls.lock().unwrap().push(call);
        }
    }

    fn injected(what: &str) -> io::Error {
        io::Error::other(format!("injected failure: {what}"))
    }

    impl Files for TestFiles {
        fn create_dir(&self, path: &Path) -> io::Result<()> {
            self.record(Call::CreateDir(path.to_path_buf()));

            DiskFiles.create_dir(path)
        }

        fn create_file(&self, path: &Path) -> io::Result<Box<dyn OpenFile>> {
            let mut open = self.gate_open.lock().unwrap();
            while !*open {
                open = self.gate_changed.wait(open).unwrap();
            }

            let faults = self.faults.lock().unwrap();

            Ok(Box::new(TestFile {
                file: File::create(path)?,
                writable: faults.fail_write_after,
                fail_sync: faults.fail_file_sync,
            }))
        }

        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            self.record(Call::Rename);
            if self.faults.lock().unwrap().fail_rename {
                return Err(injected("rename"));
            }

            DiskFiles.rename(from, to)
        }

        fn remove_file(&self, path: &Path) -> io::Result<()> {
            self.record(Call::RemoveFile);

            DiskFiles.remove_file(path)
        }

        fn sync_dir(&self, path: &Path) -> io::Result<()> {
            self.record(Call::SyncDir(path.to_path_buf()));
            if self.faults.lock().unwrap().fail_dir_sync {
                return Err(injected("directory sync"));
            }

            DiskFiles.sync_dir(path)
        }
    }

    struct TestFile {
        file: File,
        writable: Option<usize>,
        fail_sync: bool,
    }

    impl Write for TestFile {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            let Some(left) = self.writable else {
                return self.file.write(data);
            };

            if left == 0 {
                return Err(injected("write"));
            }

            let count = self.file.write(&data[..left.min(data.len())])?;
            self.writable = Some(left - count);

            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.file.flush()
        }
    }

    impl OpenFile for TestFile {
        fn sync_all(&mut self) -> io::Result<()> {
            if self.fail_sync {
                return Err(injected("file sync"));
            }

            self.file.sync_all()
        }
    }

    async fn sleep_a_little() {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }

    #[tokio::test]
    async fn save_returns_after_the_write_and_the_writer_keeps_nothing() {
        let worker = CompileWorker::spawn().unwrap();
        let state = TestDir::new("snap");
        let files = TestFiles::new();
        files.set_gate(false);
        let store = Arc::new(SnapshotStore::open_with(state.path(), files.clone()).unwrap());
        let snapshot = snapshot_of(&worker, MIXED, ListFormat::Auto).await;
        let probe = Arc::clone(&snapshot.list);
        let path = store.path_for(SOURCE).unwrap();

        let saving = tokio::spawn({
            let store = Arc::clone(&store);

            async move { store.save(snapshot).await }
        });
        sleep_a_little().await;

        // The writer is stuck and holds the list: the save has not finished.
        assert!(!saving.is_finished());
        assert_eq!(Arc::strong_count(&probe), 2);
        assert!(!path.exists());

        files.set_gate(true);
        saving.await.unwrap().unwrap();

        assert!(path.exists());
        assert_eq!(Arc::strong_count(&probe), 1);
    }

    #[tokio::test]
    async fn drain_waits_for_a_busy_writer_but_not_forever() {
        let worker = CompileWorker::spawn().unwrap();
        let state = TestDir::new("snap");
        let files = TestFiles::new();
        files.set_gate(false);
        let store = Arc::new(SnapshotStore::open_with(state.path(), files.clone()).unwrap());
        let path = store.path_for(SOURCE).unwrap();
        let snapshot = snapshot_of(&worker, MIXED, ListFormat::Auto).await;
        let saving = tokio::spawn({
            let store = Arc::clone(&store);

            async move { store.save(snapshot).await }
        });
        sleep_a_little().await;

        // The writer is stuck on the gate: drain gives up, and the file is not there yet.
        assert!(!store.drain(Duration::from_millis(100)).await);
        assert!(!path.exists());

        // Once the disk answers, drain returns after the write is done.
        files.set_gate(true);
        assert!(store.drain(Duration::from_secs(10)).await);
        assert!(path.exists());
        saving.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_refresh_loop_waits_for_a_slow_writer_before_building_the_next_list() {
        let worker = Arc::new(CompileWorker::spawn().unwrap());
        let state = TestDir::new("snap");
        let files = TestFiles::new();
        files.set_gate(false);
        let store = Arc::new(SnapshotStore::open_with(state.path(), files.clone()).unwrap());
        let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let alive_at_start = Arc::new(std::sync::Mutex::new(Vec::new()));

        let refreshes = tokio::spawn({
            let (worker, store) = (Arc::clone(&worker), Arc::clone(&store));
            let (started, alive_at_start) = (Arc::clone(&started), Arc::clone(&alive_at_start));

            async move {
                let mut earlier: Vec<std::sync::Weak<CompiledList>> = Vec::new();
                for text in ["||a.example^\n", "||b.example^\n", "||c.example^\n"] {
                    let alive = earlier
                        .iter()
                        .filter(|list| list.strong_count() > 0)
                        .count();
                    alive_at_start.lock().unwrap().push(alive);
                    started.fetch_add(1, Ordering::SeqCst);

                    let snapshot = snapshot_of(&worker, text, ListFormat::Auto).await;
                    earlier.push(Arc::downgrade(&snapshot.list));
                    store.save(snapshot).await.unwrap();
                }
            }
        });
        sleep_a_little().await;

        // The first list is with the stuck writer; the second is not even started.
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert!(!refreshes.is_finished());

        files.set_gate(true);
        refreshes.await.unwrap();

        assert_eq!(started.load(Ordering::SeqCst), 3);
        assert_eq!(*alive_at_start.lock().unwrap(), [0, 0, 0]);
    }

    #[tokio::test]
    async fn the_parent_of_every_new_directory_is_synced() {
        let worker = CompileWorker::spawn().unwrap();
        let state = TestDir::new("snap");
        let files = TestFiles::new();
        let base = state.path().to_path_buf();
        let store = SnapshotStore::open_with(&base.join("deep/er"), files.clone()).unwrap();

        store
            .save(snapshot_of(&worker, "||a.example^\n", ListFormat::Auto).await)
            .await
            .unwrap();

        let lists = base.join("deep/er/lists");
        assert_eq!(
            files.calls(),
            [
                Call::CreateDir(base.join("deep")),
                Call::CreateDir(base.join("deep/er")),
                Call::CreateDir(lists.clone()),
                Call::SyncDir(base.clone()),
                Call::SyncDir(base.join("deep")),
                Call::SyncDir(base.join("deep/er")),
                Call::Rename,
                Call::SyncDir(lists.clone()),
            ]
        );

        // The directories exist now: a new text syncs the list directory and nothing else.
        store
            .save(snapshot_of(&worker, "||b.example^\n", ListFormat::Auto).await)
            .await
            .unwrap();

        assert_eq!(files.calls(), [Call::Rename, Call::SyncDir(lists)]);
    }

    /// Saves `text` through a disk that fails as `faults` say; returns the store, the disk
    /// and the files left in the list directory.
    async fn save_with_faults(
        state: &TestDir,
        text: &str,
        faults: Faults,
    ) -> (SnapshotStore, Arc<TestFiles>, Vec<String>) {
        let worker = CompileWorker::spawn().unwrap();
        let files = TestFiles::new();
        files.set_faults(faults);
        let store = SnapshotStore::open_with(state.path(), files.clone()).unwrap();

        store
            .save(snapshot_of(&worker, text, ListFormat::Auto).await)
            .await
            .unwrap_err();
        let left = files_in(&lists_dir(state));

        (store, files, left)
    }

    async fn size_of_a_good_file(text: &str) -> u64 {
        let state = TestDir::new("snap");
        let (path, bytes) = saved_bytes(&state, text).await;
        assert!(path.exists());

        bytes.len() as u64
    }

    #[tokio::test]
    async fn bytes_are_counted_as_they_reach_the_file_even_when_the_write_fails() {
        // Slow rules, so that the file is well over the 64 KiB of the write buffer.
        let big: String = (0..4000)
            .map(|i| format!("||host{i}.*.example^\n"))
            .collect();
        let size = size_of_a_good_file(MIXED).await;
        let big_size = size_of_a_good_file(&big).await;
        assert!(size > 100 && big_size > 100_000);

        // A write that fails after a prefix: inside the buffer, and past a buffer flush.
        for (text, prefix) in [(MIXED, 100), (big.as_str(), 70_000)] {
            let state = TestDir::new("snap");
            let faults = Faults {
                fail_write_after: Some(prefix),
                ..Faults::default()
            };

            let (store, _, left) = save_with_faults(&state, text, faults).await;

            assert_eq!(store.bytes_written(), prefix as u64, "{prefix}");
            assert!(left.is_empty(), "{left:?}");
        }

        // Everything was written, then the rename or the sync of the file failed.
        for faults in [
            Faults {
                fail_rename: true,
                ..Faults::default()
            },
            Faults {
                fail_file_sync: true,
                ..Faults::default()
            },
        ] {
            let state = TestDir::new("snap");

            let (store, _, left) = save_with_faults(&state, MIXED, faults).await;

            assert_eq!(store.bytes_written(), size);
            assert!(left.is_empty(), "{left:?}");
        }
    }

    #[tokio::test]
    async fn the_sync_of_a_new_directory_that_failed_is_retried_before_anything_is_written() {
        let worker = CompileWorker::spawn().unwrap();
        let state = TestDir::new("snap");
        let files = TestFiles::new();
        let base = state.path().join("deep");
        let store = SnapshotStore::open_with(&base, files.clone()).unwrap();
        files.set_faults(Faults {
            fail_dir_sync: true,
            ..Faults::default()
        });

        // The directories are created, the sync of their parents fails, nothing is written.
        for _ in 0..2 {
            store
                .save(snapshot_of(&worker, MIXED, ListFormat::Auto).await)
                .await
                .unwrap_err();
        }

        assert_eq!(store.bytes_written(), 0);
        assert!(files_in(&base.join("lists")).is_empty());
        files.calls();

        files.set_faults(Faults::default());
        store
            .save(snapshot_of(&worker, MIXED, ListFormat::Auto).await)
            .await
            .unwrap();

        // The directories exist, but the syncs that were owed are made before the file.
        assert_eq!(
            files.calls(),
            [
                Call::SyncDir(state.path().to_path_buf()),
                Call::SyncDir(base.clone()),
                Call::Rename,
                Call::SyncDir(base.join("lists")),
            ]
        );
        assert!(store.bytes_written() > 0);
    }

    #[tokio::test]
    async fn a_directory_sync_after_the_rename_is_retried_without_writing_the_file_again() {
        let worker = CompileWorker::spawn().unwrap();
        let state = TestDir::new("snap");
        let files = TestFiles::new();
        let store = SnapshotStore::open_with(state.path(), files.clone()).unwrap();
        store
            .save(snapshot_of(&worker, "||a.example^\n", ListFormat::Auto).await)
            .await
            .unwrap();
        let size_before = store.bytes_written();
        files.calls();
        files.set_faults(Faults {
            fail_dir_sync: true,
            ..Faults::default()
        });

        store
            .save(snapshot_of(&worker, MIXED, ListFormat::Auto).await)
            .await
            .unwrap_err();
        let size_after_the_failure = store.bytes_written();
        assert!(size_after_the_failure > size_before);
        let path = store.path_for(SOURCE).unwrap();
        assert!(load(&path, &caps()).is_ok(), "the file is in place");
        files.calls();

        // The same text again: the file already holds it, but the directory is not synced.
        store
            .save(snapshot_of(&worker, MIXED, ListFormat::Auto).await)
            .await
            .unwrap_err();
        assert_eq!(files.calls(), [Call::SyncDir(lists_dir(&state))]);

        files.set_faults(Faults::default());
        store
            .save(snapshot_of(&worker, MIXED, ListFormat::Auto).await)
            .await
            .unwrap();

        assert_eq!(files.calls(), [Call::SyncDir(lists_dir(&state))]);
        assert_eq!(store.bytes_written(), size_after_the_failure);

        // Nothing is owed any more: the same text again touches no directory.
        store
            .save(snapshot_of(&worker, MIXED, ListFormat::Auto).await)
            .await
            .unwrap();

        assert_eq!(files.calls(), []);
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

    #[tokio::test]
    async fn a_snapshot_fits_only_the_redirect_setting_it_was_made_with() {
        let worker = CompileWorker::spawn().unwrap();
        let state = TestDir::new("snap");
        let store = SnapshotStore::open(state.path()).unwrap();
        let blocking = CompileOptions {
            allow_redirects: false,
            ..options(ListFormat::Hosts)
        };
        let compiled = compile(&worker, "1.2.3.4 bank.example\n", blocking).await;
        let snapshot = Snapshot::new(&compiled, &blocking, SOURCE, Validators::default());
        store.save(clone_of(&snapshot)).await.unwrap();
        store.flush().await;

        let loaded = load(&store.path_for(SOURCE).unwrap(), &blocking).unwrap();

        assert!(!loaded.meta.allow_redirects);
        assert!(loaded.fits(SOURCE, &blocking));
        let allowing = CompileOptions {
            allow_redirects: true,
            ..blocking
        };
        assert!(!loaded.fits(SOURCE, &allowing));
    }

    #[test]
    fn the_fingerprint_depends_on_every_part() {
        let base = fingerprint(1, ListFormat::Auto, ListFormat::Adblock, 10, false, 1);
        let all: HashMap<&str, u128> = HashMap::from([
            (
                "content",
                fingerprint(2, ListFormat::Auto, ListFormat::Adblock, 10, false, 1),
            ),
            (
                "configured",
                fingerprint(1, ListFormat::Hosts, ListFormat::Adblock, 10, false, 1),
            ),
            (
                "effective",
                fingerprint(1, ListFormat::Auto, ListFormat::Hosts, 10, false, 1),
            ),
            (
                "cap",
                fingerprint(1, ListFormat::Auto, ListFormat::Adblock, 11, false, 1),
            ),
            (
                "redirects",
                fingerprint(1, ListFormat::Auto, ListFormat::Adblock, 10, true, 1),
            ),
            (
                "compiler",
                fingerprint(1, ListFormat::Auto, ListFormat::Adblock, 10, false, 2),
            ),
        ]);

        for (part, value) in all {
            assert_ne!(value, base, "{part}");
        }

        assert_eq!(
            base,
            fingerprint(1, ListFormat::Auto, ListFormat::Adblock, 10, false, 1)
        );
    }
}
