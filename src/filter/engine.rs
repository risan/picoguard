//! The lookup engine: per-list compiled rules, the `$badfilter` index and the decision of
//! plan section 4.5.
//!
//! Plain rules are stored as sorted arrays of xxh3-64 hashes of the lowercase name, one array
//! per rule shape and list (plan D3, D4): 8 bytes per rule and no per-entry allocation. A
//! lookup hashes the candidate substrings of the input (see [`super::pattern`]) and
//! binary-searches the arrays. Everything else is a slow rule with a [`Matcher`].

use std::borrow::Cow;
use std::cell::Cell;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io::{self, Read};
use std::net::IpAddr;
use std::sync::Arc;

use xxhash_rust::xxh3::{Xxh3, xxh3_64};

use super::compile::{COMPILE_PEAK_BYTES_PER_RULE, SEEN_SLOW_RULE_BYTES, slow_rule_cost};
use super::parse::{FastKind, ListFormat, NetworkRule, ParseSummary, Parser, Rule, fast_rule};
use super::pattern::{
    Matcher, PatternError, for_each_exact_candidate, for_each_strict_suffix_candidate,
    for_each_suffix_candidate,
};

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_HTTPS: u16 = 65;

const READ_PIECE_BYTES: usize = 64 * 1024;

const SUB_BLOCK: usize = 0;
const EXACT_BLOCK: usize = 1;
const SUB_ALLOW: usize = 2;
const EXACT_ALLOW: usize = 3;
const STRICT_BLOCK: usize = 4;
const STRICT_ALLOW: usize = 5;
pub(super) const FAST_KINDS: usize = 6;

fn kind_index(kind: FastKind) -> usize {
    match kind {
        FastKind::SubBlock => SUB_BLOCK,
        FastKind::ExactBlock => EXACT_BLOCK,
        FastKind::SubAllow => SUB_ALLOW,
        FastKind::ExactAllow => EXACT_ALLOW,
        FastKind::StrictSubBlock => STRICT_BLOCK,
        FastKind::StrictSubAllow => STRICT_ALLOW,
    }
}

fn hash(name: &str) -> u64 {
    xxh3_64(name.as_bytes())
}

// ---- Compiled lists ----

/// The low bits of a host entry hold the group (the answer IP) its name maps to; the rest is
/// the hash of the name. One sorted array per list therefore finds a name whatever the number
/// of groups, at 8 bytes per name and group.
const HOST_GROUP_BITS: u32 = 10;
const HOST_GROUP_MASK: u64 = (1 << HOST_GROUP_BITS) - 1;

/// The most distinct answer IPs the host rules of one list may have.
pub(super) const MAX_HOST_GROUPS: usize = 1 << HOST_GROUP_BITS;

/// The host rules of one list.
#[derive(Default)]
pub(super) struct HostRules {
    /// The answer IP of each group, in the order the groups first appeared in the list.
    pub(super) ips: Vec<IpAddr>,
    /// Sorted, distinct: the hash of a name with its group in the low bits.
    pub(super) entries: Vec<u64>,
}

impl HostRules {
    fn entry(name_hash: u64, group: usize) -> u64 {
        (name_hash & !HOST_GROUP_MASK) | group as u64
    }

    /// True when every entry names a group that exists.
    pub(super) fn groups_exist(&self) -> bool {
        self.entries
            .iter()
            .all(|entry| ((entry & HOST_GROUP_MASK) as usize) < self.ips.len())
    }

    /// The answer IPs `name_hash` maps to, in the order the groups appeared.
    fn ips_of(&self, name_hash: u64) -> impl Iterator<Item = &IpAddr> {
        let first = name_hash & !HOST_GROUP_MASK;
        let start = lower_bound(&self.entries, first);

        self.entries[start..]
            .iter()
            .take_while(move |entry| *entry & !HOST_GROUP_MASK == first)
            .map(|entry| &self.ips[(*entry & HOST_GROUP_MASK) as usize])
    }
}

pub(super) struct SlowRule {
    pub(super) rule: NetworkRule,
    matcher: Matcher,
    /// Hash of what `$badfilter` compares, so another list's badfilter can find the rule.
    pub(super) identity: u64,
}

impl SlowRule {
    /// Fails when the pattern is a regular expression the `regex` crate rejects.
    pub(super) fn compile(rule: NetworkRule) -> Result<SlowRule, ()> {
        SlowRule::compile_within(rule, usize::MAX).map_err(|_| ())
    }

    /// `compile` with a regex that may hold at most `size_limit` bytes while it is built (see
    /// `Matcher::compile_within`).
    pub(super) fn compile_within(
        rule: NetworkRule,
        size_limit: usize,
    ) -> Result<SlowRule, PatternError> {
        let matcher = Matcher::compile_within(&rule.pattern, size_limit)?;

        Ok(SlowRule {
            identity: identity_hash(&rule),
            matcher,
            rule,
        })
    }

    /// The most that building the matcher held at once.
    pub(super) fn build_bytes(&self) -> usize {
        self.matcher.build_bytes()
    }

    /// What the compiled matcher costs in the slow-rule budget.
    pub(super) fn matcher_cost_bytes(&self) -> usize {
        self.matcher.cost_bytes()
    }
}

/// The rules of one list, ready for lookups. Shared between engines through an `Arc`
/// (plan D6): a refresh of another list does not rebuild it.
pub struct CompiledList {
    pub(super) fast: [Vec<u64>; FAST_KINDS],
    pub(super) hosts: HostRules,
    pub(super) slow: Vec<SlowRule>,
    pub(super) regex_failed: u64,
    /// What a compile of the same text is charged against the memory budget at its peak
    /// (see `compile_charge`).
    pub(super) compile_charge: usize,
}

impl CompiledList {
    /// Parses and compiles a whole list held in memory.
    pub fn from_text(format: ListFormat, text: &str) -> (CompiledList, ParseSummary) {
        let mut builder = ListBuilder::new();
        let mut parser = Parser::new(format, usize::MAX);
        let mut sink = |rule: Rule<'_>| builder.add(rule);
        parser.push(text.as_bytes(), &mut sink);
        let summary = parser.finish(&mut sink);

        (builder.finish(summary.format), summary)
    }

    /// Parses and compiles a list read in pieces; at most `max_rules` rules are kept.
    pub fn from_reader(
        format: ListFormat,
        max_rules: usize,
        mut reader: impl Read,
    ) -> io::Result<(CompiledList, ParseSummary)> {
        let mut builder = ListBuilder::new();
        let mut parser = Parser::new(format, max_rules);
        let mut sink = |rule: Rule<'_>| builder.add(rule);
        let mut piece = vec![0u8; READ_PIECE_BYTES];
        loop {
            let length = reader.read(&mut piece)?;
            if length == 0 {
                break;
            }

            parser.push(&piece[..length], &mut sink);
        }

        let summary = parser.finish(&mut sink);

        Ok((builder.finish(summary.format), summary))
    }

    /// Distinct rules: plain rules, host names and slow rules.
    pub fn rule_count(&self) -> usize {
        self.fast.iter().map(Vec::len).sum::<usize>() + self.hosts.entries.len() + self.slow.len()
    }

    pub fn slow_rule_count(&self) -> usize {
        self.slow.len()
    }

    /// The heap the list holds: the capacities of its arrays, and its slow rules as the
    /// slow-rule budget estimates them (plan D6).
    pub fn heap_bytes(&self) -> usize {
        let arrays = self
            .fast
            .iter()
            .chain([&self.hosts.entries])
            .map(|hashes| hashes.capacity() * size_of::<u64>())
            .sum::<usize>()
            + self.hosts.ips.capacity() * size_of::<IpAddr>()
            + self.slow.capacity() * size_of::<SlowRule>();

        arrays + self.slow.iter().map(slow_rule_cost).sum::<usize>()
    }

    /// What compiling this list again is charged against the memory budget at its peak: every
    /// plain rule of the text, duplicates included, its slow rules, and the most a regex held
    /// while it was built (plan D6). A compile within exactly this many bytes is admitted.
    pub fn compile_charge(&self) -> usize {
        self.compile_charge
    }

    /// Slow rules dropped because their regular expression does not compile.
    pub fn regex_failed(&self) -> u64 {
        self.regex_failed
    }
}

/// Collects the rules of one list. Hashes go straight into arrays; `finish` sorts them.
pub struct ListBuilder {
    fast: [Vec<u64>; FAST_KINDS],
    hosts: HostRules,
    host_index: HashMap<IpAddr, usize>,
    slow: Vec<SlowRule>,
    regex_failed: u64,
    /// Plain and host rules added, duplicates included.
    plain_added: usize,
}

impl Default for ListBuilder {
    fn default() -> Self {
        ListBuilder::new()
    }
}

impl ListBuilder {
    pub fn new() -> ListBuilder {
        ListBuilder {
            fast: Default::default(),
            hosts: HostRules::default(),
            host_index: HashMap::new(),
            slow: Vec::new(),
            regex_failed: 0,
            plain_added: 0,
        }
    }

    /// True when the host rules already have a group for `ip`.
    pub(super) fn has_host_group(&self, ip: IpAddr) -> bool {
        self.host_index.contains_key(&ip)
    }

    /// Adds a rule. A host rule that would start a group past `MAX_HOST_GROUPS` is left out;
    /// the compile worker refuses such a list before it gets here.
    pub fn add(&mut self, rule: Rule<'_>) {
        if !matches!(rule, Rule::Slow(_)) {
            self.plain_added += 1;
        }

        match rule {
            Rule::Host { ip, name } => {
                let group = match self.host_index.get(&ip) {
                    Some(group) => *group,

                    None if self.hosts.ips.len() < MAX_HOST_GROUPS => {
                        self.hosts.ips.push(ip);
                        self.host_index.insert(ip, self.hosts.ips.len() - 1);

                        self.hosts.ips.len() - 1
                    }

                    None => return,
                };

                self.hosts.entries.push(HostRules::entry(hash(name), group));
            }
            Rule::Fast { kind, name } => self.fast[kind_index(kind)].push(hash(name)),
            Rule::Slow(rule) => self.add_slow(SlowRule::compile(rule)),
        }
    }

    /// Adds a slow rule that is already compiled, or counts the regex that failed to.
    pub(super) fn add_slow(&mut self, slow: Result<SlowRule, ()>) {
        match slow {
            Ok(slow) => self.slow.push(slow),
            Err(()) => self.regex_failed += 1,
        }
    }

    /// Sorts, deduplicates and trims the arrays. `format` is the effective list format.
    pub fn finish(mut self, format: ListFormat) -> CompiledList {
        for hashes in self.fast.iter_mut() {
            sort_dedup(hashes);
        }

        sort_dedup(&mut self.hosts.entries);
        if format == ListFormat::Rpz {
            self.merge_rpz_pairs();
        }

        self.hosts.ips.shrink_to_fit();
        self.slow.shrink_to_fit();

        // The compile worker charges each rule as it comes and replaces this.
        let compile_charge = self.plain_added * COMPILE_PEAK_BYTES_PER_RULE
            + self
                .slow
                .iter()
                .map(|slow| slow_rule_cost(slow) + SEEN_SLOW_RULE_BYTES + slow.build_bytes())
                .sum::<usize>();

        CompiledList {
            fast: self.fast,
            hosts: self.hosts,
            slow: self.slow,
            regex_failed: self.regex_failed,
            compile_charge,
        }
    }

    /// An RPZ zone lists a name and `*.name` separately; both together are `||name^`.
    fn merge_rpz_pairs(&mut self) {
        for (exact, strict, sub) in [
            (EXACT_BLOCK, STRICT_BLOCK, SUB_BLOCK),
            (EXACT_ALLOW, STRICT_ALLOW, SUB_ALLOW),
        ] {
            let common: Vec<u64> = self.fast[exact]
                .iter()
                .copied()
                .filter(|hash| self.fast[strict].binary_search(hash).is_ok())
                .collect();
            if common.is_empty() {
                continue;
            }

            for kind in [exact, strict] {
                self.fast[kind].retain(|hash| common.binary_search(hash).is_err());
                self.fast[kind].shrink_to_fit();
            }

            self.fast[sub].extend(common);
            sort_dedup(&mut self.fast[sub]);
        }
    }
}

/// Membership in a sorted array of distinct xxh3 hashes. The hashes are uniformly spread, so
/// the position of `needle` can be estimated from its value: a few probes find it where a
/// binary search needs log2(n) probes that miss the CPU cache. Anything unexpected (a
/// skewed array) falls back to the binary search after a few rounds.
fn contains_hash(sorted: &[u64], needle: u64) -> bool {
    const ROUNDS: usize = 6;

    const LINEAR_TAIL: usize = 8;

    let (mut low, mut high) = (0, sorted.len());
    for _ in 0..ROUNDS {
        if high - low <= LINEAR_TAIL {
            return sorted[low..high].contains(&needle);
        }

        let (first, last) = (sorted[low], sorted[high - 1]);
        if needle < first || needle > last {
            return false;
        }

        let share = (needle - first) as f64 / (last - first) as f64;
        let at = low + (share * (high - low - 1) as f64) as usize;
        match sorted[at].cmp(&needle) {
            Ordering::Equal => return true,
            Ordering::Less => low = at + 1,
            Ordering::Greater => high = at,
        }
    }

    sorted[low..high].binary_search(&needle).is_ok()
}

/// Index of the first element of `sorted` that is not below `needle`. Found like
/// `contains_hash` does, by estimating the position first.
fn lower_bound(sorted: &[u64], needle: u64) -> usize {
    const ROUNDS: usize = 6;

    const LINEAR_TAIL: usize = 8;

    // Everything before `low` is below `needle`; everything from `high` on is not.
    let (mut low, mut high) = (0, sorted.len());
    for _ in 0..ROUNDS {
        if high - low <= LINEAR_TAIL {
            break;
        }

        let (first, last) = (sorted[low], sorted[high - 1]);
        if needle <= first {
            return low;
        }

        if needle > last {
            return high;
        }

        let share = (needle - first) as f64 / (last - first) as f64;
        let at = low + (share * (high - low - 1) as f64) as usize;
        if sorted[at] < needle {
            low = at + 1;
        } else {
            high = at;
        }
    }

    low + sorted[low..high].partition_point(|value| *value < needle)
}

fn sort_dedup(hashes: &mut Vec<u64>) {
    hashes.sort_unstable();
    hashes.dedup();
    hashes.shrink_to_fit();
}

/// Hashes the typed identity; `Hash` prefixes every string and list with its length, so
/// no two identities share an input.
fn identity_hash(rule: &NetworkRule) -> u64 {
    let mut hasher = Xxh3::new();
    rule.identity().hash(&mut hasher);

    hasher.finish()
}

/// The fast-path array and hash a rule with this identity would have, if it has one.
fn fast_key(rule: &NetworkRule) -> Option<(usize, u64)> {
    if rule.important
        || rule.restricted_types != 0
        || !rule.restricted_clients.is_empty()
        || !rule.restricted_ctags.is_empty()
    {
        return None;
    }

    let text = if rule.whitelist {
        format!("@@{}", rule.pattern)
    } else {
        rule.pattern.clone()
    };
    let (kind, name) = fast_rule(&text)?;

    Some((kind_index(kind), hash(name)))
}

// ---- Decisions ----

/// The most answer IPs one name gets from host rules. A hostile list can map one name to
/// hundreds of thousands of addresses; nothing past this is collected or copied.
pub const MAX_HOST_IPS: usize = 256;

/// What the engine decides for one input and record type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Pass,
    /// Blocked. `ips` are the answer IPs of host rules of the checked address family, in
    /// list order without duplicates; empty for network rules and other host rules. At most
    /// `MAX_HOST_IPS + 1` of them: the extra one marks a list that had more (see
    /// [`BlockedAnswer::TooMany`]).
    Block {
        ips: Vec<IpAddr>,
    },
}

/// A [`Decision`] that also says whether an allow rule matched. AdGuard Home does not filter
/// the response to a request that an allow rule matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// An allow rule matched: an allowlist, or an `@@` rule.
    Allow,
    Block {
        ips: Vec<IpAddr>,
    },
    NoMatch,
}

/// The reply AdGuard's default blocking mode builds for a blocked name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockedAnswer {
    Ips(Vec<IpAddr>),
    /// NOERROR without records.
    Empty,
    /// NOERROR with the fake SOA.
    NoData,
    /// The host rules gave more than `MAX_HOST_IPS` addresses; no complete answer is built.
    TooMany,
}

/// `query_type` is the type of the original question, `ips` the IPs of a [`Decision::Block`].
pub fn blocked_answer(query_type: u16, ips: &[IpAddr]) -> BlockedAnswer {
    if !matches!(query_type, TYPE_A | TYPE_AAAA | TYPE_HTTPS) {
        return BlockedAnswer::NoData;
    }

    let null_ip = match query_type {
        TYPE_A => Some(IpAddr::from([0, 0, 0, 0])),
        TYPE_AAAA => Some(IpAddr::from([0u16; 8])),
        _ => None,
    };
    if ips.len() > MAX_HOST_IPS {
        return BlockedAnswer::TooMany;
    }

    let answer: Vec<IpAddr> = match (query_type, null_ip) {
        (_, Some(null_ip)) if ips.is_empty() => vec![null_ip],
        (TYPE_A, _) if ips.iter().all(IpAddr::is_ipv4) => ips.to_vec(),
        (TYPE_AAAA, _) => ips.iter().filter(|ip| ip.is_ipv6()).copied().collect(),
        _ => Vec::new(),
    };

    if answer.is_empty() {
        BlockedAnswer::Empty
    } else {
        BlockedAnswer::Ips(answer)
    }
}

/// The strongest matching network rule: important allow, important block, allow, block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Class {
    Block,
    Allow,
    ImportantBlock,
    ImportantAllow,
}

/// One of the `for_each_*_candidate` walks of [`super::pattern`].
type CandidateWalk = fn(&str, &mut dyn FnMut(&str));

fn class_of(rule: &NetworkRule) -> Class {
    match (rule.whitelist, rule.important) {
        (true, true) => Class::ImportantAllow,
        (false, true) => Class::ImportantBlock,
        (true, false) => Class::Allow,
        (false, false) => Class::Block,
    }
}

/// A plain rule in adblock form; an RPZ `*.d` is `||*.d^`.
fn fast_text(kind: usize, name: &str) -> String {
    match kind {
        SUB_BLOCK => format!("||{name}^"),
        EXACT_BLOCK => format!("|{name}^"),
        SUB_ALLOW => format!("@@||{name}^"),
        EXACT_ALLOW => format!("@@|{name}^"),
        STRICT_BLOCK => format!("||*.{name}^"),
        _ => format!("@@||*.{name}^"),
    }
}

struct Query<'a> {
    host: &'a str,
    record_type: u16,
    is_ip: bool,
}

/// What restricts a rule to some record types or names.
#[derive(Clone)]
struct Condition {
    permitted: Vec<u16>,
    restricted: Vec<u16>,
    denyallow: Vec<String>,
}

impl Condition {
    fn of(rule: &NetworkRule) -> Condition {
        Condition {
            permitted: rule.dns_permitted.clone(),
            restricted: rule.dns_restricted.clone(),
            denyallow: rule.denyallow.clone(),
        }
    }

    fn holds(&self, query: &Query<'_>) -> bool {
        conditions_hold(&self.permitted, &self.restricted, &self.denyallow, query)
    }
}

fn conditions_hold(
    permitted: &[u16],
    restricted: &[u16],
    denyallow: &[String],
    query: &Query<'_>,
) -> bool {
    if restricted.contains(&query.record_type) {
        return false;
    }

    if !permitted.is_empty() && !permitted.contains(&query.record_type) {
        return false;
    }

    // urlfilter never lets a `$denyallow` rule match an IP address: IPs only come from
    // answer records, and the rule says nothing about them.
    denyallow.is_empty() || (!query.is_ip && !is_domain_or_subdomain_of_any(query.host, denyallow))
}

fn is_domain_or_subdomain_of_any(domain: &str, domains: &[String]) -> bool {
    domains.iter().any(|top| {
        domain == top
            || (domain.len() > top.len() + 1
                && domain.ends_with(top.as_str())
                && domain.as_bytes()[domain.len() - top.len() - 1] == b'.')
            || matches_tld_wildcard(domain, top)
    })
}

/// `$denyallow=google.*` stands for `google.` followed by a public suffix. urlfilter checks
/// the suffix against the ICANN part of the public suffix list; this build has a short list
/// of suffixes instead (see [`icann_suffix`]).
fn matches_tld_wildcard(domain: &str, wildcard: &str) -> bool {
    let Some(stem) = wildcard
        .strip_suffix('*')
        .filter(|stem| stem.ends_with('.'))
    else {
        return false;
    };

    let inside =
        domain.starts_with(stem) || domain.find(&format!(".{stem}")).is_some_and(|at| at > 0);
    if !inside {
        return false;
    }

    icann_suffix(domain).is_some_and(|suffix| domain.ends_with(&format!("{stem}{suffix}")))
}

const GENERIC_TLDS: &[&str] = &[
    "com",
    "net",
    "org",
    "edu",
    "gov",
    "mil",
    "int",
    "info",
    "biz",
    "name",
    "pro",
    "mobi",
    "asia",
    "tel",
    "travel",
    "jobs",
    "museum",
    "coop",
    "aero",
    "cat",
    "xxx",
    "post",
    "arpa",
    "app",
    "dev",
    "page",
    "xyz",
    "online",
    "site",
    "shop",
    "store",
    "tech",
    "top",
    "club",
    "cloud",
    "blog",
    "link",
    "live",
    "news",
    "one",
    "vip",
    "work",
    "world",
    "email",
    "website",
    "space",
    "media",
    "network",
    "digital",
    "systems",
    "solutions",
    "agency",
    "group",
    "company",
    "services",
    "today",
    "life",
    "fun",
    "icu",
    "bio",
    "art",
    "design",
    "studio",
    "global",
    "zone",
    "ltd",
    "inc",
    "llc",
];

const SECOND_LEVELS: &[&str] = &[
    "co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "mil", "sch", "nic",
];

/// An approximation of the ICANN public suffix of a name: a country code, optionally with a
/// common second level (`co.uk`), or one of the common generic top-level domains.
fn icann_suffix(domain: &str) -> Option<&str> {
    let mut labels = domain.rsplit('.');
    let last = labels.next()?;
    let country = last.len() == 2 && last.bytes().all(|b| b.is_ascii_lowercase());
    if !country {
        return GENERIC_TLDS.contains(&last).then_some(last);
    }

    match labels.next() {
        Some(second) if SECOND_LEVELS.contains(&second) && domain.matches('.').count() >= 2 => {
            Some(&domain[domain.len() - second.len() - last.len() - 1..])
        }
        _ => Some(last),
    }
}

// ---- Slow-rule index ----

/// How many leading bytes of a shortcut key the index.
const KEY_BYTES: usize = 4;

/// Finds the slow rules whose shortcut can occur in a URL, like urlfilter's shortcut table:
/// a rule is filed under the first [`KEY_BYTES`] bytes of its shortcut, and a check looks up
/// every window of that length in the URL. Rules with a shorter shortcut are always tried.
#[derive(Default)]
struct SlowIndex {
    /// `(key, list, rule)` sorted by key.
    keyed: Vec<(u32, u32, u32)>,
    always: Vec<(u32, u32)>,
}

fn key_of(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

impl SlowIndex {
    fn new(lists: &[Arc<CompiledList>]) -> SlowIndex {
        let mut index = SlowIndex::default();
        for (list_at, list) in lists.iter().enumerate() {
            for (rule_at, slow) in list.slow.iter().enumerate() {
                let (list_at, rule_at) = (list_at as u32, rule_at as u32);
                let shortcut = slow.matcher.shortcut().as_bytes();
                if shortcut.len() < KEY_BYTES {
                    index.always.push((list_at, rule_at));
                } else {
                    index.keyed.push((key_of(shortcut), list_at, rule_at));
                }
            }
        }

        index.keyed.sort_unstable();
        index.keyed.shrink_to_fit();
        index.always.shrink_to_fit();

        index
    }

    /// Calls `f` with the list position and the rule of every slow rule whose shortcut starts
    /// with some window of `url`, and of the rules without a usable shortcut. A rule may be
    /// offered more than once.
    fn for_each_candidate<'a>(
        &self,
        lists: &'a [Arc<CompiledList>],
        url: &str,
        f: &mut dyn FnMut(usize, &'a SlowRule),
    ) {
        for &(list, rule) in &self.always {
            f(list as usize, &lists[list as usize].slow[rule as usize]);
        }

        if self.keyed.is_empty() {
            return;
        }

        for window in url.as_bytes().windows(KEY_BYTES) {
            let key = key_of(window);
            let first = self.keyed.partition_point(|entry| entry.0 < key);
            for &(found, list, rule) in &self.keyed[first..] {
                if found != key {
                    break;
                }

                f(list as usize, &lists[list as usize].slow[rule as usize]);
            }
        }
    }
}

// ---- Rule sets ----

/// The rules of one urlfilter `DNSEngine`: a set of lists and the `$badfilter` index
/// built across them (plan D7).
struct RuleSet {
    lists: Vec<Arc<CompiledList>>,
    has_fast: [bool; FAST_KINDS],
    has_slow: bool,
    slow_index: SlowIndex,
    /// Hash of a plain rule's name, per array, that an unconditional badfilter disables.
    disabled_fast: [HashSet<u64>; FAST_KINDS],
    conditional_fast: [HashMap<u64, Vec<Condition>>; FAST_KINDS],
    disabled_slow: HashSet<u64>,
    conditional_slow: HashMap<u64, Vec<Condition>>,
}

impl RuleSet {
    fn new(lists: Vec<Arc<CompiledList>>) -> RuleSet {
        let mut set = RuleSet {
            has_fast: std::array::from_fn(|kind| lists.iter().any(|l| !l.fast[kind].is_empty())),
            has_slow: lists.iter().any(|list| !list.slow.is_empty()),
            slow_index: SlowIndex::new(&lists),
            lists,
            disabled_fast: Default::default(),
            conditional_fast: Default::default(),
            disabled_slow: HashSet::new(),
            conditional_slow: HashMap::new(),
        };

        let mut badfilters = Vec::new();
        for list in &set.lists {
            badfilters.extend(list.slow.iter().filter(|slow| slow.rule.badfilter));
        }

        let mut unconditional = Vec::new();
        let mut conditional = Vec::new();
        for slow in badfilters {
            let fast = fast_key(&slow.rule);
            if slow.rule.is_conditional() {
                conditional.push((slow.identity, fast, Condition::of(&slow.rule)));
            } else {
                unconditional.push((slow.identity, fast));
            }
        }

        for (identity, fast) in unconditional {
            set.disabled_slow.insert(identity);
            if let Some((kind, name)) = fast {
                set.disabled_fast[kind].insert(name);
            }
        }

        for (identity, fast, condition) in conditional {
            set.conditional_slow
                .entry(identity)
                .or_default()
                .push(condition.clone());
            if let Some((kind, name)) = fast {
                set.conditional_fast[kind]
                    .entry(name)
                    .or_default()
                    .push(condition);
            }
        }

        set
    }

    fn fast_hit(&self, kind: usize, name: u64, query: &Query<'_>) -> bool {
        let present = self
            .lists
            .iter()
            .any(|list| contains_hash(&list.fast[kind], name));
        if !present || self.disabled_fast[kind].contains(&name) {
            return false;
        }

        let overridden = self.conditional_fast[kind]
            .get(&name)
            .is_some_and(|conditions| conditions.iter().any(|c| c.holds(query)));

        !overridden
    }

    fn slow_disabled(&self, slow: &SlowRule, query: &Query<'_>) -> bool {
        self.disabled_slow.contains(&slow.identity)
            || self
                .conditional_slow
                .get(&slow.identity)
                .is_some_and(|conditions| conditions.iter().any(|c| c.holds(query)))
    }

    /// The strongest network rule that matches, after `$badfilter`.
    fn class(&self, query: &Query<'_>) -> Option<Class> {
        let best = Cell::new(None::<Class>);
        let note = |class: Class| best.set(best.get().max(Some(class)));

        if self.has_fast[SUB_BLOCK] || self.has_fast[SUB_ALLOW] {
            for_each_suffix_candidate(query.host, &mut |candidate| {
                let name = hash(candidate);
                if self.has_fast[SUB_BLOCK] && self.fast_hit(SUB_BLOCK, name, query) {
                    note(Class::Block);
                }

                if self.has_fast[SUB_ALLOW] && self.fast_hit(SUB_ALLOW, name, query) {
                    note(Class::Allow);
                }
            });
        }

        if self.has_fast[EXACT_BLOCK] || self.has_fast[EXACT_ALLOW] {
            for_each_exact_candidate(query.host, &mut |candidate| {
                let name = hash(candidate);
                if self.has_fast[EXACT_BLOCK] && self.fast_hit(EXACT_BLOCK, name, query) {
                    note(Class::Block);
                }

                if self.has_fast[EXACT_ALLOW] && self.fast_hit(EXACT_ALLOW, name, query) {
                    note(Class::Allow);
                }
            });
        }

        if self.has_fast[STRICT_BLOCK] || self.has_fast[STRICT_ALLOW] {
            for_each_strict_suffix_candidate(query.host, &mut |candidate| {
                let name = hash(candidate);
                if self.has_fast[STRICT_BLOCK] && self.fast_hit(STRICT_BLOCK, name, query) {
                    note(Class::Block);
                }

                if self.has_fast[STRICT_ALLOW] && self.fast_hit(STRICT_ALLOW, name, query) {
                    note(Class::Allow);
                }
            });
        }

        if !self.has_slow || best.get() == Some(Class::ImportantAllow) {
            return best.get();
        }

        let url = format!("http://{}", query.host);
        self.slow_index
            .for_each_candidate(&self.lists, &url, &mut |_, slow| {
                if self.slow_matches(slow, query, &url) {
                    note(class_of(&slow.rule));
                }
            });

        best.get()
    }

    /// Whether `slow` decides `query`: no badfilter itself, its conditions hold, its pattern
    /// matches and no badfilter disables it.
    fn slow_matches(&self, slow: &SlowRule, query: &Query<'_>, url: &str) -> bool {
        let rule = &slow.rule;
        let allowed = conditions_hold(
            &rule.dns_permitted,
            &rule.dns_restricted,
            &rule.denyallow,
            query,
        );

        !rule.badfilter
            && allowed
            && slow.matcher.is_match(query.host, url)
            && !self.slow_disabled(slow, query)
    }

    /// The list position and text of a rule of `class` that matches `query`, in the first
    /// list that holds one. Plain rules are rebuilt from the candidate that hit; slow rules
    /// come through the index like a check, so no other slow rule is looked at.
    fn find(&self, query: &Query<'_>, class: Class) -> Option<(usize, String)> {
        let mut best: Option<(usize, String)> = None;
        let kinds = match class {
            Class::Block => [SUB_BLOCK, EXACT_BLOCK, STRICT_BLOCK],
            Class::Allow => [SUB_ALLOW, EXACT_ALLOW, STRICT_ALLOW],
            Class::ImportantBlock | Class::ImportantAllow => [FAST_KINDS; 3],
        };

        for kind in kinds {
            let candidates: CandidateWalk = match kind {
                SUB_BLOCK | SUB_ALLOW => for_each_suffix_candidate,
                EXACT_BLOCK | EXACT_ALLOW => for_each_exact_candidate,
                STRICT_BLOCK | STRICT_ALLOW => for_each_strict_suffix_candidate,
                _ => continue,
            };

            candidates(query.host, &mut |candidate| {
                let name = hash(candidate);
                if !self.fast_hit(kind, name, query) {
                    return;
                }

                let first = self
                    .lists
                    .iter()
                    .position(|list| contains_hash(&list.fast[kind], name));
                if let Some(list) = first
                    && best.as_ref().is_none_or(|(at, _)| list < *at)
                {
                    best = Some((list, fast_text(kind, candidate)));
                }
            });
        }

        if self.has_slow {
            let url = format!("http://{}", query.host);
            let mut slow_best: Option<(usize, &SlowRule)> = None;
            self.slow_index
                .for_each_candidate(&self.lists, &url, &mut |list, slow| {
                    let earlier = slow_best.is_none_or(|(at, _)| list < at)
                        && best.as_ref().is_none_or(|(at, _)| list < *at);
                    if earlier
                        && class_of(&slow.rule) == class
                        && self.slow_matches(slow, query, &url)
                    {
                        slow_best = Some((list, slow));
                    }
                });

            if let Some((list, slow)) = slow_best {
                best = Some((list, slow.rule.text()));
            }
        }

        best
    }

    /// The first list with a host rule for `host`, and the first address it gives the name.
    fn host_rule(&self, host: &str) -> Option<(usize, IpAddr)> {
        let name = hash(host);

        self.lists
            .iter()
            .enumerate()
            .find_map(|(at, list)| list.hosts.ips_of(name).next().map(|ip| (at, *ip)))
    }

    /// The answer IPs of the host rules that match `host`, or `None` without a match. Only
    /// addresses of the family asked for are collected, and collecting stops one past
    /// `MAX_HOST_IPS`.
    fn host_rules(&self, host: &str, record_type: u16) -> Option<Vec<IpAddr>> {
        let name = hash(host);
        let wanted = |ip: &IpAddr| match record_type {
            TYPE_A => ip.is_ipv4(),
            TYPE_AAAA => ip.is_ipv6(),
            _ => false,
        };
        let mut matched = false;
        let mut ips = Vec::new();

        for ip in self.lists.iter().flat_map(|list| list.hosts.ips_of(name)) {
            matched = true;
            if !wanted(ip) {
                if !matches!(record_type, TYPE_A | TYPE_AAAA) {
                    break;
                }

                continue;
            }

            if !ips.contains(ip) {
                ips.push(*ip);
            }

            if ips.len() > MAX_HOST_IPS {
                break;
            }
        }

        matched.then_some(ips)
    }
}

// ---- The engine ----

/// The rule sets of the configured lists. Engines that differ only in their pinned sets share
/// one copy.
struct ListSets {
    main: RuleSet,
    allow: RuleSet,
}

/// The decision engine: the main lists (user rules included) and the allowlists, which
/// form a separate engine that is asked first (plan 4.5), and the two pinned sets of the rules
/// added from the status page. Any `pinned_allow` match allows, before everything else; any
/// `pinned_block` match counts as an `$important` block. Each pinned set has its own
/// `$badfilter` index, so no list can disable them.
pub struct Engine {
    lists: Arc<ListSets>,
    pinned_block: RuleSet,
    pinned_allow: RuleSet,
}

impl Engine {
    pub fn new(main: Vec<Arc<CompiledList>>, allow: Vec<Arc<CompiledList>>) -> Engine {
        Engine {
            lists: Arc::new(ListSets {
                main: RuleSet::new(main),
                allow: RuleSet::new(allow),
            }),
            pinned_block: RuleSet::new(Vec::new()),
            pinned_allow: RuleSet::new(Vec::new()),
        }
    }

    /// This engine's lists with other pinned sets. The list rule sets are shared, not rebuilt.
    pub fn with_pinned(
        &self,
        block: Vec<Arc<CompiledList>>,
        allow: Vec<Arc<CompiledList>>,
    ) -> Engine {
        Engine {
            lists: Arc::clone(&self.lists),
            pinned_block: RuleSet::new(block),
            pinned_allow: RuleSet::new(allow),
        }
    }

    /// Decides for `input` (a host name, or the text of an IP address when `input_is_ip`)
    /// checked as `record_type`: the question type for request filtering, or the type of
    /// the answer record being checked (CNAME, A, AAAA, HTTPS).
    pub fn check(&self, input: &str, record_type: u16, input_is_ip: bool) -> Decision {
        match self.verdict(input, record_type, input_is_ip) {
            Verdict::Block { ips } => Decision::Block { ips },
            Verdict::Allow | Verdict::NoMatch => Decision::Pass,
        }
    }

    /// `check`, telling a rule that allows the input from no rule at all.
    pub fn verdict(&self, input: &str, record_type: u16, input_is_ip: bool) -> Verdict {
        if input.is_empty() {
            return Verdict::NoMatch;
        }

        let host = lowercase(input);
        let query = Query {
            host: &host,
            record_type,
            is_ip: input_is_ip,
        };

        if self.pinned_allow.class(&query).is_some() {
            return Verdict::Allow;
        }

        let lists = &*self.lists;
        if lists.allow.class(&query).is_some()
            || lists.allow.host_rules(&host, record_type).is_some()
        {
            return Verdict::Allow;
        }

        let pinned_block = self
            .pinned_block
            .class(&query)
            .map(|_| Class::ImportantBlock);
        match lists.main.class(&query).max(pinned_block) {
            Some(Class::Allow | Class::ImportantAllow) => Verdict::Allow,
            Some(Class::Block | Class::ImportantBlock) => Verdict::Block { ips: Vec::new() },
            None => match lists.main.host_rules(&host, record_type) {
                Some(ips) => Verdict::Block { ips },
                None => Verdict::NoMatch,
            },
        }
    }

    /// Which rule decides `input`, step by step as `verdict` decides: the rule in the first
    /// list, in engine order, that holds a matching rule of the deciding class. `None` when no
    /// rule matches. Nothing is kept for it: plain rules are rebuilt from the name that hit,
    /// slow rules from their parsed form.
    pub fn explain(&self, input: &str, record_type: u16, input_is_ip: bool) -> Option<Explanation> {
        if input.is_empty() {
            return None;
        }

        let host = lowercase(input);
        let query = Query {
            host: &host,
            record_type,
            is_ip: input_is_ip,
        };
        let found = |allowed: bool, side: Side, found: Option<(usize, String)>| {
            found.map(|(list, rule)| Explanation {
                allowed,
                side,
                list,
                rule,
            })
        };
        let host_rule = |allowed: bool, side: Side, (list, ip): (usize, IpAddr)| Explanation {
            allowed,
            side,
            list,
            rule: format!("{ip} {host}"),
        };

        if let Some(class) = self.pinned_allow.class(&query) {
            return found(
                true,
                Side::PinnedAllow,
                self.pinned_allow.find(&query, class),
            );
        }

        let lists = &*self.lists;
        if let Some(class) = lists.allow.class(&query) {
            return found(true, Side::Allowlists, lists.allow.find(&query, class));
        }

        if let Some(rule) = lists.allow.host_rule(&host) {
            return Some(host_rule(true, Side::Allowlists, rule));
        }

        let main = lists.main.class(&query);
        let pinned_block_decides = main.is_none_or(|class| class <= Class::ImportantBlock)
            && self.pinned_block.class(&query).is_some();
        if pinned_block_decides {
            let (list, rule) = self.pinned_block.find(&query, Class::Block)?;

            return Some(Explanation {
                allowed: false,
                side: Side::PinnedBlock,
                list,
                rule: format!("{rule}$important"),
            });
        }

        match main {
            Some(class) => {
                let allowed = matches!(class, Class::Allow | Class::ImportantAllow);

                found(allowed, Side::Main, lists.main.find(&query, class))
            }
            None => lists
                .main
                .host_rule(&host)
                .map(|rule| host_rule(false, Side::Main, rule)),
        }
    }
}

/// Which rule set decided, in the order `verdict` asks them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Allows from the status page.
    PinnedAllow,
    Allowlists,
    /// Blocks from the status page.
    PinnedBlock,
    /// The user's `rules` and the blocklists.
    Main,
}

/// The rule that decides a name, from [`Engine::explain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    pub allowed: bool,
    pub side: Side,
    /// The position of the deciding list within its side.
    pub list: usize,
    pub rule: String,
}

fn lowercase(input: &str) -> Cow<'_, str> {
    if input.chars().any(char::is_uppercase) {
        Cow::Owned(input.to_lowercase())
    } else {
        Cow::Borrowed(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine(main: &[(&str, ListFormat)], allow: &[&str]) -> Engine {
        let compile = |text: &str, format| Arc::new(CompiledList::from_text(format, text).0);

        Engine::new(
            main.iter()
                .map(|(text, format)| compile(text, *format))
                .collect(),
            allow
                .iter()
                .map(|text| compile(text, ListFormat::Adblock))
                .collect(),
        )
    }

    fn adblock(text: &str) -> Engine {
        engine(&[(text, ListFormat::Adblock)], &[])
    }

    fn blocked(engine: &Engine, input: &str, record_type: u16) -> bool {
        matches!(
            engine.check(input, record_type, input.parse::<IpAddr>().is_ok()),
            Decision::Block { .. }
        )
    }

    fn ips(addresses: &[&str]) -> Vec<IpAddr> {
        addresses.iter().map(|a| a.parse().unwrap()).collect()
    }

    #[test]
    fn blocked_answer_follows_the_default_mode() {
        let null4 = BlockedAnswer::Ips(ips(&["0.0.0.0"]));
        let null6 = BlockedAnswer::Ips(ips(&["::"]));
        assert_eq!(blocked_answer(TYPE_A, &[]), null4);
        assert_eq!(blocked_answer(TYPE_AAAA, &[]), null6);
        assert_eq!(blocked_answer(TYPE_HTTPS, &[]), BlockedAnswer::Empty);
        assert_eq!(blocked_answer(16, &[]), BlockedAnswer::NoData);
        assert_eq!(
            blocked_answer(255, &ips(&["1.2.3.4"])),
            BlockedAnswer::NoData
        );
    }

    #[test]
    fn blocked_answer_with_host_rule_ips() {
        let v4 = ips(&["1.2.3.4", "5.6.7.8"]);
        let v6 = ips(&["2001:db8::1"]);
        assert_eq!(blocked_answer(TYPE_A, &v4), BlockedAnswer::Ips(v4.clone()));
        assert_eq!(
            blocked_answer(TYPE_AAAA, &v6),
            BlockedAnswer::Ips(v6.clone())
        );
        assert_eq!(blocked_answer(TYPE_HTTPS, &v4), BlockedAnswer::Empty);
        // IPs of the other family give an empty answer, not a null IP.
        assert_eq!(blocked_answer(TYPE_A, &v6), BlockedAnswer::Empty);
        assert_eq!(blocked_answer(TYPE_AAAA, &v4), BlockedAnswer::Empty);
        assert_eq!(
            blocked_answer(TYPE_A, &ips(&["1.2.3.4", "::1"])),
            BlockedAnswer::Empty
        );
        // An IPv4-mapped address is an IPv6 address for AdGuard.
        let mapped = ips(&["::ffff:1.2.3.4"]);
        assert_eq!(
            blocked_answer(TYPE_AAAA, &mapped),
            BlockedAnswer::Ips(mapped)
        );
    }

    #[test]
    fn a_name_with_more_addresses_than_the_cap_is_cut_one_past_it() {
        let many_v4: String = (0..600)
            .map(|index| format!("10.0.{}.{} big.example\n", index / 256, index % 256))
            .collect();
        let many_v6: String = (0..400)
            .map(|index| format!("2001:db8::{index:x} big.example\n"))
            .collect();
        let engine = adblock(&format!("{many_v4}{many_v6}1.1.1.1 few.example\n"));

        let Decision::Block { ips: v4 } = engine.check("big.example", TYPE_A, false) else {
            panic!("blocked");
        };
        let Decision::Block { ips: v6 } = engine.check("big.example", TYPE_AAAA, false) else {
            panic!("blocked");
        };

        assert_eq!(v4.len(), MAX_HOST_IPS + 1);
        assert!(v4.iter().all(IpAddr::is_ipv4));
        assert_eq!(v6.len(), MAX_HOST_IPS + 1);
        assert!(v6.iter().all(IpAddr::is_ipv6));
        assert_eq!(
            engine.check("big.example", TYPE_HTTPS, false),
            Decision::Block { ips: Vec::new() }
        );
        assert_eq!(
            engine.check("few.example", TYPE_A, false),
            Decision::Block {
                ips: ips(&["1.1.1.1"])
            }
        );
    }

    #[test]
    fn the_same_address_in_several_lists_counts_once() {
        let compile = |text: &str| Arc::new(CompiledList::from_text(ListFormat::Adblock, text).0);
        let engine = Engine::new(
            vec![
                compile("1.2.3.4 a.example\n"),
                compile("1.2.3.4 a.example\n"),
            ],
            Vec::new(),
        );

        assert_eq!(
            engine.check("a.example", TYPE_A, false),
            Decision::Block {
                ips: ips(&["1.2.3.4"])
            }
        );
    }

    /// A hosts list with `groups` distinct IPv4 answer IPs and 3000 names; the first name
    /// maps to the first IP only.
    fn hosts_list_with_groups(groups: usize) -> Engine {
        let text: String = (0..3000)
            .map(|index| {
                let group = index % groups;

                format!(
                    "10.{}.{}.{} name{index}.example\n",
                    group / 65_536,
                    group / 256 % 256,
                    group % 256
                )
            })
            .collect();

        adblock(&text)
    }

    /// The time `lookups` queries take, the best of a few rounds.
    fn time_of(
        engine: &Engine,
        lookups: usize,
        record_type: u16,
        name: impl Fn(usize) -> String,
    ) -> std::time::Duration {
        (0..5)
            .map(|_| {
                let started = std::time::Instant::now();
                for index in 0..lookups {
                    std::hint::black_box(engine.check(&name(index), record_type, false));
                }

                started.elapsed()
            })
            .min()
            .unwrap()
    }

    #[test]
    fn a_lookup_costs_the_same_with_one_host_group_or_the_most_groups() {
        const LOOKUPS: usize = 20_000;
        let one_group = hosts_list_with_groups(1);
        let most_groups = hosts_list_with_groups(1024);
        let unrelated = |index| format!("other{index}.example");
        let listed_for_ipv4_only = |index| format!("name{}.example", index % 3000);

        for (what, record_type, name) in [
            (
                "unrelated names",
                TYPE_A,
                &unrelated as &dyn Fn(usize) -> String,
            ),
            ("opposite family", TYPE_AAAA, &listed_for_ipv4_only),
        ] {
            let baseline = time_of(&one_group, LOOKUPS, record_type, name);
            let with_groups = time_of(&most_groups, LOOKUPS, record_type, name);

            assert!(
                with_groups < baseline * 4,
                "{what}: {with_groups:?} with 1024 groups against {baseline:?} with one"
            );
        }
    }

    #[test]
    fn blocked_answer_gives_up_past_the_cap_instead_of_copying() {
        let at_cap: Vec<IpAddr> = (0..MAX_HOST_IPS as u32)
            .map(|index| IpAddr::from(index.to_be_bytes()))
            .collect();
        let mut past_cap = at_cap.clone();
        past_cap.push(IpAddr::from([9, 9, 9, 9]));

        assert_eq!(
            blocked_answer(TYPE_A, &at_cap),
            BlockedAnswer::Ips(at_cap.clone())
        );
        assert_eq!(blocked_answer(TYPE_A, &past_cap), BlockedAnswer::TooMany);
        assert_eq!(blocked_answer(TYPE_AAAA, &past_cap), BlockedAnswer::TooMany);
    }

    #[test]
    fn plain_rules_are_sorted_deduplicated_and_counted() {
        let (list, summary) = CompiledList::from_text(
            ListFormat::Adblock,
            "||b.example^\n||a.example^\n||b.example^\n0.0.0.0 h.example h.example\n||x.example^$dnstype=A\n",
        );
        assert_eq!(summary.counters.block_sub, 3);
        assert_eq!(list.rule_count(), 4);
        assert_eq!(list.slow_rule_count(), 1);
        assert!(list.fast[SUB_BLOCK].windows(2).all(|w| w[0] < w[1]));
        assert_eq!(list.fast[SUB_BLOCK].capacity(), 2);
    }

    #[test]
    fn a_list_read_in_small_pieces_is_the_same_list() {
        struct Dribble<'a>(&'a [u8]);

        impl Read for Dribble<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let length = self.0.len().min(buffer.len()).min(3);
                buffer[..length].copy_from_slice(&self.0[..length]);
                self.0 = &self.0[length..];

                Ok(length)
            }
        }

        let text = "||a.example^\n0.0.0.0 h.example\n/x[0-9]/\n||b.example^$important\n";
        let (whole, _) = CompiledList::from_text(ListFormat::Adblock, text);
        let (pieces, summary) =
            CompiledList::from_reader(ListFormat::Adblock, 3, Dribble(text.as_bytes())).unwrap();

        assert_eq!(whole.rule_count(), 4);
        assert_eq!(pieces.rule_count(), 3);
        assert_eq!(summary.counters.over_cap, 1);
    }

    #[test]
    fn input_is_lowercased() {
        let engine = adblock("||ads.example^\n");
        assert!(blocked(&engine, "ADS.Example", TYPE_A));
        assert!(!blocked(&engine, "", TYPE_A));
    }

    #[test]
    fn host_rules_answer_with_the_ips_of_the_checked_family() {
        let engine = adblock("1.2.3.4 a.example\n2001:db8::1 a.example\n0.0.0.0 a.example\n");
        let check = |record_type| engine.check("a.example", record_type, false);
        assert_eq!(
            check(TYPE_A),
            Decision::Block {
                ips: ips(&["1.2.3.4", "0.0.0.0"])
            }
        );
        assert_eq!(
            check(TYPE_AAAA),
            Decision::Block {
                ips: ips(&["2001:db8::1"])
            }
        );
        assert_eq!(check(TYPE_HTTPS), Decision::Block { ips: Vec::new() });
        assert_eq!(check(TYPE_CNAME), Decision::Block { ips: Vec::new() });
    }

    #[test]
    fn network_rules_beat_host_rules_and_allow_beats_block() {
        let engine = adblock("0.0.0.0 h.example\n@@||h.example^\n||b.example^\n@@||b.example^\n");
        assert!(!blocked(&engine, "h.example", TYPE_A));
        assert!(!blocked(&engine, "b.example", TYPE_A));
    }

    #[test]
    fn important_beats_allow_across_lists() {
        let engine = engine(
            &[
                ("||x.example^$important\n", ListFormat::Adblock),
                ("@@||x.example^\n", ListFormat::Adblock),
            ],
            &[],
        );
        assert!(blocked(&engine, "x.example", TYPE_A));
    }

    #[test]
    fn allowlist_engine_wins_even_with_block_rules_inside() {
        let engine = engine(
            &[("||x.example^\n", ListFormat::Adblock)],
            &["||x.example^\n"],
        );
        assert!(!blocked(&engine, "x.example", TYPE_A));
        assert!(!blocked(&engine, "sub.x.example", TYPE_A));
    }

    #[test]
    fn the_verdict_tells_an_allow_rule_from_no_rule() {
        let engine = engine(
            &[("@@||ok.example^\n||bad.example^\n", ListFormat::Adblock)],
            &["||listed.example^\n"],
        );
        let verdict = |name| engine.verdict(name, TYPE_A, false);
        assert_eq!(verdict("ok.example"), Verdict::Allow);
        assert_eq!(verdict("sub.ok.example"), Verdict::Allow);
        assert_eq!(verdict("listed.example"), Verdict::Allow);
        assert_eq!(verdict("bad.example"), Verdict::Block { ips: Vec::new() });
        assert_eq!(verdict("other.example"), Verdict::NoMatch);
        assert_eq!(verdict(""), Verdict::NoMatch);
    }

    #[test]
    fn badfilter_disables_a_plain_rule_in_another_list() {
        let engine = engine(
            &[
                ("||x.example^\n||y.example^\n", ListFormat::Adblock),
                ("||x.example^$badfilter\n", ListFormat::Adblock),
            ],
            &[],
        );
        assert!(!blocked(&engine, "x.example", TYPE_A));
        assert!(!blocked(&engine, "sub.x.example", TYPE_A));
        assert!(blocked(&engine, "y.example", TYPE_A));
    }

    #[test]
    fn conditional_badfilter_disables_only_for_its_record_types() {
        let engine = adblock("||x.example^\n||x.example^$badfilter,dnstype=A\n");
        assert!(!blocked(&engine, "x.example", TYPE_A));
        assert!(blocked(&engine, "x.example", TYPE_AAAA));

        let engine = adblock("||x.example^\n||x.example^$badfilter,dnstype=~A\n");
        assert!(blocked(&engine, "x.example", TYPE_A));
        assert!(!blocked(&engine, "x.example", TYPE_AAAA));
    }

    #[test]
    fn badfilter_identity_is_case_sensitive() {
        let engine = adblock("||X.example^\n||x.example^$badfilter\n");
        assert!(blocked(&engine, "x.example", TYPE_A));
        let engine = adblock("||X.example^\n||X.example^$badfilter\n");
        assert!(!blocked(&engine, "x.example", TYPE_A));
    }

    #[test]
    fn overlapping_badfilters_disable_every_target() {
        // urlfilter v0.23.4 brings the rule back when two badfilters match; picoguard does not.
        let engine =
            adblock("||x.example^\n||x.example^$badfilter\n||x.example^$badfilter,important\n");
        assert!(!blocked(&engine, "x.example", TYPE_A));
    }

    #[test]
    fn denyallow_never_matches_an_ip_input() {
        let engine = adblock("*$denyallow=ok.example\n");
        assert!(blocked(&engine, "other.example", TYPE_A));
        assert!(!blocked(&engine, "ok.example", TYPE_A));
        assert!(!blocked(&engine, "sub.ok.example", TYPE_A));
        assert!(!blocked(&engine, "9.9.9.9", TYPE_A));
        assert!(!blocked(&engine, "2001:db8::1", TYPE_AAAA));
    }

    #[test]
    fn denyallow_tld_wildcard_uses_icann_suffixes() {
        let engine = adblock("*$denyallow=google.*\n");
        for pass in [
            "google.com",
            "www.google.co.uk",
            "google.org",
            "x.google.com.au",
        ] {
            assert!(!blocked(&engine, pass, TYPE_A), "{pass}");
        }

        for block in [
            "google.example",
            "mygoogle.com",
            "google.blogspot.com",
            "google.nosuchtld",
        ] {
            assert!(blocked(&engine, block, TYPE_A), "{block}");
        }
    }

    #[test]
    fn ip_text_inputs_use_the_separator_rules() {
        let engine = adblock("|dead^\n||beef^\n||1.2.3.4^\n");
        assert!(blocked(&engine, "dead:beef::1", TYPE_AAAA));
        assert!(blocked(&engine, "dead::1", TYPE_AAAA));
        assert!(!blocked(&engine, "deadbeef::1", TYPE_AAAA));
        assert!(blocked(&engine, "beef::1", TYPE_AAAA));
        assert!(blocked(&engine, "1.2.3.4", TYPE_A));
        assert!(!blocked(&engine, "1.2.3.45", TYPE_A));
        assert!(!blocked(&engine, "11.2.3.4", TYPE_A));
    }

    #[test]
    fn rpz_name_and_wildcard_pair_becomes_one_subdomain_rule() {
        let zone = "$TTL 3600\na.example CNAME .\n*.a.example CNAME .\nonly.example CNAME .\n*.sub.example CNAME .\nok.example CNAME rpz-passthru.\n*.ok.example CNAME rpz-passthru.\n";
        let (list, _) = CompiledList::from_text(ListFormat::Rpz, zone);
        assert_eq!(list.fast[SUB_BLOCK].len(), 1);
        assert_eq!(list.fast[EXACT_BLOCK].len(), 1);
        assert_eq!(list.fast[STRICT_BLOCK].len(), 1);
        assert_eq!(list.fast[SUB_ALLOW].len(), 1);

        let engine = Engine::new(vec![Arc::new(list)], Vec::new());
        assert!(blocked(&engine, "a.example", TYPE_A));
        assert!(blocked(&engine, "x.a.example", TYPE_A));
        assert!(blocked(&engine, "only.example", TYPE_A));
        assert!(!blocked(&engine, "x.only.example", TYPE_A));
        assert!(!blocked(&engine, "sub.example", TYPE_A));
        assert!(blocked(&engine, "x.sub.example", TYPE_A));
        assert!(!blocked(&engine, "ok.example", TYPE_A));
        assert!(!blocked(&engine, "www.ok.example", TYPE_A));
    }

    #[test]
    fn explicit_formats_through_the_engine() {
        let engine = engine(
            &[
                ("*.w.example\nv.example\n", ListFormat::Wildcard),
                (
                    "local=/d.example/\naddress=/e.example/#\n",
                    ListFormat::Dnsmasq,
                ),
                ("127.0.0.1 h.example\n", ListFormat::Hosts),
                ("plain.example\n", ListFormat::Domains),
            ],
            &[],
        );
        for name in [
            "w.example",
            "x.w.example",
            "v.example",
            "d.example",
            "s.d.example",
            "e.example",
        ] {
            assert!(blocked(&engine, name, TYPE_A), "{name}");
        }

        assert_eq!(
            engine.check("h.example", TYPE_A, false),
            Decision::Block {
                ips: ips(&["127.0.0.1"])
            }
        );
        assert!(blocked(&engine, "plain.example", TYPE_A));
        assert!(!blocked(&engine, "x.plain.example", TYPE_A));
    }

    #[test]
    fn failing_regexes_are_counted_and_skipped() {
        let (list, summary) = CompiledList::from_text(ListFormat::Adblock, "/(?=x)/\n/ok[0-9]/\n");
        assert_eq!(list.regex_failed(), 1);
        assert_eq!(list.slow_rule_count(), 1);
        assert_eq!(summary.counters.regex_rules, 2);
    }

    #[test]
    fn client_restricted_rules_match_and_permitted_ones_do_not() {
        let engine = adblock("||a.example^$client=~192.168.0.1\n||b.example^$client=192.168.0.1\n");
        assert!(blocked(&engine, "a.example", TYPE_A));
        assert!(!blocked(&engine, "b.example", TYPE_A));
    }

    /// A page list as the scheduler builds it: one plain rule per name, no text parsed.
    fn page_list(names: &[&str], kind: FastKind) -> Vec<Arc<CompiledList>> {
        if names.is_empty() {
            return Vec::new();
        }

        let mut builder = ListBuilder::new();
        for name in names {
            builder.add(Rule::Fast { kind, name });
        }

        vec![Arc::new(builder.finish(ListFormat::Adblock))]
    }

    fn pinned(main: &[&str], allow: &[&str], block: &[&str], page_allow: &[&str]) -> Engine {
        let main: Vec<(&str, ListFormat)> = main
            .iter()
            .map(|text| (*text, ListFormat::Adblock))
            .collect();

        engine(&main, allow).with_pinned(
            page_list(block, FastKind::SubBlock),
            page_list(page_allow, FastKind::SubAllow),
        )
    }

    fn null_block() -> Verdict {
        Verdict::Block { ips: Vec::new() }
    }

    #[test]
    fn a_pinned_block_beats_allows_but_not_important_allows_or_allowlists() {
        let engine = pinned(
            &["@@||a.example^\n@@||b.example^$important\n"],
            &["||e.example^\n"],
            &["a.example", "b.example", "d.example", "e.example"],
            &[],
        );
        let verdict = |name| engine.verdict(name, TYPE_A, false);

        assert_eq!(verdict("a.example"), null_block());
        assert_eq!(verdict("sub.a.example"), null_block());
        assert_eq!(verdict("d.example"), null_block());
        assert_eq!(verdict("b.example"), Verdict::Allow);
        assert_eq!(verdict("e.example"), Verdict::Allow);
        assert_eq!(verdict("other.example"), Verdict::NoMatch);
    }

    #[test]
    fn a_pinned_allow_beats_every_block() {
        let engine = pinned(
            &["||x.example^$important\n||x.example^\n"],
            &[],
            &["y.example"],
            &["x.example", "y.example"],
        );

        for name in ["x.example", "sub.x.example", "y.example", "sub.y.example"] {
            assert_eq!(
                engine.verdict(name, TYPE_A, false),
                Verdict::Allow,
                "{name}"
            );
        }
    }

    #[test]
    fn no_list_badfilter_reaches_the_pinned_sets() {
        let engine = pinned(
            &["||x.example^$important,badfilter\n||x.example^$badfilter\n||y.example^$important\n"],
            &["@@||y.example^$badfilter\n||y.example^$badfilter\n"],
            &["x.example"],
            &["y.example"],
        );

        assert_eq!(engine.verdict("x.example", TYPE_A, false), null_block());
        assert_eq!(engine.verdict("y.example", TYPE_A, false), Verdict::Allow);
    }

    #[test]
    fn a_pinned_block_answers_with_the_null_ip_over_host_rules() {
        let engine = pinned(&["1.2.3.4 h.example\n"], &[], &["h.example"], &[]);

        assert_eq!(engine.verdict("h.example", TYPE_A, false), null_block());
    }

    #[test]
    fn the_pinned_sets_also_check_answer_names_and_addresses() {
        let engine = pinned(&[], &[], &["cdn.example", "1.2.3.4"], &[]);

        assert!(matches!(
            engine.check("x.cdn.example", TYPE_CNAME, false),
            Decision::Block { .. }
        ));
        assert!(matches!(
            engine.check("1.2.3.4", TYPE_A, true),
            Decision::Block { .. }
        ));
    }

    #[test]
    fn with_pinned_shares_the_list_rule_sets() {
        let engine = adblock("||ads.example^\n/tr[a-z]{2}k/\n");
        let changed = engine.with_pinned(
            page_list(&["b.example"], FastKind::SubBlock),
            page_list(&["a.example"], FastKind::SubAllow),
        );

        assert!(Arc::ptr_eq(&engine.lists, &changed.lists));
        assert!(blocked(&changed, "ads.example", TYPE_A));
        assert!(blocked(&changed, "b.example", TYPE_A));
        assert!(!blocked(&engine, "b.example", TYPE_A));
    }

    fn candidates(engine: &Engine, host: &str) -> usize {
        let mut count = 0;
        let url = format!("http://{host}");
        engine.lists.main.slow_index.for_each_candidate(
            &engine.lists.main.lists,
            &url,
            &mut |_, _| count += 1,
        );

        count
    }

    fn explained(allowed: bool, side: Side, list: usize, rule: &str) -> Option<Explanation> {
        Some(Explanation {
            allowed,
            side,
            list,
            rule: rule.to_string(),
        })
    }

    #[test]
    fn explain_reports_the_first_list_with_a_rule_of_the_deciding_class() {
        let engine = engine(
            &[
                ("@@||ok.ads.example^\n", ListFormat::Adblock),
                ("||ads.example^\n||dup.example^\n", ListFormat::Adblock),
                (
                    "||dup.example^\n||x.example^$important\n@@||x.example^\n",
                    ListFormat::Adblock,
                ),
                (
                    "/^track[0-9]+\\.example$/\n||ad*.wild.example^\n0.0.0.0 host.example\n",
                    ListFormat::Adblock,
                ),
            ],
            &[],
        );
        let explain = |name| engine.explain(name, TYPE_A, false);

        assert_eq!(
            explain("sub.ads.example"),
            explained(false, Side::Main, 1, "||ads.example^")
        );
        assert_eq!(
            explain("ok.ads.example"),
            explained(true, Side::Main, 0, "@@||ok.ads.example^")
        );
        assert_eq!(
            explain("dup.example"),
            explained(false, Side::Main, 1, "||dup.example^")
        );
        assert_eq!(
            explain("x.example"),
            explained(false, Side::Main, 2, "||x.example^$important")
        );
        assert_eq!(
            explain("track12.example"),
            explained(false, Side::Main, 3, "/^track[0-9]+\\.example$/")
        );
        assert_eq!(
            explain("adx.wild.example"),
            explained(false, Side::Main, 3, "||ad*.wild.example^")
        );
        assert_eq!(
            explain("host.example"),
            explained(false, Side::Main, 3, "0.0.0.0 host.example")
        );
        assert_eq!(explain("other.example"), None);
    }

    #[test]
    fn explain_rebuilds_every_plain_rule_kind() {
        let engine = engine(
            &[
                (
                    "a.example CNAME .\n*.b.example CNAME .\nc.example CNAME rpz-passthru.\n*.d.example CNAME rpz-passthru.\ne.example CNAME .\n*.e.example CNAME .\n",
                    ListFormat::Rpz,
                ),
                (
                    "|f.example^\n@@|g.example^\n||g.example^\n",
                    ListFormat::Adblock,
                ),
            ],
            &[],
        );
        let explain = |name| engine.explain(name, TYPE_A, false);

        assert_eq!(
            explain("a.example"),
            explained(false, Side::Main, 0, "|a.example^")
        );
        assert_eq!(
            explain("x.b.example"),
            explained(false, Side::Main, 0, "||*.b.example^")
        );
        assert_eq!(
            explain("c.example"),
            explained(true, Side::Main, 0, "@@|c.example^")
        );
        assert_eq!(
            explain("x.d.example"),
            explained(true, Side::Main, 0, "@@||*.d.example^")
        );
        assert_eq!(
            explain("x.e.example"),
            explained(false, Side::Main, 0, "||e.example^")
        );
        assert_eq!(
            explain("f.example"),
            explained(false, Side::Main, 1, "|f.example^")
        );
        assert_eq!(
            explain("g.example"),
            explained(true, Side::Main, 1, "@@|g.example^")
        );
    }

    #[test]
    fn explain_follows_badfilter_and_conditions() {
        let disabled = adblock("||x.example^\n||x.example^$badfilter\n");
        let for_aaaa = adblock("||y.example^\n||y.example^$badfilter,dnstype=AAAA\n");
        let only_aaaa = adblock("||z.example^$dnstype=AAAA\n");

        assert_eq!(disabled.explain("x.example", TYPE_A, false), None);
        assert_eq!(
            for_aaaa.explain("y.example", TYPE_A, false),
            explained(false, Side::Main, 0, "||y.example^")
        );
        assert_eq!(for_aaaa.explain("y.example", TYPE_AAAA, false), None);
        assert_eq!(only_aaaa.explain("z.example", TYPE_A, false), None);
    }

    #[test]
    fn find_is_offered_no_unrelated_slow_rule() {
        let unrelated: String = (0..20_000)
            .map(|number| format!("||unrelated-{number:05}*.invalid^\n"))
            .collect();
        let engine = engine(
            &[
                (&unrelated, ListFormat::Adblock),
                ("||target.example^\n", ListFormat::Adblock),
            ],
            &[],
        );

        assert_eq!(candidates(&engine, "target.example"), 0);
        assert_eq!(
            engine.explain("target.example", TYPE_A, false),
            explained(false, Side::Main, 1, "||target.example^")
        );
    }

    #[test]
    fn explain_tells_the_allowlists_and_the_pinned_sets_apart() {
        let listed = pinned(&[], &["||mine.example^\n"], &[], &[]);
        let both = pinned(&[], &["||mine.example^\n"], &[], &["mine.example"]);
        let page_block = pinned(&["@@||b.example^\n"], &[], &["b.example"], &[]);
        let important_allow = pinned(&["@@||b.example^$important\n"], &[], &["b.example"], &[]);

        assert_eq!(
            listed.explain("mine.example", TYPE_A, false),
            explained(true, Side::Allowlists, 0, "||mine.example^")
        );
        assert_eq!(
            both.explain("mine.example", TYPE_A, false),
            explained(true, Side::PinnedAllow, 0, "@@||mine.example^")
        );
        assert_eq!(
            page_block.explain("b.example", TYPE_A, false),
            explained(false, Side::PinnedBlock, 0, "||b.example^$important")
        );
        assert_eq!(
            important_allow.explain("b.example", TYPE_A, false),
            explained(true, Side::Main, 0, "@@||b.example^$important")
        );
    }

    #[test]
    fn a_check_looks_only_at_slow_rules_whose_shortcut_can_occur() {
        let mut rules = String::new();
        for number in 0..500 {
            rules.push_str(&format!("||t{number:04}.example^$important\n"));
        }

        rules.push_str("/^sh[a-z]rt/\n*$denyallow=ok.example\n");
        let engine = adblock(&rules);
        assert_eq!(engine.lists.main.lists[0].slow_rule_count(), 502);
        // The regex has a one-letter shortcut and the `*` rule none: both are always tried.
        assert_eq!(candidates(&engine, "clean.example"), 2);
        assert!(candidates(&engine, "t0123.example") <= 12);
        assert!(candidates(&engine, "sub.t0499.example") <= 12);
        assert!(blocked(&engine, "t0123.example", TYPE_A));
        assert!(blocked(&engine, "sub.t0499.example", TYPE_A));
        assert!(blocked(&engine, "short.example", TYPE_A));
        assert!(!blocked(&engine, "t0500.ok.example", TYPE_A));
    }

    #[test]
    fn indexed_slow_rules_decide_like_a_scan_of_every_rule() {
        let rules = "||ads.\n.banner.\n/tr[a-z]{2}k/\n||x.example^$dnstype=A\n@@||good.ads.example^$important\n|lone\n*.cdn.\nping^\n";
        let engine = adblock(rules);
        let list = &engine.lists.main.lists[0];
        for host in [
            "ads.example",
            "good.ads.example",
            "a.banner.net",
            "track.example",
            "x.example",
            "lone.example",
            "a.lone.example",
            "img.cdn.example",
            "ping.example",
            "pingpong.example",
            "clean.example",
        ] {
            let query = Query {
                host,
                record_type: TYPE_A,
                is_ip: false,
            };
            let url = format!("http://{host}");
            let scanned = list
                .slow
                .iter()
                .any(|slow| !slow.rule.whitelist && slow.matcher.is_match(host, &url));
            let important_allow = list.slow.iter().any(|slow| {
                slow.rule.whitelist && slow.rule.important && slow.matcher.is_match(host, &url)
            });
            let expected = scanned && !important_allow;
            let decided = !matches!(
                engine.lists.main.class(&query),
                None | Some(Class::Allow | Class::ImportantAllow)
            );
            assert_eq!(decided, expected, "{host}");
        }
    }

    #[test]
    fn hash_membership_agrees_with_binary_search_on_any_distribution() {
        let uniform: Vec<u64> = (0..5000u64)
            .map(|n| xxh3_64(&n.to_le_bytes()))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let clustered: Vec<u64> = (0..5000u64)
            .map(|n| if n < 4990 { n * 3 } else { u64::MAX - n })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        for sorted in [uniform, clustered, vec![], vec![7], vec![7, 9]] {
            let mut needles: Vec<u64> = sorted
                .iter()
                .flat_map(|&n| [n, n.wrapping_add(1), n.wrapping_sub(1)])
                .collect();
            needles.extend([0, 1, u64::MAX, u64::MAX - 1]);
            for needle in needles {
                assert_eq!(
                    contains_hash(&sorted, needle),
                    sorted.binary_search(&needle).is_ok(),
                    "{needle}"
                );
            }
        }
    }
}
