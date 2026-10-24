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

use super::parse::{FastKind, ListFormat, NetworkRule, ParseSummary, Parser, Rule, fast_rule};
use super::pattern::{
    Matcher, for_each_exact_candidate, for_each_strict_suffix_candidate, for_each_suffix_candidate,
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

pub(super) struct HostGroup {
    pub(super) ip: IpAddr,
    pub(super) names: Vec<u64>,
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
        let matcher = Matcher::compile(&rule.pattern).map_err(|_| ())?;

        Ok(SlowRule {
            identity: identity_hash(&rule),
            matcher,
            rule,
        })
    }
}

/// The rules of one list, ready for lookups. Shared between engines through an `Arc`
/// (plan D6): a refresh of another list does not rebuild it.
pub struct CompiledList {
    pub(super) fast: [Vec<u64>; FAST_KINDS],
    pub(super) hosts: Vec<HostGroup>,
    pub(super) slow: Vec<SlowRule>,
    pub(super) regex_failed: u64,
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
        self.fast.iter().map(Vec::len).sum::<usize>()
            + self
                .hosts
                .iter()
                .map(|group| group.names.len())
                .sum::<usize>()
            + self.slow.len()
    }

    pub fn slow_rule_count(&self) -> usize {
        self.slow.len()
    }

    /// Slow rules dropped because their regular expression does not compile.
    pub fn regex_failed(&self) -> u64 {
        self.regex_failed
    }
}

/// Collects the rules of one list. Hashes go straight into arrays; `finish` sorts them.
pub struct ListBuilder {
    fast: [Vec<u64>; FAST_KINDS],
    hosts: Vec<HostGroup>,
    host_index: HashMap<IpAddr, usize>,
    slow: Vec<SlowRule>,
    regex_failed: u64,
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
            hosts: Vec::new(),
            host_index: HashMap::new(),
            slow: Vec::new(),
            regex_failed: 0,
        }
    }

    pub fn add(&mut self, rule: Rule<'_>) {
        match rule {
            Rule::Host { ip, name } => {
                let group = *self.host_index.entry(ip).or_insert_with(|| {
                    self.hosts.push(HostGroup {
                        ip,
                        names: Vec::new(),
                    });

                    self.hosts.len() - 1
                });
                self.hosts[group].names.push(hash(name));
            }
            Rule::Fast { kind, name } => self.fast[kind_index(kind)].push(hash(name)),
            Rule::Slow(rule) => match SlowRule::compile(rule) {
                Ok(slow) => self.slow.push(slow),
                Err(()) => self.regex_failed += 1,
            },
        }
    }

    /// Sorts, deduplicates and trims the arrays. `format` is the effective list format.
    pub fn finish(mut self, format: ListFormat) -> CompiledList {
        for hashes in self.fast.iter_mut() {
            sort_dedup(hashes);
        }

        for group in self.hosts.iter_mut() {
            sort_dedup(&mut group.names);
        }

        if format == ListFormat::Rpz {
            self.merge_rpz_pairs();
        }

        self.hosts.shrink_to_fit();
        self.slow.shrink_to_fit();

        CompiledList {
            fast: self.fast,
            hosts: self.hosts,
            slow: self.slow,
            regex_failed: self.regex_failed,
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

/// What the engine decides for one input and record type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Pass,
    /// Blocked. `ips` are the answer IPs of host rules of the checked address family, in
    /// list order without duplicates; empty for network rules and other host rules.
    Block {
        ips: Vec<IpAddr>,
    },
}

/// The reply AdGuard's default blocking mode builds for a blocked name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockedAnswer {
    Ips(Vec<IpAddr>),
    /// NOERROR without records.
    Empty,
    /// NOERROR with the fake SOA.
    NoData,
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
    let ips: Vec<IpAddr> = if ips.is_empty() {
        null_ip.into_iter().collect()
    } else {
        ips.to_vec()
    };

    let answer: Vec<IpAddr> = match query_type {
        TYPE_A if ips.iter().all(IpAddr::is_ipv4) => ips,
        TYPE_AAAA => ips.into_iter().filter(IpAddr::is_ipv6).collect(),
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

    /// Calls `f` for every slow rule whose shortcut starts with some window of `url`, and for
    /// the rules without a usable shortcut. A rule may be offered more than once.
    fn for_each_candidate<'a>(
        &self,
        lists: &'a [Arc<CompiledList>],
        url: &str,
        f: &mut dyn FnMut(&'a SlowRule),
    ) {
        for &(list, rule) in &self.always {
            f(&lists[list as usize].slow[rule as usize]);
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

                f(&lists[list as usize].slow[rule as usize]);
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
            .for_each_candidate(&self.lists, &url, &mut |slow| {
                let rule = &slow.rule;
                let allowed = conditions_hold(
                    &rule.dns_permitted,
                    &rule.dns_restricted,
                    &rule.denyallow,
                    query,
                );
                if rule.badfilter
                    || !allowed
                    || !slow.matcher.is_match(query.host, &url)
                    || self.slow_disabled(slow, query)
                {
                    return;
                }

                note(match (rule.whitelist, rule.important) {
                    (true, true) => Class::ImportantAllow,
                    (false, true) => Class::ImportantBlock,
                    (true, false) => Class::Allow,
                    (false, false) => Class::Block,
                });
            });

        best.get()
    }

    /// The answer IPs of the host rules that match `host`, or `None` without a match.
    fn host_rules(&self, host: &str, record_type: u16) -> Option<Vec<IpAddr>> {
        let name = hash(host);
        let mut matched = false;
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for list in &self.lists {
            for group in &list.hosts {
                if !contains_hash(&group.names, name) {
                    continue;
                }

                matched = true;
                let ips = if group.ip.is_ipv4() { &mut v4 } else { &mut v6 };
                if !ips.contains(&group.ip) {
                    ips.push(group.ip);
                }
            }
        }

        matched.then(|| match record_type {
            TYPE_A => v4,
            TYPE_AAAA => v6,
            _ => Vec::new(),
        })
    }
}

// ---- The engine ----

/// The decision engine: the main lists (user rules included) and the allowlists, which
/// form a separate engine that is asked first (plan 4.5).
pub struct Engine {
    main: RuleSet,
    allow: RuleSet,
}

impl Engine {
    pub fn new(main: Vec<Arc<CompiledList>>, allow: Vec<Arc<CompiledList>>) -> Engine {
        Engine {
            main: RuleSet::new(main),
            allow: RuleSet::new(allow),
        }
    }

    /// Decides for `input` (a host name, or the text of an IP address when `input_is_ip`)
    /// checked as `record_type`: the question type for request filtering, or the type of
    /// the answer record being checked (CNAME, A, AAAA, HTTPS).
    pub fn check(&self, input: &str, record_type: u16, input_is_ip: bool) -> Decision {
        if input.is_empty() {
            return Decision::Pass;
        }

        let host: Cow<'_, str> = if input.chars().any(char::is_uppercase) {
            Cow::Owned(input.to_lowercase())
        } else {
            Cow::Borrowed(input)
        };
        let query = Query {
            host: &host,
            record_type,
            is_ip: input_is_ip,
        };

        if self.allow.class(&query).is_some() || self.allow.host_rules(&host, record_type).is_some()
        {
            return Decision::Pass;
        }

        match self.main.class(&query) {
            Some(Class::Allow | Class::ImportantAllow) => Decision::Pass,
            Some(Class::Block | Class::ImportantBlock) => Decision::Block { ips: Vec::new() },
            None => match self.main.host_rules(&host, record_type) {
                Some(ips) => Decision::Block { ips },
                None => Decision::Pass,
            },
        }
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

    fn candidates(engine: &Engine, host: &str) -> usize {
        let mut count = 0;
        let url = format!("http://{host}");
        engine
            .main
            .slow_index
            .for_each_candidate(&engine.main.lists, &url, &mut |_| count += 1);

        count
    }

    #[test]
    fn a_check_looks_only_at_slow_rules_whose_shortcut_can_occur() {
        let mut rules = String::new();
        for number in 0..500 {
            rules.push_str(&format!("||t{number:04}.example^$important\n"));
        }

        rules.push_str("/^sh[a-z]rt/\n*$denyallow=ok.example\n");
        let engine = adblock(&rules);
        assert_eq!(engine.main.lists[0].slow_rule_count(), 502);
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
        let list = &engine.main.lists[0];
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
                engine.main.class(&query),
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
