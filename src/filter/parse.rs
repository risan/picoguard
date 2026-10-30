//! Blocklist line parsing for every supported list format.
//!
//! The AdGuard grammar follows urlfilter v0.23.4 as observed through the golden oracle:
//! what the oracle does is the contract, including its odd corners. The other formats
//! (wildcard, domains, hosts, dnsmasq, RPZ) are defined by plan section 4.2.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::rpz::{Record, RpzReader};

pub use crate::config::ListFormat;

/// Longest line the parser looks at; longer lines are skipped and counted.
pub const MAX_LINE_BYTES: usize = 4096;

/// How much of the start of a list `auto` detection looks at.
pub const DETECTION_BYTES: usize = 64 * 1024;

/// The six fast-path rule shapes (plan D4, plus the strict-subdomain forms of RPZ).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FastKind {
    /// `||d^`: `d` and its subdomains.
    SubBlock,
    /// `|d^`: exactly `d`.
    ExactBlock,
    /// `@@||d^`
    SubAllow,
    /// `@@|d^`
    ExactAllow,
    /// RPZ `*.d`: subdomains of `d`, not `d` itself.
    StrictSubBlock,
    StrictSubAllow,
}

/// A parsed rule handed to the sink. Borrowed names point into the line being parsed.
#[derive(Debug)]
pub enum Rule<'a> {
    /// One name of a hosts line or bare domain: an exact match with an answer IP.
    Host { ip: IpAddr, name: &'a str },
    /// A network rule in one of the fast-path shapes; `name` is lowercase.
    Fast { kind: FastKind, name: &'a str },
    /// Any other network rule that applies to DNS.
    Slow(NetworkRule),
}

/// A urlfilter network rule that is used for DNS filtering.
///
/// Rules that urlfilter does not use for DNS (not host-level, never matching the synthetic
/// DNS request) are dropped by the parser, so every field here matters for matching or
/// for `$badfilter` identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRule {
    pub whitelist: bool,
    pub important: bool,
    pub badfilter: bool,
    /// The pattern as urlfilter holds it (after the `/*` to `^` normalization).
    pub pattern: String,
    /// Content types excluded with `~`, kept for the identity of the rule.
    pub restricted_types: u32,
    pub dns_permitted: Vec<u16>,
    pub dns_restricted: Vec<u16>,
    /// `$denyallow` domains, case as written.
    pub denyallow: Vec<String>,
    /// Restricted `$client` values, kept for the identity of the rule.
    pub restricted_clients: ClientSet,
    /// Restricted `$ctag` values (sorted), kept for the identity of the rule.
    pub restricted_ctags: Vec<String>,
}

/// The entries of a `$client` modifier in the canonical form urlfilter compares: client IPs
/// and subnets as masked prefixes (`192.0.2.1` is `192.0.2.1/32`), everything else as names,
/// each part sorted and without duplicates.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ClientSet {
    pub nets: Vec<(IpAddr, u8)>,
    pub names: Vec<String>,
}

impl ClientSet {
    pub fn new(entries: &[String]) -> ClientSet {
        let mut set = ClientSet::default();
        for entry in entries {
            match parse_client_net(entry) {
                Some(net) => set.nets.push(net),
                None => set.names.push(entry.clone()),
            }
        }

        set.nets.sort();
        set.nets.dedup();
        set.names.sort();
        set.names.dedup();

        set
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty() && self.names.is_empty()
    }

    /// The entries in text form; `ClientSet::new` turns them back into the same set.
    pub fn entries(&self) -> Vec<String> {
        let nets = self.nets.iter().map(|(ip, bits)| format!("{ip}/{bits}"));

        nets.chain(self.names.iter().cloned()).collect()
    }
}

/// An IP address or `address/bits` as a masked prefix; `None` for any other client name.
fn parse_client_net(entry: &str) -> Option<(IpAddr, u8)> {
    let (address, bits) = match entry.rsplit_once('/') {
        Some((address, bits)) => (address, Some(bits)),
        None => (entry, None),
    };
    let address = match address.split_once('%') {
        // urlfilter accepts a zone on a plain IPv6 address and drops it.
        Some((bare, zone)) if bits.is_none() && !zone.is_empty() && bare.contains(':') => bare,
        _ => address,
    };
    let ip: IpAddr = address.parse().ok()?;
    let max_bits = if ip.is_ipv4() { 32 } else { 128 };
    let bits = match bits {
        None => max_bits,
        Some(bits) => {
            let canonical = bits == "0" || (!bits.starts_with('0') && !bits.starts_with('+'));

            bits.parse::<u8>()
                .ok()
                .filter(|&bits| canonical && bits <= max_bits)?
        }
    };

    Some((mask_address(ip, bits), bits))
}

fn mask_address(ip: IpAddr, bits: u8) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);

            IpAddr::V4(Ipv4Addr::from(u32::from(ip) & mask))
        }
        IpAddr::V6(ip) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0);

            IpAddr::V6(Ipv6Addr::from(u128::from(ip) & mask))
        }
    }
}

/// What urlfilter's `negatesBadfilter` compares (it ignores `$dnstype` and `$denyallow`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identity {
    pub whitelist: bool,
    pub important: bool,
    pub pattern: String,
    pub restricted_types: u32,
    pub restricted_clients: ClientSet,
    pub restricted_ctags: Vec<String>,
}

impl NetworkRule {
    pub fn is_regex(&self) -> bool {
        self.pattern.len() > 1 && self.pattern.starts_with('/') && self.pattern.ends_with('/')
    }

    pub fn identity(&self) -> Identity {
        Identity {
            whitelist: self.whitelist,
            important: self.important,
            pattern: self.pattern.clone(),
            restricted_types: self.restricted_types,
            restricted_clients: self.restricted_clients.clone(),
            restricted_ctags: self.restricted_ctags.clone(),
        }
    }

    /// True when the rule only applies to some record types or names.
    pub fn is_conditional(&self) -> bool {
        !self.dns_permitted.is_empty()
            || !self.dns_restricted.is_empty()
            || !self.denyallow.is_empty()
    }

    /// The rule as text that parses back to this rule: the pattern as stored, then the
    /// modifiers, if any, in a fixed order and spelling. No original line is kept, so a rule
    /// with modifiers may read differently from its list.
    pub fn text(&self) -> String {
        let mut modifiers = Vec::new();
        if self.important {
            modifiers.push("important".to_string());
        }

        if self.badfilter {
            modifiers.push("badfilter".to_string());
        }

        for (name, bit) in CONTENT_TYPES {
            if self.restricted_types & bit != 0 {
                modifiers.push(format!("~{name}"));
            }
        }

        let type_name = |code: &u16| {
            DNS_TYPES
                .iter()
                .find(|(_, known)| known == code)
                .map_or_else(|| code.to_string(), |(name, _)| name.to_string())
        };
        let types: Vec<String> = self
            .dns_permitted
            .iter()
            .map(type_name)
            .chain(
                self.dns_restricted
                    .iter()
                    .map(|code| format!("~{}", type_name(code))),
            )
            .collect();
        if !types.is_empty() {
            modifiers.push(format!("dnstype={}", types.join("|")));
        }

        if !self.denyallow.is_empty() {
            modifiers.push(format!("denyallow={}", self.denyallow.join("|")));
        }

        if !self.restricted_clients.is_empty() {
            let clients: Vec<String> = self
                .restricted_clients
                .entries()
                .iter()
                .map(|client| format!("~{}", client_text(client)))
                .collect();
            modifiers.push(format!("client={}", clients.join("|")));
        }

        if !self.restricted_ctags.is_empty() {
            let tags: Vec<String> = self
                .restricted_ctags
                .iter()
                .map(|tag| format!("~{tag}"))
                .collect();
            modifiers.push(format!("ctag={}", tags.join("|")));
        }

        let allow = if self.whitelist { "@@" } else { "" };
        if modifiers.is_empty() {
            return format!("{allow}{}", self.pattern);
        }

        // The pattern and the modifiers are split at the last `$` that has no backslash.
        let modifiers = modifiers.join(",").replace('$', "\\$");

        format!("{allow}{}${modifiers}", self.pattern)
    }
}

/// A `$client` name as `parse_clients` reads it back: bare when plain, otherwise quoted, with
/// the quote and the two separators escaped.
fn client_text(client: &str) -> String {
    let plain = client
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'));
    if plain {
        return client.to_string();
    }

    let escaped = client
        .replace('\'', "\\'")
        .replace(',', "\\,")
        .replace('|', "\\|");

    format!("'{escaped}'")
}

/// What the parser saw, per line class.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Counters {
    pub lines: u64,
    pub empty: u64,
    pub comments: u64,
    pub cosmetic: u64,
    /// `[Adblock Plus 2.0]` style headers.
    pub headers: u64,
    /// Host names of hosts lines and bare domains.
    pub host_names: u64,
    /// Host names that contain upper case: urlfilter indexes them as written, so they can
    /// never match a lowercased query. Dropped.
    pub unmatchable_hosts: u64,
    pub block_sub: u64,
    pub block_exact: u64,
    pub allow_sub: u64,
    pub allow_exact: u64,
    pub strict_sub_block: u64,
    pub strict_sub_allow: u64,
    /// Network rules kept as slow rules, and how many of them are regex rules and
    /// `$badfilter` rules.
    pub slow_rules: u64,
    pub regex_rules: u64,
    pub badfilter_rules: u64,
    /// Valid urlfilter rules that DNS filtering does not use (`$domain`, `$third-party`,
    /// content types that exclude a document, `$match-case`, ...).
    pub not_dns: u64,
    /// `$dnsrewrite`, `$respgeo`, and `$client` / `$ctag` rules that can never match.
    pub unsupported: u64,
    /// Lines urlfilter rejects (unknown modifier, bad value, too wide) and lines that do not
    /// belong to an explicit format.
    pub invalid: u64,
    pub non_utf8: u64,
    pub too_long: u64,
    /// RPZ records without a supported policy.
    pub rpz_skipped: u64,
    /// Rules dropped because the list reached its rule cap.
    pub over_cap: u64,
    /// The first line counted as invalid, for the one-time warning about a list.
    pub first_invalid: Option<String>,
}

/// The outcome of parsing a whole list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseSummary {
    /// The format that was used (`auto` resolved).
    pub format: ListFormat,
    pub counters: Counters,
}

/// Streaming list parser: `push` pieces of the text, then `finish`. It holds only the
/// unfinished line (at most [`MAX_LINE_BYTES`]) and, for `auto`, the first
/// [`DETECTION_BYTES`] until the format is decided.
pub struct Parser {
    format: Option<ListFormat>,
    head: Vec<u8>,
    line: Vec<u8>,
    overlong: bool,
    first_line: bool,
    max_rules: usize,
    emitted: usize,
    /// False turns a host rule's answer IP into the null address unless it already is a null
    /// route, so a list can block names but not point them somewhere.
    allow_redirects: bool,
    counters: Counters,
    rpz: RpzReader,
}

impl Parser {
    /// `format` may be `Auto`. At most `max_rules` rules are handed to the sink.
    pub fn new(format: ListFormat, max_rules: usize) -> Parser {
        Parser {
            format: (format != ListFormat::Auto).then_some(format),
            head: Vec::new(),
            line: Vec::new(),
            overlong: false,
            first_line: true,
            max_rules,
            emitted: 0,
            allow_redirects: true,
            counters: Counters::default(),
            rpz: RpzReader::new(),
        }
    }

    /// Feeds a piece of the list text. Pieces may split lines anywhere.
    pub fn push<F: FnMut(Rule<'_>)>(&mut self, chunk: &[u8], sink: &mut F) {
        if self.format.is_some() {
            self.feed(chunk, sink);

            return;
        }

        let take = chunk.len().min(DETECTION_BYTES - self.head.len());
        self.head.extend_from_slice(&chunk[..take]);
        if self.head.len() == DETECTION_BYTES {
            self.decide_format(sink);
            self.feed(&chunk[take..], sink);
        }
    }

    /// Ends the list and returns what was seen.
    pub fn finish<F: FnMut(Rule<'_>)>(mut self, sink: &mut F) -> ParseSummary {
        if self.format.is_none() {
            self.decide_format(sink);
        }

        if self.overlong || !self.line.is_empty() {
            self.end_line(sink);
        }

        let mut records = Vec::new();
        self.rpz.finish(&mut |record| records.push(record));
        for record in records {
            self.rpz_record(record, sink);
        }

        ParseSummary {
            format: self.format.unwrap_or(ListFormat::Adblock),
            counters: self.counters,
        }
    }

    /// Bytes held for an unfinished line and for format detection.
    #[cfg(test)]
    pub fn buffered_bytes(&self) -> usize {
        self.head.len() + self.line.len() + self.rpz.buffered_bytes()
    }

    fn decide_format<F: FnMut(Rule<'_>)>(&mut self, sink: &mut F) {
        let head = std::mem::take(&mut self.head);
        self.format = Some(detect_format(&head));
        self.feed(&head, sink);
    }

    fn feed<F: FnMut(Rule<'_>)>(&mut self, mut data: &[u8], sink: &mut F) {
        while !data.is_empty() {
            let Some(end) = data.iter().position(|&byte| byte == b'\n') else {
                self.extend_line(data);

                return;
            };

            self.extend_line(&data[..end]);
            self.end_line(sink);
            data = &data[end + 1..];
        }
    }

    fn extend_line(&mut self, part: &[u8]) {
        if self.overlong {
            return;
        }

        if self.line.len() + part.len() > MAX_LINE_BYTES {
            self.overlong = true;
            self.line.clear();

            return;
        }

        self.line.extend_from_slice(part);
    }

    fn end_line<F: FnMut(Rule<'_>)>(&mut self, sink: &mut F) {
        if self.overlong {
            self.overlong = false;
            self.counters.too_long += 1;

            return;
        }

        let line = std::mem::take(&mut self.line);
        self.handle_line(&line, sink);
        self.line = line;
        self.line.clear();
    }

    fn handle_line<F: FnMut(Rule<'_>)>(&mut self, bytes: &[u8], sink: &mut F) {
        self.counters.lines += 1;
        let Ok(mut text) = std::str::from_utf8(bytes) else {
            self.counters.non_utf8 += 1;
            self.first_line = false;

            return;
        };

        if self.first_line {
            self.first_line = false;
            text = text.strip_prefix('\u{feff}').unwrap_or(text);
        }

        match self.format.unwrap_or(ListFormat::Adblock) {
            ListFormat::Hosts => self.hosts_line(text, sink),
            ListFormat::Domains => self.domains_line(text, sink),
            ListFormat::Wildcard => self.wildcard_line(text, sink),
            ListFormat::Dnsmasq => self.dnsmasq_line(text, sink),
            ListFormat::Rpz => self.rpz_line(text, sink),
            ListFormat::Adblock | ListFormat::Auto => self.adguard_line(text, sink),
        }
    }

    /// Hands a rule to the sink unless the list is at its rule cap.
    fn emit<F: FnMut(Rule<'_>)>(&mut self, rule: Rule<'_>, sink: &mut F) -> bool {
        if self.emitted >= self.max_rules {
            self.counters.over_cap += 1;

            return false;
        }

        self.emitted += 1;
        sink(rule);

        true
    }

    fn emit_fast<F: FnMut(Rule<'_>)>(&mut self, kind: FastKind, name: &str, sink: &mut F) {
        if !self.emit(Rule::Fast { kind, name }, sink) {
            return;
        }

        let counter = match kind {
            FastKind::SubBlock => &mut self.counters.block_sub,
            FastKind::ExactBlock => &mut self.counters.block_exact,
            FastKind::SubAllow => &mut self.counters.allow_sub,
            FastKind::ExactAllow => &mut self.counters.allow_exact,
            FastKind::StrictSubBlock => &mut self.counters.strict_sub_block,
            FastKind::StrictSubAllow => &mut self.counters.strict_sub_allow,
        };
        *counter += 1;
    }

    /// Keeps the answer IPs of host rules only when `allow` is true, or when the IP is one of
    /// the null routes (`0.0.0.0`, `::`, `127.0.0.1`, `::1`); any other IP becomes `0.0.0.0`.
    pub fn allow_redirects(mut self, allow: bool) -> Parser {
        self.allow_redirects = allow;

        self
    }

    fn emit_host<F: FnMut(Rule<'_>)>(&mut self, ip: IpAddr, name: &str, sink: &mut F) {
        let ip = if self.allow_redirects || is_null_route(ip) {
            ip
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };

        if name.chars().any(char::is_uppercase) {
            self.counters.unmatchable_hosts += 1;
        } else if self.emit(Rule::Host { ip, name }, sink) {
            self.counters.host_names += 1;
        }
    }

    fn note_invalid(&mut self, line: &str) {
        self.counters.invalid += 1;
        if self.counters.first_invalid.is_none() {
            self.counters.first_invalid = Some(line.chars().take(100).collect());
        }
    }

    fn adguard_line<F: FnMut(Rule<'_>)>(&mut self, raw: &str, sink: &mut F) {
        let line = raw.trim();
        if line.is_empty() {
            self.counters.empty += 1;
        } else if is_comment(line) {
            self.counters.comments += 1;
        } else if is_cosmetic(line) {
            self.counters.cosmetic += 1;
        } else if is_adblock_header(line) {
            self.counters.headers += 1;
        } else if let Some((kind, name)) = fast_rule(line) {
            self.emit_fast(kind, name, sink);
        } else if let Some((ip, names)) = host_rule(line) {
            for name in names {
                self.emit_host(ip, name, sink);
            }
        } else {
            self.network_rule(line, sink);
        }
    }

    fn network_rule<F: FnMut(Rule<'_>)>(&mut self, line: &str, sink: &mut F) {
        match parse_network_rule(line) {
            Ok(rule) => {
                let (regex, badfilter) = (rule.is_regex(), rule.badfilter);
                if self.emit(Rule::Slow(rule), sink) {
                    self.counters.slow_rules += 1;
                    self.counters.regex_rules += u64::from(regex);
                    self.counters.badfilter_rules += u64::from(badfilter);
                }
            }
            Err(Drop::Invalid) => self.note_invalid(line),
            Err(Drop::Unsupported) => self.counters.unsupported += 1,
            Err(Drop::NotDns) => self.counters.not_dns += 1,
        }
    }

    /// Classifies a line of the explicit formats that are plain text with `#` comments.
    fn plain_line<'a>(&mut self, raw: &'a str) -> Option<&'a str> {
        let line = raw.trim();
        if line.is_empty() {
            self.counters.empty += 1;

            return None;
        }

        let content = if line.starts_with(['#', '!']) {
            ""
        } else {
            line.split('#').next().unwrap_or("").trim()
        };
        if content.is_empty() {
            self.counters.comments += 1;

            return None;
        }

        Some(content)
    }

    fn hosts_line<F: FnMut(Rule<'_>)>(&mut self, raw: &str, sink: &mut F) {
        let Some(content) = self.plain_line(raw) else {
            return;
        };

        let mut words = content.split_whitespace();
        let ip = words.next().and_then(parse_addr);
        let names: Vec<&str> = words.collect();
        let Some(ip) = ip.filter(|_| !names.is_empty()) else {
            self.note_invalid(content);

            return;
        };

        for name in names {
            self.emit_host(ip, &name.to_lowercase(), sink);
        }
    }

    fn domains_line<F: FnMut(Rule<'_>)>(&mut self, raw: &str, sink: &mut F) {
        let Some(content) = self.plain_line(raw) else {
            return;
        };

        let name = content.to_lowercase();
        if is_plain_name(&name) {
            self.emit_host(IpAddr::V4(Ipv4Addr::UNSPECIFIED), &name, sink);
        } else {
            self.note_invalid(content);
        }
    }

    fn wildcard_line<F: FnMut(Rule<'_>)>(&mut self, raw: &str, sink: &mut F) {
        let Some(content) = self.plain_line(raw) else {
            return;
        };

        let name = content.to_lowercase();
        let name = name.strip_prefix("*.").unwrap_or(&name);
        if is_plain_name(name) {
            self.emit_fast(FastKind::SubBlock, name, sink);
        } else {
            self.note_invalid(content);
        }
    }

    fn dnsmasq_line<F: FnMut(Rule<'_>)>(&mut self, raw: &str, sink: &mut F) {
        let Some(content) = self.plain_line(raw) else {
            return;
        };

        let domains = dnsmasq_domains(content);
        let Some(domains) = domains else {
            self.note_invalid(content);

            return;
        };

        for domain in domains {
            self.emit_fast(FastKind::SubBlock, &domain, sink);
        }
    }

    fn rpz_line<F: FnMut(Rule<'_>)>(&mut self, raw: &str, sink: &mut F) {
        let mut records = Vec::new();
        self.rpz.feed_line(raw, &mut |record| records.push(record));
        for record in records {
            self.rpz_record(record, sink);
        }
    }

    fn rpz_record<F: FnMut(Rule<'_>)>(&mut self, record: Record, sink: &mut F) {
        match record {
            Record::Directive => self.counters.headers += 1,
            Record::Other => self.counters.rpz_skipped += 1,
            Record::TooLong => self.counters.too_long += 1,
            Record::Policy {
                name,
                wildcard,
                allow,
            } => {
                let kind = match (wildcard, allow) {
                    (false, false) => FastKind::ExactBlock,
                    (true, false) => FastKind::StrictSubBlock,
                    (false, true) => FastKind::ExactAllow,
                    (true, true) => FastKind::StrictSubAllow,
                };
                self.emit_fast(kind, &name, sink);
            }
        }
    }
}

/// The domains of a dnsmasq `address=/d1/d2/ip`, `local=/d/` or `server=/d/` line, or
/// `None` for any other line (including `server=` lines that forward to an upstream).
fn dnsmasq_domains(content: &str) -> Option<Vec<String>> {
    let (key, value) = content.split_once('=')?;
    let inner = value.strip_prefix('/')?;
    let mut parts: Vec<&str> = inner.split('/').collect();
    let tail = parts.pop()?;
    if !matches!(key, "address" | "local" | "server") || (key == "server" && !tail.is_empty()) {
        return None;
    }

    let domains: Option<Vec<String>> = parts
        .iter()
        .map(|part| {
            let domain = part.trim_start_matches('.').to_lowercase();

            is_plain_name(&domain).then_some(domain)
        })
        .collect();

    domains.filter(|domains| !domains.is_empty())
}

/// A host name as the explicit formats accept it: lowercase letters, digits, `.`, `-`, `_`.
fn is_plain_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        })
}

// ---- Format detection ----

/// Decides the format of a list from its first [`DETECTION_BYTES`] (plan section 4.2).
pub fn detect_format(head: &[u8]) -> ListFormat {
    let head = &head[..head.len().min(DETECTION_BYTES)];
    let text = String::from_utf8_lossy(head);
    let text = text.trim_start_matches('\u{feff}');
    let mut first_content = None;
    let mut rule_lines = 0;
    let mut wildcard_lines = 0;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('[') {
            continue;
        }

        if line.starts_with(['!', '#', ';']) {
            if let Some(format) = header_format(line) {
                return format;
            }

            continue;
        }

        first_content.get_or_insert(line);
        if rule_lines < 200 {
            rule_lines += 1;
            wildcard_lines += usize::from(is_wildcard_line(line));
        }
    }

    if let Some(first) = first_content {
        let lower = first.to_ascii_lowercase();
        if lower.starts_with("$ttl") || lower.starts_with("$origin") || is_soa_record(first) {
            return ListFormat::Rpz;
        }

        if ["address=/", "local=/", "server=/"]
            .iter()
            .any(|prefix| lower.starts_with(prefix))
        {
            return ListFormat::Dnsmasq;
        }
    }

    if rule_lines > 0 && wildcard_lines * 10 >= rule_lines * 9 {
        return ListFormat::Wildcard;
    }

    ListFormat::Adblock
}

/// The format a `Syntax:` or `Format:` header comment names.
fn header_format(comment: &str) -> Option<ListFormat> {
    let lower = comment.to_ascii_lowercase();
    let value = ["syntax:", "format:"]
        .iter()
        .find_map(|key| lower.find(key).map(|at| &lower[at + key.len()..]))?;
    let has = |word: &str| value.contains(word);

    if has("rpz") {
        Some(ListFormat::Rpz)
    } else if has("dnsmasq") {
        Some(ListFormat::Dnsmasq)
    } else if has("adblock") || has("adguard") || has("ublock") {
        Some(ListFormat::Adblock)
    } else if has("wildcard") || has("without subdomains") {
        Some(ListFormat::Wildcard)
    } else if has("hosts") {
        Some(ListFormat::Hosts)
    } else if has("domains") {
        Some(ListFormat::Domains)
    } else {
        None
    }
}

fn is_soa_record(line: &str) -> bool {
    line.split_whitespace()
        .take(4)
        .skip(1)
        .any(|word| word.eq_ignore_ascii_case("SOA"))
}

fn is_wildcard_line(line: &str) -> bool {
    line.strip_prefix("*.").is_some_and(|name| {
        !name.is_empty() && !name.contains(char::is_whitespace) && !name.contains('*')
    })
}

// ---- AdGuard grammar: line classes ----

const COSMETIC_MARKERS: [&str; 12] = [
    "##", "#@#", "#?#", "#@?#", "#$#", "#@$#", "#$?#", "#@$?#", "#%#", "#@%#", "$$", "$@$",
];

fn is_comment(line: &str) -> bool {
    match line.as_bytes().first() {
        Some(b'!') => true,
        Some(b'#') => {
            line.len() == 1
                || !COSMETIC_MARKERS
                    .iter()
                    .any(|marker| line.starts_with(marker))
        }
        _ => false,
    }
}

/// urlfilter looks for a marker at the first `#` and the first `$` only, and ignores one
/// that follows a space (a hosts file comment such as `0.0.0.0 a.example  ## note`).
fn is_cosmetic(line: &str) -> bool {
    b"#$".iter().any(|&first| {
        let Some(at) = line.bytes().position(|byte| byte == first) else {
            return false;
        };

        (at == 0 || line.as_bytes()[at - 1] != b' ')
            && COSMETIC_MARKERS
                .iter()
                .any(|marker| line[at..].starts_with(marker))
    })
}

fn is_adblock_header(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();

    lower.starts_with('[')
        && lower.ends_with(']')
        && ["adblock", "ublock", "adguard"]
            .iter()
            .any(|word| lower.contains(word))
}

/// `||d^`, `|d^`, `@@||d^` and `@@|d^` with a plain lowercase `d` and no modifiers.
pub(crate) fn fast_rule(line: &str) -> Option<(FastKind, &str)> {
    let (allow, rest) = match line.strip_prefix("@@") {
        Some(rest) => (true, rest),
        None => (false, line),
    };
    let (sub, rest) = match rest.strip_prefix("||") {
        Some(rest) => (true, rest),
        None => (false, rest.strip_prefix('|')?),
    };
    let name = rest.strip_suffix('^')?;
    let plain = !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        });
    if !plain {
        return None;
    }

    let kind = match (sub, allow) {
        (true, false) => FastKind::SubBlock,
        (false, false) => FastKind::ExactBlock,
        (true, true) => FastKind::SubAllow,
        (false, true) => FastKind::ExactAllow,
    };

    Some((kind, name))
}

fn is_null_route(ip: IpAddr) -> bool {
    [
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ]
    .contains(&ip)
}

/// urlfilter's `NewHostRule`, including its inline comment handling: the text is cut one
/// byte before the first `#` (it assumes a space there).
fn host_rule(line: &str) -> Option<(IpAddr, Vec<&str>)> {
    let mut text = line;
    if let Some(hash) = line.find('#').filter(|&hash| hash > 0) {
        text = std::str::from_utf8(&line.as_bytes()[..hash - 1]).ok()?;
    }

    let (first, mut rest) = split_next_by_whitespace(text);
    if rest.is_empty() {
        return is_domain_name(first).then(|| (IpAddr::V4(Ipv4Addr::UNSPECIFIED), vec![first]));
    }

    let ip = parse_addr(first)?;
    let mut names = Vec::new();
    while !rest.is_empty() {
        let (name, after) = split_next_by_whitespace(rest);
        names.push(name);
        rest = after;
    }

    Some((ip, names))
}

fn split_next_by_whitespace(text: &str) -> (&str, &str) {
    let text = text.trim_start_matches([' ', '\t']);
    match text.find([' ', '\t']) {
        Some(end) => (&text[..end], text[end..].trim_start_matches([' ', '\t'])),
        None => (text, ""),
    }
}

/// `netip.ParseAddr`: an IPv6 address may carry a `%zone`, which is dropped.
fn parse_addr(text: &str) -> Option<IpAddr> {
    if let Some((address, zone)) = text.split_once('%') {
        if zone.is_empty() {
            return None;
        }

        return address.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }

    text.parse().ok()
}

/// urlfilter's `IsDomainName`: dot separated labels of letters, digits and inner hyphens,
/// and a last label of letters (or `xn--`) that is at least two characters long.
fn is_domain_name(name: &str) -> bool {
    if name.len() > 253 {
        return false;
    }

    let mut labels = name.rsplit('.');
    let tld = labels.next().unwrap_or("");
    let is_letter = |b: u8| b.is_ascii_alphabetic();
    let tld_ok = is_valid_label(tld)
        && tld.len() >= 2
        && is_letter(tld.as_bytes()[0])
        && is_letter(tld.as_bytes()[tld.len() - 1]);

    tld_ok && labels.all(is_valid_label)
}

fn is_valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }

    if label.starts_with("xn--") && bytes.len() < 8 {
        return false;
    }

    bytes.iter().enumerate().all(|(at, &b)| {
        b.is_ascii_alphanumeric() || (b == b'-' && at != 0 && at != bytes.len() - 1)
    })
}

// ---- AdGuard grammar: network rules ----

/// Why a network rule is not kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Drop {
    /// urlfilter rejects the rule.
    Invalid,
    /// A feature picoguard does not have: `$dnsrewrite`, `$respgeo`, permitted clients/tags.
    Unsupported,
    /// A valid rule that DNS filtering does not use or that cannot match a DNS request.
    NotDns,
}

const THIRD_PARTY: u32 = 1 << 0;
const MATCH_CASE: u32 = 1 << 1;
const IMPORTANT: u32 = 1 << 2;
const BADFILTER: u32 = 1 << 3;
const ELEMHIDE: u32 = 1 << 4;
const GENERICHIDE: u32 = 1 << 5;
const GENERICBLOCK: u32 = 1 << 6;
const JSINJECT: u32 = 1 << 7;
const URLBLOCK: u32 = 1 << 8;
const CONTENT: u32 = 1 << 9;
const EXTENSION: u32 = 1 << 10;
const STEALTH: u32 = 1 << 11;
const EMPTY: u32 = 1 << 12;
const MP4: u32 = 1 << 13;
const POPUP: u32 = 1 << 14;
const BLACKLIST_ONLY: u32 = EMPTY | MP4 | POPUP;
const WHITELIST_ONLY: u32 =
    CONTENT | ELEMHIDE | EXTENSION | GENERICBLOCK | GENERICHIDE | JSINJECT | STEALTH | URLBLOCK;
const DOCUMENT_ONLY: u32 =
    JSINJECT | ELEMHIDE | CONTENT | URLBLOCK | GENERICBLOCK | GENERICHIDE | EXTENSION | POPUP;
const HOST_LEVEL: u32 = IMPORTANT | BADFILTER;

/// Content type bits. The DNS request is of type "document" (bit 0), which no content
/// type modifier names, so a permitted list never contains it and a restricted list never
/// excludes it.
const TYPE_DOCUMENT: u32 = 1 << 0;
const CONTENT_TYPES: [(&str, u32); 11] = [
    ("subdocument", 1 << 1),
    ("script", 1 << 2),
    ("stylesheet", 1 << 3),
    ("object", 1 << 4),
    ("image", 1 << 5),
    ("xmlhttprequest", 1 << 6),
    ("media", 1 << 7),
    ("font", 1 << 8),
    ("websocket", 1 << 9),
    ("ping", 1 << 10),
    ("other", 1 << 11),
];

#[derive(Default)]
struct Clients {
    permitted: Vec<String>,
    restricted: Vec<String>,
}

#[derive(Default)]
struct Options {
    enabled: u32,
    disabled: u32,
    permitted_types: u32,
    restricted_types: u32,
    dns_permitted: Vec<u16>,
    dns_restricted: Vec<u16>,
    denyallow: Vec<String>,
    has_domain: bool,
    rewrite: bool,
    respgeo: bool,
    client: Option<Clients>,
    ctag: Option<Clients>,
}

impl Options {
    fn set(&mut self, whitelist: bool, option: u32, enabled: bool) -> Result<(), ()> {
        let wrong_side = if whitelist {
            option & BLACKLIST_ONLY == option
        } else {
            option & WHITELIST_ONLY == option
        };
        if wrong_side {
            return Err(());
        }

        if enabled {
            self.enabled |= option;
        } else {
            self.disabled |= option;
        }

        Ok(())
    }

    fn apply(&mut self, whitelist: bool, name: &str, value: &str) -> Result<(), ()> {
        match name {
            "third-party" | "~first-party" => self.set(whitelist, THIRD_PARTY, true),
            "~third-party" | "first-party" => self.set(whitelist, THIRD_PARTY, false),
            "match-case" => self.set(whitelist, MATCH_CASE, true),
            "~match-case" => self.set(whitelist, MATCH_CASE, false),
            "important" => self.set(whitelist, IMPORTANT, true),
            "badfilter" => self.set(whitelist, BADFILTER, true),
            "elemhide" => self.set(whitelist, ELEMHIDE, true),
            "generichide" => self.set(whitelist, GENERICHIDE, true),
            "genericblock" => self.set(whitelist, GENERICBLOCK, true),
            "jsinject" => self.set(whitelist, JSINJECT, true),
            "urlblock" => self.set(whitelist, URLBLOCK, true),
            "content" => self.set(whitelist, CONTENT, true),
            "stealth" => self.set(whitelist, STEALTH, true),
            "popup" => self.set(whitelist, POPUP, true),
            "empty" => self.set(whitelist, EMPTY, true),
            "mp4" => self.set(whitelist, MP4, true),
            "extension" => self.set(whitelist, EXTENSION, true),
            "~extension" => {
                self.enabled ^= EXTENSION;

                Ok(())
            }
            "document" => {
                let first = self.set(whitelist, ELEMHIDE, true);
                for option in [JSINJECT, URLBLOCK, CONTENT, EXTENSION] {
                    let _ = self.set(whitelist, option, true);
                }

                first
            }
            "dnstype" => self.set_dns_types(value),
            "dnsrewrite" => {
                self.rewrite = true;

                Ok(())
            }
            "respgeo" => {
                self.respgeo = true;

                Ok(())
            }
            "domain" => {
                parse_domains(value)?;
                self.has_domain = true;

                Ok(())
            }
            "denyallow" => {
                let (permitted, restricted) = parse_domains(value)?;
                if !restricted.is_empty() || permitted.is_empty() {
                    return Err(());
                }

                self.denyallow = permitted;

                Ok(())
            }
            "client" => {
                self.client = parse_clients(value)?;

                Ok(())
            }
            "ctag" => {
                self.ctag = parse_ctags(value)?;

                Ok(())
            }
            _ => self.set_content_type(name),
        }
    }

    fn set_content_type(&mut self, name: &str) -> Result<(), ()> {
        let (restricted, bare) = match name.strip_prefix('~') {
            Some(bare) => (true, bare),
            None => (false, name),
        };
        let (_, bit) = CONTENT_TYPES
            .iter()
            .find(|(type_name, _)| *type_name == bare)
            .ok_or(())?;
        if restricted {
            self.restricted_types |= bit;
        } else {
            self.permitted_types |= bit;
        }

        Ok(())
    }

    fn set_dns_types(&mut self, value: &str) -> Result<(), ()> {
        if value.is_empty() {
            return Err(());
        }

        let (mut permitted, mut restricted) = (Vec::new(), Vec::new());
        for item in value.split('|') {
            let (is_restricted, name) = match item.strip_prefix('~') {
                Some(name) => (true, name),
                None => (false, item),
            };
            let code = dns_type_code(name).ok_or(())?;
            if is_restricted {
                restricted.push(code);
            } else {
                permitted.push(code);
            }
        }

        self.dns_permitted = permitted;
        self.dns_restricted = restricted;

        Ok(())
    }

    fn has_restrictions(&self) -> bool {
        self.has_domain
            || self.respgeo
            || self.client.is_some()
            || self.ctag.is_some()
            || !self.dns_permitted.is_empty()
            || !self.dns_restricted.is_empty()
            || !self.denyallow.is_empty()
    }
}

/// urlfilter `parseDomains` with `|` separators; returns (permitted, restricted).
fn parse_domains(value: &str) -> Result<(Vec<String>, Vec<String>), ()> {
    if value.is_empty() {
        return Err(());
    }

    let (mut permitted, mut restricted) = (Vec::new(), Vec::new());
    for item in value.split('|') {
        let (is_restricted, domain) = match item.strip_prefix('~') {
            Some(domain) => (true, domain),
            None => (false, item),
        };
        if !is_domain_name(domain) && !domain.ends_with(".*") {
            return Err(());
        }

        if is_restricted {
            restricted.push(domain.to_string());
        } else {
            permitted.push(domain.to_string());
        }
    }

    Ok((permitted, restricted))
}

/// urlfilter `parseClients`; `None` when the value has no entries at all.
fn parse_clients(value: &str) -> Result<Option<Clients>, ()> {
    if value.is_empty() {
        return Err(());
    }

    let mut clients = Clients::default();
    for part in split_with_escape(value, b'|') {
        let (restricted, client) = match part.strip_prefix('~') {
            Some(client) => (true, client),
            None => (false, part.as_str()),
        };
        let bytes = client.as_bytes();
        let quote = if bytes.len() >= 2
            && (bytes[0] == b'\'' || bytes[0] == b'"')
            && bytes[0] == bytes[bytes.len() - 1]
        {
            Some(bytes[0] as char)
        } else {
            None
        };
        let mut client = match quote {
            Some(_) => client[1..client.len() - 1].to_string(),
            None => client.to_string(),
        }
        .replace("\\,", ",");
        if let Some(quote) = quote {
            client = client.replace(&format!("\\{quote}"), &quote.to_string());
        }

        if client.is_empty() {
            return Err(());
        }

        if restricted {
            clients.restricted.push(client);
        } else {
            clients.permitted.push(client);
        }
    }

    Ok(Clients::normalized(clients))
}

/// urlfilter `parseCTags`: lowercase letters, digits and `_`, `~` for exclusion.
fn parse_ctags(value: &str) -> Result<Option<Clients>, ()> {
    if value.is_empty() {
        return Err(());
    }

    let mut tags = Clients::default();
    for item in value.split('|') {
        let (restricted, tag) = match item.strip_prefix('~') {
            Some(tag) => (true, tag),
            None => (false, item),
        };
        if !tag
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(());
        }

        if restricted {
            tags.restricted.push(tag.to_string());
        } else {
            tags.permitted.push(tag.to_string());
        }
    }

    Ok(Clients::normalized(tags))
}

impl Clients {
    /// Sorted sets; `None` when empty (the rule then has no restriction).
    fn normalized(mut self) -> Option<Clients> {
        for list in [&mut self.permitted, &mut self.restricted] {
            list.sort();
            list.dedup();
        }

        (!self.permitted.is_empty() || !self.restricted.is_empty()).then_some(self)
    }
}

/// urlfilter `splitWithEscapeCharacter` with `\` as the escape: `\<sep>` is a literal
/// separator, empty parts are dropped.
fn split_with_escape(text: &str, separator: u8) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut parts = Vec::new();
    let mut current = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'\\' && at + 1 < bytes.len() && bytes[at + 1] == separator {
            current.push(separator);
            at += 1;
        } else if bytes[at] == separator {
            if !current.is_empty() {
                parts.push(String::from_utf8_lossy(&current).into_owned());
                current.clear();
            }
        } else {
            current.push(bytes[at]);
        }

        at += 1;
    }

    if !current.is_empty() {
        parts.push(String::from_utf8_lossy(&current).into_owned());
    }

    parts
}

/// The last `$` that is not escaped with a backslash splits pattern and options.
fn split_pattern_and_options(text: &str) -> (String, String) {
    let bytes = text.as_bytes();
    let mut escaped = false;
    for at in (0..bytes.len()).rev() {
        if bytes[at] != b'$' {
            continue;
        }

        if at > 0 && bytes[at - 1] == b'\\' {
            escaped = true;

            continue;
        }

        let options = &text[at + 1..];
        let options = if escaped {
            options.replace("\\$", "$")
        } else {
            options.to_string()
        };

        return (text[..at].to_string(), options);
    }

    (text.to_string(), String::new())
}

pub fn dns_type_code(name: &str) -> Option<u16> {
    if name.eq_ignore_ascii_case("none") || name.eq_ignore_ascii_case("reserved") {
        return None;
    }

    let upper = name.to_ascii_uppercase();

    DNS_TYPES
        .iter()
        .find(|(type_name, _)| *type_name == upper)
        .map(|(_, code)| *code)
}

fn is_pattern_too_wide(pattern: &str) -> bool {
    matches!(pattern, "||" | "|" | "*" | "") || pattern.len() < 3
}

fn parse_network_rule(text: &str) -> Result<NetworkRule, Drop> {
    if text.is_empty() || text == "@@" {
        return Err(Drop::Invalid);
    }

    let (whitelist, rest) = match text.strip_prefix("@@") {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let (pattern, option_text) =
        if rest.starts_with('/') && rest.ends_with('/') && !rest.contains("replace=") {
            (rest.to_string(), String::new())
        } else {
            split_pattern_and_options(rest)
        };

    let mut options = Options::default();
    for item in split_with_escape(&option_text, b',') {
        let (name, value) = match item.find('=').filter(|&at| at > 0) {
            Some(at) => (&item[..at], &item[at + 1..]),
            None => (item.as_str(), ""),
        };
        options
            .apply(whitelist, name, value)
            .map_err(|()| Drop::Invalid)?;
    }

    if options.enabled & DOCUMENT_ONLY != 0 {
        options.permitted_types = TYPE_DOCUMENT;
    }

    let mut normalized = pattern.clone();
    if let Some(stem) = pattern.strip_suffix("/*") {
        normalized = format!("{stem}^");
    }

    if is_pattern_too_wide(&pattern) && !options.has_restrictions() {
        return Err(Drop::Invalid);
    }

    let permitted_client = options
        .client
        .as_ref()
        .is_some_and(|c| !c.permitted.is_empty());
    let permitted_tag = options
        .ctag
        .as_ref()
        .is_some_and(|c| !c.permitted.is_empty());
    if options.rewrite || options.respgeo || permitted_client || permitted_tag {
        return Err(Drop::Unsupported);
    }

    let host_level = !options.has_domain
        && !(options.permitted_types != 0 && options.restricted_types != 0)
        && options.disabled == 0
        && options.enabled & !HOST_LEVEL == 0;
    if !host_level || options.permitted_types != 0 || pattern == "^" {
        return Err(Drop::NotDns);
    }

    let restricted = |clients: &Option<Clients>| {
        clients
            .as_ref()
            .map(|clients| clients.restricted.clone())
            .unwrap_or_default()
    };

    Ok(NetworkRule {
        whitelist,
        important: options.enabled & IMPORTANT != 0,
        badfilter: options.enabled & BADFILTER != 0,
        pattern: normalized,
        restricted_types: options.restricted_types,
        restricted_clients: ClientSet::new(&restricted(&options.client)),
        restricted_ctags: restricted(&options.ctag),
        dns_permitted: options.dns_permitted,
        dns_restricted: options.dns_restricted,
        denyallow: options.denyallow,
    })
}

/// Record type names urlfilter accepts in `$dnstype` (the miekg/dns table).
const DNS_TYPES: [(&str, u16); 86] = [
    ("A", 1),
    ("AAAA", 28),
    ("AFSDB", 18),
    ("AMTRELAY", 260),
    ("ANY", 255),
    ("APL", 42),
    ("ATMA", 34),
    ("AVC", 258),
    ("AXFR", 252),
    ("CAA", 257),
    ("CDNSKEY", 60),
    ("CDS", 59),
    ("CERT", 37),
    ("CNAME", 5),
    ("CSYNC", 62),
    ("DHCID", 49),
    ("DLV", 32769),
    ("DNAME", 39),
    ("DNSKEY", 48),
    ("DS", 43),
    ("EID", 31),
    ("EUI48", 108),
    ("EUI64", 109),
    ("GID", 102),
    ("GPOS", 27),
    ("HINFO", 13),
    ("HIP", 55),
    ("HTTPS", 65),
    ("IPSECKEY", 45),
    ("ISDN", 20),
    ("IXFR", 251),
    ("KEY", 25),
    ("KX", 36),
    ("L32", 105),
    ("L64", 106),
    ("LOC", 29),
    ("LP", 107),
    ("MAILA", 254),
    ("MAILB", 253),
    ("MB", 7),
    ("MD", 3),
    ("MF", 4),
    ("MG", 8),
    ("MINFO", 14),
    ("MR", 9),
    ("MX", 15),
    ("NAPTR", 35),
    ("NID", 104),
    ("NIMLOC", 32),
    ("NINFO", 56),
    ("NS", 2),
    ("NSAP-PTR", 23),
    ("NSEC", 47),
    ("NSEC3", 50),
    ("NSEC3PARAM", 51),
    ("NULL", 10),
    ("NXNAME", 128),
    ("NXT", 30),
    ("OPENPGPKEY", 61),
    ("OPT", 41),
    ("PTR", 12),
    ("PX", 26),
    ("RESINFO", 261),
    ("RKEY", 57),
    ("RP", 17),
    ("RRSIG", 46),
    ("RT", 21),
    ("SIG", 24),
    ("SMIMEA", 53),
    ("SOA", 6),
    ("SPF", 99),
    ("SRV", 33),
    ("SSHFP", 44),
    ("SVCB", 64),
    ("TA", 32768),
    ("TALINK", 58),
    ("TKEY", 249),
    ("TLSA", 52),
    ("TSIG", 250),
    ("TXT", 16),
    ("UID", 101),
    ("UINFO", 100),
    ("UNSPEC", 103),
    ("URI", 256),
    ("X25", 19),
    ("ZONEMD", 63),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn describe(rule: &Rule<'_>) -> String {
        match rule {
            Rule::Host { ip, name } => format!("host {ip} {name}"),
            Rule::Fast { kind, name } => format!("{kind:?} {name}"),
            Rule::Slow(rule) => {
                let mut text = format!("slow {}", rule.pattern);
                for (flag, on) in [
                    ("allow", rule.whitelist),
                    ("important", rule.important),
                    ("badfilter", rule.badfilter),
                ] {
                    if on {
                        text.push_str(&format!(" {flag}"));
                    }
                }

                let types = |list: &[u16], prefix: &str| {
                    list.iter()
                        .map(|t| format!("{prefix}{t}"))
                        .collect::<Vec<_>>()
                };
                let mut dns = types(&rule.dns_permitted, "");
                dns.extend(types(&rule.dns_restricted, "~"));
                if !dns.is_empty() {
                    text.push_str(&format!(" dnstype={}", dns.join("|")));
                }

                if !rule.denyallow.is_empty() {
                    text.push_str(&format!(" denyallow={}", rule.denyallow.join("|")));
                }

                if !rule.restricted_clients.is_empty() {
                    let nets = rule
                        .restricted_clients
                        .nets
                        .iter()
                        .map(|(ip, bits)| format!("{ip}/{bits}"));
                    let names = rule.restricted_clients.names.iter().cloned();
                    let entries: Vec<String> = nets.chain(names).collect();
                    text.push_str(&format!(" client={}", entries.join("|")));
                }

                if !rule.restricted_ctags.is_empty() {
                    text.push_str(&format!(" ctag={}", rule.restricted_ctags.join("|")));
                }

                text
            }
        }
    }

    fn parse_chunks(format: ListFormat, chunks: &[&[u8]]) -> (Vec<String>, ParseSummary) {
        let mut rules = Vec::new();
        let mut parser = Parser::new(format, usize::MAX);
        let mut sink = |rule: Rule<'_>| rules.push(describe(&rule));
        for chunk in chunks {
            parser.push(chunk, &mut sink);
        }

        let summary = parser.finish(&mut sink);

        (rules, summary)
    }

    fn parse(format: ListFormat, text: &str) -> (Vec<String>, ParseSummary) {
        parse_chunks(format, &[text.as_bytes()])
    }

    fn adguard(text: &str) -> (Vec<String>, Counters) {
        let (rules, summary) = parse(ListFormat::Adblock, text);

        (rules, summary.counters)
    }

    fn one(line: &str) -> String {
        let (rules, _) = adguard(line);
        assert_eq!(rules.len(), 1, "{line:?} gave {rules:?}");

        rules[0].clone()
    }

    fn none(line: &str) -> Counters {
        let (rules, counters) = adguard(line);
        assert!(rules.is_empty(), "{line:?} gave {rules:?}");

        counters
    }

    #[test]
    fn line_classes_are_counted() {
        let text = "\n   \n! comment\n# comment\n#\n[Adblock Plus 2.0]\nexample.com##.ad\nexample.com#@#.ad\nexample.com#?#div\nexample.com#$#a{b:c}\nexample.com#%#//x\nexample.com$$script\n||a.example^\n";
        let (rules, counters) = adguard(text);
        assert_eq!(rules, ["SubBlock a.example"]);
        assert_eq!(counters.lines, 13);
        assert_eq!(counters.empty, 2);
        assert_eq!(counters.comments, 3);
        assert_eq!(counters.headers, 1);
        assert_eq!(counters.cosmetic, 6);
        assert_eq!(counters.block_sub, 1);
    }

    #[test]
    fn host_rules_keep_their_ip_unless_redirects_are_not_allowed() {
        let text = "1.2.3.4 a.example\n0.0.0.0 b.example\n127.0.0.1 c.example\n::1 d.example\n:: e.example\n2001:db8::1 f.example\n10.0.0.1 g.example h.example\n";
        for format in [ListFormat::Adblock, ListFormat::Hosts] {
            let described = |mut parser: Parser| {
                let mut rules = Vec::new();
                let mut sink = |rule: Rule<'_>| rules.push(describe(&rule));
                parser.push(text.as_bytes(), &mut sink);
                parser.finish(&mut sink);

                rules
            };

            let kept = described(Parser::new(format, usize::MAX));
            let blocked = described(Parser::new(format, usize::MAX).allow_redirects(false));

            assert_eq!(
                kept,
                [
                    "host 1.2.3.4 a.example",
                    "host 0.0.0.0 b.example",
                    "host 127.0.0.1 c.example",
                    "host ::1 d.example",
                    "host :: e.example",
                    "host 2001:db8::1 f.example",
                    "host 10.0.0.1 g.example",
                    "host 10.0.0.1 h.example",
                ],
                "{format:?}"
            );
            assert_eq!(
                blocked,
                [
                    "host 0.0.0.0 a.example",
                    "host 0.0.0.0 b.example",
                    "host 127.0.0.1 c.example",
                    "host ::1 d.example",
                    "host :: e.example",
                    "host 0.0.0.0 f.example",
                    "host 0.0.0.0 g.example",
                    "host 0.0.0.0 h.example",
                ],
                "{format:?}"
            );
        }
    }

    #[test]
    fn cosmetic_marker_after_a_space_is_a_hosts_comment() {
        assert_eq!(
            one("0.0.0.0 phish.example  ## phishing"),
            "host 0.0.0.0 phish.example"
        );
    }

    #[test]
    fn fast_path_shapes() {
        let (rules, counters) = adguard(
            "||sub.example^\n|exact.example^\n@@||allow.example^\n@@|allow-exact.example^\n",
        );
        assert_eq!(
            rules,
            [
                "SubBlock sub.example",
                "ExactBlock exact.example",
                "SubAllow allow.example",
                "ExactAllow allow-exact.example"
            ]
        );
        assert_eq!(
            (
                counters.block_sub,
                counters.block_exact,
                counters.allow_sub,
                counters.allow_exact
            ),
            (1, 1, 1, 1)
        );
    }

    #[test]
    fn rules_outside_the_fast_shapes_are_slow_rules_with_their_spelling() {
        assert_eq!(one("||ADS.example^"), "slow ||ADS.example^");
        assert_eq!(one("||ads.example"), "slow ||ads.example");
        assert_eq!(one("||ads.example^|"), "slow ||ads.example^|");
        assert_eq!(
            one("||ads.example^$important"),
            "slow ||ads.example^ important"
        );
        assert_eq!(one("||a*b.example^"), "slow ||a*b.example^");
        assert_eq!(one("||a.example:80^"), "slow ||a.example:80^");
        assert_eq!(one("ads.example^"), "slow ads.example^");
        assert_eq!(
            one("@@||x.example^$important"),
            "slow ||x.example^ allow important"
        );
    }

    #[test]
    fn host_lines() {
        assert_eq!(one("0.0.0.0 ads.example"), "host 0.0.0.0 ads.example");
        assert_eq!(one("127.0.0.1\tads.example"), "host 127.0.0.1 ads.example");
        assert_eq!(one("::1 ads.example"), "host ::1 ads.example");
        assert_eq!(
            one("::ffff:1.2.3.4 ads.example"),
            "host ::ffff:1.2.3.4 ads.example"
        );
        assert_eq!(one("fe80::1%lo0 ads.example"), "host fe80::1 ads.example");
        let (rules, counters) = adguard("0.0.0.0 a.example b.example\tc.example\n");
        assert_eq!(
            rules,
            [
                "host 0.0.0.0 a.example",
                "host 0.0.0.0 b.example",
                "host 0.0.0.0 c.example"
            ]
        );
        assert_eq!(counters.host_names, 3);
    }

    #[test]
    fn bare_domain_is_a_host_rule_with_the_null_ip() {
        assert_eq!(one("ads.example"), "host 0.0.0.0 ads.example");
        assert_eq!(one("localhost"), "host 0.0.0.0 localhost");
        assert_eq!(
            one("xn--bcher-kva.example"),
            "host 0.0.0.0 xn--bcher-kva.example"
        );
        assert_eq!(one("a.b"), "slow a.b");
        assert_eq!(one("under_score.example"), "slow under_score.example");
        assert_eq!(one("1.2.3.4"), "slow 1.2.3.4");
        assert_eq!(one("two tokens.example"), "slow two tokens.example");
        assert_eq!(one("999.1.1.1 ads.example"), "slow 999.1.1.1 ads.example");
    }

    #[test]
    fn inline_comment_cuts_one_byte_before_the_hash_like_urlfilter() {
        assert_eq!(one("0.0.0.0 a.example # why"), "host 0.0.0.0 a.example");
        assert_eq!(one("0.0.0.0 a.example#why"), "host 0.0.0.0 a.exampl");
        assert_eq!(one("a.example # why"), "host 0.0.0.0 a.example");
        assert_eq!(one("a.example#why"), "host 0.0.0.0 a.exampl");
    }

    #[test]
    fn upper_case_host_names_never_match_and_are_counted() {
        let counters = none("0.0.0.0 Ads.Example\n");
        assert_eq!(counters.unmatchable_hosts, 1);
        assert_eq!(counters.host_names, 0);
        assert_eq!(none("Ads.Example").unmatchable_hosts, 1);
    }

    #[test]
    fn dnstype_modifier() {
        assert_eq!(
            one("||a.example^$dnstype=A|~AAAA"),
            "slow ||a.example^ dnstype=1|~28"
        );
        assert_eq!(
            one("||a.example^$dnstype=txt"),
            "slow ||a.example^ dnstype=16"
        );
        assert_eq!(
            one("||a.example^$dnstype=ANY"),
            "slow ||a.example^ dnstype=255"
        );
        for bad in ["NONE", "", "NOTATYPE", "A||", "~"] {
            let counters = none(&format!("||a.example^$dnstype={bad}"));
            assert_eq!(counters.invalid, 1, "dnstype={bad}");
        }
    }

    #[test]
    fn denyallow_modifier() {
        assert_eq!(
            one("||a.example^$denyallow=x.example|y.example"),
            "slow ||a.example^ denyallow=x.example|y.example"
        );
        assert_eq!(
            one("||a.example^$denyallow=Upper.example"),
            "slow ||a.example^ denyallow=Upper.example"
        );
        assert_eq!(
            one("*$denyallow=x.example,dnstype=A"),
            "slow * dnstype=1 denyallow=x.example"
        );
        assert_eq!(
            one("||a.example^$denyallow=google.*"),
            "slow ||a.example^ denyallow=google.*"
        );
        for bad in ["", "~x.example", "not a domain", "x.example|~y.example"] {
            assert_eq!(
                none(&format!("||a.example^$denyallow={bad}")).invalid,
                1,
                "{bad}"
            );
        }
    }

    #[test]
    fn important_and_badfilter() {
        assert_eq!(
            one("||a.example^$important,badfilter"),
            "slow ||a.example^ important badfilter"
        );
        let (_, counters) = adguard("||a.example^$badfilter\n||b.example^$badfilter\n");
        assert_eq!(counters.badfilter_rules, 2);
    }

    #[test]
    fn content_type_modifiers_decide_whether_a_document_request_matches() {
        assert_eq!(none("||a.example^$script").not_dns, 1);
        assert_eq!(none("||a.example^$image,stylesheet").not_dns, 1);
        assert_eq!(none("||a.example^$script,~image").not_dns, 1);
        assert_eq!(one("||a.example^$~script"), "slow ||a.example^");
        assert_eq!(one("||a.example^$~script,~image"), "slow ||a.example^");
    }

    #[test]
    fn modifiers_dns_filtering_does_not_use_are_counted_not_fatal() {
        for rule in [
            "||a.example^$third-party",
            "||a.example^$~third-party",
            "||a.example^$first-party",
            "||a.example^$~first-party",
            "||a.example^$domain=b.example",
            "||a.example^$domain=~b.example",
            "||a.example^$match-case",
            "||a.example^$~match-case",
            "||a.example^$popup",
            "||a.example^$empty",
            "||a.example^$mp4",
            "@@||a.example^$document",
            "@@||a.example^$urlblock",
            "@@||a.example^$elemhide",
            "@@||a.example^$stealth",
            "@@||a.example^$extension",
        ] {
            let (rules, counters) = adguard(rule);
            assert!(rules.is_empty(), "{rule}: {rules:?}");
            assert_eq!(counters.not_dns, 1, "{rule}");
        }

        // `~extension` toggles the option, so on and off cancel out.
        assert_eq!(
            one("@@||a.example^$extension,~extension"),
            "slow ||a.example^ allow"
        );
    }

    #[test]
    fn whitelist_only_and_unknown_modifiers_are_invalid() {
        for rule in [
            "||a.example^$document",
            "||a.example^$elemhide",
            "||a.example^$stealth",
            "||a.example^$extension",
            "||a.example^$nosuchmodifier",
            "||a.example^$important,nosuchmodifier",
            "||a.example^$redirect=noop",
            "||a.example^$cookie",
            "||a.example^$csp=x",
            "||a.example^$replace=/a/b/",
            "||a.example^$domain=",
            "||a.example^$domain=not a domain",
            "@@||a.example^$popup",
        ] {
            let counters = none(rule);
            assert_eq!(counters.invalid, 1, "{rule}");
            assert!(counters.first_invalid.is_some());
        }
    }

    fn identity_of(rule: &str) -> Identity {
        let mut identity = None;
        let mut parser = Parser::new(ListFormat::Adblock, usize::MAX);
        let mut sink = |parsed: Rule<'_>| {
            if let Rule::Slow(rule) = parsed {
                identity = Some(rule.identity());
            }
        };
        parser.push(format!("{rule}\n").as_bytes(), &mut sink);
        parser.finish(&mut sink);

        identity.unwrap_or_else(|| panic!("{rule:?} is not a slow rule"))
    }

    #[test]
    fn client_addresses_and_subnets_are_compared_in_normal_form() {
        let same = |a: &str, b: &str| {
            assert_eq!(
                identity_of(&format!("||a.example^$client={a}")),
                identity_of(&format!("||a.example^$client={b}")),
                "{a} and {b}"
            );
        };
        same("~192.0.2.1", "~192.0.2.1/32");
        same("~192.0.2.0/24", "~192.0.2.77/24");
        same("~2001:db8::1", "~2001:0DB8:0:0:0:0:0:1/128");
        same("~fe80::1%eth0", "~fe80::1");
        same("~b|~a", "~a|~b");
        same("~a|~a", "~a");
        same("~0.0.0.0/0", "~10.1.2.3/0");
    }

    #[test]
    fn client_entries_that_differ_stay_different() {
        let differ = |a: &str, b: &str| {
            assert_ne!(
                identity_of(&format!("||a.example^$client={a}")),
                identity_of(&format!("||a.example^$client={b}")),
                "{a} and {b}"
            );
        };
        differ("~a|~b", "~a\\|b");
        differ("~192.0.2.1", "~192.0.2.1/24");
        differ("~192.0.2.1", "~::ffff:192.0.2.1");
        differ("~Mom", "~mom");
        differ("~192.0.2.1/033", "~192.0.2.1/33");
        differ("~192.0.2.1/32", "~192.0.2.1/32|~x");
    }

    #[test]
    fn client_ctag_dnsrewrite_and_respgeo() {
        assert_eq!(none("||a.example^$dnsrewrite=1.2.3.4").unsupported, 1);
        assert_eq!(none("||a.example^$respgeo=us").unsupported, 1);
        assert_eq!(none("||a.example^$client=127.0.0.1").unsupported, 1);
        assert_eq!(none("||a.example^$ctag=device_pc").unsupported, 1);
        assert_eq!(none("||a.example^$client=~a|b").unsupported, 1);
        assert_eq!(
            one("||a.example^$client=~192.168.0.1|~'Mom\\'s laptop'"),
            "slow ||a.example^ client=192.168.0.1/32|Mom's laptop"
        );
        assert_eq!(
            one("||a.example^$ctag=~device_pc|~device_phone"),
            "slow ||a.example^ ctag=device_pc|device_phone"
        );
        assert_eq!(none("||a.example^$client=").invalid, 1);
        assert_eq!(none("||a.example^$ctag=BAD").invalid, 1);
    }

    #[test]
    fn option_splitting_and_delimiter_rules() {
        assert_eq!(one("||a.example^$"), "slow ||a.example^");
        assert_eq!(
            one("||a.example^$,important"),
            "slow ||a.example^ important"
        );
        assert_eq!(
            one("||a.example^$important,important"),
            "slow ||a.example^ important"
        );
        // An escaped comma belongs to the value; the value is then not a domain.
        assert_eq!(
            none("||a.example^$denyallow=a.example\\,b.example").invalid,
            1
        );
        // The delimiter is the last unescaped dollar sign.
        assert_eq!(
            one("||a.example^$important$"),
            "slow ||a.example^$important"
        );
        assert_eq!(
            one("||esc-dollar\\$sign.example^"),
            "slow ||esc-dollar\\$sign.example^"
        );
    }

    #[test]
    fn too_wide_rules_are_invalid_unless_restricted() {
        for rule in ["*", "||", "|", "//", "/", "a", "*$important"] {
            assert_eq!(none(rule).invalid, 1, "{rule}");
        }

        assert_eq!(one("*$dnstype=A"), "slow * dnstype=1");
        assert_eq!(one("/a/$dnstype=A"), "slow /a/ dnstype=1");
        assert_eq!(none("^").invalid, 1);
        assert_eq!(none("^$dnstype=A").not_dns, 1);
    }

    #[test]
    fn trailing_slash_star_becomes_a_separator() {
        assert_eq!(one("example.org/*"), "slow example.org^");
        assert_eq!(one("||path.example/*"), "slow ||path.example^");
    }

    fn slow_rule(line: &str) -> NetworkRule {
        let mut parsed = None;
        let mut parser = Parser::new(ListFormat::Adblock, usize::MAX);
        let mut sink = |rule: Rule<'_>| {
            if let Rule::Slow(rule) = rule {
                parsed = Some(rule);
            }
        };
        parser.push(format!("{line}\n").as_bytes(), &mut sink);
        parser.finish(&mut sink);

        parsed.unwrap_or_else(|| panic!("{line:?} is not a slow rule"))
    }

    #[test]
    fn a_rule_without_modifiers_shows_as_written() {
        for line in [
            r"/^ad[0-9]+\./",
            "/ads$/",
            "||ad*.example^",
            "@@||ok*.example^",
        ] {
            assert_eq!(slow_rule(line).text(), line);
        }

        assert_eq!(slow_rule("||ad*.example/*").text(), "||ad*.example^");
    }

    #[test]
    fn rule_text_parses_back_to_the_same_rule() {
        for line in [
            "||ads.example^$important",
            "@@||x.example^$important",
            r"/^ad[0-9]+\./",
            "/ads$/",
            "||ad*.example^",
            "||a.example^$dnstype=A|~AAAA",
            "*$denyallow=x.example|y.example",
            "||c.example^$client=~192.168.1.5|~laptop",
            r"||m.example^$client=~'Mom\'s laptop'",
            "||t.example^$ctag=~device_pc",
            "||s.example^$~script,~image",
            r"||d.example^$client=~'cash\$box'",
            r"||e.example^$client=~'a\,b'|~'c\|d'",
            r"||f.example^$client=~'x\$y\,z'",
            r"||g.example^$client=~'back\\slash'",
        ] {
            let rule = slow_rule(line);
            let text = rule.text();

            assert_eq!(slow_rule(&text), rule, "{line} gave {text}");
        }
    }

    #[test]
    fn rule_text_is_the_pattern_and_modifiers_in_a_fixed_order() {
        assert_eq!(
            slow_rule("||a.example^$dnstype=A|~AAAA").text(),
            "||a.example^$dnstype=A|~AAAA"
        );
        assert_eq!(slow_rule(r"/^ad[0-9]+\./").text(), r"/^ad[0-9]+\./");
        assert_eq!(
            slow_rule("||x.example^$dnstype=AAAA,important").text(),
            "||x.example^$important,dnstype=AAAA"
        );
    }

    #[test]
    fn regex_rules() {
        let (rules, counters) = adguard("/^ad[0-9]+\\./\n/ab/$important,dnstype=MX\n");
        assert_eq!(
            rules,
            ["slow /^ad[0-9]+\\./", "slow /ab/ important dnstype=15"]
        );
        assert_eq!(counters.regex_rules, 2);
    }

    #[test]
    fn explicit_hosts_format() {
        let text = "# hosts\n127.0.0.1 localhost\n0.0.0.0 Ads.Example   other.example # note\nfe80::1%lo0 ip6-localhost\nads.example\n||x.example^\n";
        let (rules, summary) = parse(ListFormat::Hosts, text);
        assert_eq!(
            rules,
            [
                "host 127.0.0.1 localhost",
                "host 0.0.0.0 ads.example",
                "host 0.0.0.0 other.example",
                "host fe80::1 ip6-localhost"
            ]
        );
        assert_eq!(summary.counters.invalid, 2);
        assert_eq!(summary.counters.comments, 1);
    }

    #[test]
    fn explicit_domains_format() {
        let (rules, summary) = parse(
            ListFormat::Domains,
            "! x\n# y\nAds.Example\nb.example # c\ntwo tokens\n\n",
        );
        assert_eq!(
            rules,
            ["host 0.0.0.0 ads.example", "host 0.0.0.0 b.example"]
        );
        assert_eq!(summary.counters.invalid, 1);
    }

    #[test]
    fn explicit_wildcard_format_covers_apex_and_subdomains() {
        let (rules, summary) = parse(
            ListFormat::Wildcard,
            "# Syntax: Domains Wildcard\n*.a.example\nb.example\nC.Example\n*.d.*.example\n",
        );
        assert_eq!(
            rules,
            [
                "SubBlock a.example",
                "SubBlock b.example",
                "SubBlock c.example"
            ]
        );
        assert_eq!(summary.counters.block_sub, 3);
        assert_eq!(summary.counters.invalid, 1);
    }

    #[test]
    fn explicit_dnsmasq_format() {
        let text = "# c\nlocal=/a.example/\nserver=/b.example/\nserver=/c.example/1.1.1.1\naddress=/d.example/e.example/0.0.0.0\naddress=/f.example/#\nipset=/g.example/set\nA.Example\n";
        let (rules, summary) = parse(ListFormat::Dnsmasq, text);
        assert_eq!(
            rules,
            [
                "SubBlock a.example",
                "SubBlock b.example",
                "SubBlock d.example",
                "SubBlock e.example",
                "SubBlock f.example"
            ]
        );
        assert_eq!(summary.counters.invalid, 3);
    }

    #[test]
    fn explicit_rpz_format() {
        let text = "$TTL 3600\n@ SOA localhost. root.localhost. 1 2 3 4 5\n  NS localhost.\na.example CNAME .\n*.a.example CNAME .\nb.example CNAME rpz-passthru.\n*.b.example CNAME rpz-passthru.\nc.example A 1.2.3.4\n";
        let (rules, summary) = parse(ListFormat::Rpz, text);
        assert_eq!(
            rules,
            [
                "ExactBlock a.example",
                "StrictSubBlock a.example",
                "ExactAllow b.example",
                "StrictSubAllow b.example"
            ]
        );
        assert_eq!(summary.counters.rpz_skipped, 3);
        assert_eq!(summary.counters.block_exact, 1);
        assert_eq!(summary.counters.strict_sub_allow, 1);
    }

    #[test]
    fn auto_detection() {
        let wildcard_hint = b"# Syntax: Domains Wildcard (without subdomains)\n*.a.example\n";
        let domains_hint = b"# Syntax: Domains (without subdomains)\na.example\n";
        assert_eq!(detect_format(wildcard_hint), ListFormat::Wildcard);
        assert_eq!(detect_format(domains_hint), ListFormat::Wildcard);
        assert_eq!(
            detect_format(b"! Syntax: AdBlock\n||a.example^\n"),
            ListFormat::Adblock
        );
        assert_eq!(
            detect_format(b"# Syntax: DNSMasq v2.86 or newer\n"),
            ListFormat::Dnsmasq
        );
        assert_eq!(
            detect_format(b"$TTL 3600\n; Syntax: RPZ\n"),
            ListFormat::Rpz
        );
        assert_eq!(
            detect_format(b"# Format: hosts\n0.0.0.0 a.example\n"),
            ListFormat::Hosts
        );
        assert_eq!(
            detect_format(b"# Syntax: Domains\na.example\n"),
            ListFormat::Domains
        );
        assert_eq!(
            detect_format(b"; c\n$ORIGIN rpz.\na CNAME .\n"),
            ListFormat::Rpz
        );
        assert_eq!(
            detect_format(b"; c\n@ IN SOA ns. admin. 1 2 3 4 5\n"),
            ListFormat::Rpz
        );
        assert_eq!(
            detect_format(b"# c\nlocal=/a.example/\n"),
            ListFormat::Dnsmasq
        );
        assert_eq!(detect_format(b"server=/a.example/\n"), ListFormat::Dnsmasq);
        assert_eq!(
            detect_format(b"address=/a.example/#\n"),
            ListFormat::Dnsmasq
        );
        assert_eq!(detect_format(b"# c\n||a.example^\n"), ListFormat::Adblock);
        assert_eq!(detect_format(b"0.0.0.0 a.example\n"), ListFormat::Adblock);
        assert_eq!(detect_format(b""), ListFormat::Adblock);
    }

    #[test]
    fn wildcard_share_decides_without_a_hint() {
        let mut ninety = String::new();
        for i in 0..90 {
            ninety.push_str(&format!("*.d{i}.example\n"));
        }

        for i in 0..10 {
            ninety.push_str(&format!("plain{i}.example\n"));
        }

        assert_eq!(detect_format(ninety.as_bytes()), ListFormat::Wildcard);

        let mut eighty = String::new();
        for i in 0..80 {
            eighty.push_str(&format!("*.d{i}.example\n"));
        }

        for i in 0..20 {
            eighty.push_str(&format!("plain{i}.example\n"));
        }

        assert_eq!(detect_format(eighty.as_bytes()), ListFormat::Adblock);
    }

    #[test]
    fn a_bare_domain_list_without_a_hint_keeps_adguard_semantics() {
        let (rules, summary) = parse(ListFormat::Auto, "a.example\nb.example\n");
        assert_eq!(summary.format, ListFormat::Adblock);
        assert_eq!(rules, ["host 0.0.0.0 a.example", "host 0.0.0.0 b.example"]);
    }

    #[test]
    fn auto_reports_the_detected_format() {
        let (rules, summary) = parse(ListFormat::Auto, "# Syntax: DNSMasq\nlocal=/a.example/\n");
        assert_eq!(summary.format, ListFormat::Dnsmasq);
        assert_eq!(rules, ["SubBlock a.example"]);
    }

    #[test]
    fn result_does_not_depend_on_where_the_chunks_split() {
        let text = "# Syntax: AdBlock\n||a.example^\r\n0.0.0.0 b.example\n@@||c.example^$important\n/x[0-9]/\nlast.example";
        let whole = parse(ListFormat::Auto, text);
        for size in [1, 2, 3, 7, 16] {
            let chunks: Vec<&[u8]> = text.as_bytes().chunks(size).collect();
            assert_eq!(
                parse_chunks(ListFormat::Auto, &chunks),
                whole,
                "chunk size {size}"
            );
        }

        assert_eq!(whole.0.len(), 5);
    }

    #[test]
    fn detection_waits_for_the_first_64_kib() {
        let mut text = String::from("# comment\n");
        while text.len() < DETECTION_BYTES + 100 {
            text.push_str("# padding comment line\n");
        }

        text.push_str("local=/late.example/\n");
        let (rules, summary) = parse(ListFormat::Auto, &text);
        // The directive is past the detection window, so the list is AdGuard grammar.
        assert_eq!(summary.format, ListFormat::Adblock);
        assert_eq!(rules, ["slow local=/late.example/"]);
    }

    #[test]
    fn lines_over_the_cap_are_skipped_and_counted() {
        let mut text = String::from("||a.example^\n");
        text.push_str(&"x".repeat(MAX_LINE_BYTES + 1));
        text.push('\n');
        text.push_str(&"y".repeat(MAX_LINE_BYTES));
        text.push_str("\n||b.example^\n");
        let (rules, summary) = parse(ListFormat::Adblock, &text);
        assert_eq!(rules.len(), 3);
        assert_eq!(summary.counters.too_long, 1);
    }

    #[test]
    fn a_huge_single_line_stays_within_the_line_cap() {
        let mut parser = Parser::new(ListFormat::Adblock, usize::MAX);
        let mut count = 0;
        let mut sink = |_: Rule<'_>| count += 1;
        let chunk = vec![b'a'; 1024 * 1024];
        let mut peak = 0;
        for _ in 0..64 {
            parser.push(&chunk, &mut sink);
            peak = peak.max(parser.buffered_bytes());
        }

        let summary = parser.finish(&mut sink);
        assert_eq!(summary.counters.too_long, 1);
        assert_eq!(count, 0);
        assert!(peak <= MAX_LINE_BYTES, "held {peak} bytes");
    }

    #[test]
    fn an_rpz_record_spanning_many_short_lines_stays_within_the_cap() {
        let mut parser = Parser::new(ListFormat::Rpz, usize::MAX);
        let mut rules = Vec::new();
        let mut sink = |rule: Rule<'_>| rules.push(describe(&rule));
        parser.push(b"big.example CNAME (\n", &mut sink);
        let mut peak = 0;
        for _ in 0..100_000 {
            parser.push(b"  x\n", &mut sink);
            peak = peak.max(parser.buffered_bytes());
        }

        parser.push(b")\nok.example CNAME .\n", &mut sink);
        let summary = parser.finish(&mut sink);
        assert_eq!(summary.counters.too_long, 1);
        assert_eq!(rules, ["ExactBlock ok.example"]);
        assert!(peak <= MAX_LINE_BYTES, "held {peak} bytes");
    }

    #[test]
    fn auto_detection_holds_at_most_the_detection_window() {
        let mut parser = Parser::new(ListFormat::Auto, usize::MAX);
        let mut sink = |_: Rule<'_>| {};
        let chunk = vec![b'a'; 1024 * 1024];
        parser.push(&chunk, &mut sink);
        assert!(parser.buffered_bytes() <= MAX_LINE_BYTES);
    }

    #[test]
    fn rule_cap_drops_and_counts_the_rest() {
        let mut rules = Vec::new();
        let mut parser = Parser::new(ListFormat::Adblock, 2);
        let mut sink = |rule: Rule<'_>| rules.push(describe(&rule));
        parser.push(
            b"||a.example^\n||b.example^\n||c.example^\n0.0.0.0 d.example e.example\n",
            &mut sink,
        );
        let summary = parser.finish(&mut sink);
        assert_eq!(rules.len(), 2);
        assert_eq!(summary.counters.over_cap, 3);
    }

    #[test]
    fn invalid_utf8_lines_are_counted() {
        let mut parser = Parser::new(ListFormat::Adblock, usize::MAX);
        let mut seen = 0;
        let mut sink = |_: Rule<'_>| seen += 1;
        parser.push(
            b"||a.example^\n||\xff\xfe.example^\n||b.example^\n",
            &mut sink,
        );
        let summary = parser.finish(&mut sink);
        assert_eq!(seen, 2);
        assert_eq!(summary.counters.non_utf8, 1);
    }

    #[test]
    fn a_byte_order_mark_is_ignored() {
        let (rules, _) = parse(ListFormat::Adblock, "\u{feff}||a.example^\n");
        assert_eq!(rules, ["SubBlock a.example"]);
    }
}
