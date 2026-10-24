//! A stateful reader for RPZ zone files (DNS master file syntax).
//!
//! It keeps `$ORIGIN`, the previous owner (for blank-owner lines) and joins parenthesized
//! multi-line records. Only the policy records matter: `owner CNAME .` blocks the name,
//! `*.owner CNAME .` blocks its subdomains, `CNAME rpz-passthru.` allows with the same scope.

/// What one complete record of the zone means for the blocklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// A policy for `name`; `wildcard` is the `*.name` form (subdomains only).
    Policy {
        name: String,
        wildcard: bool,
        allow: bool,
    },
    /// `$ORIGIN`, `$TTL`, `$INCLUDE` and other directives.
    Directive,
    /// A record without a supported policy (SOA, NS, other CNAME targets, IP triggers, ...).
    Other,
    /// A parenthesized record that grew past [`MAX_RECORD_BYTES`]; it was discarded.
    TooLong,
}

/// The most text one record may accumulate; the same cap as a list line.
pub const MAX_RECORD_BYTES: usize = super::parse::MAX_LINE_BYTES;

#[derive(Debug, Default)]
pub struct RpzReader {
    origin: Option<String>,
    last_owner: Option<String>,
    pending: String,
    pending_blank_owner: bool,
    discarding: bool,
    depth: i32,
}

impl RpzReader {
    pub fn new() -> RpzReader {
        RpzReader::default()
    }

    /// Feeds one line; calls `out` for every record the line completes.
    pub fn feed_line(&mut self, line: &str, out: &mut impl FnMut(Record)) {
        let stripped = strip_comment(line);
        if self.depth == 0 {
            if stripped.trim().is_empty() {
                return;
            }

            self.pending.clear();
            self.pending_blank_owner = stripped.starts_with([' ', '\t']);
        }

        let (flat, depth_change) = flatten_parentheses(&stripped);
        self.depth = (self.depth + depth_change).max(0);
        if !self.discarding && self.pending.len() + 1 + flat.len() > MAX_RECORD_BYTES {
            self.discarding = true;
            self.pending = String::new();
        }

        if !self.discarding {
            self.pending.push(' ');
            self.pending.push_str(&flat);
        }

        if self.depth == 0 {
            self.end_record(out);
        }
    }

    /// Flushes a record left open by a missing closing parenthesis.
    pub fn finish(&mut self, out: &mut impl FnMut(Record)) {
        if self.depth > 0 {
            self.depth = 0;
            self.end_record(out);
        }
    }

    /// Bytes held for the record in progress.
    #[cfg(test)]
    pub fn buffered_bytes(&self) -> usize {
        self.pending.len()
    }

    fn end_record(&mut self, out: &mut impl FnMut(Record)) {
        if std::mem::take(&mut self.discarding) {
            out(Record::TooLong);

            return;
        }

        let record = std::mem::take(&mut self.pending);
        self.record(&record, self.pending_blank_owner, out);
    }

    fn record(&mut self, text: &str, blank_owner: bool, out: &mut impl FnMut(Record)) {
        let text = text.trim();
        if text.starts_with('$') {
            let mut words = text.split_whitespace();
            if words
                .next()
                .is_some_and(|d| d.eq_ignore_ascii_case("$ORIGIN"))
            {
                // `$ORIGIN .` is the root: an absolute owner has nothing to lose.
                self.origin = words
                    .next()
                    .map(|origin| origin.trim_end_matches('.').to_ascii_lowercase())
                    .filter(|origin| !origin.is_empty());
            }

            out(Record::Directive);

            return;
        }

        let mut words = text.split_whitespace();
        let owner = if blank_owner {
            match self.last_owner.clone() {
                Some(owner) => owner,
                None => {
                    out(Record::Other);

                    return;
                }
            }
        } else {
            let Some(owner) = words.next() else {
                return;
            };
            self.last_owner = Some(owner.to_string());

            owner.to_string()
        };

        let record_type = words.by_ref().find(|word| !is_class(word) && !is_ttl(word));
        let target = words.next();
        let is_cname = record_type.is_some_and(|word| word.eq_ignore_ascii_case("CNAME"));
        let action = match target {
            Some(".") | Some("*.") => Some(false),
            Some(target) if target.eq_ignore_ascii_case("rpz-drop.") => Some(false),
            Some(target) if target.eq_ignore_ascii_case("rpz-passthru.") => Some(true),
            _ => None,
        };

        let policy = match (is_cname, action) {
            (true, Some(allow)) => {
                self.policy_name(&owner)
                    .map(|(name, wildcard)| Record::Policy {
                        name,
                        wildcard,
                        allow,
                    })
            }
            _ => None,
        };

        out(policy.unwrap_or(Record::Other));
    }

    /// The name a policy owner stands for, and whether it is the `*.name` form.
    fn policy_name(&self, owner: &str) -> Option<(String, bool)> {
        if owner == "@" {
            return None;
        }

        let mut name = owner.to_ascii_lowercase();
        if name.ends_with('.') {
            name.pop();
            if let Some(origin) = self.origin.as_deref() {
                name = relative_to(&name, origin)?.to_string();
            }
        }

        let wildcard = name.starts_with("*.");
        if wildcard {
            name.drain(..2);
        }

        let valid = !name.is_empty()
            && name.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
            });
        let trigger = TRIGGER_SUFFIXES.iter().any(|suffix| name.ends_with(suffix));

        (valid && !trigger).then_some((name, wildcard))
    }
}

/// `name` without the zone `origin`, when it is the origin or ends in `.origin`.
fn relative_to<'a>(name: &'a str, origin: &str) -> Option<&'a str> {
    let relative = name.strip_suffix(origin)?;
    if relative.is_empty() {
        return Some(relative);
    }

    relative.strip_suffix('.')
}

/// Owner suffixes of the RPZ triggers that are not about the queried name.
const TRIGGER_SUFFIXES: [&str; 4] = [".rpz-ip", ".rpz-nsdname", ".rpz-nsip", ".rpz-client-ip"];

fn is_class(word: &str) -> bool {
    ["IN", "CH", "HS", "CS"]
        .iter()
        .any(|class| word.eq_ignore_ascii_case(class))
}

fn is_ttl(word: &str) -> bool {
    word.starts_with(|c: char| c.is_ascii_digit())
        && word
            .chars()
            .all(|c| c.is_ascii_digit() || "smhdwSMHDW".contains(c))
}

/// Cuts a `;` comment, leaving semicolons inside quoted strings alone.
fn strip_comment(line: &str) -> String {
    let mut quoted = false;
    let mut escaped = false;
    let mut kept = String::with_capacity(line.len());
    for c in line.chars() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            quoted = !quoted;
        } else if c == ';' && !quoted {
            break;
        }

        kept.push(c);
    }

    kept
}

/// Replaces parentheses outside quotes with spaces and returns the nesting change.
fn flatten_parentheses(line: &str) -> (String, i32) {
    let mut quoted = false;
    let mut change = 0;
    let flat = line
        .chars()
        .map(|c| {
            if c == '"' {
                quoted = !quoted;
            }

            match c {
                '(' if !quoted => {
                    change += 1;

                    ' '
                }
                ')' if !quoted => {
                    change -= 1;

                    ' '
                }
                _ => c,
            }
        })
        .collect();

    (flat, change)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> Vec<Record> {
        let mut reader = RpzReader::new();
        let mut records = Vec::new();
        for line in text.lines() {
            reader.feed_line(line, &mut |record| records.push(record));
        }

        reader.finish(&mut |record| records.push(record));

        records
    }

    fn policy(name: &str, wildcard: bool, allow: bool) -> Record {
        Record::Policy {
            name: name.to_string(),
            wildcard,
            allow,
        }
    }

    #[test]
    fn exact_and_wildcard_block() {
        let records = read("ads.example CNAME .\n*.ads.example CNAME .\n");
        assert_eq!(
            records,
            [
                policy("ads.example", false, false),
                policy("ads.example", true, false)
            ]
        );
    }

    #[test]
    fn passthru_allows_with_the_same_scope() {
        let records = read("ok.example CNAME rpz-passthru.\n*.ok.example CNAME rpz-passthru.\n");
        assert_eq!(
            records,
            [
                policy("ok.example", false, true),
                policy("ok.example", true, true)
            ]
        );
    }

    #[test]
    fn nodata_and_drop_actions_block() {
        let records = read("a.example CNAME *.\nb.example CNAME rpz-drop.\n");
        assert_eq!(
            records,
            [
                policy("a.example", false, false),
                policy("b.example", false, false)
            ]
        );
    }

    #[test]
    fn directives_soa_and_ns_are_not_policies() {
        let text = "$TTL 3600\n@ SOA localhost. root.localhost. 1 28800 3600 259200 3600\n  NS  localhost.\n;\n; comment\n";
        let records = read(text);
        assert_eq!(records, [Record::Directive, Record::Other, Record::Other]);
    }

    #[test]
    fn blank_owner_repeats_the_previous_owner() {
        let records = read("multi.example CNAME .\n    CNAME rpz-passthru.\n");
        assert_eq!(
            records,
            [
                policy("multi.example", false, false),
                policy("multi.example", false, true)
            ]
        );
    }

    #[test]
    fn optional_ttl_and_class_fields() {
        let records = read(
            "a.example 300 IN CNAME .\nb.example IN 1h CNAME .\nc.example 1h30m CNAME .\nd.example IN CNAME .\n",
        );
        let names: Vec<_> = records
            .iter()
            .map(|record| match record {
                Record::Policy { name, .. } => name.as_str(),
                _ => "?",
            })
            .collect();
        assert_eq!(names, ["a.example", "b.example", "c.example", "d.example"]);
    }

    #[test]
    fn origin_makes_absolute_owners_relative() {
        let text = "$ORIGIN rpz.local.\nrel.example CNAME .\nabs.example.rpz.local. CNAME .\n*.abs2.example.rpz.local. CNAME .\n";
        let records = read(text);
        assert_eq!(records[0], Record::Directive);
        assert_eq!(records[1], policy("rel.example", false, false));
        assert_eq!(records[2], policy("abs.example", false, false));
        assert_eq!(records[3], policy("abs2.example", true, false));
    }

    #[test]
    fn absolute_owner_without_origin_loses_the_trailing_dot() {
        let records = read("ads.example. CNAME .\n");
        assert_eq!(records, [policy("ads.example", false, false)]);
    }

    #[test]
    fn parenthesized_records_span_lines() {
        let text = "@ IN SOA ns.local. admin.local. (\n  2026102401 ; serial\n  3600 600\n  86400 300 )\nads.example CNAME .\n";
        let records = read(text);
        assert_eq!(
            records,
            [Record::Other, policy("ads.example", false, false)]
        );
    }

    #[test]
    fn comments_are_stripped_but_not_inside_quotes() {
        let text = "ads.example CNAME . ; blocked\ntxt.example TXT \"a;b\" ; comment\n";
        let records = read(text);
        assert_eq!(
            records,
            [policy("ads.example", false, false), Record::Other]
        );
    }

    #[test]
    fn other_record_types_and_triggers_are_skipped() {
        let text = "a.example A 1.2.3.4\nb.example CNAME walled.example.\n32.4.3.2.1.rpz-ip CNAME .\nns.rpz-nsdname CNAME .\nmid*.example CNAME .\n";
        let records = read(text);
        assert_eq!(records, vec![Record::Other; 5]);
    }

    #[test]
    fn a_record_over_the_byte_cap_is_discarded_through_its_closing_parenthesis() {
        let mut reader = RpzReader::new();
        let mut records = Vec::new();
        let mut out = |record| records.push(record);
        reader.feed_line("big.example CNAME (", &mut out);
        let mut peak = 0;
        for _ in 0..10_000 {
            reader.feed_line("  ads.example", &mut out);
            peak = peak.max(reader.buffered_bytes());
        }

        reader.feed_line(")", &mut out);
        reader.feed_line("after.example CNAME .", &mut out);
        reader.finish(&mut out);
        assert_eq!(
            records,
            [Record::TooLong, policy("after.example", false, false)]
        );
        assert!(peak <= MAX_RECORD_BYTES, "held {peak} bytes");
    }

    #[test]
    fn a_record_at_the_byte_cap_is_kept() {
        let padding = " ".repeat(MAX_RECORD_BYTES - 23);
        let text = format!("a.example CNAME (\n{padding}\n.\n)\n");
        assert_eq!(read(&text), [policy("a.example", false, false)]);
    }

    #[test]
    fn an_oversized_record_left_open_is_counted_at_the_end() {
        let mut text = String::from("big.example CNAME (\n");
        text.push_str(&"  x\n".repeat(5_000));
        assert_eq!(read(&text), [Record::TooLong]);
    }

    #[test]
    fn origin_stripping_respects_label_boundaries() {
        let text = "$ORIGIN rpz.test.\nad.notrpz.test. CNAME .\nad.rpz.test. CNAME .\nrpz.test. CNAME .\nother.example. CNAME .\n";
        let records = read(text);
        assert_eq!(
            records,
            [
                Record::Directive,
                Record::Other,
                policy("ad", false, false),
                Record::Other,
                Record::Other,
            ]
        );
    }

    #[test]
    fn the_root_origin_removes_nothing_from_absolute_owners() {
        let text = "$ORIGIN .\nabs.example. CNAME .\n*.wild.example. CNAME .\nrel.example CNAME .\nok.example. CNAME rpz-passthru.\n";
        let records = read(text);
        assert_eq!(
            records,
            [
                Record::Directive,
                policy("abs.example", false, false),
                policy("wild.example", true, false),
                policy("rel.example", false, false),
                policy("ok.example", false, true),
            ]
        );
    }

    #[test]
    fn the_root_origin_replaces_an_earlier_zone_origin() {
        let records = read("$ORIGIN rpz.test.\n$ORIGIN .\nabs.example. CNAME .\n");

        assert_eq!(records[2], policy("abs.example", false, false));
    }

    #[test]
    fn names_are_lowercased() {
        let records = read("ADS.Example CNAME .\n");
        assert_eq!(records, [policy("ads.example", false, false)]);
    }
}
