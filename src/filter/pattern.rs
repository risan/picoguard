//! urlfilter-equivalent pattern matching for slow rules, and the candidate enumeration of
//! the fast path.
//!
//! urlfilter turns a rule pattern into a regular expression and matches it against the
//! host name, or against the synthetic URL `http://<host>` for patterns with a URL prefix.
//! Patterns that are not `/regex/` rules are matched here without a regex engine: the
//! translation produces only literals, `.*`, the separator class and anchors, and a small
//! backtracking matcher keeps each rule at a few dozen bytes. `/regex/` rules use the
//! `regex` crate after a translation of the Go (RE2) syntax differences.

use std::fmt;

use regex::{Regex, RegexBuilder};

/// Compiled regexes may not grow beyond this many bytes.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// The lazy DFA cache of one regex.
const REGEX_DFA_LIMIT: usize = 1 << 17;

/// Go's `regexp` rejects repetition counts above this.
const MAX_REPEAT: u32 = 1000;

/// A compiled slow-rule pattern.
pub struct Matcher {
    /// Lowercase; urlfilter checks it against the URL before the pattern.
    shortcut: String,
    subject: Subject,
    body: Body,
}

/// What the pattern is matched against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Subject {
    Host,
    /// The synthetic URL `http://<host>`.
    Url,
}

enum Body {
    Any,
    Glob(Glob),
    Regex(Regex),
}

#[derive(Debug, PartialEq, Eq)]
pub enum PatternError {
    /// The regular expression is rejected by Go's `regexp` or cannot be compiled here.
    Regex(String),
}

impl fmt::Display for PatternError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatternError::Regex(message) => write!(formatter, "regex: {message}"),
        }
    }
}

impl Matcher {
    /// `pattern` is the rule pattern after urlfilter's normalization (`/*` to `^`).
    pub fn compile(pattern: &str) -> Result<Matcher, PatternError> {
        let is_regex = is_regex_pattern(pattern);
        let shortcut = if is_regex {
            regex_shortcut(pattern)
        } else {
            glob_shortcut(pattern).to_string()
        };
        let shortcut = if shortcut.len() > 1 {
            shortcut.to_lowercase()
        } else {
            String::new()
        };

        let subject = if !is_regex && uses_url(pattern) {
            Subject::Url
        } else {
            Subject::Host
        };

        let body = if matches!(pattern, "||" | "|" | "*" | "") {
            Body::Any
        } else if is_regex {
            let inner = &pattern[1..pattern.len() - 1];
            if inner == ".*" {
                Body::Any
            } else {
                Body::Regex(compile_regex(inner)?)
            }
        } else {
            Body::Glob(Glob::parse(pattern))
        };

        Ok(Matcher {
            shortcut,
            subject,
            body,
        })
    }

    /// The lowercase text a URL must contain for the rule to match; empty when the rule has
    /// no usable shortcut.
    pub fn shortcut(&self) -> &str {
        &self.shortcut
    }

    /// `host` is the lowercase input; `url` is `http://` followed by `host`.
    pub fn is_match(&self, host: &str, url: &str) -> bool {
        if !self.shortcut.is_empty() && !url.contains(&self.shortcut) {
            return false;
        }

        let subject = match self.subject {
            Subject::Host => host,
            Subject::Url => url,
        };

        match &self.body {
            Body::Any => true,
            Body::Glob(glob) => glob.is_match(subject.as_bytes()),
            Body::Regex(regex) => regex.is_match(subject),
        }
    }
}

fn is_regex_pattern(pattern: &str) -> bool {
    pattern.len() > 1 && pattern.starts_with('/') && pattern.ends_with('/')
}

/// urlfilter's `shouldMatchHostname` is false for these patterns.
fn uses_url(pattern: &str) -> bool {
    ["||", "http://", "https://", "://"]
        .iter()
        .any(|prefix| pattern.starts_with(prefix))
        || (pattern.len() >= 4 && pattern.starts_with('/') && pattern.ends_with('.'))
}

fn compile_regex(source: &str) -> Result<Regex, PatternError> {
    let translated = translate_go_regex(source)?;

    RegexBuilder::new(&translated)
        .case_insensitive(true)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_DFA_LIMIT)
        .build()
        .map_err(|error| PatternError::Regex(error.to_string()))
}

// ---- Glob patterns ----

/// `||` is the URL start, a single `|` the subject start, and a trailing `|` the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Start {
    Anywhere,
    Anchored,
    UrlHost,
}

#[derive(Debug)]
enum Token {
    Literal(Vec<u8>),
    /// `*`: any run of characters.
    Any,
    /// `^`: one character other than a letter, digit, space or one of `.%_-`, or the end.
    Separator,
}

#[derive(Debug)]
struct Glob {
    start: Start,
    tokens: Vec<Token>,
    end: bool,
    has_any: bool,
}

impl Glob {
    /// The same translation as urlfilter's `patternToRegexp`, without the regex: every
    /// character is a literal except `*` and `^`; `|` is an anchor only at the ends.
    fn parse(pattern: &str) -> Glob {
        let (start, rest) = if let Some(rest) = pattern.strip_prefix("||") {
            (Start::UrlHost, rest)
        } else if let Some(rest) = pattern.strip_prefix('|') {
            (Start::Anchored, rest)
        } else {
            (Start::Anywhere, pattern)
        };
        let (end, rest) = match rest.strip_suffix('|') {
            Some(rest) => (true, rest),
            None => (false, rest),
        };

        let mut tokens: Vec<Token> = Vec::new();
        let mut buffer = [0; 4];
        for c in rest.chars() {
            match c {
                '*' => tokens.push(Token::Any),
                '^' => tokens.push(Token::Separator),
                _ => {
                    let mut lower = c.to_lowercase();
                    let literal = match (lower.next(), lower.next()) {
                        (Some(single), None) => single,
                        _ => c,
                    };
                    let bytes = literal.encode_utf8(&mut buffer).as_bytes();
                    match tokens.last_mut() {
                        Some(Token::Literal(run)) => run.extend_from_slice(bytes),
                        _ => tokens.push(Token::Literal(bytes.to_vec())),
                    }
                }
            }
        }

        let has_any = tokens.iter().any(|token| matches!(token, Token::Any));

        Glob {
            start,
            tokens,
            end,
            has_any,
        }
    }

    fn is_match(&self, subject: &[u8]) -> bool {
        // A failed (token, position) pair fails from every start, so one memo serves all.
        let mut failed = if self.has_any {
            vec![false; self.tokens.len() * (subject.len() + 1)]
        } else {
            Vec::new()
        };

        match self.start {
            Start::Anchored => self.match_from(subject, 0, 0, &mut failed),
            Start::UrlHost => {
                const SCHEME: &[u8] = b"http://";
                if !subject
                    .get(..SCHEME.len())
                    .is_some_and(|head| head.eq_ignore_ascii_case(SCHEME))
                {
                    return false;
                }

                // `([a-z0-9-_.]+\.)?` may skip leading labels made of name characters.
                if self.match_from(subject, 0, SCHEME.len(), &mut failed) {
                    return true;
                }

                for (at, &byte) in subject.iter().enumerate().skip(SCHEME.len()) {
                    if !is_name_byte(byte) {
                        break;
                    }

                    if byte == b'.'
                        && at > SCHEME.len()
                        && self.match_from(subject, 0, at + 1, &mut failed)
                    {
                        return true;
                    }
                }

                false
            }
            Start::Anywhere => (0..=subject.len())
                .filter(|&at| is_boundary(subject, at))
                .any(|at| self.match_from(subject, 0, at, &mut failed)),
        }
    }

    fn match_from(&self, subject: &[u8], token: usize, at: usize, failed: &mut [bool]) -> bool {
        let Some(current) = self.tokens.get(token) else {
            return !self.end || at == subject.len();
        };

        let memo = token * (subject.len() + 1) + at;
        if self.has_any && failed[memo] {
            return false;
        }

        let found = match current {
            Token::Literal(literal) => {
                subject[at..].starts_with(literal)
                    && self.match_from(subject, token + 1, at + literal.len(), failed)
            }
            Token::Separator => match subject.get(at) {
                None => self.match_from(subject, token + 1, at, failed),
                Some(&byte) if is_separator(byte) => {
                    self.match_from(subject, token + 1, at + char_len(byte), failed)
                }
                Some(_) => false,
            },
            Token::Any => (at..=subject.len())
                .filter(|&next| is_boundary(subject, next))
                .any(|next| self.match_from(subject, token + 1, next, failed)),
        };

        if !found && self.has_any {
            failed[memo] = true;
        }

        found
    }
}

fn is_boundary(bytes: &[u8], at: usize) -> bool {
    at == bytes.len() || bytes[at] & 0xC0 != 0x80
}

fn char_len(lead: u8) -> usize {
    match lead {
        0..=0x7F => 1,
        0x80..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

/// A character of `[a-z0-9-_.]`, the class of the optional prefix after `||`.
fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

/// The first byte of a character that `^` accepts: not a letter, digit, space or `.%_-`.
fn is_separator(byte: u8) -> bool {
    if byte >= 0x80 {
        return true;
    }

    !(byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'.' | b'%' | b'_' | b'-'))
}

// ---- Shortcuts ----

/// urlfilter's `findShortcut`: the longest run of the pattern without `*`, `^` and `|`.
pub fn glob_shortcut(pattern: &str) -> &str {
    let mut shortcut = "";
    let mut rest = pattern;
    while !rest.is_empty() {
        let Some(at) = rest.find(['*', '^', '|']) else {
            if rest.len() > shortcut.len() {
                return rest;
            }

            break;
        };

        if at > shortcut.len() {
            shortcut = &rest[..at];
        }

        rest = &rest[at + 1..];
    }

    shortcut
}

/// urlfilter's `findRegexpShortcut` for a `/regex/` pattern, as the Go code computes it.
/// It is crude (an escape like `\b` leaves a letter behind), and the oracle shows that the
/// crude result decides which rules match, so it is reproduced exactly.
pub fn regex_shortcut(pattern: &str) -> String {
    let inner = &pattern[1..pattern.len() - 1];
    if inner.contains('?') {
        return String::new();
    }

    let mut chars: Vec<char> = "...".chars().chain(inner.chars()).collect();
    for (open, close) in [('{', '}'), ('(', ')'), ('[', ']')] {
        chars = replace_brackets(&chars, open, close);
    }

    chars = replace_class_text(&chars);

    let text: String = chars.into_iter().collect();
    let mut longest = "";
    for part in text.split(|c| "\\^$*+?.()|[]{}".contains(c)) {
        if part.len() > longest.len() {
            longest = part;
        }
    }

    longest.to_string()
}

/// Go: `([^\\])\<open>.*[^\\]\<close>` replaced by `$1...`, leftmost and greedy.
fn replace_brackets(chars: &[char], open: char, close: char) -> Vec<char> {
    let mut out = Vec::with_capacity(chars.len());
    let mut at = 0;
    while at < chars.len() {
        if chars[at] != '\\' && chars.get(at + 1) == Some(&open) {
            let end = (at + 3..chars.len())
                .rev()
                .find(|&j| chars[j] == close && chars[j - 1] != '\\');
            if let Some(end) = end {
                out.push(chars[at]);
                out.extend("...".chars());
                at = end + 1;

                continue;
            }
        }

        out.push(chars[at]);
        at += 1;
    }

    out
}

/// Go: `([^\\])\[a-zA-Z]` (the literal text `[a-zA-Z]`) replaced by `$1...`.
fn replace_class_text(chars: &[char]) -> Vec<char> {
    const CLASS: &str = "[a-zA-Z]";
    let class: Vec<char> = CLASS.chars().collect();
    let mut out = Vec::with_capacity(chars.len());
    let mut at = 0;
    while at < chars.len() {
        if chars[at] != '\\' && chars[at + 1..].starts_with(&class) {
            out.push(chars[at]);
            out.extend("...".chars());
            at += 1 + class.len();

            continue;
        }

        out.push(chars[at]);
        at += 1;
    }

    out
}

// ---- Go regex syntax ----

/// Translates the differences between Go's `regexp` syntax and the `regex` crate's.
///
/// - `\Q..\E` quotes, `\<` and `\>` are literals, `\_` and other punctuation escapes;
/// - `{` that does not start a valid `{n}`, `{n,}` or `{n,m}` (counts without leading
///   zeros) is a literal;
/// - octal escapes become hex literals, named captures become plain groups;
/// - `\d \w \s \b` are ASCII only, the `regex` crate's are Unicode;
/// - inside a class `[` and `&&` `~~` are literals;
/// - flags other than `i m s U` and lookaround groups are errors in Go;
/// - Go-only errors (unknown escapes, backreferences) stay errors in the `regex` crate.
pub fn translate_go_regex(source: &str) -> Result<String, PatternError> {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len() + 8);
    let mut at = 0;
    // Go does not allow stacked repetition operators (`a**`, `a*+`); `a*?` is lazy.
    let mut after_repeat = false;
    let mut lazy_taken = false;
    while at < chars.len() {
        let c = chars[at];
        let before = out.len();
        let next = match c {
            '\\' => translate_escape(&chars, at, &mut out, false)?,
            '[' => translate_class(&chars, at, &mut out)?,
            '(' => translate_group(&chars, at, &mut out)?,
            '{' => translate_brace(&chars, at, &mut out)?,
            c => {
                out.push(c);

                at + 1
            }
        };

        let repeats = matches!(c, '*' | '+' | '?') || (c == '{' && out[before..].starts_with('{'));
        if repeats && after_repeat {
            if c != '?' || lazy_taken {
                return Err(syntax_error("invalid nested repetition operator"));
            }

            lazy_taken = true;
        } else {
            after_repeat = repeats;
            lazy_taken = false;
        }

        at = next;
    }

    Ok(out)
}

fn syntax_error(message: &str) -> PatternError {
    PatternError::Regex(message.to_string())
}

fn push_escaped(out: &mut String, c: char) {
    if "\\.+*?()|[]{}^$#&-~".contains(c) {
        out.push('\\');
    }

    out.push(c);
}

/// Handles the escape at `chars[at]` and returns the index after it.
fn translate_escape(
    chars: &[char],
    at: usize,
    out: &mut String,
    in_class: bool,
) -> Result<usize, PatternError> {
    let Some(&c) = chars.get(at + 1) else {
        return Err(syntax_error("trailing backslash"));
    };

    match c {
        'Q' if !in_class => {
            let mut next = at + 2;
            while next < chars.len() {
                if chars[next] == '\\' && chars.get(next + 1) == Some(&'E') {
                    return Ok(next + 2);
                }

                push_escaped(out, chars[next]);
                next += 1;
            }

            Ok(next)
        }
        'E' => Err(syntax_error("stray \\E")),
        'd' | 'D' | 'w' | 'W' | 's' | 'S' => {
            let (set, negated) = match c.to_ascii_lowercase() {
                'd' => ("0-9", c == 'D'),
                'w' => ("0-9A-Za-z_", c == 'W'),
                _ => ("\\t\\n\\f\\r ", c == 'S'),
            };
            match (in_class, negated) {
                (false, false) => out.push_str(&format!("[{set}]")),
                (false, true) => out.push_str(&format!("[^{set}]")),
                (true, false) => out.push_str(set),
                (true, true) => out.push_str(&format!("[^{set}]")),
            }

            Ok(at + 2)
        }
        'b' | 'B' if !in_class => {
            out.push_str(&format!("(?-u:\\{c})"));

            Ok(at + 2)
        }
        '<' | '>' => {
            out.push(c);

            Ok(at + 2)
        }
        '0'..='7' => translate_octal(chars, at, out),
        'p' | 'P' | 'x' => {
            out.push('\\');
            out.push(c);
            let mut next = at + 2;
            if chars.get(next) == Some(&'{') {
                let close = chars[next..]
                    .iter()
                    .position(|&ch| ch == '}')
                    .ok_or_else(|| syntax_error("unclosed brace in escape"))?;
                out.extend(&chars[next..=next + close]);
                next += close + 1;
            } else if c == 'x' {
                let digits = chars[next..].iter().take(2).count();
                out.extend(&chars[next..next + digits]);
                next += digits;
            } else if let Some(&letter) = chars.get(next) {
                out.push(letter);
                next += 1;
            }

            Ok(next)
        }
        c if !c.is_ascii() => Err(syntax_error("escaped non-ASCII character")),
        c => {
            out.push('\\');
            out.push(c);

            Ok(at + 2)
        }
    }
}

/// Go's octal escape: `\0` or a non-zero digit followed by an octal digit, then up to two
/// more octal digits. A single non-zero digit is a backreference, which Go rejects.
fn translate_octal(chars: &[char], at: usize, out: &mut String) -> Result<usize, PatternError> {
    let digits: Vec<u32> = chars[at + 1..]
        .iter()
        .map_while(|c| c.to_digit(8))
        .take(3)
        .collect();
    if digits.len() == 1 && digits[0] != 0 {
        return Err(syntax_error("backreferences are not supported"));
    }

    let value = digits.iter().fold(0, |value, digit| value * 8 + digit);
    out.push_str(&format!("\\x{{{value:X}}}"));

    Ok(at + 1 + digits.len())
}

fn translate_class(chars: &[char], start: usize, out: &mut String) -> Result<usize, PatternError> {
    out.push('[');
    let mut at = start + 1;
    if chars.get(at) == Some(&'^') {
        out.push('^');
        at += 1;
    }

    if chars.get(at) == Some(&']') {
        out.push_str("\\]");
        at += 1;
    }

    while at < chars.len() {
        match chars[at] {
            ']' => {
                out.push(']');

                return Ok(at + 1);
            }
            '[' => {
                let posix_end = (chars.get(at + 1) == Some(&':'))
                    .then(|| chars[at + 2..].windows(2).position(|w| w == [':', ']']))
                    .flatten();
                match posix_end {
                    Some(len) => {
                        out.extend(&chars[at..at + 2 + len + 2]);
                        at += 2 + len + 2;
                    }
                    None => {
                        out.push_str("\\[");
                        at += 1;
                    }
                }
            }
            '\\' => at = translate_escape(chars, at, out, true)?,
            c @ ('&' | '~') => {
                out.push('\\');
                out.push(c);
                at += 1;
            }
            c => {
                out.push(c);
                at += 1;
            }
        }
    }

    Err(syntax_error("unclosed character class"))
}

fn translate_group(chars: &[char], at: usize, out: &mut String) -> Result<usize, PatternError> {
    if chars.get(at + 1) != Some(&'?') {
        out.push('(');

        return Ok(at + 1);
    }

    let rest: String = chars[at + 2..].iter().collect();
    let name_start = rest.strip_prefix("P<").or_else(|| rest.strip_prefix('<'));
    if let Some(name_start) = name_start {
        let name_end = name_start
            .find('>')
            .ok_or_else(|| syntax_error("unclosed group name"))?;
        let name = &name_start[..name_end];
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(syntax_error("invalid named capture"));
        }

        // Go accepts numeric and repeated names, which the regex crate rejects; nothing
        // can refer to a capture here, so a plain group is equivalent.
        out.push_str("(?:");
        let header = &rest[..rest.len() - name_start.len() + name_end + 1];

        return Ok(at + 2 + header.chars().count());
    }

    let flags_end = rest
        .find([')', ':'])
        .ok_or_else(|| syntax_error("unclosed group flags"))?;
    let flags = &rest[..flags_end];
    if !flags.chars().all(|c| "imsU-".contains(c)) {
        return Err(syntax_error("unsupported group syntax"));
    }

    out.push_str("(?");
    out.push_str(flags);

    Ok(at + 2 + flags.chars().count())
}

/// A `{` starts a repetition only as `{n}`, `{n,}` or `{n,m}`; otherwise it is literal.
fn translate_brace(chars: &[char], at: usize, out: &mut String) -> Result<usize, PatternError> {
    let rest: String = chars[at + 1..].iter().collect();
    let Some(close) = rest.find('}') else {
        out.push_str("\\{");

        return Ok(at + 1);
    };

    let body = &rest[..close];
    let (low, high) = match body.split_once(',') {
        Some((low, high)) => (low, Some(high)),
        None => (body, None),
    };
    // Go's parseInt: digits without a leading zero.
    let digits = |text: &str| {
        !text.is_empty()
            && text.bytes().all(|b| b.is_ascii_digit())
            && (text.len() == 1 || !text.starts_with('0'))
    };
    let valid = digits(low) && high.is_none_or(|high| high.is_empty() || digits(high));
    if !valid {
        out.push_str("\\{");

        return Ok(at + 1);
    }

    for number in [Some(low), high]
        .into_iter()
        .flatten()
        .filter(|text| digits(text))
    {
        if number.parse::<u32>().map_or(true, |n| n > MAX_REPEAT) {
            return Err(syntax_error("repeat count too large"));
        }
    }

    out.push('{');
    out.push_str(body);
    out.push('}');

    Ok(at + 2 + body.chars().count())
}

// ---- Fast-path candidates ----

/// Calls `f` with every substring of `input` that a `||d^` rule can match: it starts at the
/// beginning or just after a `.` when everything before is in `[a-z0-9-_.]`, and ends at
/// the end or just before a separator character.
pub fn for_each_suffix_candidate(input: &str, f: &mut dyn FnMut(&str)) {
    let bytes = input.as_bytes();
    for_each_end(input, 0, f);
    for (at, &byte) in bytes.iter().enumerate() {
        if !is_name_byte(byte) {
            break;
        }

        if byte == b'.' && at >= 1 {
            for_each_end(input, at + 1, f);
        }
    }
}

/// Like [`for_each_suffix_candidate`] for `|d^` rules, which start at the beginning only.
pub fn for_each_exact_candidate(input: &str, f: &mut dyn FnMut(&str)) {
    for_each_end(input, 0, f);
}

/// The proper suffixes after a `.` that run to the end of `input` (RPZ `*.d` rules).
pub fn for_each_strict_suffix_candidate(input: &str, f: &mut dyn FnMut(&str)) {
    for (at, byte) in input.bytes().enumerate() {
        if byte == b'.' && at + 1 < input.len() {
            f(&input[at + 1..]);
        }
    }
}

fn for_each_end(input: &str, start: usize, f: &mut dyn FnMut(&str)) {
    let bytes = input.as_bytes();
    for end in start + 1..=bytes.len() {
        if end == bytes.len() || (bytes[end] & 0xC0 != 0x80 && is_separator(bytes[end])) {
            f(&input[start..end]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &str, host: &str) -> bool {
        let matcher =
            Matcher::compile(pattern).unwrap_or_else(|error| panic!("{pattern}: {error}"));
        let url = format!("http://{host}");

        matcher.is_match(host, &url)
    }

    type Enumerate = fn(&str, &mut dyn FnMut(&str));

    fn candidates(enumerate: Enumerate, input: &str) -> Vec<String> {
        let mut found = Vec::new();
        enumerate(input, &mut |candidate| found.push(candidate.to_string()));
        found.sort();

        found
    }

    fn suffixes(input: &str) -> Vec<String> {
        candidates(for_each_suffix_candidate, input)
    }

    fn exacts(input: &str) -> Vec<String> {
        candidates(for_each_exact_candidate, input)
    }

    fn strict(input: &str) -> Vec<String> {
        candidates(for_each_strict_suffix_candidate, input)
    }

    fn sorted(mut expected: Vec<&str>) -> Vec<String> {
        expected.sort();

        expected.into_iter().map(String::from).collect()
    }

    #[test]
    fn subdomain_anchor_and_separator() {
        assert!(matches("||ads.example^", "ads.example"));
        assert!(matches("||ads.example^", "www.ads.example"));
        assert!(matches("||ads.example^", "a.b.ads.example"));
        assert!(!matches("||ads.example^", "xads.example"));
        assert!(!matches("||ads.example^", "ads.example.org"));
        assert!(!matches("||ads.example^", "ads.examples"));
    }

    #[test]
    fn without_a_separator_the_rule_matches_longer_names() {
        assert!(matches("||ads.example", "ads.example.org"));
        assert!(matches("||ads.example", "ads.examples"));
        assert!(!matches("||ads.example", "xads.example"));
    }

    #[test]
    fn exact_anchor() {
        assert!(matches("|ads.example^", "ads.example"));
        assert!(!matches("|ads.example^", "www.ads.example"));
        assert!(matches("|ads", "ads.example"));
        assert!(!matches("|ads", "xads"));
    }

    #[test]
    fn end_anchor() {
        assert!(matches("example|", "ads.example"));
        assert!(!matches("example|", "ads.example.org"));
        assert!(matches("|ads.example|", "ads.example"));
        assert!(!matches("|ads.example|", "x.ads.example"));
    }

    #[test]
    fn unanchored_pattern_is_a_substring() {
        assert!(matches("ads", "x-ads-y.example"));
        assert!(matches(".adonweb.ru^", "www.adonweb.ru"));
        assert!(!matches(".adonweb.ru^", "adonweb.ru"));
    }

    #[test]
    fn wildcards() {
        assert!(matches("||ad*.example^", "ad123.example"));
        assert!(matches("||ad*.example^", "www.ad.example"));
        assert!(matches("||ad*.example^", "ads.x.example"));
        assert!(!matches("||ad*.example^", "ad.example.org"));
        assert!(matches("*.leading.example", "x.leading.example"));
        assert!(!matches("*.leading.example", "leading.example"));
        assert!(matches("||*.star-first.example^", "sub.star-first.example"));
        assert!(!matches("||*.star-first.example^", "star-first.example"));
        assert!(matches("*", "anything"));
        assert!(matches("||", "anything"));
        assert!(matches("|", "anything"));
    }

    #[test]
    fn a_pipe_inside_the_pattern_is_literal() {
        assert!(matches("||mid|pipe.example^", "mid|pipe.example"));
        assert!(!matches("||mid|pipe.example^", "mid.pipe.example"));
    }

    #[test]
    fn regex_metacharacters_in_a_pattern_are_literal() {
        assert!(matches("a.b", "a.b"));
        assert!(!matches("a.b", "axb"));
        assert!(matches("a+b", "a+b"));
        assert!(matches("a(b)c", "a(b)c"));
        assert!(matches("a[b]c", "a[b]c"));
        assert!(matches("a{2}", "a{2}"));
        assert!(matches("a$b", "a$b"));
        assert!(matches("a?b", "a?b"));
        assert!(matches("a\\b", "a\\b"));
        assert!(!matches(
            "esc-dollar\\$sign.example^",
            "esc-dollar$sign.example"
        ));
    }

    #[test]
    fn separator_class() {
        // `^` is anything but a letter, digit or one of `.%_-`, or the end.
        assert!(matches("||a^", "a"));
        assert!(matches("||a^", "a:b"));
        assert!(!matches("||a^", "a b"));
        assert!(matches("||a^", "a/b"));
        assert!(!matches("||a^", "a.b"));
        assert!(!matches("||a^", "a-b"));
        assert!(!matches("||a^", "a_b"));
        assert!(!matches("||a^", "a%b"));
        assert!(!matches("||a^", "a1"));
        assert!(matches("||a^", "a\u{e9}"));
        assert!(matches("a^b", "a:b"));
        assert!(!matches("a^b", "ab"));
        assert!(matches("^", "x"));
    }

    #[test]
    fn separator_matches_ipv6_colons() {
        assert!(matches("|dead^", "dead:beef::1"));
        assert!(matches("||dead^", "dead:beef::1"));
        assert!(!matches("||beef^", "dead:beef::1"));
        assert!(!matches("|beef^", "dead:beef::1"));
        assert!(matches("||2001:db8::^", "2001:db8::"));
        assert!(matches("||2001:db8:3::^", "2001:db8:3::"));
        assert!(!matches("||2001:db8:3::^", "2001:db8:3::1"));
        assert!(!matches("||dead^", "xdead:beef::1"));
    }

    #[test]
    fn dots_are_not_separators_in_ip_text() {
        assert!(matches("||1.2.3.4^", "1.2.3.4"));
        assert!(!matches("||1.2.3.4^", "1.2.3.45"));
        assert!(!matches("||1.2.3.4^", "11.2.3.4"));
        assert!(matches("||1.2.3.4^", "9.1.2.3.4"));
    }

    #[test]
    fn ipv4_mapped_ipv6_text() {
        assert!(matches("||::ffff:1.2.3.4^", "::ffff:1.2.3.4"));
        assert!(!matches("||1.2.3.4^", "::ffff:1.2.3.4"));
        assert!(matches("|::ffff:1.2.3.4^", "::ffff:1.2.3.4"));
    }

    #[test]
    fn subdomain_prefix_group_only_spans_name_characters() {
        // `||` allows `([a-z0-9-_.]+\.)?` before the pattern, so a colon blocks it.
        assert!(matches("||b^", "a.b"));
        assert!(!matches("||b^", "a:b"));
        assert!(!matches("||b^", ".b"));
        assert!(matches("||b^", "..b"));
        assert!(matches("||b^", "a_x-1.b"));
    }

    #[test]
    fn pattern_with_url_prefix_matches_the_url() {
        assert!(matches("://scheme-less.example^", "scheme-less.example"));
        assert!(!matches(
            "://scheme-less.example^",
            "www.scheme-less.example"
        ));
        assert!(matches("http://url-c.example^", "url-c.example"));
        assert!(!matches("http://url-c.example^", "sub.url-c.example"));
        assert!(!matches("|http://url-b.example", "url-b.example"));
    }

    #[test]
    fn patterns_with_a_path_never_match_a_bare_host() {
        assert!(!matches("||path.example/ads^", "path.example"));
        assert!(!matches("/ads/foo.", "ads"));
        assert!(!matches("||url-f.example/", "url-f.example"));
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(matches("||UPPER.example^", "upper.example"));
        assert!(matches("||upper.example^", "upper.example"));
        assert!(matches("\u{dc}N\u{cf}", "\u{fc}n\u{ef}"));
    }

    #[test]
    fn shortcut_is_the_longest_run_without_specials() {
        assert_eq!(glob_shortcut("||ads.example^"), "ads.example");
        assert_eq!(glob_shortcut("||ad*.example^"), ".example");
        assert_eq!(glob_shortcut("||a*b^"), "a");
        assert_eq!(glob_shortcut("*"), "");
        assert_eq!(glob_shortcut("abc*de"), "abc");
        assert_eq!(glob_shortcut("ab*cd*efg"), "efg");
    }

    #[test]
    fn regex_shortcut_follows_the_go_implementation() {
        assert_eq!(regex_shortcut("/tracker-\\d{2,3}\\.example$/"), "tracker-");
        assert_eq!(regex_shortcut("/^ad[sx]?[0-9]+\\./"), "");
        assert_eq!(regex_shortcut("/(?i)UPPER-CI\\.example/"), "");
        assert_eq!(regex_shortcut("/\\bword\\b/"), "bword");
        assert_eq!(
            regex_shortcut("/^\\Qquoted.[literal]\\E\\.example$/"),
            "Qquoted"
        );
        assert_eq!(
            regex_shortcut("/^regex-host[0-9]+\\.example$/"),
            "regex-host"
        );
        assert_eq!(
            regex_shortcut("/^94\\.242\\.247\\.(2[0-9]|3[0-2]):/"),
            "242"
        );
        assert_eq!(regex_shortcut("/ab/"), "ab");
        assert_eq!(regex_shortcut("/a|b/"), "a");
    }

    #[test]
    fn a_shortcut_that_is_not_in_the_url_rejects_the_rule() {
        // urlfilter checks the shortcut before the pattern, which makes `\b` rules
        // unmatchable; the oracle decides, so this is kept.
        assert!(!matches("/\\bword\\b/", "word.test"));
        assert!(matches("/word\\b/", "word.test"));
    }

    #[test]
    fn regex_rules() {
        assert!(matches("/^ad[sx]?[0-9]+\\./", "ads22.example"));
        assert!(!matches("/^ad[sx]?[0-9]+\\./", "xad1.example"));
        assert!(matches(
            "/tracker-\\d{2,3}\\.example$/",
            "tracker-12.example"
        ));
        assert!(!matches(
            "/tracker-\\d{2,3}\\.example$/",
            "tracker-1.example"
        ));
        assert!(matches("/(?i)UPPER-CI\\.example/", "upper-ci.example"));
        assert!(matches("/UPPER-CS\\.example/", "upper-cs.example"));
        assert!(matches("//", "x"));
        assert!(matches("/.*/", "x"));
    }

    #[test]
    fn go_syntax_translation() {
        let translated = |source: &str| translate_go_regex(source).unwrap();
        assert_eq!(translated("a\\_b"), "a\\_b");
        assert_eq!(translated("a\\<b\\>"), "a<b>");
        assert_eq!(translated("\\Qa.b[\\E"), "a\\.b\\[");
        assert_eq!(translated("\\Qunterminated.["), "unterminated\\.\\[");
        assert_eq!(translated("a{"), "a\\{");
        assert_eq!(translated("a{,3}"), "a\\{,3}");
        assert_eq!(translated("a{x}"), "a\\{x}");
        assert_eq!(translated("a{2,3}"), "a{2,3}");
        assert_eq!(translated("a{2,}"), "a{2,}");
        assert_eq!(
            translated("\\d\\D\\w\\W\\s\\S"),
            "[0-9][^0-9][0-9A-Za-z_][^0-9A-Za-z_][\\t\\n\\f\\r ][^\\t\\n\\f\\r ]"
        );
        assert_eq!(translated("\\b\\B"), "(?-u:\\b)(?-u:\\B)");
        assert_eq!(translated("[\\d_]"), "[0-9_]");
        assert_eq!(translated("[^\\D]"), "[^[^0-9]]");
        assert_eq!(translated("[a&&b]"), "[a\\&\\&b]");
        assert_eq!(translated("[a[b]"), "[a\\[b]");
        assert_eq!(translated("[[:alpha:]x]"), "[[:alpha:]x]");
        assert_eq!(translated("\\pL+\\p{Greek}"), "\\pL+\\p{Greek}");
        assert_eq!(translated("\\x{4e2d}\\x61"), "\\x{4e2d}\\x61");
        assert_eq!(translated("(?i)a(?:b)(?P<n>c)"), "(?i)a(?:b)(?:c)");
        assert_eq!(translated("a.b"), "a.b");
    }

    #[test]
    fn octal_escapes_become_hex_literals() {
        let translated = |source: &str| translate_go_regex(source).unwrap();
        assert_eq!(translated("\\141"), "\\x{61}");
        assert_eq!(translated("\\0"), "\\x{0}");
        assert_eq!(translated("\\012"), "\\x{A}");
        assert_eq!(translated("\\1411"), "\\x{61}1");
        assert_eq!(translated("\\777"), "\\x{1FF}");
        assert!(translate_go_regex("\\18").is_err());
    }

    #[test]
    fn named_captures_become_plain_groups() {
        let translated = |source: &str| translate_go_regex(source).unwrap();
        assert_eq!(translated("(?P<1>a)"), "(?:a)");
        assert_eq!(translated("(?P<a>x)(?P<a>y)"), "(?:x)(?:y)");
        assert_eq!(translated("(?<n_1>z)"), "(?:z)");
        for source in [
            "(?P<bad-name>x)",
            "(?P<>x)",
            "(?<>x)",
            "(?P<\u{e9}>x)",
            "(?P<open",
            "(?<=look)",
            "(?<!look)",
        ] {
            assert!(translate_go_regex(source).is_err(), "{source} should fail");
        }
    }

    #[test]
    fn repetition_counts_follow_go_syntax() {
        let translated = |source: &str| translate_go_regex(source).unwrap();
        assert_eq!(translated("a{01}"), "a\\{01}");
        assert_eq!(translated("a{1,02}"), "a\\{1,02}");
        assert_eq!(translated("a{00}"), "a\\{00}");
        assert_eq!(translated("a{0}"), "a{0}");
        assert_eq!(translated("a{10,20}"), "a{10,20}");
        assert_eq!(translated("a{0,}"), "a{0,}");
        assert!(translate_go_regex("a{1001}").is_err());
    }

    #[test]
    fn go_octal_names_and_counts_match_like_go() {
        assert!(matches("/^(?:\\141ds)\\.example$/", "ads.example"));
        assert!(matches("/^[\\141-\\143]x\\.example$/", "bx.example"));
        assert!(matches("/^\\1411\\.example$/", "a1.example"));
        assert!(matches("/^(?P<1>n)(?P<1>m)\\.example$/", "nm.example"));
        assert!(matches("/^lead{01}\\.example$/", "lead{01}.example"));
        assert!(!matches("/^lead{01}\\.example$/", "lead.example"));
        assert!(matches("/^cc{1,2}\\.example$/", "ccc.example"));
    }

    #[test]
    fn syntax_go_rejects_is_rejected() {
        for source in [
            "(?x)a b",
            "(?=look)",
            "(?<=look)",
            "x*+",
            "[",
            "(unclosed",
            "\\y",
            "\\1",
            "\\8",
            "\\Z",
            "(?P<bad-name>x)",
            "(?i",
            "\\\u{e9}",
        ] {
            assert!(
                Matcher::compile(&format!("/{source}/")).is_err(),
                "{source} should not compile"
            );
        }
    }

    #[test]
    fn go_regex_syntax_matches_like_go() {
        assert!(matches("/^brace{\\.example$/", "brace{.example"));
        assert!(matches("/^lit\\{x\\}\\.example$/", "lit{x}.example"));
        assert!(matches(
            "/^under\\_score\\.example$/",
            "under_score.example"
        ));
        assert!(matches(
            "/\\pL+\\.latin-class\\.example/",
            "abc.latin-class.example"
        ));
        assert!(!matches(
            "/\\pL+\\.latin-class\\.example/",
            "ab1.latin-class.example"
        ));
        assert!(matches(
            "/^\\p{Latin}+\\.script\\.example$/",
            "abc.script.example"
        ));
        assert!(matches(
            "/\\p{Greek}\\.greek\\.example/",
            "\u{3b1}.greek.example"
        ));
        assert!(matches(
            "/^[[:alpha:]]+\\.posix\\.example$/",
            "abc.posix.example"
        ));
        assert!(matches("/^\\x61bc\\.hex\\.example$/", "abc.hex.example"));
        assert!(matches(
            "/^[\\w-]+\\.word-class\\.example$/",
            "ab-1.word-class.example"
        ));
        assert!(matches("/^[^\\D]+\\.negd\\.example$/", "123.negd.example"));
        assert!(!matches("/^[^\\D]+\\.negd\\.example$/", "abc.negd.example"));
        assert!(matches("/(?s)dot.all\\.example/", "dotxall.example"));
        assert!(matches("/(?U)lazy.+\\.example/", "lazyabc.example"));
        assert!(matches("/^\\x{4e2d}$/", "\u{4e2d}"));
        // `\d` and `\w` are ASCII only in Go.
        assert!(!matches(
            "/^\\d+\\.digits\\.example$/",
            "\u{661}\u{662}.digits.example"
        ));
        assert!(!matches("/^\\w+\\.w\\.example$/", "\u{e9}.w.example"));
    }

    #[test]
    fn suffix_candidates_for_host_names() {
        assert_eq!(suffixes("a.b.c"), sorted(vec!["a.b.c", "b.c", "c"]));
        assert_eq!(suffixes("c"), ["c"]);
        assert_eq!(suffixes(""), Vec::<String>::new());
        assert_eq!(suffixes("a..b"), sorted(vec!["a..b", ".b", "b"]));
        assert_eq!(suffixes(".a"), [".a"]);
    }

    #[test]
    fn suffix_candidates_stop_at_characters_outside_the_name_class() {
        // `a:b.c`: the prefix group cannot cross the colon, but the colon ends a candidate.
        assert_eq!(suffixes("a:b.c"), sorted(vec!["a", "a:b.c"]));
        assert_eq!(
            suffixes("dead:beef::1"),
            sorted(vec!["dead", "dead:beef", "dead:beef:", "dead:beef::1"])
        );
        assert_eq!(suffixes("x.y:z"), sorted(vec!["x.y", "x.y:z", "y", "y:z"]));
    }

    #[test]
    fn ends_include_every_separator_position() {
        assert_eq!(suffixes("a/b"), sorted(vec!["a", "a/b"]));
        assert_eq!(suffixes("a b"), ["a b"]);
        assert_eq!(suffixes("a\u{e9}"), sorted(vec!["a", "a\u{e9}"]));
    }

    #[test]
    fn exact_candidates_start_at_the_beginning_only() {
        assert_eq!(exacts("a.b.c"), ["a.b.c"]);
        assert_eq!(
            exacts("dead:beef::1"),
            sorted(vec!["dead", "dead:beef", "dead:beef:", "dead:beef::1"])
        );
        assert_eq!(exacts(""), Vec::<String>::new());
    }

    #[test]
    fn strict_suffix_candidates_exclude_the_whole_name() {
        assert_eq!(strict("a.b.c"), sorted(vec!["b.c", "c"]));
        assert_eq!(strict("c"), Vec::<String>::new());
        assert_eq!(strict("a."), Vec::<String>::new());
    }

    /// The regular expression a non-regex pattern stands for: metacharacters are escaped,
    /// `*` is `.*`, `^` the separator class, a leading `||` the URL start with an optional
    /// subdomain prefix, a leading `|` the start, a trailing `|` the end.
    fn reference_regex(pattern: &str) -> String {
        if matches!(pattern, "||" | "|" | "*" | "") {
            return ".*".to_string();
        }

        let escaped: String = pattern
            .chars()
            .flat_map(|c| {
                let escape = ".+?${}()[]/\\".contains(c);

                escape.then_some('\\').into_iter().chain([c])
            })
            .collect();
        let prefix_len = if escaped.starts_with("||") { 2 } else { 1 };
        let mut body = escaped;
        if body.len() > 1 {
            let middle = body[prefix_len..body.len() - 1].replace('|', "\\|");
            body = format!(
                "{}{}{}",
                &body[..prefix_len],
                middle,
                &body[body.len() - 1..]
            );
        }

        let body = body
            .replace('*', ".*")
            .replace('^', "([^ a-zA-Z0-9.%_-]|$)");
        let body = if let Some(rest) = body.strip_prefix("||") {
            format!("^(http|https|ws|wss)://([a-z0-9-_.]+\\.)?{rest}")
        } else if let Some(rest) = body.strip_prefix('|') {
            format!("^{rest}")
        } else {
            body
        };

        match body.strip_suffix('|') {
            Some(rest) => format!("{rest}$"),
            None => body,
        }
    }

    #[test]
    fn globs_match_like_the_regex_urlfilter_builds() {
        let anchors = ["||", "|", ""];
        let bodies = [
            "a", "a.b", "a*b", "a^", "^a", "a^b", "x|y", "a.", "*a", "a*", "a*b*c", "a**b", "a:b",
            "dead", "1.2.3", "a-b", "a_b", "a/b", "a$b", "a\\b", "a%b",
        ];
        let ends = ["", "^", "|", "^|"];
        let inputs = [
            "",
            "a",
            "b",
            "ab",
            "aab",
            "a.b",
            "a-b",
            "a_b",
            "a:b",
            "a b",
            "a/b",
            "a%b",
            "x.a",
            "x.a.b",
            "a.b.c",
            "b.a",
            "a.",
            "a..b",
            "..a",
            "x-1.a",
            "xa",
            "ax",
            "x|y",
            "a|b",
            "dead:beef::1",
            "xdead:beef::1",
            "1.2.3.4",
            "11.2.3.4",
            "a$b",
            "a\\b",
            "a1b",
            "aXb",
            "a.b.c.d",
            "a:b.c",
            "c.a:b",
            "\u{e9}a",
            "a\u{e9}",
            "a*b",
        ];
        let mut checked = 0;
        for anchor in anchors {
            for body in bodies {
                for end in ends {
                    let pattern = format!("{anchor}{body}{end}");
                    let reference = regex::RegexBuilder::new(&reference_regex(&pattern))
                        .case_insensitive(true)
                        .build()
                        .unwrap_or_else(|error| panic!("{pattern}: {error}"));
                    for input in inputs {
                        let url = format!("http://{input}");
                        let subject = if uses_url(&pattern) { &url } else { input };
                        assert_eq!(
                            matches(&pattern, input),
                            reference.is_match(subject),
                            "pattern {pattern:?} input {input:?}"
                        );
                        checked += 1;
                    }
                }
            }
        }

        assert!(checked > 9_000);
    }

    #[test]
    fn fast_path_candidates_agree_with_the_matcher_for_every_substring() {
        // The fast path must find exactly the names a slow `||d^` / `|d^` rule matches.
        let inputs = [
            "a.b.c",
            "x",
            "a..b",
            ".a",
            "a:b.c",
            "dead:beef::1",
            "1.2.3.4",
            "::ffff:1.2.3.4",
            "a_b-c.d",
            "a b",
            "a/b.c",
            "a.b/c.d",
            "xn--a.b",
            "a%b.c",
            "x.y:z",
        ];
        for input in inputs {
            let sub = suffixes(input);
            let exact = exacts(input);
            for from in 0..input.len() {
                for to in from + 1..=input.len() {
                    let part = &input[from..to];
                    let sub_rule = format!("||{part}^");
                    assert_eq!(
                        matches(&sub_rule, input),
                        sub.iter().any(|c| c == part),
                        "{sub_rule} vs {input}"
                    );

                    let exact_rule = format!("|{part}^");
                    assert_eq!(
                        matches(&exact_rule, input),
                        exact.iter().any(|c| c == part),
                        "{exact_rule} vs {input}"
                    );
                }
            }
        }
    }
}
