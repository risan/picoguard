//! What a request is checked against when a password is set: the user and password, the
//! signed session cookie, the per-address failure table, and the one slot in which a password
//! hash runs.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use hyper::header::{self, HeaderMap};
use ring::hmac;
use ring::rand::SystemRandom;
use tokio::sync::Semaphore;

use crate::config::WebConfig;
use crate::password::PasswordHash;

const SESSION_COOKIE: &str = "picoguard_session";
const SESSION_SECONDS: u64 = 30 * 24 * 60 * 60;
pub(super) const SIGNED_OUT_COOKIE: &str =
    "picoguard_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict";

const LIMITED_AFTER_FAILURES: usize = 5;
/// Five failures within this span lock an address until this long after the last one.
const LIMIT_WINDOW_SECONDS: u32 = 15 * 60;
const LIMITER_ADDRESSES: usize = 64;

pub(super) enum Attempt<'a> {
    /// The credentials of an `Authorization: Basic` header, still encoded.
    Basic(&'a str),
    Form {
        user: &'a str,
        password: &'a str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Check {
    Accepted,
    Refused,
    Limited,
}

pub(super) struct Auth {
    password: Password,
    sessions: Sessions,
    limiter: Arc<Mutex<Limiter>>,
    /// One permit: a single password hash runs at a time, so hashing holds at most one core
    /// and the failure count of an address is exact under concurrent attempts.
    hashing: Arc<Semaphore>,
}

enum Password {
    /// `base64(user ":" password)`, as a Basic header carries it.
    Plain(Credentials),
    Hashed {
        user: Credentials,
        hash: PasswordHash,
        /// Filled by the first right answer, so a script repeating it skips the slow hash.
        known: Arc<OnceLock<Credentials>>,
    },
}

impl Auth {
    /// `None` when no password is configured.
    pub(super) fn new(web: &WebConfig) -> Result<Option<Auth>, String> {
        let (password, key_material) = match (&web.user, &web.password, &web.password_hash) {
            (Some(user), Some(password), _) => (
                Password::Plain(Credentials::new(&base64(
                    format!("{user}:{password}").as_bytes(),
                ))?),
                format!("picoguard session v1:plain:{user}:{password}"),
            ),

            (Some(user), None, Some(hash)) => (
                Password::Hashed {
                    user: Credentials::new(user)?,
                    hash: hash.clone(),
                    known: Arc::new(OnceLock::new()),
                },
                format!("picoguard session v1:hash:{user}:{hash}"),
            ),

            _ => {
                return Ok(None);
            }
        };

        Ok(Some(Auth {
            password,
            sessions: Sessions {
                key: hmac::Key::new(hmac::HMAC_SHA256, key_material.as_bytes()),
            },
            limiter: Arc::new(Mutex::new(Limiter::new(Instant::now()))),
            hashing: Arc::new(Semaphore::new(1)),
        }))
    }

    /// Whether any `Cookie` header carries a valid, unexpired session; `now` is Unix seconds.
    pub(super) fn has_session(&self, headers: &HeaderMap, now: u64) -> bool {
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .filter(|(name, _)| *name == SESSION_COOKIE)
            .any(|(_, token)| self.sessions.accepts(token, now))
    }

    pub(super) fn session_cookie(&self, now: u64) -> String {
        format!(
            "{SESSION_COOKIE}={}; Max-Age={SESSION_SECONDS}; Path=/; HttpOnly; SameSite=Strict",
            self.sessions.token(now + SESSION_SECONDS)
        )
    }

    /// A password check. A limited address is refused before any comparison.
    pub(super) async fn check(&self, peer: IpAddr, attempt: Attempt<'_>) -> Check {
        let peer = peer.to_canonical();
        if self
            .limiter
            .lock()
            .unwrap()
            .is_limited(peer, Instant::now())
        {
            return Check::Limited;
        }

        match &self.password {
            Password::Plain(expected) => {
                let accepted = attempt
                    .encoded()
                    .is_some_and(|sent| expected.accepts(&sent));

                self.settle(peer, accepted)
            }

            Password::Hashed { user, hash, known } => {
                let is_known = attempt
                    .encoded()
                    .is_some_and(|sent| known.get().is_some_and(|known| known.accepts(&sent)));
                if is_known {
                    return self.settle(peer, true);
                }

                let Some((sent_user, password)) = attempt.decoded() else {
                    return self.settle(peer, false);
                };

                let is_user = std::str::from_utf8(&sent_user).is_ok_and(|sent| user.accepts(sent));
                let sent = Sent {
                    is_user,
                    user: sent_user,
                    password,
                };

                self.check_hash(peer, sent, hash.clone(), Arc::clone(known))
                    .await
            }
        }
    }

    /// Runs the hash on a blocking thread, since the runtime thread also answers DNS. The
    /// closure records the outcome before it lets the permit go, so the next waiter sees it,
    /// and a request dropped mid-hash still has its failure counted.
    async fn check_hash(
        &self,
        peer: IpAddr,
        sent: Sent,
        hash: PasswordHash,
        known: Arc<OnceLock<Credentials>>,
    ) -> Check {
        let permit = Arc::clone(&self.hashing)
            .acquire_owned()
            .await
            .expect("the hashing semaphore is never closed");
        if self
            .limiter
            .lock()
            .unwrap()
            .is_limited(peer, Instant::now())
        {
            return Check::Limited;
        }

        let limiter = Arc::clone(&self.limiter);
        let checked = tokio::task::spawn_blocking(move || {
            let accepted = hash.verify(&sent.password) && sent.is_user;

            let mut limiter = limiter.lock().unwrap();
            if accepted {
                limiter.clear(peer);
                let pair = [&sent.user[..], b":", &sent.password].concat();
                if let Ok(credentials) = Credentials::new(&base64(&pair)) {
                    let _ = known.set(credentials);
                }
            } else {
                limiter.record_failure(peer, Instant::now());
            }
            drop(limiter);
            drop(permit);

            accepted
        })
        .await;

        match checked {
            Ok(true) => Check::Accepted,
            Ok(false) | Err(_) => Check::Refused,
        }
    }

    /// Records the outcome of a check that needed no hash.
    fn settle(&self, peer: IpAddr, accepted: bool) -> Check {
        let mut limiter = self.limiter.lock().unwrap();

        if accepted {
            limiter.clear(peer);

            return Check::Accepted;
        }

        limiter.record_failure(peer, Instant::now());

        Check::Refused
    }
}

/// A decoded attempt, moved to the thread that hashes it.
struct Sent {
    is_user: bool,
    user: Vec<u8>,
    password: Vec<u8>,
}

impl Attempt<'_> {
    /// `base64(user ":" password)`, the form a Basic header carries. `None` for a form user
    /// with a `:`: user `admin:a` with password `b` would equal user `admin` with password
    /// `a:b`.
    fn encoded(&self) -> Option<String> {
        match self {
            Attempt::Basic(sent) => Some(sent.to_string()),

            Attempt::Form { user, .. } if user.contains(':') => None,

            Attempt::Form { user, password } => {
                Some(base64(format!("{user}:{password}").as_bytes()))
            }
        }
    }

    /// The user and the password. RFC 7617 splits Basic credentials at the first `:`. `None`
    /// for a Basic header that does not decode or has no `:`.
    fn decoded(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        match self {
            Attempt::Basic(sent) => {
                let decoded = base64_decode(sent)?;
                let colon = decoded.iter().position(|byte| *byte == b':')?;

                Some((decoded[..colon].to_vec(), decoded[colon + 1..].to_vec()))
            }

            Attempt::Form { user, password } => {
                Some((user.as_bytes().to_vec(), password.as_bytes().to_vec()))
            }
        }
    }
}

/// Signs session tokens `<expiry>.<tag>`: the expiry in Unix seconds, and the HMAC-SHA256 of
/// those digits in lowercase hex. The key comes from the config, so a token outlives a restart
/// with nothing on disk, and a new user, password or hash ends every token.
struct Sessions {
    key: hmac::Key,
}

impl Sessions {
    fn token(&self, expiry: u64) -> String {
        let expiry = expiry.to_string();
        let tag = hmac::sign(&self.key, expiry.as_bytes());

        let mut token = expiry;
        token.push('.');
        for byte in tag.as_ref() {
            token.push_str(&format!("{byte:02x}"));
        }

        token
    }

    fn accepts(&self, token: &str, now: u64) -> bool {
        let Some((expiry, tag)) = token.split_once('.') else {
            return false;
        };
        let Some(tag) = lowercase_hex::<32>(tag) else {
            return false;
        };

        if hmac::verify(&self.key, expiry.as_bytes(), &tag).is_err() {
            return false;
        }

        expiry.bytes().all(|digit| digit.is_ascii_digit())
            && expiry.parse::<u64>().is_ok_and(|expiry| now < expiry)
    }
}

fn lowercase_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };

    if text.len() != N * 2 {
        return None;
    }

    let mut bytes = [0; N];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
        *byte = digit(pair[0])? << 4 | digit(pair[1])?;
    }

    Some(bytes)
}

/// The newest failed password checks per address, in a table that is allocated once.
struct Limiter {
    start: Instant,
    entries: Vec<Strikes>,
}

struct Strikes {
    ip: IpAddr,
    /// Seconds since `Limiter::start`, oldest first; only the first `count` are set.
    failures: [u32; LIMITED_AFTER_FAILURES],
    count: u8,
}

impl Strikes {
    fn newest(&self) -> u32 {
        self.failures[usize::from(self.count) - 1]
    }
}

impl Limiter {
    fn new(start: Instant) -> Limiter {
        Limiter {
            start,
            entries: Vec::with_capacity(LIMITER_ADDRESSES),
        }
    }

    fn seconds(&self, now: Instant) -> u32 {
        let elapsed = now.saturating_duration_since(self.start).as_secs();

        u32::try_from(elapsed).unwrap_or(u32::MAX)
    }

    fn is_limited(&self, ip: IpAddr, now: Instant) -> bool {
        let now = self.seconds(now);
        let ip = ip.to_canonical();

        self.entries
            .iter()
            .find(|strikes| strikes.ip == ip)
            .is_some_and(|strikes| {
                usize::from(strikes.count) == LIMITED_AFTER_FAILURES
                    && strikes.newest() - strikes.failures[0] < LIMIT_WINDOW_SECONDS
                    && now.saturating_sub(strikes.newest()) < LIMIT_WINDOW_SECONDS
            })
    }

    fn record_failure(&mut self, ip: IpAddr, now: Instant) {
        let now = self.seconds(now);
        let ip = ip.to_canonical();

        if let Some(strikes) = self.entries.iter_mut().find(|strikes| strikes.ip == ip) {
            if usize::from(strikes.count) == LIMITED_AFTER_FAILURES {
                strikes.failures.rotate_left(1);
                strikes.failures[LIMITED_AFTER_FAILURES - 1] = now;
            } else {
                strikes.failures[usize::from(strikes.count)] = now;
                strikes.count += 1;
            }

            return;
        }

        let strikes = Strikes {
            ip,
            failures: [now; LIMITED_AFTER_FAILURES],
            count: 1,
        };

        if self.entries.len() < LIMITER_ADDRESSES {
            self.entries.push(strikes);

            return;
        }

        // An expired entry always has an older last failure than a live one, so this reuses
        // an expired entry first.
        if let Some(oldest) = self
            .entries
            .iter_mut()
            .min_by_key(|strikes| strikes.newest())
        {
            *oldest = strikes;
        }
    }

    fn clear(&mut self, ip: IpAddr) {
        let ip = ip.to_canonical();

        self.entries.retain(|strikes| strikes.ip != ip);
    }

    #[cfg(test)]
    fn failures(&self, ip: IpAddr) -> usize {
        self.entries
            .iter()
            .find(|strikes| strikes.ip == ip.to_canonical())
            .map_or(0, |strikes| usize::from(strikes.count))
    }

    #[cfg(test)]
    fn capacity(&self) -> usize {
        self.entries.capacity()
    }
}

/// Strict standard Base64 with padding; anything else is `None`.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let value = |byte: u8| match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };

    if !text.len().is_multiple_of(4) {
        return None;
    }

    let mut bytes = Vec::with_capacity(text.len() / 4 * 3);
    let quads = text.as_bytes().chunks(4);
    let last = quads.len().saturating_sub(1);

    for (index, quad) in quads.enumerate() {
        let padding = quad.iter().rev().take_while(|byte| **byte == b'=').count();
        if padding > 2 || (padding > 0 && index != last) {
            return None;
        }

        let mut group = 0u32;
        for byte in &quad[..4 - padding] {
            group = group << 6 | u32::from(value(*byte)?);
        }
        group <<= 6 * padding;

        let decoded = group.to_be_bytes();
        let kept = 3 - padding;
        // Bits a canonical encoder leaves at zero.
        if decoded[1 + kept..].iter().any(|byte| *byte != 0) {
            return None;
        }

        bytes.extend_from_slice(&decoded[1..1 + kept]);
    }

    Some(bytes)
}

/// The expected `Authorization` credentials, kept as an HMAC-SHA256 tag under a key drawn at
/// startup. Tags have one size, so neither what is stored nor the comparison depends on the
/// length of the secret, and `hmac::verify` does not stop at the first difference.
pub(super) struct Credentials {
    key: hmac::Key,
    tag: hmac::Tag,
}

impl Credentials {
    pub(super) fn new(credentials: &str) -> Result<Credentials, String> {
        let key = hmac::Key::generate(hmac::HMAC_SHA256, &SystemRandom::new())
            .map_err(|_| "cannot draw a random key for the web credentials".to_string())?;
        let tag = hmac::sign(&key, credentials.as_bytes());

        Ok(Credentials { key, tag })
    }

    pub(super) fn accepts(&self, sent: &str) -> bool {
        hmac::verify(&self.key, sent.as_bytes(), self.tag.as_ref()).is_ok()
    }
}

pub(super) fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let group = chunk.iter().enumerate().fold(0u32, |group, (index, byte)| {
            group | u32::from(*byte) << (16 - 8 * index)
        });

        for index in 0..4 {
            if index <= chunk.len() {
                text.push(ALPHABET[(group >> (18 - 6 * index) & 0x3f) as usize] as char);
            } else {
                text.push('=');
            }
        }
    }

    text
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hyper::header::HeaderValue;
    use tokio::task::JoinSet;

    use super::*;

    #[test]
    fn base64_matches_the_standard_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
            ("admin:s3cret", "YWRtaW46czNjcmV0"),
        ] {
            assert_eq!(base64(plain.as_bytes()), encoded, "{plain}");
        }
    }

    #[test]
    fn credentials_are_accepted_only_when_every_byte_is_equal() {
        let credentials = Credentials::new("abc").unwrap();

        assert!(credentials.accepts("abc"));
        assert!(!credentials.accepts("abd"));
        assert!(!credentials.accepts("abcd"));
        assert!(!credentials.accepts("ab"));
        assert!(!credentials.accepts(""));
        assert!(Credentials::new("").unwrap().accepts(""));
    }

    #[test]
    fn what_is_kept_of_the_credentials_has_the_same_size_whatever_their_length() {
        let short = Credentials::new("a").unwrap();
        let long = Credentials::new(&"a".repeat(5000)).unwrap();

        assert_eq!(short.tag.as_ref().len(), long.tag.as_ref().len());
        assert_eq!(std::mem::size_of_val(&short), std::mem::size_of_val(&long));
        assert!(!short.accepts(&"a".repeat(5000)));
        assert!(long.accepts(&"a".repeat(5000)));
    }

    #[test]
    fn base64_decoding_inverts_the_encoding_and_refuses_anything_else() {
        for plain in [
            "",
            "f",
            "fo",
            "foo",
            "foob",
            "fooba",
            "foobar",
            "admin:s3cret",
        ] {
            assert_eq!(
                base64_decode(&base64(plain.as_bytes())).as_deref(),
                Some(plain.as_bytes()),
                "{plain}"
            );
        }

        for bad in [
            "Zg=", "Zg", "Z===", "Zm9v!", "=Zg=", "Zg==Zg==", "Zm9v-_", "Zh==", "Zm9=",
        ] {
            assert_eq!(base64_decode(bad), None, "{bad}");
        }
    }

    const T: u64 = 1_800_000_000;

    fn web_config(user: &str, password: &str) -> WebConfig {
        WebConfig {
            user: Some(user.to_string()),
            password: Some(password.to_string()),
            ..WebConfig::default()
        }
    }

    fn hashed_config(user: &str, hash: &PasswordHash) -> WebConfig {
        WebConfig {
            user: Some(user.to_string()),
            password_hash: Some(hash.clone()),
            ..WebConfig::default()
        }
    }

    fn auth(config: &WebConfig) -> Auth {
        Auth::new(config).unwrap().unwrap()
    }

    fn token_of(cookie: &str) -> String {
        let value = cookie.strip_prefix("picoguard_session=").unwrap();

        value.split(';').next().unwrap().to_string()
    }

    fn cookie_headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(header::COOKIE, HeaderValue::from_str(value).unwrap());
        }

        headers
    }

    fn accepts(auth: &Auth, token: &str, now: u64) -> bool {
        auth.has_session(
            &cookie_headers(&[&format!("picoguard_session={token}")]),
            now,
        )
    }

    #[test]
    fn no_password_means_no_auth() {
        assert!(Auth::new(&WebConfig::default()).unwrap().is_none());
    }

    #[test]
    fn the_session_cookie_is_strict_http_only_and_lasts_thirty_days() {
        let auth = auth(&web_config("admin", "s3cret"));
        let cookie = auth.session_cookie(T);

        assert!(cookie.starts_with("picoguard_session="), "{cookie}");
        assert!(
            cookie.ends_with("; Max-Age=2592000; Path=/; HttpOnly; SameSite=Strict"),
            "{cookie}"
        );
        assert_eq!(
            SIGNED_OUT_COOKIE,
            "picoguard_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict"
        );
    }

    #[test]
    fn a_token_is_accepted_until_its_expiry_and_not_after() {
        let auth = auth(&web_config("admin", "s3cret"));
        let token = token_of(&auth.session_cookie(T));

        assert!(accepts(&auth, &token, T));
        assert!(accepts(&auth, &token, T + 2_591_999));
        assert!(!accepts(&auth, &token, T + 2_592_000));
    }

    #[test]
    fn a_token_with_any_changed_character_is_refused() {
        let auth = auth(&web_config("admin", "s3cret"));
        let token = token_of(&auth.session_cookie(T));
        assert!(accepts(&auth, &token, T));

        for position in 0..token.len() {
            let original = token.as_bytes()[position];
            let replacements: &[u8] = if original == b'.' {
                b"0a"
            } else {
                b"0123456789abcdefABCDEF."
            };

            for &replacement in replacements {
                if replacement == original {
                    continue;
                }

                let mut changed = token.clone().into_bytes();
                changed[position] = replacement;
                let changed = String::from_utf8(changed).unwrap();

                assert!(!accepts(&auth, &changed, T), "{changed}");
            }
        }

        assert!(!accepts(&auth, &format!("{token}0"), T));
        assert!(!accepts(&auth, &format!("0{token}"), T));
        assert!(!accepts(&auth, &token[1..], T));
        assert!(!accepts(&auth, &token[..token.len() - 1], T));
    }

    #[test]
    fn a_token_from_another_user_password_or_hash_is_refused() {
        let first_hash = PasswordHash::new(b"s3cret", 1000).unwrap();
        let second_hash = PasswordHash::new(b"s3cret", 1000).unwrap();
        let sites = [
            auth(&web_config("admin", "s3cret")),
            auth(&web_config("admin", "other")),
            auth(&web_config("other", "s3cret")),
            auth(&hashed_config("admin", &first_hash)),
            auth(&hashed_config("admin", &second_hash)),
        ];

        for (issuer_index, issuer) in sites.iter().enumerate() {
            let token = token_of(&issuer.session_cookie(T));

            for (checker_index, checker) in sites.iter().enumerate() {
                assert_eq!(
                    accepts(checker, &token, T),
                    issuer_index == checker_index,
                    "issued by {issuer_index}, checked by {checker_index}"
                );
            }
        }
    }

    #[test]
    fn the_same_config_makes_the_same_key() {
        let hash = PasswordHash::new(b"s3cret", 1000).unwrap();

        for config in [web_config("admin", "s3cret"), hashed_config("admin", &hash)] {
            let before = auth(&config);
            let after = auth(&config);

            assert!(accepts(&after, &token_of(&before.session_cookie(T)), T));
            assert!(accepts(&before, &token_of(&after.session_cookie(T)), T));
        }
    }

    #[test]
    fn malformed_tokens_are_refused_without_panicking() {
        let auth = auth(&web_config("admin", "s3cret"));
        let hex = "0".repeat(64);

        for token in [
            String::new(),
            ".".to_string(),
            "1.".to_string(),
            ".ab".to_string(),
            format!("abc.{hex}"),
            format!("18446744073709551616.{hex}"),
            format!("+1.{hex}"),
            format!("1.{}", "0".repeat(63)),
            format!("1.{}", "0".repeat(65)),
            format!("1.{}", "z".repeat(64)),
            format!("1.{}é", "0".repeat(62)),
        ] {
            assert!(!accepts(&auth, &token, 0), "{token}");
        }
    }

    #[test]
    fn the_session_is_found_among_other_cookies() {
        let auth = auth(&web_config("admin", "s3cret"));
        let token = token_of(&auth.session_cookie(T));

        assert!(auth.has_session(
            &cookie_headers(&[&format!("a=1; picoguard_session={token}; b=2")]),
            T
        ));
        assert!(auth.has_session(
            &cookie_headers(&[
                "picoguard_session=1.00",
                &format!("picoguard_session={token}")
            ]),
            T
        ));
        assert!(!auth.has_session(
            &cookie_headers(&[&format!("picoguard_session2={token}")]),
            T
        ));
        assert!(!auth.has_session(&HeaderMap::new(), T));
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn minutes(count: u64) -> Duration {
        Duration::from_secs(count * 60)
    }

    #[test]
    fn five_failures_within_fifteen_minutes_lock_until_fifteen_minutes_after_the_last() {
        let start = Instant::now();
        let mut limiter = Limiter::new(start);
        let peer = ip("192.0.2.1");

        for minute in 0..5 {
            assert!(!limiter.is_limited(peer, start + minutes(minute)));
            limiter.record_failure(peer, start + minutes(minute));
        }

        let last = start + minutes(4);
        assert!(limiter.is_limited(peer, last + Duration::from_secs(1)));
        assert!(limiter.is_limited(peer, last + Duration::from_secs(899)));
        assert!(!limiter.is_limited(peer, last + Duration::from_secs(900)));
    }

    #[test]
    fn four_failures_do_not_lock() {
        let start = Instant::now();
        let mut limiter = Limiter::new(start);
        let peer = ip("192.0.2.1");

        for _ in 0..4 {
            limiter.record_failure(peer, start);
        }

        assert!(!limiter.is_limited(peer, start));
    }

    #[test]
    fn five_failures_spread_over_fifteen_minutes_or_more_do_not_lock() {
        let start = Instant::now();
        let mut limiter = Limiter::new(start);
        let peer = ip("192.0.2.1");

        for minute in [0, 4, 8, 12, 15] {
            limiter.record_failure(peer, start + minutes(minute));
        }

        assert!(!limiter.is_limited(peer, start + minutes(15)));
    }

    #[test]
    fn a_success_clears_the_address() {
        let start = Instant::now();
        let mut limiter = Limiter::new(start);
        let peer = ip("192.0.2.1");

        for _ in 0..4 {
            limiter.record_failure(peer, start);
        }
        limiter.clear(peer);
        limiter.record_failure(peer, start);

        assert!(!limiter.is_limited(peer, start));
        assert_eq!(limiter.failures(peer), 1);
    }

    #[test]
    fn other_addresses_are_not_affected() {
        let start = Instant::now();
        let mut limiter = Limiter::new(start);

        for _ in 0..5 {
            limiter.record_failure(ip("192.0.2.1"), start);
        }

        assert!(limiter.is_limited(ip("192.0.2.1"), start));
        assert!(!limiter.is_limited(ip("192.0.2.2"), start));
        assert!(!limiter.is_limited(ip("2001:db8::1"), start));
    }

    #[test]
    fn an_ipv4_mapped_address_counts_as_its_ipv4_address() {
        let start = Instant::now();
        let mut limiter = Limiter::new(start);

        for _ in 0..3 {
            limiter.record_failure(ip("::ffff:192.0.2.1"), start);
        }
        for _ in 0..2 {
            limiter.record_failure(ip("192.0.2.1"), start);
        }

        assert!(limiter.is_limited(ip("192.0.2.1"), start));
        assert!(limiter.is_limited(ip("::ffff:192.0.2.1"), start));
    }

    #[test]
    fn a_full_table_drops_the_entry_with_the_oldest_last_failure() {
        let start = Instant::now();
        let mut limiter = Limiter::new(start);
        let peer = |index: u16| IpAddr::from([10, 0, (index >> 8) as u8, index as u8]);
        assert_eq!(limiter.capacity(), 64);

        for index in 0..65 {
            limiter.record_failure(peer(index), start + Duration::from_secs(u64::from(index)));
            assert_eq!(limiter.capacity(), 64);
        }

        assert_eq!(limiter.failures(peer(0)), 0);
        assert_eq!(limiter.failures(peer(1)), 1);
        assert_eq!(limiter.failures(peer(64)), 1);

        // Peer 1 has the oldest first failure, but its last one is live: an expired entry,
        // peer 2's, is reused instead.
        limiter.record_failure(peer(1), start + Duration::from_secs(1000));
        limiter.record_failure(peer(100), start + Duration::from_secs(1899));
        assert_eq!(limiter.failures(peer(1)), 2);
        assert_eq!(limiter.failures(peer(2)), 0);
        assert_eq!(limiter.failures(peer(100)), 1);

        // 64 new addresses replace every entry, the live ones last.
        for index in 200..263 {
            limiter.record_failure(peer(index), start + Duration::from_secs(2000));
        }
        assert_eq!(limiter.failures(peer(1)), 0);
        assert_eq!(limiter.failures(peer(100)), 1);
        limiter.record_failure(peer(263), start + Duration::from_secs(2000));
        assert_eq!(limiter.failures(peer(100)), 0);
        assert_eq!(limiter.capacity(), 64);
    }

    fn basic(user: &str, password: &str) -> String {
        base64(format!("{user}:{password}").as_bytes())
    }

    async fn check_basic(auth: &Auth, peer: &str, user: &str, password: &str) -> Check {
        auth.check(ip(peer), Attempt::Basic(&basic(user, password)))
            .await
    }

    async fn check_form(auth: &Auth, peer: &str, user: &str, password: &str) -> Check {
        auth.check(ip(peer), Attempt::Form { user, password }).await
    }

    fn timed_verify(hash: &PasswordHash) -> Duration {
        (0..3)
            .map(|_| {
                let started = Instant::now();
                hash.verify(b"not it");

                started.elapsed()
            })
            .min()
            .unwrap()
    }

    #[tokio::test]
    async fn plain_credentials_are_checked_without_a_hash() {
        let auth = auth(&web_config("admin", "s3cret"));

        assert_eq!(
            check_basic(&auth, "192.0.2.1", "admin", "s3cret").await,
            Check::Accepted
        );
        assert_eq!(
            check_form(&auth, "192.0.2.1", "admin", "s3cret").await,
            Check::Accepted
        );
        assert_eq!(
            check_basic(&auth, "192.0.2.1", "admin", "wrong").await,
            Check::Refused
        );
        assert_eq!(
            check_form(&auth, "192.0.2.1", "other", "s3cret").await,
            Check::Refused
        );
        assert_eq!(
            auth.check(ip("192.0.2.1"), Attempt::Basic("not base64!"))
                .await,
            Check::Refused
        );
    }

    #[tokio::test]
    async fn a_hashed_password_accepts_only_the_right_user_and_password() {
        let hash = PasswordHash::new(b"s3cret", 1000).unwrap();
        let auth = auth(&hashed_config("admin", &hash));

        for peer in ["192.0.2.1", "192.0.2.2"] {
            assert_eq!(
                check_basic(&auth, peer, "admin", "wrong").await,
                Check::Refused
            );
            assert_eq!(
                check_form(&auth, peer, "other", "s3cret").await,
                Check::Refused
            );
            assert_eq!(
                check_form(&auth, peer, "admin", "s3cret ").await,
                Check::Refused
            );
            assert_eq!(
                auth.check(ip(peer), Attempt::Basic(&base64(b"admin-s3cret")))
                    .await,
                Check::Refused
            );
            assert_eq!(
                check_basic(&auth, peer, "admin", "s3cret").await,
                Check::Accepted
            );
            assert_eq!(
                check_form(&auth, peer, "admin", "s3cret").await,
                Check::Accepted
            );
        }
    }

    #[tokio::test]
    async fn after_the_first_success_the_same_credentials_are_checked_in_microseconds() {
        let hash = PasswordHash::new(b"s3cret", 100_000).unwrap();
        let auth = auth(&hashed_config("admin", &hash));

        let started = Instant::now();
        assert_eq!(
            check_basic(&auth, "192.0.2.1", "admin", "s3cret").await,
            Check::Accepted
        );
        let first = started.elapsed();

        let started = Instant::now();
        for _ in 0..50 {
            assert_eq!(
                check_basic(&auth, "192.0.2.1", "admin", "s3cret").await,
                Check::Accepted
            );
            assert_eq!(
                check_form(&auth, "192.0.2.1", "admin", "s3cret").await,
                Check::Accepted
            );
        }
        let hundred = started.elapsed();

        assert!(
            hundred < first / 10,
            "first {first:?}, next 100 {hundred:?}"
        );
    }

    #[tokio::test]
    async fn every_wrong_attempt_pays_the_full_hash_even_after_a_success() {
        let hash = PasswordHash::new(b"s3cret", 100_000).unwrap();
        let auth = auth(&hashed_config("admin", &hash));
        assert_eq!(
            check_form(&auth, "192.0.2.1", "admin", "s3cret").await,
            Check::Accepted
        );
        let one = timed_verify(&hash);

        let started = Instant::now();
        assert_eq!(
            check_form(&auth, "192.0.2.1", "admin", "wrong").await,
            Check::Refused
        );
        let wrong = started.elapsed();

        assert!(
            wrong >= one / 2,
            "one hash {one:?}, wrong attempt {wrong:?}"
        );
    }

    #[tokio::test]
    async fn a_wrong_user_and_a_wrong_password_cost_the_same_hash() {
        let hash = PasswordHash::new(b"s3cret", 100_000).unwrap();
        let auth = auth(&hashed_config("admin", &hash));
        let one = timed_verify(&hash);

        for (user, password) in [("other", "s3cret"), ("admin", "wrong")] {
            let started = Instant::now();
            assert_eq!(
                check_basic(&auth, "192.0.2.1", user, password).await,
                Check::Refused
            );
            let took = started.elapsed();

            assert!(
                took >= one / 2,
                "{user}: one hash {one:?}, attempt {took:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_limited_address_is_refused_before_any_comparison() {
        let hash = PasswordHash::new(b"s3cret", 1000).unwrap();

        for config in [web_config("admin", "s3cret"), hashed_config("admin", &hash)] {
            let auth = auth(&config);
            assert_eq!(
                check_basic(&auth, "192.0.2.9", "admin", "s3cret").await,
                Check::Accepted
            );

            for _ in 0..5 {
                assert_eq!(
                    check_form(&auth, "192.0.2.1", "admin", "wrong").await,
                    Check::Refused
                );
            }

            assert_eq!(
                check_basic(&auth, "192.0.2.1", "admin", "s3cret").await,
                Check::Limited
            );
            assert_eq!(
                check_form(&auth, "192.0.2.1", "admin", "s3cret").await,
                Check::Limited
            );
            assert_eq!(
                check_form(&auth, "192.0.2.2", "admin", "s3cret").await,
                Check::Accepted
            );
        }
    }

    #[tokio::test]
    async fn concurrent_attempts_from_one_address_never_pass_the_limit() {
        let hash = PasswordHash::new(b"s3cret", 1000).unwrap();
        let auth = Arc::new(auth(&hashed_config("admin", &hash)));
        let mut attempts = JoinSet::new();

        for _ in 0..10 {
            let auth = Arc::clone(&auth);
            attempts.spawn(async move { check_form(&auth, "192.0.2.1", "admin", "wrong").await });
        }

        let outcomes = attempts.join_all().await;
        let count = |wanted| {
            outcomes
                .iter()
                .filter(|outcome| **outcome == wanted)
                .count()
        };

        assert_eq!(count(Check::Refused), 5, "{outcomes:?}");
        assert_eq!(count(Check::Limited), 5, "{outcomes:?}");
        assert_eq!(
            check_form(&auth, "192.0.2.1", "admin", "s3cret").await,
            Check::Limited
        );
    }

    #[tokio::test]
    async fn a_failure_is_counted_even_when_the_request_is_dropped_mid_hash() {
        let hash = PasswordHash::new(b"s3cret", 2_000_000).unwrap();
        let auth = Arc::new(auth(&hashed_config("admin", &hash)));

        let attempt = tokio::spawn({
            let auth = Arc::clone(&auth);

            async move { check_form(&auth, "192.0.2.1", "admin", "wrong").await }
        });
        while auth.hashing.available_permits() != 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        attempt.abort();
        while auth.hashing.available_permits() != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(auth.limiter.lock().unwrap().failures(ip("192.0.2.1")), 1);

        let quick = PasswordHash::new(b"s3cret", 1000).unwrap();
        let auth = Auth {
            password: Password::Hashed {
                user: Credentials::new("admin").unwrap(),
                hash: quick,
                known: Arc::new(OnceLock::new()),
            },
            ..Arc::into_inner(auth).unwrap()
        };
        for _ in 0..4 {
            assert_eq!(
                check_form(&auth, "192.0.2.1", "admin", "wrong").await,
                Check::Refused
            );
        }

        assert_eq!(
            check_form(&auth, "192.0.2.1", "admin", "s3cret").await,
            Check::Limited
        );
    }

    #[tokio::test]
    async fn a_form_user_with_a_colon_never_matches_a_shifted_password() {
        let hash = PasswordHash::new(b"a:b", 1000).unwrap();

        let plain = auth(&web_config("admin", "a:b"));
        assert_eq!(
            check_form(&plain, "192.0.2.1", "admin:a", "b").await,
            Check::Refused
        );
        assert_eq!(
            check_form(&plain, "192.0.2.1", "admin", "a:b").await,
            Check::Accepted
        );
        assert_eq!(
            check_basic(&plain, "192.0.2.1", "admin", "a:b").await,
            Check::Accepted
        );

        let hashed = auth(&hashed_config("admin", &hash));
        assert_eq!(
            check_form(&hashed, "192.0.2.1", "admin:a", "b").await,
            Check::Refused
        );
        assert_eq!(
            check_form(&hashed, "192.0.2.1", "admin", "a:b").await,
            Check::Accepted
        );
        assert_eq!(
            check_form(&hashed, "192.0.2.1", "admin:a", "b").await,
            Check::Refused
        );
        assert_eq!(
            check_basic(&hashed, "192.0.2.1", "admin", "a:b").await,
            Check::Accepted
        );
    }
}
