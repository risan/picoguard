//! The stored form of the status page password (`web.password_hash`): PBKDF2-HMAC-SHA256 with a
//! random 16-byte salt, written as `pbkdf2-sha256$<iterations>$<salt hex>$<derived key hex>`.

use std::fmt;
use std::num::NonZeroU32;
use std::str::FromStr;

use ring::pbkdf2::{self, PBKDF2_HMAC_SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;

/// OWASP's figure for PBKDF2-HMAC-SHA256. Each hash keeps its own count, so changing this never
/// breaks a stored hash.
pub const DEFAULT_ITERATIONS: u32 = 600_000;
pub const MIN_ITERATIONS: u32 = 1_000;
/// Stops a typo that would make every sign-in take minutes.
pub const MAX_ITERATIONS: u32 = 10_000_000;

const PREFIX: &str = "pbkdf2-sha256";

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(try_from = "String")]
pub struct PasswordHash {
    iterations: NonZeroU32,
    salt: [u8; 16],
    derived: [u8; 32],
}

impl PasswordHash {
    pub fn new(password: &[u8], iterations: u32) -> Result<PasswordHash, String> {
        let iterations = checked_iterations(iterations)?;
        let mut salt = [0; 16];
        SystemRandom::new()
            .fill(&mut salt)
            .map_err(|_| "cannot draw a random salt".to_string())?;
        let mut derived = [0; 32];
        pbkdf2::derive(
            PBKDF2_HMAC_SHA256,
            iterations,
            &salt,
            password,
            &mut derived,
        );

        Ok(PasswordHash {
            iterations,
            salt,
            derived,
        })
    }

    /// Takes as long as the stored cost says, whatever the password.
    pub fn verify(&self, password: &[u8]) -> bool {
        pbkdf2::verify(
            PBKDF2_HMAC_SHA256,
            self.iterations,
            &self.salt,
            password,
            &self.derived,
        )
        .is_ok()
    }
}

fn checked_iterations(iterations: u32) -> Result<NonZeroU32, String> {
    if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
        return Err(format!(
            "the iterations must be from {MIN_ITERATIONS} to {MAX_ITERATIONS}"
        ));
    }

    NonZeroU32::new(iterations).ok_or_else(|| "the iterations must not be 0".to_string())
}

impl FromStr for PasswordHash {
    type Err = String;

    fn from_str(text: &str) -> Result<PasswordHash, String> {
        let invalid = |reason: &str| {
            format!("invalid password hash: {reason}; make one with picoguard --hash-password")
        };

        let mut parts = text.split('$');
        let (Some(PREFIX), Some(iterations), Some(salt), Some(derived), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(invalid(&format!(
                "expected {PREFIX}$<iterations>$<salt>$<hash>"
            )));
        };

        if iterations.is_empty() || !iterations.bytes().all(|digit| digit.is_ascii_digit()) {
            return Err(invalid("the iterations are not a number"));
        }

        let iterations = iterations
            .parse::<u32>()
            .map_err(|_| "the iterations are out of range".to_string())
            .and_then(checked_iterations)
            .map_err(|reason| invalid(&reason))?;
        let salt = from_hex(salt).ok_or_else(|| invalid("the salt is not 32 hex digits"))?;
        let derived = from_hex(derived).ok_or_else(|| invalid("the hash is not 64 hex digits"))?;

        Ok(PasswordHash {
            iterations,
            salt,
            derived,
        })
    }
}

fn from_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 {
        return None;
    }

    let mut bytes = [0; N];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
        let high = char::from(pair[0]).to_digit(16)?;
        let low = char::from(pair[1]).to_digit(16)?;
        *byte = (high * 16 + low) as u8;
    }

    Some(bytes)
}

impl TryFrom<String> for PasswordHash {
    type Error = String;

    fn try_from(text: String) -> Result<PasswordHash, String> {
        text.parse()
    }
}

impl fmt::Display for PasswordHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{PREFIX}${}$", self.iterations)?;
        for byte in self.salt {
            write!(formatter, "{byte:02x}")?;
        }

        write!(formatter, "$")?;
        for byte in self.derived {
            write!(formatter, "{byte:02x}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTOR: &str = "pbkdf2-sha256$1000$000102030405060708090a0b0c0d0e0f$33a78c377ca7b6590fa1b215cc970fba516076f108ecb68af58ec95d86021701";

    #[test]
    fn a_hash_made_elsewhere_verifies_its_password() {
        let hash: PasswordHash = VECTOR.parse().unwrap();

        assert!(hash.verify(b"s3cret"));
        assert!(!hash.verify(b"s3cret "));
        assert!(!hash.verify(b""));
        assert_eq!(hash.to_string(), VECTOR);
    }

    #[test]
    fn a_new_hash_has_a_random_salt_and_verifies_only_its_password() {
        let first = PasswordHash::new(b"pw", 1000).unwrap();
        let second = PasswordHash::new(b"pw", 1000).unwrap();

        assert_ne!(first, second);
        for hash in [&first, &second] {
            assert!(hash.verify(b"pw"));
            assert!(!hash.verify(b"px"));
            assert_eq!(&hash.to_string().parse::<PasswordHash>().unwrap(), hash);
        }
    }

    #[test]
    fn only_the_one_format_is_accepted() {
        let salt = "000102030405060708090a0b0c0d0e0f";
        let derived = "33a78c377ca7b6590fa1b215cc970fba516076f108ecb68af58ec95d86021701";

        for bad in [
            String::new(),
            "pbkdf2-sha256".to_string(),
            format!("pbkdf2-sha1$1000${salt}${derived}"),
            format!("pbkdf2-sha256$999${salt}${derived}"),
            format!("pbkdf2-sha256$10000001${salt}${derived}"),
            format!("pbkdf2-sha256$+1000${salt}${derived}"),
            format!("pbkdf2-sha256$1e3${salt}${derived}"),
            format!("pbkdf2-sha256$1000${}${derived}", &salt[..30]),
            format!("pbkdf2-sha256$1000$g{}${derived}", &salt[1..]),
            format!("pbkdf2-sha256$1000${salt}${}", &derived[..62]),
            format!("pbkdf2-sha256$1000${salt}${derived}$x"),
            format!(" {VECTOR}"),
            format!("{VECTOR} "),
        ] {
            assert!(bad.parse::<PasswordHash>().is_err(), "{bad:?}");
        }

        let upper = format!(
            "pbkdf2-sha256$1000${}${}",
            salt.to_uppercase(),
            derived.to_uppercase()
        );
        let hash: PasswordHash = upper.parse().unwrap();

        assert_eq!(hash.to_string(), VECTOR);
        assert!(hash.verify(b"s3cret"));
    }

    #[test]
    fn the_cost_must_be_within_bounds_to_make_a_hash() {
        assert!(PasswordHash::new(b"pw", 999).is_err());
        assert!(PasswordHash::new(b"pw", 10_000_001).is_err());
    }
}
