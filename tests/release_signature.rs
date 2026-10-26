//! Pins the release signature contract that `stage-update` builds on: a 44-byte
//! DER public key whose last 32 bytes `ring` takes as an Ed25519 key, and a raw
//! 64-byte OpenSSL signature over the bytes of `SHA256SUMS`.

use ring::signature::{ED25519, UnparsedPublicKey};

const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

const TEST_KEY: &[u8] = include_bytes!("fixtures/release/test-key.der");
const SUMS: &[u8] = include_bytes!("fixtures/release/SHA256SUMS");
const SIGNATURE: &[u8] = include_bytes!("fixtures/release/SHA256SUMS.sig");
const RELEASE_KEY: &[u8] = include_bytes!("../dist/release-key.der");

fn raw_public_key(der: &[u8]) -> &[u8] {
    assert_eq!(der.len(), 44);
    assert_eq!(der[..12], SPKI_PREFIX);
    &der[12..]
}

#[test]
fn openssl_signature_verifies_with_ring() {
    let key = UnparsedPublicKey::new(&ED25519, raw_public_key(TEST_KEY));

    assert_eq!(SIGNATURE.len(), 64);
    assert!(key.verify(SUMS, SIGNATURE).is_ok());
}

#[test]
fn modified_sums_is_rejected() {
    let key = UnparsedPublicKey::new(&ED25519, raw_public_key(TEST_KEY));
    let mut modified = SUMS.to_vec();
    modified.push(b'\n');

    assert!(key.verify(&modified, SIGNATURE).is_err());
}

#[test]
fn release_key_has_the_published_format() {
    assert_eq!(RELEASE_KEY.len(), 44);
    assert_eq!(RELEASE_KEY[..12], SPKI_PREFIX);
}
