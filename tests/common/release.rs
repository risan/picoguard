//! Release files signed by a throwaway key made from a fixed seed, for the stager and for
//! `verify-update`. The real release key's private half never exists on this machine.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use picoguard::release::Request;
use ring::digest;
use ring::signature::{Ed25519KeyPair, KeyPair};

pub const TEST_SEED: u8 = 7;
pub const TARGET: &str = "x86_64-unknown-linux-musl";
pub const REQUEST_ID: &str = "0123456789abcdef";

fn pair(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

/// The public half of the test key, as the constructors take it.
pub fn test_key() -> [u8; 32] {
    pair(TEST_SEED).public_key().as_ref().try_into().unwrap()
}

pub fn sign(sums: &[u8]) -> Vec<u8> {
    sign_with(TEST_SEED, sums)
}

pub fn sign_with(seed: u8, sums: &[u8]) -> Vec<u8> {
    pair(seed).sign(sums).as_ref().to_vec()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, bytes)
        .as_ref()
        .try_into()
        .unwrap()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One `sha256sum` line.
pub fn sums_line(name: &str, bytes: &[u8]) -> String {
    format!("{}  {name}\n", hex(&sha256(bytes)))
}

pub fn script(version: &str) -> Vec<u8> {
    format!("#!/bin/sh\necho \"picoguard {version}\"\n").into_bytes()
}

/// The four files of an update.
#[derive(Clone)]
pub struct Files {
    pub binary: Vec<u8>,
    pub sums: Vec<u8>,
    pub signature: Vec<u8>,
    pub request: Vec<u8>,
}

impl Files {
    pub fn good(version: &str, binary: &[u8]) -> Files {
        let sums = sums_line(&format!("picoguard-{TARGET}"), binary).into_bytes();
        let signature = sign(&sums);
        let request = Request {
            id: REQUEST_ID.to_string(),
            version: version.to_string(),
        }
        .format()
        .into_bytes();

        Files {
            binary: binary.to_vec(),
            sums,
            signature,
            request,
        }
    }

    /// Replaces `SHA256SUMS` and signs it again with the test key.
    pub fn resign(&mut self, sums: &str) {
        self.sums = sums.as_bytes().to_vec();
        self.signature = sign(&self.sums);
    }

    pub fn write(&self, dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        write_file(&dir.join("picoguard"), &self.binary, 0o755);
        write_file(&dir.join("SHA256SUMS"), &self.sums, 0o644);
        write_file(&dir.join("SHA256SUMS.sig"), &self.signature, 0o644);
        write_file(&dir.join("request"), &self.request, 0o644);
    }
}

pub fn write_file(path: &Path, bytes: &[u8], mode: u32) {
    use std::io::Write;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    file.write_all(bytes).unwrap();
}

/// A fresh directory under `target/`, which may hold executables, with a parent that only
/// the test user can change.
pub fn scratch(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&path);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&path)
        .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();

    path
}

/// Writes a good update to `<root>/staged`, after `tweak` changed the files.
pub fn stage_dir(
    root: &Path,
    version: &str,
    binary: &[u8],
    tweak: impl FnOnce(&mut Files),
) -> PathBuf {
    let mut files = Files::good(version, binary);
    tweak(&mut files);
    let dir = root.join("staged");
    files.write(&dir);

    dir
}
