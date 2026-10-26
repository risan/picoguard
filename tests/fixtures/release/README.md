# Release signature fixtures

Used by `tests/release_signature.rs`, which checks that `ring` accepts a signature made
by OpenSSL in the release format.

- `test-key.der`: a throwaway Ed25519 public key, 44 bytes of DER SubjectPublicKeyInfo.
- `SHA256SUMS`: a file in the release format over placeholder content.
- `SHA256SUMS.sig`: its 64-byte signature, made by `scripts/sign-release.sh` with the
  matching throwaway private key.

The private key was created in a temporary directory and deleted right after signing.
No private key exists in this repository.
