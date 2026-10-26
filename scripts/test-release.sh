#!/usr/bin/env bash
# Tests for the release scripts. Needs bash, openssl, git and base64 only.
set -euo pipefail

cd "$(dirname "$0")/.."

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

case_name=

fail() {
    echo "FAIL $case_name: $*" >&2
    exit 1
}

run_case() {
    case_name=$1
    "$1"
    echo "ok $1"
}

expect_success() {
    local status=0

    "$@" >"$scratch/out" 2>&1 || status=$?
    if [ "$status" -ne 0 ]; then
        cat "$scratch/out" >&2
        fail "expected success, got exit $status: $*"
    fi
}

expect_failure() {
    local status=0

    "$@" >"$scratch/out" 2>&1 || status=$?
    if [ "$status" -eq 0 ]; then
        cat "$scratch/out" >&2
        fail "expected failure, got success: $*"
    fi
}

expect_output() {
    if ! grep -q -F -- "$1" "$scratch/out"; then
        cat "$scratch/out" >&2
        fail "output does not contain: $1"
    fi
}

# --- preflight ---------------------------------------------------------------

commit_sha=1111111111111111111111111111111111111111
other_sha=2222222222222222222222222222222222222222

manifest_with_version() {
    local manifest="$scratch/Cargo.toml"

    cat >"$manifest" <<TOML
[package]
name = "picoguard"
version = "$1"
edition = "2024"

[dependencies]
serde = { version = "9.9.9" }
TOML
    echo "$manifest"
}

preflight() {
    local tag=$1 type=$2 peeled=$3 version=$4 manifest

    manifest=$(manifest_with_version "$version")
    GITHUB_SHA=$commit_sha scripts/release-preflight.sh "$tag" "$type" "$peeled" "$manifest"
}

preflight_accepts_matching_annotated_tag() {
    expect_success preflight v0.2.0 tag "$commit_sha" 0.2.0
    expect_output "version=0.2.0"
    expect_output "prerelease=false"
}

preflight_marks_prerelease() {
    expect_success preflight v0.3.0-rc.1 tag "$commit_sha" 0.3.0-rc.1
    expect_output "version=0.3.0-rc.1"
    expect_output "prerelease=true"
}

preflight_rejects_version_mismatch() {
    expect_failure preflight v0.2.1 tag "$commit_sha" 0.2.0
    expect_output "v0.2.1"
    expect_output "0.2.0"
}

preflight_rejects_lightweight_tag() {
    expect_failure preflight v0.2.0 commit "$commit_sha" 0.2.0
}

preflight_rejects_bad_tag_shape() {
    expect_failure preflight v0.2 tag "$commit_sha" 0.2
    expect_failure preflight 0.2.0 tag "$commit_sha" 0.2.0
    expect_failure preflight v0.2.0+x tag "$commit_sha" 0.2.0+x
}

preflight_rejects_other_commit() {
    expect_failure preflight v0.2.0 tag "$other_sha" 0.2.0
}

run_case preflight_accepts_matching_annotated_tag
run_case preflight_marks_prerelease
run_case preflight_rejects_version_mismatch
run_case preflight_rejects_lightweight_tag
run_case preflight_rejects_bad_tag_shape
run_case preflight_rejects_other_commit

# --- signing -----------------------------------------------------------------

sign_log="$scratch/sign-output.log"
sign_keys="$scratch/sign-keys.txt"
: >"$sign_log"
: >"$sign_keys"

# make_keypair <name>: a throwaway key as the one-line base64 the secret holds
# in $scratch/<name>.key, and its public DER in $scratch/<name>.pub.
make_keypair() {
    local name=$1

    openssl genpkey -algorithm ed25519 -outform DER -out "$scratch/$name.der" 2>/dev/null
    openssl pkey -inform DER -in "$scratch/$name.der" -pubout -outform DER -out "$scratch/$name.pub"
    base64 -w0 "$scratch/$name.der" >"$scratch/$name.key"
    cat "$scratch/$name.key" >>"$sign_keys"
    echo >>"$sign_keys"
    rm -f "$scratch/$name.der"
}

fake_release_dir() {
    local dir="$scratch/release-$1"

    rm -rf "$dir"
    mkdir -p "$dir"
    printf '%s  picoguard-x86_64-unknown-linux-musl\n' \
        e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 >"$dir/SHA256SUMS"
    echo "$dir"
}

# sign_release <key> <dir> <public-key>: runs the script with the key in its
# environment and keeps the output for sign_never_prints_key.
sign_release() {
    RELEASE_SIGNING_KEY=$1 scripts/sign-release.sh "$2" "$3" 2>&1 | tee -a "$sign_log"
}

sign_writes_verified_signature() {
    local dir

    make_keypair good
    dir=$(fake_release_dir good)

    expect_success sign_release "$(cat "$scratch/good.key")" "$dir" "$scratch/good.pub"
    expect_output "Signature Verified Successfully"
    expect_output "a modified SHA256SUMS fails verification"

    [ "$(stat -c %s "$dir/SHA256SUMS.sig")" -eq 64 ] || fail "signature is not 64 bytes"
    openssl pkeyutl -verify -pubin -inkey "$scratch/good.pub" -keyform DER \
        -rawin -in "$dir/SHA256SUMS" -sigfile "$dir/SHA256SUMS.sig" >/dev/null ||
        fail "the Interfaces OpenSSL command does not verify the signature"
}

sign_rejects_other_key() {
    local dir

    make_keypair key_a
    make_keypair key_b
    dir=$(fake_release_dir other)

    expect_failure sign_release "$(cat "$scratch/key_a.key")" "$dir" "$scratch/key_b.pub"
    expect_output "does not match the public key file"
    [ ! -e "$dir/SHA256SUMS.sig" ] || fail "a signature was left behind"
}

sign_requires_key() {
    local dir

    make_keypair good
    dir=$(fake_release_dir required)

    expect_failure sign_release "" "$dir" "$scratch/good.pub"
    expect_output "RELEASE_SIGNING_KEY"
    [ ! -e "$dir/SHA256SUMS.sig" ] || fail "a signature was left behind"

    expect_failure env -u RELEASE_SIGNING_KEY scripts/sign-release.sh "$dir" "$scratch/good.pub"
    expect_output "RELEASE_SIGNING_KEY"
    [ ! -e "$dir/SHA256SUMS.sig" ] || fail "a signature was left behind"
}

sign_rejects_malformed_key() {
    local dir garbage

    make_keypair good
    dir=$(fake_release_dir malformed)
    garbage=$(echo "this is not a private key" | base64 -w0)
    echo "$garbage" >>"$sign_keys"

    expect_failure sign_release "not-base64!" "$dir" "$scratch/good.pub"
    [ ! -e "$dir/SHA256SUMS.sig" ] || fail "a signature was left behind"

    expect_failure sign_release "$garbage" "$dir" "$scratch/good.pub"
    [ ! -e "$dir/SHA256SUMS.sig" ] || fail "a signature was left behind"
}

sign_removes_stale_signature() {
    local dir

    make_keypair good
    dir=$(fake_release_dir stale)
    echo stale >"$dir/SHA256SUMS.sig"

    expect_failure sign_release "" "$dir" "$scratch/good.pub"
    [ ! -e "$dir/SHA256SUMS.sig" ] || fail "the stale signature survived a failed run"
}

sign_never_prints_key() {
    if grep -q -F -f "$sign_keys" "$sign_log"; then
        fail "a key appeared in the output of the sign script"
    fi
}

run_case sign_writes_verified_signature
run_case sign_rejects_other_key
run_case sign_requires_key
run_case sign_rejects_malformed_key
run_case sign_removes_stale_signature
run_case sign_never_prints_key
