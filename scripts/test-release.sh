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
