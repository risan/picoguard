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

# --- crates.io publish decision ----------------------------------------------

crate_prerelease_is_check_only() {
    expect_success scripts/publish-crate.sh --decide 0.3.0-rc.1 true
    expect_output "check-only"
}

# fake_bin <name>: a stub command whose body is read from stdin, in a directory
# to put first on PATH.
fake_bin() {
    mkdir -p "$scratch/fake-bin"
    {
        echo '#!/usr/bin/env bash'
        cat
    } >"$scratch/fake-bin/$1"
    chmod +x "$scratch/fake-bin/$1"
}

with_fake_bin() {
    PATH="$scratch/fake-bin:$PATH" "$@"
}

crate_decides_from_the_registry_status() {
    fake_bin curl <<'STUB'
printf %s "$FAKE_HTTP_CODE"
STUB

    expect_success with_fake_bin env FAKE_HTTP_CODE=200 scripts/publish-crate.sh --decide 1.0.0 false
    expect_output "skip"

    expect_success with_fake_bin env FAKE_HTTP_CODE=404 scripts/publish-crate.sh --decide 1.0.0 false
    expect_output "publish"

    expect_failure with_fake_bin env FAKE_HTTP_CODE=503 scripts/publish-crate.sh --decide 1.0.0 false
    expect_output "503"
}

crate_publish_needs_a_token() {
    fake_bin curl <<'STUB'
printf 404
STUB
    fake_bin cargo <<'STUB'
echo "cargo $*" >>"$FAKE_CARGO_LOG"
STUB
    : >"$scratch/cargo.log"

    expect_failure with_fake_bin env CARGO_REGISTRY_TOKEN= FAKE_CARGO_LOG="$scratch/cargo.log" \
        scripts/publish-crate.sh 1.0.0 false
    expect_output "CARGO_REGISTRY_TOKEN"
    [ ! -s "$scratch/cargo.log" ] || fail "cargo ran without a token"

    expect_success with_fake_bin env CARGO_REGISTRY_TOKEN=token FAKE_CARGO_LOG="$scratch/cargo.log" \
        scripts/publish-crate.sh 1.0.0 false
    grep -q -x 'cargo publish --locked --no-verify' "$scratch/cargo.log" || fail "cargo publish was not run as planned"
}

crate_skip_and_check_only_never_publish() {
    fake_bin curl <<'STUB'
printf 200
STUB
    fake_bin cargo <<'STUB'
echo "cargo $*" >>"$FAKE_CARGO_LOG"
STUB
    : >"$scratch/cargo.log"

    expect_success with_fake_bin env CARGO_REGISTRY_TOKEN=token FAKE_CARGO_LOG="$scratch/cargo.log" \
        scripts/publish-crate.sh 1.0.0 false
    expect_success with_fake_bin env CARGO_REGISTRY_TOKEN=token FAKE_CARGO_LOG="$scratch/cargo.log" \
        scripts/publish-crate.sh 1.0.0-rc.1 true
    [ ! -s "$scratch/cargo.log" ] || fail "cargo ran although nothing is to be published"
}

run_case crate_prerelease_is_check_only
run_case crate_decides_from_the_registry_status
run_case crate_publish_needs_a_token
run_case crate_skip_and_check_only_never_publish

# --- GitHub release ----------------------------------------------------------

release_files=(
    picoguard-x86_64-unknown-linux-musl
    picoguard-aarch64-unknown-linux-musl
    picoguard-armv7-unknown-linux-musleabihf
    install.sh
    proxmox-lxc.sh
    SHA256SUMS
    SHA256SUMS.sig
)
tag_object_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
moved_object_id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

fake_gh() {
    fake_bin gh <<'STUB'
echo "$*" >>"$FAKE_GH_LOG"

case "$*" in
    *"--paginate"*"/releases"*)
        if [ -n "${FAKE_LIST_FAILS:-}" ]; then
            echo "gh: HTTP 502" >&2
            exit 1
        fi
        printf '%s' "${FAKE_LIST_OUTPUT:-}"
        ;;
    "api repos/"*"/git/ref/tags/"*)
        # FAKE_REF_ANSWERS holds one answer per call; the last one repeats.
        if [ ! -e "$FAKE_REF_STATE" ]; then
            echo "$FAKE_REF_ANSWERS" >"$FAKE_REF_STATE"
        fi
        read -r answer rest <"$FAKE_REF_STATE"
        echo "$answer"
        if [ -n "$rest" ]; then
            echo "$rest" >"$FAKE_REF_STATE"
        fi
        ;;
    "api repos/"*"/git/tags/"*)
        printf '%s\n' "$FAKE_TAG_MESSAGE"
        ;;
    "release create"*)
        previous=
        for argument in "$@"; do
            if [ "$previous" = "--notes-file" ]; then
                cp "$argument" "$FAKE_NOTES_COPY"
            fi
            previous=$argument
        done
        ;;
    "release view"*)
        echo "${FAKE_ASSET_COUNT:-7}"
        ;;
esac
STUB
}

# release_assets_dir <name>: a directory holding the seven release files.
release_assets_dir() {
    local dir="$scratch/assets-$1" file

    rm -rf "$dir"
    mkdir -p "$dir"
    for file in "${release_files[@]}"; do
        echo "$file" >"$dir/$file"
    done
    echo "$dir"
}

# publish_release <dir> <prerelease> <env assignments...>: runs the publisher
# against the fake gh. $gh_log gets every gh call.
publish_release() {
    local dir=$1 prerelease=$2
    shift 2

    : >"$gh_log"
    rm -f "$scratch/ref.state"
    with_fake_bin env GITHUB_REPOSITORY=risan/picoguard \
        FAKE_GH_LOG="$gh_log" FAKE_NOTES_COPY="$scratch/notes.copy" \
        FAKE_TAG_MESSAGE="picoguard v0.3.0" \
        FAKE_REF_STATE="$scratch/ref.state" FAKE_REF_ANSWERS="$tag_object_id" \
        "$@" \
        scripts/publish-github-release.sh v0.3.0 "$tag_object_id" "$prerelease" "$dir"
}

gh_log="$scratch/gh.log"

gh_calls() {
    grep -c -E -- "$1" "$gh_log" || true
}

gh_line_of() {
    grep -n -E -- "$1" "$gh_log" | head -1 | cut -d: -f1
}

github_release_first_run() {
    local dir file

    fake_gh
    dir=$(release_assets_dir first)

    expect_success publish_release "$dir" false
    [ "$(gh_calls '^release create v0.3.0 --draft --verify-tag ')" -eq 1 ] || fail "no single draft create"
    [ "$(gh_calls '^release delete')" -eq 0 ] || fail "deleted something on a first run"
    for file in "${release_files[@]}"; do
        grep -q -E "^release create .* $dir/$file( |\$)" "$gh_log" || fail "$file was not uploaded"
    done
    [ "$(gh_calls '^release edit v0.3.0 --draft=false --latest$')" -eq 1 ] || fail "not published as latest"

    [ "$(gh_line_of '^release create')" -lt "$(gh_line_of '^release view')" ] || fail "asset count checked before create"
    [ "$(gh_line_of '^release view')" -lt "$(gh_line_of '^release edit')" ] || fail "published before the asset count"
}

github_release_replaces_draft() {
    fake_gh

    expect_success publish_release "$(release_assets_dir draft)" false FAKE_LIST_OUTPUT=true
    [ "$(gh_calls '^release delete v0.3.0 --yes$')" -eq 1 ] || fail "the draft was not deleted"
    [ "$(gh_line_of '^release delete')" -lt "$(gh_line_of '^release create')" ] || fail "created before deleting the draft"
    [ "$(gh_calls '^release edit .*--draft=false')" -eq 1 ] || fail "not published"
}

github_release_refuses_published() {
    fake_gh

    expect_failure publish_release "$(release_assets_dir published)" false FAKE_LIST_OUTPUT=false
    expect_output "already published"
    [ "$(gh_calls '^release (create|edit|delete)')" -eq 0 ] || fail "changed a published release"
}

github_release_api_error() {
    fake_gh

    expect_failure publish_release "$(release_assets_dir api_error)" false FAKE_LIST_FAILS=1
    [ "$(gh_calls '^release create')" -eq 0 ] || fail "created a release after an API error"
}

github_release_prerelease_flag() {
    fake_gh

    expect_success publish_release "$(release_assets_dir pre)" true
    grep -q -E '^release create .* --prerelease( |$)' "$gh_log" || fail "--prerelease missing on create"
    [ "$(gh_calls '^release edit v0.3.0 --draft=false$')" -eq 1 ] || fail "a prerelease must be published without --latest"

    expect_success publish_release "$(release_assets_dir stable)" false
    ! grep -q -E '^release create .* --prerelease( |$)' "$gh_log" || fail "--prerelease on a stable release"
}

github_release_tag_moved() {
    fake_gh

    expect_failure publish_release "$(release_assets_dir moved_early)" false \
        FAKE_REF_ANSWERS="$moved_object_id"
    [ "$(gh_calls '^release create')" -eq 0 ] || fail "created a release for a moved tag"

    expect_failure publish_release "$(release_assets_dir moved_late)" false \
        FAKE_REF_ANSWERS="$tag_object_id $moved_object_id"
    [ "$(gh_calls '^release create')" -eq 1 ] || fail "the draft was not created"
    [ "$(gh_calls '^release edit')" -eq 0 ] || fail "published although the tag moved"
}

github_release_notes_from_object() {
    fake_gh

    expect_success publish_release "$(release_assets_dir notes)" false FAKE_TAG_MESSAGE="the notes of this tag"
    grep -q -F "api repos/risan/picoguard/git/tags/$tag_object_id " "$gh_log" || fail "notes not read from the tag object"
    [ "$(cat "$scratch/notes.copy")" = "the notes of this tag" ] || fail "notes file differs from the tag message"
}

github_release_needs_all_assets() {
    local dir

    fake_gh
    dir=$(release_assets_dir missing)
    rm "$dir/SHA256SUMS.sig"

    expect_failure publish_release "$dir" false
    [ "$(gh_calls '^release create')" -eq 0 ] || fail "created a release with a file missing"

    expect_failure publish_release "$(release_assets_dir short)" false FAKE_ASSET_COUNT=6
    [ "$(gh_calls '^release edit')" -eq 0 ] || fail "published with the wrong asset count"
}

run_case github_release_first_run
run_case github_release_replaces_draft
run_case github_release_refuses_published
run_case github_release_api_error
run_case github_release_prerelease_flag
run_case github_release_tag_moved
run_case github_release_notes_from_object
run_case github_release_needs_all_assets

# --- workflow rules ----------------------------------------------------------

workflow=.github/workflows/release.yml

# workflow_violations <file>: one line per broken rule; nothing when it is sound.
workflow_violations() {
    local file=$1 on_block expected_on_block

    grep -n 'uses:' "$file" | grep -v -E 'uses: [^@[:space:]]+@[0-9a-f]{40}( |$)' |
        sed 's/^/unpinned action: /' || true

    on_block=$(awk '/^on:/ { inside = 1; next } /^[^ #]/ { inside = 0 } inside && NF' "$file" | sed 's/^ *//')
    printf -v expected_on_block "push:\ntags: ['v*']"
    if [ "$on_block" != "$expected_on_block" ]; then
        echo "the on: block is not push of v* tags only"
    fi

    grep -q -x 'permissions: {}' "$file" || echo "top-level permissions: {} is missing"

    awk '
        /^jobs:/ { jobs = 1 }
        jobs && /^  [a-z_-]+:[[:space:]]*$/ { job = $1 }
        /contents: write/ && job != "release:" { print "contents: write outside the release job: " $0 }
    ' "$file"
    grep -q 'contents: write' "$file" || echo "the release job has no contents: write"

    grep -n -E 'actions/cache|cache:' "$file" | sed 's/^/cache: /' || true

    if [ "$(grep -c 'persist-credentials: false' "$file")" -ne "$(grep -c 'actions/checkout@' "$file")" ]; then
        echo "persist-credentials: false count differs from the checkout count"
    fi

    grep -n 'runs-on:' "$file" | grep -v -E 'runs-on: ubuntu-24\.04$' | sed 's/^/runner: /' || true

    if [ "$(grep -c 'secrets.RELEASE_SIGNING_KEY' "$file")" -ne 1 ]; then
        echo "secrets.RELEASE_SIGNING_KEY must appear exactly once"
    fi

    awk '
        function check(   i, name, count, names) {
            if (step !~ /scripts\/[a-z-]+\.sh/) {
                return
            }
            count = split("TAG TAG_OBJECT PRERELEASE VERSION", names, " ")
            for (i = 1; i <= count; i++) {
                name = names[i]
                if (step ~ ("\\$\\{?" name "([^A-Za-z0-9_]|$)") && step !~ ("\n *" name ":")) {
                    print "a step passes $" name " to a script without an env mapping"
                }
            }
        }
        /^      - / { check(); step = "" }
        { step = step "\n" $0 }
        END { check() }
    ' "$file"

    grep -n -E '^ +(TAG_OBJECT|PRERELEASE|VERSION): ' "$file" | grep -v 'needs.preflight.outputs.' |
        sed 's/^/not mapped from the preflight outputs: /' || true
}

workflow_rules() {
    local violations

    [ -f "$workflow" ] || fail "$workflow does not exist"
    violations=$(workflow_violations "$workflow")
    if [ -n "$violations" ]; then
        echo "$violations" >&2
        fail "the workflow breaks its rules"
    fi
}

workflow_rules_detect_violations() {
    local mutation mutated="$scratch/mutated.yml"
    # The sed programs hold a literal ${{ }} expression, which is not a shell expansion.
    # shellcheck disable=SC2016
    local mutations=(
        '0,/@[0-9a-f]\{40\}/s//@main/'
        's/^    tags: .*/&\n  pull_request:/'
        '/^permissions: {}$/d'
        '0,/contents: read/s//contents: write/'
        's/^defaults:/cache: true\ndefaults:/'
        '0,/persist-credentials: false/{/persist-credentials: false/d}'
        '0,/ubuntu-24.04/s//ubuntu-latest/'
        's/^\( *\)RELEASE_SIGNING_KEY: .*/&\n\1COPY: ${{ secrets.RELEASE_SIGNING_KEY }}/'
        '/^ *TAG_OBJECT: /d'
        's/^\( *\)PRERELEASE: .*/\1PRERELEASE: true/'
    )

    [ -f "$workflow" ] || fail "$workflow does not exist"
    for mutation in "${mutations[@]}"; do
        sed "$mutation" "$workflow" >"$mutated"
        if cmp -s "$workflow" "$mutated"; then
            fail "the mutation changed nothing: $mutation"
        fi
        if [ -z "$(workflow_violations "$mutated")" ]; then
            fail "no rule caught the mutation: $mutation"
        fi
    done
}

run_case workflow_rules
run_case workflow_rules_detect_violations
