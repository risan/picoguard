#!/usr/bin/env bash
# Usage: RELEASE_SIGNING_KEY=<base64 of the PKCS#8 DER private key> \
#            sign-release.sh <release-dir> [public-key]
#
# Signs <release-dir>/SHA256SUMS with the Ed25519 release key and writes the raw
# 64-byte signature to <release-dir>/SHA256SUMS.sig, but only after proving that
# the key matches the public key file and that the signature verifies for the
# real file and fails for a modified copy. Never prints key material.
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 <release-dir> [public-key]" >&2
    exit 2
fi

release_dir=$1
public_key=${2:-$(dirname "$0")/../dist/release-key.der}
sums="$release_dir/SHA256SUMS"
signature="$release_dir/SHA256SUMS.sig"

die() {
    echo "error: $*" >&2
    exit 1
}

rm -f "$signature"

[ -f "$sums" ] || die "$sums does not exist"
[ -f "$public_key" ] || die "public key file $public_key does not exist"

[ -n "${RELEASE_SIGNING_KEY:-}" ] || die "RELEASE_SIGNING_KEY is not set or is empty"

umask 077
work_dir=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/sign-release.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT

# Every command that reads the key has its stderr discarded: an error message
# must never echo key material into a log.
printf '%s' "$RELEASE_SIGNING_KEY" | base64 -d >"$work_dir/key.der" 2>/dev/null ||
    die "RELEASE_SIGNING_KEY is not valid base64"

openssl pkey -inform DER -in "$work_dir/key.der" -pubout -outform DER \
    -out "$work_dir/derived-public.der" 2>/dev/null ||
    die "RELEASE_SIGNING_KEY is not a DER private key"

cmp -s "$work_dir/derived-public.der" "$public_key" ||
    die "RELEASE_SIGNING_KEY does not match the public key file $public_key"

openssl pkeyutl -sign -keyform DER -inkey "$work_dir/key.der" -rawin \
    -in "$sums" -out "$work_dir/SHA256SUMS.sig" 2>/dev/null ||
    die "signing failed"
rm -f "$work_dir/key.der"

[ "$(stat -c %s "$work_dir/SHA256SUMS.sig")" -eq 64 ] ||
    die "the signature is not 64 bytes"

verify() {
    openssl pkeyutl -verify -pubin -inkey "$public_key" -keyform DER \
        -rawin -in "$1" -sigfile "$work_dir/SHA256SUMS.sig"
}

verify "$sums" || die "the signature does not verify against $public_key"

cp "$sums" "$work_dir/modified-SHA256SUMS"
printf '\n' >>"$work_dir/modified-SHA256SUMS"
if verify "$work_dir/modified-SHA256SUMS" >/dev/null 2>&1; then
    die "a modified SHA256SUMS verified: the self-check is broken"
fi

echo "ok: a modified SHA256SUMS fails verification"

mv "$work_dir/SHA256SUMS.sig" "$signature"
