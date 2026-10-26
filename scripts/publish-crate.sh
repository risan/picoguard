#!/usr/bin/env bash
# Usage: publish-crate.sh [--decide] <version> <prerelease: true|false>
#
# A prerelease is only package-checked. A stable version is published unless
# crates.io already has it, because a re-run must publish only what is missing.
# --decide prints check-only, skip or publish and does nothing else.
set -euo pipefail

decide_only=false
if [ "${1:-}" = "--decide" ]; then
    decide_only=true
    shift
fi

if [ "$#" -ne 2 ] || { [ "$2" != true ] && [ "$2" != false ]; }; then
    echo "usage: $0 [--decide] <version> <true|false>" >&2
    exit 2
fi

version=$1
prerelease=$2
crate=${CRATE_NAME:-picoguard}

decide() {
    if [ "$prerelease" = true ]; then
        echo check-only
        return
    fi

    local status

    status=$(curl -sS -o /dev/null -w '%{http_code}' \
        -A 'picoguard-release (github.com/risan/picoguard)' \
        "https://crates.io/api/v1/crates/$crate/$version")

    case $status in
        200) echo skip ;;
        404) echo publish ;;
        *)
            echo "error: crates.io answered $status for $crate $version" >&2
            return 1
            ;;
    esac
}

decision=$(decide)

if [ "$decide_only" = true ]; then
    echo "$decision"
    exit 0
fi

case $decision in
    check-only)
        echo "prerelease $version: package check only, nothing is published to crates.io"
        ;;
    skip)
        echo "$crate $version is already on crates.io, nothing to publish"
        ;;
    publish)
        if [ -z "${CARGO_REGISTRY_TOKEN:-}" ]; then
            echo "error: CARGO_REGISTRY_TOKEN is not set, cannot publish $crate $version" >&2
            exit 1
        fi

        cargo publish --locked --no-verify
        ;;
esac
