#!/usr/bin/env bash
# Prints the path of the pinned AdGuard Home v0.107.79 linux/amd64 binary, downloading it
# first when needed.
#
# The release tarball is cached in ~/.cache/picoguard-oracle (outside the repository) and
# checked against the pinned SHA-256 (the value in the release's checksums.txt) before it is
# unpacked.
set -euo pipefail

version="v0.107.79"
sha256="c48f4a43000665484c5ec28177de11a004759b620dae8f77b2aabefc9ef3687f"
url="https://github.com/AdguardTeam/AdGuardHome/releases/download/$version/AdGuardHome_linux_amd64.tar.gz"

cache="${PICOGUARD_ORACLE_CACHE:-$HOME/.cache/picoguard-oracle}"
tarball="$cache/AdGuardHome_${version}_linux_amd64.tar.gz"
unpacked="$cache/AdGuardHome_$version"

mkdir -p "$cache"
if [ ! -x "$unpacked/AdGuardHome" ]; then
    if [ ! -f "$tarball" ]; then
        curl -sSfL -o "$tarball.part" "$url"
        mv "$tarball.part" "$tarball"
    fi

    echo "$sha256  $tarball" | sha256sum --check --status || {
        echo "error: $tarball does not match the pinned SHA-256" >&2
        exit 1
    }

    rm -rf "$unpacked.part"
    mkdir -p "$unpacked.part"
    tar -xzf "$tarball" -C "$unpacked.part" --strip-components=2 ./AdGuardHome/AdGuardHome
    mv "$unpacked.part" "$unpacked"
fi

echo "$unpacked/AdGuardHome"
