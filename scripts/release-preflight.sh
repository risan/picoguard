#!/usr/bin/env bash
# Usage: release-preflight.sh <tag> <object-type> <peeled-commit> [manifest]
#
# Fails unless the tag is an annotated tag on $GITHUB_SHA whose name is "v" plus
# the manifest version. Prints version= and prerelease= lines for $GITHUB_OUTPUT.
set -euo pipefail

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
    echo "usage: $0 <tag> <object-type> <peeled-commit> [manifest]" >&2
    exit 2
fi

tag=$1
object_type=$2
peeled_commit=$3
manifest=${4:-Cargo.toml}

if [ "$object_type" != "tag" ]; then
    echo "error: $tag is a $object_type, not an annotated tag; create it with git tag -a" >&2
    exit 1
fi

if [ "$peeled_commit" != "${GITHUB_SHA:-}" ]; then
    echo "error: $tag points to $peeled_commit, but this run builds ${GITHUB_SHA:-nothing}" >&2
    exit 1
fi

if ! [[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "error: tag $tag is not of the form vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-prerelease" >&2
    exit 1
fi

version=$(awk '
    /^\[/ { in_package = ($0 == "[package]"); next }
    in_package && $1 == "version" && $2 == "=" { gsub(/"/, "", $3); print $3; exit }
' "$manifest")

if [ -z "$version" ]; then
    echo "error: no version in the [package] table of $manifest" >&2
    exit 1
fi

if [ "$tag" != "v$version" ]; then
    echo "error: tag $tag does not match version $version in $manifest (expected v$version)" >&2
    exit 1
fi

prerelease=false
if [[ $version == *-* ]]; then
    prerelease=true
fi

echo "version=$version"
echo "prerelease=$prerelease"
