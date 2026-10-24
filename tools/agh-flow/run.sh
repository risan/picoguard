#!/usr/bin/env bash
# Records the full-flow golden file with the pinned AdGuard Home release.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
agh="$("$root/tools/agh-flow/fetch.sh")"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
(cd "$root/tools/agh-flow" && go build -o "$work/agh-flow" .)

"$work/agh-flow" \
    -agh "$agh" \
    -case "$root/tests/fixtures/golden/flow/flow.case" \
    -out "$root/tests/fixtures/golden/flow/flow.expected"
echo "flow: $(grep -c '^Q ' "$root/tests/fixtures/golden/flow/flow.expected") queries"
