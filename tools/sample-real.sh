#!/usr/bin/env bash
# Samples the queries for the real-list golden test (tests/fixtures/golden/real).
# Run once after the list fixtures change; regen.sh then recomputes the answers.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
lists="$root/tests/fixtures/lists"
out="$root/tests/fixtures/golden/real/queries.txt"
bin="$(mktemp)"
trap 'rm -f "$bin"' EXIT

mkdir -p "$(dirname "$out")"
(cd "$root/tools/agh-oracle" && go build -o "$bin" .)
"$bin" sample -seed 20261024 -n "${1:-3000}" \
    "$lists/adguard-dns.txt.gz" "$lists/hagezi-pro.txt.gz" "$lists/hagezi-tif-mini.txt.gz" > "$out"
echo "$(wc -l < "$out") queries in $out"
