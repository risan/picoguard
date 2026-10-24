#!/usr/bin/env bash
# Regenerates every golden file from the AdGuard Home oracles.
#
#   tools/regen.sh            matcher goldens (agh-oracle), then full-flow golden (agh-flow)
#   tools/regen.sh oracle     matcher goldens only (no network, needs Go)
#   tools/regen.sh flow       full-flow golden only (downloads AdGuard Home once)
#
# The tools are GPL-3.0 and dev-only; the generated files are committed.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
golden="$root/tests/fixtures/golden"
lists="$root/tests/fixtures/lists"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mode="${1:-all}"

# Prints the agh-oracle arguments for a split case directory.
oracle_args() {
    local dir="$1" f
    for f in "$dir"/main-*.txt; do [ -e "$f" ] && echo "-list $f"; done
    [ -e "$dir/user.txt" ] && echo "-user $dir/user.txt"
    for f in "$dir"/allow-*.txt; do [ -e "$f" ] && echo "-allow $f"; done
    echo "-q $dir/queries.txt"
}

regen_oracle() {
    (cd "$root/tools/agh-oracle" && go build -o "$work/agh-oracle" .)

    for case_file in "$golden"/cases/*.case; do
        name="$(basename "$case_file" .case)"
        "$root/tools/split-case.sh" "$case_file" "$work/$name"
        # shellcheck disable=SC2046
        "$work/agh-oracle" $(oracle_args "$work/$name") > "$golden/cases/$name.expected"
        echo "oracle: $name ($(wc -l < "$golden/cases/$name.expected") queries)"
    done

    "$work/agh-oracle" \
        -list "$lists/adguard-dns.txt.gz" \
        -list "$lists/hagezi-pro.txt.gz" \
        -list "$lists/hagezi-tif-mini.txt.gz" \
        -q "$golden/real/queries.txt" > "$golden/real/expected.txt"
    echo "oracle: real ($(wc -l < "$golden/real/expected.txt") queries)"
}

regen_flow() {
    "$root/tools/agh-flow/run.sh"
}

case "$mode" in
    all) regen_oracle; regen_flow ;;
    oracle) regen_oracle ;;
    flow) regen_flow ;;
    *) echo "usage: tools/regen.sh [all|oracle|flow]" >&2; exit 2 ;;
esac
