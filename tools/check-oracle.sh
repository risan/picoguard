#!/usr/bin/env bash
# Checks agh-oracle against the real AdGuard Home binary: both get the same lists and queries
# and must give the same block/pass decision and blocked answer. Queries the binary cannot be
# asked (a check type different from the query type, ANY) are left out of the comparison.
#
#   tools/check-oracle.sh [case-name ...]     default: every matcher case and the real lists
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
golden="$root/tests/fixtures/golden"
lists="$root/tests/fixtures/lists"
agh="$("$root/tools/agh-flow/fetch.sh")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
(cd "$root/tools/agh-flow" && go build -o "$work/agh-flow" .)

status=0

compare() {
    local name="$1" expected="$2" actual="$3"
    # Only two-field queries are replayed; keep those from the oracle output.
    LC_ALL=C awk 'NF == 4 && $2 != "ANY" && $1 !~ /[\200-\377]/' "$expected" > "$work/oracle.txt"
    # Differences that come from the test setup, not from matching: the binary knows its
    # client (127.0.0.1) and applies $dnsrewrite, the oracle does neither.
    case "$name" in
        modifiers) grep -v -E '^(client|rewrite|rewrite-cname)\.example ' "$work/oracle.txt" > "$work/o2.txt" || true
                   grep -v -E '^(client|rewrite|rewrite-cname)\.example ' "$actual" > "$work/a2.txt" || true
                   mv "$work/o2.txt" "$work/oracle.txt"; actual="$work/a2.txt" ;;
        *) ;;
    esac

    if diff -u "$work/oracle.txt" "$actual" > "$work/diff.txt"; then
        echo "ok: $name ($(wc -l < "$actual") queries)"
    else
        echo "DIFF: $name"
        head -40 "$work/diff.txt"
        status=1
    fi
}

cases=("$@")
if [ ${#cases[@]} -eq 0 ]; then
    for f in "$golden"/cases/*.case; do cases+=("$(basename "$f" .case)"); done
    cases+=(real)
fi

for name in "${cases[@]}"; do
    if [ "$name" = real ]; then
        "$work/agh-flow" -agh "$agh" \
            -list "$lists/adguard-dns.txt.gz" -list "$lists/hagezi-pro.txt.gz" \
            -list "$lists/hagezi-tif-mini.txt.gz" \
            -q "$golden/real/queries.txt" -out "$work/real.actual"
        compare real "$golden/real/expected.txt" "$work/real.actual"
        continue
    fi

    "$root/tools/split-case.sh" "$golden/cases/$name.case" "$work/$name"
    args=()
    for f in "$work/$name"/main-*.txt; do args+=(-list "$f"); done
    [ -e "$work/$name/user.txt" ] && args+=(-user "$work/$name/user.txt")
    for f in "$work/$name"/allow-*.txt; do [ -e "$f" ] && args+=(-allow "$f"); done
    "$work/agh-flow" -agh "$agh" "${args[@]}" -q "$work/$name/queries.txt" -out "$work/$name.actual"
    compare "$name" "$golden/cases/$name.expected" "$work/$name.actual"
done

exit "$status"
