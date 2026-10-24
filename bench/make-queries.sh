#!/bin/sh
# Turn an AdGuard Home querylog.json into a file of unique "name type" pairs
# for replay.sh. querylog.json holds one JSON object per line.
#
# Usage: make-queries.sh <querylog.json> [output-file]
#
# The default output is queries.txt in the current directory. Needs only
# POSIX sh, sed, awk and sort (BusyBox is fine). Names are lowercased and a
# trailing dot is removed.
#
# The log is private: it shows what your network looks up. Keep the result
# out of version control.

set -eu

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <querylog.json> [output-file]" >&2
    exit 2
fi

input=$1
output=${2:-queries.txt}

# AdGuard Home writes the question as "QH":"example.com" and then "QT":"A"
# on each line. Lines without both are skipped.
sed -n 's/.*"QH":"\([^"]*\)".*"QT":"\([A-Za-z0-9]*\)".*/\1 \2/p' "$input" \
    | awk '{
        name = tolower($1)
        sub(/\.$/, "", name)
        if (name != "") {
            print name, toupper($2)
        }
    }' \
    | sort -u >"$output"

echo "$(wc -l <"$output" | tr -d ' ') unique queries in $output"
