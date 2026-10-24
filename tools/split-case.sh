#!/usr/bin/env bash
# Splits a matcher .case file into main-N.txt, user.txt, allow-N.txt and queries.txt files
# in the given directory. Usage: tools/split-case.sh CASE_FILE OUT_DIR
set -euo pipefail

mkdir -p "$2"
awk -v dir="$2" '
    /^\[(main|user|allow|queries|deviations)\]$/ {
        section = substr($0, 2, length($0) - 2)
        if (section == "main") { main++; out = dir "/main-" main ".txt" }
        else if (section == "allow") { allow++; out = dir "/allow-" allow ".txt" }
        else if (section == "user") { out = dir "/user.txt" }
        else if (section == "queries") { out = dir "/queries.txt" }
        else { out = "/dev/null" }
        printf "" > out
        next
    }
    out != "" { print > out }
' "$1"
