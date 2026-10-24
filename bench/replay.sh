#!/bin/sh
# Replay a list of DNS queries against a running resolver and measure the
# resolver process. Works with BusyBox sh (no bashisms, no split -n).
#
# Usage: replay.sh <label> <process-name> [port]
#
#   label         names the run in the output ("picoguard-cold")
#   process-name  the resolver process, found with pidof ("picoguard", "numa")
#   port          DNS port on 127.0.0.1 (default 53)
#
# Environment:
#   QUERIES   file with one "name type" per line (default: queries.txt in the
#             current directory; make it with make-queries.sh)
#   CLIENTS   number of parallel dig clients (default 16)
#   OUT_DIR   where raw results go (default: a new directory under /tmp)
#
# Run it as the user that owns the resolver (or root): it reads /proc/<pid>.
# Run it twice in a row for a cold and a warm replay.

set -eu

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <label> <process-name> [port]" >&2
    exit 2
fi

label=$1
process=$2
port=${3:-53}
queries=${QUERIES:-queries.txt}
clients=${CLIENTS:-16}
out_dir=${OUT_DIR:-$(mktemp -d "/tmp/replay-$label.XXXXXX")}

if [ ! -s "$queries" ]; then
    echo "$0: query file $queries is missing or empty" >&2
    exit 2
fi

pid=$(pidof "$process" | awk '{ print $1 }')
if [ -z "$pid" ]; then
    echo "$0: no process named $process" >&2
    exit 2
fi

ticks_per_second=$(getconf CLK_TCK 2>/dev/null || echo 100)
mkdir -p "$out_dir"

proc_kb() {
    awk -v key="$1:" '$1 == key { print $2 }' "/proc/$pid/status"
}

cpu_ticks() {
    # Drop "pid (comm) " first, because the name can hold spaces. Then utime
    # and stime are fields 12 and 13.
    sed 's/^.*) //' "/proc/$pid/stat" | awk '{ print $12 + $13 }'
}

write_bytes() {
    awk '$1 == "write_bytes:" { print $2 }' "/proc/$pid/io" 2>/dev/null || echo 0
}

sample_rss() {
    while :; do
        proc_kb VmRSS >>"$out_dir/rss.samples"
        sleep 1
    done
}

total=$(wc -l <"$queries" | tr -d ' ')
per_client=$(( (total + clients - 1) / clients ))
split -l "$per_client" "$queries" "$out_dir/part."

rss_before=$(proc_kb VmRSS)
ticks_before=$(cpu_ticks)
written_before=$(write_bytes)
started=$(date +%s)

: >"$out_dir/rss.samples"
sample_rss &
sampler=$!
trap 'kill "$sampler" 2>/dev/null || true' EXIT INT TERM

client_pids=""
for part in "$out_dir"/part.*; do
    dig @127.0.0.1 -p "$port" +tries=1 +time=5 +noall +comments -f "$part" \
        >"$part.out" 2>&1 &
    client_pids="$client_pids $!"
done

for client_pid in $client_pids; do
    wait "$client_pid" || true
done

finished=$(date +%s)
kill "$sampler" 2>/dev/null || true
trap - EXIT INT TERM

ticks_after=$(cpu_ticks)
written_after=$(write_bytes)
rss_after=$(proc_kb VmRSS)
peak_kb=$(proc_kb VmHWM)
rss_max=$(sort -n "$out_dir/rss.samples" | tail -n 1)
rss_max=${rss_max:-$rss_after}

cat "$out_dir"/part.*.out >"$out_dir/all.out"
timeouts=$(grep -c -e 'timed out' -e 'no servers could be reached' "$out_dir/all.out" || true)
cpu_seconds=$(awk -v ticks="$((ticks_after - ticks_before))" -v hz="$ticks_per_second" \
    'BEGIN { printf "%.1f", ticks / hz }')

echo "label:            $label"
echo "process:          $process (pid $pid), port $port"
echo "queries:          $total, $clients clients"
echo "wall seconds:     $((finished - started))"
echo "cpu seconds:      $cpu_seconds"
echo "rss before (kB):  $rss_before"
echo "rss after (kB):   $rss_after"
echo "rss max sampled:  $rss_max kB"
echo "VmHWM peak (kB):  $peak_kb"
echo "disk writes (B):  $((written_after - written_before))"
echo "client timeouts:  $timeouts"
echo "status counts:"
grep -o 'status: [A-Z]*' "$out_dir/all.out" | sort | uniq -c | sort -rn | sed 's/^/  /'
echo "raw files:        $out_dir"
