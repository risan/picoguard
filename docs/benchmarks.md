# Benchmarks

Measured on 2026-10-25 against numa v0.25.0 and picoguard at commit c547117. These are x86_64
numbers from a container. Nothing was measured on an ARM board yet (see "Open measurements").

## Results

| Metric | numa v0.25.0 | picoguard | Ratio |
|---|---|---|---|
| RSS after lists load | 36.6 MB | 10.1 MB | 3.6x lower |
| Steady RSS after the replay (`VmRSS`) | 45.3 MB | 16.2 MB | 2.8x lower |
| Peak RSS (`VmHWM`) | 58.5 MB | 16.3 MB | 3.6x lower |
| CPU seconds, cold replay | 66.1 s | 8.4 s | 7.9x lower |
| CPU seconds, second replay (cache holds 10k entries, so mostly misses again) | not measured | 8.3 s | |
| Time to blocking after start | about 20 s | about 1 s | |
| Disk writes at first start | 12.4 MB | 4.9 MB (3 list snapshots) | |
| Disk writes during the replay | 0 | about 100 KB (warning lines for upstream timeouts, since rate-limited) | |
| SERVFAIL / client timeouts | 139 / 4 | 135 / 0 | |
| `RssFile` (binary pages in memory) | 8.1 MB | 3.8 MB | |

The project targets were: steady RSS at most half of numa (22 MB), peak at most half (29 MB), CPU
at most half (33 s). All three were met.

Memory per rule: about 8 bytes for a plain domain rule. The three lists below hold about 450k
rules, which is about 3.6 MB of rule arrays.

## Method

- **Box.** Proxmox container 104, Alpine 3.24, x86_64, 1 core, 256 MB RAM, no swap. Each server ran
  alone on port 53.
- **Workload.** 52,137 unique (name, type) pairs from the AdGuard Home query log of a real home
  network. They were replayed by 16 parallel `dig -f` clients with
  [`bench/replay.sh`](../bench/replay.sh). The query file comes from
  [`bench/make-queries.sh`](../bench/make-queries.sh).
- **Lists (same for both).** AdGuard DNS filter, HaGeZi Pro (`wildcard/pro-onlydomains`) and HaGeZi
  TIF mini (`wildcard/tif.mini-onlydomains`). numa reported 450,888 unique domains.
- **Upstreams.** The same four DoH servers, by IP.
- **Cache.** 10,000 entries, minimum TTL 60 s. Log level `warn`.
- **Measured from `/proc/<pid>`.** `VmRSS` (steady) and `VmHWM` (peak) from `status`, CPU seconds
  as utime plus stime from `stat`, disk writes from `io` (`write_bytes`).
- **Cold replay** is the first run after the server starts, with an empty cache.

How to rerun it: [bench/README.md](../bench/README.md).

## Open measurements

Not measured yet:

- **ARM boards.** ARMv7 (Orange Pi Zero) and ARM64 (TV box) numbers for RSS, CPU and latency. The
  goals there are steady RSS of at most 20 MB and a peak during a refresh of at most 28 MB.
- **Peak during a list refresh** when a list has changed. The expected cost is about 2 MB more
  per list being refreshed.
- **Latency during a refresh.** Replay while the largest list refreshes with changed content:
  p99 for cached answers and the number of lost queries. The goal is no lost queries and p99
  under 2 ms for cached answers.
- **Saturation.** A flood of unique names over UDP and 16 TCP clients; RSS should stay at or
  below 28 MB.
- **Memory per extra 100k domains.** Expected near 0.8 MB of rule arrays plus the list's parse
  scratch during a refresh.
- **Disk writes over 24 hours** with unchanged lists (the goal is 0 bytes), measured on a board.
