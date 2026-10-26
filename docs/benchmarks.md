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

## Cache memory after v0.1.0

Measured on a WSL2 x86_64 box with static musl release builds (built like the release binaries), the
v0.1.0 lists (HaGeZi Pro and TIF mini, about 420k rules) and a fake UDP upstream that answers every
query. The cache is the default 10,000 entries. RSS is `RssAnon` after replaying 12,000 unique
queries of the real-network file, which fills the cache and evicts a few hundred entries. Boot is
3.75 MB of `RssAnon` in both builds.

| Build | `RssAnon` with a full cache (three runs) | Per cached entry |
|---|---|---|
| v0.1.0 (3 allocations per entry, `lru` crate) | 14.3, 14.2, 15.6 MB | about 1.1 KB |
| One allocation per entry, index-linked LRU | 8.3, 10.9, 10.8 MB | about 0.6 KB |

A single 30,000-query run gave 13.7 MB before and 8.8 MB after. The run-to-run spread (2 to 3 MB)
comes from how the allocator fragments under concurrent misses; the improvement is larger than the
spread in every run.

`opt-level = "s"` was tried on top of this and not adopted. The binary shrinks from 4.48 to 3.47 MB
and CPU per query is within noise end to end (`Engine::check` is 7 to 8% slower), but the same replay gave 14.0, 11.8 and 12.7 MB of
`RssAnon`, about 2.8 MB more than `opt-level = 3` on average. Only `RssFile` gets smaller, by under
1 MB. Measure it on an ARM board before trying again.

The allocator behind these numbers is the one `cargo zigbuild` links: with zig 0.17 the static musl
binaries call Zig's own `malloc` (`SmpAllocator`), not musl's `mallocng`. Memory after a burst of
misses depends on that allocator, so measure again when the zig version of the release build
changes.

## Merged build, default lists (2026-10-26)

The same static musl build at commit 480e34d, after the cache change (the later review fixes do not
touch the cache), on a busy WSL2 x86_64 box with a fake UDP upstream. Medians of three runs:

| Workload | Empty cache (RSS) | Full 10,000-entry cache (RSS) | Peak |
|---|---|---|---|
| AdGuard DNS filter + HaGeZi Pro + TIF mini, 49,389 A/AAAA queries | 10.0 MB | 15.0 MB (14.8 to 16.5) | 15.0 MB |
| The numa comparison lists (about 450k rules), 52,137 queries | 9.8 MB | 15.8 MB (14.1 to 16.0) | 15.8 MB |

Before the cache change the first workload ended at 19.3 MB. `RssFile` moved between 1.5 and 3.4 MB
from run to run on this box, so differences under 2 MB are noise. The CPU time of these runs is not
comparable with the numa table above, because the upstream here is a fake one on the same machine.
