# Benchmark scripts

Two POSIX `sh` scripts. They also run under BusyBox (Alpine, Armbian minimal, OpenWrt).

| Script | What it does |
|---|---|
| `make-queries.sh <querylog.json> [out]` | Takes an AdGuard Home `querylog.json` and writes the unique `name TYPE` pairs, one per line (`queries.txt` by default). |
| `replay.sh <label> <process-name> [port]` | Splits the query file over 16 parallel `dig -f` clients, sends it to `127.0.0.1:<port>`, and measures the resolver process through `/proc`. |

`replay.sh` prints one block per run:

- wall seconds and CPU seconds (utime + stime of the resolver, from `/proc/<pid>/stat`);
- `VmRSS` before and after, the largest `VmRSS` sampled each second, and `VmHWM` (the peak);
- bytes written to disk during the run (`write_bytes` from `/proc/<pid>/io`);
- client timeouts and a count of each DNS status (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, ...).

Environment: `QUERIES` (query file, default `queries.txt`), `CLIENTS` (default 16), `OUT_DIR` (raw
`dig` output and RSS samples, default a new directory in `/tmp`).

Needs `dig` (package `bind-tools` on Alpine, `dnsutils` or `bind9-dnsutils` on Debian), `pidof`,
`awk`, `sed`, `sort`, `split`. Run it as root or as the user that owns the resolver, so it can read
`/proc/<pid>/io`.

## Rerun the numa comparison on a Proxmox container

The numbers in [docs/benchmarks.md](../docs/benchmarks.md) came from a small Alpine container.
To repeat them:

1. **Container.** Create an Alpine container: 1 core, 256 MB RAM, no swap. Install `dig`
   (`apk add bind-tools`). Nothing else listens on port 53.
2. **Queries.** On the machine that runs AdGuard Home, copy `data/querylog.json` (in the
   AdGuard Home working directory). Run `make-queries.sh querylog.json queries.txt`. Copy
   `queries.txt` to the container. The log is private: do not publish it.
3. **Same settings for every server.** Use the same blocklists (the benchmark used AdGuard DNS
   filter, HaGeZi Pro and HaGeZi TIF mini), the same four DoH upstream IPs, a cache of 10,000
   entries, a minimum TTL of 60 s for numa, and log level `warn`. Set these in each server's
   own config file.
4. **One server at a time.** Stop the other server. Start the one under test, then wait until it
   has loaded its lists (picoguard: about 1 s from snapshots; numa: about 20 s). Note `VmRSS`
   from `/proc/<pid>/status` as "RSS after lists load".
5. **Cold replay.** `QUERIES=queries.txt ./replay.sh numa-cold numa 53`
6. **Second replay.** Run the same command again with a new label. The cache only holds 10,000
   entries, so most of the 52,137 queries are misses again.
7. **Repeat** for `picoguard` (`./replay.sh picoguard-cold picoguard 53`). Restart the server
   between servers, not between the cold and the second replay.
8. **Compare** `cpu seconds`, `rss after`, `VmHWM peak`, `disk writes` and the status counts.
   `SERVFAIL` and timeouts should be similar. Many more of them in one server means it dropped
   or failed queries, and the CPU numbers are then not comparable.

`RssFile` (the binary's pages) is in `/proc/<pid>/status`. Read it too if you want to compare it.

Run each test more than once if the container shares its host with other work. CPU seconds are
steady, but wall time is not.
