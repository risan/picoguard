# picoguard

picoguard is a DNS ad and malware blocker written in Rust. It runs on a cheap 256 MB ARM board
(Orange Pi Zero class) and uses very little memory, CPU and SD-card wear. It forwards queries to
encrypted upstreams (DoH, DoT), blocks names with the popular blocklist formats, and keeps its
query log and statistics in memory only.

## Why

A home DNS blocker should fit on a 256 MB board where every MB counts, and should not wear out an
SD card. picoguard was built to use less than half the memory and CPU of numa, another blocker
that we tried first, while reading every popular blocklist format correctly. On the same lists (about 450k
domains), the same 10,000-entry cache and the same replay of 52,137 real queries (x86_64
container, 2026-10-25):

| | picoguard | numa v0.25.0 |
|---|---|---|
| Steady RSS | 16.2 MB | 45.3 MB |
| Peak RSS | 16.3 MB | 58.5 MB |
| CPU seconds, cold replay | 8.4 s | 66.1 s |

For scale: AdGuard Home v0.107.79 used 80–93 MB RSS with only the AdGuard DNS filter (~191k
rules) on two home LXC containers (2026-10-24, not the same workload, so not a benchmark).
AdGuard Home is the reference for blocking decisions, not for memory. A plain domain rule costs
picoguard about 8 bytes. Details, method and open measurements:
[docs/benchmarks.md](docs/benchmarks.md).

## Features

- DNS on UDP and TCP port 53 for all record types. Blocking applies to every type of a blocked
  name, and to CNAME targets and answer addresses (catches CNAME cloaking).
- Encrypted upstreams: DoH and DoT, several servers with load balancing and failover, bootstrapped
  from fixed IPs, connections kept open. On CPUs without hardware AES it prefers ChaCha20-Poly1305.
- Six blocklist formats, detected per list: adblock/AdGuard DNS syntax, hosts, plain domains,
  wildcard domains, dnsmasq and RPZ. Same block and allow decisions as AdGuard Home v0.107.79.
- Lists download on a schedule with ETag / If-Modified-Since. A failed download keeps the last
  good list. A new list takes effect without a restart.
- A small status page: totals, top blocked domains, top clients, recent queries, list status, and
  a pause button. Totals and list status are open on the LAN; the rest needs `web.user` and
  `web.password`.
- Almost no disk writes: no query log, no stats file. The only routine write is the last-good
  copy of a list, only when it changed, and it can be turned off.
- Static binaries for ARMv7, ARM64 and x86_64 Linux, and a systemd unit.
- One TOML file for all settings.

Not included: DHCP (your router does that), serving DoH/DoT to your devices, per-client rules,
DNS rewriting, DNSSEC validation.

## Documentation

- [docs/install.md](docs/install.md): install on a used TV box, an Orange Pi Zero, or a Proxmox
  LXC / x86_64 Linux, point your router at it, and make the SD card last.
- [docs/configuration.md](docs/configuration.md): every config key, list formats, and lists for
  256 MB, 512 MB and 1 GB boards.
- [docs/benchmarks.md](docs/benchmarks.md): measurements against numa, method, open measurements.
- [bench/README.md](bench/README.md): rerun the benchmark.
- [dist/picoguard.toml](dist/picoguard.toml) and [dist/picoguard.service](dist/picoguard.service):
  example config and systemd unit.
- [tools/README.md](tools/README.md): the AdGuard Home oracle tools behind the compatibility tests.

## Status

Pre-release. Version 0.1.0 is coming. Measured so far on x86_64 only. ARM board numbers are still
open.

## Known differences from AdGuard Home

picoguard makes the same block/pass decision as AdGuard Home v0.107.79 on the same lists
(checked against the AdGuard Home binary, see `tools/README.md`), with these exceptions:

- Overlapping `$badfilter` rules. urlfilter v0.23.4 brings a rule back when two badfilter
  rules match the same name, so the badfilter stops working. picoguard disables every
  targeted rule.
- `$denyallow=name.*` (a top-level-domain wildcard) checks the suffix against a short built-in
  list of public suffixes, where urlfilter uses the full ICANN list.
- `$dnsrewrite` and `$respgeo` rules are counted and ignored, and `$client` / `$ctag` rules
  match as for a client without a name or tag (restrictions with `~` apply, permitted values
  never do).
- A hosts line with a real address (`203.0.113.7 name`) in a downloaded list (`url`) blocks the
  name like `0.0.0.0 name` instead of answering with that address, so a compromised list cannot
  redirect names. AdGuard Home answers with the address. Set `allow_redirects = true` on the list
  to get that back; lists with `path` and the `rules` key always answer with the address.
- A list in `[[lists]]` that blocks any of three made-up names (`||*^`, `/./`) is refused and the
  last good copy stays; AdGuard Home would install it and block everything.
- IP addresses of a host rule that appears on several lines of one list are answered grouped
  by address, not in line order.
- Non-ASCII input names are compared after lowercase only. Go folds case with the Unicode
  simple folding table (`σ` and `ς`, `ſ` and `s` match each other in a `(?i)` rule); picoguard
  does not. DNS names arrive as ASCII (punycode), so this only affects rules written in Unicode.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
