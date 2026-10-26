# picoguard

picoguard blocks ads, trackers and malware for your whole network at the DNS level. It is a small
Rust program that fits on a cheap 256 MB ARM board, an old TV box or a tiny Proxmox container. It
makes the same block decisions as AdGuard Home on the same lists, with a fraction of the memory.

## Quick start

Pick one path. Each one asks a few questions, then prints the address to give to your router.

| You have | Run | Details |
|---|---|---|
| A board (TV box, Orange Pi, Raspberry Pi 2+) or any Linux VM | `sudo sh install.sh` | [install.sh](docs/install.md#install-on-a-board-or-vm-with-installsh) |
| A Proxmox VE host | `bash proxmox-lxc.sh` (on the host) | [Proxmox LXC](docs/install.md#install-in-a-proxmox-lxc) |
| A machine that already runs Docker | `docker compose up -d --build` | [Docker](docs/install.md#run-in-docker) |

The repository is private for now, so get the release files with the GitHub CLI first
(`gh auth login` once):

```sh
gh release download -R risan/picoguard -p 'picoguard-*' -p SHA256SUMS -p install.sh -p proxmox-lxc.sh
sudo sh install.sh            # on a board or VM
bash proxmox-lxc.sh           # or: on the Proxmox host, creates an Alpine container
```

Once the repository is public, one line is enough:

```sh
curl -fsSL https://github.com/risan/picoguard/releases/latest/download/install.sh | sudo sh
```

Then:

1. Set the picoguard address as the DNS server in your router's DHCP settings
   ([how](docs/install.md#3-point-your-network-at-picoguard)).
2. Open the status page at `http://<address>:8080/` and log in as `admin` with the password the
   installer printed.

To update, run `install.sh` again. It keeps your config, and it puts the old version back if the
new one does not answer ([details](docs/install.md#update-picoguard)).

## What it blocks

The default lists are the [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter)
(the AdGuard Home default), [HaGeZi Pro](https://github.com/hagezi/dns-blocklists) (ads, trackers,
telemetry) and HaGeZi Threat Intelligence Feeds mini (malware, phishing, scam).

We replayed 52,137 real queries of one household through AdGuard's own matching engine with each
candidate list set (2026-10-26):

| Lists | Names blocked | picoguard memory, empty cache |
|---|---|---|
| AdGuard DNS filter only (the AdGuard Home default) | 2,225 | — |
| HaGeZi Pro + TIF mini | 2,525, but misses 84 that AdGuard blocks | 8.2 MB |
| **AdGuard DNS + HaGeZi Pro + TIF mini (default)** | **2,606, misses none** | **11.4 MB (19.3 MB with a full cache)** |
| OISD big, OISD small or StevenBlack alone | 450 to 1,135 | — |

So on the same lists picoguard blocks exactly what AdGuard Home blocks. With its default lists it
blocks more: about 380 extra names, mostly telemetry and trackers. DNS blocking cannot remove ads
that are served from the same names as the content (YouTube video ads, for example); no DNS
blocker can.

Six list formats are read and detected per list: adblock/AdGuard DNS syntax, hosts, plain
domains, wildcard domains, dnsmasq and RPZ. To change lists, see
[Choose lists for your board](docs/configuration.md#choose-lists-for-your-board).

## Memory and speed

On the same lists (about 450k rules), the same 10,000-entry cache and the same replay of 52,137
real queries (x86_64 container, 2026-10-25):

| | picoguard | numa v0.25.0 |
|---|---|---|
| Steady memory (RSS) | 16.2 MB | 45.3 MB |
| Peak memory | 16.3 MB | 58.5 MB |
| CPU for the replay | 8.4 s | 66.1 s |

AdGuard Home v0.107.79 used 80–93 MB on two home containers with only the AdGuard DNS filter (not
the same workload, so not a benchmark). Details and method: [docs/benchmarks.md](docs/benchmarks.md).

## Replacing AdGuard Home

What stays the same:

- The block and allow decisions on the same lists. This was checked on 16 popular lists and
  13.5 million queries against AdGuard's own engine, with zero differences.
- Blocked names get `0.0.0.0` / `::` like AdGuard Home's default blocking mode. CNAME targets and
  answer addresses are checked too (this catches CNAME cloaking).
- Encrypted upstreams (DoH, DoT) with several servers, a cache, local names via your router, and a
  status page with the query log and a pause button.

Move your settings from `AdGuardHome.yaml` to `/etc/picoguard/picoguard.toml`:

| AdGuard Home | picoguard |
|---|---|
| `filters` | `[[lists]]` with `url` |
| `whitelist_filters` | `[[allowlists]]` |
| `user_rules` | `rules = [...]` |
| `upstream_dns` | `[upstream] servers` |
| `local_ptr_upstreams`, private domains | `[local] resolver` |

Not included: DHCP (your router does it), serving DoH/DoT to your devices, per-client settings,
DNS rewrites, parental control and safe search, blocked-services toggles, query log on disk,
DNSSEC validation, editing settings from the web page (edit the TOML file).

For redundancy, run two picoguard instances (for example two containers, or a board and a
container) and give both addresses to your router as primary and secondary DNS.

## Features

- DNS on UDP and TCP port 53, for all record types.
- Encrypted upstreams: DoH and DoT, load balanced with failover, bootstrapped from fixed IPs. On
  CPUs without hardware AES it prefers ChaCha20-Poly1305.
- Lists download on a schedule with ETag / If-Modified-Since, and a new list takes effect without
  a restart. A failed download, a list that is too big, or a list that blocks everything keeps the
  last good copy.
- Status page: totals and list status for everyone on the LAN; query log, top lists and pause
  only with the password.
- Almost no disk writes: the query log and statistics live in memory. The only routine write is
  the last good copy of a list, only when it changed, and it can be turned off.
- Hardened service: its own system user, port 53 as the only privilege, and a systemd sandbox.
- Static binaries for ARMv7, ARM64 and x86_64 Linux. One TOML file for all settings.

## Documentation

- [docs/install.md](docs/install.md): the three install paths, a manual install, pointing your
  network at picoguard, making the SD card last, troubleshooting.
- [docs/configuration.md](docs/configuration.md): every config key, the list formats, and which
  lists fit 256 MB, 512 MB and 1 GB.
- [docs/benchmarks.md](docs/benchmarks.md): measurements and method.
- [dist/](dist/): example config, systemd unit, OpenRC script, Docker config.
- [tools/README.md](tools/README.md): the AdGuard Home oracle tools behind the compatibility tests.

## Status

Version 0.1.0 is released (private). Measured on x86_64 so far; numbers from a real ARM board
are still to come.

## Known differences from AdGuard Home

picoguard makes the same block/pass decision as AdGuard Home v0.107.79 on the same lists
(checked against the AdGuard Home binary, see `tools/README.md`), with these exceptions. The
first four are on purpose, for safety on a small board.

- A hosts line with a real address (`203.0.113.7 name`) in a downloaded list (`url`) blocks the
  name like `0.0.0.0 name` instead of answering with that address, so a compromised list cannot
  redirect names. AdGuard Home answers with the address. Set `allow_redirects = true` on the list
  to get that back; lists with `path` and the `rules` key always answer with the address.
- A list in `[[lists]]` that blocks any of three made-up names (`||*^`, `/./`) is refused and the
  last good copy stays; AdGuard Home would install it and block everything.
- A list with more than `max_rules` rules (default 1.5 million) or more slow rules than
  `slow_rule_budget` allows is refused and the last good copy stays. AdGuard Home has no limit.
- Wildcard, dnsmasq and RPZ files are read by what their format means. AdGuard Home reads every
  file as adblock syntax and so blocks much less with them (nothing at all with dnsmasq and RPZ
  files). Adblock-format lists, the common case, give the same result in both.
- Overlapping `$badfilter` rules. urlfilter v0.23.4 brings a rule back when two badfilter
  rules match the same name, so the badfilter stops working. picoguard disables every
  targeted rule.
- `$denyallow=name.*` (a top-level-domain wildcard) checks the suffix against a short built-in
  list of public suffixes, where urlfilter uses the full ICANN list.
- `$dnsrewrite` and `$respgeo` rules are counted and ignored, and `$client` / `$ctag` rules
  match as for a client without a name or tag (restrictions with `~` apply, permitted values
  never do).
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
