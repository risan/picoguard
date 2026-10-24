# Real list fixtures

Downloaded on **2026-10-24** and stored gzip-compressed (`gzip -9 -n`). The tests read them
through `flate2`; the text is the list exactly as published.

| File | Source | Lines | SHA-256 of the text |
|---|---|---|---|
| `adguard-dns.txt.gz` | https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt (AdGuard DNS filter, version 1.0.84.3) | 191,441 | `b11c4fb36b598fa24ceb0be28ea6180b638fc222ec35e2ca796d4340390a6b0d` |
| `hagezi-pro.txt.gz` | https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt (version 2026.1024.0904.02) | 208,310 | `e01dc8c3ae3320b47b8ad8dec6ac2977e2f7acebe11941747278adb9daab73c4` |
| `hagezi-tif-mini.txt.gz` | https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.mini.txt | 212,435 | `46efbea4f78358e8736b49fd77aaf1a6dfe78e32f48a1d7d1f1416ff6ca3a799` |

The three lists together are the benchmark set (about 451k domains). `tests/fixtures/golden/real`
holds the sampled queries (`queries.txt`) and the oracle output (`expected.txt`), produced by
`tools/sample-real.sh` and `tools/regen.sh`.

Census of this copy of the AdGuard DNS filter (the plan quoted the session download, 190,791
`||d^` and 191 `@@||d^`; the list has changed since): 190,543 lines of the exact form `||d^`,
11 of the form `@@||d^`, 879 other rule lines (wildcards, `@@||d^|`, regexes, substring rules).

## Format fixtures (also downloaded 2026-10-24)

Small complete lists, one per format, used by the `auto` detection tests
(`tests/filter_formats.rs`). All HaGeZi lists are from
`https://raw.githubusercontent.com/hagezi/dns-blocklists/main/<format>/<name>.txt`.

| File | Source | Lines | SHA-256 of the text |
|---|---|---|---|
| `hagezi-adblock-dyndns.txt.gz` | `adblock/dyndns.txt` | 1,554 | `f1a22de36b67fb804184b20e42a0e6997c1f76bedbab00f2529aea70a91c8e8d` |
| `hagezi-dnsmasq-dyndns.txt.gz` | `dnsmasq/dyndns.txt` | 1,553 | `c9bf441066d2276c11c20516d0caab5353e50a0ee83e8b95936f846cfc6e9f71` |
| `hagezi-rpz-dyndns.txt.gz` | `rpz/dyndns.txt` | 3,098 | `b654ee3628f8cba6e8d3805eb50a7b7121172f5e5be2455e43d05ccc946e05e1` |
| `hagezi-wildcard-dyndns.txt.gz` | `wildcard/dyndns.txt` (`*.d` lines) | 1,553 | `03e3b825f50073c77e89228def4c3e35678d5890d17614362b76ed3c064b4322` |
| `hagezi-wildcard-dyndns-onlydomains.txt.gz` | `wildcard/dyndns-onlydomains.txt` (`d` lines) | 1,553 | `116b3701853d49ef8f7026a7c0d1aabf82f091e45184c02239c00ab1c61a1fa9` |
| `stevenblack-hosts.txt.gz` | https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts (dated 18 October 2026) | 78,317 | `af019612ef8c1239762033947cfd70716c1d53dab78541b9d924f1966f2e6170` |
