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
