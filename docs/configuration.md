# Configuration

picoguard reads one TOML file. The default path is `/etc/picoguard/picoguard.toml`; change it with
`-c FILE`. The shipped example is [`dist/picoguard.toml`](../dist/picoguard.toml): every value in it
is the default, and most are commented out. Check a file without starting the server:

```sh
picoguard --check -c /etc/picoguard/picoguard.toml
```

It prints `OK` or the first error. Unknown keys are errors, so a typo cannot hide.

Top-level keys (`blocked_ttl`, `rules`, ...) must come before the first `[section]` header. This
is a TOML rule.

Two instances can use the same file. They do not sync with each other.

## Top-level keys

| Key | Default | Meaning |
|---|---|---|
| `blocked_ttl` | `10` | TTL in seconds of blocked answers. |
| `refuse_any` | `true` | Answer `ANY` queries with NOTIMP. |
| `blocked_hosts` | `["version.bind", "id.server", "hostname.bind"]` | Names answered with REFUSED. |
| `rules` | `[]` | Your own rules, one per string: adblock syntax or hosts lines. They join the lists below as one more list. |

`rules` example:

```toml
rules = [
    "||ads.example.com^",
    "@@||good.example.com^",
]
```

## `[server]`

| Key | Default | Meaning |
|---|---|---|
| `bind` | `["0.0.0.0", "::"]` | Addresses to listen on, UDP and TCP. `::` is IPv6 only, so both entries can share the port. |
| `port` | `53` | DNS port. |
| `allow_from` | private ranges (see below) | Only these networks may query. Others get no answer. |
| `udp_size` | `1232` | EDNS UDP payload size advertised to clients and upstreams (512 to 4096). |

The default `allow_from` is loopback (`127.0.0.0/8`, `::1/128`), RFC 1918 (`10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`), `100.64.0.0/10` (Tailscale), link-local (`169.254.0.0/16`,
`fe80::/10`) and `fc00::/7`. `100.64.0.0/10` is also the carrier-grade NAT space of some ISPs: remove
it if you do not use Tailscale. To allow everyone, use `["0.0.0.0/0", "::/0"]`. Do that only behind a
firewall: an open resolver is abused for attacks.

## `[upstream]`

| Key | Default | Meaning |
|---|---|---|
| `servers` | Cloudflare `1.1.1.1`, `1.0.0.1` and Quad9 `9.9.9.10`, `149.112.112.10`, all over DoH | Forwarding servers. Several are load balanced by speed; a failing one is skipped. |
| `bootstrap` | `["9.9.9.9", "1.1.1.1"]` | Plain IPs used to resolve upstream host names. Not used when `servers` hold IP addresses. |
| `timeout_ms` | `5000` | How long to wait for one upstream. |

Forms of a server: `https://IP/path` (DoH by IP), `https://host/path` (DoH by name, needs
`bootstrap`), `tls://IP#name` (DoT), `udp://IP:port`, `tcp://IP:port`.

## `[local]`

Off by default. Set it to send reverse lookups of private addresses and your local domain to the
router. Without it, such queries get NXDOMAIN. This includes every name under the private
reverse zones of RFC 6303, such as the DNS-SD names `lb._dns-sd._udp.0.1.168.192.in-addr.arpa`.
They never go to the public servers.

| Key | Default | Meaning |
|---|---|---|
| `resolver` | not set | The router, as `IP:port`, for example `"192.168.1.1:53"`. |
| `domains` | `[]` | Local domains that go to that resolver, for example `["lan", "home.arpa"]`. |

## `[[lists]]` and `[[allowlists]]`

Blocklists are `[[lists]]` tables. Allowlists (names that are never blocked) are
`[[allowlists]]` with the same keys. If the file has no `[[lists]]` at all, picoguard uses the
AdGuard DNS filter, HaGeZi Pro and HaGeZi Threat Intelligence mini. As soon as you write one
`[[lists]]`, only your lists are used.

| Key | Default | Meaning |
|---|---|---|
| `name` | none | Label on the status page. |
| `url` | none | `http://` or `https://` address. Set `url` or `path`, not both. |
| `path` | none | Local file. Read at start and again every `refresh_hours`. |
| `format` | `"auto"` | `auto`, `adblock`, `hosts`, `domains`, `wildcard`, `dnsmasq` or `rpz`. |
| `refresh_hours` | `24` | How often to download again. |
| `max_rules` | `1500000` | A list with more rules is not used: the refresh fails, the status page shows the error and the last good copy stays. One list of 1.5 million rules takes about 12 MB, and the old and the new copy exist together during a refresh, which is what fits the 64 MB limit of the systemd unit. A bigger list, such as HaGeZi TIF (full, about 2.1 million rules), needs `max_rules` raised on purpose (and a unit memory limit to match). |
| `max_body_bytes` | `67108864` (64 MiB) | A larger download is stopped and not used. |
| `allow_redirects` | `false` | Hosts lines with a real address (`203.0.113.7 name`) are answered with that address only if this is `true`. Otherwise a downloaded list answers any address except `0.0.0.0`, `::`, `127.0.0.1` and `::1` like `0.0.0.0`, so a list can block names but not send them elsewhere. Lists with `path` and your own `rules` always keep the address (for local names). |
| `slow_rule_budget` | `8388608` (8 MiB) | Estimated bytes for rules that are not plain domains (regex, wildcards, modifiers). A regex is charged the memory it really holds (about 8 KB for `/track[0-9]+/`, close to 1 MB for `/(\pL\|\pN){1,50}x/`), a wildcard rule 64 bytes for each of its parts, and every distinct rule at least 32 bytes more, even a regex that does not compile. A list over it is not used. |

Downloads use `If-None-Match` and `If-Modified-Since`. A failed download keeps the last good list.
A download that takes longer than 10 minutes in all fails. A redirect to a loopback, private,
link-local or unspecified address fails too, unless the list URL itself points into those ranges.
A list in `[[lists]]` that blocks any of three made-up check names (for example because of a rule
like `||*^` or `/./`) is refused the same way: the last good copy stays and the status page shows the
error. Allowlists and your own `rules` are not checked.
A new list takes effect without a restart and without dropping queries. One list refreshes at a time.

Example:

```toml
[[lists]]
name = "adguard-dns"
url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"

[[allowlists]]
path = "/etc/picoguard/allow.txt"
```

## List formats

picoguard reads six formats. Set `format = "auto"` (the default) and it detects the format once per
list, from the first 64 KiB, in this order:

1. A header comment that names the format (`Syntax:` or `Format:`). HaGeZi lists have one.
   `Domains Wildcard` and `Domains (without subdomains)` mean `wildcard`; `DNSMasq` means
   `dnsmasq`; `RPZ` means `rpz`; `AdBlock` means `adblock`.
2. The first line that is not a comment: `$TTL`, `$ORIGIN` or an SOA record means `rpz`;
   `address=/`, `local=/` or `server=/` means `dnsmasq`.
3. At least 90% of the first 200 rule lines look like `*.domain`: `wildcard`.
4. Otherwise the AdGuard grammar (`adblock`). A list of bare domains without a header is read with
   AdGuard rules: each line blocks that exact name only, not its subdomains. This is what
   AdGuard Home does too. If the list means "this domain and all subdomains", set
   `format = "wildcard"`.

The detected format shows on the status page. If auto picks wrong, set `format` yourself.

| Format | What it reads |
|---|---|
| `adblock` | AdGuard DNS syntax: `\|\|domain^`, `@@\|\|domain^` (allow), `\|domain^`, `domain^`, `*` wildcards, partial labels (`\|\|ads.`), `/regex/`. Modifiers `$important`, `$badfilter`, `$denyallow`, `$dnstype`. Hosts lines and bare domains in the same file also work. Cosmetic and comment lines are skipped. |
| `hosts` | Hosts files: `0.0.0.0 name`, `127.0.0.1 name`, `:: name`, several names per line, inline comments. |
| `domains` | One domain per line. Each blocks that exact name only. |
| `wildcard` | `domain` or `*.domain` per line. Each blocks the domain and all its subdomains. HaGeZi "wildcard" lists. |
| `dnsmasq` | `address=/domain/...`, `local=/domain/`, `server=/domain/`. Each blocks the domain and its subdomains. |
| `rpz` | RPZ zone files: `domain CNAME .` blocks the name; `*.domain CNAME .` blocks the subdomains; `CNAME rpz-passthru.` allows. Other record types are skipped and counted. |

Rules that need features picoguard does not have (`$client`, `$ctag`, `$dnsrewrite`) are parsed and
counted, not fatal. Unknown lines are counted and logged once per list. See the README for the
exact differences from AdGuard Home.

### Which rule wins

The same order as AdGuard Home:

1. A name in an allowlist (`[[allowlists]]`) is never blocked.
2. Otherwise, among all matching rules: `$important` allow, then `$important` block, then allow
   (`@@`), then block.

When a rule allows the name that was asked (an allowlist, or `@@` in a list or in `rules`), the
answer is not checked either: a CNAME target or an answer address that a blocklist matches does
not block it, as in AdGuard Home.

Your `rules` count as one more list. So `||example.com^$important` in a list still beats
`@@||example.com^` in `rules`, as in AdGuard Home.

## `[cache]`

| Key | Default | Meaning |
|---|---|---|
| `max_entries` | `10000` | Most answers kept. |
| `max_bytes` | `4194304` (4 MiB) | Most bytes of answers kept. The first of the two limits that is hit evicts the oldest answer. |
| `min_ttl` | `0` | Raise shorter TTLs to this many seconds. |
| `max_ttl` | `86400` | Lower longer TTLs to this many seconds. |
| `max_response_size` | `4096` | Larger upstream answers are served but not cached. |

Cache cost is about 600 bytes per entry in practice (6 MB for 10,000 entries in the benchmark).

## `[limits]`

These keep memory fixed. The defaults fit a 256 MB board; you rarely change them.

| Key | Default | Meaning |
|---|---|---|
| `h2_stream_window` | `65536` | HTTP/2 flow-control window per DoH request, in bytes. |
| `h2_connection_window` | `131072` | HTTP/2 flow-control window per DoH connection. |
| `h2_max_header_list` | `16384` | Largest HTTP/2 header block accepted from an upstream. |
| `upstream_concurrency` | `32` | Most requests in flight to one upstream. |
| `max_inflight_queries` | `128` | Most upstream queries in flight in total. Beyond this, UDP queries are dropped and TCP queries get SERVFAIL. |
| `max_waiting_clients` | `256` | Most clients waiting for an answer. Same overflow rule. |
| `tcp_max_connections` | `16` | Most TCP clients at once. |
| `tcp_idle_secs` | `30` | Close a TCP client after this many idle seconds. |
| `tcp_read_buffer` | `2048` | Starting read buffer per TCP client, in bytes. |
| `tcp_queue_replies` | `4` | Most replies queued for one TCP client. |
| `tcp_queue_bytes` | `131072` | Most bytes queued for one TCP client. |
| `tcp_write_timeout_secs` | `5` | Close a TCP client that does not read its reply in this time. |
| `upstream_reply_max` | `65536` | Largest upstream reply accepted, in bytes. |
| `pending_bytes` | `1048576` | One shared budget for replies held for delivery. When used up, new queries get SERVFAIL (TCP) or are dropped (UDP). |

## `[web]`

The status page. With `user` and `password` set, it shows totals, top blocked domains, top clients,
recent queries and list status, and can pause blocking for a set time and refresh the lists.

Without a password the page is read-only and limited: it shows totals and list status only. The
query log, the top lists, pause, resume and refresh answer 403 ("set web.user and web.password to
use this"), and the page says so. picoguard logs one warning at start when no password is set.
Every device that may open the page could otherwise read the household's queries and switch
blocking off.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Turn the status page on or off. |
| `bind` | `["0.0.0.0", "::"]` | Addresses to listen on. |
| `port` | `8080` | HTTP port. |
| `allow_from` | same as `server.allow_from` | Only these networks may open the page. Others are disconnected. |
| `hostnames` | `[]` | Host names the page answers to, besides IP addresses. Add the name you type in the browser, for example `["orangepi.lan"]`. |
| `user`, `password` | not set | Set both to require basic auth on every request and to unlock the full page. Neither can be empty; the user cannot contain `:`. |

Basic auth is sent in clear text over HTTP. Use it with `allow_from` on a trusted LAN, not across
the internet.

## `[stats]`

Statistics and the query log live in memory only and are lost on restart.

| Key | Default | Meaning |
|---|---|---|
| `query_log_entries` | `1000` | Recent queries kept (up to 100000). Allocated in full. |
| `top_k` | `50` | Entries in each top list (up to 1000). Allocated in full. |

## `[state]`

| Key | Default | Meaning |
|---|---|---|
| `dir` | `"/var/lib/picoguard"` | Where list snapshots go. The systemd unit creates this directory (`StateDirectory=picoguard`). |
| `persist_lists` | `true` | Keep a copy of each changed list on disk. This is the only routine write. When `false`, nothing is written; lists live in memory and download again at every start. |

## `[log]`

| Key | Default | Meaning |
|---|---|---|
| `level` | `"warn"` | `error`, `warn`, `info`, `debug` or `trace`. At `warn` there are no per-query lines. |

## Choose lists for your board

Memory use is roughly:

```
RSS  =  6.5 MB  +  8 bytes x rules  +  cache  (about 0.6 KB per entry)
```

Measured: 450,000 rules and an empty cache gave 9.8 MB; the same lists with a full 10,000-entry
cache gave 15.8 MB (see [benchmarks](benchmarks.md)). During a refresh, one list is held twice for a
short time: add about 2 MB per large list, one list at a time.

Lists that use many regex or wildcard rules cost more than 8 bytes per rule. The status page
shows the real count and size of each list.

The table is a plan from the formula above. It has not been measured on a board yet.

| Board RAM | Lists | Rules | Cache | Expected RSS |
|---|---|---|---|---|
| 256 MB | The default: AdGuard DNS filter, HaGeZi Pro and HaGeZi TIF mini | about 450k | 10,000 entries (default) | about 11 MB idle, 19 MB after 49,000 queries (measured on x86_64) |
| 256 MB, lighter | HaGeZi Pro and HaGeZi TIF mini only | at most about 260k | 10,000 entries | about 12 to 15 MB |
| 512 MB | Above plus a larger HaGeZi list (for example Pro++) | up to about 1 million | `max_entries = 30000`, `max_bytes = 12582912` | about 25 to 35 MB |
| 1 GB or more | Any mix, for example several regional lists | up to about 3 million (raise `max_rules` for a list over 1.5 million) | `max_entries = 100000`, `max_bytes = 41943040` | about 60 to 90 MB |

Notes:

- More lists help less than you think. Lists overlap by a large share, and each duplicate still
  costs 8 bytes.
- The systemd unit sets `MemoryMax=64M`. If you go beyond the 512 MB row, raise it in a drop-in
  (`systemctl edit picoguard`).
- Do not go above 1.5 million rules in one list unless you raised `max_rules` and the memory limit
  of the unit: `max_rules` stops it.
