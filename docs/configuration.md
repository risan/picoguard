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
| `rules` | `[]` | Your own rules, one per string: adblock syntax or hosts lines. They join the lists below as one more list. The status page shows them read-only. |

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

Block and Allow from the status page (below, under `[web]`) take their own places:

- Allow from the page works like an allowlist entry, and is asked even before the allowlists. It
  beats every block, `$important` included, and the answer is not checked.
- Block from the page counts as `||name^$important`. It beats `@@` in lists and in `rules`, but
  not an `$important` allow or an allowlist.
- No list's `$badfilter` undoes a Block or an Allow from the page.
- An Allow from the page for a name also wins over a Block from the page for one of its
  subdomains.

## `[cache]`

| Key | Default | Meaning |
|---|---|---|
| `max_entries` | `10000` | Most answers kept. |
| `max_bytes` | `4194304` (4 MiB) | Most bytes of answers kept. The first of the two limits that is hit evicts the oldest answer. |
| `min_ttl` | `0` | Raise shorter TTLs to this many seconds. |
| `max_ttl` | `86400` | Lower longer TTLs to this many seconds. |
| `max_response_size` | `4096` | Larger upstream answers are served but not cached. |
| `optimistic` | `true` | Answer an expired cached answer at once and refresh it in the background (below). `false` turns it off. |
| `optimistic_answer_ttl_secs` | `30` | The TTL of every record in such an answer. 1 to 3600. |
| `optimistic_max_age_secs` | `43200` (12 h) | How long after it expires a cached answer may still be served. 1 to 604800 (7 days). |

Cache cost is about 600 bytes per entry in practice (6 MB for 10,000 entries in the benchmark).

### Optimistic caching

With `optimistic = true`, a query whose cached answer has expired, by no more than
`optimistic_max_age_secs`, is answered at once from the cache. Every TTL in that answer is
`optimistic_answer_ttl_secs`, so clients ask again soon.

- The same answer starts one background refresh of the question. Concurrent queries for it share
  that one refresh, and a refresh joins a lookup already under way. The refreshed answer replaces
  the old one; the next query gets it.
- A failed refresh leaves the old answer in place, served until it is `optimistic_max_age_secs`
  past its expiry. After that the query waits for the upstream as before. With the upstreams down,
  names already cached keep resolving for up to that age.
- At most half of the smaller of `limits.max_inflight_queries` and `limits.upstream_concurrency`
  refreshes run at once (at least one; 16 with the defaults). They wait for no client. Under load
  a refresh may be skipped; the next query for the name tries again.
- A stale answer counts as cached. Refreshes are not client queries: they count on the Upstreams
  card only, never in the totals or the query log, and a failed one logs no line of its own.
- Block rules and pause apply to a stale answer as to a fresh one, including a rule added after
  it was cached.
- `min_ttl` and `max_ttl` still decide when an answer expires; optimism starts after that.
- Stale answers stay within `max_entries` and `max_bytes`, like any other.
- `optimistic = false` turns it off: an expired answer is a normal miss.

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

The status page. With `user` and a password (`password_hash`, or `password`) set, it shows totals,
top blocked domains, top clients, upstream servers, the cache, recent queries and list status, and
can pause blocking for a set time, refresh the lists, clear the DNS cache, block or allow a name,
and check which rule decides a name.

Without a password the page is read-only and limited: it shows totals and list status only. The
query log, pause, resume, refresh, Clear cache, `/api/rules`, `/api/rules/remove` and
`/api/explain` answer 403 ("set web.user and web.password_hash (or web.password) to use this"),
and the page says so. The top lists, the
upstream servers and the cache size are left out of `/api/status`, and the page hides them.
picoguard logs one warning at start when no password is set. Every device that may open the page
could otherwise read the household's queries and switch blocking off.

The Upstreams card, and the `upstreams` field of `/api/status`, cover every server in
`[upstream] servers` and then the `[local]` resolver when one is set. The API lists them in that
order; the card sorts them by answered count, highest first. Each entry has `label` (the server as
written in `[upstream] servers`, or the `[local] resolver` address), `kind` (`upstream` or `local`),
`answered`, `failed` and `avg_ms` (`null` before the first answer).

- The counts start at picoguard's start. A try that is repeated on the next server counts as a
  failure on the first one, and the repeat counts on the second as its own answer or failure.
- picoguard's own lookups count too: list downloads and the update check.
- A query that a blocking rule held back after the answer came in did reach the server and counts.
  A cached answer and a query blocked by a request rule never reach a server and do not count.
- `avg_ms` is the average over the answers, in milliseconds with one decimal. The time runs from
  sending the request until the reply arrives. It includes opening a connection when one is needed,
  and it leaves out picoguard's own wait for a free slot on that server.
- Background refreshes of cached answers count too.
- The card is only for the signed-in page, because a DoH address can hold a private profile ID.

The Cache card shows how many answers the cache holds and their size, from the `cache` field of
`/api/status` (`{"entries": n, "bytes": n}`, signed-in only). Its Clear cache button asks for
confirmation, then calls `POST /api/cache/clear`, which empties the cache, frees its memory and
answers `{"cleared": n}` with the number of answers removed; the card shows "Cache cleared (n
answers)". The next query for any name goes upstream. Lookups already under way are not stopped,
and their answers are cached when they land.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Turn the status page on or off. |
| `bind` | `["0.0.0.0", "::"]` | Addresses to listen on. |
| `port` | `8080` | HTTP port. |
| `allow_from` | same as `server.allow_from` | Only these networks may open the page. Others are disconnected. |
| `hostnames` | `[]` | Host names the page answers to, besides IP addresses. Add the name you type in the browser, for example `["orangepi.lan"]`. |
| `user`, `password` | not set | Set `user` and one of `password` or `password_hash` to require a sign-in and to unlock the full page. Neither can be empty; the user cannot contain `:`. |
| `password_hash` | not set | The password as a salted hash, instead of `password` (not both). Make one with `picoguard --hash-password`. |

### Signing in

With a password set, the page opens with its own sign-in form; the browser never shows its
password prompt. A right user and password sets a session cookie (`HttpOnly`, `SameSite=Strict`)
that lasts 30 days:

- A restart of picoguard keeps every session; nothing about them is written to disk.
- A new `user`, `password` or `password_hash` ends every session at the next start.
- **Sign out** ends the session in that browser only. A copy of the cookie taken elsewhere stays
  valid until it expires.
- A clock moved back keeps sessions longer by that much.

Scripts keep using basic auth on `/api/*`, for example
`curl -u admin:PASSWORD http://192.168.1.53:8080/api/status`. With a hash, the first right answer
pays the hash, and the same credentials after it are checked in microseconds.

Wrong passwords are limited per client address. After 5 failed password checks within 15 minutes,
sign-ins and basic auth from that address answer 429 ("too many attempts, try again later") until
15 minutes after its last failure. A right password clears the address. picoguard tracks 64
addresses; when the table is full, the one with the oldest last failure is dropped.

Make a hash with `picoguard --hash-password`. It reads the password from standard input (it asks
without echo on a terminal) and prints a line to paste into `[web]`:

```sh
$ picoguard --hash-password
Password:
password_hash = "pbkdf2-sha256$600000$..."
```

The hash is PBKDF2-HMAC-SHA256 with 600,000 iterations and a random salt. Each wrong password pays
the full hash, one at a time: about 0.1 s on a desktop and about 1 to 2 s on an ARMv7 board. A right
sign-in pays it once a month per browser.

Prefer `password_hash`. With a plaintext `password` the config holds the password itself, and a
captured session cookie can be checked against guesses quickly. Either way, anyone who can read the
config can sign in, so keep it `0640 root:picoguard` as `install.sh` writes it.

The page is plain HTTP: the cookie and basic auth cross the network in clear text. Use them with
`allow_from` on a trusted LAN, not across the internet. Cookies do not tell ports apart, so another
web service on the same address sees the session cookie. A browser that still holds basic
credentials from an older picoguard keeps sending them; it shows the dashboard without the form,
and **Sign out** cannot end that until the browser forgets them.

### Block, Allow and Check a name

Each row of the query log has **Block** (or **Allow** when the query was blocked) and **Why**.
Block and Allow add a rule for that name and its subdomains; the Lists tab shows them in the card
**Your rules**, each with **Remove**, and your config `rules` read-only below them.

- The rules are kept in memory only. A restart or an update clears them, and nothing is written
  to disk. Add a rule you want to keep to `rules` in the config.
- At most 500 names.
- A name is trimmed, lowercased and loses one trailing dot. It must then be 1 to 253 characters in
  at least two labels of 1 to 63 letters, digits, hyphens or underscores, none starting with a
  hyphen. Anything else answers 400 `{"error": "not a domain name"}`.
- One rule per name: the other action replaces the rule in its place, and the same action again
  changes nothing. A new name past 500 answers 409
  `{"error": "too many rules (500); remove some first"}`; replacing one at the cap works.
- The list is in the order the names were first added.
- A change is in force when its answer comes back. It never waits for a list download: only the
  page's rules are rebuilt, the lists are not read again.
- Cached answers follow the new rules at their next query.
- While blocking is paused, a change is kept and applies when blocking is on again.

Which rule decides a name, in the order of "Which rule wins" above, comes from **Check a name** on
the Lists tab; **Why** on a log row fills it in and runs it.

- The name is judged as an `A` query, with blocking on even while it is paused.
- Among lists of equal standing, the first one is reported: your `rules`, then the lists in config
  order.
- Plain rules are shown in adblock form (`||name^`, `|name^`, and `||*.name^` for an RPZ
  `*.name`). Hosts lines show as `address name`.
- Other rules are rebuilt from the parsed rule: a regex or wildcard without modifiers shows exactly
  as written; with modifiers, they come in a fixed order and spelling, which may differ from the
  list (`$dnstype=AAAA,important` shows as `$important,dnstype=AAAA`).
- A Block from the page shows as `||name^$important`, an Allow as `@@||name^`; their list is
  `your rules`. Your config `rules` show as `config rules`, an allowlist or blocklist by its
  name, or its URL or path when it has none.
- A name blocked only by its answer (a CNAME target or an address, "blocked (answer)" in the
  query log) shows `none`: only the name itself is checked.

The routes, all signed-in only; the two changes follow the same `Origin`, content type and body
rules as every other change:

| Route | Body | Answer |
|---|---|---|
| `GET /api/rules` | | `{"rules": [{"name": "ads.example", "action": "block"}], "config_rules": ["@@\|\|good.example^"], "max": 500}` |
| `POST /api/rules` | `{"name": "...", "action": "block"}` or `"allow"` | the same as `GET`; 400 or 409 |
| `POST /api/rules/remove` | `{"name": "..."}` | the same as `GET`; 404 `{"error": "no such rule"}` |
| `GET /api/explain?name=...` | | `{"name": "ads.example", "decision": "blocked", "list": "config rules", "rule": "\|\|ads.example^"}`; `decision` is `blocked`, `allowed` or `none` (then `list` and `rule` are `null`) |

The name in `/api/explain` is read as sent, without percent-decoding: a domain name never needs
it.

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

## `[update]`

The status page shows the running version. About once a day, picoguard also asks GitHub whether
a newer release exists, and the page says "update available" with a short summary of the release
notes and the command that updates your kind of build. A release binary installed with
`install.sh`, shown to a signed-in user (`web.user` and `web.password` or `web.password_hash`),
also gets an **Update** button that installs it ([how it works](install.md#from-the-status-page)).

| Key | Default | Meaning |
|---|---|---|
| `check` | `true` | Look for a newer release, and offer the button. `false`: picoguard never contacts GitHub, so there is no "update available" and no button. |

What the check does:

- It asks `api.github.com` for the latest release of picoguard: once a few minutes after start,
  then once a day. It goes through your configured `[upstream]` servers like a list download and
  keeps nothing on disk.
- It sends a plain GET whose only identifying part is picoguard's User-Agent, which holds the
  version (`picoguard/0.3.1`), and, from the second check on, the ETag of the last answer. No
  cookie, no token, no account.
- A failed check is logged once at `warn` (a missing release at `info`) and changes nothing on the
  page. It never affects DNS answers.
- With `check = false`, or with the status page turned off (`[web] enabled = false`), picoguard
  makes no request and no DNS lookup for GitHub.

The button is the only thing in picoguard that installs a program. It does so through a separate
root installer that `install.sh` sets up, not through picoguard itself, which still cannot write
its own binary. Turning the button off for good, and removing the installer, is described in
[install.md](install.md#from-the-status-page).

The command shown depends on how the binary was built:

| Build | Command |
|---|---|
| Release binary (`install.sh`, the release assets) | `curl -fsSL https://github.com/risan/picoguard/releases/latest/download/install.sh \| sudo sh` |
| Docker image | `git pull && docker compose up -d --build` |
| Source (`cargo install`, `cargo build`) | `cargo install --locked picoguard` |

An older picoguard rejects an `[update]` section as an unknown key. When you go back to an older
version, remove the section first.

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
