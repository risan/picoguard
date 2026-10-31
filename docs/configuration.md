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

Two instances can use the same file. They do not sync with each other, and each keeps what is
saved from its own status page in its own `state.dir`.

## Settings saved from the status page

What you change on the status page is saved in `settings.json` in `[state] dir`
(`/var/lib/picoguard/settings.json` by default), never in this file: picoguard cannot write
`/etc/picoguard`. Today that is the Block and Allow rules from the query log, the upstream servers
and bootstrap addresses, the cache settings, the block lists and allowlists, the DNS rewrites,
SafeSearch and the blocked services (below).

- A value saved from the page wins over the same value in this file. The page's rules join your
  `rules`; they never replace them.
- The file is written only when you save a change on the page: never at start, on a timer or on a
  list refresh, and not for a change that changes nothing. It is written whole, as
  `settings.json.part` first and then renamed, readable by picoguard's user only.
- picoguard never deletes or rewrites the file on its own. To go back to this file alone, stop
  picoguard and delete `settings.json`.
- A saved file that cannot be used (unreadable, a link or anything but a plain file, larger than
  256 KiB, not valid, or a value that makes the config invalid) never stops picoguard. It starts on
  this file alone, logs one warning, and the page says "Saved settings could not be used:
  <reason>. Saving from this page replaces them."
- `picoguard --check` checks the saved file too. When it would be ignored, it prints
  `warning: saved settings in <path> will be ignored: <reason>`, and still `OK` with exit code 0:
  picoguard would start.
- A save that fails (for example a read-only state folder) answers 503
  `{"error": "could not save settings: <reason>"}`, and the change is not applied either.

`GET /api/settings` (signed-in only) shows what the page can change, each value with where it
comes from (`"from": "page"` or `"file"`), and nothing of `[web]`:

```json
{"file": "/var/lib/picoguard/settings.json", "error": null, "can_save": true,
 "upstream": {"servers": ["https://1.1.1.1/dns-query"], "bootstrap": ["9.9.9.9", "1.1.1.1"], "from": "file"},
 "cache": {"max_entries": 10000, "max_bytes": 4194304, "min_ttl": 0, "max_ttl": 86400, "optimistic": true, "from": "file"},
 "rewrites": {"entries": [], "from": "file"},
 "safe_search": {"on": false, "from": "file"},
 "services": {"block": [], "from": "file"},
 "memory": {"estimate_bytes": 26535936, "budget_bytes": 50331648}}
```

`error` is why the saved file was not used at start, until a save replaces it. `can_save` is
`false` after a save failed, until one works. `memory` is the [memory estimate](#the-memory-budget)
and the budget it is checked against.

### Upstream servers and cache from the page

The Settings tab has a card for each. The card says "From the config file" or "Set on this page";
**Save** saves the card and puts it in force at once, without a restart, and **Use the config
file** goes back to this file's values.

- **Upstream servers**: `[upstream] servers` (1 to 8, in order; add, remove, move up and down)
  and `bootstrap` (0 to 4 addresses). A server this file would refuse is refused with the same
  reason, and nothing is saved. `timeout_ms` stays in this file. Queries already waiting finish on
  the servers they started on; the new servers answer every query after the save. A server kept
  by its exact address keeps its counts on the dashboard's Upstreams card, and a new one starts at
  0; answers that queries in flight get from the old servers after the save are not counted. The
  query log's "Via" column (`#0`, `#1`, ...) is the position in the list in force at the time.
- Replaced servers close their connections once the queries that started on them have ended, within
  `timeout_ms`. If two earlier changes are still finishing, a further change answers 409 "the
  previous upstream change is still finishing; try again in a few seconds".
- **Cache**: `max_entries`, `max_bytes` (256 KiB to 16 MiB from the page; the card asks in
  KiB), `min_ttl`, `max_ttl` and `optimistic`. Saving a change empties the cache, like Clear
  cache, and the new limits and TTLs apply to the next answer. The other `[cache]` keys stay in
  this file. A larger `max_bytes` that would take the [memory estimate](#the-memory-budget) past
  the budget is refused with 400 "a cache of 16.0 MB would pass the memory budget: the estimate
  would be 51.2 MB of 48.0 MB"; a smaller one always works.

`POST /api/settings` takes any of `upstream`, `cache`, `rewrites`, `safe_search` and
`services`. A value sets it, `null` goes back to this file. The body may be up to 64 KiB. It
answers the same as `GET`, 400 with the reason for a value that is refused, 409 as above or for
blocked services that would pass the memory budget, 502 when the catalog of services cannot be
downloaded, or 503 when the file cannot be saved; in every refusal nothing changes.

```json
{"upstream": {"servers": ["tls://9.9.9.9#dns.quad9.net", "https://1.1.1.1/dns-query"], "bootstrap": ["9.9.9.9"]},
 "cache": null,
 "rewrites": [{"name": "nas.lan", "answer": "192.168.1.10"}, {"name": "*.nas.lan", "answer": "nas.lan"}],
 "safe_search": true,
 "services": ["tiktok"]}
```

A change that leaves the saved values as they are writes nothing.

### Rewrites and SafeSearch from the page

The Settings tab has a **Rewrites** card (a table of name and answer, Add, Remove) and a
**SafeSearch** card (one switch), each with "From the config file" or "Set on this page", its
own **Save**, and **Use the config file**. They follow [`[[rewrites]]` and
`safe_search`](#rewrites-and-safesearch) below, and apply at once: the next query is answered from
them.

- The page sends the whole table. Names and name answers are kept lowercase, without spaces or a
  final dot, and an address is kept in its standard form (`FD00:0::10` becomes `fd00::10`), so
  `NAS.lan.` and `nas.lan` are the same rewrite and saving it again writes nothing.
- A table this file would refuse is refused with the same reason (400), for example
  "rewrites[0] points nas.lan at itself", and nothing is saved.
- The new table is built off the DNS thread, saved, then put in force whole; the old one is freed
  off the DNS thread.
- **Check a name** on the Lists tab says "rewritten to X (your rewrite)" or "rewritten to X
  (SafeSearch)" for a rewritten name, before any list. `GET /api/explain` then answers
  `{"decision": "rewritten", "list": "your rewrites" or "SafeSearch", "rule": "rewritten to X (...)"}`.

### Blocked services from the page

The Settings tab has a **Blocked services** card: a switch for each service of the catalog,
grouped as the catalog groups them, a filter box, "From the config file" or "Set on this page",
**Save**, and **Use the config file**. It follows [`[services]`](#services) below.

- The catalog is downloaded the first time the Settings tab is opened, and the card says
  "Loading the list of services" until it is read. If it cannot be downloaded the card says why,
  and the page asks again a minute later.
- **Save** puts the services switched on in force at once. Switching one on downloads the catalog
  (once for the change) and builds that service's list, within the [memory
  budget](#the-memory-budget); switching one off drops its list and downloads nothing.
- Refused, with nothing saved or changed: an id the catalog does not have (400 "there is no
  service "x" in the catalog"), services that would hold more than 20,000 rules together, those
  already on included (400 "the services switched on would hold 22000 rules, more than 20000"),
  services that would pass the memory budget (409 "the blocked services would pass the memory
  budget: ..."), or a catalog that cannot be downloaded (502
  "could not download the catalog of the blocked services: ...").

`GET /api/services` (signed-in only) shows the catalog's services and which are on; the first
call starts the download:

```json
{"services": [{"id": "tiktok", "name": "TikTok", "group": "social_network", "on": true}],
 "loaded_at": 1793491200, "error": null, "loading": false}
```

`loaded_at` is when the catalog was last read (seconds since 1970), `error` why the last download
or refresh failed (until one works), and `loading` is true until the catalog, or the lists of the
services switched on, are read.

### Lists from the page

The Lists tab changes the block lists and allowlists that are downloaded (`url` lists). Lists
read from a file (`path`) stay in this file: the page marks them "from the config file" and
cannot change them (409).

- **The first change copies this file's lists to the page.** Once a list is added, turned off,
  renamed, given other refresh hours or removed on the page, the saved settings hold every URL
  list, and this file's `url` lists are no longer used; its `path` lists still are, first. A page
  list with the same role and URL as a list of this file keeps that list's `format`,
  `max_rules`, `max_body_bytes`, `slow_rule_budget` and `allow_redirects`; a list only the page
  has gets the defaults (`format = "auto"`, no redirects). **Use the config file** removes the
  page's lists and goes back to this file's.
- **Each row** has an on switch, the refresh hours (1 to 168) and Remove. A list that is off is
  not downloaded and holds no memory. A rename or new hours changes nothing else: the list in
  force is kept. Turning a list on again downloads it.
- **Add a list**: a name, an `http://` or `https://` address, block list or allowlist, and the
  refresh hours. The page answers at once, shows the list as "checking" while it is downloaded
  and compiled, then "added", "refused: <name> needs X MB, Y MB left of Z MB" (it would pass the
  [memory budget](#the-memory-budget)) or "failed: <name>: <reason>" (the download or the list
  failed). A refused or failed list is not saved. One list is checked at a time; a second Add
  meanwhile answers 409. At most 32 block lists and 16 allowlists; one address once per role.
- A list added from the page is a list like the others: refreshed every `refresh_hours`, the last
  good copy kept on a failure, and its copy kept on disk under `persist_lists`, so it comes back
  at start without a download. A refresh of it never writes `settings.json`.

The API, all `POST` with a JSON body, signed in. A list is named by its `role` (`"block"` or
`"allow"`) and its `source` (the URL, or the path for a file list). Unknown keys, such as `path`,
`format` or `allow_redirects`, are refused with 400.

| Route | Body | Answer |
|---|---|---|
| `/api/lists/add` | `{"role": "block", "name": "HaGeZi Pro", "url": "https://...", "refresh_hours": 24}` | 202 `{"list": "checking"}`; 400 with the reason; 409 while another add is checked |
| `/api/lists/edit` | `{"role", "source"}` with any of `"name"`, `"refresh_hours"`, `"enabled"` | the lists as `GET /api/lists`; 404 for a list that is not there; 409 for a file list or a list turned on that would pass the budget; 502 when it cannot be downloaded |
| `/api/lists/remove` | `{"role", "source"}` | the lists, as above |
| `/api/lists/reset` | `{}` | the lists, back to this file's |

`GET /api/lists` (open without a password, like the list status) shows each list's `name`,
`kind`, `format`, `rules`, `age_seconds`, `last_error`, `enabled`, `refresh_hours`, `editable`
(a URL list), `from` (`"page"` or `"file"`) and `heap_bytes` (the memory its copy holds), and
the `memory` estimate. Signed in, it also shows each list's `source` (left out without a
password: an address can carry a private token) and `pending`, the list added last:
`{"kind", "name", "source", "state"}` with the state above. Without a password, `last_error`
only says "the last refresh failed (set a password to see why)" (here and in `/api/status`),
since a reason can quote a part of the address, and a list named by its address shows only
its host.

### The memory budget

`[limits] memory_mb` (default 48, under the 64 MB `MemoryMax` of the systemd unit and the Docker
compose file) is what picoguard's estimate of its whole memory may reach when something is
added from the page. The estimate is:

```
estimate = 6 MiB                                    the idle process (binary, runtime, threads)
         + pending_bytes + tcp_max_connections x tcp_queue_bytes     buffers under load
         + query_log_entries x 352 + 3 x top_k x 336                 the stats, when full
         + cache max_bytes x 1.25                                    the cache, when full
         + the memory of every list in force                         heap_bytes of each
         + the largest list's compile again                          a refresh builds a new copy
```

The lists of the [blocked services](#services) count as one list: their memory together, and the
compile of all of them again, since a refresh of the catalog builds the new lists while the old
ones are in force.

A list's compile is charged 24 bytes for each plain rule, duplicates included (its array grows
by doubling, so the old and new array live together for a moment), and the estimated cost of
each slow rule. Building a `/regex/` rule holds more for a moment (about 640 KB of compiler
tables, its parse, counted from its length and up to 96 KB for each Unicode class such as
`\pL`, plus five times its automaton at most), so a compile within little room refuses the list
before it parses or builds such a regex. A regex whose parse alone would pass 4 MB (dozens of
Unicode classes) is too complex and does not compile. The list's compile charge is the most its compile needed at
any one moment. A compile of the same text again always fits in that charge. The numbers are
measured: the tests compare them with what full stats, a full cache and the real
lists hold. With the defaults and the three default lists the estimate is about 25 MB.

- **Checked when** a list is added or turned on again, a list from the page is refreshed, the
  cache gets larger on the page, a blocked service is switched on, and the catalog of services is
  refreshed (when it does not fit, the lists in force stay). A list is compiled within the room the budget leaves and stops
  at once when it passes it, so a list far too large never fills the memory; then its finished
  copy must fit too.
- **A list from the page whose refresh grows past the budget** keeps its last good copy, and the
  list shows "over the memory budget" until a refresh fits again.
- **Lists of this file are never checked**, at start or on a refresh: an update never stops a
  setup that works. They keep their own `max_rules` and other caps, and they count in the
  estimate, so the page shows the estimate in red ("over the budget") when they pass it, and
  then nothing more can be added.
- One change at a time: adds, refreshes, cache changes and blocked services wait for each other,
  so two of them never count the same room.
- The Lists and Settings tabs show "Memory estimate: X MB of Y MB".

## Top-level keys

| Key | Default | Meaning |
|---|---|---|
| `blocked_ttl` | `10` | TTL in seconds of blocked answers. |
| `refuse_any` | `true` | Answer `ANY` queries with NOTIMP. |
| `blocked_hosts` | `["version.bind", "id.server", "hostname.bind"]` | Names answered with REFUSED. |
| `rules` | `[]` | Your own rules, one per string: adblock syntax or hosts lines. They join the lists below as one more list. The status page shows them read-only. |
| `safe_search` | `false` | Force SafeSearch on Google, Bing and DuckDuckGo, and restricted mode on YouTube. See [Rewrites and SafeSearch](#rewrites-and-safesearch). |
| `[[rewrites]]` | none | Names picoguard answers itself. See [Rewrites and SafeSearch](#rewrites-and-safesearch). |

`rules` example:

```toml
rules = [
    "||ads.example.com^",
    "@@||good.example.com^",
]
```

### Rewrites and SafeSearch

A rewrite makes picoguard answer a name itself, with addresses or with the addresses of another
name. Each `[[rewrites]]` entry has a `name` and an `answer`:

```toml
[[rewrites]]
name = "nas.lan"
answer = "192.168.1.10"

[[rewrites]]
name = "nas.lan"
answer = "fd00::10"

[[rewrites]]
name = "*.nas.lan"
answer = "nas.lan"
```

- `name` is a domain name of at least two labels, or `*.` and one: `*.nas.lan` covers every
  name under `nas.lan` (`tv.nas.lan`, `a.b.nas.lan`), not `nas.lan` itself. A name of its own
  beats a wildcard, and a longer wildcard beats a shorter one.
- `answer` is an IPv4 or IPv6 address, or another domain name. One name has either addresses
  (as many entries as you like) or exactly one other name, never both; a name may not point at
  itself. At most 1000 entries. An answer that only looks like an address (`192.168.001.10`)
  is refused.
- **Addresses**: an `A` query gets the IPv4 addresses, `AAAA` the IPv6 ones, both with TTL 60.
  Any other type, or a type with no address of its family, gets an empty answer (NOERROR, no
  records).
- **Another name**: for `A` and `AAAA`, picoguard looks that name up for the same type the
  usual way (the cache, then the upstreams; a name under `[local] domains` through the local
  resolver), but without rewrites or blocking. The
  answer holds only the addresses at the end of the name's CNAME chain, under the name that was
  asked (no CNAME records), with the smallest TTL on the way, counted down while it is cached,
  and at most 300 seconds. A name that does not exist, or has no such address, gives an empty
  answer; any other failure of the lookup, SERVFAIL. Other types get an empty answer. The
  name's own answer is cached as usual.
- **Another name that has addresses of its own rewrite** is answered with those addresses, as
  if they were written on the first name (TTL 60): `*.nas.lan → nas.lan` with
  `nas.lan → 192.168.1.10` answers `a.nas.lan` with 192.168.1.10. This is one step and only
  for addresses: when the other name is itself rewritten to a third name, that rewrite is not
  followed, and the other name is looked up as above, so rewrites never loop. The same holds
  for the SafeSearch names below: a rewrite of `forcesafesearch.google.com` to an address
  answers the Google searches with it.
- Rewrites come before `[local]` and the lists: a rewritten name is never blocked, a name under
  `[local] domains` can be rewritten without a `resolver`, and rewrites still apply while
  blocking is paused.
- A reply that waits to be written (a slow TCP client) follows the rewrites, SafeSearch and
  pause in force when it is written: a rewrite changed or a pause started or ended meanwhile
  answers the question the new way.
- The query log shows a rewritten query as "rewritten", and `/api/status` counts them in
  `counters.rewritten`.

`safe_search = true` adds rewrites of its own, the way AdGuard Home does it:

| Names | Answered with the addresses of |
|---|---|
| `google.<domain>` and `www.google.<domain>`, for each of Google's 187 search domains (`google.com`, `google.co.uk`, `google.de`, ...) | `forcesafesearch.google.com` |
| `bing.com`, `www.bing.com` | `strict.bing.com` |
| `duckduckgo.com`, `www.duckduckgo.com`, `start.duckduckgo.com` | `safe.duckduckgo.com` |
| `www.youtube.com`, `m.youtube.com`, `youtubei.googleapis.com`, `youtube.googleapis.com`, `www.youtube-nocookie.com` | `restrictmoderate.youtube.com` |

SafeSearch is off while blocking is paused. A rewrite of yours for the same name wins.

Memory: 1000 rewrites of home names hold about 80 KB, and 1000 of the longest names about
520 KB. They are not part of the memory estimate.

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

Device names: with `resolver` set, the signed-in page names each private client shown in Top
clients and the query log, from a PTR lookup to the router, with the IP beside the name. In the
API, each `top_clients` entry of `/api/status` and each `/api/querylog` entry has `name`: the
device name, or `null`. Names appear on a later refresh, never holding up the page or a DNS
answer. A name is kept for its record's TTL (5 minutes to 1 day), and "no name" for 5 minutes,
in memory, for at most 256 addresses. At most 4 lookups run at once, each giving up after 2
seconds. Loopback and public addresses are never looked up.

## `[[lists]]` and `[[allowlists]]`

Blocklists are `[[lists]]` tables. Allowlists (names that are never blocked) are
`[[allowlists]]` with the same keys. If the file has no `[[lists]]` at all, picoguard uses the
AdGuard DNS filter, HaGeZi Pro and HaGeZi Threat Intelligence mini. As soon as you write one
`[[lists]]`, only your lists are used. One `url` or `path` may appear once among the `[[lists]]`,
and once among the `[[allowlists]]`.

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
| `enabled` | `true` | A list that is off is not downloaded and holds no memory. The page can turn lists on and off. |
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

## `[services]`

Blocked services: switch a service on and picoguard blocks every name it uses, from one list of
rules per service. The list of services and their rules is AdGuard's catalog from
[HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry) (GPL-3.0). picoguard does
not ship it: it downloads it at run time, through its own upstreams, with the TLS and redirect
rules of the list downloads.

```toml
[services]
block = ["tiktok", "youtube"]
```

| Key | Default | Meaning |
|---|---|---|
| `block` | `[]` | The ids of the services to block (the catalog's `id`, for example `tiktok`). At most 1000, each 1 to 64 visible characters, none twice. The status page can change it. |
| `catalog_url` | AdGuard's `services.json` on `adguardteam.github.io` | Where the catalog is downloaded from, `http://` or `https://`. Not on the page. |
| `refresh_hours` | `24` | How often the catalog is downloaded again while a service is on. Not on the page. |

- With no service switched on, the catalog is never downloaded, except once when the Settings
  tab is opened, to show the services.
- At start with services on, the catalog is downloaded once; until it is read, those services are
  not blocked (the page says "loading"). It is downloaded again every `refresh_hours`; a refresh
  that fails, or whose lists would pass the [memory budget](#the-memory-budget), keeps the lists
  in force and tries again later, with the same waits as a list.
- Each service switched on is a list of its own, named "Blocked service: <name>": **Check a
  name** names it, a pause turns it off like every list, and an allowlist or an Allow rule wins
  over it as over any list.
- No copy of the catalog or of the services' lists is ever written to disk.
- Caps: a catalog of at most 2 MiB, read once and freed at once; at most 1000 services; an id and
  a name of at most 64 bytes, a group of at most 32, at most 2000 rules of at most 256 bytes per
  service (a service over a cap is left out); the services switched on hold at most 20,000 rules
  together (AdGuard's whole catalog held 2,406 in 2026). Exception rules (`@@`) and rules with
  `$badfilter` or `$important` are left out: a service only blocks, and never changes other lists.
- Memory: the index of the catalog (ids, names and groups) holds about 12 KB, and every service
  of a catalog of AdGuard's size switched on about 100 KB. The index is not part of the memory
  estimate; the lists are.

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
| `memory_mb` | `48` | The budget of the [memory estimate](#the-memory-budget): a list added or turned on from the page, a refresh of a page list and a larger cache set on the page must keep the estimate within it. Lists of this file are never checked. |

## `[web]`

The status page. With `user` and a password (`password_hash`, or `password`) set, it shows totals,
top blocked domains, top clients, upstream servers, the cache, recent queries and list status, and
can pause blocking for a set time, refresh the lists, clear the DNS cache, block or allow a name,
and check which rule decides a name.

Without a password the page is read-only and limited: it shows totals and list status only. The
query log, pause, resume, refresh, Clear cache, `/api/rules`, `/api/rules/remove`,
`/api/explain` and `/api/settings` answer 403 ("set web.user and web.password_hash (or web.password) to use this"),
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
- picoguard's own lookups count too: list downloads and the update check, and device-name lookups
  (on the local entry).
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

- The rules are saved on the device (see "Settings saved from the status page") and are back
  after a restart or an update. A change is saved before it is in force; one that cannot be saved
  answers 503 and changes nothing.
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
| `GET /api/explain?name=...` | | `{"name": "ads.example", "decision": "blocked", "list": "config rules", "rule": "\|\|ads.example^"}`; `decision` is `blocked`, `allowed`, `rewritten` (see [Rewrites and SafeSearch from the page](#rewrites-and-safesearch-from-the-page)) or `none` (then `list` and `rule` are `null`) |

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
| `dir` | `"/var/lib/picoguard"` | Where list snapshots and the settings saved from the status page (`settings.json`) go. The systemd unit creates this directory (`StateDirectory=picoguard`). |
| `persist_lists` | `true` | Keep a copy of each changed list on disk. This is the only routine write; `settings.json` is written only when you save a change on the page. When `false`, no list is written; lists live in memory and download again at every start. |

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
  version (`picoguard/0.4.0`), and, from the second check on, the ETag of the last answer. No
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
