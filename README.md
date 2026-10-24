# picoguard

A DNS ad and malware blocker written in Rust, built to run on a 256 MB ARM board
(Orange Pi Zero class) with very little memory, CPU and SD-card wear.

It forwards to encrypted upstreams (DoH, DoT), reads the popular blocklist
formats (adblock/AdGuard DNS syntax, hosts, plain domains, wildcard domains,
dnsmasq, RPZ) and keeps its query log and statistics in memory only.

## Status

In development. Nothing is usable yet: the config file loads and validates
(`picoguard --check`), the DNS server is not built.

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
- IP addresses of a host rule that appears on several lines of one list are answered grouped
  by address, not in line order.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
