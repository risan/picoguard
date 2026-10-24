# picoguard

A DNS ad and malware blocker written in Rust, built to run on a 256 MB ARM board
(Orange Pi Zero class) with very little memory, CPU and SD-card wear.

It forwards to encrypted upstreams (DoH, DoT), reads the popular blocklist
formats (adblock/AdGuard DNS syntax, hosts, plain domains, wildcard domains,
dnsmasq, RPZ) and keeps its query log and statistics in memory only.

## Status

In development. Nothing is usable yet: the config file loads and validates
(`picoguard --check`), the DNS server is not built.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
