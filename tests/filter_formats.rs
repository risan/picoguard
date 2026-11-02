//! `auto` detection and parsing on complete real list files.

mod common;

use std::net::IpAddr;
use std::sync::Arc;

use common::{fixtures_dir, read_text};
use picoguard::filter::engine::{CompiledList, Decision, Engine, TYPE_A, TYPE_AAAA};
use picoguard::filter::parse::{Counters, ListFormat, ParseSummary, Parser, Rule};

fn parse_file(name: &str, format: ListFormat) -> ParseSummary {
    let text = read_text(&fixtures_dir().join(format!("lists/{name}.txt.gz")));
    let mut parser = Parser::new(format, usize::MAX);
    let mut sink = |_: Rule<'_>| {};
    for chunk in text.as_bytes().chunks(64 * 1024) {
        parser.push(chunk, &mut sink);
    }

    parser.finish(&mut sink)
}

fn counters(name: &str) -> Counters {
    parse_file(name, ListFormat::Auto).counters
}

#[test]
fn auto_picks_the_right_format_for_every_real_list() {
    for (name, expected) in [
        ("adguard-dns", ListFormat::Adblock),
        ("hagezi-pro", ListFormat::Adblock),
        ("hagezi-tif-mini", ListFormat::Adblock),
        ("hagezi-adblock-dyndns", ListFormat::Adblock),
        ("hagezi-wildcard-dyndns", ListFormat::Wildcard),
        ("hagezi-wildcard-dyndns-onlydomains", ListFormat::Wildcard),
        ("hagezi-dnsmasq-dyndns", ListFormat::Dnsmasq),
        ("hagezi-rpz-dyndns", ListFormat::Rpz),
        // A hosts file is AdGuard grammar: it understands hosts lines natively.
        ("stevenblack-hosts", ListFormat::Adblock),
    ] {
        assert_eq!(
            parse_file(name, ListFormat::Auto).format,
            expected,
            "{name}"
        );
    }
}

/// Counts the lines of the exact form `||d^` (or `@@||d^`) the way a grep would.
fn plain_lines(name: &str, prefix: &str) -> u64 {
    let text = read_text(&fixtures_dir().join(format!("lists/{name}.txt.gz")));

    text.lines()
        .filter(|line| {
            line.strip_prefix(prefix)
                .and_then(|rest| rest.strip_suffix('^'))
                .is_some_and(|domain| {
                    !domain.is_empty()
                        && domain.bytes().all(|b| {
                            b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)
                        })
                })
        })
        .count() as u64
}

#[test]
fn adguard_dns_filter_census() {
    let counters = counters("adguard-dns");
    // The plan quoted 190,791 and 191 for the download of the planning session; this
    // is the fixture downloaded on 2026-10-24 (see tests/fixtures/lists/README.md).
    assert_eq!(counters.block_sub, 190_543);
    assert_eq!(counters.block_sub, plain_lines("adguard-dns", "||"));
    assert_eq!(counters.allow_sub, 11);
    assert_eq!(counters.allow_sub, plain_lines("adguard-dns", "@@||"));
    assert_eq!(counters.invalid, 0, "{:?}", counters.first_invalid);
    assert!(counters.slow_rules > 500 && counters.slow_rules < 2_000);
    assert!(counters.regex_rules > 0);
    assert_eq!(counters.too_long, 0);
}

#[test]
fn hagezi_adblock_lists_are_plain_rules() {
    for (name, rules) in [("hagezi-pro", 208_296), ("hagezi-tif-mini", 212_422)] {
        let counters = counters(name);
        assert_eq!(counters.block_sub, rules, "{name}");
        assert_eq!(counters.block_sub, plain_lines(name, "||"));
        assert_eq!(counters.slow_rules, 0, "{name}");
        assert_eq!(counters.invalid, 0, "{name}");
        assert_eq!(counters.headers, 1, "{name}");
    }
}

#[test]
fn explicit_and_detected_wildcard_lists_agree() {
    let detected = parse_file("hagezi-wildcard-dyndns", ListFormat::Auto);
    let explicit = parse_file("hagezi-wildcard-dyndns", ListFormat::Wildcard);
    assert_eq!(detected, explicit);
    assert_eq!(detected.counters.block_sub, 1_541);
    assert_eq!(detected.counters.invalid, 0);

    let only_domains = parse_file("hagezi-wildcard-dyndns-onlydomains", ListFormat::Auto);
    assert_eq!(only_domains.counters.block_sub, detected.counters.block_sub);
}

#[test]
fn dnsmasq_and_rpz_lists_block_the_same_domains() {
    let dnsmasq = counters("hagezi-dnsmasq-dyndns");
    assert_eq!(dnsmasq.block_sub, 1_541);
    assert_eq!(dnsmasq.invalid, 0);

    // RPZ lists every domain twice: the name and `*.name`.
    let rpz = counters("hagezi-rpz-dyndns");
    assert_eq!(rpz.block_exact, 1_541);
    assert_eq!(rpz.strict_sub_block, 1_541);
    // $TTL and the SOA / NS records of the zone apex.
    assert_eq!(rpz.rpz_skipped, 2);
}

#[test]
fn hosts_file_is_read_as_host_rules() {
    let counters = counters("stevenblack-hosts");
    assert!(counters.host_names > 70_000, "{}", counters.host_names);
    assert_eq!(counters.slow_rules, 0);
    assert_eq!(counters.invalid, 0, "{:?}", counters.first_invalid);
    assert_eq!(counters.unmatchable_hosts, 0);
}

#[test]
fn explicit_hosts_format_reads_the_same_names() {
    let auto = counters("stevenblack-hosts");
    let hosts = parse_file("stevenblack-hosts", ListFormat::Hosts).counters;
    assert_eq!(hosts.host_names, auto.host_names);
    assert_eq!(hosts.invalid, 0);
}

fn engine_of_hosts(text: &str) -> Engine {
    let (list, _) = CompiledList::from_text(ListFormat::Hosts, text);

    Engine::new(vec![Arc::new(list)], Vec::new())
}

fn answer_of(engine: &Engine, name: &str, record_type: u16) -> Option<Vec<IpAddr>> {
    match engine.check(name, record_type, false) {
        Decision::Block { ips } => Some(ips),
        Decision::Pass => None,
    }
}

#[test]
fn every_name_of_the_real_hosts_list_is_redirected_and_a_near_miss_is_not() {
    let text = read_text(&fixtures_dir().join("lists/stevenblack-hosts.txt.gz"));
    let engine = engine_of_hosts(&text);
    let null: IpAddr = "0.0.0.0".parse().unwrap();
    let names: Vec<&str> = text
        .lines()
        .filter_map(|line| line.strip_prefix("0.0.0.0 "))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter(|name| *name != "0.0.0.0")
        .collect();
    assert!(names.len() > 70_000, "{}", names.len());

    for name in &names {
        assert_eq!(answer_of(&engine, name, TYPE_A), Some(vec![null]), "{name}");
    }

    for name in names.iter().step_by(97) {
        let mut changed = name.to_string();
        changed.insert(0, 'x');

        assert_eq!(answer_of(&engine, &changed, TYPE_A), None, "{changed}");
        assert_eq!(answer_of(&engine, &format!("sub.{name}"), TYPE_A), None);
    }
}

/// 100,000 names over 50 answer IPs, a third of them with an IPv6 address, every seventh
/// with both families.
#[test]
fn a_large_hosts_list_answers_every_name_with_its_own_addresses() {
    let address_of = |n: usize, ipv6: bool| -> IpAddr {
        if ipv6 {
            format!("2001:db8::{:x}", n % 50 + 1).parse().unwrap()
        } else {
            format!("10.0.{}.1", n % 50).parse().unwrap()
        }
    };
    let families_of = |n: usize| match (n.is_multiple_of(7), n.is_multiple_of(3)) {
        (true, _) => (true, true),
        (false, ipv6) => (!ipv6, ipv6),
    };
    let mut text = String::new();
    for n in 0..100_000 {
        let (v4, v6) = families_of(n);
        if v4 {
            text.push_str(&format!("{} host{n}.example\n", address_of(n, false)));
        }

        if v6 {
            text.push_str(&format!("{} host{n}.example\n", address_of(n, true)));
        }
    }

    let engine = engine_of_hosts(&text);

    for n in 0..100_000 {
        let name = format!("host{n}.example");
        let (v4, v6) = families_of(n);
        let expected = |wanted: bool, ipv6: bool| {
            Some(if wanted {
                vec![address_of(n, ipv6)]
            } else {
                Vec::new()
            })
        };

        assert_eq!(
            answer_of(&engine, &name, TYPE_A),
            expected(v4, false),
            "{name}"
        );
        assert_eq!(
            answer_of(&engine, &name, TYPE_AAAA),
            expected(v6, true),
            "{name}"
        );
    }

    for n in (0..100_000).step_by(11) {
        for missing in [
            format!("hosu{n}.example"),
            format!("host{n}.exampl"),
            format!("sub.host{n}.example"),
            format!("host{}.example", n + 100_000),
        ] {
            assert_eq!(answer_of(&engine, &missing, TYPE_A), None, "{missing}");
        }
    }

    assert_eq!(answer_of(&engine, "example", TYPE_A), None);
}
