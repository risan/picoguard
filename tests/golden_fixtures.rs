//! The golden files are complete and consistent with their inputs. The oracles that
//! produce them are not run here (tests are hermetic); `tools/regen.sh` regenerates them
//! and `tools/check-oracle.sh` checks the matcher oracle against the AdGuard Home binary.

mod common;

use common::{fixtures_dir, load_cases, load_real, read_text};

#[test]
fn every_case_has_an_expected_line_per_query() {
    let cases = load_cases();
    assert!(cases.len() >= 12, "only {} cases", cases.len());

    for case in &cases {
        assert!(!case.queries.is_empty(), "{}: no queries", case.name);
        assert_eq!(
            case.queries.len(),
            case.expected.len(),
            "{}: expected file out of date, run tools/regen.sh oracle",
            case.name
        );

        for (query, expected) in case.queries.iter().zip(&case.expected) {
            assert_eq!(query, &expected.query, "{}: query order", case.name);
        }
    }
}

#[test]
fn deviations_name_queries_where_the_oracle_decides_differently() {
    let mut deviations = 0;
    for case in load_cases() {
        for (query, picoguard) in &case.deviations {
            let expected = case
                .expected
                .iter()
                .find(|expected| &expected.query == query)
                .unwrap_or_else(|| panic!("{}: deviation for unknown query {query:?}", case.name));
            assert_ne!(
                &expected.outcome, picoguard,
                "{}: {query:?} is not a deviation any more",
                case.name
            );
            deviations += 1;
        }
    }

    assert!(
        deviations >= 3,
        "the overlapping $badfilter case is missing"
    );
}

#[test]
fn matcher_cases_cover_the_plan_list() {
    let mut text = String::new();
    for case in load_cases() {
        text.push_str(&case.main.concat());
        text.push_str(&case.user);
        text.push_str(&case.allow.concat());
    }

    for needle in [
        "$important",
        "$badfilter",
        "$denyallow=",
        "$dnstype=",
        "$script",
        "$~script",
        "$document",
        "$third-party",
        "$~third-party",
        "$domain=",
        "$client=",
        "$ctag=",
        "$dnsrewrite=",
        "\\p{Latin}",
        "\\Q",
        "(?i)",
        "||ADS.example^",
        "|dead^",
        "||dead^",
    ] {
        assert!(text.contains(needle), "no fixture rule uses {needle}");
    }
}

#[test]
fn real_list_fixtures_have_enough_varied_queries() {
    let real = load_real();
    assert_eq!(real.lists.len(), 3);
    assert!(real.lists.iter().all(|list| list.lines().count() > 100_000));
    assert!(
        real.expected.len() >= 1000,
        "{} queries",
        real.expected.len()
    );

    let blocked = real.expected.iter().filter(|e| e.outcome.blocked).count();
    assert!(blocked > 300 && real.expected.len() - blocked > 300);

    let types: std::collections::BTreeSet<&str> = real
        .expected
        .iter()
        .map(|e| e.query.check_type.as_str())
        .collect();
    for ty in ["A", "AAAA", "HTTPS", "TXT", "CNAME"] {
        assert!(types.contains(ty), "no {ty} query");
    }

    let ips = real
        .expected
        .iter()
        .filter(|e| e.query.input.parse::<std::net::IpAddr>().is_ok())
        .count();
    assert!(ips >= 20, "{ips} IP inputs");
}

#[test]
fn flow_golden_has_a_reply_for_every_query() {
    let dir = fixtures_dir().join("golden/flow");
    let case = read_text(&dir.join("flow.case"));
    let queries = case
        .split("[queries]\n")
        .nth(1)
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .count();
    let expected = read_text(&dir.join("flow.expected"));
    assert_eq!(
        expected
            .lines()
            .filter(|line| line.starts_with("Q "))
            .count(),
        queries
    );
}
