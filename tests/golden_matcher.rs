//! The matcher golden decisions: picoguard must give the decision and the blocked answer
//! the AdGuard Home oracle gives, on the hand-written cases and on the real lists. The
//! deviations listed in a case (plan D7) must differ from the oracle exactly as written.

mod common;

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;

use common::{Case, Expected, Outcome, Query, load_cases, load_real};
use picoguard::filter::engine::{BlockedAnswer, CompiledList, Decision, Engine, blocked_answer};
use picoguard::filter::parse::{ListFormat, dns_type_code};

fn compile(text: &str) -> Arc<CompiledList> {
    Arc::new(CompiledList::from_text(ListFormat::Adblock, text).0)
}

/// The engine AdGuard Home builds: user rules first, then the lists; allowlists apart.
fn engine_for(case: &Case) -> Engine {
    let mut main = Vec::new();
    if !case.user.is_empty() {
        main.push(compile(&case.user));
    }

    main.extend(case.main.iter().map(|text| compile(text)));
    let allow = case.allow.iter().map(|text| compile(text)).collect();

    Engine::new(main, allow)
}

fn type_code(name: &str) -> u16 {
    dns_type_code(name).unwrap_or_else(|| panic!("unknown record type {name}"))
}

fn ip_set(answer: &str) -> BTreeSet<IpAddr> {
    answer
        .split(',')
        .map(|ip| ip.parse().unwrap_or_else(|_| panic!("bad ip {ip:?}")))
        .collect()
}

/// Whether picoguard's outcome equals the oracle's. The IPs of a blocked answer are
/// compared as sets: a record set has no order, and picoguard keeps the IPs of a list
/// grouped by address rather than by line.
fn same_outcome(actual: &Outcome, expected: &Outcome) -> bool {
    if actual.blocked != expected.blocked {
        return false;
    }

    if matches!(expected.answer.as_str(), "" | "empty" | "nodata")
        || actual.answer == expected.answer
    {
        return actual.answer == expected.answer;
    }

    actual
        .answer
        .contains(|c: char| c.is_ascii_digit() || c == ':')
        && ip_set(&actual.answer) == ip_set(&expected.answer)
}

fn outcome(engine: &Engine, query: &Query) -> Outcome {
    let is_ip = query.input.parse::<IpAddr>().is_ok();
    match engine.check(&query.input, type_code(&query.check_type), is_ip) {
        Decision::Pass => Outcome {
            blocked: false,
            answer: String::new(),
        },
        Decision::Block { ips } => {
            let answer = match blocked_answer(type_code(&query.query_type), &ips) {
                BlockedAnswer::NoData => "nodata".to_string(),
                BlockedAnswer::Empty => "empty".to_string(),
                BlockedAnswer::TooMany => "toomany".to_string(),
                BlockedAnswer::Ips(ips) => ips
                    .iter()
                    .map(IpAddr::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            };

            Outcome {
                blocked: true,
                answer,
            }
        }
    }
}

fn compare(engine: &Engine, expected: &[Expected], deviations: &[(Query, Outcome)]) -> Vec<String> {
    let mut mismatches = Vec::new();
    for entry in expected {
        let actual = outcome(engine, &entry.query);
        let deviation = deviations.iter().find(|(query, _)| query == &entry.query);
        match deviation {
            Some((_, picoguard)) => {
                if &actual != picoguard {
                    mismatches.push(format!(
                        "{}: expected deviation {picoguard:?}, got {actual:?}",
                        entry.query.key()
                    ));
                }
            }
            None => {
                if !same_outcome(&actual, &entry.outcome) {
                    mismatches.push(format!(
                        "{}: oracle {:?}, picoguard {actual:?}",
                        entry.query.key(),
                        entry.outcome
                    ));
                }
            }
        }
    }

    mismatches
}

#[test]
fn hand_written_cases_match_the_oracle() {
    let mut total = 0;
    let mut deviations = 0;
    for case in load_cases() {
        let engine = engine_for(&case);
        let mismatches = compare(&engine, &case.expected, &case.deviations);
        assert!(
            mismatches.is_empty(),
            "{}: {} of {} differ\n{}",
            case.name,
            mismatches.len(),
            case.expected.len(),
            mismatches.join("\n")
        );
        total += case.expected.len();
        deviations += case.deviations.len();
    }

    println!("golden: {total} hand-written queries match ({deviations} are expected deviations)");
    assert!(total > 600);
}

#[test]
fn real_lists_match_the_oracle() {
    let real = load_real();
    let lists = real.lists.iter().map(|text| compile(text)).collect();
    let engine = Engine::new(lists, Vec::new());
    let mismatches = compare(&engine, &real.expected, &[]);
    assert!(
        mismatches.is_empty(),
        "{} of {} differ\n{}",
        mismatches.len(),
        real.expected.len(),
        mismatches[..mismatches.len().min(40)].join("\n")
    );

    println!("golden: {} real-list queries match", real.expected.len());
}
