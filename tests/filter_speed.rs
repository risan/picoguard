//! Check time on the real lists. Timing only means something in a release build, so the
//! bound is asserted there: `cargo test --release --test filter_speed -- --nocapture`.

mod common;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use common::load_real;
use picoguard::filter::engine::{CompiledList, Decision, Engine};
use picoguard::filter::parse::{ListFormat, dns_type_code};

/// The target of plan S2.5 on x86 (P2 measured 26 microseconds before the index).
const MAX_AVERAGE_MICROS: f64 = 2.0;

#[test]
fn a_check_on_the_real_lists_is_fast() {
    let real = load_real();
    let lists: Vec<_> = real
        .lists
        .iter()
        .map(|text| Arc::new(CompiledList::from_text(ListFormat::Adblock, text).0))
        .collect();
    let slow: usize = lists.iter().map(|list| list.slow_rule_count()).sum();
    let engine = Engine::new(lists, Vec::new());
    let queries: Vec<_> = real
        .expected
        .iter()
        .map(|entry| {
            let query = &entry.query;
            let is_ip = query.input.parse::<IpAddr>().is_ok();

            (
                query.input.as_str(),
                dns_type_code(&query.check_type).unwrap(),
                is_ip,
            )
        })
        .collect();

    // The best of several passes keeps a busy machine from failing the bound.
    let passes = if cfg!(debug_assertions) { 1 } else { 10 };
    let mut best = f64::MAX;
    let mut blocked = 0;
    for _ in 0..passes {
        blocked = 0;
        let started = Instant::now();
        for _ in 0..5 {
            for &(input, record_type, is_ip) in &queries {
                if engine.check(input, record_type, is_ip) != Decision::Pass {
                    blocked += 1;
                }
            }
        }

        best = best.min(started.elapsed().as_secs_f64() * 1e6 / (5 * queries.len()) as f64);
    }

    let average = best;
    println!(
        "check: {average:.2} us average over {} queries, {slow} slow rules, {} blocked per pass",
        queries.len(),
        blocked / 5
    );
    assert!(blocked > 0);

    if !cfg!(debug_assertions) {
        assert!(
            average <= MAX_AVERAGE_MICROS,
            "{average:.2} us per check, limit {MAX_AVERAGE_MICROS} us"
        );
    }
}
