//! Check time on the real lists. Timing only means something in a release build, so the
//! bound is asserted there: `cargo test --release --test filter_speed -- --nocapture`.

mod common;

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{RealLists, load_real};
use picoguard::filter::engine::{CompiledList, Decision, Engine, ListBuilder};
use picoguard::filter::parse::{FastKind, ListFormat, Rule, dns_type_code};

/// The target of plan S2.5 on x86 (P2 measured 26 microseconds before the index).
const MAX_AVERAGE_MICROS: f64 = 2.0;

/// Page rules at their cap.
const PAGE_RULES: usize = 500;

/// The most one rule change may take: the two page lists and their rule sets.
const MAX_RULE_CHANGE: Duration = Duration::from_millis(5);

fn compile_real(real: &RealLists) -> Vec<Arc<CompiledList>> {
    real.lists
        .iter()
        .map(|text| Arc::new(CompiledList::from_text(ListFormat::Adblock, text).0))
        .collect()
}

fn queries_of(real: &RealLists) -> Vec<(&str, u16, bool)> {
    real.expected
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
        .collect()
}

/// The first `count` distinct names the real queries ask for: what users see in their log.
fn logged_names(real: &RealLists, count: usize) -> Vec<String> {
    let mut seen = HashSet::new();

    real.expected
        .iter()
        .map(|entry| entry.query.input.to_ascii_lowercase())
        .filter(|input| input.parse::<IpAddr>().is_err())
        .filter(|input| seen.insert(input.clone()))
        .take(count)
        .collect()
}

/// A page list as the scheduler builds it: one plain rule per name, no text parsed.
fn page_list(names: &[String], kind: FastKind) -> Arc<CompiledList> {
    let mut builder = ListBuilder::new();
    for name in names {
        builder.add(Rule::Fast { kind, name });
    }

    Arc::new(builder.finish(ListFormat::Adblock))
}

/// The best average of several passes, in microseconds, and the blocked queries of one pass.
/// The best of several passes keeps a busy machine from failing the bound.
fn best_check_micros(engine: &Engine, queries: &[(&str, u16, bool)]) -> (f64, usize) {
    let passes = if cfg!(debug_assertions) { 1 } else { 10 };
    let mut best = f64::MAX;
    let mut blocked = 0;
    for _ in 0..passes {
        blocked = 0;
        let started = Instant::now();
        for _ in 0..5 {
            for &(input, record_type, is_ip) in queries {
                if engine.check(input, record_type, is_ip) != Decision::Pass {
                    blocked += 1;
                }
            }
        }

        best = best.min(started.elapsed().as_secs_f64() * 1e6 / (5 * queries.len()) as f64);
    }

    (best, blocked / 5)
}

fn best_of(rounds: usize, mut work: impl FnMut()) -> Duration {
    (0..rounds)
        .map(|_| {
            let started = Instant::now();
            work();

            started.elapsed()
        })
        .min()
        .unwrap()
}

#[test]
fn a_check_on_the_real_lists_is_fast() {
    let real = load_real();
    let lists = compile_real(&real);
    let slow: usize = lists.iter().map(|list| list.slow_rule_count()).sum();
    let engine = Engine::new(lists, Vec::new());
    let queries = queries_of(&real);

    let (average, blocked) = best_check_micros(&engine, &queries);
    println!(
        "check: {average:.2} us average over {} queries, {slow} slow rules, {blocked} blocked per pass",
        queries.len(),
    );
    assert!(blocked > 0);

    if !cfg!(debug_assertions) {
        assert!(
            average <= MAX_AVERAGE_MICROS,
            "{average:.2} us per check, limit {MAX_AVERAGE_MICROS} us"
        );
    }
}

/// The extra hashed suffix pass of the page blocks, against the same lists without them. Both
/// engines are timed in the same passes, so a busy machine slows both alike.
const MAX_PAGE_BLOCK_SLOWDOWN: f64 = 1.5;

#[test]
fn a_check_with_500_page_blocks_stays_fast() {
    let real = load_real();
    let names = logged_names(&real, PAGE_RULES);
    assert_eq!(names.len(), PAGE_RULES);
    let without = Engine::new(compile_real(&real), Vec::new());
    let with = without.with_pinned(vec![page_list(&names, FastKind::SubBlock)], Vec::new());
    let queries = queries_of(&real);

    let (mut baseline, mut average, mut blocked) = (f64::MAX, f64::MAX, 0);
    for _ in 0..if cfg!(debug_assertions) { 1 } else { 5 } {
        baseline = baseline.min(best_check_micros(&without, &queries).0);
        let (micros, pass_blocked) = best_check_micros(&with, &queries);
        average = average.min(micros);
        blocked = pass_blocked;
    }

    println!(
        "check with {PAGE_RULES} page blocks: {average:.2} us average over {} queries ({baseline:.2} us without), {blocked} blocked per pass",
        queries.len(),
    );
    assert!(blocked > 0);

    if !cfg!(debug_assertions) {
        assert!(
            average <= baseline * MAX_PAGE_BLOCK_SLOWDOWN,
            "{average:.2} us per check with page blocks, {baseline:.2} us without"
        );
    }
}

/// Measured on an AMD Ryzen 9 5900X, release, best of 10: the assemble of a refresh over the
/// three real lists (612,151 rules, 878 slow) took 0.012 to 0.013 ms, and a rule change with 500
/// page blocks and 500 page allows 0.010 ms.
#[test]
fn assembly_and_a_rule_change_on_the_real_lists_take_milliseconds() {
    let real = load_real();
    let lists = compile_real(&real);
    let blocks = logged_names(&real, PAGE_RULES);
    let allows: Vec<String> = (0..PAGE_RULES)
        .map(|index| format!("page-allow-{index:03}.example"))
        .collect();

    let assemble = best_of(10, || {
        std::hint::black_box(Engine::new(lists.clone(), Vec::new()));
    });
    let engine = Engine::new(lists.clone(), Vec::new());
    let rule_change = best_of(10, || {
        let block = page_list(&blocks, FastKind::SubBlock);
        let allow = page_list(&allows, FastKind::SubAllow);
        std::hint::black_box(engine.with_pinned(vec![block], vec![allow]));
    });

    println!(
        "assemble over the real lists: {:.3} ms; a rule change with {PAGE_RULES} blocks and {PAGE_RULES} allows: {:.3} ms",
        assemble.as_secs_f64() * 1e3,
        rule_change.as_secs_f64() * 1e3
    );

    if !cfg!(debug_assertions) {
        assert!(
            rule_change <= MAX_RULE_CHANGE,
            "a rule change took {rule_change:?}, limit {MAX_RULE_CHANGE:?}"
        );
    }
}
