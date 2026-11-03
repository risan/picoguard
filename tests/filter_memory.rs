//! Heap cost of plain rules. This test binary has a counting global allocator and a single
//! test, so nothing else allocates while it measures.

use picoguard::filter::engine::CompiledList;
use picoguard::filter::parse::ListFormat;

#[path = "common/counting.rs"]
mod counting;

use counting::live;

#[global_allocator]
static ALLOCATOR: counting::Counting = counting::Counting;

const RULES: usize = 450_000;

#[test]
fn a_plain_rule_costs_at_most_nine_bytes_of_heap() {
    let mut text = String::with_capacity(RULES * 30);
    for n in 0..RULES {
        text.push_str(&format!("||host{n}.tracker{}.example^\n", n % 977));
    }

    let before = live();
    let (list, summary) = CompiledList::from_text(ListFormat::Adblock, &text);
    let after = live();

    assert_eq!(summary.counters.block_sub, RULES as u64);
    assert_eq!(list.rule_count(), RULES);

    let per_rule = (after - before) as f64 / RULES as f64;
    println!("heap per plain rule: {per_rule:.3} bytes");
    assert!(per_rule <= 9.0, "{per_rule} bytes per rule");
}
