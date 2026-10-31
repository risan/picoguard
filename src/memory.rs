//! The memory budget (plan D6): an estimate of what the whole process may hold, checked
//! against `[limits] memory_mb` before a list from the page is put in force and before the
//! page makes the cache larger. The constants are measured; `tests/memory_estimate.rs` checks
//! the estimate against what full stats, a full cache and real lists hold.

use crate::config::{LimitsConfig, StatsConfig};

const MIB: usize = 1024 * 1024;

/// The process with no lists, an empty cache and empty stats: the binary and its libraries,
/// the runtime, the stacks of its threads and the servers' small heap. A release build on
/// x86_64 measured 5.6 MB of RSS (5.0 MB of it the binary and libc).
pub const IDLE_BYTES: usize = 6 * MIB;

/// A full query-log slot: the slot and a name of the longest wire length, with the
/// allocator's overhead. With the top lists below: 1,000 entries and top 50 measured 362,264
/// bytes for 402,400 reserved; 5,000 and top 100, 1,723,633 for 1,860,800.
pub const QUERY_LOG_ENTRY_BYTES: usize = 352;

/// An entry of one of the three top lists (names asked, names blocked, clients), with its name.
pub const TOP_ENTRY_BYTES: usize = 336;

/// What a full cache holds on the heap per byte it counts against `max_bytes`, in percent:
/// its slots and hash table grow past the counted cost. Measured 110 % for caches of 256 KiB
/// and 4 MiB full of replies of 50 to 300 bytes.
pub const CACHE_HEAP_PERCENT: usize = 125;

/// What the estimate shows on the page: what the process may hold, and the budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Memory {
    pub estimate_bytes: usize,
    pub budget_bytes: usize,
}

/// Bytes that stay the same while picoguard runs: the idle process, the buffers its limits
/// allow (replies held for delivery, the TCP output queues) and the stats, which are
/// allocated up to their sizes and never shrink.
pub fn fixed_bytes(limits: &LimitsConfig, stats: &StatsConfig) -> usize {
    IDLE_BYTES
        + limits.pending_bytes
        + limits.tcp_max_connections * limits.tcp_queue_bytes
        + stats_bytes(stats)
}

pub fn stats_bytes(stats: &StatsConfig) -> usize {
    stats.query_log_entries * QUERY_LOG_ENTRY_BYTES + 3 * stats.top_k * TOP_ENTRY_BYTES
}

pub fn cache_bytes(max_bytes: usize) -> usize {
    max_bytes / 100 * CACHE_HEAP_PERCENT
}

pub fn budget_bytes(limits: &LimitsConfig) -> usize {
    limits.memory_mb * MIB
}

/// What one compiled list in force counts in the estimate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ListBytes {
    /// `CompiledList::heap_bytes`.
    pub heap: usize,
    /// `CompiledList::compile_charge`: what compiling it again holds at the peak.
    pub charge: usize,
}

/// What is held besides the room of the one compile that may run: the fixed part, the cache at
/// its `max_bytes`, and every list in force.
pub fn steady_bytes(fixed: usize, cache_max_bytes: usize, lists: &[ListBytes]) -> usize {
    fixed + cache_bytes(cache_max_bytes) + lists.iter().map(|list| list.heap).sum::<usize>()
}

/// The estimate of the whole process: what is steadily held, and the largest list's compile
/// charge again, since a refresh holds the old copy while the new one is built. Compiles run
/// one at a time, so one charge covers any of them.
pub fn estimate(fixed: usize, cache_max_bytes: usize, lists: &[ListBytes]) -> usize {
    let largest = lists.iter().map(|list| list.charge).max().unwrap_or(0);

    steady_bytes(fixed, cache_max_bytes, lists) + largest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_estimate_adds_the_largest_compile_charge_to_what_is_held() {
        let lists = [
            ListBytes {
                heap: 1000,
                charge: 3000,
            },
            ListBytes {
                heap: 500,
                charge: 4000,
            },
        ];

        assert_eq!(steady_bytes(10_000, 400, &lists), 10_000 + 500 + 1500);
        assert_eq!(estimate(10_000, 400, &lists), 10_000 + 500 + 1500 + 4000);
        assert_eq!(estimate(10_000, 400, &[]), 10_500);
    }

    #[test]
    fn the_default_settings_leave_most_of_the_budget_for_lists() {
        let config = crate::config::Config::default();
        let fixed = fixed_bytes(&config.limits, &config.stats);

        assert_eq!(budget_bytes(&config.limits), 48 * MIB);
        assert!(fixed + cache_bytes(config.cache.max_bytes) < 16 * MIB);
    }
}
