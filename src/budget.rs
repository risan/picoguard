//! A byte budget that hands out charges which give the bytes back on drop.
//! One global budget covers every reply held for delivery; each TCP
//! connection has a smaller one for its output queue.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct Budget {
    used: AtomicUsize,
    capacity: usize,
}

impl Budget {
    pub fn new(capacity: usize) -> Arc<Budget> {
        Arc::new(Budget {
            used: AtomicUsize::new(0),
            capacity,
        })
    }

    /// Reserves `bytes`, or returns `None` when that would pass the capacity.
    pub fn try_charge(self: &Arc<Budget>, bytes: usize) -> Option<Charge> {
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|total| *total <= self.capacity)
            })
            .ok()?;

        Some(Charge {
            budget: Arc::clone(self),
            bytes,
        })
    }

    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    pub fn is_exhausted(&self) -> bool {
        self.used() >= self.capacity
    }
}

#[derive(Debug)]
pub struct Charge {
    budget: Arc<Budget>,
    bytes: usize,
}

impl std::fmt::Debug for Budget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Budget({}/{})", self.used(), self.capacity)
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charges_add_up_to_the_capacity_and_no_further() {
        let budget = Budget::new(100);

        let first = budget.try_charge(60).unwrap();
        let second = budget.try_charge(40).unwrap();

        assert_eq!(budget.used(), 100);
        assert!(budget.is_exhausted());
        assert!(budget.try_charge(1).is_none());
        drop((first, second));
    }

    #[test]
    fn a_dropped_charge_returns_its_bytes() {
        let budget = Budget::new(100);
        let charge = budget.try_charge(80).unwrap();
        assert!(budget.try_charge(30).is_none());

        drop(charge);

        assert_eq!(budget.used(), 0);
        assert!(!budget.is_exhausted());
        assert!(budget.try_charge(30).is_some());
    }

    #[test]
    fn a_failed_charge_changes_nothing() {
        let budget = Budget::new(10);
        let _held = budget.try_charge(8).unwrap();

        assert!(budget.try_charge(5).is_none());
        assert!(budget.try_charge(usize::MAX).is_none());

        assert_eq!(budget.used(), 8);
    }
}
