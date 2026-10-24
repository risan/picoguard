//! The rules in force right now: how filtering is switched on or off, and a
//! generation number that changes whenever a decision made earlier may be
//! stale. The filter engine joins this in a later phase.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// What request filtering decided about a client query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestVerdict {
    Pass,
}

/// What response filtering decided about an upstream reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseVerdict {
    Pass,
}

/// The policy at one moment. Every filtering step takes the view that is
/// current when it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyView {
    pub generation: u64,
    pub paused: bool,
}

struct State {
    generation: u64,
    paused_until: Option<Instant>,
}

pub struct Policy {
    state: Mutex<State>,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy::new()
    }
}

impl Policy {
    pub fn new() -> Policy {
        Policy {
            state: Mutex::new(State {
                generation: 0,
                paused_until: None,
            }),
        }
    }

    /// Pausing is judged against the deadline, so it ends without an event.
    pub fn view(&self, now: Instant) -> PolicyView {
        let state = self.state.lock().unwrap();

        PolicyView {
            generation: state.generation,
            paused: state.paused_until.is_some_and(|deadline| now < deadline),
        }
    }

    pub fn pause(&self, duration: Duration, now: Instant) {
        let mut state = self.state.lock().unwrap();
        state.paused_until = Some(now + duration);
        state.generation += 1;
    }

    pub fn resume(&self) {
        let mut state = self.state.lock().unwrap();
        state.paused_until = None;
        state.generation += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_policy_is_active_at_generation_zero() {
        let view = Policy::new().view(Instant::now());

        assert_eq!(
            view,
            PolicyView {
                generation: 0,
                paused: false
            }
        );
    }

    #[test]
    fn pausing_lasts_until_the_deadline_and_expiry_changes_nothing() {
        let policy = Policy::new();
        let start = Instant::now();

        policy.pause(Duration::from_secs(60), start);

        let during = policy.view(start + Duration::from_secs(59));
        let after = policy.view(start + Duration::from_secs(60));
        assert!(during.paused);
        assert!(!after.paused);
        assert_eq!(during.generation, after.generation);
    }

    #[test]
    fn pause_and_resume_each_start_a_new_generation() {
        let policy = Policy::new();
        let start = Instant::now();

        policy.pause(Duration::from_secs(60), start);
        let paused = policy.view(start);
        policy.resume();
        let resumed = policy.view(start);

        assert_eq!(paused.generation, 1);
        assert_eq!(resumed.generation, 2);
        assert!(!resumed.paused);
    }

    #[test]
    fn pausing_again_extends_the_deadline() {
        let policy = Policy::new();
        let start = Instant::now();

        policy.pause(Duration::from_secs(10), start);
        policy.pause(Duration::from_secs(100), start);

        assert!(policy.view(start + Duration::from_secs(50)).paused);
    }
}
