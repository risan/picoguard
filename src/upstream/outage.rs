//! Keeps the log of a failing upstream short. A busy resolver fails thousands of queries
//! in a minute when a server goes away; one line per failure would wear out an SD card
//! (plan D19). The log gets a line when the failures start, a summary every
//! `SUMMARY_EVERY` while they go on, and a line when the server works again.

use std::time::Duration;

use tokio::time::Instant;

/// The longest the log stays quiet about a failure that goes on.
const SUMMARY_EVERY: Duration = Duration::from_secs(5 * 60);

/// A success counts as a recovery only this long after the last failure: a server that
/// fails and answers by turns is still failing, and must not log on every change.
const QUIET_BEFORE_RECOVERY: Duration = Duration::from_secs(30);

#[derive(Debug, PartialEq, Eq)]
pub enum Report {
    /// Nothing to log.
    Silent,
    /// The first failure of an outage.
    Started,
    /// The outage goes on; `suppressed` failures were not logged since the last line.
    Continues { suppressed: u64 },
}

#[derive(Debug, PartialEq, Eq)]
pub struct Recovered {
    /// Failures during the whole outage.
    pub failures: u64,
}

#[derive(Default)]
pub struct Outage {
    ongoing: Option<Ongoing>,
}

struct Ongoing {
    failures: u64,
    suppressed: u64,
    last_failure: Instant,
    last_line: Instant,
}

impl Outage {
    pub fn failed(&mut self, now: Instant) -> Report {
        let Some(ongoing) = &mut self.ongoing else {
            self.ongoing = Some(Ongoing {
                failures: 1,
                suppressed: 0,
                last_failure: now,
                last_line: now,
            });

            return Report::Started;
        };

        ongoing.failures += 1;
        ongoing.last_failure = now;

        if now.duration_since(ongoing.last_line) < SUMMARY_EVERY {
            ongoing.suppressed += 1;

            return Report::Silent;
        }

        let suppressed = std::mem::take(&mut ongoing.suppressed);
        ongoing.last_line = now;

        Report::Continues { suppressed }
    }

    pub fn succeeded(&mut self, now: Instant) -> Option<Recovered> {
        let ongoing = self.ongoing.as_ref()?;
        if now.duration_since(ongoing.last_failure) < QUIET_BEFORE_RECOVERY {
            return None;
        }

        let failures = ongoing.failures;
        self.ongoing = None;

        Some(Recovered { failures })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn after(start: Instant, seconds: u64) -> Instant {
        start + Duration::from_secs(seconds)
    }

    #[test]
    fn an_outage_logs_its_start_and_then_one_summary_per_five_minutes() {
        let start = Instant::now();
        let mut outage = Outage::default();

        let reports: Vec<Report> = (0..1000).map(|_| outage.failed(after(start, 1))).collect();

        assert_eq!(reports[0], Report::Started);
        assert!(reports[1..].iter().all(|report| *report == Report::Silent));
        assert_eq!(
            outage.failed(after(start, 299)),
            Report::Silent,
            "still inside the five minutes"
        );
        assert_eq!(
            outage.failed(after(start, 301)),
            Report::Continues { suppressed: 1000 }
        );
        assert_eq!(outage.failed(after(start, 302)), Report::Silent);
        assert_eq!(
            outage.failed(after(start, 601)),
            Report::Continues { suppressed: 1 }
        );
    }

    #[test]
    fn a_success_long_after_the_last_failure_ends_the_outage_with_its_failure_count() {
        let start = Instant::now();
        let mut outage = Outage::default();
        outage.failed(start);
        outage.failed(after(start, 1));

        assert_eq!(
            outage.succeeded(after(start, 40)),
            Some(Recovered { failures: 2 })
        );
        assert_eq!(outage.succeeded(after(start, 41)), None, "once");
        assert_eq!(
            outage.failed(after(start, 50)),
            Report::Started,
            "a new outage"
        );
    }

    #[test]
    fn a_server_that_fails_and_answers_by_turns_stays_in_one_outage() {
        let start = Instant::now();
        let mut outage = Outage::default();
        let mut lines = 0;

        for second in 0..200 {
            if outage.failed(after(start, 2 * second)) != Report::Silent {
                lines += 1;
            }

            if outage.succeeded(after(start, 2 * second + 1)).is_some() {
                lines += 1;
            }
        }

        assert_eq!(lines, 2, "the start, and one summary after 5 minutes");
    }

    #[test]
    fn a_success_without_an_outage_logs_nothing() {
        assert_eq!(Outage::default().succeeded(Instant::now()), None);
    }
}
