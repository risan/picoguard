//! The rules in force right now: the filter engine, how filtering is switched on or off,
//! and a generation number that changes whenever a decision made earlier may be stale
//! (plan D20). Every filtering step takes the view that is current when it runs.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::dns::build::ReplyParts;
use crate::dns::wire::{Query, RData, Records, Section};
use crate::filter::engine::{Decision, Engine, TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_HTTPS};

/// The policy at one moment.
#[derive(Clone)]
pub struct PolicyView {
    pub generation: u64,
    pub paused: bool,
    engine: Arc<Engine>,
}

impl PolicyView {
    /// Step 2: the decision for the question of a client query. While paused everything
    /// passes.
    pub fn check_request(&self, query: &Query<'_>) -> Decision {
        let name = &query.question.name;
        if self.paused || name.is_root() {
            return Decision::Pass;
        }

        self.engine
            .check(&name.to_string(), query.question.qtype, false)
    }

    /// Step 6: the decision for an upstream reply. The records of the answer section are
    /// checked in order and the first blocked one decides. While paused everything passes.
    pub fn check_response(&self, parts: ReplyParts<'_>) -> Decision {
        if self.paused {
            return Decision::Pass;
        }

        let message = parts.bytes;
        let Ok(records) = Records::new(message) else {
            return Decision::Pass;
        };

        for record in records {
            let Ok(record) = record else {
                break;
            };

            if record.section != Section::Answer {
                break;
            }

            let Ok(data) = record.data(message) else {
                continue;
            };

            let decision = match data {
                // AdGuard Home checks an empty host name for a root target, which matches
                // nothing.
                RData::Cname(target) if target.is_root() => Decision::Pass,
                RData::Cname(target) => self.engine.check(&target.to_string(), TYPE_CNAME, false),
                RData::A(address) => self.check_address(IpAddr::V4(address), TYPE_A),
                RData::Aaaa(address) => self.check_address(IpAddr::V6(address), TYPE_AAAA),
                RData::Https(hints) => hints
                    .map(|address| self.check_address(address, TYPE_HTTPS))
                    .find(|decision| *decision != Decision::Pass)
                    .unwrap_or(Decision::Pass),
                _ => Decision::Pass,
            };

            if decision != Decision::Pass {
                return decision;
            }
        }

        Decision::Pass
    }

    fn check_address(&self, address: IpAddr, record_type: u16) -> Decision {
        self.engine.check(&go_ip_text(address), record_type, true)
    }
}

/// The text Go's `net.IP.String` gives, which is what AdGuard Home matches rules against:
/// an IPv4-mapped IPv6 address prints as dotted IPv4.
fn go_ip_text(address: IpAddr) -> String {
    match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
        IpAddr::V4(v4) => v4.to_string(),
    }
}

struct State {
    generation: u64,
    paused_until: Option<Instant>,
    engine: Arc<Engine>,
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
    /// A policy without rules: everything passes.
    pub fn new() -> Policy {
        Policy::with_engine(Arc::new(Engine::new(Vec::new(), Vec::new())))
    }

    pub fn with_engine(engine: Arc<Engine>) -> Policy {
        Policy {
            state: Mutex::new(State {
                generation: 0,
                paused_until: None,
                engine,
            }),
        }
    }

    /// Pausing is judged against the deadline, so it ends without an event.
    pub fn view(&self, now: Instant) -> PolicyView {
        let state = self.state.lock().unwrap();

        PolicyView {
            generation: state.generation,
            paused: state.paused_until.is_some_and(|deadline| now < deadline),
            engine: Arc::clone(&state.engine),
        }
    }

    /// Puts `engine` in force and starts a new generation, so no earlier decision is reused.
    /// Returns the engine it replaces: send it to the compile worker to be dropped there,
    /// never drop it on the DNS thread (plan D20).
    pub fn swap_engine(&self, engine: Arc<Engine>) -> Arc<Engine> {
        let mut state = self.state.lock().unwrap();
        state.generation += 1;

        std::mem::replace(&mut state.engine, engine)
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
    use hickory_proto::rr::RecordType;

    use super::*;
    use crate::dns::test_util::{self, QuerySpec, ResponseSpec};
    use crate::filter::engine::CompiledList;
    use crate::filter::parse::ListFormat;

    fn engine(rules: &str) -> Arc<Engine> {
        let (list, _) = CompiledList::from_text(ListFormat::Adblock, rules);

        Arc::new(Engine::new(vec![Arc::new(list)], Vec::new()))
    }

    #[test]
    fn a_new_policy_is_active_at_generation_zero() {
        let view = Policy::new().view(Instant::now());

        assert_eq!(view.generation, 0);
        assert!(!view.paused);
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

    #[test]
    fn swapping_the_engine_starts_a_new_generation_and_returns_the_old_engine() {
        let first = engine("||a.example^\n");
        let policy = Policy::with_engine(Arc::clone(&first));

        let old = policy.swap_engine(engine("||b.example^\n"));

        assert!(Arc::ptr_eq(&old, &first));
        assert_eq!(policy.view(Instant::now()).generation, 1);
    }

    fn request_decision(view: &PolicyView, name: &str, rtype: RecordType) -> Decision {
        let packet = QuerySpec::new(name, rtype).bytes();
        let query = Query::parse(&packet).unwrap();

        view.check_request(&query)
    }

    #[test]
    fn requests_are_checked_by_name_and_type_until_paused() {
        let policy = Policy::with_engine(engine("||ads.example^$dnstype=A\n"));
        let now = Instant::now();
        let view = policy.view(now);

        assert!(matches!(
            request_decision(&view, "x.ads.example.", RecordType::A),
            Decision::Block { .. }
        ));
        assert_eq!(
            request_decision(&view, "x.ads.example.", RecordType::AAAA),
            Decision::Pass
        );
        assert_eq!(request_decision(&view, ".", RecordType::A), Decision::Pass);

        policy.pause(Duration::from_secs(5), now);
        assert_eq!(
            request_decision(&policy.view(now), "x.ads.example.", RecordType::A),
            Decision::Pass
        );
    }

    fn response_decision(
        view: &PolicyView,
        rtype: RecordType,
        answers: Vec<hickory_proto::rr::Record>,
    ) -> Decision {
        let spec = QuerySpec::new("q.example.", rtype);
        let reply = ResponseSpec {
            answers,
            ..ResponseSpec::default()
        }
        .bytes(&spec);

        view.check_response(ReplyParts {
            bytes: &reply,
            ttl_offsets: &[],
            opt_start: None,
        })
    }

    fn ip(text: &str) -> std::net::Ipv4Addr {
        text.parse().unwrap()
    }

    #[test]
    fn answer_records_are_checked_in_order_and_the_first_blocked_one_decides() {
        let policy = Policy::with_engine(engine(
            "||tracker.example^\n1.1.1.1 9.9.9.9\n||203.0.113.7^\n",
        ));
        let view = policy.view(Instant::now());
        let a = |address: &str| test_util::a("q.example.", 60, ip(address));
        let check = |answers| response_decision(&view, RecordType::A, answers);

        assert_eq!(check(vec![a("8.8.8.8")]), Decision::Pass);
        assert!(matches!(
            check(vec![test_util::cname(
                "q.example.",
                60,
                "cdn.tracker.example."
            )]),
            Decision::Block { .. }
        ));
        assert_eq!(
            check(vec![a("9.9.9.9")]),
            Decision::Block {
                ips: vec!["1.1.1.1".parse().unwrap()]
            }
        );
        assert!(matches!(
            check(vec![a("8.8.8.8"), a("203.0.113.7")]),
            Decision::Block { .. }
        ));
    }

    #[test]
    fn a_root_cname_target_is_not_checked_as_a_name() {
        let policy = Policy::with_engine(engine("/^\\.$/\n/./\n"));
        let view = policy.view(Instant::now());
        let root_target = vec![test_util::cname("q.example.", 60, ".")];

        assert_eq!(
            response_decision(&view, RecordType::A, root_target),
            Decision::Pass
        );
    }

    #[test]
    fn https_hints_are_checked() {
        let policy = Policy::with_engine(engine("||203.0.113.7^\n||2001:db8::bad^\n"));
        let view = policy.view(Instant::now());
        let hints = |v4: &[&str], v6: &[&str]| {
            let v4: Vec<_> = v4.iter().map(|text| ip(text)).collect();
            let v6: Vec<_> = v6.iter().map(|text| text.parse().unwrap()).collect();

            response_decision(
                &view,
                RecordType::HTTPS,
                vec![test_util::https("q.example.", 60, &v4, &v6)],
            )
        };

        assert_eq!(hints(&["8.8.8.8"], &["2606:4700::1111"]), Decision::Pass);
        assert!(matches!(
            hints(&["8.8.8.8", "203.0.113.7"], &[]),
            Decision::Block { .. }
        ));
        assert!(matches!(
            hints(&[], &["2001:db8::bad"]),
            Decision::Block { .. }
        ));
    }

    #[test]
    fn an_ipv4_mapped_answer_is_checked_as_dotted_ipv4_text() {
        let policy = Policy::with_engine(engine("||203.0.113.7^\n"));
        let view = policy.view(Instant::now());
        let mapped: std::net::Ipv6Addr = "::ffff:203.0.113.7".parse().unwrap();

        let decision = response_decision(
            &view,
            RecordType::AAAA,
            vec![test_util::aaaa("q.example.", 60, mapped)],
        );

        assert!(matches!(decision, Decision::Block { .. }));
        assert_eq!(go_ip_text(IpAddr::V6(mapped)), "203.0.113.7");
        assert_eq!(go_ip_text("2001:db8::1".parse().unwrap()), "2001:db8::1");
    }

    #[test]
    fn a_paused_policy_passes_every_reply() {
        let policy = Policy::with_engine(engine("||tracker.example^\n"));
        let now = Instant::now();
        policy.pause(Duration::from_secs(5), now);
        let answers = || vec![test_util::cname("q.example.", 60, "tracker.example.")];

        assert_eq!(
            response_decision(&policy.view(now), RecordType::A, answers()),
            Decision::Pass
        );
        assert!(matches!(
            response_decision(
                &policy.view(now + Duration::from_secs(6)),
                RecordType::A,
                answers()
            ),
            Decision::Block { .. }
        ));
    }
}
