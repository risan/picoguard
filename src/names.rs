//! Device names: the PTR name the `[local]` resolver gives each private client address shown on
//! the signed-in page, kept in a small fixed-size table.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::budget::Budget;
use crate::config::{LimitsConfig, UpstreamConfig};
use crate::dns::wire::{CLASS_IN, Header, Name, Records, Section, rcode, read_name, rtype};
use crate::upstream::{Tally, Upstreams};

/// The most addresses the table keeps.
pub const MAX_NAMES: usize = 256;
/// The most name bytes the table keeps across all addresses: 256 names of 253 bytes would
/// hold about 83 KB.
pub const NAME_BYTES: usize = 16 * 1024;
/// The most lookups in flight at once.
pub const MAX_LOOKUPS: usize = 4;
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
/// The largest reply a lookup reads. A PTR reply is a few hundred bytes.
pub const NAME_REPLY_MAX: usize = 4096;
const SHORTEST_NAME_SECS: u32 = 300;
const LONGEST_NAME_SECS: u32 = 86_400;
const NO_NAME_KEPT: Duration = Duration::from_secs(300);

/// A name a lookup found, with the TTL of its PTR record.
#[derive(Debug, PartialEq, Eq)]
pub struct Found {
    pub name: Box<str>,
    pub ttl: u32,
}

/// What the table knows of an address about to be shown, and whether the caller must start
/// its lookup.
#[derive(Debug, PartialEq, Eq)]
pub struct Shown {
    pub name: Option<Box<str>>,
    pub look_up: bool,
}

struct Slot {
    address: IpAddr,
    /// The name found, or, while it is looked up again, the expired one.
    name: Option<Box<str>>,
    /// When the name, or "no name", expires. `None` while a lookup is in flight.
    until: Option<Instant>,
    last_used: u64,
}

/// At most `MAX_NAMES` addresses with what their lookups gave, dropping the least recently
/// shown. Searched linearly: a few hundred addresses, asked on a 5 s poll.
pub struct NameTable {
    slots: Vec<Slot>,
    name_bytes: usize,
    in_flight: usize,
    max_lookups: usize,
    /// Bumped by every `shown`, to order the slots by use.
    uses: u64,
}

impl NameTable {
    pub fn new(max_lookups: usize) -> NameTable {
        NameTable {
            slots: Vec::new(),
            name_bytes: 0,
            in_flight: 0,
            max_lookups,
            uses: 0,
        }
    }

    /// What is known of `address`. `look_up` is true when the caller must look it up now and
    /// then `settle` it: it is new or expired, and a lookup slot is free. A new address with
    /// no free slot is not kept; the next poll asks again.
    pub fn shown(&mut self, address: IpAddr, now: Instant) -> Shown {
        self.uses += 1;
        let slot_free = self.in_flight < self.max_lookups;

        if let Some(slot) = self.slots.iter_mut().find(|slot| slot.address == address) {
            slot.last_used = self.uses;
            let expired = slot.until.is_some_and(|until| until <= now);
            let look_up = expired && slot_free;
            if look_up {
                slot.until = None;
                self.in_flight += 1;
            }

            return Shown {
                name: slot.name.clone(),
                look_up,
            };
        }

        if !slot_free {
            return Shown {
                name: None,
                look_up: false,
            };
        }

        if self.slots.len() >= MAX_NAMES {
            self.drop_least_recently_used(None);
        }

        self.slots.push(Slot {
            address,
            name: None,
            until: None,
            last_used: self.uses,
        });
        self.in_flight += 1;

        Shown {
            name: None,
            look_up: true,
        }
    }

    /// Ends the lookup of `address` with what it found: a name kept for its TTL, clamped to
    /// 5 minutes – 1 day, or "no name" kept for 5 minutes.
    pub fn settle(&mut self, address: IpAddr, found: Option<Found>, now: Instant) {
        let (mut name, kept) = match found {
            Some(Found { name, ttl }) => {
                let secs = ttl.clamp(SHORTEST_NAME_SECS, LONGEST_NAME_SECS);

                (Some(name), Duration::from_secs(secs.into()))
            }

            None => (None, NO_NAME_KEPT),
        };
        let held = self
            .slots
            .iter()
            .find(|slot| slot.address == address)
            .map_or(0, |slot| name_len(&slot.name));

        while self.name_bytes - held + name_len(&name) > NAME_BYTES {
            if !self.drop_least_recently_used(Some(address)) {
                name = None;
                break;
            }
        }

        // Dropping slots moves the last one, so the slot is found again.
        let Some(slot) = self.slots.iter_mut().find(|slot| slot.address == address) else {
            return;
        };

        if slot.until.is_none() {
            self.in_flight -= 1;
        }

        self.name_bytes = self.name_bytes - held + name_len(&name);
        slot.name = name;
        slot.until = Some(now + kept);
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Drops the least recently shown slot that is not in flight and not `keep`; false when
    /// there is none.
    fn drop_least_recently_used(&mut self, keep: Option<IpAddr>) -> bool {
        let victim = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.until.is_some() && Some(slot.address) != keep)
            .min_by_key(|(_, slot)| slot.last_used)
            .map(|(index, _)| index);
        let Some(index) = victim else {
            return false;
        };

        let dropped = self.slots.swap_remove(index);
        self.name_bytes -= name_len(&dropped.name);

        true
    }
}

fn name_len(name: &Option<Box<str>>) -> usize {
    name.as_ref().map_or(0, |name| name.len())
}

/// Looks up the names of client addresses through the `[local]` resolver, in a pool and a
/// budget of their own: a stalled lookup never holds an exchange slot or reply bytes a client
/// query needs.
pub(crate) struct DeviceNames {
    table: Mutex<NameTable>,
    resolver: Upstreams,
    budget: Arc<Budget>,
}

impl DeviceNames {
    pub(crate) fn new(
        resolver: SocketAddr,
        upstream: &UpstreamConfig,
        limits: &LimitsConfig,
    ) -> Arc<DeviceNames> {
        // A configured `upstream_concurrency` of 1 would otherwise let one lookup at a time
        // reach the router.
        let names_limits = LimitsConfig {
            upstream_concurrency: MAX_LOOKUPS,
            upstream_reply_max: NAME_REPLY_MAX,
            ..limits.clone()
        };

        Arc::new(DeviceNames {
            table: Mutex::new(NameTable::new(MAX_LOOKUPS)),
            resolver: Upstreams::plain(resolver, upstream, &names_limits),
            budget: Budget::new(MAX_LOOKUPS * NAME_REPLY_MAX),
        })
    }

    /// What the lookups have done, for the `[local]` entry of the Upstreams card.
    pub(crate) fn tally(&self) -> Tally {
        self.resolver
            .tallies()
            .map(|(_, tally)| tally)
            .next()
            .unwrap_or_default()
    }

    /// The name known for `address`, if any. Starts its lookup in the background when one is
    /// due, and never waits for it. Must be called on the runtime.
    pub(crate) fn name_of(self: &Arc<Self>, address: IpAddr) -> Option<Box<str>> {
        let shown = self.table.lock().unwrap().shown(address, Instant::now());
        if shown.look_up {
            tokio::spawn(Arc::clone(self).look_up(address));
        }

        shown.name
    }

    async fn look_up(self: Arc<Self>, address: IpAddr) {
        let mut request = ptr_query(address);
        let found = self
            .resolver
            .query_charged_within(&mut request, &self.budget, LOOKUP_TIMEOUT)
            .await
            .ok()
            .and_then(|answered| host_name_in(&answered.reply));

        self.table
            .lock()
            .unwrap()
            .settle(address, found, Instant::now());
    }

    #[cfg(test)]
    pub(crate) fn lookups_in_flight(&self) -> usize {
        self.table.lock().unwrap().in_flight
    }

    #[cfg(test)]
    pub(crate) fn held_bytes(&self) -> usize {
        self.budget.used()
    }
}

/// The name a PTR lookup of `address` asks for, of its canonical form, so that a mapped IPv4
/// address is asked under `in-addr.arpa`.
pub(crate) fn reverse_name(address: IpAddr) -> Name {
    let text = match address.to_canonical() {
        IpAddr::V4(v4) => {
            let [first, second, third, fourth] = v4.octets();

            format!("{fourth}.{third}.{second}.{first}.in-addr.arpa")
        }

        IpAddr::V6(v6) => {
            let nibbles: String = v6
                .octets()
                .iter()
                .rev()
                .map(|byte| format!("{:x}.{:x}.", byte & 0xF, byte >> 4))
                .collect();

            format!("{nibbles}ip6.arpa")
        }
    };

    Name::from_text(&text).expect("a reverse name is at most 73 bytes of short labels")
}

/// A PTR question for `address`, with recursion desired, built like the list hosts' lookups.
fn ptr_query(address: IpAddr) -> Vec<u8> {
    let mut request = vec![0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    request.extend_from_slice(reverse_name(address).as_wire());
    request.extend_from_slice(&rtype::PTR.to_be_bytes());
    request.extend_from_slice(&CLASS_IN.to_be_bytes());

    request
}

/// The target of the first PTR record of a NOERROR answer, when it is a host name. Records
/// before it, such as the CNAME of a classless delegation (RFC 2317), are passed over.
fn host_name_in(reply: &[u8]) -> Option<Found> {
    if Header::parse(reply).ok()?.rcode() != rcode::NOERROR {
        return None;
    }

    let record = Records::new(reply)
        .ok()?
        .map_while(Result::ok)
        .take_while(|record| record.section == Section::Answer)
        .find(|record| record.rtype == rtype::PTR && record.class == CLASS_IN)?;
    let (target, end) = read_name(reply, record.rdata.start).ok()?;
    if end != record.rdata.end || !is_host_name(&target) {
        return None;
    }

    Some(Found {
        name: target.to_string().into(),
        ttl: record.ttl,
    })
}

/// Host-name syntax (RFC 1123 §2.1) with `_` allowed, as routers put it in DHCP names: every
/// label is letters, digits, hyphens and underscores, and does not start or end with a
/// hyphen. Names read from the wire are lowercased already. No byte that passes needs an
/// escape, so the name's text is exactly its labels joined by dots.
fn is_host_name(name: &Name) -> bool {
    let is_name_byte = |byte: &u8| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-' || *byte == b'_'
    };

    !name.is_root()
        && name.labels().all(|label| {
            label.iter().all(is_name_byte)
                && label.first() != Some(&b'-')
                && label.last() != Some(&b'-')
        })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, Instant};

    use hickory_proto::rr::rdata::PTR;
    use hickory_proto::rr::{Name as HickoryName, RData, Record, RecordType};

    use super::*;
    use crate::config::{LimitsConfig, UpstreamConfig};
    use crate::dns::test_util::{QuerySpec, ResponseSpec, a, cname, name, ptr, soa};
    use crate::dns::wire::{Query, rcode, rtype};
    use crate::upstream::test_dns::{FakeRouter, fake_router};

    fn address(number: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + number))
    }

    fn found(name: &str, ttl: u32) -> Option<Found> {
        Some(Found {
            name: name.into(),
            ttl,
        })
    }

    fn shown(name: Option<&str>, look_up: bool) -> Shown {
        Shown {
            name: name.map(Box::from),
            look_up,
        }
    }

    fn seconds(count: u64) -> Duration {
        Duration::from_secs(count)
    }

    #[test]
    fn a_new_address_starts_one_lookup_and_shows_no_name() {
        let mut table = NameTable::new(MAX_LOOKUPS);
        let t0 = Instant::now();

        assert_eq!(table.shown(address(1), t0), shown(None, true));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn an_address_in_flight_starts_no_second_lookup() {
        let mut table = NameTable::new(MAX_LOOKUPS);
        let t0 = Instant::now();

        let looked_up: Vec<bool> = (0..10)
            .map(|_| table.shown(address(1), t0).look_up)
            .collect();

        assert!(looked_up[0]);
        assert!(looked_up[1..].iter().all(|look_up| !look_up));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn at_most_four_lookups_run_at_once() {
        let mut table = NameTable::new(4);
        let t0 = Instant::now();

        let started = (0..20)
            .filter(|number| table.shown(address(*number), t0).look_up)
            .count();

        assert_eq!(started, 4);
        assert_eq!(table.len(), 4);
        assert_eq!(table.shown(address(20), t0), shown(None, false));

        table.settle(address(0), found("pc.lan", 600), t0);

        assert_eq!(table.shown(address(20), t0), shown(None, true));
    }

    #[test]
    fn a_found_name_is_kept_for_its_ttl_clamped_to_five_minutes_and_one_day() {
        for (ttl, kept) in [(60, 300), (3600, 3600), (200_000, 86_400)] {
            let mut table = NameTable::new(MAX_LOOKUPS);
            let t0 = Instant::now();
            table.shown(address(1), t0);
            table.settle(address(1), found("pc.lan", ttl), t0);

            assert_eq!(
                table.shown(address(1), t0 + seconds(kept - 1)),
                shown(Some("pc.lan"), false),
                "TTL {ttl}"
            );
            // An expired name keeps showing while it is looked up again.
            assert_eq!(
                table.shown(address(1), t0 + seconds(kept)),
                shown(Some("pc.lan"), true),
                "TTL {ttl}"
            );
            assert_eq!(
                table.shown(address(1), t0 + seconds(kept)),
                shown(Some("pc.lan"), false),
                "TTL {ttl}"
            );
        }
    }

    #[test]
    fn an_expired_name_is_replaced_or_dropped_when_its_new_lookup_ends() {
        let mut table = NameTable::new(MAX_LOOKUPS);
        let t0 = Instant::now();
        let later = t0 + seconds(300);
        for number in [1, 2] {
            table.shown(address(number), t0);
            table.settle(address(number), found("old.lan", 60), t0);
            table.shown(address(number), later);
        }

        table.settle(address(1), found("new.lan", 600), later);
        table.settle(address(2), None, later);

        assert_eq!(
            table.shown(address(1), later),
            shown(Some("new.lan"), false)
        );
        assert_eq!(table.shown(address(2), later), shown(None, false));
        assert_eq!(table.name_bytes, "new.lan".len());
    }

    #[test]
    fn no_name_is_kept_for_five_minutes() {
        let mut table = NameTable::new(MAX_LOOKUPS);
        let t0 = Instant::now();
        table.shown(address(1), t0);
        table.settle(address(1), None, t0);

        assert_eq!(
            table.shown(address(1), t0 + seconds(299)),
            shown(None, false)
        );
        assert_eq!(
            table.shown(address(1), t0 + seconds(300)),
            shown(None, true)
        );
    }

    #[test]
    fn the_257th_address_drops_the_least_recently_used() {
        let mut table = NameTable::new(MAX_LOOKUPS);
        let t0 = Instant::now();
        for number in 0..256 {
            assert!(table.shown(address(number), t0).look_up);
            table.settle(address(number), found(&format!("pc-{number}.lan"), 600), t0);
        }

        table.shown(address(0), t0);

        assert!(table.shown(address(256), t0).look_up);
        assert_eq!(table.len(), 256);
        assert_eq!(table.shown(address(1), t0), shown(None, true));
        assert_eq!(table.shown(address(0), t0), shown(Some("pc-0.lan"), false));
    }

    #[test]
    fn addresses_in_flight_are_never_dropped() {
        let mut table = NameTable::new(MAX_LOOKUPS);
        let t0 = Instant::now();
        for number in 0..3 {
            assert!(table.shown(address(number), t0).look_up);
        }

        for number in 3..256 {
            assert!(table.shown(address(number), t0).look_up);
            table.settle(address(number), found(&format!("pc-{number}.lan"), 600), t0);
        }

        assert!(table.shown(address(256), t0).look_up);
        assert_eq!(table.len(), 256);

        for number in 0..3 {
            table.settle(address(number), found(&format!("pc-{number}.lan"), 600), t0);
        }

        for number in 0..3 {
            let name = format!("pc-{number}.lan");
            assert_eq!(table.shown(address(number), t0), shown(Some(&name), false));
        }

        assert_eq!(table.shown(address(3), t0), shown(None, true));
    }

    #[test]
    fn names_past_the_byte_budget_drop_the_least_recently_used() {
        let mut table = NameTable::new(MAX_LOOKUPS);
        let t0 = Instant::now();
        let long_name = |number: u32| format!("{number:0>8}{}", "x".repeat(245));
        for number in 0..100 {
            assert!(table.shown(address(number), t0).look_up);
            table.settle(address(number), found(&long_name(number), 600), t0);
        }

        assert_eq!(long_name(99).len(), 253);
        assert!(table.name_bytes <= NAME_BYTES);
        assert!(table.len() <= 64, "{} slots", table.len());
        assert_eq!(
            table.shown(address(99), t0),
            shown(Some(&long_name(99)), false)
        );
        assert_eq!(table.shown(address(0), t0), shown(None, true));
    }

    const OWNER: &str = "50.110.168.192.in-addr.arpa.";

    fn reply(answers: Vec<Record>, rcode: u8) -> Vec<u8> {
        let query = QuerySpec::new(OWNER, RecordType::PTR);
        let response = ResponseSpec {
            answers,
            rcode,
            ..ResponseSpec::default()
        };

        response.bytes(&query)
    }

    fn named(name: &str, ttl: u32) -> Option<Found> {
        Some(Found {
            name: name.into(),
            ttl,
        })
    }

    #[test]
    fn reverse_names_of_ipv4_ipv6_and_mapped_addresses() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 110, 50));
        let v6 = IpAddr::V6("fd00::1".parse::<Ipv6Addr>().unwrap());
        let mapped = IpAddr::V6("::ffff:192.168.1.6".parse::<Ipv6Addr>().unwrap());
        let v6_reverse = format!("1.{}d.f.ip6.arpa", "0.".repeat(29));

        assert_eq!(reverse_name(v4).to_string(), "50.110.168.192.in-addr.arpa");
        assert_eq!(reverse_name(v6).to_string(), v6_reverse);
        assert_eq!(reverse_name(v6).labels().count(), 34);
        assert_eq!(reverse_name(mapped).to_string(), "6.1.168.192.in-addr.arpa");
    }

    #[test]
    fn the_ptr_query_asks_one_ptr_question_with_recursion_desired() {
        let address = IpAddr::V4(Ipv4Addr::new(192, 168, 110, 50));
        let request = ptr_query(address);

        let query = Query::parse(&request).unwrap();

        assert_eq!(query.question.qtype, rtype::PTR);
        assert_eq!(query.question.qclass, CLASS_IN);
        assert!(query.header.recursion_desired());
        assert_eq!(query.question.name, reverse_name(address));
    }

    #[test]
    fn the_first_ptr_target_is_lowercased_without_its_trailing_dot() {
        let answers = vec![
            ptr(OWNER, 600, "Risan-PC.LAN."),
            ptr(OWNER, 60, "other.lan."),
        ];

        assert_eq!(
            host_name_in(&reply(answers, rcode::NOERROR)),
            named("risan-pc.lan", 600)
        );
    }

    #[test]
    fn a_cname_before_the_ptr_is_passed_over() {
        let answers = vec![
            cname(OWNER, 60, "50.0-127.110.168.192.in-addr.arpa."),
            ptr("50.0-127.110.168.192.in-addr.arpa.", 900, "printer.lan."),
        ];

        assert_eq!(
            host_name_in(&reply(answers, rcode::NOERROR)),
            named("printer.lan", 900)
        );
    }

    #[test]
    fn nxdomain_servfail_no_ptr_and_malformed_replies_give_no_name() {
        let nxdomain = ResponseSpec {
            authorities: vec![soa("168.192.in-addr.arpa.", 300, 300)],
            rcode: rcode::NXDOMAIN,
            ..ResponseSpec::default()
        }
        .bytes(&QuerySpec::new(OWNER, RecordType::PTR));
        let a_only = vec![a(OWNER, 600, Ipv4Addr::new(192, 0, 2, 1))];
        let whole = reply(vec![ptr(OWNER, 600, "pc.lan.")], rcode::NOERROR);
        let cut = &whole[..whole.len() - 3];

        assert_eq!(host_name_in(&nxdomain), None);
        assert_eq!(host_name_in(&reply(Vec::new(), rcode::NOERROR)), None);
        assert_eq!(
            host_name_in(&reply(vec![ptr(OWNER, 600, "pc.lan.")], rcode::SERVFAIL)),
            None
        );
        assert_eq!(host_name_in(&reply(a_only, rcode::NOERROR)), None);
        assert_eq!(host_name_in(cut), None);
        assert_eq!(host_name_in(&whole), named("pc.lan", 600));
    }

    /// A reply to the PTR question of 1.0.168.192 with one PTR answer whose RDLENGTH is
    /// `rdlength` and whose RDATA is `rdata`.
    fn hand_written(rdlength: u16, rdata: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        bytes.extend_from_slice(b"\x011\x010\x03168\x03192\x07in-addr\x04arpa\x00\x00\x0c\x00\x01");
        bytes.extend_from_slice(&[0xC0, 0x0C, 0, 12, 0, 1, 0, 0, 2, 88]);
        bytes.extend_from_slice(&rdlength.to_be_bytes());
        bytes.extend_from_slice(rdata);

        bytes
    }

    #[test]
    fn a_ptr_target_must_end_exactly_at_its_rdata_end() {
        let target = b"\x05my-pc\x03lan\x00";
        let mut with_junk = target.to_vec();
        with_junk.extend_from_slice(&[0xAB, 0xCD]);
        let arpa_at = hand_written(0, &[])
            .windows(5)
            .position(|window| window == b"\x04arpa")
            .unwrap() as u8;
        let compressed = [b"\x05my-pc".as_slice(), &[0xC0, arpa_at]].concat();

        assert_eq!(
            host_name_in(&hand_written(target.len() as u16, target)),
            named("my-pc.lan", 600)
        );
        assert_eq!(
            host_name_in(&hand_written(target.len() as u16 - 1, target)),
            None
        );
        assert_eq!(
            host_name_in(&hand_written(with_junk.len() as u16, &with_junk)),
            None
        );
        assert_eq!(
            host_name_in(&hand_written(compressed.len() as u16, &compressed)),
            named("my-pc.arpa", 600)
        );
    }

    fn ptr_to_labels(labels: &[&[u8]]) -> Vec<u8> {
        let target = HickoryName::from_labels(labels.iter().copied()).unwrap();
        let record = Record::from_rdata(name(OWNER), 600, RData::PTR(PTR(target)));

        reply(vec![record], rcode::NOERROR)
    }

    #[test]
    fn a_target_that_is_not_a_host_name_gives_no_name() {
        let refused: [&[&[u8]]; 10] = [
            &[b"<b>", b"lan"],
            &[b"a b", b"lan"],
            &[b"x\x07y", b"lan"],
            &[b"caf\xC3\xA9", b"lan"],
            &[b"a.b", b"lan"],
            &[b"a/b", b"lan"],
            &[b"\"q\"", b"lan"],
            &[b"-pc", b"lan"],
            &[b"pc-", b"lan"],
            &[b"---", b"lan"],
        ];

        for labels in refused {
            assert_eq!(host_name_in(&ptr_to_labels(labels)), None, "{labels:?}");
        }

        assert_eq!(host_name_in(&ptr_to_labels(&[])), None, "the root");
    }

    #[test]
    fn letters_digits_hyphens_and_underscores_make_a_host_name() {
        let longest = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );

        for kept in [
            "my-pc-2.lan",
            "2nd-floor.lan",
            "xn--caf-dma.lan",
            "my_pc.lan",
            &longest,
        ] {
            let answer = reply(vec![ptr(OWNER, 600, &format!("{kept}."))], rcode::NOERROR);

            assert_eq!(host_name_in(&answer), named(kept, 600));
        }

        assert_eq!(longest.len(), 253);
    }

    fn lan_address(number: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(0xC0A8_0100 + number))
    }

    fn names_for(router: &FakeRouter, limits: &LimitsConfig) -> Arc<DeviceNames> {
        DeviceNames::new(router.address, &UpstreamConfig::default(), limits)
    }

    /// Polls `done` every 10 ms; false when it is still not true after `limit`.
    async fn wait_until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
        let started = Instant::now();

        while !done() {
            if started.elapsed() > limit {
                return false;
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        true
    }

    #[tokio::test]
    async fn the_names_pool_takes_four_slots_whatever_the_limits() {
        let router = fake_router(&[], true).await;
        let limits = LimitsConfig {
            upstream_concurrency: 1,
            ..LimitsConfig::default()
        };
        let names = names_for(&router, &limits);
        let started = Instant::now();

        for number in 0..4 {
            assert_eq!(names.name_of(lan_address(number)), None);
        }

        assert!(wait_until(Duration::from_secs(3), || router.asked().len() >= 4).await);
        // With one slot, a second lookup could not be sent before the first try of the first
        // one ended at 1 s.
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn twenty_addresses_send_four_lookups_and_repeats_send_none() {
        let router = fake_router(&[], true).await;
        let names = names_for(&router, &LimitsConfig::default());

        for number in 0..20 {
            assert_eq!(names.name_of(lan_address(number)), None);
        }

        for _ in 0..10 {
            assert_eq!(names.name_of(lan_address(0)), None);
        }

        assert!(wait_until(Duration::from_secs(3), || router.asked().len() >= 4).await);
        tokio::time::sleep(Duration::from_millis(300)).await;

        // A second try asks the same name again, so the names asked are counted, not the
        // questions.
        let asked: HashSet<String> = router.asked().into_iter().collect();
        assert_eq!(asked.len(), 4, "{asked:?}");
        assert!(asked.contains(&reverse_name(lan_address(0)).to_string()));
        assert_eq!(names.lookups_in_flight(), 4);
    }

    #[tokio::test]
    async fn a_lookup_gives_up_after_two_seconds_and_counts_each_try_on_the_resolver() {
        let router = fake_router(&[], true).await;
        let names = names_for(&router, &LimitsConfig::default());
        let started = Instant::now();

        assert_eq!(names.name_of(lan_address(1)), None);

        assert!(wait_until(Duration::from_secs(6), || names.lookups_in_flight() == 0).await);
        let took = started.elapsed();
        assert!(took >= Duration::from_millis(1900), "{took:?}");
        // The configured 5 s timeout would give up at 5 s.
        assert!(took < Duration::from_secs(4), "{took:?}");
        assert_eq!(router.asked().len(), 2, "one retry");
        assert_eq!((names.tally().answered, names.tally().failed), (0, 2));

        assert_eq!(names.name_of(lan_address(1)), None);
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(router.asked().len(), 2, "no name is kept for 5 minutes");
        assert_eq!(names.lookups_in_flight(), 0);
    }

    #[tokio::test]
    async fn a_found_name_shows_on_a_later_call_and_counts_as_an_answer() {
        let owner = reverse_name(lan_address(1)).to_string();
        let router = fake_router(&[(&owner, "Risan-PC.lan.", 600)], false).await;
        let names = names_for(&router, &LimitsConfig::default());

        assert_eq!(names.name_of(lan_address(1)), None);

        let mut shown = None;
        let appeared = wait_until(Duration::from_secs(5), || {
            shown = names.name_of(lan_address(1));

            shown.is_some()
        })
        .await;
        assert!(appeared);
        assert_eq!(shown.as_deref(), Some("risan-pc.lan"));
        assert_eq!((names.tally().answered, names.tally().failed), (1, 0));
        assert_eq!(router.asked(), [owner]);
    }
}
