//! Device names: the PTR name the `[local]` resolver gives each private client address shown on
//! the signed-in page, kept in a small fixed-size table.

use std::net::IpAddr;
use std::time::{Duration, Instant};

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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use super::*;

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
}
