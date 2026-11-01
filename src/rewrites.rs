//! DNS rewrites (plan D7): names picoguard answers itself. The user's rewrites are a small
//! sorted table, built off the DNS thread and swapped whole; SafeSearch is static data.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::config::Rewrite;
use crate::dns::wire::{Labels, Name};
use crate::scheduler::normalized_name;

/// The TTL of an answer made of a rewrite's addresses.
pub const ADDRESS_TTL: u32 = 60;
/// The longest TTL of an answer looked up through a rewrite's target name.
pub const MAX_TARGET_TTL: u32 = 300;

/// Google's search domains, after `google.` (Google's `supported_domains`, 187 entries).
const GOOGLE_SEARCH_DOMAINS: [&str; 187] = [
    "ad", "ae", "al", "am", "as", "at", "az", "ba", "be", "bf", "bg", "bi", "bj", "bs", "bt", "by",
    "ca", "cat", "cd", "cf", "cg", "ch", "ci", "cl", "cm", "cn", "co.ao", "co.bw", "co.ck",
    "co.cr", "co.id", "co.il", "co.in", "co.jp", "co.ke", "co.kr", "co.ls", "co.ma", "co.mz",
    "co.nz", "co.th", "co.tz", "co.ug", "co.uk", "co.uz", "co.ve", "co.vi", "co.za", "co.zm",
    "co.zw", "com", "com.af", "com.ag", "com.ar", "com.au", "com.bd", "com.bh", "com.bn", "com.bo",
    "com.br", "com.bz", "com.co", "com.cu", "com.cy", "com.do", "com.ec", "com.eg", "com.et",
    "com.fj", "com.gh", "com.gi", "com.gt", "com.hk", "com.jm", "com.kh", "com.kw", "com.lb",
    "com.ly", "com.mm", "com.mt", "com.mx", "com.my", "com.na", "com.ng", "com.ni", "com.np",
    "com.om", "com.pa", "com.pe", "com.pg", "com.ph", "com.pk", "com.pr", "com.py", "com.qa",
    "com.sa", "com.sb", "com.sg", "com.sl", "com.sv", "com.tj", "com.tr", "com.tw", "com.ua",
    "com.uy", "com.vc", "com.vn", "cv", "cz", "de", "dj", "dk", "dm", "dz", "ee", "es", "fi", "fm",
    "fr", "ga", "ge", "gg", "gl", "gm", "gr", "gy", "hn", "hr", "ht", "hu", "ie", "im", "iq", "is",
    "it", "je", "jo", "kg", "ki", "kz", "la", "li", "lk", "lt", "lu", "lv", "md", "me", "mg", "mk",
    "ml", "mn", "mu", "mv", "mw", "ne", "nl", "no", "nr", "nu", "pl", "pn", "ps", "pt", "ro", "rs",
    "ru", "rw", "sc", "se", "sh", "si", "sk", "sm", "sn", "so", "sr", "st", "td", "tg", "tl", "tm",
    "tn", "to", "tt", "vu", "ws",
];
const GOOGLE_SAFE: &str = "forcesafesearch.google.com";
const BING_SAFE: &str = "strict.bing.com";
const DUCKDUCKGO_SAFE: &str = "safe.duckduckgo.com";
const YOUTUBE_SAFE: &str = "restrictmoderate.youtube.com";
/// The SafeSearch names besides Google's search domains.
const SAFE_SEARCH: [(&str, &str); 10] = [
    ("bing.com", BING_SAFE),
    ("www.bing.com", BING_SAFE),
    ("duckduckgo.com", DUCKDUCKGO_SAFE),
    ("www.duckduckgo.com", DUCKDUCKGO_SAFE),
    ("start.duckduckgo.com", DUCKDUCKGO_SAFE),
    ("www.youtube.com", YOUTUBE_SAFE),
    ("m.youtube.com", YOUTUBE_SAFE),
    ("youtubei.googleapis.com", YOUTUBE_SAFE),
    ("youtube.googleapis.com", YOUTUBE_SAFE),
    ("www.youtube-nocookie.com", YOUTUBE_SAFE),
];

/// What a rewritten name answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found<'a> {
    /// A gets the IPv4 addresses, AAAA the IPv6 ones.
    Addresses(&'a [IpAddr]),
    /// The addresses of this name, looked up without rewrites or blocking.
    Target(&'a str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum By {
    User,
    SafeSearch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    Addresses(Box<[IpAddr]>),
    Target(Box<str>),
    /// A target name whose own rewrite has addresses: the entry that holds them, which is
    /// always an `Addresses`, so an alias shares them and costs no copy.
    AddressesOf(Entry),
}

/// Where an answer is in the tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Entry {
    Exact(usize),
    Wildcard(usize),
}

/// Owner names in wire format with their answers, sorted by owner.
type Table = Vec<(Box<[u8]>, Answer)>;

/// The user's rewrites: exact names, and the base names of `*.` wildcards.
#[derive(Debug, Default)]
pub struct Rewrites {
    exact: Table,
    wildcards: Table,
    /// The SafeSearch names that a rewrite of the user gives addresses, and the entry that
    /// holds them.
    safe_search_addresses: Vec<(&'static str, Entry)>,
}

impl Rewrites {
    /// The table of `rewrites`, which the config checks have passed.
    pub fn new(rewrites: &[Rewrite]) -> Result<Rewrites, String> {
        let mut owners: BTreeMap<(bool, Box<[u8]>), Answer> = BTreeMap::new();

        for rewrite in rewrites {
            let owner = rewrite.name.trim();
            let (is_wildcard, base) = match owner.strip_prefix("*.") {
                Some(base) => (true, base),
                None => (false, owner),
            };
            let wire = normalized_name(base)
                .and_then(|base| Name::from_text(&base))
                .ok_or_else(|| format!("rewrite {owner:?}: not a domain name"))?;
            let key = (is_wildcard, Box::from(wire.as_wire()));
            let answer = rewrite.answer.trim();

            if let Ok(address) = answer.parse::<IpAddr>() {
                match owners.entry(key).or_insert(Answer::Addresses(Box::new([]))) {
                    Answer::Addresses(addresses) if addresses.contains(&address) => {}

                    Answer::Addresses(addresses) => {
                        let mut more = std::mem::take(addresses).into_vec();
                        more.push(address);
                        *addresses = more.into_boxed_slice();
                    }

                    Answer::Target(_) | Answer::AddressesOf(_) => {
                        return Err(format!("rewrite {owner:?} has addresses and a name"));
                    }
                }

                continue;
            }

            let target = normalized_name(answer)
                .ok_or_else(|| format!("rewrite {owner:?}: {answer:?} is not an answer"))?;
            if owners
                .insert(key, Answer::Target(target.into_boxed_str()))
                .is_some()
            {
                return Err(format!("rewrite {owner:?} has more than one answer"));
            }
        }

        let mut rewrites = Rewrites::default();
        for ((is_wildcard, owner), answer) in owners {
            let table = if is_wildcard {
                &mut rewrites.wildcards
            } else {
                &mut rewrites.exact
            };

            table.push((owner, answer));
        }

        rewrites.answer_targets_with_addresses();

        Ok(rewrites)
    }

    /// A target name that has addresses of its own rewrite is answered with them. One step
    /// only, against the table as written: a target's own target is never followed, so there
    /// are no loops.
    fn answer_targets_with_addresses(&mut self) {
        let addresses_of = |rewrites: &Rewrites, target: &str| {
            let entry = rewrites.find_user(&Name::from_text(target)?)?;

            matches!(rewrites.answer(entry), Answer::Addresses(_)).then_some(entry)
        };
        let resolved = |rewrites: &Rewrites, table: &Table| -> Vec<Option<Entry>> {
            table
                .iter()
                .map(|(_, answer)| match answer {
                    Answer::Target(target) => addresses_of(rewrites, target),
                    Answer::Addresses(_) | Answer::AddressesOf(_) => None,
                })
                .collect()
        };
        let exact = resolved(self, &self.exact);
        let wildcards = resolved(self, &self.wildcards);
        self.safe_search_addresses = [GOOGLE_SAFE, BING_SAFE, DUCKDUCKGO_SAFE, YOUTUBE_SAFE]
            .into_iter()
            .filter_map(|target| Some((target, addresses_of(self, target)?)))
            .collect();

        for (table, resolved) in [(&mut self.exact, exact), (&mut self.wildcards, wildcards)] {
            for ((_, answer), owner) in table.iter_mut().zip(resolved) {
                if let Some(owner) = owner {
                    *answer = Answer::AddressesOf(owner);
                }
            }
        }
    }

    /// The rewrite of `name`: the user's own first, then SafeSearch when `safe_search` is on.
    /// An exact name beats a wildcard, and a longer wildcard a shorter one.
    pub fn find(&self, name: &Name, safe_search: bool) -> Option<(Found<'_>, By)> {
        if let Some(entry) = self.find_user(name) {
            return Some((self.found(entry), By::User));
        }

        if !safe_search {
            return None;
        }

        let target = safe_search_target(name)?;
        let found = match self
            .safe_search_addresses
            .iter()
            .find(|(safe, _)| *safe == target)
        {
            Some((_, owner)) => self.found(*owner),
            None => Found::Target(target),
        };

        Some((found, By::SafeSearch))
    }

    fn find_user(&self, name: &Name) -> Option<Entry> {
        let wire = name.as_wire();
        if let Some(index) = search(&self.exact, wire) {
            return Some(Entry::Exact(index));
        }

        // `*.x` answers for the names below x, never x itself: only the proper suffixes count.
        let mut start = 0;
        while wire[start] != 0 {
            start += 1 + usize::from(wire[start]);

            if let Some(index) = search(&self.wildcards, &wire[start..]) {
                return Some(Entry::Wildcard(index));
            }
        }

        None
    }

    fn answer(&self, entry: Entry) -> &Answer {
        match entry {
            Entry::Exact(index) => &self.exact[index].1,
            Entry::Wildcard(index) => &self.wildcards[index].1,
        }
    }

    fn found(&self, entry: Entry) -> Found<'_> {
        match self.answer(entry) {
            Answer::Addresses(addresses) => Found::Addresses(addresses),
            Answer::Target(target) => Found::Target(target),
            // One step: the owner holds addresses.
            Answer::AddressesOf(owner) => self.found(*owner),
        }
    }

    pub fn len(&self) -> usize {
        self.exact.len() + self.wildcards.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn search(table: &Table, wire: &[u8]) -> Option<usize> {
    table
        .binary_search_by(|(owner, _)| owner.as_ref().cmp(wire))
        .ok()
}

/// The SafeSearch name of a search engine's name, if it has one.
fn safe_search_target(name: &Name) -> Option<&'static str> {
    if let Some((_, target)) = SAFE_SEARCH
        .iter()
        .find(|(owner, _)| is_name(owner, name.labels()))
    {
        return Some(target);
    }

    let mut labels = name.labels();
    let mut first = labels.next()?;
    if first == b"www" {
        first = labels.next()?;
    }

    if first != b"google" {
        return None;
    }

    GOOGLE_SEARCH_DOMAINS
        .iter()
        .any(|domain| is_name(domain, labels.clone()))
        .then_some(GOOGLE_SAFE)
}

fn is_name(text: &str, labels: Labels<'_>) -> bool {
    text.split('.').map(str::as_bytes).eq(labels)
}

/// `rewrite` as it is kept: the name and a name answer lowercased, without spaces or a final
/// dot, and an address written the standard way. Anything that is not valid is left as sent,
/// for the checks to name.
pub fn normalized(rewrite: &Rewrite) -> Rewrite {
    let owner = rewrite.name.trim();
    let name = match owner.strip_prefix("*.") {
        Some(base) => normalized_name(base).map(|base| format!("*.{base}")),
        None => normalized_name(owner),
    };
    let answer = rewrite.answer.trim();
    let answer = match answer.parse::<IpAddr>() {
        Ok(address) => Some(address.to_string()),
        Err(_) => normalized_name(answer),
    };

    Rewrite {
        name: name.unwrap_or_else(|| rewrite.name.clone()),
        answer: answer.unwrap_or_else(|| rewrite.answer.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite(name: &str, answer: &str) -> Rewrite {
        Rewrite {
            name: name.to_string(),
            answer: answer.to_string(),
        }
    }

    fn table(entries: &[(&str, &str)]) -> Rewrites {
        let rewrites: Vec<Rewrite> = entries
            .iter()
            .map(|(name, answer)| rewrite(name, answer))
            .collect();

        Rewrites::new(&rewrites).unwrap()
    }

    fn name(text: &str) -> Name {
        Name::from_text(text).unwrap()
    }

    fn found<'a>(rewrites: &'a Rewrites, text: &str, safe_search: bool) -> Option<Found<'a>> {
        rewrites
            .find(&name(text), safe_search)
            .map(|(found, _)| found)
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn an_exact_name_answers_only_for_itself() {
        let rewrites = table(&[("nas.lan", "192.168.1.10")]);

        assert_eq!(
            found(&rewrites, "nas.lan", false),
            Some(Found::Addresses(&[ip("192.168.1.10")]))
        );
        assert_eq!(
            found(&rewrites, "NAS.Lan.", false),
            Some(Found::Addresses(&[ip("192.168.1.10")]))
        );
        assert_eq!(found(&rewrites, "a.nas.lan", false), None);
        assert_eq!(found(&rewrites, "lan", false), None);
        assert_eq!(found(&rewrites, "xnas.lan", false), None);
    }

    #[test]
    fn a_wildcard_answers_for_the_names_below_it_not_for_its_base() {
        let rewrites = table(&[("*.nas.lan", "nas.example")]);

        assert_eq!(
            found(&rewrites, "a.nas.lan", false),
            Some(Found::Target("nas.example"))
        );
        assert_eq!(
            found(&rewrites, "b.a.nas.lan", false),
            Some(Found::Target("nas.example"))
        );
        assert_eq!(found(&rewrites, "nas.lan", false), None);
        assert_eq!(found(&rewrites, "anas.lan", false), None);
    }

    #[test]
    fn an_exact_name_beats_a_wildcard_and_a_longer_wildcard_a_shorter_one() {
        let rewrites = table(&[
            ("*.home.lan", "10.0.0.1"),
            ("*.room.home.lan", "10.0.0.2"),
            ("tv.room.home.lan", "10.0.0.3"),
            ("*.tv.room.home.lan", "10.0.0.4"),
        ]);
        let address = |text| match found(&rewrites, text, false) {
            Some(Found::Addresses([address])) => address.to_string(),
            other => panic!("{text}: {other:?}"),
        };

        assert_eq!(address("x.home.lan"), "10.0.0.1");
        assert_eq!(address("room.home.lan"), "10.0.0.1");
        assert_eq!(address("pc.room.home.lan"), "10.0.0.2");
        assert_eq!(address("tv.room.home.lan"), "10.0.0.3");
        assert_eq!(address("app.tv.room.home.lan"), "10.0.0.4");
        assert_eq!(address("a.b.c.room.home.lan"), "10.0.0.2");
        assert_eq!(found(&rewrites, "home.lan", false), None);
    }

    #[test]
    fn one_name_keeps_all_its_addresses_once_in_order() {
        let rewrites = table(&[
            ("nas.lan", "192.168.1.10"),
            ("nas.lan", "fd00::10"),
            ("NAS.lan.", "192.168.1.10"),
            ("nas.lan", "192.168.1.11"),
        ]);

        assert_eq!(
            found(&rewrites, "nas.lan", false),
            Some(Found::Addresses(&[
                ip("192.168.1.10"),
                ip("fd00::10"),
                ip("192.168.1.11")
            ]))
        );
        assert_eq!(rewrites.len(), 1);
    }

    #[test]
    fn a_name_with_addresses_and_a_name_or_two_names_is_refused() {
        for entries in [
            [("a.lan", "10.0.0.1"), ("a.lan", "b.lan")],
            [("a.lan", "b.lan"), ("a.lan", "10.0.0.1")],
            [("a.lan", "b.lan"), ("A.lan", "c.lan")],
        ] {
            let rewrites: Vec<Rewrite> = entries
                .iter()
                .map(|(name, answer)| rewrite(name, answer))
                .collect();

            assert!(Rewrites::new(&rewrites).is_err(), "{entries:?}");
        }
    }

    #[test]
    fn safe_search_rewrites_the_search_engines_only_when_on() {
        let rewrites = Rewrites::default();

        for (asked, target) in [
            ("google.com", GOOGLE_SAFE),
            ("www.google.com", GOOGLE_SAFE),
            ("www.google.co.uk", GOOGLE_SAFE),
            ("google.com.au", GOOGLE_SAFE),
            ("www.google.cat", GOOGLE_SAFE),
            ("bing.com", BING_SAFE),
            ("www.bing.com", BING_SAFE),
            ("duckduckgo.com", DUCKDUCKGO_SAFE),
            ("www.duckduckgo.com", DUCKDUCKGO_SAFE),
            ("start.duckduckgo.com", DUCKDUCKGO_SAFE),
            ("www.youtube.com", YOUTUBE_SAFE),
            ("m.youtube.com", YOUTUBE_SAFE),
            ("youtubei.googleapis.com", YOUTUBE_SAFE),
            ("youtube.googleapis.com", YOUTUBE_SAFE),
            ("www.youtube-nocookie.com", YOUTUBE_SAFE),
        ] {
            assert_eq!(
                rewrites.find(&name(asked), true),
                Some((Found::Target(target), By::SafeSearch)),
                "{asked}"
            );
            assert_eq!(rewrites.find(&name(asked), false), None, "{asked}");
        }

        for other in [
            "mail.google.com",
            "google.example",
            "www.google.co",
            "google.co.uk.example",
            "x.www.google.com",
            "forcesafesearch.google.com",
            "strict.bing.com",
            "youtube.com",
            "music.youtube.com",
            "com",
        ] {
            assert_eq!(rewrites.find(&name(other), true), None, "{other}");
        }
    }

    #[test]
    fn the_google_search_domains_are_sorted_and_unique() {
        assert!(
            GOOGLE_SEARCH_DOMAINS
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
    }

    #[test]
    fn a_rewrite_of_the_user_beats_safe_search() {
        let rewrites = table(&[("www.google.com", "10.0.0.1"), ("*.bing.com", "b.lan")]);

        assert_eq!(
            rewrites.find(&name("www.google.com"), true),
            Some((Found::Addresses(&[ip("10.0.0.1")]), By::User))
        );
        assert_eq!(
            rewrites.find(&name("www.bing.com"), true),
            Some((Found::Target("b.lan"), By::User))
        );
        assert_eq!(
            rewrites.find(&name("google.de"), true),
            Some((Found::Target(GOOGLE_SAFE), By::SafeSearch))
        );
    }

    #[test]
    fn a_target_with_addresses_of_its_own_rewrite_is_answered_with_them() {
        let rewrites = table(&[
            ("*.nas.lan", "nas.lan"),
            ("nas.lan", "192.168.1.10"),
            ("nas.lan", "fd00::10"),
            ("tv.lan", "box.room.lan"),
            ("*.room.lan", "10.0.0.7"),
            ("forcesafesearch.google.com", "10.0.0.8"),
        ]);

        assert_eq!(
            found(&rewrites, "a.nas.lan", false),
            Some(Found::Addresses(&[ip("192.168.1.10"), ip("fd00::10")]))
        );
        assert_eq!(
            found(&rewrites, "tv.lan", false),
            Some(Found::Addresses(&[ip("10.0.0.7")]))
        );
        assert_eq!(
            rewrites.find(&name("www.google.com"), true),
            Some((Found::Addresses(&[ip("10.0.0.8")]), By::SafeSearch))
        );
        assert_eq!(
            rewrites.find(&name("www.bing.com"), true),
            Some((Found::Target(BING_SAFE), By::SafeSearch))
        );
    }

    #[test]
    fn a_target_whose_rewrite_is_another_name_is_not_followed() {
        let rewrites = table(&[
            ("a.lan", "b.lan"),
            ("b.lan", "c.lan"),
            ("c.lan", "10.0.0.3"),
            ("x.lan", "y.lan"),
            ("y.lan", "x.lan"),
        ]);

        assert_eq!(
            found(&rewrites, "a.lan", false),
            Some(Found::Target("b.lan"))
        );
        assert_eq!(
            found(&rewrites, "b.lan", false),
            Some(Found::Addresses(&[ip("10.0.0.3")]))
        );
        assert_eq!(
            found(&rewrites, "x.lan", false),
            Some(Found::Target("y.lan"))
        );
        assert_eq!(
            found(&rewrites, "y.lan", false),
            Some(Found::Target("x.lan"))
        );
    }

    #[test]
    fn rewrites_are_kept_lowercase_without_spaces_or_a_final_dot() {
        let cases = [
            (("NAS.Lan.", " 192.168.1.10 "), ("nas.lan", "192.168.1.10")),
            ((" *.Home.LAN ", "Nas.Lan."), ("*.home.lan", "nas.lan")),
            (("tv.lan", " FD00:0::10 "), ("tv.lan", "fd00::10")),
            (("nas", "10.0.0.1"), ("nas", "10.0.0.1")),
            (("a.lan", "not an answer"), ("a.lan", "not an answer")),
        ];

        for ((name, answer), (kept_name, kept_answer)) in cases {
            assert_eq!(
                normalized(&rewrite(name, answer)),
                rewrite(kept_name, kept_answer),
                "{name} {answer}"
            );
        }
    }
}
