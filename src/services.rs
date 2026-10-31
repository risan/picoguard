//! Blocked services (plan D8): AdGuard's catalog of services and the rules that block each,
//! downloaded at run time and never shipped. Only the index (id, name, group) is kept, and one
//! compiled list for each service switched on; the body and its parse are freed at once.

use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use serde::Serialize;
use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::config::{MAX_BLOCKED_SERVICES, MAX_SERVICE_ID_BYTES, ServicesConfig};
use crate::filter::compile::{CompileError, CompileOptions, CompileWorker, Compiled};
use crate::filter::engine::CompiledList;
use crate::filter::parse::ListFormat;
use crate::lists::{Downloader, Fetch, Limits, MAX_PIECE_BYTES, PIECE_QUEUE, Piece, Validators};
use crate::memory::ListBytes;

/// The largest catalog read; AdGuard's was 264 KB in 2026.
pub const MAX_CATALOG_BYTES: u64 = 2 * 1024 * 1024;
const MAX_NAME_BYTES: usize = 64;
const MAX_GROUP_BYTES: usize = 32;
const MAX_RULES_PER_SERVICE: usize = 2000;
const MAX_RULE_BYTES: usize = 256;
/// The services switched on together; AdGuard's whole catalog held 2,406 in 2026.
pub const MAX_SELECTED_RULES: usize = 20_000;
/// How long the page waits before it asks for a catalog that failed to download again.
const INDEX_RETRY: Duration = Duration::from_secs(60);

/// The compiled list of one service switched on, put in force like any list.
#[derive(Clone)]
pub(crate) struct ServiceList {
    pub id: Box<str>,
    /// "Blocked service: <name>", as "Check a name" shows it.
    pub label: String,
    pub list: Arc<CompiledList>,
    pub fingerprint: u128,
    /// The rules it was compiled from, which count in `MAX_SELECTED_RULES`.
    pub rules: usize,
}

impl ServiceList {
    pub fn bytes(&self) -> ListBytes {
        ListBytes {
            heap: self.list.heap_bytes(),
            charge: self.list.compile_charge(),
        }
    }
}

/// The rules of a service to compile: its id, its name and its rules, one per line.
pub(crate) type Wanted = (Box<str>, Box<str>, String);

/// What is known about the catalog and the services in force.
#[derive(Default)]
pub(crate) struct State {
    /// The services of the last catalog read.
    pub index: Option<Vec<Service>>,
    /// When the last catalog was read.
    pub loaded_at: Option<SystemTime>,
    /// Why the last download or refresh failed; cleared by the next one that works.
    pub error: Option<String>,
    pub fetching: bool,
    /// When the page last started a download of the index.
    pub asked_at: Option<Instant>,
    /// The ids switched on in force.
    pub selection: Vec<String>,
    /// The service lists in force, as one group of the memory estimate (plan D8).
    pub bytes: ListBytes,
    /// When the catalog is downloaded again; `None` with no service switched on.
    pub next_check: Option<Instant>,
    /// Refreshes that failed in a row.
    pub failures: u32,
}

/// The catalog of the blocked services: where it comes from, one download at a time, and
/// what is known about it.
pub(crate) struct Services {
    url: String,
    /// `services.refresh_hours` on the scheduler's clock.
    pub interval: Duration,
    pub state: Mutex<State>,
    fetching: tokio::sync::Mutex<()>,
    /// The downloader and the compile worker, once the scheduler runs.
    runtime: OnceLock<(Arc<Downloader>, CompileWorker)>,
    /// Wakes the scheduler when the selection or its next check changes.
    pub changed: Notify,
}

impl Services {
    pub fn new(config: &ServicesConfig, hour: Duration) -> Services {
        let state = State {
            selection: config.block.clone(),
            next_check: (!config.block.is_empty()).then(Instant::now),
            ..State::default()
        };

        Services {
            url: config.catalog_url.clone(),
            interval: hour * config.refresh_hours,
            state: Mutex::new(state),
            fetching: tokio::sync::Mutex::new(()),
            runtime: OnceLock::new(),
            changed: Notify::new(),
        }
    }

    pub fn start(&self, downloader: Arc<Downloader>, worker: CompileWorker) {
        let _ = self.runtime.set((downloader, worker));
    }

    pub fn worker(&self) -> Option<&CompileWorker> {
        self.runtime.get().map(|(_, worker)| worker)
    }

    /// Downloads and reads the catalog, one download at a time, keeps its index and returns
    /// the rules of the services in `wanted` it has. The body is read and freed off the
    /// runtime thread.
    pub async fn fetch(&self, wanted: &[String]) -> Result<Vec<Wanted>, String> {
        let Some((downloader, _)) = self.runtime.get() else {
            return Err("the blocked services are not running".to_string());
        };

        let _one = self.fetching.lock().await;
        self.state.lock().unwrap().fetching = true;
        let wanted = wanted.to_vec();
        let read = match download(downloader, &self.url).await {
            Ok(body) => tokio::task::spawn_blocking(move || parse(&body, &wanted))
                .await
                .unwrap_or_else(|_| Err("reading the catalog was stopped".to_string())),

            Err(error) => Err(error),
        };
        let mut state = self.state.lock().unwrap();
        state.fetching = false;

        match read {
            Ok(catalog) => {
                let rules = catalog
                    .rules
                    .into_iter()
                    .map(|(at, rules)| {
                        let service = &catalog.services[at];

                        (service.id.clone(), service.name.clone(), rules)
                    })
                    .collect();
                state.index = Some(catalog.services);
                state.loaded_at = Some(SystemTime::now());
                state.error = None;

                Ok(rules)
            }

            Err(error) => {
                state.error = Some(error.clone());

                Err(error)
            }
        }
    }

    /// Whether the page should start a download of the index now: none is held, none is
    /// running, and the last one asked for is a minute old.
    pub fn should_load_index(&self) -> bool {
        if self.runtime.get().is_none() {
            return false;
        }

        let mut state = self.state.lock().unwrap();
        let asked_long_ago = state.asked_at.is_none_or(|at| at.elapsed() >= INDEX_RETRY);
        if state.index.is_some() || state.fetching || !asked_long_ago {
            return false;
        }

        state.asked_at = Some(Instant::now());

        true
    }

    /// The page's view of the catalog.
    pub fn view(&self) -> ServicesView {
        let state = self.state.lock().unwrap();
        let services = state
            .index
            .iter()
            .flatten()
            .map(|service| ServiceView {
                id: service.id.to_string(),
                name: service.name.to_string(),
                group: service.group.to_string(),
                on: state.selection.iter().any(|id| **id == *service.id),
            })
            .collect();
        let waiting = state.error.is_none()
            && (state.index.is_none()
                || (!state.selection.is_empty() && state.loaded_at.is_none()));

        ServicesView {
            services,
            loaded_at: state.loaded_at.and_then(|at| {
                at.duration_since(SystemTime::UNIX_EPOCH)
                    .ok()
                    .map(|since| since.as_secs())
            }),
            error: state.error.clone(),
            loading: state.fetching || waiting,
        }
    }
}

/// `GET /api/services`.
#[derive(Debug, Serialize)]
pub struct ServicesView {
    pub services: Vec<ServiceView>,
    /// Seconds since the epoch.
    pub loaded_at: Option<u64>,
    pub error: Option<String>,
    pub loading: bool,
}

#[derive(Debug, Serialize)]
pub struct ServiceView {
    pub id: String,
    pub name: String,
    pub group: String,
    pub on: bool,
}

/// The list of one service's rules, compiled on the worker within `room` bytes (see
/// `CompileWorker::start_within`). A service only blocks, and never a canary name.
pub(crate) async fn compile(
    worker: &CompileWorker,
    rules: String,
    room: usize,
) -> Result<Compiled, CompileError> {
    let options = CompileOptions {
        allow_redirects: false,
        check_canaries: true,
        ..CompileOptions::new(ListFormat::Adblock, MAX_RULES_PER_SERVICE as u32)
    };
    let compilation = worker.start_within(options, room);
    for piece in rules.as_bytes().chunks(MAX_PIECE_BYTES) {
        if compilation
            .pieces
            .send(Piece::Data(piece.to_vec()))
            .await
            .is_err()
        {
            return compilation.result().await;
        }
    }

    drop(rules);
    let _ = compilation.pieces.send(Piece::End).await;

    compilation.result().await
}

/// One service of the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub id: Box<str>,
    pub name: Box<str>,
    pub group: Box<str>,
}

/// What a catalog holds for picoguard: every service it may show, and the rules of the
/// services asked for.
#[derive(Debug, Default)]
pub struct Catalog {
    pub services: Vec<Service>,
    /// For each service asked for that the catalog has: its index in `services` and its rules,
    /// one per line.
    pub rules: Vec<(usize, String)>,
}

/// The catalog in `body`, with the rules of the services in `wanted`. An entry over a cap is
/// left out; only `id`, `name`, `group` and `rules` are read, the rest is skipped unkept.
pub fn parse(body: &[u8], wanted: &[String]) -> Result<Catalog, String> {
    let mut reader = serde_json::Deserializer::from_slice(body);
    let mut catalog = Catalog::default();
    let found = CatalogSeed {
        wanted,
        catalog: &mut catalog,
    }
    .deserialize(&mut reader)
    .and_then(|found| reader.end().map(|()| found))
    .map_err(|error| format!("the catalog is not valid: {error}"))?;
    if !found {
        return Err("the catalog has no blocked_services".to_string());
    }

    catalog.services.shrink_to_fit();

    Ok(catalog)
}

/// The top-level object; answers whether it had `blocked_services`.
struct CatalogSeed<'a> {
    wanted: &'a [String],
    catalog: &'a mut Catalog,
}

impl<'de> DeserializeSeed<'de> for CatalogSeed<'_> {
    type Value = bool;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<bool, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for CatalogSeed<'_> {
    type Value = bool;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object with blocked_services")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
        let mut found = false;
        while let Some(key) = map.next_key::<String>()? {
            if key == "blocked_services" && !found {
                found = true;
                map.next_value_seed(EntriesSeed {
                    wanted: self.wanted,
                    catalog: &mut *self.catalog,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }

        Ok(found)
    }
}

struct EntriesSeed<'a> {
    wanted: &'a [String],
    catalog: &'a mut Catalog,
}

impl<'de> DeserializeSeed<'de> for EntriesSeed<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for EntriesSeed<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a list of services")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while let Some(entry) = seq.next_element_seed(EntrySeed)? {
            let catalog = &mut *self.catalog;
            let Some(entry) = entry else {
                continue;
            };

            let is_new = !catalog
                .services
                .iter()
                .any(|service| service.id == entry.service.id);
            if !is_new || catalog.services.len() == MAX_BLOCKED_SERVICES {
                continue;
            }

            if self.wanted.iter().any(|id| **id == *entry.service.id) && !entry.rules.is_empty() {
                catalog.rules.push((catalog.services.len(), entry.rules));
            }

            catalog.services.push(entry.service);
        }

        Ok(())
    }
}

struct Entry {
    service: Service,
    rules: String,
}

/// One service; `None` when it is over a cap or lacks its id or name.
struct EntrySeed;

impl<'de> DeserializeSeed<'de> for EntrySeed {
    type Value = Option<Entry>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for EntrySeed {
    type Value = Option<Entry>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a service")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let (mut id, mut name, mut group) = (None, None, None);
        let mut rules = Some(String::new());
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "id" => id = Some(map.next_value::<String>()?),
                "name" => name = Some(map.next_value::<String>()?),
                "group" => group = Some(map.next_value::<String>()?),
                "rules" => {
                    rules = map.next_value_seed(RulesSeed)?;
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }

        let is_id = |id: &String| {
            (1..=MAX_SERVICE_ID_BYTES).contains(&id.len())
                && id.bytes().all(|byte| byte.is_ascii_graphic())
        };
        let is_text =
            |text: &String, most: usize| text.len() <= most && !text.chars().any(char::is_control);
        let id = id.filter(is_id);
        let name = name.filter(|name| !name.is_empty() && is_text(name, MAX_NAME_BYTES));
        let group = group.unwrap_or_default().to_ascii_lowercase();
        let (Some(id), Some(name), Some(rules)) = (id, name, rules) else {
            return Ok(None);
        };

        if !is_text(&group, MAX_GROUP_BYTES) {
            return Ok(None);
        }

        Ok(Some(Entry {
            service: Service {
                id: id.into_boxed_str(),
                name: name.into_boxed_str(),
                group: group.into_boxed_str(),
            },
            rules,
        }))
    }
}

/// The rules of one service, one per line; `None` when they are over a cap. Exceptions and
/// rules that would reach into other lists (`$badfilter`, `$important`) are left out: a
/// service only blocks.
struct RulesSeed;

impl<'de> DeserializeSeed<'de> for RulesSeed {
    type Value = Option<String>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for RulesSeed {
    type Value = Option<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a list of rules")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut rules = Rules {
            text: String::new(),
            count: 0,
            over: false,
        };
        while seq.next_element_seed(&mut rules)?.is_some() {}

        Ok((!rules.over).then_some(rules.text))
    }
}

struct Rules {
    text: String,
    count: usize,
    over: bool,
}

impl<'de> DeserializeSeed<'de> for &mut Rules {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl Visitor<'_> for &mut Rules {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a rule")
    }

    fn visit_str<E: de::Error>(self, rule: &str) -> Result<(), E> {
        if self.over {
            return Ok(());
        }

        self.count += 1;
        if self.count > MAX_RULES_PER_SERVICE
            || rule.len() > MAX_RULE_BYTES
            || rule.chars().any(char::is_control)
        {
            self.over = true;
            self.text = String::new();

            return Ok(());
        }

        let rule = rule.trim();
        let modifiers = rule.rsplit_once('$').map_or("", |(_, modifiers)| modifiers);
        let reaches_other_lists = rule.starts_with("@@")
            || modifiers.contains("badfilter")
            || modifiers.contains("important");
        if rule.is_empty() || reaches_other_lists {
            return Ok(());
        }

        self.text.push_str(rule);
        self.text.push('\n');

        Ok(())
    }
}

/// The catalog at `url`, at most `MAX_CATALOG_BYTES`, through the list downloader (its TLS and
/// redirect rules, and one resolver for the whole download).
pub async fn download(downloader: &Downloader, url: &str) -> Result<Vec<u8>, String> {
    let limits = Limits {
        max_body_bytes: MAX_CATALOG_BYTES,
        idle_timeout: std::time::Duration::from_secs(30),
        total_timeout: std::time::Duration::from_secs(120),
        max_redirects: 5,
    };
    let download = match downloader
        .fetch(url, &Validators::default(), &limits)
        .await
        .map_err(|error| error.to_string())?
    {
        Fetch::Modified(download) => download,
        Fetch::NotModified => return Err("not modified".to_string()),
    };
    let (sender, mut receiver) = tokio::sync::mpsc::channel(PIECE_QUEUE);
    // The pumping future owns the only sender, so the collector below cannot wait for ever.
    let pumping = async move {
        let result = download.pump(&sender).await;
        drop(sender);

        result
    };
    let collecting = async {
        let mut body = Vec::new();
        while let Some(piece) = receiver.recv().await {
            match piece {
                Piece::Data(data) => body.extend_from_slice(&data),
                Piece::End => return Some(body),
            }
        }

        None
    };
    let (pumped, body) = tokio::join!(pumping, collecting);
    pumped.map_err(|error| error.to_string())?;

    body.ok_or_else(|| "the catalog ended early".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wanted(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|id| id.to_string()).collect()
    }

    fn entry(id: &str, name: &str, group: &str, rules: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "name": name,
            "group": group,
            "rules": rules,
            "icon_svg": "<svg>an icon that is never kept</svg>",
        })
    }

    fn body(entries: Vec<serde_json::Value>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "blocked_services": entries,
            "groups": [{"id": "social"}],
        }))
        .unwrap()
    }

    fn ids(catalog: &Catalog) -> Vec<&str> {
        catalog
            .services
            .iter()
            .map(|service| &*service.id)
            .collect()
    }

    #[test]
    fn the_index_has_every_service_and_the_rules_only_of_those_wanted() {
        let catalog = parse(
            &body(vec![
                entry(
                    "chat",
                    "Chat",
                    "messenger",
                    &["||chat.example^", "||chat.example.net^"],
                ),
                entry("video", "Video", "streaming", &["||video.example^"]),
            ]),
            &wanted(&["video", "missing"]),
        )
        .unwrap();

        assert_eq!(
            catalog.services,
            [
                Service {
                    id: "chat".into(),
                    name: "Chat".into(),
                    group: "messenger".into(),
                },
                Service {
                    id: "video".into(),
                    name: "Video".into(),
                    group: "streaming".into(),
                },
            ]
        );
        assert_eq!(catalog.rules, [(1, "||video.example^\n".to_string())]);
    }

    #[test]
    fn an_entry_over_a_cap_or_without_an_id_or_name_is_left_out() {
        let long_rule = format!("||{}.example^", "a".repeat(250));
        let many_rules: Vec<String> = (0..2001).map(|n| format!("||n{n}.example^")).collect();
        let many_rules: Vec<&str> = many_rules.iter().map(String::as_str).collect();
        let entries = vec![
            entry(&"i".repeat(65), "Long id", "g", &["||a.example^"]),
            entry("with space", "Bad id", "g", &["||a.example^"]),
            entry("long_name", &"n".repeat(65), "g", &["||a.example^"]),
            entry(
                "long_group",
                "Long group",
                &"g".repeat(33),
                &["||a.example^"],
            ),
            entry("long_rule", "Long rule", "g", &[&long_rule]),
            entry("many", "Many", "g", &many_rules),
            entry("newline", "Newline", "g", &["||a.example^\n||b.example^"]),
            serde_json::json!({"name": "No id", "rules": []}),
            serde_json::json!({"id": "noname", "rules": []}),
            entry("ok", "Ok", "g", &["||ok.example^"]),
            entry("ok", "Twice", "g", &["||twice.example^"]),
            entry(
                &"i".repeat(64),
                &"n".repeat(64),
                &"g".repeat(32),
                &["||max.example^"],
            ),
        ];
        let all: Vec<String> = entries
            .iter()
            .filter_map(|entry| entry["id"].as_str().map(str::to_string))
            .collect();

        let catalog = parse(&body(entries), &all).unwrap();

        assert_eq!(ids(&catalog), ["ok", "i".repeat(64).as_str()]);
        assert_eq!(catalog.services[0].name.as_ref(), "Ok");
        assert_eq!(catalog.rules.len(), 2);
    }

    #[test]
    fn at_most_1000_services_are_kept() {
        let entries = (0..1005)
            .map(|n| entry(&format!("s{n}"), "S", "g", &[]))
            .collect();

        let catalog = parse(&body(entries), &[]).unwrap();

        assert_eq!(catalog.services.len(), 1000);
        assert_eq!(&*catalog.services[999].id, "s999");
    }

    #[test]
    fn exceptions_and_rules_that_reach_other_lists_are_left_out() {
        let catalog = parse(
            &body(vec![entry(
                "s",
                "S",
                "g",
                &[
                    "||a.example^",
                    "@@||b.example^",
                    "||c.example^$badfilter",
                    "||d.example^$important",
                    "||e.example^$dnstype=~CNAME",
                    "/^f[0-9]+\\.example$/",
                    "  ",
                ],
            )]),
            &wanted(&["s"]),
        )
        .unwrap();

        assert_eq!(
            catalog.rules[0].1,
            "||a.example^\n||e.example^$dnstype=~CNAME\n/^f[0-9]+\\.example$/\n"
        );
    }

    #[test]
    fn a_body_that_is_not_a_catalog_is_refused() {
        for (body, reason) in [
            (&b"[]"[..], "the catalog is not valid"),
            (b"{\"groups\": []}", "the catalog has no blocked_services"),
            (b"{\"blocked_services\": [", "the catalog is not valid"),
            (b"{\"blocked_services\": []} x", "the catalog is not valid"),
            (b"<html>", "the catalog is not valid"),
        ] {
            let error = parse(body, &[]).unwrap_err();

            assert!(error.starts_with(reason), "{error}");
        }
    }

    #[test]
    fn unknown_fields_and_escaped_text_are_read() {
        let body = concat!(
            r#"{"version": 2, "blocked_services": [{"icon_svg": "<svg/>", "#,
            r#""rules": ["||a\u002eexample^"], "extra": {"x": [1, 2]}, "#,
            r#""group": "Social_Network", "name": "Caf\u00e9", "id": "cafe"}]}"#,
        )
        .as_bytes();

        let catalog = parse(body, &wanted(&["cafe"])).unwrap();

        assert_eq!(&*catalog.services[0].name, "Café");
        assert_eq!(&*catalog.services[0].group, "social_network");
        assert_eq!(catalog.rules[0].1, "||a.example^\n");
    }
}
