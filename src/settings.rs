//! The settings saved from the status page (plan D1-D3). They live in `settings.json` in
//! `state.dir`, which the service may write, and override the config file field by field; the
//! config file itself is never written. The file holds only what the page may change, in types
//! of its own, so the config file's other fields of a section are never lost.
//!
//! A file that cannot be used never stops picoguard: it starts on the config file alone and
//! keeps the reason for the page. Only a save from the page writes the file, whole, through a
//! `.part` file and a rename.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::config::{CacheConfig, Config, ConfigError, ListConfig, Rewrite};
use crate::pipeline::Pipeline;
use crate::release;
use crate::scheduler::{ButtonRule, MAX_BUTTON_RULES, drop_off_runtime, normalized_name};
use crate::upstream::Upstreams;

pub const FILE_NAME: &str = "settings.json";
const PART_NAME: &str = "settings.json.part";
pub const MAX_FILE_BYTES: usize = 256 * 1024;
const VERSION: u32 = 1;

const MAX_UPSTREAMS: usize = 8;
const MAX_BOOTSTRAP: usize = 4;
const MIN_CACHE_BYTES: usize = 256 * 1024;
const MAX_CACHE_BYTES: usize = 16 * 1024 * 1024;
const MAX_PAGE_BLOCKLISTS: usize = 32;
const MAX_PAGE_ALLOWLISTS: usize = 16;
const MAX_REFRESH_HOURS: u32 = 168;

/// The whole file. Every key but `version` may be left out; a key that is out leaves the
/// config file's value in force.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<UpstreamSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheSettings>,
    /// With it, the config file's URL lists are not used; its `path` lists stay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lists: Option<Vec<PageList>>,
    /// Block and Allow from the query log. They join the config's `rules`, never replace them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub page_rules: Vec<ButtonRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrites: Option<Vec<Rewrite>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe_search: Option<bool>,
    /// The ids of the blocked services.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<String>>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            version: VERSION,
            upstream: None,
            cache: None,
            lists: None,
            page_rules: Vec::new(),
            rewrites: None,
            safe_search: None,
            services: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamSettings {
    pub servers: Vec<String>,
    pub bootstrap: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheSettings {
    pub max_entries: usize,
    pub max_bytes: usize,
    pub min_ttl: u32,
    pub max_ttl: u32,
    pub optimistic: bool,
}

impl CacheSettings {
    /// The page's fields of `config`.
    pub fn of(config: &CacheConfig) -> CacheSettings {
        CacheSettings {
            max_entries: config.max_entries,
            max_bytes: config.max_bytes,
            min_ttl: config.min_ttl,
            max_ttl: config.max_ttl,
            optimistic: config.optimistic,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListRole {
    Block,
    Allow,
}

/// A list added or edited on the page: always a URL list. Its format and caps come from the
/// config file's entry of the same role and URL, or are the defaults.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageList {
    pub role: ListRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub url: String,
    pub refresh_hours: u32,
    pub enabled: bool,
}

impl Settings {
    /// The limits of the page itself; the merged config is checked like the config file after.
    fn validate(&self) -> Result<(), String> {
        if self.version != VERSION {
            return Err(format!(
                "version {} is unknown, this picoguard reads version {VERSION}",
                self.version
            ));
        }

        if let Some(upstream) = &self.upstream {
            if !(1..=MAX_UPSTREAMS).contains(&upstream.servers.len()) {
                return Err(format!("upstream.servers: 1 to {MAX_UPSTREAMS} servers"));
            }

            if upstream.bootstrap.len() > MAX_BOOTSTRAP {
                return Err(format!(
                    "upstream.bootstrap: at most {MAX_BOOTSTRAP} addresses"
                ));
            }
        }

        if let Some(cache) = &self.cache
            && !(MIN_CACHE_BYTES..=MAX_CACHE_BYTES).contains(&cache.max_bytes)
        {
            return Err(format!(
                "cache.max_bytes must be from {MIN_CACHE_BYTES} to {MAX_CACHE_BYTES}"
            ));
        }

        if let Some(lists) = &self.lists {
            validate_page_lists(lists)?;
        }

        validate_page_rules(&self.page_rules)
    }

    /// Puts these settings over `config`, the config file alone.
    fn overlay(&self, config: &mut Config) {
        if let Some(upstream) = &self.upstream {
            config.upstream.servers.clone_from(&upstream.servers);
            config.upstream.bootstrap.clone_from(&upstream.bootstrap);
        }

        if let Some(cache) = &self.cache {
            config.cache.max_entries = cache.max_entries;
            config.cache.max_bytes = cache.max_bytes;
            config.cache.min_ttl = cache.min_ttl;
            config.cache.max_ttl = cache.max_ttl;
            config.cache.optimistic = cache.optimistic;
        }

        if let Some(lists) = &self.lists {
            config.lists = with_page_lists(&config.lists, lists, ListRole::Block);
            config.allowlists = with_page_lists(&config.allowlists, lists, ListRole::Allow);
        }

        if let Some(rewrites) = &self.rewrites {
            config.rewrites.clone_from(rewrites);
        }

        if let Some(safe_search) = self.safe_search {
            config.safe_search = safe_search;
        }

        if let Some(services) = &self.services {
            config.services.block.clone_from(services);
        }
    }
}

fn validate_page_lists(lists: &[PageList]) -> Result<(), String> {
    let count = |role| lists.iter().filter(|list| list.role == role).count();

    if count(ListRole::Block) > MAX_PAGE_BLOCKLISTS {
        return Err(format!("lists: at most {MAX_PAGE_BLOCKLISTS} block lists"));
    }

    if count(ListRole::Allow) > MAX_PAGE_ALLOWLISTS {
        return Err(format!("lists: at most {MAX_PAGE_ALLOWLISTS} allowlists"));
    }

    for (index, list) in lists.iter().enumerate() {
        if !(1..=MAX_REFRESH_HOURS).contains(&list.refresh_hours) {
            return Err(format!(
                "lists[{index}].refresh_hours must be from 1 to {MAX_REFRESH_HOURS}"
            ));
        }
    }

    Ok(())
}

fn validate_page_rules(rules: &[ButtonRule]) -> Result<(), String> {
    if rules.len() > MAX_BUTTON_RULES {
        return Err(format!("page_rules: at most {MAX_BUTTON_RULES} rules"));
    }

    for (index, rule) in rules.iter().enumerate() {
        if normalized_name(&rule.name).as_deref() != Some(rule.name.as_str()) {
            return Err(format!("page_rules[{index}].name is not a domain name"));
        }

        if rules[..index].iter().any(|other| other.name == rule.name) {
            return Err(format!("page_rules[{index}] is listed twice"));
        }
    }

    Ok(())
}

/// The config file's `path` lists of one role, then the page's lists of that role. A page list
/// keeps the format and caps of the config file's entry with its URL, so copying the file's
/// lists to the page changes nothing about them.
fn with_page_lists(file: &[ListConfig], page: &[PageList], role: ListRole) -> Vec<ListConfig> {
    let paths = file.iter().filter(|list| list.path.is_some()).cloned();
    let urls = page.iter().filter(|list| list.role == role).map(|list| {
        let options = file
            .iter()
            .find(|entry| entry.url.as_deref() == Some(list.url.as_str()))
            .cloned()
            .unwrap_or_default();

        ListConfig {
            name: list.name.clone(),
            url: Some(list.url.clone()),
            refresh_hours: list.refresh_hours,
            enabled: list.enabled,
            ..options
        }
    });

    paths.chain(urls).collect()
}

/// `settings` over `file`, the config file alone, checked as a whole: what a save or a start
/// would run with.
pub fn merged(file: &Config, settings: &Settings) -> Result<Config, String> {
    settings.validate()?;

    let mut config = file.clone();
    settings.overlay(&mut config);
    config.validate().map_err(|error| error.to_string())?;

    Ok(config)
}

/// The settings in `path`, or `None` when there is no file. The file sits in a folder the
/// service can write, and `--check` reads it as root: a link or anything but a regular file of
/// at most `MAX_FILE_BYTES` is refused.
pub fn read(path: &Path) -> Result<Option<Settings>, String> {
    let bytes = match release::read_regular(path, MAX_FILE_BYTES as u64) {
        Ok(bytes) => bytes,

        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }

        Err(error) => {
            return Err(format!("cannot read it: {error}"));
        }
    };

    // A JSON array would fill the struct too.
    if bytes.trim_ascii_start().first() != Some(&b'{') {
        return Err("not a JSON object".to_string());
    }

    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| error.to_string())
}

/// What picoguard runs with.
pub struct Loaded {
    /// The config file with the saved settings over it.
    pub config: Config,
    pub saved: Saved,
}

/// The config file at `config_path`, then its saved settings. Only the config file can fail.
pub fn load(config_path: &Path) -> Result<Loaded, ConfigError> {
    Ok(with_saved(Config::load(config_path)?))
}

/// `file`, the config file alone, with the settings saved in its `state.dir` over it; a file
/// that cannot be used leaves `file` alone and its reason in `saved`.
pub fn with_saved(file: Config) -> Loaded {
    let path = file.state.dir.join(FILE_NAME);
    let used = read(&path).and_then(|settings| match settings {
        Some(settings) => merged(&file, &settings).map(|config| Some((config, settings))),
        None => Ok(None),
    });

    let (config, settings, error) = match used {
        Ok(Some((config, settings))) => (config, settings, None),
        Ok(None) => (file.clone(), Settings::default(), None),
        Err(reason) => (file.clone(), Settings::default(), Some(reason)),
    };

    Loaded {
        config,
        saved: Saved::new(file, settings, error),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveError {
    TooLarge,
    /// The reason, from the file system.
    Failed(String),
}

impl std::fmt::Display for SaveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SaveError::TooLarge => write!(
                formatter,
                "the settings would be larger than {} KiB",
                MAX_FILE_BYTES / 1024
            ),

            SaveError::Failed(reason) => write!(formatter, "could not save settings: {reason}"),
        }
    }
}

/// The saved settings in force and the one lock every change that saves holds, from building
/// the change to publishing it. Lock order: this, then the list assembly lock.
pub struct Saved {
    path: PathBuf,
    /// The config file alone: what the settings go over, and what a reset goes back to.
    file_config: Config,
    settings: tokio::sync::Mutex<Settings>,
    /// Why the file found at start was not used, until a save replaces it.
    error: Mutex<Option<String>>,
    /// False after a save failed, until one works.
    can_save: AtomicBool,
    before_rename: Mutex<Option<BeforeRename>>,
}

type BeforeRename = Arc<dyn Fn() + Send + Sync>;

impl Saved {
    pub fn new(file_config: Config, settings: Settings, error: Option<String>) -> Saved {
        Saved {
            path: file_config.state.dir.join(FILE_NAME),
            file_config,
            settings: tokio::sync::Mutex::new(settings),
            error: Mutex::new(error),
            can_save: AtomicBool::new(true),
            before_rename: Mutex::new(None),
        }
    }

    /// Runs `hook` on the writing thread of every later save, after the `.part` file is
    /// written and before it is renamed: a test can disconnect a client right there.
    #[doc(hidden)]
    pub fn run_before_rename(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self.before_rename.lock().unwrap() = Some(Arc::new(hook));
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn file_config(&self) -> &Config {
        &self.file_config
    }

    pub fn error(&self) -> Option<String> {
        self.error.lock().unwrap().clone()
    }

    pub fn can_save(&self) -> bool {
        self.can_save.load(Ordering::Relaxed)
    }

    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, Settings> {
        self.settings.lock().await
    }

    /// Writes `settings` as the whole file, off the runtime thread. The caller holds the lock
    /// and publishes its change only when this worked.
    pub async fn save(&self, settings: &Settings) -> Result<(), SaveError> {
        let bytes = encode(settings)?;
        let dir = self.file_config.state.dir.clone();
        let before_rename = self.before_rename.lock().unwrap().clone();
        let written = tokio::task::spawn_blocking(move || write(&dir, &bytes, before_rename))
            .await
            .unwrap_or_else(|_| Err(io::Error::other("the write was stopped")));
        self.can_save.store(written.is_ok(), Ordering::Relaxed);

        match written {
            Ok(()) => {
                *self.error.lock().unwrap() = None;

                Ok(())
            }

            Err(error) => {
                log::warn!("cannot save settings to {}: {error}", self.path.display());

                Err(SaveError::Failed(error.to_string()))
            }
        }
    }
}

/// A change of the page's upstream and cache settings. For each key, `None` leaves it as it
/// is, `Some(None)` goes back to the config file's value and `Some(Some(value))` sets it.
#[derive(Debug, Default)]
pub struct PageChange {
    pub upstream: Option<Option<UpstreamSettings>>,
    pub cache: Option<Option<CacheSettings>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeError {
    /// The settings were refused, with the reason.
    Invalid(String),
    /// Two replaced upstream pools are still in use by queries that started before them.
    UpstreamBusy,
    /// The change was not saved, so it is not in force either.
    NotSaved(SaveError),
    /// The task that applies the change ended without an answer.
    NotApplied,
}

/// What a change puts in force once it is saved.
struct Prepared {
    upstreams: Option<Upstreams>,
    cache: Option<CacheConfig>,
}

/// Builds the change, saves it, then puts it in force, all under the settings lock. Whatever
/// can fail (a value out of range, a server that cannot be used, a full set of replaced pools,
/// the write) fails before anything is in force. A change that leaves the settings as they are
/// writes nothing; one that only moves a value between the page and the config file is saved
/// and replaces nothing.
pub(crate) async fn apply(
    saved: &Saved,
    pipeline: &Pipeline,
    change: PageChange,
    answer: tokio::sync::oneshot::Sender<Result<(), ChangeError>>,
) {
    let mut settings = saved.lock().await;
    let upstream = change.upstream.unwrap_or_else(|| settings.upstream.clone());
    let cache = change.cache.unwrap_or_else(|| settings.cache.clone());
    if upstream == settings.upstream && cache == settings.cache {
        let _ = answer.send(Ok(()));

        return;
    }

    let old_upstream = std::mem::replace(&mut settings.upstream, upstream);
    let old_cache = std::mem::replace(&mut settings.cache, cache);
    let prepared = prepare(
        saved.file_config(),
        &settings,
        &old_upstream,
        &old_cache,
        pipeline,
    )
    .await;
    let saved_change = match prepared {
        Ok(prepared) => match saved.save(&settings).await {
            Ok(()) => Ok(prepared),

            Err(error) => {
                drop_off_runtime(prepared).await;

                Err(ChangeError::NotSaved(error))
            }
        },

        Err(error) => Err(error),
    };
    let prepared = match saved_change {
        Ok(prepared) => prepared,

        Err(error) => {
            settings.upstream = old_upstream;
            settings.cache = old_cache;
            let _ = answer.send(Err(error));

            return;
        }
    };

    let replaced_upstreams = prepared
        .upstreams
        .map(|upstreams| pipeline.upstreams().replace(upstreams));
    let replaced_cache = prepared.cache.map(|cache| pipeline.replace_cache(&cache));
    let _ = answer.send(Ok(()));

    // The lock is held until the replaced cache is freed, so changes never stack copies.
    drop_off_runtime((replaced_upstreams, replaced_cache, old_upstream, old_cache)).await;
}

/// The objects `settings` needs that differ from those in force under the old values. The
/// checks and the new pool are built off the runtime thread: building TLS settings may read
/// files (`/proc/cpuinfo` on 32-bit ARM).
async fn prepare(
    file: &Config,
    settings: &Settings,
    old_upstream: &Option<UpstreamSettings>,
    old_cache: &Option<CacheSettings>,
    pipeline: &Pipeline,
) -> Result<Prepared, ChangeError> {
    let cache_in_force = |page: &Option<CacheSettings>| {
        page.clone()
            .unwrap_or_else(|| CacheSettings::of(&file.cache))
    };
    let new_upstreams =
        upstream_in_force(old_upstream, file) != upstream_in_force(&settings.upstream, file);
    let new_cache = cache_in_force(old_cache) != cache_in_force(&settings.cache);
    let shared = Arc::clone(pipeline.upstreams());
    let file = file.clone();
    let settings = settings.clone();

    tokio::task::spawn_blocking(move || {
        let config = merged(&file, &settings).map_err(ChangeError::Invalid)?;
        let upstreams = if new_upstreams {
            if !shared.can_replace() {
                return Err(ChangeError::UpstreamBusy);
            }

            Some(
                Upstreams::from_config(&config.upstream, &config.limits)
                    .map_err(ChangeError::Invalid)?,
            )
        } else {
            None
        };

        Ok(Prepared {
            upstreams,
            cache: new_cache.then_some(config.cache),
        })
    })
    .await
    .unwrap_or(Err(ChangeError::NotApplied))
}

fn upstream_in_force<'a>(
    page: &'a Option<UpstreamSettings>,
    file: &'a Config,
) -> (&'a [String], &'a [IpAddr]) {
    match page {
        Some(page) => (&page.servers, &page.bootstrap),
        None => (&file.upstream.servers, &file.upstream.bootstrap),
    }
}

/// Counts what is written to it, and keeps nothing.
struct Counter(usize);

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += bytes.len();

        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The file's bytes. It is written twice, first only counted, so the cap is checked before
/// anything is allocated and the buffer is never grown: a save costs the file's size once.
fn encode(settings: &Settings) -> Result<Vec<u8>, SaveError> {
    let failed = |error: serde_json::Error| SaveError::Failed(error.to_string());
    let mut counter = Counter(0);
    serde_json::to_writer_pretty(&mut counter, settings).map_err(failed)?;

    if counter.0 > MAX_FILE_BYTES {
        return Err(SaveError::TooLarge);
    }

    let mut bytes = Vec::with_capacity(counter.0);
    serde_json::to_writer_pretty(&mut bytes, settings).map_err(failed)?;

    Ok(bytes)
}

/// The file appears whole or not at all (as `stage::write_whole`). Once it is renamed in place
/// it is saved: a failed sync of the folder after that is only logged.
fn write(dir: &Path, bytes: &[u8], before_rename: Option<BeforeRename>) -> io::Result<()> {
    let part = dir.join(PART_NAME);
    match fs::remove_file(&part) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            return Err(error);
        }

        _ => {}
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&part)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);

    if let Err(error) = written {
        let _ = fs::remove_file(&part);

        return Err(error);
    }

    if let Some(hook) = before_rename {
        hook();
    }

    fs::rename(&part, dir.join(FILE_NAME))?;

    if let Err(error) = File::open(dir).and_then(|dir| dir.sync_all()) {
        log::warn!("saved settings, but cannot sync {}: {error}", dir.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::config::ListFormat;
    use crate::scheduler::Action;
    use crate::test_dir::TestDir;

    fn rule(name: &str, action: Action) -> ButtonRule {
        ButtonRule {
            name: name.to_string(),
            action,
        }
    }

    fn page_list(role: ListRole, url: &str) -> PageList {
        PageList {
            role,
            name: Some(format!("page {url}")),
            url: url.to_string(),
            refresh_hours: 6,
            enabled: true,
        }
    }

    fn config_in(dir: &Path) -> Config {
        let mut config = Config::default();
        config.state.dir = dir.to_path_buf();

        config
    }

    fn reason(settings: &Settings) -> String {
        merged(&Config::default(), settings).expect_err("settings should be refused")
    }

    #[test]
    fn no_settings_change_nothing() {
        assert_eq!(
            merged(&Config::default(), &Settings::default()).unwrap(),
            Config::default()
        );
    }

    #[test]
    fn each_setting_replaces_only_its_own_fields() {
        let mut file = Config::default();
        file.upstream.timeout_ms = 2000;
        file.cache.max_response_size = 1232;
        file.cache.optimistic_answer_ttl_secs = 5;
        let settings = Settings {
            upstream: Some(UpstreamSettings {
                servers: vec!["tls://9.9.9.9#dns.quad9.net".to_string()],
                bootstrap: vec!["9.9.9.9".parse().unwrap()],
            }),
            cache: Some(CacheSettings {
                max_entries: 500,
                max_bytes: 1024 * 1024,
                min_ttl: 10,
                max_ttl: 3600,
                optimistic: false,
            }),
            rewrites: Some(vec![Rewrite {
                name: "nas.lan".to_string(),
                answer: "192.168.1.10".to_string(),
            }]),
            safe_search: Some(true),
            services: Some(vec!["tiktok".to_string()]),
            ..Settings::default()
        };

        let config = merged(&file, &settings).unwrap();

        assert_eq!(config.upstream.servers, ["tls://9.9.9.9#dns.quad9.net"]);
        assert_eq!(config.upstream.bootstrap.len(), 1);
        assert_eq!(config.upstream.timeout_ms, 2000);
        assert_eq!(config.cache.max_entries, 500);
        assert_eq!(config.cache.max_bytes, 1024 * 1024);
        assert_eq!(config.cache.min_ttl, 10);
        assert_eq!(config.cache.max_ttl, 3600);
        assert!(!config.cache.optimistic);
        assert_eq!(config.cache.max_response_size, 1232);
        assert_eq!(config.cache.optimistic_answer_ttl_secs, 5);
        assert_eq!(config.rewrites, settings.rewrites.unwrap());
        assert!(config.safe_search);
        assert_eq!(config.services.block, ["tiktok"]);
        assert_eq!(config.lists, file.lists);
        assert_eq!(config.web, file.web);
    }

    #[test]
    fn page_lists_follow_the_path_lists_and_replace_the_url_lists() {
        let file = Config {
            lists: vec![
                ListConfig {
                    url: Some("https://file.example/hosts.txt".to_string()),
                    format: ListFormat::Hosts,
                    max_rules: 1000,
                    max_body_bytes: 4096,
                    slow_rule_budget: 2048,
                    allow_redirects: true,
                    ..ListConfig::default()
                },
                ListConfig {
                    path: Some(PathBuf::from("/etc/picoguard/mine.txt")),
                    ..ListConfig::default()
                },
                ListConfig {
                    url: Some("https://file.example/gone.txt".to_string()),
                    ..ListConfig::default()
                },
            ],
            allowlists: vec![ListConfig {
                path: Some(PathBuf::from("/etc/picoguard/allow.txt")),
                ..ListConfig::default()
            }],
            ..Config::default()
        };
        let settings = Settings {
            lists: Some(vec![
                page_list(ListRole::Allow, "https://page.example/allow.txt"),
                page_list(ListRole::Block, "https://file.example/hosts.txt"),
                PageList {
                    enabled: false,
                    ..page_list(ListRole::Block, "https://page.example/new.txt")
                },
            ]),
            ..Settings::default()
        };

        let config = merged(&file, &settings).unwrap();

        let sources: Vec<_> = config
            .lists
            .iter()
            .map(|list| (list.url.as_deref(), list.path.as_deref()))
            .collect();
        assert_eq!(
            sources,
            [
                (None, Some(Path::new("/etc/picoguard/mine.txt"))),
                (Some("https://file.example/hosts.txt"), None),
                (Some("https://page.example/new.txt"), None),
            ]
        );

        let inherited = &config.lists[1];
        assert_eq!(
            inherited.name.as_deref(),
            Some("page https://file.example/hosts.txt")
        );
        assert_eq!(inherited.refresh_hours, 6);
        assert_eq!(inherited.format, ListFormat::Hosts);
        assert_eq!(inherited.max_rules, 1000);
        assert_eq!(inherited.max_body_bytes, 4096);
        assert_eq!(inherited.slow_rule_budget, 2048);
        assert!(inherited.allow_redirects);

        let new = &config.lists[2];
        assert!(!new.enabled);
        assert_eq!(
            ListConfig {
                name: None,
                url: None,
                refresh_hours: 24,
                enabled: true,
                ..new.clone()
            },
            ListConfig::default()
        );

        assert_eq!(config.allowlists.len(), 2);
        assert_eq!(config.allowlists[0], file.allowlists[0]);
        assert_eq!(
            config.allowlists[1].url.as_deref(),
            Some("https://page.example/allow.txt")
        );
    }

    #[test]
    fn copying_the_file_lists_to_the_page_changes_nothing() {
        let mut file = Config::default();
        file.lists[1].format = ListFormat::Domains;
        file.lists[1].max_rules = 5000;
        file.lists[2].refresh_hours = 12;
        file.lists[2].enabled = false;
        file.allowlists = vec![ListConfig {
            name: Some("ok".to_string()),
            url: Some("https://file.example/ok.txt".to_string()),
            allow_redirects: true,
            ..ListConfig::default()
        }];
        fn copy(lists: &[ListConfig], role: ListRole) -> impl Iterator<Item = PageList> + '_ {
            lists.iter().map(move |list| PageList {
                role,
                name: list.name.clone(),
                url: list.url.clone().unwrap(),
                refresh_hours: list.refresh_hours,
                enabled: list.enabled,
            })
        }

        let settings = Settings {
            lists: Some(
                copy(&file.lists, ListRole::Block)
                    .chain(copy(&file.allowlists, ListRole::Allow))
                    .collect(),
            ),
            ..Settings::default()
        };

        assert_eq!(merged(&file, &settings).unwrap(), file);
    }

    #[test]
    fn without_the_lists_key_the_file_lists_are_back() {
        let mut settings = Settings {
            lists: Some(vec![page_list(
                ListRole::Block,
                "https://page.example/a.txt",
            )]),
            ..Settings::default()
        };
        assert_ne!(
            merged(&Config::default(), &settings).unwrap().lists,
            Config::default().lists
        );

        settings.lists = None;

        assert_eq!(
            merged(&Config::default(), &settings).unwrap(),
            Config::default()
        );
    }

    #[test]
    fn settings_outside_the_page_limits_are_refused_with_a_reason() {
        let upstream = |servers: usize, bootstrap: usize| UpstreamSettings {
            servers: vec!["https://1.1.1.1/dns-query".to_string(); servers],
            bootstrap: vec!["9.9.9.9".parse().unwrap(); bootstrap],
        };
        let cache = |max_bytes| CacheSettings {
            max_entries: 100,
            max_bytes,
            min_ttl: 0,
            max_ttl: 60,
            optimistic: true,
        };
        let lists = |role, count: usize| {
            (0..count)
                .map(|index| page_list(role, &format!("https://page.example/{index}.txt")))
                .collect()
        };
        let cases = [
            (
                Settings {
                    version: 2,
                    ..Settings::default()
                },
                "version 2 is unknown",
            ),
            (
                Settings {
                    upstream: Some(upstream(0, 0)),
                    ..Settings::default()
                },
                "upstream.servers: 1 to 8 servers",
            ),
            (
                Settings {
                    upstream: Some(upstream(9, 0)),
                    ..Settings::default()
                },
                "upstream.servers: 1 to 8 servers",
            ),
            (
                Settings {
                    upstream: Some(upstream(1, 5)),
                    ..Settings::default()
                },
                "upstream.bootstrap: at most 4 addresses",
            ),
            (
                Settings {
                    upstream: Some(UpstreamSettings {
                        servers: vec!["1.1.1.1".to_string()],
                        bootstrap: Vec::new(),
                    }),
                    ..Settings::default()
                },
                "upstream.servers[0] must start with one of",
            ),
            (
                Settings {
                    cache: Some(cache(256 * 1024 - 1)),
                    ..Settings::default()
                },
                "cache.max_bytes must be from 262144 to 16777216",
            ),
            (
                Settings {
                    cache: Some(cache(16 * 1024 * 1024 + 1)),
                    ..Settings::default()
                },
                "cache.max_bytes must be from 262144 to 16777216",
            ),
            (
                Settings {
                    cache: Some(CacheSettings {
                        min_ttl: 100,
                        ..cache(1024 * 1024)
                    }),
                    ..Settings::default()
                },
                "cache.min_ttl must be <= cache.max_ttl",
            ),
            (
                Settings {
                    lists: Some(lists(ListRole::Block, 33)),
                    ..Settings::default()
                },
                "lists: at most 32 block lists",
            ),
            (
                Settings {
                    lists: Some(lists(ListRole::Allow, 17)),
                    ..Settings::default()
                },
                "lists: at most 16 allowlists",
            ),
            (
                Settings {
                    lists: Some(vec![PageList {
                        refresh_hours: 169,
                        ..page_list(ListRole::Block, "https://page.example/a.txt")
                    }]),
                    ..Settings::default()
                },
                "lists[0].refresh_hours must be from 1 to 168",
            ),
            (
                Settings {
                    lists: Some(vec![PageList {
                        refresh_hours: 0,
                        ..page_list(ListRole::Block, "https://page.example/a.txt")
                    }]),
                    ..Settings::default()
                },
                "lists[0].refresh_hours must be from 1 to 168",
            ),
            (
                Settings {
                    lists: Some(vec![page_list(ListRole::Block, "ftp://page.example/a")]),
                    ..Settings::default()
                },
                "lists[0].url must start with http:// or https://",
            ),
            (
                Settings {
                    lists: Some(vec![
                        page_list(ListRole::Block, "https://page.example/a.txt"),
                        page_list(ListRole::Block, "https://page.example/a.txt"),
                    ]),
                    ..Settings::default()
                },
                "lists[1] has the same source as lists[0]",
            ),
            (
                Settings {
                    page_rules: vec![rule("Ads.example", Action::Block)],
                    ..Settings::default()
                },
                "page_rules[0].name is not a domain name",
            ),
            (
                Settings {
                    page_rules: vec![rule("*.ads.example", Action::Block)],
                    ..Settings::default()
                },
                "page_rules[0].name is not a domain name",
            ),
            (
                Settings {
                    page_rules: vec![
                        rule("ads.example", Action::Block),
                        rule("ads.example", Action::Allow),
                    ],
                    ..Settings::default()
                },
                "page_rules[1] is listed twice",
            ),
            (
                Settings {
                    page_rules: (0..501)
                        .map(|index| rule(&format!("r{index}.example"), Action::Block))
                        .collect(),
                    ..Settings::default()
                },
                "page_rules: at most 500 rules",
            ),
            (
                Settings {
                    rewrites: Some(vec![Rewrite {
                        name: "nas.lan".to_string(),
                        answer: "nas.lan".to_string(),
                    }]),
                    ..Settings::default()
                },
                "rewrites[0] points nas.lan at itself",
            ),
            (
                Settings {
                    services: Some(vec!["a b".to_string()]),
                    ..Settings::default()
                },
                "services.block[0] must be 1 to 64 visible characters",
            ),
        ];

        for (settings, expected) in cases {
            let message = reason(&settings);

            assert!(
                message.contains(expected),
                "{settings:?}: expected {expected:?}, got {message:?}"
            );
        }
    }

    #[test]
    fn the_file_round_trips_and_leaves_out_what_is_not_set() {
        let settings = Settings {
            safe_search: Some(false),
            page_rules: vec![rule("ads.example", Action::Block)],
            ..Settings::default()
        };

        let bytes = encode(&settings).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();

        assert_eq!(
            serde_json::from_slice::<Settings>(&bytes).unwrap(),
            settings
        );
        assert!(text.contains("\n  \"version\": 1,\n"), "{text}");
        for absent in ["upstream", "cache", "lists", "rewrites", "services"] {
            assert!(!text.contains(absent), "{absent}: {text}");
        }

        assert_eq!(bytes.capacity(), bytes.len());
    }

    #[test]
    fn unknown_keys_and_a_missing_version_make_the_file_unusable() {
        for (text, expected) in [
            ("{\"version\": 1, \"web\": {}}", "unknown field `web`"),
            (
                "{\"version\": 1, \"upstream\": {\"servers\": [], \"bootstrap\": [], \"timeout_ms\": 1}}",
                "unknown field `timeout_ms`",
            ),
            (
                "{\"version\": 1, \"page_rules\": [{\"name\": \"a.example\", \"action\": \"block\", \"x\": 1}]}",
                "unknown field `x`",
            ),
            ("{\"safe_search\": true}", "missing field `version`"),
        ] {
            let message = serde_json::from_str::<Settings>(text)
                .unwrap_err()
                .to_string();

            assert!(message.contains(expected), "{text}: {message}");
        }
    }

    #[test]
    fn no_file_is_no_settings() {
        let dir = TestDir::new("settings-none");

        assert_eq!(read(&dir.path().join(FILE_NAME)), Ok(None));
        assert_eq!(read(&dir.path().join("missing").join(FILE_NAME)), Ok(None));
    }

    #[test]
    fn a_link_a_pipe_a_folder_or_a_file_too_large_is_refused() {
        let dir = TestDir::new("settings-hostile");
        let good = dir.path().join("good.json");
        fs::write(&good, "{\"version\": 1}").unwrap();
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&good, &link).unwrap();
        let pipe = dir.path().join("pipe.json");
        let pipe_name = CString::new(pipe.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(pipe_name.as_ptr(), 0o600) }, 0);
        let folder = dir.path().join("folder.json");
        fs::create_dir(&folder).unwrap();
        let large = dir.path().join("large.json");
        let padding = " ".repeat(MAX_FILE_BYTES);
        fs::write(&large, format!("{{\"version\": 1}}{padding}")).unwrap();

        assert_eq!(read(&good), Ok(Some(Settings::default())));
        for path in [link, pipe, folder, large] {
            let refused = read(&path);

            assert!(
                refused
                    .as_ref()
                    .is_err_and(|reason| reason.starts_with("cannot read it: ")),
                "{path:?}: {refused:?}"
            );
        }
    }

    #[test]
    fn a_file_of_the_largest_size_is_read() {
        let dir = TestDir::new("settings-largest");
        let path = dir.path().join(FILE_NAME);
        let text = "{\"version\": 1}";
        fs::write(
            &path,
            format!("{text}{}", " ".repeat(MAX_FILE_BYTES - text.len())),
        )
        .unwrap();

        assert_eq!(read(&path), Ok(Some(Settings::default())));
    }

    #[test]
    fn the_config_file_alone_is_used_when_the_saved_file_cannot_be() {
        let dir = TestDir::new("settings-start");
        let file = config_in(dir.path());
        let path = dir.path().join(FILE_NAME);

        let none = with_saved(file.clone());
        assert_eq!(none.config, file);
        assert_eq!(none.saved.error(), None);

        fs::write(
            &path,
            "{\"version\": 1, \"safe_search\": true, \"page_rules\": [{\"name\": \"ads.example\", \"action\": \"block\"}]}",
        )
        .unwrap();
        let good = with_saved(file.clone());
        assert!(good.config.safe_search);
        assert_eq!(good.saved.error(), None);

        for (text, expected) in [
            ("{\"version\": 1", "EOF while parsing"),
            ("[1]", "not a JSON object"),
            (
                "{\"version\": 1, \"upstream\": {\"servers\": [\"x\"], \"bootstrap\": []}}",
                "upstream.servers[0] must start with one of",
            ),
        ] {
            fs::write(&path, text).unwrap();

            let bad = with_saved(file.clone());

            assert_eq!(bad.config, file, "{text}");
            let error = bad.saved.error().unwrap_or_default();
            assert!(error.contains(expected), "{text}: {error}");
        }
    }

    async fn page_rules_of(saved: &Saved) -> Vec<ButtonRule> {
        saved.lock().await.page_rules.clone()
    }

    #[tokio::test]
    async fn a_save_writes_the_whole_file_for_the_owner_only_and_leaves_no_part() {
        let dir = TestDir::new("settings-save");
        let mut file = config_in(dir.path());
        file.web.user = Some("admin".to_string());
        file.web.password = Some("s3cret-password".to_string());
        let saved = Saved::new(file.clone(), Settings::default(), Some("bad".to_string()));
        fs::write(dir.path().join(PART_NAME), "stale").unwrap();
        let settings = Settings {
            page_rules: vec![rule("ads.example", Action::Block)],
            ..Settings::default()
        };

        saved.save(&settings).await.unwrap();

        let path = dir.path().join(FILE_NAME);
        assert_eq!(read(&path), Ok(Some(settings.clone())));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!dir.path().join(PART_NAME).exists());
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains("s3cret") && !text.contains("admin"),
            "{text}"
        );
        assert_eq!(saved.error(), None);
        assert!(saved.can_save());
        assert!(
            page_rules_of(&saved).await.is_empty(),
            "save publishes nothing"
        );

        let replaced = Settings::default();
        saved.save(&replaced).await.unwrap();
        assert_eq!(read(&path), Ok(Some(replaced)));
    }

    #[tokio::test]
    async fn a_failed_save_says_why_and_writes_nothing() {
        let dir = TestDir::new("settings-fail");
        let missing = dir.path().join("missing");
        let saved = Saved::new(config_in(&missing), Settings::default(), None);

        let error = saved.save(&Settings::default()).await.unwrap_err();

        assert!(
            error.to_string().starts_with("could not save settings: "),
            "{error}"
        );
        assert!(!saved.can_save());
        assert!(!missing.exists());

        fs::create_dir(&missing).unwrap();
        saved.save(&Settings::default()).await.unwrap();
        assert!(saved.can_save());
    }

    #[tokio::test]
    async fn settings_over_the_size_cap_are_refused_before_writing() {
        let dir = TestDir::new("settings-large");
        let saved = Saved::new(config_in(dir.path()), Settings::default(), None);
        let long_label = "a".repeat(60);
        let settings = Settings {
            page_rules: (0..3000)
                .map(|index| rule(&format!("{long_label}.{index}.example"), Action::Block))
                .collect(),
            ..Settings::default()
        };

        assert_eq!(saved.save(&settings).await, Err(SaveError::TooLarge));
        assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
    }
}
