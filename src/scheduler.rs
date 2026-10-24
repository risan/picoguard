//! The list scheduler (plan S4.3). At boot every configured list is loaded from its snapshot
//! and the first engine is assembled from them. Afterwards one task refreshes the lists, one
//! at a time, each on its own interval. A refresh that changes a list compiles it on the
//! worker, assembles the next engine there, swaps it into the policy and waits for the
//! snapshot to be written before the next refresh starts, so at most the current and one
//! new copy are in memory (D13). Any failure keeps the copy in force.

use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::config::{Config, ListConfig};
use crate::filter::compile::{CompileOptions, CompileWorker};
use crate::filter::engine::CompiledList;
use crate::filter::parse::ListFormat;
use crate::filter::snapshot::{Snapshot, SnapshotStore};
use crate::lists::{Downloader, Limits, Refresh, RefreshError, Updated, Validators, refresh_file};
use crate::policy::Policy;
use crate::upstream::random_u64;

/// How far an interval is moved, up or down, so lists do not refresh in step.
const INTERVAL_JITTER: f64 = 0.1;

/// The clock of the scheduler. Tests shrink it.
#[derive(Debug, Clone)]
pub struct Timing {
    /// What `refresh_hours = 1` lasts.
    pub hour: Duration,
    /// Waits after the first, second, third and every later failure in a row.
    pub retries: [Duration; 4],
    /// A list that booted from a snapshot is checked once within this time after the start.
    pub first_check: Duration,
}

impl Default for Timing {
    fn default() -> Timing {
        Timing {
            hour: Duration::from_secs(3600),
            retries: [
                Duration::from_secs(60),
                Duration::from_secs(300),
                Duration::from_secs(900),
                Duration::from_secs(3600),
            ],
            first_check: Duration::from_secs(60),
        }
    }
}

impl Timing {
    fn retry_after(&self, failures: u32) -> Duration {
        let step = (failures.max(1) as usize - 1).min(self.retries.len() - 1);

        self.retries[step]
    }
}

enum Work {
    Refresh,
    Save,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Blocklist,
    Allowlist,
}

/// What is known about one list, for the status page.
#[derive(Debug, Clone)]
pub struct ListStatus {
    pub name: String,
    pub role: Role,
    /// The format the copy in force was read as (`auto` resolved); `None` before any copy.
    pub format: Option<ListFormat>,
    pub rules: usize,
    /// When the copy in force was loaded, downloaded or confirmed current. A snapshot read at
    /// boot counts from the boot: it records no download time.
    pub checked: Option<Instant>,
    /// Why the last refresh failed; cleared by the next one that works.
    pub last_error: Option<String>,
}

/// The scheduler seen from outside: what the lists look like, and a way to ask for a refresh.
#[derive(Default)]
pub struct ListControl {
    statuses: Mutex<Vec<ListStatus>>,
    refresh_requested: Notify,
}

impl ListControl {
    /// Blocklists first, then allowlists, in config order.
    pub fn statuses(&self) -> Vec<ListStatus> {
        self.statuses.lock().unwrap().clone()
    }

    /// Asks for every list to be refreshed now. The scheduler still does one refresh at a time,
    /// and asks made while it is busy count as one.
    pub fn refresh_all(&self) {
        self.refresh_requested.notify_one();
    }
}

enum Source {
    Url(String),
    Path(PathBuf),
}

/// A snapshot the writer could not put on disk. The list in force is fine; only its copy on
/// disk is behind, so it is written again, with growing waits, until that works.
struct PendingSave {
    snapshot: Snapshot,
    /// Writes that failed in a row.
    failures: u32,
    retry_at: Instant,
}

/// The copy of a list that is in force.
struct Loaded {
    list: Arc<CompiledList>,
    format: ListFormat,
    fingerprint: u128,
    validators: Validators,
}

struct Entry {
    label: String,
    role: Role,
    source: Source,
    /// The URL or path as written; names the snapshot file.
    key: String,
    options: CompileOptions,
    interval: Duration,
    max_body_bytes: u64,
    loaded: Option<Loaded>,
    /// What is in force but not yet on disk. A snapshot that was loaded from disk, or written
    /// without error, is persisted whatever the next check finds; the fingerprint of
    /// `loaded` says nothing about the disk.
    pending_save: Option<PendingSave>,
    due: Instant,
    /// Refreshes that failed in a row.
    failures: u32,
    checked: Option<Instant>,
    last_error: Option<String>,
}

pub struct Scheduler {
    policy: Arc<Policy>,
    control: Arc<ListControl>,
    worker: CompileWorker,
    store: Arc<SnapshotStore>,
    timing: Timing,
    user_rules: Option<Arc<CompiledList>>,
    entries: Vec<Entry>,
}

impl Scheduler {
    /// Loads what can be loaded without the network and puts the first engine in force.
    /// A list without a usable snapshot starts empty and is refreshed first.
    pub async fn boot(
        config: &Config,
        worker: CompileWorker,
        store: Arc<SnapshotStore>,
        timing: Timing,
    ) -> Result<Scheduler, String> {
        let user_rules = compile_user_rules(&config.rules, &worker).await?;
        let blocklists = config.lists.iter().map(|list| (Role::Blocklist, list));
        let allowlists = config.allowlists.iter().map(|list| (Role::Allowlist, list));
        let entries = blocklists
            .chain(allowlists)
            .filter_map(|(role, list)| Entry::new(role, list, &timing))
            .collect();

        let mut scheduler = Scheduler {
            policy: Arc::new(Policy::new()),
            control: Arc::new(ListControl::default()),
            worker,
            store,
            timing,
            user_rules,
            entries,
        };

        for index in 0..scheduler.entries.len() {
            scheduler.load_at_boot(index).await;
        }

        scheduler.publish_all();

        let (main, allow) = scheduler.lists_in_force(None);
        let engine = scheduler
            .worker
            .assemble(main, allow)
            .await
            .map_err(|error| format!("cannot build the filter: {error:?}"))?;
        scheduler.policy = Arc::new(Policy::with_engine(Arc::new(engine)));

        Ok(scheduler)
    }

    /// The policy the pipeline filters with; every swap goes through it.
    pub fn policy(&self) -> Arc<Policy> {
        Arc::clone(&self.policy)
    }

    pub fn control(&self) -> Arc<ListControl> {
        Arc::clone(&self.control)
    }

    /// The copy of the list at `index` (counting blocklists, then allowlists, in config order)
    /// that is in force, if it has one.
    pub fn list(&self, index: usize) -> Option<&Arc<CompiledList>> {
        self.entries
            .get(index)?
            .loaded
            .as_ref()
            .map(|loaded| &loaded.list)
    }

    /// Refreshes whichever list is due next and writes snapshots that failed to write, until
    /// `stop` is ready. Never two at once. Work already started is finished; nothing new
    /// starts after `stop`, except one last try to write the snapshots still pending.
    pub async fn run(mut self, downloader: Downloader, stop: impl Future<Output = ()>) {
        tokio::pin!(stop);
        let control = self.control();

        while let Some((index, work, at)) = self.next_work() {
            tokio::select! {
                biased;

                () = &mut stop => {
                    break;
                }

                () = control.refresh_requested.notified() => {
                    self.refresh_all_now();

                    continue;
                }

                () = tokio::time::sleep_until(at) => {}
            }

            match work {
                Work::Refresh => {
                    self.refresh(index, &downloader).await;
                }

                Work::Save => {
                    self.retry_save(index).await;
                }
            }
        }

        for index in 0..self.entries.len() {
            self.retry_save(index).await;
        }
    }

    fn publish_all(&self) {
        let statuses = self.entries.iter().map(Entry::status).collect();
        *self.control.statuses.lock().unwrap() = statuses;
    }

    fn publish(&self, index: usize) {
        self.control.statuses.lock().unwrap()[index] = self.entries[index].status();
    }

    /// Makes every list due. A list that is due already keeps its earlier time, so lists that
    /// wait for their turn go before the ones just refreshed, however often this is asked.
    fn refresh_all_now(&mut self) {
        let now = Instant::now();

        for entry in &mut self.entries {
            entry.due = entry.due.min(now);
        }
    }

    fn next_work(&self) -> Option<(usize, Work, Instant)> {
        let refreshes = self
            .entries
            .iter()
            .enumerate()
            .map(|(index, entry)| (index, Work::Refresh, entry.due));
        let saves = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let pending = entry.pending_save.as_ref()?;

                Some((index, Work::Save, pending.retry_at))
            });

        refreshes.chain(saves).min_by_key(|(_, _, at)| *at)
    }

    /// Refreshes the list at `index` now. The list in force stays in force unless a new copy
    /// was compiled, assembled into an engine and swapped in.
    pub async fn refresh(&mut self, index: usize, downloader: &Downloader) {
        let outcome = match self.fetch(index, downloader).await {
            Ok(Refresh::NotModified) => {
                log::info!("{}: not modified", self.entries[index].label);

                Ok(())
            }

            Ok(Refresh::Updated(updated)) => self.install(index, updated).await,
            Err(error) => Err(error.to_string()),
        };
        let entry = &mut self.entries[index];

        match outcome {
            Ok(()) => {
                if entry.failures > 0 {
                    log::info!("{}: refreshed again", entry.label);
                }

                entry.failures = 0;
                entry.due = Instant::now() + jittered(entry.interval);
                entry.checked = Some(Instant::now());
                entry.last_error = None;
            }

            Err(message) => {
                if entry.failures == 0 {
                    log::warn!(
                        "{}: refresh failed, keeping the current copy: {message}",
                        entry.label
                    );
                } else {
                    log::debug!("{}: refresh failed again: {message}", entry.label);
                }

                entry.failures += 1;
                entry.due = Instant::now() + self.timing.retry_after(entry.failures);
                entry.last_error = Some(message);
            }
        }

        self.publish(index);
    }

    async fn fetch(&self, index: usize, downloader: &Downloader) -> Result<Refresh, RefreshError> {
        let entry = &self.entries[index];

        match &entry.source {
            Source::Url(url) => {
                let previous = entry
                    .loaded
                    .as_ref()
                    .map(|loaded| loaded.validators.clone())
                    .unwrap_or_default();
                let limits = Limits {
                    max_body_bytes: entry.max_body_bytes,
                    ..Limits::default()
                };

                downloader
                    .refresh(&self.worker, url, &previous, &limits, entry.options)
                    .await
            }

            Source::Path(path) => {
                let compiled = refresh_file(
                    &self.worker,
                    path.clone(),
                    entry.max_body_bytes,
                    entry.options,
                )
                .await?;

                Ok(Refresh::Updated(Box::new(Updated {
                    compiled,
                    validators: Validators::default(),
                })))
            }
        }
    }

    /// Puts a freshly compiled copy in force, unless it changes nothing or looks broken.
    async fn install(&mut self, index: usize, updated: Box<Updated>) -> Result<(), String> {
        let entry = &mut self.entries[index];
        let rules_in_force = entry.loaded.as_ref().map(|loaded| loaded.list.rule_count());

        if let Some(loaded) = &mut entry.loaded
            && loaded.fingerprint == updated.compiled.fingerprint
        {
            log::info!("{}: downloaded again, same content", entry.label);
            loaded.validators = updated.validators.clone();
            self.worker.discard(updated);

            return Ok(());
        }

        if updated.compiled.list.rule_count() == 0 && rules_in_force.is_some_and(|count| count > 0)
        {
            self.worker.discard(updated);

            return Err("the new copy has no rules".to_string());
        }

        let Updated {
            compiled,
            validators,
        } = *updated;
        let new_list = Arc::clone(&compiled.list);
        let (main, allow) = self.lists_in_force(Some((index, Arc::clone(&new_list))));
        let engine = match self.worker.assemble(main, allow).await {
            Ok(engine) => engine,

            Err(error) => {
                self.worker.discard(compiled);

                return Err(format!("cannot build the filter: {error:?}"));
            }
        };

        let old_engine = self.policy.swap_engine(Arc::new(engine));
        self.worker.discard(old_engine);

        let entry = &mut self.entries[index];
        log::info!(
            "{}: {} rules ({} slow)",
            entry.label,
            new_list.rule_count(),
            new_list.slow_rule_count()
        );

        let snapshot = Snapshot::new(&compiled, &entry.options, &entry.key, validators.clone());
        let replaced = entry.loaded.replace(Loaded {
            list: new_list,
            format: compiled.summary.format,
            fingerprint: compiled.fingerprint,
            validators,
        });
        let outdated = entry.pending_save.take();
        self.worker.discard((replaced, outdated));

        if matches!(entry.source, Source::Url(_)) {
            self.save(index, snapshot, 0).await;
        }

        Ok(())
    }

    /// Writes `snapshot`; if that fails the entry keeps it to write again later.
    /// `failures` is how many writes of it failed before this one.
    async fn save(&mut self, index: usize, snapshot: Snapshot, failures: u32) {
        let result = self.store.save(snapshot.clone()).await;
        let entry = &mut self.entries[index];

        match result {
            Ok(()) if failures > 0 => {
                log::info!("{}: the snapshot is written now", entry.label);
            }

            Ok(()) => {}

            Err(error) => {
                if failures == 0 {
                    log::warn!(
                        "{}: cannot write the snapshot, will try again: {error}",
                        entry.label
                    );
                } else {
                    log::debug!("{}: cannot write the snapshot again: {error}", entry.label);
                }

                let failures = failures + 1;
                entry.pending_save = Some(PendingSave {
                    snapshot,
                    failures,
                    retry_at: Instant::now() + self.timing.retry_after(failures),
                });
            }
        }
    }

    /// Writes the snapshot of the list at `index` again if an earlier write failed. A check
    /// that finds the list unchanged never writes; this is the only way a failed write is
    /// tried again.
    pub async fn retry_save(&mut self, index: usize) {
        let Some(pending) = self.entries[index].pending_save.take() else {
            return;
        };

        self.save(index, pending.snapshot, pending.failures).await;
    }

    /// The lists for the next engine: the user rules first, then every list in force in
    /// config order, with `replacing` standing in for the list at its index.
    fn lists_in_force(
        &self,
        replacing: Option<(usize, Arc<CompiledList>)>,
    ) -> (Vec<Arc<CompiledList>>, Vec<Arc<CompiledList>>) {
        let mut main: Vec<Arc<CompiledList>> = self.user_rules.iter().cloned().collect();
        let mut allow = Vec::new();

        for (index, entry) in self.entries.iter().enumerate() {
            let list = match &replacing {
                Some((replaced, list)) if *replaced == index => Some(Arc::clone(list)),
                _ => entry.loaded.as_ref().map(|loaded| Arc::clone(&loaded.list)),
            };
            let Some(list) = list else {
                continue;
            };

            match entry.role {
                Role::Blocklist => main.push(list),
                Role::Allowlist => allow.push(list),
            }
        }

        (main, allow)
    }

    async fn load_at_boot(&mut self, index: usize) {
        let entry = &self.entries[index];
        let loaded = match &entry.source {
            Source::Url(_) => self.load_snapshot(entry).await,
            Source::Path(path) => self.compile_file(entry, path.clone()).await,
        };
        let entry = &mut self.entries[index];

        entry.due = match loaded {
            Some(loaded) => {
                entry.loaded = Some(loaded);
                entry.checked = Some(Instant::now());

                // Compiled from the file or loaded from a snapshot: the first check can wait.
                Instant::now() + self.timing.first_check.mul_f64(unit_random())
            }

            None if matches!(entry.source, Source::Path(_)) => {
                entry.failures = 1;

                Instant::now() + self.timing.retry_after(1)
            }

            None => Instant::now(),
        };
    }

    async fn load_snapshot(&self, entry: &Entry) -> Option<Loaded> {
        let path = self.store.path_for(&entry.key)?;
        let snapshot = match self.worker.load(path, entry.options).await {
            Ok(snapshot) => snapshot,

            Err(crate::filter::snapshot::SnapshotError::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound =>
            {
                return None;
            }

            Err(error) => {
                log::warn!("{}: ignoring the snapshot: {error}", entry.label);

                return None;
            }
        };

        if !snapshot.fits(&entry.key, &entry.options) {
            log::info!(
                "{}: the snapshot was made for another format or limit, downloading again",
                entry.label
            );
            self.worker.discard(snapshot);

            return None;
        }

        log::info!(
            "{}: {} rules from the snapshot",
            entry.label,
            snapshot.list.rule_count()
        );

        Some(Loaded {
            list: Arc::clone(&snapshot.list),
            format: snapshot.meta.effective_format,
            fingerprint: snapshot.meta.fingerprint,
            validators: snapshot.meta.validators.clone(),
        })
    }

    async fn compile_file(&self, entry: &Entry, path: PathBuf) -> Option<Loaded> {
        match refresh_file(&self.worker, path, entry.max_body_bytes, entry.options).await {
            Ok(compiled) => {
                log::info!("{}: {} rules", entry.label, compiled.list.rule_count());

                Some(Loaded {
                    format: compiled.summary.format,
                    fingerprint: compiled.fingerprint,
                    list: compiled.list,
                    validators: Validators::default(),
                })
            }

            Err(error) => {
                log::warn!("{}: cannot read the list: {error}", entry.label);

                None
            }
        }
    }
}

impl Entry {
    fn status(&self) -> ListStatus {
        ListStatus {
            name: self.label.clone(),
            role: self.role,
            format: self.loaded.as_ref().map(|loaded| loaded.format),
            rules: self
                .loaded
                .as_ref()
                .map_or(0, |loaded| loaded.list.rule_count()),
            checked: self.checked,
            last_error: self.last_error.clone(),
        }
    }

    fn new(role: Role, list: &ListConfig, timing: &Timing) -> Option<Entry> {
        let (source, key) = match (&list.url, &list.path) {
            (Some(url), _) => (Source::Url(url.clone()), url.clone()),
            (None, Some(path)) => (Source::Path(path.clone()), path.display().to_string()),
            (None, None) => return None,
        };
        let label = match &list.name {
            Some(name) => name.clone(),
            None => key.clone(),
        };

        Some(Entry {
            label,
            role,
            source,
            key,
            options: CompileOptions {
                slow_rule_budget: list.slow_rule_budget,
                ..CompileOptions::new(list.format, list.max_rules)
            },
            interval: timing.hour * list.refresh_hours,
            max_body_bytes: list.max_body_bytes,
            loaded: None,
            pending_save: None,
            due: Instant::now(),
            failures: 0,
            checked: None,
            last_error: None,
        })
    }
}

/// The user's `rules`, one list in the AdGuard grammar; the first list of the main engine.
async fn compile_user_rules(
    rules: &[String],
    worker: &CompileWorker,
) -> Result<Option<Arc<CompiledList>>, String> {
    if rules.is_empty() {
        return Ok(None);
    }

    let text = rules.join("\n");
    let list = worker
        .run(move || CompiledList::from_text(ListFormat::Adblock, &text).0)
        .await
        .map_err(|error| format!("cannot compile rules: {error:?}"))?;
    log::info!("user rules: {} rules", list.rule_count());

    Ok(Some(Arc::new(list)))
}

fn unit_random() -> f64 {
    (random_u64() >> 11) as f64 / (1u64 << 53) as f64
}

/// `interval` moved by up to `INTERVAL_JITTER` either way.
fn jittered(interval: Duration) -> Duration {
    interval.mul_f64(1.0 - INTERVAL_JITTER + 2.0 * INTERVAL_JITTER * unit_random())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_wait_longer_up_to_an_hour() {
        let timing = Timing::default();

        let waits: Vec<u64> = (1..=6)
            .map(|failures| timing.retry_after(failures).as_secs())
            .collect();

        assert_eq!(waits, [60, 300, 900, 3600, 3600, 3600]);
    }

    #[test]
    fn an_interval_moves_by_ten_percent_at_most() {
        let day = Duration::from_secs(24 * 3600);

        let waits: Vec<Duration> = (0..2000).map(|_| jittered(day)).collect();

        assert!(
            waits
                .iter()
                .all(|wait| { *wait >= day.mul_f64(0.9) && *wait <= day.mul_f64(1.1) })
        );
        assert!(waits.iter().any(|wait| *wait < day.mul_f64(0.95)));
        assert!(waits.iter().any(|wait| *wait > day.mul_f64(1.05)));
    }
}
