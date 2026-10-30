//! The list scheduler (plan S4.3). At boot every configured list is loaded from its snapshot
//! and the first engine is assembled from them. Afterwards one task refreshes the lists, one
//! at a time, each on its own interval. A refresh that changes a list compiles it on the
//! worker, assembles the next engine there, swaps it into the policy and waits for the
//! snapshot to be written before the next refresh starts, so at most the current and one
//! new copy are in memory (D13). Any failure keeps the copy in force.
//!
//! The rules added from the status page live in [`ListControl`], in memory only. A change
//! rebuilds only those rules and keeps the engine's list rule sets. Every swap after boot, a
//! refresh's or a rule change's, holds one lock there, so each builds on the other's latest
//! result.

use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, Semaphore, oneshot};
use tokio::time::Instant;

use crate::config::{Config, ListConfig};
use crate::filter::compile::{CompileError, CompileOptions, CompileWorker};
use crate::filter::engine::{CompiledList, Engine, ListBuilder, Side};
use crate::filter::parse::{FastKind, ListFormat, Rule};
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

/// The most rules the status page may add.
pub const MAX_BUTTON_RULES: usize = 500;

/// The most rule changes that may wait or run at once. A change runs as a task of its own, so
/// a client that goes away does not cancel it; this bounds those tasks whatever the request
/// rate.
pub const MAX_PENDING_CHANGES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Block,
    Allow,
}

/// A rule added from the status page: the name and its subdomains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ButtonRule {
    pub name: String,
    pub action: Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleError {
    NotADomainName,
    TooMany,
    NoSuchRule,
    /// The task that applies the change ended without an answer.
    NotApplied,
}

/// The rule that decides a name, and the list that holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explained {
    pub allowed: bool,
    /// The list's name on the status page, `your rules` or `config rules`.
    pub list: String,
    pub rule: String,
}

/// Where a list of the engine comes from, so explain can name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListId {
    ConfigRules,
    /// The entry at this index: blocklists, then allowlists, as in `statuses`.
    Configured(usize),
}

/// A list for the engine and where it comes from.
type InForce = (ListId, Arc<CompiledList>);

/// What every swap after boot reads and writes under one lock.
#[derive(Default)]
struct Assembly {
    /// The list of each engine position, as the scheduler last put the lists in force.
    main_ids: Vec<ListId>,
    allow_ids: Vec<ListId>,
    /// In the order first added.
    rules: Vec<ButtonRule>,
    /// The page lists in force; `None` for a side without rules.
    block: Option<Arc<CompiledList>>,
    allow: Option<Arc<CompiledList>>,
}

enum Edit {
    Add(String, Action),
    Remove(String),
}

impl Assembly {
    /// The rules after `edit`, or `None` when it changes nothing.
    fn edited(&self, edit: &Edit) -> Result<Option<Vec<ButtonRule>>, RuleError> {
        match edit {
            Edit::Add(name, action) => {
                match self.rules.iter().position(|rule| rule.name == *name) {
                    Some(at) if self.rules[at].action == *action => Ok(None),

                    Some(at) => {
                        let mut rules = self.rules.clone();
                        rules[at].action = *action;

                        Ok(Some(rules))
                    }

                    None if self.rules.len() >= MAX_BUTTON_RULES => Err(RuleError::TooMany),

                    None => {
                        let mut rules = Vec::with_capacity(self.rules.len() + 1);
                        rules.extend_from_slice(&self.rules);
                        rules.push(ButtonRule {
                            name: name.clone(),
                            action: *action,
                        });

                        Ok(Some(rules))
                    }
                }
            }

            Edit::Remove(name) => {
                let at = self
                    .rules
                    .iter()
                    .position(|rule| rule.name == *name)
                    .ok_or(RuleError::NoSuchRule)?;
                let mut rules = self.rules.clone();
                rules.remove(at);

                Ok(Some(rules))
            }
        }
    }

    fn page_lists(&self) -> (Vec<Arc<CompiledList>>, Vec<Arc<CompiledList>>) {
        (
            self.block.iter().cloned().collect(),
            self.allow.iter().cloned().collect(),
        )
    }
}

/// The scheduler seen from outside: what the lists look like, a way to ask for a refresh, and
/// the rules added from the status page, which it also puts in force.
pub struct ListControl {
    statuses: Mutex<Vec<ListStatus>>,
    refresh_requested: Notify,
    policy: Arc<Policy>,
    assembly: tokio::sync::Mutex<Assembly>,
    pending: Arc<Semaphore>,
}

impl ListControl {
    /// A control without lists or rules, swapping engines into `policy`.
    pub fn new(policy: Arc<Policy>) -> ListControl {
        ListControl {
            statuses: Mutex::new(Vec::new()),
            refresh_requested: Notify::new(),
            policy,
            assembly: tokio::sync::Mutex::new(Assembly::default()),
            pending: Arc::new(Semaphore::new(MAX_PENDING_CHANGES)),
        }
    }

    /// Blocklists first, then allowlists, in config order.
    pub fn statuses(&self) -> Vec<ListStatus> {
        self.statuses.lock().unwrap().clone()
    }

    /// Asks for every list to be refreshed now. The scheduler still does one refresh at a time,
    /// and asks made while it is busy count as one.
    pub fn refresh_all(&self) {
        self.refresh_requested.notify_one();
    }

    /// Calls `f` with the rules from the status page, in the order added. The rules are only
    /// borrowed: nothing is copied out.
    pub async fn with_button_rules<R>(&self, f: impl FnOnce(&[ButtonRule]) -> R) -> R {
        f(&self.assembly.lock().await.rules)
    }

    /// Which list and rule decide `name` asked as `A`, with blocking on. The engine and the list
    /// positions are read under the lock every swap holds, so they always match.
    pub async fn explain(&self, name: &str) -> Option<Explained> {
        let assembly = self.assembly.lock().await;
        let explanation = self.policy.explain(name)?;
        let list = match explanation.side {
            Side::PinnedAllow | Side::PinnedBlock => "your rules".to_string(),
            Side::Allowlists => self.list_name(assembly.allow_ids.get(explanation.list)),
            Side::Main => self.list_name(assembly.main_ids.get(explanation.list)),
        };

        Some(Explained {
            allowed: explanation.allowed,
            list,
            rule: explanation.rule,
        })
    }

    fn list_name(&self, id: Option<&ListId>) -> String {
        match id {
            Some(ListId::ConfigRules) => "config rules".to_string(),
            Some(ListId::Configured(index)) => self
                .statuses
                .lock()
                .unwrap()
                .get(*index)
                .map_or_else(String::new, |status| status.name.clone()),
            None => String::new(),
        }
    }

    /// Blocks or allows `name` and its subdomains. One rule per name: the other action replaces
    /// the rule in its place; the same again changes nothing. In force when this returns.
    pub async fn add_button_rule(
        self: &Arc<Self>,
        name: &str,
        action: Action,
    ) -> Result<(), RuleError> {
        let name = normalized_name(name).ok_or(RuleError::NotADomainName)?;

        self.change(Edit::Add(name, action)).await
    }

    pub async fn remove_button_rule(self: &Arc<Self>, name: &str) -> Result<(), RuleError> {
        let name = normalized_name(name).ok_or(RuleError::NotADomainName)?;

        self.change(Edit::Remove(name)).await
    }

    /// Waiting for a permit holds nothing and can be cancelled. Once the change is spawned it
    /// runs to its end, whether or not its caller still waits, so a change sent is applied
    /// once and no build is ever dropped half done on the runtime thread.
    async fn change(self: &Arc<Self>, edit: Edit) -> Result<(), RuleError> {
        let permit = Arc::clone(&self.pending)
            .acquire_owned()
            .await
            .map_err(|_| RuleError::NotApplied)?;
        let (answer, answered) = oneshot::channel();
        let control = Arc::clone(self);
        tokio::spawn(async move {
            control.apply(edit, answer).await;
            drop(permit);
        });

        answered.await.unwrap_or(Err(RuleError::NotApplied))
    }

    /// Holds the lock from the check until the replaced engine and lists are freed, so changes
    /// never stack more than one extra copy of the page rules.
    async fn apply(&self, edit: Edit, answer: oneshot::Sender<Result<(), RuleError>>) {
        let mut assembly = self.assembly.lock().await;
        let rules = match assembly.edited(&edit) {
            Ok(Some(rules)) => rules,

            Ok(None) => {
                let _ = answer.send(Ok(()));

                return;
            }

            Err(error) => {
                let _ = answer.send(Err(error));

                return;
            }
        };

        let current = self.policy.engine();
        let built = tokio::task::spawn_blocking(move || {
            let block = page_list(&rules, Action::Block);
            let allow = page_list(&rules, Action::Allow);
            let engine = current.with_pinned(
                block.iter().cloned().collect(),
                allow.iter().cloned().collect(),
            );
            drop(current);

            (rules, block, allow, engine)
        })
        .await;
        let Ok((rules, block, allow, engine)) = built else {
            let _ = answer.send(Err(RuleError::NotApplied));

            return;
        };

        let old_engine = self.policy.swap_engine(Arc::new(engine));
        let old_rules = std::mem::replace(&mut assembly.rules, rules);
        let old_block = std::mem::replace(&mut assembly.block, block);
        let old_allow = std::mem::replace(&mut assembly.allow, allow);
        let _ = answer.send(Ok(()));

        drop_off_runtime((old_engine, old_rules, old_block, old_allow)).await;
    }

    /// Puts the lists of a refresh in force with the page rules in force, and swaps the engine
    /// in. Assembling runs on the compile worker, which is idle once the list has compiled.
    async fn put_in_force(
        &self,
        main: Vec<InForce>,
        allow: Vec<InForce>,
        worker: &CompileWorker,
    ) -> Result<(), CompileError> {
        let mut assembly = self.assembly.lock().await;
        let (main_ids, main): (Vec<ListId>, Vec<Arc<CompiledList>>) = main.into_iter().unzip();
        let (allow_ids, allow): (Vec<ListId>, Vec<Arc<CompiledList>>) = allow.into_iter().unzip();
        let (page_block, page_allow) = assembly.page_lists();
        let engine = worker
            .run(move || Engine::new(main, allow).with_pinned(page_block, page_allow))
            .await?;

        let old_engine = self.policy.swap_engine(Arc::new(engine));
        worker.discard(old_engine);
        assembly.main_ids = main_ids;
        assembly.allow_ids = allow_ids;

        Ok(())
    }
}

/// The page list of one action: a plain `||name^` or `@@||name^` per rule, built without
/// parsing any text. `None` when no rule has that action.
fn page_list(rules: &[ButtonRule], action: Action) -> Option<Arc<CompiledList>> {
    let kind = match action {
        Action::Block => FastKind::SubBlock,
        Action::Allow => FastKind::SubAllow,
    };
    let mut builder = ListBuilder::new();
    let mut any = false;
    for rule in rules.iter().filter(|rule| rule.action == action) {
        builder.add(Rule::Fast {
            kind,
            name: &rule.name,
        });
        any = true;
    }

    any.then(|| Arc::new(builder.finish(ListFormat::Adblock)))
}

/// Drops `garbage` on tokio's blocking pool and waits until it is gone: an engine must never
/// be dropped on the DNS thread (plan D20).
async fn drop_off_runtime<T: Send + 'static>(garbage: T) {
    let _ = tokio::task::spawn_blocking(move || drop(garbage)).await;
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

        let placeholder = Arc::new(Policy::new());
        let mut scheduler = Scheduler {
            control: Arc::new(ListControl::new(Arc::clone(&placeholder))),
            policy: placeholder,
            worker,
            store,
            timing,
            user_rules,
            entries,
        };

        for index in 0..scheduler.entries.len() {
            scheduler.load_at_boot(index).await;
        }

        let (main, allow) = scheduler.lists_in_force(None);
        let (main_ids, main): (Vec<ListId>, Vec<Arc<CompiledList>>) = main.into_iter().unzip();
        let (allow_ids, allow): (Vec<ListId>, Vec<Arc<CompiledList>>) = allow.into_iter().unzip();
        let engine = scheduler
            .worker
            .assemble(main, allow)
            .await
            .map_err(|error| format!("cannot build the filter: {error:?}"))?;

        // The first engine is generation 0, so the policy is made with it, not swapped.
        scheduler.policy = Arc::new(Policy::with_engine(Arc::new(engine)));
        let mut control = ListControl::new(scheduler.policy());
        let assembly = control.assembly.get_mut();
        assembly.main_ids = main_ids;
        assembly.allow_ids = allow_ids;
        scheduler.control = Arc::new(control);
        scheduler.publish_all();

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
        if let Err(error) = self.control.put_in_force(main, allow, &self.worker).await {
            self.worker.discard(compiled);

            return Err(format!("cannot build the filter: {error:?}"));
        }

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

    /// The lists for the next engine, each with where it comes from: the user rules first,
    /// then every list in force in config order, with `replacing` standing in for the list at
    /// its index.
    fn lists_in_force(
        &self,
        replacing: Option<(usize, Arc<CompiledList>)>,
    ) -> (Vec<InForce>, Vec<InForce>) {
        let mut main: Vec<InForce> = self
            .user_rules
            .iter()
            .map(|rules| (ListId::ConfigRules, Arc::clone(rules)))
            .collect();
        let mut allow = Vec::new();

        for (index, entry) in self.entries.iter().enumerate() {
            let list = match &replacing {
                Some((replaced, list)) if *replaced == index => Some(Arc::clone(list)),
                _ => entry.loaded.as_ref().map(|loaded| Arc::clone(&loaded.list)),
            };
            let Some(list) = list else {
                continue;
            };

            let id = ListId::Configured(index);
            match entry.role {
                Role::Blocklist => main.push((id, list)),
                Role::Allowlist => allow.push((id, list)),
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
                allow_redirects: list.allow_redirects || list.url.is_none(),
                check_canaries: role == Role::Blocklist,
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

/// A name for a rule from the status page, or `None` when it is not a domain name: trimmed,
/// lowercased and without one trailing dot, 1 to 253 characters in at least two labels of 1
/// to 63 letters, digits, hyphens or underscores, none starting with a hyphen. Such a name is
/// exactly what a plain `||name^` rule holds, so no `^`, `$` or `*` can reach a page rule.
pub fn normalized_name(text: &str) -> Option<String> {
    let lowered = text.trim().to_ascii_lowercase();
    let name = lowered.strip_suffix('.').unwrap_or(&lowered);
    let is_label = |label: &str| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
    };
    let valid =
        (1..=253).contains(&name.len()) && name.contains('.') && name.split('.').all(is_label);

    valid.then(|| name.to_string())
}

pub(crate) fn unit_random() -> f64 {
    (random_u64() >> 11) as f64 / (1u64 << 53) as f64
}

/// `interval` moved by up to `INTERVAL_JITTER` either way.
pub(crate) fn jittered(interval: Duration) -> Duration {
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

    struct RecordsDropThread(std::sync::mpsc::Sender<std::thread::ThreadId>);

    impl Drop for RecordsDropThread {
        fn drop(&mut self) {
            let _ = self.0.send(std::thread::current().id());
        }
    }

    #[tokio::test]
    async fn garbage_is_dropped_off_the_runtime_thread() {
        let (sender, receiver) = std::sync::mpsc::channel();

        drop_off_runtime(RecordsDropThread(sender)).await;

        let dropped_on = receiver
            .try_recv()
            .expect("dropped by the time the call returns");
        assert_ne!(dropped_on, std::thread::current().id());
    }

    #[tokio::test]
    async fn waiting_changes_are_bounded_and_cancellable() {
        let control = Arc::new(ListControl::new(Arc::new(Policy::new())));
        let held = control.assembly.lock().await;

        for index in 0..50 {
            let name = format!("waiting-{index}.example");
            tokio::select! {
                biased;

                _ = control.add_button_rule(&name, Action::Block) => {
                    panic!("a change finished while the lock was held");
                }

                () = std::future::ready(()) => {}
            }
        }

        assert!(Arc::strong_count(&control) <= 1 + MAX_PENDING_CHANGES);
        assert_eq!(control.pending.available_permits(), 0);

        drop(held);
        let mut in_force = 0;
        for _ in 0..200 {
            in_force = control.with_button_rules(<[ButtonRule]>::len).await;
            if in_force == MAX_PENDING_CHANGES
                && control.pending.available_permits() == MAX_PENDING_CHANGES
            {
                break;
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(in_force, MAX_PENDING_CHANGES);
        assert_eq!(control.pending.available_permits(), MAX_PENDING_CHANGES);
        assert_eq!(
            control
                .add_button_rule("later.example", Action::Block)
                .await,
            Ok(())
        );
    }

    /// A name of `length` characters in labels of 63 and one shorter last label.
    fn long_name(length: usize) -> String {
        let mut name = String::new();
        while name.len() + 64 < length {
            name.push_str(&"a".repeat(63));
            name.push('.');
        }

        let rest = length - name.len();
        name.push_str(&"b".repeat(rest));

        name
    }

    #[test]
    fn names_are_trimmed_lowercased_and_lose_one_trailing_dot() {
        assert_eq!(
            normalized_name(" Example.ORG. ").as_deref(),
            Some("example.org")
        );
        assert_eq!(
            normalized_name("a_b.example").as_deref(),
            Some("a_b.example")
        );
        assert_eq!(normalized_name("1.2.3.4").as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn names_outside_rule_5_are_refused() {
        let too_long = long_name(254);
        let long_label = format!("{}.example", "a".repeat(64));
        assert_eq!(too_long.len(), 254);

        for bad in [
            "a",
            "-x.com",
            &too_long,
            "x..y",
            &long_label,
            "",
            ".",
            "x.com..",
            "x.com^",
            "x.com^$badfilter",
            "x com",
            "%41.com",
            "*.x.com",
            "ünï.com",
        ] {
            assert_eq!(normalized_name(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_longest_name_is_accepted() {
        let longest = long_name(253);
        assert_eq!(longest.len(), 253);
        assert!(longest.split('.').take(3).all(|label| label.len() == 63));

        assert_eq!(normalized_name(&longest).as_ref(), Some(&longest));
        assert_eq!(
            normalized_name(&format!("{longest}.")).as_ref(),
            Some(&longest)
        );
    }
}
