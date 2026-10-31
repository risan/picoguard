//! The list scheduler (plan S4.3). At boot every configured list is loaded from its snapshot
//! and the first engine is assembled from them. Afterwards one task refreshes the lists, one
//! at a time, each on its own interval. A refresh that changes a list compiles it on the
//! worker, assembles the next engine there, swaps it into the policy and waits for the
//! snapshot to be written before the next refresh starts, so at most the current and one
//! new copy are in memory (D13). Any failure keeps the copy in force.
//!
//! The rules added from the status page are saved with the page's settings ([`Saved`]) and put
//! in force by [`ListControl`]. A change rebuilds only those rules and keeps the engine's list
//! rule sets, and is saved before it is put in force. Every swap after boot, a refresh's or a
//! rule change's, holds one lock there, so each builds on the other's latest result.

use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, Semaphore, mpsc, oneshot};
use tokio::time::Instant;

use crate::config::{Config, ListConfig};
use crate::filter::compile::{CompileError, CompileOptions, CompileWorker};
use crate::filter::engine::{CompiledList, Engine, ListBuilder, Side};
use crate::filter::parse::{FastKind, ListFormat, Rule};
use crate::filter::snapshot::{Snapshot, SnapshotStore};
use crate::lists::{Downloader, Limits, Refresh, RefreshError, Updated, Validators, refresh_file};
use crate::memory::{self, ListBytes, Memory};
use crate::pipeline::Pipeline;
use crate::policy::Policy;
use crate::settings::{
    self, ChangeError, ListRole, PageChange, PageList, SaveError, Saved, Settings,
};
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

/// What a refresh of a page list that would pass the memory budget says (plan D6).
pub const OVER_THE_MEMORY_BUDGET: &str = "over the memory budget";

/// What is known about one list, for the status page.
#[derive(Debug, Clone)]
pub struct ListStatus {
    pub name: String,
    pub role: Role,
    /// The URL or the path as written: with the role, what names the list.
    pub source: String,
    /// A URL list; a path list is changed in the config file only.
    pub is_url: bool,
    /// Set on the status page, not taken from the config file.
    pub from_page: bool,
    /// A list that is off is not downloaded and holds nothing.
    pub enabled: bool,
    pub refresh_hours: u32,
    /// What the copy in force counts in the memory estimate; zero without a copy.
    pub bytes: ListBytes,
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

/// The most changes that save (rules and settings) that may wait or run at once. A change
/// runs as a task of its own, so a client that goes away does not cancel it; this bounds those
/// tasks whatever the request rate.
pub const MAX_PENDING_CHANGES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Block,
    Allow,
}

/// A rule added from the status page: the name and its subdomains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ButtonRule {
    pub name: String,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    NotADomainName,
    TooMany,
    NoSuchRule,
    /// The task that applies the change ended without an answer.
    NotApplied,
    /// The change was not saved, so it is not in force either.
    NotSaved(SaveError),
}

/// A change of the lists from the status page. A list is named by its role and source.
#[derive(Debug, Clone)]
pub enum ListEdit {
    Add {
        role: ListRole,
        name: Option<String>,
        url: String,
        refresh_hours: u32,
    },
    Edit {
        role: ListRole,
        source: String,
        name: Option<String>,
        refresh_hours: Option<u32>,
        enabled: Option<bool>,
    },
    Remove {
        role: ListRole,
        source: String,
    },
    /// Back to the config file's lists.
    Reset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListError {
    /// Refused with the reason, before anything was downloaded.
    Invalid(String),
    NoSuchList,
    /// A path list: it is changed in the config file.
    ConfigFileOnly,
    /// An add is being checked already.
    AddInFlight,
    /// The list would pass the memory budget. `needs` is what it adds to the estimate, `None`
    /// when its compile stopped at the room that was `left`.
    OverBudget {
        name: String,
        needs: Option<usize>,
        left: usize,
        budget: usize,
    },
    /// The download or the compile of a list failed.
    Failed {
        name: String,
        reason: String,
    },
    NotSaved(SaveError),
    NotApplied,
}

/// The last list added from the page while it is checked, and how that ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingList {
    pub role: ListRole,
    pub name: Option<String>,
    pub url: String,
    /// `None` while it is checked.
    pub outcome: Option<Result<(), ListError>>,
    /// Which add this is, so an add only ever changes its own row.
    id: u64,
}

/// The lists the scheduler is to put in force, and the settings that hold them.
struct Replace {
    blocklists: Vec<ListConfig>,
    allowlists: Vec<ListConfig>,
    from_page: bool,
    settings: Settings,
    reply: oneshot::Sender<Result<(), ListError>>,
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
    /// The page lists in force; `None` for a side without rules.
    block: Option<Arc<CompiledList>>,
    allow: Option<Arc<CompiledList>>,
}

enum Edit {
    Add(String, Action),
    Remove(String),
}

/// `rules` (in the order first added) after `edit`, or `None` when it changes nothing.
fn edited(rules: &[ButtonRule], edit: &Edit) -> Result<Option<Vec<ButtonRule>>, RuleError> {
    match edit {
        Edit::Add(name, action) => match rules.iter().position(|rule| rule.name == *name) {
            Some(at) if rules[at].action == *action => Ok(None),

            Some(at) => {
                let mut rules = rules.to_vec();
                rules[at].action = *action;

                Ok(Some(rules))
            }

            None if rules.len() >= MAX_BUTTON_RULES => Err(RuleError::TooMany),

            None => {
                let mut edited = Vec::with_capacity(rules.len() + 1);
                edited.extend_from_slice(rules);
                edited.push(ButtonRule {
                    name: name.clone(),
                    action: *action,
                });

                Ok(Some(edited))
            }
        },

        Edit::Remove(name) => {
            let at = rules
                .iter()
                .position(|rule| rule.name == *name)
                .ok_or(RuleError::NoSuchRule)?;
            let mut rules = rules.to_vec();
            rules.remove(at);

            Ok(Some(rules))
        }
    }
}

impl Assembly {
    fn page_lists(&self) -> (Vec<Arc<CompiledList>>, Vec<Arc<CompiledList>>) {
        (
            self.block.iter().cloned().collect(),
            self.allow.iter().cloned().collect(),
        )
    }
}

/// The scheduler seen from outside: what the lists look like, a way to ask for a refresh, and
/// the rules added from the status page, which it saves and puts in force.
pub struct ListControl {
    statuses: Mutex<Vec<ListStatus>>,
    refresh_requested: Notify,
    policy: Arc<Policy>,
    /// Holds the page rules; its lock comes before the admission and the assembly lock.
    saved: Arc<Saved>,
    /// Held from working out the room of a compile, or of a larger cache, until the result is
    /// in force and what it replaced is freed, so two of them never count the same room
    /// (plan D6). Every list refresh holds it too. Lock order: the settings lock, this, the
    /// assembly lock.
    admission: tokio::sync::Mutex<()>,
    budget_bytes: usize,
    /// `memory::fixed_bytes` and the config's own rules.
    fixed_bytes: usize,
    /// The cache's `max_bytes` in force.
    cache_max_bytes: AtomicUsize,
    assembly: tokio::sync::Mutex<Assembly>,
    pending: Arc<Semaphore>,
    /// To the scheduler's task, which owns the lists.
    commands: mpsc::Sender<Replace>,
    pending_list: Mutex<Option<PendingList>>,
    /// The saved settings hold the lists, so the config file's URL lists are not used.
    lists_on_page: AtomicBool,
    next_add: AtomicU64,
}

impl ListControl {
    /// A control without lists or page lists, swapping engines into `policy` and saving rule
    /// changes to `saved`.
    pub fn new(policy: Arc<Policy>, saved: Arc<Saved>) -> ListControl {
        ListControl::with_commands(policy, saved).0
    }

    /// A control, and the end of its commands that the scheduler reads.
    fn with_commands(
        policy: Arc<Policy>,
        saved: Arc<Saved>,
    ) -> (ListControl, mpsc::Receiver<Replace>) {
        let file = saved.file_config();
        let (commands, received) = mpsc::channel(1);

        let control = ListControl {
            statuses: Mutex::new(Vec::new()),
            refresh_requested: Notify::new(),
            policy,
            admission: tokio::sync::Mutex::new(()),
            budget_bytes: memory::budget_bytes(&file.limits),
            fixed_bytes: memory::fixed_bytes(&file.limits, &file.stats),
            cache_max_bytes: AtomicUsize::new(file.cache.max_bytes),
            saved,
            assembly: tokio::sync::Mutex::new(Assembly::default()),
            pending: Arc::new(Semaphore::new(MAX_PENDING_CHANGES)),
            commands,
            pending_list: Mutex::new(None),
            lists_on_page: AtomicBool::new(false),
            next_add: AtomicU64::new(0),
        };

        (control, received)
    }

    pub fn saved(&self) -> &Arc<Saved> {
        &self.saved
    }

    /// Whether the saved settings hold the lists, even none at all.
    pub fn lists_on_page(&self) -> bool {
        self.lists_on_page.load(Ordering::Relaxed)
    }

    /// The estimate of the whole process with the lists in force, and the budget.
    pub fn memory(&self) -> Memory {
        Memory {
            estimate_bytes: memory::estimate(
                self.fixed_bytes,
                self.cache_max_bytes.load(Ordering::Relaxed),
                &self.list_bytes(),
            ),
            budget_bytes: self.budget_bytes,
        }
    }

    /// The admission lock (see the field). The caller holds the settings lock or none.
    pub(crate) async fn admission(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.admission.lock().await
    }

    /// Whether a cache of `max_bytes` keeps the estimate within the budget; the reason when
    /// not. The caller holds the admission lock.
    pub(crate) fn cache_fits(&self, max_bytes: usize) -> Result<(), String> {
        let estimate = memory::estimate(self.fixed_bytes, max_bytes, &self.list_bytes());
        if estimate <= self.budget_bytes {
            return Ok(());
        }

        Err(format!(
            "a cache of {} would pass the memory budget: the estimate would be {} of {}",
            memory::megabytes(max_bytes),
            memory::megabytes(estimate),
            memory::megabytes(self.budget_bytes)
        ))
    }

    /// The cache in force now has `max_bytes`. The caller holds the admission lock.
    pub(crate) fn set_cache_max_bytes(&self, max_bytes: usize) {
        self.cache_max_bytes.store(max_bytes, Ordering::Relaxed);
    }

    fn list_bytes(&self) -> Vec<ListBytes> {
        self.statuses
            .lock()
            .unwrap()
            .iter()
            .map(|status| status.bytes)
            .collect()
    }

    /// What a compile may be charged now: the budget less what is held without it. The
    /// caller holds the admission lock.
    fn compile_room(&self) -> usize {
        let steady = memory::steady_bytes(
            self.fixed_bytes,
            self.cache_max_bytes.load(Ordering::Relaxed),
            &self.list_bytes(),
        );

        self.budget_bytes.saturating_sub(steady)
    }

    /// Whether the estimate with `lists` in force stays within the budget.
    fn fits(&self, lists: &[ListBytes]) -> bool {
        let estimate = memory::estimate(
            self.fixed_bytes,
            self.cache_max_bytes.load(Ordering::Relaxed),
            lists,
        );

        estimate <= self.budget_bytes
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
        f(&self.saved.lock().await.page_rules)
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

    async fn change(self: &Arc<Self>, edit: Edit) -> Result<(), RuleError> {
        self.spawn_change(|control, answer| async move { control.apply(edit, answer).await })
            .await
            .unwrap_or(Err(RuleError::NotApplied))
    }

    /// Changes the upstream and cache settings of the page: saved, then put in force.
    pub async fn change_settings(
        self: &Arc<Self>,
        pipeline: &Arc<Pipeline>,
        change: PageChange,
    ) -> Result<(), ChangeError> {
        let pipeline = Arc::clone(pipeline);

        self.spawn_change(|control, answer| async move {
            settings::apply(&control, &pipeline, change, answer).await;
        })
        .await
        .unwrap_or(Err(ChangeError::NotApplied))
    }

    /// The list added last from the page, while it is checked and after.
    pub fn pending_list(&self) -> Option<PendingList> {
        self.pending_list.lock().unwrap().clone()
    }

    /// Starts adding a list from the page. The request is checked and refused at once, or
    /// accepted while the list is downloaded, compiled and admitted against the memory budget;
    /// `pending_list` then says how that ends. One add at a time.
    pub async fn add_list(self: &Arc<Self>, edit: ListEdit) -> Result<(), ListError> {
        let ListEdit::Add {
            role, name, url, ..
        } = &edit
        else {
            return Err(ListError::NotApplied);
        };

        let id = self.next_add.fetch_add(1, Ordering::Relaxed);
        let previous = {
            let mut pending = self.pending_list.lock().unwrap();
            if pending.as_ref().is_some_and(|list| list.outcome.is_none()) {
                return Err(ListError::AddInFlight);
            }

            pending.replace(PendingList {
                role: *role,
                name: name.clone(),
                url: url.clone(),
                outcome: None,
                id,
            })
        };
        // Until the add is spawned, a caller that goes away takes the reservation with it.
        let mut reserved = Reservation {
            pending: &self.pending_list,
            id,
            previous: Some(previous),
            spawned: AtomicBool::new(false),
        };

        let accepted = self
            .spawn_change(|control, answer| {
                reserved.spawned.store(true, Ordering::Relaxed);

                async move {
                    let outcome = control.apply_lists(edit, Some(answer)).await;
                    if let Some(pending) = control.pending_list.lock().unwrap().as_mut()
                        && pending.id == id
                        && pending.outcome.is_none()
                    {
                        pending.outcome = Some(outcome);
                    }
                }
            })
            .await
            .unwrap_or(Err(ListError::NotApplied));
        if accepted.is_ok() {
            reserved.previous = None;
        } else {
            reserved.spawned.store(false, Ordering::Relaxed);
        }

        accepted
    }

    /// Edits, removes or resets the lists of the page: saved, then in force when this returns.
    /// A list that is turned on again, or that a reset brings back, is downloaded and admitted
    /// against the memory budget first.
    pub async fn change_lists(self: &Arc<Self>, edit: ListEdit) -> Result<(), ListError> {
        self.spawn_change(|control, answer| async move {
            let outcome = control.apply_lists(edit, None).await;
            let _ = answer.send(outcome);
        })
        .await
        .unwrap_or(Err(ListError::NotApplied))
    }

    /// Under the settings lock: the page's lists after `edit`, checked as a whole, then handed
    /// to the scheduler, which admits, saves and puts them in force. `accepted` is answered as
    /// soon as the edit is checked; the outcome is returned.
    async fn apply_lists(
        &self,
        edit: ListEdit,
        mut accepted: Option<oneshot::Sender<Result<(), ListError>>>,
    ) -> Result<(), ListError> {
        let mut answer_early = |result: &Result<(), ListError>| {
            if let Some(accepted) = accepted.take() {
                let _ = accepted.send(result.clone());
            }
        };
        let mut settings = self.saved.lock().await;
        let file = self.saved.file_config();
        let current = settings
            .lists
            .clone()
            .unwrap_or_else(|| page_lists_of(file));
        let lists = match edited_lists(file, &current, settings.lists.is_some(), edit) {
            Ok(Some(lists)) => lists,

            Ok(None) => {
                answer_early(&Ok(()));

                return Ok(());
            }

            Err(error) => {
                answer_early(&Err(error.clone()));

                return Err(error);
            }
        };
        let mut next = settings.clone();
        next.lists = lists;
        let checked = {
            let file = file.clone();
            let next = next.clone();
            tokio::task::spawn_blocking(move || settings::merged(&file, &next))
                .await
                .unwrap_or_else(|_| Err("the check was stopped".to_string()))
        };
        let config = match checked {
            Ok(config) => config,

            Err(reason) => {
                let error = ListError::Invalid(reason);
                answer_early(&Err(error.clone()));

                return Err(error);
            }
        };

        answer_early(&Ok(()));
        let lists = next.lists.clone();
        let (reply, replied) = oneshot::channel();
        let command = Replace {
            blocklists: config.lists,
            allowlists: config.allowlists,
            from_page: next.lists.is_some(),
            settings: next,
            reply,
        };
        if self.commands.send(command).await.is_err() {
            return Err(ListError::NotApplied);
        }

        let outcome = replied.await.unwrap_or(Err(ListError::NotApplied));
        if outcome.is_ok() {
            settings.lists = lists;
        }

        outcome
    }

    /// Waiting for a permit holds nothing and can be cancelled. Once the change is spawned it
    /// runs to its end, whether or not its caller still waits, so a change sent is applied
    /// once and no build is ever dropped half done on the runtime thread. `None` when the
    /// change ended without an answer.
    async fn spawn_change<T, F>(
        self: &Arc<Self>,
        change: impl FnOnce(Arc<Self>, oneshot::Sender<T>) -> F,
    ) -> Option<T>
    where
        T: Send + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let permit = Arc::clone(&self.pending).acquire_owned().await.ok()?;
        let (answer, answered) = oneshot::channel();
        let change = change(Arc::clone(self), answer);
        tokio::spawn(async move {
            change.await;
            drop(permit);
        });

        answered.await.ok()
    }

    /// Holds the locks from the check until the replaced engine and lists are freed, so changes
    /// never stack more than one extra copy of the page rules. The engine is built first, then
    /// the rules are saved, and only a saved change is put in force.
    async fn apply(&self, edit: Edit, answer: oneshot::Sender<Result<(), RuleError>>) {
        let mut settings = self.saved.lock().await;
        let rules = match edited(&settings.page_rules, &edit) {
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

        let mut assembly = self.assembly.lock().await;
        let current = self.policy.engine();
        // The engine goes into its `Arc` here: the struct is over a kilobyte, and returned by
        // value it would be one more copy in the task's output and in this future.
        let built = tokio::task::spawn_blocking(move || {
            let block = page_list(&rules, Action::Block);
            let allow = page_list(&rules, Action::Allow);
            let engine = Arc::new(current.with_pinned(
                block.iter().cloned().collect(),
                allow.iter().cloned().collect(),
            ));
            drop(current);

            (rules, block, allow, engine)
        })
        .await;
        let Ok((rules, block, allow, engine)) = built else {
            let _ = answer.send(Err(RuleError::NotApplied));

            return;
        };

        let old_rules = std::mem::replace(&mut settings.page_rules, rules);
        if let Err(error) = self.saved.save(&settings).await {
            let unsaved = std::mem::replace(&mut settings.page_rules, old_rules);
            let _ = answer.send(Err(RuleError::NotSaved(error)));
            drop_off_runtime((unsaved, block, allow, engine)).await;

            return;
        }

        let old_engine = self.policy.swap_engine(engine);
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

/// The add being checked, held in the pending row from the check of `add_list` until its task
/// is spawned. Dropped before that, or refused, it puts the row as it was back.
/// A row that a newer add has replaced meanwhile is left alone.
struct Reservation<'a> {
    pending: &'a Mutex<Option<PendingList>>,
    id: u64,
    previous: Option<Option<PendingList>>,
    spawned: AtomicBool,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if self.spawned.load(Ordering::Relaxed) {
            return;
        }

        let Some(previous) = self.previous.take() else {
            return;
        };

        let mut pending = self.pending.lock().unwrap();
        if pending.as_ref().is_some_and(|list| list.id == self.id) {
            *pending = previous;
        }
    }
}

/// The URL lists of the config file as the page holds them: what the first edit from the page
/// copies.
fn page_lists_of(file: &Config) -> Vec<PageList> {
    let blocklists = file.lists.iter().map(|list| (ListRole::Block, list));
    let allowlists = file.allowlists.iter().map(|list| (ListRole::Allow, list));

    blocklists
        .chain(allowlists)
        .filter_map(|(role, list)| {
            Some(PageList {
                role,
                name: list.name.clone(),
                url: list.url.clone()?,
                refresh_hours: list.refresh_hours,
                enabled: list.enabled,
            })
        })
        .collect()
}

/// The page's lists after `edit`: `Some(None)` to go back to the config file's lists,
/// `Some(Some(lists))` for the lists to save, `None` when the edit changes nothing. `current`
/// is what is in force now (the config file's URL lists when `on_page` is false).
fn edited_lists(
    file: &Config,
    current: &[PageList],
    on_page: bool,
    edit: ListEdit,
) -> Result<Option<Option<Vec<PageList>>>, ListError> {
    let position = |role: ListRole, source: &str| {
        let lists = match role {
            ListRole::Block => &file.lists,
            ListRole::Allow => &file.allowlists,
        };
        if lists.iter().any(|list| {
            list.path
                .as_ref()
                .is_some_and(|path| path.display().to_string() == source)
        }) {
            return Err(ListError::ConfigFileOnly);
        }

        current
            .iter()
            .position(|list| list.role == role && list.url == source)
            .ok_or(ListError::NoSuchList)
    };
    let mut lists = current.to_vec();

    match edit {
        ListEdit::Reset => {
            return Ok(on_page.then_some(None));
        }

        ListEdit::Add {
            role,
            name,
            url,
            refresh_hours,
        } => {
            if current
                .iter()
                .any(|list| list.role == role && list.url == url)
            {
                return Err(ListError::Invalid("that list is added already".to_string()));
            }

            lists.push(PageList {
                role,
                name,
                url,
                refresh_hours,
                enabled: true,
            });
        }

        ListEdit::Edit {
            role,
            source,
            name,
            refresh_hours,
            enabled,
        } => {
            let list = &mut lists[position(role, &source)?];
            if let Some(name) = name {
                list.name = (!name.is_empty()).then_some(name);
            }

            if let Some(refresh_hours) = refresh_hours {
                list.refresh_hours = refresh_hours;
            }

            if let Some(enabled) = enabled {
                list.enabled = enabled;
            }
        }

        ListEdit::Remove { role, source } => {
            lists.remove(position(role, &source)?);
        }
    }

    if lists == current {
        return Ok(None);
    }

    Ok(Some(Some(lists)))
}

/// Drops `garbage` on tokio's blocking pool and waits until it is gone: an engine must never
/// be dropped on the DNS thread (plan D20).
pub(crate) async fn drop_off_runtime<T: Send + 'static>(garbage: T) {
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
    /// Off: never refreshed, and holds no copy.
    enabled: bool,
    /// A list of the page: every compile of it is admitted against the memory budget.
    budgeted: bool,
    refresh_hours: u32,
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
    /// Lists from the page to put in force; taken by `run`.
    commands: Option<mpsc::Receiver<Replace>>,
}

impl Scheduler {
    /// Loads what can be loaded without the network and puts the first engine in force.
    /// A list without a usable snapshot starts empty and is refreshed first.
    pub async fn boot(
        config: &Config,
        saved: Arc<Saved>,
        worker: CompileWorker,
        store: Arc<SnapshotStore>,
        timing: Timing,
    ) -> Result<Scheduler, String> {
        let user_rules = compile_user_rules(&config.rules, &worker).await?;
        let from_page = saved.lock().await.lists.is_some();
        let blocklists = config.lists.iter().map(|list| (Role::Blocklist, list));
        let allowlists = config.allowlists.iter().map(|list| (Role::Allowlist, list));
        let entries = blocklists
            .chain(allowlists)
            .filter_map(|(role, list)| Entry::new(role, list, from_page, &timing))
            .collect();

        let placeholder = Arc::new(Policy::new());
        let mut scheduler = Scheduler {
            control: Arc::new(ListControl::new(
                Arc::clone(&placeholder),
                Arc::clone(&saved),
            )),
            policy: placeholder,
            worker,
            store,
            timing,
            user_rules,
            entries,
            commands: None,
        };

        for index in 0..scheduler.entries.len() {
            if scheduler.entries[index].enabled {
                scheduler.load_at_boot(index).await;
            }
        }

        let (main, allow) = scheduler.lists_in_force(None);
        let (main_ids, main): (Vec<ListId>, Vec<Arc<CompiledList>>) = main.into_iter().unzip();
        let (allow_ids, allow): (Vec<ListId>, Vec<Arc<CompiledList>>) = allow.into_iter().unzip();
        let (page_block, page_allow) = {
            let settings = saved.lock().await;

            (
                page_list(&settings.page_rules, Action::Block),
                page_list(&settings.page_rules, Action::Allow),
            )
        };
        let (pinned_block, pinned_allow) = (
            page_block.iter().cloned().collect(),
            page_allow.iter().cloned().collect(),
        );
        let engine = scheduler
            .worker
            .run(move || Engine::new(main, allow).with_pinned(pinned_block, pinned_allow))
            .await
            .map_err(|error| format!("cannot build the filter: {error:?}"))?;

        // The first engine is generation 0, so the policy is made with it, not swapped.
        scheduler.policy = Arc::new(Policy::with_engine(Arc::new(engine)));
        let (mut control, commands) = ListControl::with_commands(scheduler.policy(), saved);
        scheduler.commands = Some(commands);
        control.fixed_bytes += scheduler
            .user_rules
            .as_ref()
            .map_or(0, |rules| rules.heap_bytes());
        control.cache_max_bytes = AtomicUsize::new(config.cache.max_bytes);
        control.lists_on_page = AtomicBool::new(from_page);
        let assembly = control.assembly.get_mut();
        assembly.main_ids = main_ids;
        assembly.allow_ids = allow_ids;
        assembly.block = page_block;
        assembly.allow = page_allow;
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
        let mut commands = self.commands.take();

        loop {
            let next = self.next_work();
            let due = async {
                match &next {
                    Some((_, _, at)) => tokio::time::sleep_until(*at).await,
                    None => std::future::pending().await,
                }
            };
            let command = async {
                match commands.as_mut() {
                    Some(commands) => commands.recv().await,
                    None => std::future::pending().await,
                }
            };

            tokio::select! {
                biased;

                () = &mut stop => {
                    break;
                }

                () = control.refresh_requested.notified() => {
                    self.refresh_all_now();

                    continue;
                }

                Some(command) = command => {
                    let outcome = self.replace(command.blocklists, command.allowlists, command.from_page, &command.settings, &downloader).await;
                    let _ = command.reply.send(outcome);

                    continue;
                }

                () = due => {}
            }

            let Some((index, work, _)) = next else {
                continue;
            };

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

    /// Puts `blocklists` and `allowlists` in force in place of the lists in force, then saves
    /// `settings`, which hold them. A list in force before and after keeps its copy; a new
    /// name or refresh interval changes only that. A list that is new, or on again, is
    /// downloaded and compiled within the room the memory budget leaves, and its copy must
    /// fit the budget; any that cannot be refuses the whole change. A list that is off or
    /// gone is dropped. Nothing is in force before the settings are saved.
    async fn replace(
        &mut self,
        blocklists: Vec<ListConfig>,
        allowlists: Vec<ListConfig>,
        from_page: bool,
        settings: &Settings,
        downloader: &Downloader,
    ) -> Result<(), ListError> {
        let control = Arc::clone(&self.control);
        let admitted = control.admission.lock().await;
        let wanted: Vec<Entry> = blocklists
            .iter()
            .map(|list| (Role::Blocklist, list))
            .chain(allowlists.iter().map(|list| (Role::Allowlist, list)))
            .filter_map(|(role, list)| Entry::new(role, list, from_page, &self.timing))
            .collect();
        let in_force = |wanted: &Entry| {
            self.entries.iter().position(|entry| {
                entry.enabled && entry.role == wanted.role && entry.key == wanted.key
            })
        };
        let kept: Vec<Option<usize>> = wanted.iter().map(&in_force).collect();

        // Every list in force stays held until the new set is, so a compile has the room
        // they leave; the set after the change counts only the lists that stay.
        let mut held = control.list_bytes();
        let mut after: Vec<ListBytes> = kept.iter().flatten().map(|at| held[*at]).collect();
        let mut admitted_copies = Vec::new();
        for (index, entry) in wanted.iter().enumerate() {
            if kept[index].is_some() || !entry.enabled {
                continue;
            }

            match self.admit(entry, &held, &after, downloader).await {
                Ok(compiled) => {
                    let bytes = ListBytes {
                        heap: compiled.compiled.list.heap_bytes(),
                        charge: compiled.compiled.list.compile_charge(),
                    };
                    held.push(bytes);
                    after.push(bytes);
                    admitted_copies.push((index, compiled));
                }

                Err(error) => {
                    self.worker.discard((wanted, admitted_copies));
                    let _ = self.worker.run(|| ()).await;

                    return Err(error);
                }
            }
        }

        if let Err(error) = control.saved.save(settings).await {
            self.worker.discard((wanted, admitted_copies));
            let _ = self.worker.run(|| ()).await;

            return Err(ListError::NotSaved(error));
        }

        let mut old: Vec<Option<Entry>> = self.entries.drain(..).map(Some).collect();
        let mut turned_off = Vec::new();
        let mut snapshots = Vec::new();
        for (index, mut entry) in wanted.into_iter().enumerate() {
            if let Some(at) = kept[index] {
                let mut kept = old[at].take().expect("each list is kept once");
                turned_off.extend(kept.take_settings_of(entry));
                entry = kept;
            }

            if let Some(at) = admitted_copies.iter().position(|(at, _)| *at == index) {
                let (_, updated) = admitted_copies.swap_remove(at);
                let Updated {
                    compiled,
                    validators,
                } = *updated;
                if matches!(entry.source, Source::Url(_)) {
                    snapshots.push((
                        self.entries.len(),
                        Snapshot::new(&compiled, &entry.options, &entry.key, validators.clone()),
                    ));
                }

                entry.loaded = Some(Loaded {
                    format: compiled.summary.format,
                    fingerprint: compiled.fingerprint,
                    list: compiled.list,
                    validators,
                });
                entry.checked = Some(Instant::now());
                entry.due = Instant::now() + jittered(entry.interval);
                log::info!("{}: added", entry.label);
            }

            self.entries.push(entry);
        }

        let (main, allow) = self.lists_in_force(None);
        if let Err(error) = control.put_in_force(main, allow, &self.worker).await {
            log::warn!("cannot build the filter with the changed lists: {error:?}");
        }

        control.lists_on_page.store(from_page, Ordering::Relaxed);
        self.publish_all();
        for (index, snapshot) in snapshots {
            self.save(index, snapshot, 0).await;
        }

        self.worker.discard((old, turned_off));
        let _ = self.worker.run(|| ()).await;
        drop(admitted);

        Ok(())
    }

    /// Downloads and compiles the list of `entry` within the room the budget leaves while
    /// `held` are held, and checks that its copy fits with the lists `after` the change.
    async fn admit(
        &self,
        entry: &Entry,
        held: &[ListBytes],
        after: &[ListBytes],
        downloader: &Downloader,
    ) -> Result<Box<Updated>, ListError> {
        let control = &self.control;
        let steady = memory::steady_bytes(
            control.fixed_bytes,
            control.cache_max_bytes.load(Ordering::Relaxed),
            held,
        );
        let left = control.budget_bytes.saturating_sub(steady);
        let fetched = match &entry.source {
            Source::Url(url) => {
                let limits = Limits {
                    max_body_bytes: entry.max_body_bytes,
                    ..Limits::default()
                };

                downloader
                    .refresh(
                        &self.worker,
                        url,
                        &Validators::default(),
                        &limits,
                        entry.options,
                        left,
                    )
                    .await
            }

            Source::Path(path) => refresh_file(
                &self.worker,
                path.clone(),
                entry.max_body_bytes,
                entry.options,
            )
            .await
            .map(|compiled| {
                Refresh::Updated(Box::new(Updated {
                    compiled,
                    validators: Validators::default(),
                }))
            }),
        };
        let failed = |reason: String| ListError::Failed {
            name: entry.label.clone(),
            reason,
        };
        let updated = match fetched {
            Ok(Refresh::Updated(updated)) => updated,
            Ok(Refresh::NotModified) => return Err(failed("not modified".to_string())),

            Err(RefreshError::Compile(CompileError::OverMemoryBudget)) => {
                return Err(ListError::OverBudget {
                    name: entry.label.clone(),
                    needs: None,
                    left,
                    budget: control.budget_bytes,
                });
            }

            Err(error) => return Err(failed(error.to_string())),
        };

        let list = &updated.compiled.list;
        let mut with_it = after.to_vec();
        with_it.push(ListBytes {
            heap: list.heap_bytes(),
            charge: list.compile_charge(),
        });
        if !control.fits(&with_it) {
            let before = memory::estimate(
                control.fixed_bytes,
                control.cache_max_bytes.load(Ordering::Relaxed),
                after,
            );
            let after = memory::estimate(
                control.fixed_bytes,
                control.cache_max_bytes.load(Ordering::Relaxed),
                &with_it,
            );
            self.worker.discard(updated);

            return Err(ListError::OverBudget {
                name: entry.label.clone(),
                needs: Some(after - before),
                left: control.budget_bytes.saturating_sub(before),
                budget: control.budget_bytes,
            });
        }

        Ok(updated)
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
            .filter(|(_, entry)| entry.enabled)
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
    /// was compiled, assembled into an engine and swapped in. A list of the page is compiled
    /// within the room the memory budget leaves, and a larger copy must fit the budget.
    pub async fn refresh(&mut self, index: usize, downloader: &Downloader) {
        let control = Arc::clone(&self.control);
        let admitted = control.admission.lock().await;
        let room = if self.entries[index].budgeted {
            control.compile_room()
        } else {
            usize::MAX
        };
        let outcome = match self.fetch(index, downloader, room).await {
            Ok(Refresh::NotModified) => {
                log::info!("{}: not modified", self.entries[index].label);

                Ok(())
            }

            Ok(Refresh::Updated(updated)) => self.install(index, updated).await,

            Err(RefreshError::Compile(CompileError::OverMemoryBudget)) => {
                Err(OVER_THE_MEMORY_BUDGET.to_string())
            }

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
        // What the refresh replaced or refused is dropped on the worker before anything else
        // may count the room it held.
        let _ = self.worker.run(|| ()).await;
        drop(admitted);
    }

    async fn fetch(
        &self,
        index: usize,
        downloader: &Downloader,
        admission_bytes: usize,
    ) -> Result<Refresh, RefreshError> {
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
                    .refresh(
                        &self.worker,
                        url,
                        &previous,
                        &limits,
                        entry.options,
                        admission_bytes,
                    )
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

        if entry.budgeted && !self.fits_in_place_of(index, &updated.compiled.list) {
            self.worker.discard(updated);

            return Err(OVER_THE_MEMORY_BUDGET.to_string());
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

    /// Whether `list` may replace the copy of the list at `index`: a copy that is no larger
    /// always may; a larger one only within the budget.
    fn fits_in_place_of(&self, index: usize, list: &CompiledList) -> bool {
        let mut lists = self.control.list_bytes();
        let new = ListBytes {
            heap: list.heap_bytes(),
            charge: list.compile_charge(),
        };
        let old = lists[index];
        if new.heap <= old.heap && new.charge <= old.charge {
            return true;
        }

        lists[index] = new;

        self.control.fits(&lists)
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
    /// Takes what the page may change from `wanted`, the same list as the page has it now:
    /// its name, its refresh interval, whether it is on, and its options, which only a new
    /// config file changes. A list with other options is downloaded again soon. Returns the
    /// copy of a list turned off, to be freed off the DNS thread.
    fn take_settings_of(&mut self, wanted: Entry) -> Option<(Option<Loaded>, Option<PendingSave>)> {
        self.label = wanted.label;
        self.budgeted = wanted.budgeted;
        if self.refresh_hours != wanted.refresh_hours {
            self.refresh_hours = wanted.refresh_hours;
            self.interval = wanted.interval;
            if self.failures == 0 && self.loaded.is_some() {
                self.due = Instant::now() + jittered(self.interval);
            }
        }

        let mut dropped = None;
        if !wanted.enabled {
            self.enabled = false;
            self.last_error = None;
            dropped = Some((self.loaded.take(), self.pending_save.take()));
        }

        if self.options != wanted.options || self.max_body_bytes != wanted.max_body_bytes {
            self.options = wanted.options;
            self.max_body_bytes = wanted.max_body_bytes;
            if let Some(loaded) = &mut self.loaded {
                loaded.validators = Validators::default();
            }

            self.due = Instant::now();
        }

        dropped
    }

    fn status(&self) -> ListStatus {
        ListStatus {
            name: self.label.clone(),
            role: self.role,
            source: self.key.clone(),
            is_url: matches!(self.source, Source::Url(_)),
            from_page: self.budgeted,
            enabled: self.enabled,
            refresh_hours: self.refresh_hours,
            bytes: self
                .loaded
                .as_ref()
                .map_or_else(ListBytes::default, |loaded| ListBytes {
                    heap: loaded.list.heap_bytes(),
                    charge: loaded.list.compile_charge(),
                }),
            format: self.loaded.as_ref().map(|loaded| loaded.format),
            rules: self
                .loaded
                .as_ref()
                .map_or(0, |loaded| loaded.list.rule_count()),
            checked: self.checked,
            last_error: self.last_error.clone(),
        }
    }

    /// `from_page`: the settings of the page hold the lists, so a URL list is the page's.
    fn new(role: Role, list: &ListConfig, from_page: bool, timing: &Timing) -> Option<Entry> {
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
            enabled: list.enabled,
            budgeted: from_page && list.url.is_some(),
            refresh_hours: list.refresh_hours,
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
    use crate::settings::Settings;
    use crate::test_dir::TestDir;

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

    fn saved_in(dir: &TestDir) -> Arc<Saved> {
        let mut config = Config::default();
        config.state.dir = dir.path().to_path_buf();

        Arc::new(Saved::new(config, Settings::default(), None))
    }

    #[tokio::test]
    async fn waiting_changes_are_bounded_and_cancellable() {
        let dir = TestDir::new("scheduler-waiting");
        let control = Arc::new(ListControl::new(Arc::new(Policy::new()), saved_in(&dir)));
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

    #[test]
    fn a_refused_add_puts_back_the_row_before_it_only_while_the_row_is_its_own() {
        let row = |id: u64, url: &str| PendingList {
            role: ListRole::Block,
            name: None,
            url: url.to_string(),
            outcome: Some(Ok(())),
            id,
        };
        let pending = Mutex::new(Some(row(1, "https://lists.example/refused.txt")));
        let reservation = |previous| Reservation {
            pending: &pending,
            id: 1,
            previous: Some(previous),
            spawned: AtomicBool::new(false),
        };

        drop(reservation(Some(row(
            0,
            "https://lists.example/before.txt",
        ))));
        assert_eq!(pending.lock().unwrap().as_ref().unwrap().id, 0);

        *pending.lock().unwrap() = Some(row(2, "https://lists.example/newer.txt"));
        drop(reservation(Some(row(
            0,
            "https://lists.example/before.txt",
        ))));
        assert_eq!(
            pending.lock().unwrap().as_ref().unwrap().url,
            "https://lists.example/newer.txt",
            "a newer add's row stays"
        );
    }

    #[tokio::test]
    async fn an_add_whose_caller_leaves_before_it_starts_leaves_no_add_in_flight() {
        let dir = TestDir::new("scheduler-add-left");
        let control = Arc::new(ListControl::new(Arc::new(Policy::new()), saved_in(&dir)));
        let held = Arc::clone(&control.pending)
            .acquire_many_owned(MAX_PENDING_CHANGES as u32)
            .await
            .unwrap();
        let add = || ListEdit::Add {
            role: ListRole::Block,
            name: None,
            url: "https://lists.example/a.txt".to_string(),
            refresh_hours: 24,
        };

        tokio::select! {
            biased;

            _ = control.add_list(add()) => {
                panic!("the add started without a permit");
            }

            () = std::future::ready(()) => {}
        }

        assert_eq!(control.pending_list(), None);
        drop(held);
        // No scheduler reads the commands here, so the add is checked and then not applied.
        assert_eq!(control.add_list(add()).await, Ok(()));
        for _ in 0..200 {
            if control
                .pending_list()
                .and_then(|list| list.outcome)
                .is_some()
            {
                break;
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert_eq!(
            control.pending_list().and_then(|list| list.outcome),
            Some(Err(ListError::NotApplied))
        );
    }

    #[test]
    fn a_change_cut_off_at_shutdown_changes_nothing_and_frees_its_permit() {
        let dir = TestDir::new("scheduler-cut-off");
        let policy = Arc::new(Policy::new());
        let control = Arc::new(ListControl::new(Arc::clone(&policy), saved_in(&dir)));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let holder = Arc::clone(&control);
            tokio::spawn(async move {
                let _held = holder.assembly.lock().await;
                std::future::pending::<()>().await;
            });
            while control.assembly.try_lock().is_ok() {
                tokio::task::yield_now().await;
            }

            let changer = Arc::clone(&control);
            tokio::spawn(
                async move { changer.add_button_rule("cut.example", Action::Block).await },
            );
            while control.pending.available_permits() == MAX_PENDING_CHANGES {
                tokio::task::yield_now().await;
            }
        });
        drop(runtime);

        assert_eq!(policy.view(std::time::Instant::now()).generation, 0);
        let rules = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(control.with_button_rules(<[ButtonRule]>::len));
        assert_eq!(rules, 0);
        assert!(!dir.path().join(crate::settings::FILE_NAME).exists());
        assert_eq!(control.pending.available_permits(), MAX_PENDING_CHANGES);
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
