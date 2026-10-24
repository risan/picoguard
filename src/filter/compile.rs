//! The compile worker: one plain thread that parses and compiles list text, loads snapshot
//! files and drops big values, so none of that runs on the DNS thread (plan D13, D20).

use std::cell::Cell;
use std::collections::HashSet;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc as std_mpsc;

use tokio::sync::{mpsc, oneshot};
use xxhash_rust::xxh3::{Xxh3, xxh3_128};

use super::engine::{CompiledList, Engine, ListBuilder};
use super::parse::{ListFormat, NetworkRule, ParseSummary, Parser, Rule};
use super::snapshot::{self, Snapshot, SnapshotError};
use crate::lists::{PIECE_QUEUE, Piece, PieceSender};

/// Bump on every change to compiled output (what any list text compiles to, in the parser,
/// the compiler or the snapshot encoding), however small: snapshots written by an older
/// compiler are then ignored and the lists compile again (plan D14).
pub const COMPILER_VERSION: u32 = 3;

/// Default memory budget of the slow rules of one list. Plan section 5 leaves about 8 MB
/// between the steady total (20 MB) and the refresh peak (28 MB). The real lists are far
/// below it: the AdGuard DNS filter, with 878 slow rules and 22 regexes, is estimated at 1 MB.
pub const DEFAULT_SLOW_RULE_BUDGET: usize = 8 * 1024 * 1024;

/// The per-list settings that change the compiled result (the first two) or limit it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompileOptions {
    pub format: ListFormat,
    pub max_rules: u32,
    /// Bytes the slow rules and regexes of the list may cost, as `SlowRuleBudget` estimates.
    /// A list over it fails to compile or to load; it never changes what a list means, so
    /// it is not part of the fingerprint.
    pub slow_rule_budget: usize,
}

impl CompileOptions {
    pub fn new(format: ListFormat, max_rules: u32) -> CompileOptions {
        CompileOptions {
            format,
            max_rules,
            slow_rule_budget: DEFAULT_SLOW_RULE_BUDGET,
        }
    }
}

/// Estimated bytes of a compiled slow rule: measured at 430 to 800 bytes for glob rules and
/// 3 to 20 KiB for regexes (a Unicode class such as `\p{L}` is the expensive one).
const SLOW_RULE_BYTES: usize = 512;
const TEXT_BYTE_COST: usize = 4;
const REGEX_BYTES: usize = 24 * 1024;

/// Counts the estimated memory of the slow rules of one list against a budget. Parsing and
/// snapshot loading charge the same way, so a list that compiles also loads.
pub(super) struct SlowRuleBudget {
    left: usize,
}

pub(super) struct OverBudget;

impl SlowRuleBudget {
    pub(super) fn new(total: usize) -> SlowRuleBudget {
        SlowRuleBudget { left: total }
    }

    pub(super) fn charge(&mut self, rule: &NetworkRule) -> Result<(), OverBudget> {
        let cost = slow_rule_cost(rule);
        self.left = self.left.checked_sub(cost).ok_or(OverBudget)?;

        Ok(())
    }
}

pub(super) fn slow_rule_cost(rule: &NetworkRule) -> usize {
    let text = rule.pattern.len()
        + 24 * rule.restricted_clients.nets.len()
        + rule
            .denyallow
            .iter()
            .chain(&rule.restricted_clients.names)
            .chain(&rule.restricted_ctags)
            .map(|name| name.len() + 24)
            .sum::<usize>()
        + 2 * (rule.dns_permitted.len() + rule.dns_restricted.len());
    let regex = if rule.is_regex() { REGEX_BYTES } else { 0 };

    SLOW_RULE_BYTES + TEXT_BYTE_COST * text + regex
}

pub struct Compiled {
    pub list: Arc<CompiledList>,
    pub summary: ParseSummary,
    /// xxh3-128 of the source text.
    pub content_hash: u128,
    /// Identifies this result: same text, effective format, options and compiler give the
    /// same fingerprint (plan D14).
    pub fingerprint: u128,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CompileError {
    /// The sender was dropped before `Piece::End`: the text is incomplete.
    Aborted,
    WorkerStopped,
    /// The slow rules of the list cost more than `CompileOptions::slow_rule_budget`.
    OverBudget,
}

/// A compile job that is waiting for text. Send the pieces, then `Piece::End`, then await
/// the result.
pub struct Compilation {
    pub pieces: PieceSender,
    result: oneshot::Receiver<Result<Compiled, CompileError>>,
}

impl Compilation {
    pub async fn result(self) -> Result<Compiled, CompileError> {
        drop(self.pieces);

        self.result
            .await
            .unwrap_or(Err(CompileError::WorkerStopped))
    }
}

enum Job {
    Compile {
        options: CompileOptions,
        pieces: mpsc::Receiver<Piece>,
        reply: oneshot::Sender<Result<Compiled, CompileError>>,
    },
    Load {
        path: PathBuf,
        options: CompileOptions,
        reply: oneshot::Sender<Result<Snapshot, SnapshotError>>,
    },
    Run(Box<dyn FnOnce() + Send>),
}

pub struct CompileWorker {
    jobs: std_mpsc::Sender<Job>,
}

impl CompileWorker {
    pub fn spawn() -> io::Result<CompileWorker> {
        let (jobs, queue) = std_mpsc::channel();
        std::thread::Builder::new()
            .name("picoguard-compile".to_string())
            .spawn(move || run(queue))?;

        Ok(CompileWorker { jobs })
    }

    /// Starts a compile job; the worker then waits for its pieces.
    pub fn start(&self, options: CompileOptions) -> Compilation {
        let (pieces, receiver) = mpsc::channel(PIECE_QUEUE);
        let (reply, result) = oneshot::channel();
        let _ = self.jobs.send(Job::Compile {
            options,
            pieces: receiver,
            reply,
        });

        Compilation { pieces, result }
    }

    /// Reads a snapshot file on the worker.
    pub async fn load(
        &self,
        path: PathBuf,
        options: CompileOptions,
    ) -> Result<Snapshot, SnapshotError> {
        let (reply, result) = oneshot::channel();
        let _ = self.jobs.send(Job::Load {
            path,
            options,
            reply,
        });

        result.await.unwrap_or_else(|_| {
            Err(SnapshotError::Io(io::Error::other(
                "the compile worker stopped",
            )))
        })
    }

    /// Drops `garbage` on the worker: an old engine or a replaced list has arrays of
    /// megabytes, and freeing them must not stall the DNS thread.
    pub fn discard<T: Send + 'static>(&self, garbage: T) {
        let _ = self.jobs.send(Job::Run(Box::new(move || drop(garbage))));
    }

    /// Runs `work` on the worker and returns its result.
    pub async fn run<T, F>(&self, work: F) -> Result<T, CompileError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let (reply, result) = oneshot::channel();
        let job = Job::Run(Box::new(move || {
            let _ = reply.send(work());
        }));
        self.jobs
            .send(job)
            .map_err(|_| CompileError::WorkerStopped)?;

        result.await.map_err(|_| CompileError::WorkerStopped)
    }

    /// Builds the next engine on the worker: its slow-rule scan and `$badfilter` indexes
    /// (plan D7) must not run on the DNS thread. `main` holds the lists and the user rules,
    /// `allow` the allowlists.
    pub async fn assemble(
        &self,
        main: Vec<Arc<CompiledList>>,
        allow: Vec<Arc<CompiledList>>,
    ) -> Result<Engine, CompileError> {
        self.run(move || Engine::new(main, allow)).await
    }
}

fn run(queue: std_mpsc::Receiver<Job>) {
    while let Ok(job) = queue.recv() {
        match job {
            Job::Compile {
                options,
                pieces,
                reply,
            } => {
                let _ = reply.send(compile(options, pieces));
            }

            Job::Load {
                path,
                options,
                reply,
            } => {
                let _ = reply.send(snapshot::load(&path, &options));
            }

            Job::Run(work) => {
                work();
            }
        }
    }
}

fn compile(
    options: CompileOptions,
    mut pieces: mpsc::Receiver<Piece>,
) -> Result<Compiled, CompileError> {
    let mut builder = ListBuilder::new();
    let mut parser = Parser::new(options.format, options.max_rules as usize);
    let mut hasher = Xxh3::new();
    let mut budget = SlowRuleBudget::new(options.slow_rule_budget);
    let mut seen_slow_rules = HashSet::new();
    let over_budget = Cell::new(false);
    let mut sink = |rule: Rule<'_>| {
        if over_budget.get() {
            return;
        }

        if let Rule::Slow(slow) = &rule {
            // The debug text holds every field, so equal text means an identical rule.
            if !seen_slow_rules.insert(xxh3_128(format!("{slow:?}").as_bytes())) {
                return;
            }

            if budget.charge(slow).is_err() {
                over_budget.set(true);

                return;
            }
        }

        builder.add(rule);
    };

    loop {
        match pieces.blocking_recv() {
            Some(Piece::Data(bytes)) => {
                hasher.update(&bytes);
                parser.push(&bytes, &mut sink);
                if over_budget.get() {
                    return Err(CompileError::OverBudget);
                }
            }

            Some(Piece::End) => break,

            None => return Err(CompileError::Aborted),
        }
    }

    let summary = parser.finish(&mut sink);
    if over_budget.get() {
        return Err(CompileError::OverBudget);
    }

    let content_hash = hasher.digest128();

    Ok(Compiled {
        list: Arc::new(builder.finish(summary.format)),
        fingerprint: snapshot::fingerprint(
            content_hash,
            options.format,
            summary.format,
            options.max_rules,
            COMPILER_VERSION,
        ),
        content_hash,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use std::thread::ThreadId;

    use xxhash_rust::xxh3::xxh3_128;

    use super::*;
    use crate::filter::engine::{Decision, Engine, TYPE_A};

    const LIST: &str = "||ads.example^\n@@||ok.ads.example^\n0.0.0.0 host.example\n/track[0-9]+/\n";

    fn options(format: ListFormat) -> CompileOptions {
        CompileOptions {
            format,
            max_rules: 1000,
            slow_rule_budget: DEFAULT_SLOW_RULE_BUDGET,
        }
    }

    async fn compile_in_pieces(
        worker: &CompileWorker,
        options: CompileOptions,
        text: &[u8],
        piece_size: usize,
    ) -> Result<Compiled, CompileError> {
        let compilation = worker.start(options);
        // The worker stops listening once the job has failed.
        for piece in text.chunks(piece_size) {
            if compilation
                .pieces
                .send(Piece::Data(piece.to_vec()))
                .await
                .is_err()
            {
                break;
            }
        }

        let _ = compilation.pieces.send(Piece::End).await;

        compilation.result().await
    }

    fn blocked(list: &Arc<CompiledList>, name: &str) -> bool {
        let engine = Engine::new(vec![Arc::clone(list)], Vec::new());

        matches!(engine.check(name, TYPE_A, false), Decision::Block { .. })
    }

    #[tokio::test]
    async fn pieces_of_any_size_compile_to_the_same_list() {
        let worker = CompileWorker::spawn().unwrap();
        let (expected, _) = CompiledList::from_text(ListFormat::Adblock, LIST);

        for size in [1, 3, 7, LIST.len()] {
            let compiled =
                compile_in_pieces(&worker, options(ListFormat::Auto), LIST.as_bytes(), size)
                    .await
                    .unwrap();

            assert_eq!(compiled.list.rule_count(), expected.rule_count(), "{size}");
            assert!(blocked(&compiled.list, "ads.example"), "{size}");
            assert!(blocked(&compiled.list, "x.ads.example"), "{size}");
            assert!(blocked(&compiled.list, "host.example"), "{size}");
            assert!(blocked(&compiled.list, "track77.example"), "{size}");
            assert!(!blocked(&compiled.list, "ok.ads.example"), "{size}");
            assert_eq!(compiled.summary.format, ListFormat::Adblock);
            assert_eq!(compiled.content_hash, xxh3_128(LIST.as_bytes()));
        }
    }

    #[tokio::test]
    async fn a_dropped_sender_aborts_the_job_and_the_worker_goes_on() {
        let worker = CompileWorker::spawn().unwrap();
        let compilation = worker.start(options(ListFormat::Auto));
        compilation
            .pieces
            .send(Piece::Data(b"||a.example^\n".to_vec()))
            .await
            .unwrap();

        let aborted = compilation.result().await;

        assert_eq!(aborted.err(), Some(CompileError::Aborted));
        let next =
            compile_in_pieces(&worker, options(ListFormat::Auto), LIST.as_bytes(), 100).await;
        assert!(next.is_ok());
    }

    #[tokio::test]
    async fn the_fingerprint_follows_content_effective_format_options_and_compiler() {
        let worker = CompileWorker::spawn().unwrap();
        let text = b"a.example\nb.example\n";
        let fingerprint = |options, text: &'static [u8]| {
            let worker = &worker;

            async move {
                compile_in_pieces(worker, options, text, 64)
                    .await
                    .unwrap()
                    .fingerprint
            }
        };

        let auto = fingerprint(options(ListFormat::Auto), text).await;

        assert_eq!(auto, fingerprint(options(ListFormat::Auto), text).await);
        assert_ne!(auto, fingerprint(options(ListFormat::Domains), text).await);
        assert_ne!(auto, fingerprint(options(ListFormat::Hosts), text).await);
        assert_ne!(
            auto,
            fingerprint(options(ListFormat::Auto), b"a.example\n").await
        );
        let other_cap = CompileOptions {
            max_rules: 999,
            ..options(ListFormat::Auto)
        };
        assert_ne!(auto, fingerprint(other_cap, text).await);
    }

    #[tokio::test]
    async fn explicit_format_changes_the_result_for_the_same_text() {
        let worker = CompileWorker::spawn().unwrap();
        let text = b"a.example\n";

        let adguard = compile_in_pieces(&worker, options(ListFormat::Auto), text, 64)
            .await
            .unwrap();
        let domains = compile_in_pieces(&worker, options(ListFormat::Domains), text, 64)
            .await
            .unwrap();

        assert_eq!(adguard.content_hash, domains.content_hash);
        assert_eq!(adguard.summary.format, ListFormat::Adblock);
        assert_eq!(domains.summary.format, ListFormat::Domains);
        assert_ne!(adguard.fingerprint, domains.fingerprint);
    }

    struct RecordsDropThread(std_mpsc::Sender<(ThreadId, Option<String>)>);

    impl Drop for RecordsDropThread {
        fn drop(&mut self) {
            let thread = std::thread::current();
            let _ = self
                .0
                .send((thread.id(), thread.name().map(str::to_string)));
        }
    }

    fn slow_rule_cost_of(line: &str) -> usize {
        let mut cost = None;
        let mut parser = Parser::new(ListFormat::Adblock, 10);
        let mut sink = |rule: Rule<'_>| {
            if let Rule::Slow(slow) = rule {
                cost = Some(slow_rule_cost(&slow));
            }
        };
        parser.push(line.as_bytes(), &mut sink);
        parser.finish(&mut sink);

        cost.expect("the line is a slow rule")
    }

    fn with_budget(slow_rule_budget: usize) -> CompileOptions {
        CompileOptions {
            slow_rule_budget,
            ..options(ListFormat::Adblock)
        }
    }

    #[tokio::test]
    async fn slow_rules_are_charged_against_the_budget_to_the_byte() {
        let worker = CompileWorker::spawn().unwrap();
        let cost = slow_rule_cost_of("a1*b\n");
        let lines = |count: usize| -> String { (0..count).map(|i| format!("a{i}*b\n")).collect() };

        let fits = compile_in_pieces(&worker, with_budget(3 * cost), lines(3).as_bytes(), 64).await;
        let over = compile_in_pieces(&worker, with_budget(3 * cost), lines(4).as_bytes(), 64).await;

        assert_eq!(fits.unwrap().list.slow_rule_count(), 3);
        assert_eq!(over.err(), Some(CompileError::OverBudget));
    }

    #[tokio::test]
    async fn millions_of_identical_slow_rules_cost_one_rule() {
        const COPIES: usize = 1_000_000;
        let worker = CompileWorker::spawn().unwrap();
        let text = "a*b\n".repeat(COPIES);
        let uncapped = CompileOptions {
            max_rules: COPIES as u32,
            ..options(ListFormat::Adblock)
        };

        let compiled = compile_in_pieces(&worker, uncapped, text.as_bytes(), 64 * 1024)
            .await
            .unwrap();

        assert_eq!(compiled.list.slow_rule_count(), 1);
    }

    #[tokio::test]
    async fn many_different_slow_rules_fail_the_job_within_the_default_budget() {
        let worker = CompileWorker::spawn().unwrap();
        let text: String = (0..200_000).map(|i| format!("a{i}*b\n")).collect();
        let uncapped = CompileOptions {
            max_rules: 200_000,
            ..options(ListFormat::Adblock)
        };

        let result = compile_in_pieces(&worker, uncapped, text.as_bytes(), 64 * 1024).await;

        assert_eq!(result.err(), Some(CompileError::OverBudget));
        let next = compile_in_pieces(&worker, options(ListFormat::Auto), LIST.as_bytes(), 100)
            .await
            .unwrap();
        assert!(blocked(&next.list, "ads.example"));
    }

    #[tokio::test]
    async fn many_regexes_fail_the_job_within_the_default_budget() {
        let worker = CompileWorker::spawn().unwrap();
        let text: String = (0..2000).map(|i| format!("/track{i}[0-9]+/\n")).collect();

        let result = compile_in_pieces(
            &worker,
            options(ListFormat::Adblock),
            text.as_bytes(),
            64 * 1024,
        )
        .await;

        assert_eq!(result.err(), Some(CompileError::OverBudget));
    }

    #[tokio::test]
    async fn a_list_with_a_few_hundred_slow_rules_fits_the_default_budget() {
        let worker = CompileWorker::spawn().unwrap();
        let globs: String = (0..800).map(|i| format!("||ads{i}.*.example^\n")).collect();
        let regexes: String = (0..20).map(|i| format!("/track{i}[0-9]+/\n")).collect();
        let text = format!("{globs}{regexes}");

        let compiled = compile_in_pieces(
            &worker,
            options(ListFormat::Adblock),
            text.as_bytes(),
            64 * 1024,
        )
        .await
        .unwrap();

        assert_eq!(compiled.list.slow_rule_count(), 820);
    }

    #[tokio::test]
    async fn work_runs_on_the_worker_thread_and_its_result_comes_back() {
        let worker = CompileWorker::spawn().unwrap();

        let (thread, name) = worker
            .run(|| {
                let thread = std::thread::current();
                (thread.id(), thread.name().map(str::to_string))
            })
            .await
            .unwrap();

        assert_ne!(thread, std::thread::current().id());
        assert_eq!(name.as_deref(), Some("picoguard-compile"));
    }

    #[tokio::test]
    async fn an_assembled_engine_decides_like_one_built_in_place() {
        let worker = CompileWorker::spawn().unwrap();
        let blocklist = compile_in_pieces(
            &worker,
            options(ListFormat::Auto),
            b"||ads.example^\n||both.example^\n||bad.example^\n||bad.example^$badfilter\n",
            64,
        )
        .await
        .unwrap();
        let user_rules =
            compile_in_pieces(&worker, options(ListFormat::Auto), b"||mine.example^\n", 64)
                .await
                .unwrap();
        let allowlist =
            compile_in_pieces(&worker, options(ListFormat::Auto), b"||both.example^\n", 64)
                .await
                .unwrap();
        let main = vec![Arc::clone(&blocklist.list), Arc::clone(&user_rules.list)];
        let allow = vec![Arc::clone(&allowlist.list)];
        let in_place = Engine::new(main.clone(), allow.clone());

        let assembled = worker.assemble(main, allow).await.unwrap();

        for name in ["ads.example", "mine.example", "both.example", "bad.example"] {
            assert_eq!(
                assembled.check(name, TYPE_A, false),
                in_place.check(name, TYPE_A, false),
                "{name}"
            );
        }

        assert!(matches!(
            assembled.check("mine.example", TYPE_A, false),
            Decision::Block { .. }
        ));
        assert_eq!(
            assembled.check("both.example", TYPE_A, false),
            Decision::Pass
        );
        assert_eq!(
            assembled.check("bad.example", TYPE_A, false),
            Decision::Pass
        );
    }

    #[test]
    fn discarded_values_are_dropped_on_the_worker_thread() {
        let worker = CompileWorker::spawn().unwrap();
        let (sender, receiver) = std_mpsc::channel();

        worker.discard(RecordsDropThread(sender));

        let (thread, name) = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert_ne!(thread, std::thread::current().id());
        assert_eq!(name.as_deref(), Some("picoguard-compile"));
    }
}
