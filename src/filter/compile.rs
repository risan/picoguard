//! The compile worker: one plain thread that parses and compiles list text, loads snapshot
//! files and drops big values, so none of that runs on the DNS thread (plan D13, D20).

use std::any::Any;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc as std_mpsc;

use tokio::sync::{mpsc, oneshot};
use xxhash_rust::xxh3::Xxh3;

use super::engine::{CompiledList, ListBuilder};
use super::parse::{ListFormat, ParseSummary, Parser, Rule};
use super::snapshot::{self, Snapshot, SnapshotError};
use crate::lists::{PIECE_QUEUE, Piece, PieceSender};

/// Bump when parsing or compiling changes what a list means: snapshots written by an older
/// compiler are then ignored and the lists compile again (plan D14).
pub const COMPILER_VERSION: u32 = 2;

/// The per-list settings that change the compiled result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompileOptions {
    pub format: ListFormat,
    pub max_rules: u32,
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
        max_rules: u32,
        reply: oneshot::Sender<Result<Snapshot, SnapshotError>>,
    },
    Discard(Box<dyn Any + Send>),
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
    pub async fn load(&self, path: PathBuf, max_rules: u32) -> Result<Snapshot, SnapshotError> {
        let (reply, result) = oneshot::channel();
        let _ = self.jobs.send(Job::Load {
            path,
            max_rules,
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
        let _ = self.jobs.send(Job::Discard(Box::new(garbage)));
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
                max_rules,
                reply,
            } => {
                let _ = reply.send(snapshot::load(&path, max_rules));
            }

            Job::Discard(garbage) => {
                drop(garbage);
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
    let mut sink = |rule: Rule<'_>| builder.add(rule);

    loop {
        match pieces.blocking_recv() {
            Some(Piece::Data(bytes)) => {
                hasher.update(&bytes);
                parser.push(&bytes, &mut sink);
            }

            Some(Piece::End) => break,

            None => return Err(CompileError::Aborted),
        }
    }

    let summary = parser.finish(&mut sink);
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
        }
    }

    async fn compile_in_pieces(
        worker: &CompileWorker,
        options: CompileOptions,
        text: &[u8],
        piece_size: usize,
    ) -> Result<Compiled, CompileError> {
        let compilation = worker.start(options);
        for piece in text.chunks(piece_size) {
            compilation
                .pieces
                .send(Piece::Data(piece.to_vec()))
                .await
                .unwrap();
        }

        compilation.pieces.send(Piece::End).await.unwrap();

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
