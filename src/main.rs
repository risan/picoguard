use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use picoguard::config::Config;
use picoguard::filter::compile::CompileWorker;
use picoguard::filter::snapshot::SnapshotStore;
use picoguard::lists::{Downloader, resolver_over};
use picoguard::pipeline::Pipeline;
use picoguard::scheduler::{Scheduler, Timing};
use picoguard::server::{self, Listeners};
use picoguard::upstream::tls::Tls;
use picoguard::web::{self, Web, WebListeners};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::oneshot;
use tokio::time::Instant;

const DEFAULT_CONFIG_PATH: &str = "/etc/picoguard/picoguard.toml";
/// After SIGTERM or SIGINT: how long the refresh in progress and the snapshot writer may take
/// to finish before the process exits anyway.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(10);

const USAGE: &str = "\
Usage: picoguard [OPTIONS]

Options:
  -c, --config FILE  Config file (default: /etc/picoguard/picoguard.toml)
      --check        Load and validate the config, print OK or the error, then exit
      --version      Print the version
  -h, --help         Print this help";

#[derive(Debug, PartialEq)]
enum Command {
    Run { config_path: PathBuf },
    Check { config_path: PathBuf },
    Version,
    Help,
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut args = args.into_iter();
    let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    let mut check = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("{arg} needs a file argument"))?;
                config_path = PathBuf::from(value);
            }

            "--check" => {
                check = true;
            }

            "--version" => {
                return Ok(Command::Version);
            }

            "-h" | "--help" => {
                return Ok(Command::Help);
            }

            _ => {
                return Err(format!("unknown argument {arg}"));
            }
        }
    }

    if check {
        return Ok(Command::Check { config_path });
    }

    Ok(Command::Run { config_path })
}

fn main() -> ExitCode {
    match parse_args(std::env::args().skip(1)) {
        Ok(Command::Run { config_path }) => run(&config_path),

        Ok(Command::Check { config_path }) => check(&config_path),

        Ok(Command::Version) => {
            println!("picoguard {}", env!("CARGO_PKG_VERSION"));

            ExitCode::SUCCESS
        }

        Ok(Command::Help) => {
            println!("{USAGE}");

            ExitCode::SUCCESS
        }

        Err(message) => {
            eprintln!("picoguard: {message}\n\n{USAGE}");

            ExitCode::from(2)
        }
    }
}

fn check(config_path: &Path) -> ExitCode {
    match Config::load(config_path) {
        Ok(_) => {
            println!("OK");

            ExitCode::SUCCESS
        }

        Err(error) => {
            eprintln!("{error}");

            ExitCode::FAILURE
        }
    }
}

fn run(config_path: &Path) -> ExitCode {
    let config = match Config::load(config_path) {
        Ok(config) => config,

        Err(error) => {
            eprintln!("{error}");

            return ExitCode::FAILURE;
        }
    };

    picoguard::log::init(config.log.level);
    log::info!(
        "picoguard {} loaded {}",
        env!("CARGO_PKG_VERSION"),
        config_path.display()
    );

    if let Err(message) = serve(config) {
        log::error!("{message}");

        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

fn serve(config: Config) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("cannot start the runtime: {error}"))?;

    run_to_shutdown(runtime, async {
        let worker = CompileWorker::spawn()
            .map_err(|error| format!("cannot start the compile worker: {error}"))?;
        let store = if config.state.persist_lists {
            SnapshotStore::open(&config.state.dir)
                .map_err(|error| format!("cannot start the snapshot writer: {error}"))?
        } else {
            SnapshotStore::disabled()
        };
        let store = Arc::new(store);
        let scheduler =
            Scheduler::boot(&config, worker, Arc::clone(&store), Timing::default()).await?;
        let pipeline = Pipeline::new(&config, scheduler.policy())?;
        let listeners = Listeners::bind(&config.server)?;
        let status_page = if config.web.enabled {
            Some(WebListeners::bind(&config.web)?)
        } else {
            None
        };
        let mut stop_signals = StopSignals::install()?;

        for address in listeners.udp_addresses() {
            log::info!("listening on {address} (udp and tcp)");
        }

        if let Some(status_page) = status_page {
            for address in status_page.addresses() {
                log::info!("status page on http://{address}/");
            }

            let web = Web::new(
                &config,
                Arc::clone(pipeline.stats()),
                scheduler.policy(),
                scheduler.control(),
            )?;
            web::spawn(status_page, Arc::new(web));
        }

        let downloader = Downloader::new(
            resolver_over(Arc::clone(pipeline.upstreams())),
            Arc::new(Tls::with_webpki_roots()),
        );
        let (stop_refreshing, stopped) = oneshot::channel::<()>();
        let mut refreshing = tokio::spawn(scheduler.run(downloader, async {
            let _ = stopped.await;
        }));
        server::spawn(listeners, pipeline, &config);

        stop_signals.received().await;
        log::info!("stopping");
        let _ = stop_refreshing.send(());

        let deadline = Instant::now() + SHUTDOWN_WAIT;
        if tokio::time::timeout_at(deadline, &mut refreshing)
            .await
            .is_err()
        {
            log::warn!("the list refresh did not finish in time, stopping it");
            refreshing.abort();
        }

        let writer_wait = deadline.saturating_duration_since(Instant::now());
        if !store.drain(writer_wait).await {
            log::warn!("the snapshot writer did not finish in time");
        }

        Ok(deadline)
    })
}

/// Runs `work` to completion; it returns the moment by which the process must be gone.
/// Dropping the runtime would wait for every blocking task, however long (a list on a hung
/// disk), so it is stopped with what is left of that allowance and the stuck threads are
/// left behind.
fn run_to_shutdown(
    runtime: tokio::runtime::Runtime,
    work: impl std::future::Future<Output = Result<Instant, String>>,
) -> Result<(), String> {
    let outcome = runtime.block_on(work);
    let deadline = match &outcome {
        Ok(deadline) => *deadline,
        Err(_) => Instant::now() + SHUTDOWN_WAIT,
    };

    runtime.shutdown_timeout(deadline.saturating_duration_since(Instant::now()));

    outcome.map(|_| ())
}

/// SIGTERM (the service manager) and SIGINT (Ctrl-C).
struct StopSignals {
    terminate: Signal,
    interrupt: Signal,
}

impl StopSignals {
    fn install() -> Result<StopSignals, String> {
        let install =
            |kind| signal(kind).map_err(|error| format!("cannot listen for signals: {error}"));

        Ok(StopSignals {
            terminate: install(SignalKind::terminate())?,
            interrupt: install(SignalKind::interrupt())?,
        })
    }

    async fn received(&mut self) {
        tokio::select! {
            _ = self.terminate.recv() => {}
            _ = self.interrupt.recv() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;

    fn parse(args: &[&str]) -> Result<Command, String> {
        parse_args(args.iter().map(|arg| arg.to_string()))
    }

    fn default_path() -> PathBuf {
        PathBuf::from(DEFAULT_CONFIG_PATH)
    }

    #[test]
    fn no_arguments_runs_with_the_default_config() {
        assert_eq!(
            parse(&[]),
            Ok(Command::Run {
                config_path: default_path()
            })
        );
    }

    #[test]
    fn config_flag_sets_the_path_in_both_spellings() {
        for flag in ["-c", "--config"] {
            assert_eq!(
                parse(&[flag, "/tmp/a.toml"]),
                Ok(Command::Run {
                    config_path: PathBuf::from("/tmp/a.toml")
                })
            );
        }
    }

    #[test]
    fn check_keeps_the_default_path() {
        assert_eq!(
            parse(&["--check"]),
            Ok(Command::Check {
                config_path: default_path()
            })
        );
    }

    #[test]
    fn check_and_config_combine_in_any_order() {
        let expected = Ok(Command::Check {
            config_path: PathBuf::from("/tmp/a.toml"),
        });

        assert_eq!(parse(&["--check", "-c", "/tmp/a.toml"]), expected);
        assert_eq!(parse(&["-c", "/tmp/a.toml", "--check"]), expected);
    }

    #[test]
    fn version_and_help_are_recognized() {
        assert_eq!(parse(&["--version"]), Ok(Command::Version));
        assert_eq!(parse(&["--help"]), Ok(Command::Help));
        assert_eq!(parse(&["-h"]), Ok(Command::Help));
    }

    #[test]
    fn unknown_argument_is_an_error() {
        assert_eq!(
            parse(&["--frobnicate"]),
            Err("unknown argument --frobnicate".to_string())
        );
    }

    #[test]
    fn config_flag_without_value_is_an_error() {
        assert_eq!(
            parse(&["--config"]),
            Err("--config needs a file argument".to_string())
        );
    }

    #[test]
    fn a_blocking_task_that_never_returns_does_not_hold_the_runtime_past_the_deadline() {
        let (done, finished) = mpsc::channel();

        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let outcome = run_to_shutdown(runtime, async {
                // Like a local list that is a pipe nobody writes to.
                let (keep_open, never_sent) = mpsc::channel::<()>();
                std::mem::forget(keep_open);
                tokio::task::spawn_blocking(move || never_sent.recv());
                tokio::time::sleep(Duration::from_millis(50)).await;

                Ok(Instant::now() + Duration::from_millis(300))
            });
            let _ = done.send(outcome);
        });

        let outcome = finished.recv_timeout(Duration::from_secs(5));

        assert_eq!(outcome, Ok(Ok(())));
    }
}
