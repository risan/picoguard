use std::path::{Path, PathBuf};
use std::process::ExitCode;

use picoguard::config::Config;

const DEFAULT_CONFIG_PATH: &str = "/etc/picoguard/picoguard.toml";
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
            "--version" => return Ok(Command::Version),
            "-h" | "--help" => return Ok(Command::Help),
            _ => return Err(format!("unknown argument {arg}")),
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

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
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
}
