use std::fmt::Arguments;
use std::io::Write;

use log::{Level, LevelFilter, Log, Metadata, Record};

use crate::config::LogLevel;

// No timestamps: journald adds them.
struct StderrLogger;

static LOGGER: StderrLogger = StderrLogger;

impl Log for StderrLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let line = format_line(record.level(), *record.args());
            let _ = writeln!(std::io::stderr().lock(), "{line}");
        }
    }

    fn flush(&self) {}
}

pub fn init(level: LogLevel) {
    log::set_max_level(level_filter(level));
    let _ = log::set_logger(&LOGGER);
}

fn level_filter(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Error => LevelFilter::Error,

        LogLevel::Warn => LevelFilter::Warn,

        LogLevel::Info => LevelFilter::Info,

        LogLevel::Debug => LevelFilter::Debug,

        LogLevel::Trace => LevelFilter::Trace,
    }
}

fn format_line(level: Level, message: Arguments) -> String {
    format!("{level} {message}")
}
