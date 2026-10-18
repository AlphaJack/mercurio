//! Minimal stderr logger driven by `-v` count.

use log::{Level, LevelFilter, Log, Metadata, Record};

struct Stderr;

impl Log for Stderr {
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let tag = match record.level() {
                Level::Error => "ERROR",
                Level::Warn => "WARNING",
                Level::Info => "INFO",
                Level::Debug => "DEBUG",
                Level::Trace => "TRACE",
            };
            errln!("{tag} - {}", record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: Stderr = Stderr;

pub fn init(verbose: u8) {
    let level = match verbose {
        0 => LevelFilter::Error,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(level);
    }
}
