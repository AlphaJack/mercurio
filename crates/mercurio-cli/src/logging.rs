//! One `tracing` subscriber for every command; the library's `log` records reach it through `tracing-log`.

use std::fmt;

use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

/// Log to stderr at the `-v` level. `serve` keeps the timestamped `tracing` format plus one `request` event per request at INFO; the other commands print `LEVEL - message` lines.
pub fn init(verbose: u8, serve: bool) {
    let level = match verbose {
        0 => LevelFilter::ERROR,
        1 => LevelFilter::WARN,
        2 => LevelFilter::INFO,
        3 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };
    let filter = Targets::new().with_default(level);
    let output = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    let result = if serve {
        let filter = filter.with_target("request", LevelFilter::INFO);
        tracing_subscriber::registry().with(output).with(filter).try_init()
    } else {
        tracing_subscriber::registry().with(output.event_format(Plain)).with(filter).try_init()
    };
    if let Err(e) = result {
        errln!("logging: {e}");
    }
}

/// `WARNING - message`: the CLI's line format.
struct Plain;

impl<S, N> FormatEvent<S, N> for Plain
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(&self, ctx: &FmtContext<'_, S, N>, mut writer: Writer<'_>, event: &Event<'_>) -> fmt::Result {
        let tag = match *event.metadata().level() {
            Level::ERROR => "ERROR",
            Level::WARN => "WARNING",
            Level::INFO => "INFO",
            Level::DEBUG => "DEBUG",
            Level::TRACE => "TRACE",
        };
        write!(writer, "{tag} - ")?;
        ctx.format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}
