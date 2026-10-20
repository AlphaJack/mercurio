//! One `tracing` subscriber for every command; the library's `log` records reach it through `tracing-log`.

use std::fmt;
use std::sync::Arc;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

/// Receives the library's log lines of one `serve` request: level and message, as they happen.
pub type Sink = Arc<dyn Fn(Level, String) + Send + Sync>;

tokio::task_local! {
    static SINK: Sink;
}

/// Run `fut` with the library's log lines (DEBUG and up) also going to `sink`; they still reach stderr at the `-v` level. Delivery runs inside the calling task, so the lines are this request's.
pub async fn capture<F: Future>(sink: Sink, fut: F) -> F::Output {
    SINK.scope(sink, fut).await
}

/// The binary's own modules: they share the library's `mercurio` crate name but are not library lines.
const BINARY_MODULES: [&str; 3] = ["mercurio::serve", "mercurio::storage", "mercurio::logging"];

/// Hands library events to the current request's [`Sink`], if any.
struct Capture;

impl<S: Subscriber> Layer<S> for Capture {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        // Library lines arrive from `log` (target `log`, the real one in `log.target`).
        if event.metadata().target() != "log" {
            return;
        }
        if SINK.try_with(|_| ()).is_err() {
            return;
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        let library = fields.target == "mercurio" || fields.target.starts_with("mercurio::");
        if !library || BINARY_MODULES.iter().any(|m| fields.target.starts_with(m)) {
            return;
        }
        let level = *event.metadata().level();
        SINK.with(|sink| sink(level, fields.message));
    }
}

/// The `message` and `log.target` of a `log` record.
#[derive(Default)]
struct Fields {
    message: String,
    target: String,
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "log.target" {
            self.target = value.to_string();
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }
}

/// How the log looks on stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// `LEVEL - message` lines (every command but `serve`).
    Cli,
    /// `serve`: timestamped `tracing` lines.
    Server,
    /// `serve --log-format json`: one JSON object per line, fields included.
    Json,
}

/// Log to stderr at the `-v` level. `serve` adds one `request` event per request at INFO and hands library lines to the request that caused them ([`capture`]).
pub fn init(verbose: u8, style: Style) {
    let level = match verbose {
        0 => LevelFilter::ERROR,
        1 => LevelFilter::WARN,
        2 => LevelFilter::INFO,
        3 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };
    let filter = Targets::new().with_default(level);
    let output = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    let server = filter.clone().with_target("request", LevelFilter::INFO);
    // `Capture` hands library lines to the request that caused them, whatever the `-v` level.
    let result = match style {
        Style::Server => tracing_subscriber::registry()
            .with(output.with_filter(server))
            .with(Capture.with_filter(LevelFilter::DEBUG))
            .try_init(),
        Style::Json => tracing_subscriber::registry()
            .with(output.json().flatten_event(true).with_current_span(false).with_span_list(false).with_filter(server))
            .with(Capture.with_filter(LevelFilter::DEBUG))
            .try_init(),
        Style::Cli => tracing_subscriber::registry().with(output.event_format(Plain)).with(filter).try_init(),
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
