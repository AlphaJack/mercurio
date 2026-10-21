//! # mercurio
//!
#![doc = env!("CARGO_PKG_DESCRIPTION")]
//!
//! Services are addressed by URL scheme and query parameters. They can be grouped in configuration files (TEXT and YAML) with tags and `${NAME}` templates. The default API is async on tokio ([`AsyncMercurio`]); [`Mercurio`] is the blocking one. The core is sans-IO, so any [`AsyncTransport`] or [`Transport`] (another runtime, wasm, a proxy, a test double) can drive it.
//!
//! ## Quick start
//!
//! ```no_run
//! # async fn run() -> Result<(), mercurio::Error> {
//! use mercurio::{AsyncMercurio, Message, NotifyType};
//!
//! let mut m = AsyncMercurio::new();
//! m.add("ntfy://my-topic")?;
//! m.add("discord://webhook_id/webhook_token")?;
//! let msg = Message::new("Disk almost full").title("server-1").kind(NotifyType::Warning);
//! let report = m.notify(&msg).await;
//! for (entry, outcome) in report.failures() {
//!     eprintln!("{}: {:?}", entry.label, outcome.result);
//! }
//! m.close().await;
//! # Ok(()) }
//! ```
//!
//! `AsyncMercurio` works on any runtime and spawns nothing. One `notify` call sends to its targets concurrently inside the calling task (at most 128 sends in flight across the process), so it uses one thread; spawn several calls to use more cores. [`AsyncMercurio::new`] does its I/O on tokio and rustls with an in-house HTTP/1.1 client ([`TokioTransport`], feature `transport-tokio`); [`AsyncMercurio::with_transport`] takes any [`AsyncTransport`].
//!
//! `notify` never panics and never returns early: every URL gets a [`ReportEntry`] in the [`Report`], with one [`Outcome`] per target and every [`Attempt`] made (more than one with `?retry=`). [`Report::status`] sums it up as a [`Status`].
//!
//! ## Architecture
//!
//! 1. **Parse.** [`parse()`] splits a URL into a [`ParsedUrl`] (lenient: tokens may contain `:`, `/` or `@`), finds the [`ServiceDef`] for the scheme ([`service_for_scheme`]) and calls its parser. The parser validates the URL and returns a typed [`Notify`] value, wrapped in a [`Target`].
//! 2. **Prepare.** [`Target::prepare`] runs the message pipeline: payload cap, escapes, format conversion ([`NotifyFormat`]), title merging and overflow handling ([`OverflowMode`]: `upstream`, `truncate`, `split`). The result is one or more [`Prepared`] pieces.
//! 3. **Plan.** [`Notify::plan`] turns each piece into a [`Plan`]: HTTP requests with continuations that inspect the responses, socket sessions, datagrams, local commands. No I/O happens here ([`Target::plan`] does steps 2 and 3).
//! 4. **Execute.** [`Target::deliver_async`] walks the plan on an [`AsyncTransport`] ([`TokioTransport`] by default) and [`Target::deliver`] on a blocking [`Transport`] (`BlockingTransport`, [`testing::FakeTransport`] in tests, or your own), both with `?retry=` / `?wait=` handling based on [`ErrorClass`].
//!
//! Around this core:
//!
//! - Runtime services: a per-notifier [`Registry`], with [`Registry::register_scheme`] for a closure and [`Registry::register`] for a full [`ServiceDef`].
//! - Configuration: [`Config`] loads TEXT and YAML files from paths, `http(s)://` or memory, with `include`, tags and [`TemplateVars`].
//! - Tags: [`Tag`] and [`TagFilter`] (`all`, `always`, AND/OR groups).
//! - [`store`]: the per-target [`PersistentStore`](store::PersistentStore) (tokens, sessions, delivery tracking).
//! - Attachments: [`AttachmentSet`] loads files, `http(s)://` and `memory://` sources into [`Attachment`]s.
//! - [`Asset`]: branding (`app_id`, colours, images) and pipeline defaults.
//!
//! ## Sans-IO: plans without a network
//!
//! A [`Target`] builds its [`Plan`] without sending anything. The plan is a plain value: inspect it or hand it to any transport. [`testing::FakeTransport`] records every request and answers from a script:
//!
//! ```
//! use mercurio::testing::FakeTransport;
//! use mercurio::{Asset, Message, service::Plan};
//!
//! let target = mercurio::parse("json://localhost/hook")?;
//! let msg = Message::new("Backup done").title("cron");
//!
//! // Build the plan: no I/O.
//! match target.plan(&msg, &Asset::default())? {
//!     Plan::Http(req, _) => assert_eq!(req.url, "http://localhost/hook"),
//!     other => panic!("unexpected plan {other:?}"),
//! }
//!
//! // Run it on a fake transport.
//! let fake = FakeTransport::new();
//! fake.respond(204, "");
//! assert!(target.send(&msg, &fake, &Asset::default()).is_success());
//! let req = fake.last_request().unwrap();
//! assert!(String::from_utf8_lossy(&req.body).contains("Backup done"));
//! # Ok::<(), mercurio::Error>(())
//! ```
//!
//! Services read the clock and randomness (timestamps, signatures, nonces, multipart boundaries) from the transport's [`Env`] too, through [`Context::env`]. [`testing::FixedEnv`] freezes both, so two runs build byte-identical requests: `FakeTransport::new().with_env(FixedEnv::new(1_700_000_000))`.
//!
//! ## Custom transport
//!
//! Implement [`AsyncTransport`] (for [`AsyncMercurio`]) or [`Transport`] (for [`Mercurio`]) to add logging, tracing, metrics, a proxy or a test double. Only `http`, `file` and `sleep` are required; `connect`, `datagram` and `command` default to [`Error::Unsupported`] and `env` to [`SystemEnv`], so a wrapper forwards them to keep e-mail, chat protocols, syslog and desktop notifications working:
//!
//! ```no_run
//! use std::sync::Arc;
//! use std::time::Duration;
//! use mercurio::{
//!     transport::AsyncConn, AsyncMercurio, transport::AsyncTransport, transport::BoxFuture, transport::Command, transport::CommandOutput, transport::Datagram, transport::Endpoint, transport::FileOp,
//!     transport::FileOutput, transport::Request, transport::Response, Result, transport::TokioTransport,
//! };
//!
//! /// Logs every operation, then lets tokio do it.
//! struct Logged(TokioTransport);
//!
//! impl AsyncTransport for Logged {
//!     fn http<'a>(&'a self, req: &'a Request) -> BoxFuture<'a, Result<Response>> {
//!         eprintln!("{} {}", req.method.as_str(), mercurio::redact_url(&req.url));
//!         self.0.http(req)
//!     }
//!     fn connect<'a>(&'a self, ep: &'a Endpoint) -> BoxFuture<'a, Result<Box<dyn AsyncConn>>> {
//!         eprintln!("connect {ep:?}");
//!         self.0.connect(ep)
//!     }
//!     fn datagram<'a>(&'a self, dg: &'a Datagram) -> BoxFuture<'a, Result<()>> {
//!         self.0.datagram(dg)
//!     }
//!     fn command<'a>(&'a self, cmd: &'a Command) -> BoxFuture<'a, Result<CommandOutput>> {
//!         eprintln!("run {}", cmd.program);
//!         self.0.command(cmd)
//!     }
//!     fn file<'a>(&'a self, op: &'a FileOp) -> BoxFuture<'a, Result<FileOutput>> {
//!         self.0.file(op)
//!     }
//!     fn sleep(&self, d: Duration) -> BoxFuture<'_, ()> {
//!         self.0.sleep(d)
//!     }
//! }
//!
//! let mut m = AsyncMercurio::with_transport(Arc::new(Logged(TokioTransport::new())));
//! m.add("mailto://user:pass@example.com")?;
//! # Ok::<(), mercurio::Error>(())
//! ```
//!
//! A `tracing` wrapper does the same with each future wrapped in a span (`Instrument::instrument`).
//!
//! ## Blocking API
//!
//! [`Mercurio`] has the same targets, configuration and reports as [`AsyncMercurio`] without a runtime: `notify` blocks until every service has answered, sending on one thread per target. `Mercurio::new` uses `BlockingTransport` (ureq + rustls), which needs the `transport-blocking` feature:
//!
//! ```toml
//! mercurio = { version = "0.1", default-features = false, features = ["all-services", "transport-blocking"] }
//! ```
//!
//! ```no_run
//! use mercurio::{Mercurio, Message};
//!
//! let mut m = Mercurio::new();
//! m.add("ntfy://my-topic")?;
//! let report = m.notify(&Message::new("Finished in 42s").title("Backup"));
//! # Ok::<(), mercurio::Error>(())
//! ```
//!
//! [`Blocking`] puts a blocking [`Transport`] behind [`AsyncTransport`]; [`AsyncMercurio`] converts from a [`Mercurio`].
//!
//! ## Custom services
//!
//! [`Registry::register_scheme`] adds a URL scheme at run time, to one notifier's [`Registry`] ([`Mercurio::registry_mut`]). The closure gets each prepared piece of the message and a [`Hook`] (parsed URL, asset, store) and returns a [`Plan`]: requests for mercurio to send, or [`Plan::Done`] when it did the work itself.
//!
//! ```
//! use mercurio::Mercurio;
//! use mercurio::service::{Plan, Request};
//!
//! let mut m = Mercurio::new();
//! m.registry_mut().register_scheme("bookhook", |msg, hook| {
//!     let channel = hook.url.text("channel").unwrap_or_else(|| "general".into());
//!     Plan::send(Request::post(format!("https://{}/notify", hook.url.host())).json(&serde_json::json!({
//!         "channel": channel,
//!         "text": format!("{}: {}", msg.title, msg.body),
//!     })))
//! })?;
//! m.add("bookhook://hooks.internal?channel=ops")?;
//! # Ok::<(), mercurio::Error>(())
//! ```
//!
//! [`Registry::register`] adds a full [`ServiceDef`] with its own URL parser, limits and [`Notify`] type, written like a built-in service. Built-in services always win. Each notifier has its own registry, so two notifiers in one process can map the same scheme to different handlers.
//!
//! ## Configuration and tags
//!
//! [`Mercurio::add_config`] loads a file or URL; [`Mercurio::add_config_text`] takes the text directly. The format (TEXT or YAML) is detected.
//!
//! ```
//! use std::sync::Arc;
//! use mercurio::testing::FakeTransport;
//! use mercurio::{Mercurio, Message, NotifyOptions, TagFilter};
//!
//! let yaml = "
//! version: 1
//! urls:
//!   - json://localhost/devops:
//!       tag: devops, critical
//!   - json://localhost/always:
//!       tag: always
//!   - json://localhost/untagged
//! ";
//! let fake = Arc::new(FakeTransport::new());
//! let mut m = Mercurio::with_transport(fake.clone());
//! assert_eq!(m.add_config_text(yaml, None)?, 3);
//!
//! // "devops" matches the devops entry; `always` joins every tagged run.
//! let report = m.notify_with(&Message::new("deploy failed"), NotifyOptions::new().tags(&TagFilter::parse("devops")));
//! assert_eq!(report.entries.len(), 2);
//!
//! // Without a tag (the CLI default) only untagged entries are notified.
//! let report = m.notify_with(&Message::new("fyi"), NotifyOptions::new().tags(&TagFilter::untagged()));
//! assert_eq!(report.entries.len(), 1);
//! # Ok::<(), mercurio::Error>(())
//! ```
//!
//! ## Testing your integration
//!
//! [`testing::FakeTransport`] works with the whole stack, so application code that sends notifications can be tested without accounts or a network:
//!
//! ```
//! use std::sync::Arc;
//! use mercurio::testing::FakeTransport;
//! use mercurio::{Mercurio, Message, Status};
//!
//! let fake = Arc::new(FakeTransport::new());
//! fake.respond(500, "server error");
//! let mut m = Mercurio::with_transport(fake.clone());
//! m.add("json://localhost/hook")?;
//! let report = m.notify(&Message::new("hi"));
//! assert_eq!(report.status(), Status::Failure);
//! assert_eq!(fake.requests().len(), 1);
//! # Ok::<(), mercurio::Error>(())
//! ```
//!
//! ## Cargo features
//!
//! Every service is compiled by default (`all-services`). Each one also has its own feature, `service-<id>`, so a build can carry only the services it uses:
//!
#![doc = include_str!(concat!(env!("OUT_DIR"), "/features.md"))]
//!
//! For a slim build, disable default features and pick services: `mercurio = { version = "0.1", default-features = false, features = ["service-telegram", "service-ntfy"] }`. Add `bundle-timezones` to keep `?tz=` zones working on hosts without a system time zone database.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(
    not(feature = "all-services"),
    allow(dead_code, unused_imports, reason = "helpers serve optional services")
)]

// Hidden modules are public only for the CLI and the integration tests; they are not a stable API. Use the re-exports below.
#[path = "asset.rs"]
mod asset_def;
mod attachment;
mod config;
mod convert;
mod crypto;
mod env;
mod error;
mod http;
mod machine;
mod message;
mod net;
mod parse;
mod plan;
mod prepare;
mod registry;
#[path = "service.rs"]
mod service_def;
mod services;
pub mod store;
mod tag;
mod target;
#[expect(clippy::unwrap_used, reason = "fakes fail loudly by design")]
#[cfg_attr(
    any(test, feature = "testing"),
    expect(clippy::expect_used, clippy::panic, reason = "fixtures fail loudly by design")
)]
pub mod testing;
mod time;
#[path = "transport.rs"]
mod transport_def;
mod url;
mod util;

#[cfg(feature = "transport-blocking")]
mod blocking;
mod mercurio_async;
mod notify;
mod report;
#[cfg(feature = "transport-tokio")]
mod tokio;

pub use attachment::{AttachSource, AttachmentSet, Cache, Location};
pub use config::template::{TemplateError, TemplateVars};
pub use config::{AssetValue, Config, ConfigFormat, ConfigOptions, ConfigService, PendingTarget};
pub use error::{Error, ErrorClass, Result};
pub use mercurio_async::AsyncMercurio;
pub use message::{Attachment, Message, NotifyFormat, NotifyType, OverflowMode};
pub use notify::{Mercurio, NotifyOptions, Selection};
pub use plan::{Delivery, Outcome, redact_url};
pub use registry::Registry;
pub use report::{Attempt, Report, ReportEntry, Status};
pub use tag::{Tag, TagFilter};
pub use target::{Target, parse, service_for_scheme, services};

pub use asset::Asset;

/// Branding and pipeline defaults: [`Asset`] and the types and constants around it.
pub mod asset {
    pub use crate::asset_def::{
        Asset, DEFAULT_STORAGE_IDLEN, ICON_PNG, ICON_SVG, IconFile, ImageSize, PAGES_URL, REPOSITORY_URL, StorageMode,
    };
}

/// Writing a service: the [`Notify`] trait, its [`ServiceDef`], the [`Plan`] it returns and the request types it builds. Add one to a notifier through its [`Registry`].
pub mod service {
    pub use crate::error::ResultExt;
    pub use crate::http::{Method, Multipart, Request, Response};
    pub use crate::message::Prepared;
    pub use crate::plan::Plan;
    pub use crate::prepare::{Piece, PreparedMessage};
    pub use crate::registry::{CustomScheme, Handler, Hook};
    pub use crate::service_def::{Context, Kind, Limits, Notify, Param, Secret, ServiceDef, UrlIdentifier};
    pub use crate::target::MAX_RETRY_AFTER;
    pub use crate::url::{COMMON_PARAMS, Pairs, ParsedUrl};
}

/// Doing the I/O: the [`Transport`] and [`AsyncTransport`] traits, the built-in transports and the operations they run.
pub mod transport {
    #[cfg(feature = "transport-blocking")]
    pub use crate::blocking::BlockingTransport;
    pub use crate::env::{Env, SystemEnv};
    pub use crate::http::{MAX_BODY, Method, Multipart, Request, Response, body_too_large};
    #[cfg(feature = "transport-tokio")]
    pub use crate::tokio::TokioTransport;
    pub(crate) use crate::transport_def::*;
    pub use crate::transport_def::{
        AsyncConn, AsyncTransport, Blocking, BoxFuture, ChannelBinding, Command, CommandOutput, Conn, Datagram,
        DatagramTarget, Endpoint, FileMeta, FileOp, FileOutput, Transport,
    };
}

// Crate-internal shorthands (`crate::Plan`, `crate::Request`, ...) for the items the modules above own.
pub(crate) use asset::*;
pub(crate) use service::*;
pub(crate) use transport::*;

/// The Cargo feature table of the crate docs, generated from `Cargo.toml` (the book's library page shows it too).
#[doc(hidden)]
pub const FEATURES_TABLE: &str = include_str!(concat!(env!("OUT_DIR"), "/features.md"));
/// Helpers for the CLI, the integration tests, `xtask` and the crate's macros. Not a stable API: anything here may change in any release.
#[doc(hidden)]
pub mod __private {
    pub use crate::config::template::{TemplateSchema, valid_name, validate_value};
    pub use crate::config::{default_paths, detect_format, expand_path, spec, yaml};
    pub use crate::crypto::{b64, b64_decode, hmac_sha256};
    pub use crate::http::{MultipartPart, multipart_parts, parse_multipart};

    /// Random bytes from the system generator.
    #[expect(clippy::disallowed_methods, reason = "for the CLI, outside any send")]
    pub fn random_bytes(buf: &mut [u8]) {
        crate::env::system().fill_random(buf);
    }

    /// Random hex from the system generator.
    #[expect(clippy::disallowed_methods, reason = "for the CLI, outside any send")]
    pub fn random_hex(n_bytes: usize) -> String {
        crate::env::system().random_hex(n_bytes)
    }
    pub use crate::message::guess_mime;
    pub use crate::parse::{parse_bool, parse_urls};
    pub use crate::time::utc_parts;
    pub use crate::url::{parse_url_unverified, unquote, unquote_plus};
    pub use regex::Regex;
}

/// The Rust code blocks of the documentation book (`docs/book/src`) run as doc-tests, so `cargo test --doc` keeps the book's examples compiling. `build.rs` lists every page.
#[cfg(doctest)]
mod book {
    include!(concat!(env!("OUT_DIR"), "/book_generated.rs"));
}
