//! # mercurio
//!
#![doc = env!("CARGO_PKG_DESCRIPTION")]
//!
//! Services are addressed by URL scheme and query parameters. They can be grouped in configuration files (TEXT and YAML) with tags and `${NAME}` templates. I/O is blocking by default; the core is sans-IO, so any [`Transport`] (async runtime, wasm, proxy, test double) can drive it.
//!
//! ## Quick start
//!
//! ```no_run
//! use mercurio::{Mercurio, Message, NotifyType};
//!
//! let mut m = Mercurio::new();
//! m.add("ntfy://my-topic")?;
//! m.add("discord://webhook_id/webhook_token")?;
//! let report = m.notify(&Message::new("Disk almost full").title("server-1").kind(NotifyType::Warning));
//! for (entry, outcome) in report.failures() {
//!     eprintln!("{}: {:?}", entry.label, outcome.result);
//! }
//! # Ok::<(), mercurio::Error>(())
//! ```
//!
//! [`Mercurio::notify`] never panics and never returns early: every URL gets a [`ReportEntry`] in the [`Report`], with one [`Outcome`] per target and every [`Attempt`] made (more than one with `?retry=`). [`Report::status`] sums it up as a [`Status`].
//!
//! ## Architecture
//!
//! 1. **Parse.** [`parse()`] splits a URL into a [`ParsedUrl`] (lenient: tokens may contain `:`, `/` or `@`), finds the [`ServiceDef`] for the scheme ([`service_for_scheme`]) and calls its parser. The parser validates the URL and returns a typed [`Notify`] value, wrapped in a [`Target`].
//! 2. **Prepare.** [`Target::prepare`] runs the message pipeline: payload cap, escapes, format conversion ([`NotifyFormat`]), title merging and overflow handling ([`OverflowMode`]: `upstream`, `truncate`, `split`). The result is one or more [`Prepared`] pieces.
//! 3. **Plan.** [`Notify::plan`] turns each piece into a [`Plan`]: HTTP requests with continuations that inspect the responses, socket sessions, datagrams, local commands. No I/O happens here ([`Target::plan`] does steps 2 and 3).
//! 4. **Execute.** [`Target::send`] walks the plan on a [`Transport`]: [`DefaultTransport`] (blocking `ureq` + rustls) by default, [`testing::FakeTransport`] in tests or your own. [`Target::deliver`] adds `?retry=` / `?wait=` handling based on [`ErrorClass`].
//!
//! Around this core:
//!
//! - Runtime services: [`register_scheme`] for a closure, [`register`] for a full [`ServiceDef`].
//! - Configuration: [`Config`] loads TEXT and YAML files from paths, `http(s)://` or memory, with `include`, tags and [`TemplateVars`].
//! - Tags: [`Tag`] and [`TagFilter`] (`all`, `always`, AND/OR groups).
//! - [`store`]: the per-target [`PersistentStore`] (tokens, sessions, delivery tracking).
//! - Attachments: [`AttachmentSet`] loads files, `http(s)://` and `memory://` sources into [`Attachment`]s.
//! - [`Asset`]: branding (`app_id`, colours, images) and pipeline defaults.
//!
//! ## Sans-IO: plans without a network
//!
//! A [`Target`] builds its [`Plan`] without sending anything. The plan is a plain value: inspect it or hand it to any transport. [`testing::FakeTransport`] records every request and answers from a script:
//!
//! ```
//! use mercurio::testing::FakeTransport;
//! use mercurio::{Asset, Message, Plan};
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
//! ## Custom transport
//!
//! Implement [`Transport::http`] (the other methods are optional: raw sockets, datagrams and local programs default to [`Error::Unsupported`]). Pass it to [`Mercurio::with_transport`].
//!
//! ```no_run
//! use std::sync::Arc;
//! use mercurio::{DefaultTransport, Mercurio, Message, Request, Response, Result, Transport};
//!
//! /// Logs every request, then delegates to the default transport.
//! #[derive(Debug)]
//! struct Logging(DefaultTransport);
//!
//! impl Transport for Logging {
//!     fn http(&self, req: &Request) -> Result<Response> {
//!         eprintln!("{} {}", req.method.as_str(), mercurio::redact_url(&req.url));
//!         self.0.http(req)
//!     }
//! }
//!
//! let mut m = Mercurio::with_transport(Arc::new(Logging(DefaultTransport::new())));
//! m.add("ntfy://my-topic")?;
//! m.notify(&Message::new("hello"));
//! # Ok::<(), mercurio::Error>(())
//! ```
//!
//! An async application can run [`Mercurio::notify`] on a blocking thread pool (`spawn_blocking`). It can also drive plans itself: walk the [`Plan`] tree and feed each [`Request`]'s [`Response`] to the continuation.
//!
//! ## Custom services
//!
//! [`Mercurio::register_scheme`] adds a URL scheme at run time. The closure gets each prepared piece of the message and a [`Hook`] (parsed URL, asset, store) and returns a [`Plan`]: requests for mercurio to send, or [`Plan::Done`] when it did the work itself.
//!
//! ```
//! use mercurio::{Mercurio, Plan, Request};
//!
//! Mercurio::register_scheme("bookhook", |msg, hook| {
//!     let channel = hook.url.text("channel").unwrap_or_else(|| "general".into());
//!     Plan::send(Request::post(format!("https://{}/notify", hook.url.host())).json(&serde_json::json!({
//!         "channel": channel,
//!         "text": format!("{}: {}", msg.title, msg.body),
//!     })))
//! })?;
//! let mut m = Mercurio::new();
//! m.add("bookhook://hooks.internal?channel=ops")?;
//! # Ok::<(), mercurio::Error>(())
//! ```
//!
//! [`register`] adds a full [`ServiceDef`] with its own URL parser, limits and [`Notify`] type, written like a built-in service (`crates/mercurio/src/services/gotify.rs` is a short one). Built-in services always win.
//!
//! ## Configuration and tags
//!
//! [`Mercurio::add_config`] loads a file or URL; [`Mercurio::add_config_text`] takes the text directly. The format (TEXT or YAML) is detected.
//!
//! ```
//! use std::sync::Arc;
//! use mercurio::testing::FakeTransport;
//! use mercurio::{Mercurio, Message, TagFilter};
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
//! let report = m.notify_tagged(&Message::new("deploy failed"), &TagFilter::parse("devops"));
//! assert_eq!(report.entries.len(), 2);
//!
//! // Without a tag (the CLI default) only untagged entries are notified.
//! let report = m.notify_tagged(&Message::new("fyi"), &TagFilter::untagged());
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
//! For a slim build, disable default features and pick services: `mercurio = { version = "0.1", default-features = false, features = ["service-telegram", "service-ntfy"] }`

#![cfg_attr(docsrs, feature(doc_cfg))]
// Shared helpers serve optional services: a build without `all-services` leaves part of the helpers unused. The default build still checks.
#![cfg_attr(
    not(feature = "all-services"),
    allow(dead_code, unused_imports, reason = "helpers serve optional services")
)]

// Hidden modules are public only for the CLI and the integration tests; they are not a stable API. Use the re-exports below.
mod asset;
#[doc(hidden)]
pub mod attachment;
#[doc(hidden)]
pub mod config;
mod convert;
#[doc(hidden)]
pub mod crypto;
mod error;
mod http;
#[doc(hidden)]
pub mod message;
mod net;
#[doc(hidden)]
pub mod parse;
#[doc(hidden)]
pub mod plan;
mod prepare;
mod registry;
mod service;
mod services;
pub mod store;
mod tag;
#[expect(clippy::unwrap_used, reason = "fakes fail loudly by design")]
#[cfg_attr(
    any(test, feature = "testing"),
    expect(clippy::expect_used, clippy::panic, reason = "fixtures fail loudly by design")
)]
pub mod testing;
mod transport;
#[doc(hidden)]
pub mod url;
mod util;

mod notify;

pub use asset::{Asset, ICON_PNG, ICON_SVG, IconFile, PAGES_URL, REPOSITORY_URL};
pub use attachment::{AttachSource, AttachmentSet};
pub use config::template::TemplateVars;
pub use config::{Config, ConfigFormat, ConfigOptions};
pub use error::{Error, ErrorClass, Result, ResultExt};
#[doc(hidden)]
pub use http::parse_multipart;
pub use http::{Method, Multipart, Request, Response};
pub use message::{Attachment, Message, NotifyFormat, NotifyType, OverflowMode, Prepared};
pub use notify::{
    Attempt, MAX_RETRY_AFTER, Mercurio, Report, ReportEntry, Selection, Status, Target, parse, service_for_scheme,
    services,
};
pub use plan::{Delivery, Outcome, Plan, redact_url};
pub use registry::{CustomScheme, Handler, Hook, register, register_scheme, unregister};

/// The Cargo feature table of the crate docs, generated from `Cargo.toml` (the book's library page shows it too).
#[doc(hidden)]
pub const FEATURES_TABLE: &str = include_str!(concat!(env!("OUT_DIR"), "/features.md"));
pub use service::{Context, Kind, Limits, Notify, Param, Secret, ServiceDef, UrlIdentifier};
pub use store::{Memo, PersistentStore, Store, StoreRef};
pub use tag::{Tag, TagFilter};
pub use transport::{DefaultTransport, Transport};
pub use url::COMMON_PARAMS;
pub use url::ParsedUrl;

#[doc(hidden)]
pub mod __private {
    pub use regex::Regex;
}

/// The Rust code blocks of the documentation book (`docs/book/src`) run as doc-tests, so `cargo test --doc` keeps the book's examples compiling. `build.rs` lists every page.
#[cfg(doctest)]
mod book {
    include!(concat!(env!("OUT_DIR"), "/book_generated.rs"));
}
