//! Service fixtures: each `tests/fixtures/services/<service>.json` lists cases (a URL, a message, scripted responses). `record_fixture` (behind the `testing` feature) returns what mercurio did for every case. The integration tests snapshot that with `insta` (`cargo insta review` after a change).
//!
//! ```json
//! {
//!   "pipeline": {"url": "gotify://host/token"},
//!   "cases": [
//!     {
//!       "name": "basic",
//!       "url": "gotify://host/token",
//!       "title": "t", "body": "b", "type": "info", "format": "markdown",
//!       "attachments": [{"name": "a.png", "b64": "..."}],
//!       "responses": [{"status": 200, "body": "{}"}],
//!       "ignore": ["json:/timestamp", "header:date", "query:ts", "form:nonce"]
//!     }
//!   ]
//! }
//! ```
//!
//! The service is the file name up to `__`. A case without `title`, `body` or `type` gets `Mercurio Title`, `Mercurio Body`, `info` (a top-level `defaults` object overrides them; `asset` overrides the app identity). `pipeline` adds the formatting and overflow cases of `tests/fixtures/pipeline.json`, run on its `url` with its other fields. HTTP services record their requests; services speaking another protocol (SMTP, SMPP, MQTT, IRC, APRS, syslog, XMPP, desktop commands) record events through the comparator registered in `events`. Multi-send cases (`"sends": N` or `"messages": [{title, body, type}]`) notify one target repeatedly and record each send.
//!
//! `ignore` entries replace changing values with `<ignored>`:
//!
//! | entry | masks |
//! |---|---|
//! | `json:/a/*/b` | JSON body value at a pointer (`*` = any key/index) |
//! | `header:name` | a request header |
//! | `query:key` | a URL query parameter |
//! | `path:3`, `path:-1` | a URL path segment (0-based; negative counts from the end) |
//! | `path~regex` | every regex match in the URL path |
//! | `form:key` / `part:name` | a form field / multipart part |
//! | `text` / `bytes` | the whole text / binary body |
//! | `events:/0/send` | an event value at a pointer |

pub mod desktop;
pub mod events;
mod runner;
pub mod socket;
pub mod stream;

pub use runner::*;
