//! What a handler knows about the request it answers, and how it fails.
//!
//! [`Caller`] is who calls: what `authenticate` proved, refined when a handler checks a Config ID's login.
//! [`Call`] is the rest a handler reads besides its typed parameters: what the client accepts, the client's address and
//! the request's event. [`Fault`] is an error answer, which [`fault_response!`] turns into each operation's typed
//! response.

use std::net::SocketAddr;
use std::sync::{Mutex, PoisonError};

use super::api::operations::responses;
use super::api::{self, types};
use super::auth::Role;

/// A value a handler sets on the request it answers (`Send + Sync`, unlike `Cell`).
#[derive(Debug, Default)]
pub(super) struct Slot<T>(Mutex<T>);

impl<T: Clone> Slot<T> {
    pub(super) fn new(value: T) -> Self {
        Slot(Mutex::new(value))
    }

    pub(super) fn get(&self) -> T {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    pub(super) fn set(&self, value: T) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = value;
    }
}

/// Who is calling: the `Api::Principal`.
#[derive(Debug, Default)]
pub(crate) struct Caller {
    /// What the caller has proven, refined when a handler accepts a Config ID's login.
    pub role: Slot<Role>,
    /// Basic Auth credentials, when sent.
    pub credentials: Option<(String, String)>,
    /// A key whose valid login is disabled (answered with 403).
    pub disabled_key: Slot<Option<String>>,
}

/// The request as a handler sees it beside its parameters.
pub(super) struct Call<'a> {
    pub caller: &'a Caller,
    /// The client asked for (or sent) JSON: errors and results are JSON.
    pub json: bool,
    /// The client accepts HTML (or sent `text/*`): notification logs are an HTML list.
    pub html: bool,
    /// The client asked for a live stream (`Accept: text/event-stream`).
    pub event_stream: bool,
    /// The body's media type, lower case, without parameters.
    pub content_type: String,
    /// The body's size in bytes.
    pub body_len: usize,
    pub remote: Option<SocketAddr>,
    event: &'a api::server::RequestEvent,
}

/// Whoever no authentication step found: never the case, as `authenticate` always finds a [`Caller`].
static NOBODY: std::sync::LazyLock<Caller> = std::sync::LazyLock::new(Caller::default);

impl<'a> Call<'a> {
    pub(super) fn new(ctx: &'a api::server::Context<'_, Option<std::sync::Arc<Caller>>>) -> Self {
        let header = |name: &str| ctx.headers().get(name).and_then(|v| v.to_str().ok());
        let accept = header("accept").map(str::trim).filter(|a| !a.is_empty());
        let content_type = media_type(header("content-type").unwrap_or(""));
        let html_from = accept.map_or(content_type.as_str(), |a| a).to_ascii_lowercase();
        Call {
            caller: ctx.principal.as_deref().unwrap_or(&NOBODY),
            json: wants_json(accept, &content_type),
            html: html_from.contains("text/*") || html_from.contains("text/html"),
            event_stream: accept.is_some_and(|a| a.split(',').any(|m| media_type(m) == "text/event-stream")),
            remote: ctx.peer(),
            event: ctx.event,
            content_type,
            body_len: ctx.request.body().len(),
        }
    }

    /// Adds a field to the request's event (see `docs/book/src/server.md`).
    pub(super) fn note(&self, key: &'static str, value: impl serde::Serialize) {
        self.event.set(api::EventKey::new(key), value);
    }

    /// The client's address, as the webhook and the logs show it.
    pub(super) fn remote_ip(&self) -> String {
        self.remote.map(|a| a.ip().to_string()).unwrap_or_default()
    }

    /// An error answer in the format the client reads.
    pub(super) fn fail(&self, f: Fault) -> Fault {
        self.note("fault", &f.message);
        Fault { json: self.json, ..f }
    }
}

/// A media type without parameters, lower case.
pub(super) fn media_type(value: &str) -> String {
    value.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

/// Either an `Accept` asking for JSON or a missing / wildcard `Accept` on a request with a JSON body.
pub(super) fn wants_json(accept: Option<&str>, content_type: &str) -> bool {
    let accept = accept.unwrap_or("");
    let accept_all = matches!(accept.trim(), "" | "*/*");
    is_json_mime(accept) || (accept_all && is_json_mime(content_type))
}

/// `(text|application)/(x-)?json` at the start of `s`.
pub(super) fn is_json_mime(s: &str) -> bool {
    let s = s.trim_start().to_ascii_lowercase();
    ["text/json", "text/x-json", "application/json", "application/x-json"].iter().any(|m| s.starts_with(m))
}

/// A loose boolean: the first character decides (`y`, `1`, `t`, `e`, `a`, `+` are true).
pub(super) fn parse_bool(value: Option<&str>, default: bool) -> bool {
    match value.map(|v| v.trim().to_ascii_lowercase()) {
        Some(v) if !v.is_empty() => matches!(v.as_bytes().first(), Some(b'a' | b'y' | b'1' | b't' | b'e' | b'+')),
        _ => default,
    }
}

/// An error answer: status, message, the field at fault, and what the status needs (`WWW-Authenticate` for 401,
/// `Retry-After` for 503).
#[derive(Debug, Clone)]
pub(crate) struct Fault {
    pub status: u16,
    pub message: String,
    pub field: Option<&'static str>,
    /// The `WWW-Authenticate` challenge of a 401.
    pub challenge: String,
    /// `Retry-After` seconds of a 503.
    pub retry_after: i64,
    /// `{"error": ...}` rather than text.
    pub json: bool,
}

impl Fault {
    pub(super) fn new(status: u16, message: impl Into<String>) -> Fault {
        Fault { status, message: message.into(), field: None, challenge: String::new(), retry_after: 1, json: false }
    }

    #[must_use]
    pub(super) fn field(self, field: &'static str) -> Fault {
        Fault { field: Some(field), ..self }
    }

    /// A 401 with its `WWW-Authenticate` challenge for `realm`.
    pub(super) fn unauthorized(realm: &str) -> Fault {
        Fault { challenge: format!("Basic realm=\"{realm}\""), ..Fault::new(401, "Access Denied") }
    }

    #[must_use]
    pub(super) fn retry_after(self, seconds: i64) -> Fault {
        Fault { retry_after: seconds, ..self }
    }

    /// The body of the shared `Error` response.
    pub(super) fn body(&self) -> responses::Error {
        if self.json {
            responses::Error::Json(types::Error { error: self.message.clone(), field: self.field.map(str::to_owned) })
        } else {
            responses::Error::Plain(self.message.clone())
        }
    }
}

/// `impl From<Fault>` for an operation's `Response`: each status the operation declares maps to its variant, and
/// any other status to `$other`.
macro_rules! fault_response {
    ($op:ident: $($status:literal => $variant:ident),* ; other => $other:ident) => {
        impl From<$crate::serve::call::Fault> for $crate::serve::api::operations::$op::Response {
            fn from(f: $crate::serve::call::Fault) -> Self {
                use $crate::serve::api::operations::$op::Response;
                match f.status {
                    401 => Response::Unauthorized { body: f.body(), www_authenticate: f.challenge.clone() },
                    $($status => Response::$variant(f.body()),)*
                    _ => Response::$other(f.body()),
                }
            }
        }
    };
}
pub(crate) use fault_response;
