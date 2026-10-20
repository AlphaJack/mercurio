//! Request and response plumbing between axum and the handlers.
//!
//! Header values are read as UTF-8 (clients send UTF-8 titles in `X-Apprise-Title`). Values that are not valid UTF-8 are read as Latin-1.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use axum::RequestExt;
use http_body_util::{BodyExt, LengthLimitError};
use mercurio::__private::unquote_plus;
use serde_json::{Value, json};

/// Largest request body read: one attachment of `attach_size` bytes plus the other fields, and never less than [`MIN_BODY`].
pub fn body_limit(attach_size: u64) -> usize {
    usize::try_from(attach_size).unwrap_or(usize::MAX).saturating_add(FIELDS_ALLOWANCE).max(MIN_BODY)
}
/// Room a request body keeps for its fields beside an upload.
const FIELDS_ALLOWANCE: usize = 1024 * 1024;
/// The body limit when attachments are off or small.
const MIN_BODY: usize = 8 * 1024 * 1024;
/// The most a body buffer is sized by `Content-Length` before any byte arrives.
const PREALLOC_MAX: usize = 256 * 1024 * 1024;
/// How long a client may take to send a request head (and how long an idle connection stays open), and each piece of its body.
pub const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A value a handler sets on the request it is answering (`Send + Sync`, unlike `Cell`).
#[derive(Default)]
pub struct Slot<T>(Mutex<T>);

impl<T: Clone> Slot<T> {
    pub fn get(&self) -> T {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    pub fn set(&self, value: T) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = value;
    }
}

/// What one request did, beyond what its head and status say: handlers fill it in, `observe` logs it as one event.
#[derive(Debug, Default)]
pub struct RequestEvent {
    /// The Config ID used.
    pub key: Option<String>,
    /// Services notified, and how many of them failed.
    pub services: Option<usize>,
    pub failed: Option<usize>,
    /// The answer is a live stream; its results are not part of the event.
    pub stream: bool,
    /// The message of an error answer.
    pub error: Option<String>,
    /// What went wrong without failing the request (a skipped URL, an unreadable configuration).
    pub detail: Vec<String>,
}

impl RequestEvent {
    pub fn shared() -> Arc<Mutex<RequestEvent>> {
        Arc::default()
    }
}

pub struct Req {
    pub method: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    /// Read into one buffer, so a body that is only text can become its `String` without a copy ([`Req::take_body`]).
    body: Mutex<Vec<u8>>,
    pub remote: String,
    /// Who this request has proven to be.
    pub role: Slot<super::auth::Role>,
    /// A key whose valid login is disabled (answered with 403).
    pub disabled_key: Slot<Option<String>>,
    /// The event `observe` logs for this request.
    pub event: Arc<Mutex<RequestEvent>>,
}

/// The request as the handlers see it, with the role [`super::router`]'s gate proved. The body limit is axum's `DefaultBodyLimit` (413 beyond); a body that can not be read gets axum's rejection, and the connection is closed.
impl<S: Send + Sync> axum::extract::FromRequest<S> for Req {
    type Rejection = Reply;

    async fn from_request(request: axum::extract::Request, _: &S) -> Result<Req, Reply> {
        let remote = request.extensions().get::<axum::extract::ConnectInfo<SocketAddr>>().map(|c| c.0.ip().to_string());
        let role = request.extensions().get::<super::auth::Role>().copied().unwrap_or_default();
        let event = request.extensions().get::<Arc<Mutex<RequestEvent>>>().cloned().unwrap_or_default();
        let method = request.method().as_str().to_ascii_uppercase();
        let query = form_pairs(request.uri().query().unwrap_or(""));
        let headers =
            request.headers().iter().map(|(k, v)| (k.as_str().to_string(), decode_header(v.as_bytes()))).collect();
        let length: usize = request
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        // Frames go straight into one buffer sized by `Content-Length`; collecting them first would hold the body twice.
        let mut stream = request.with_limited_body().into_body();
        let mut body = Vec::with_capacity(length.min(PREALLOC_MAX));
        while let Some(frame) = stream.frame().await {
            match frame {
                Ok(frame) => {
                    if let Ok(data) = frame.into_data() {
                        body.extend_from_slice(&data);
                    }
                }
                Err(e) => {
                    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&e);
                    let mut too_large = false;
                    while let Some(err) = source {
                        too_large |= err.is::<LengthLimitError>();
                        source = err.source();
                    }
                    let (status, why) =
                        if too_large { (413, "length limit exceeded") } else { (400, "failed to read the body") };
                    return Err(Reply::text(status, &format!("Failed to buffer the request body: {why}"))
                        .header("Connection", "close"));
                }
            }
        }
        Ok(Req {
            method,
            query,
            headers,
            body: Mutex::new(body),
            remote: remote.unwrap_or_default(),
            role: Slot(Mutex::new(role)),
            disabled_key: Slot::default(),
            event,
        })
    }
}

/// A header value: UTF-8 when valid, Latin-1 otherwise.
pub fn decode_header(value: &[u8]) -> String {
    match std::str::from_utf8(value) {
        Ok(s) => s.to_string(),
        Err(_) => value.iter().map(|&b| char::from(b)).collect(),
    }
}

impl Req {
    /// Add to the request's [`RequestEvent`].
    pub fn note(&self, f: impl FnOnce(&mut RequestEvent)) {
        f(&mut self.event.lock().unwrap_or_else(PoisonError::into_inner));
    }

    /// A header value (first occurrence), trimmed.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim())
    }

    /// A non-empty header value.
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.header(name).filter(|v| !v.is_empty())
    }

    /// An `X-Apprise-{name}` header.
    pub fn x_header(&self, name: &str) -> Option<&str> {
        self.header_value(&format!("X-Apprise-{name}"))
    }

    /// The first query string value for `name`.
    pub fn query(&self, name: &str) -> Option<&str> {
        self.query.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// Read the request body in place.
    pub fn with_body<T>(&self, f: impl FnOnce(&[u8]) -> T) -> T {
        f(&self.body.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Move the body out, leaving the request without one: its buffer becomes whatever the caller makes of it.
    pub fn take_body(&self) -> Vec<u8> {
        std::mem::take(&mut *self.body.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Free the body once it is parsed, so its bytes are gone while the notification is sent.
    pub fn release_body(&self) {
        drop(self.take_body());
    }

    /// The media type of the body, lower-cased, without parameters.
    pub fn content_type(&self) -> String {
        self.header("content-type").unwrap_or("").split(';').next().unwrap_or("").trim().to_ascii_lowercase()
    }

    /// `true` when the body is JSON (`(text|application)/(x-)?json`).
    pub fn json_payload(&self) -> bool {
        is_json_mime(&self.content_type())
    }

    /// See [`wants_json`].
    pub fn wants_json(&self) -> bool {
        wants_json(self.header("accept"), &self.content_type())
    }

    /// Accept (the request type when absent) prefers HTML: `text/html` or `text/*`.
    pub fn wants_html_logs(&self) -> bool {
        let accept = self.header("accept").map(str::to_string).unwrap_or_else(|| self.content_type());
        let accept = accept.to_ascii_lowercase();
        accept.contains("text/*") || accept.contains("text/html")
    }

    /// Basic Auth credentials; `None` when absent or malformed.
    pub fn basic_auth(&self) -> Option<(String, String)> {
        basic_auth(self.header("authorization")?)
    }
}

/// Either an `Accept` asking for JSON or a missing / wildcard `Accept` on a request with a JSON body (`content_type`).
pub fn wants_json(accept: Option<&str>, content_type: &str) -> bool {
    let accept = accept.unwrap_or("");
    let accept_all = matches!(accept.trim(), "" | "*/*");
    is_json_mime(accept) || (accept_all && is_json_mime(content_type))
}

/// The credentials of an `Authorization: Basic` value, UTF-8 or else Latin-1 (OkHttp's default, used by Apprise Mobile); `None` when malformed.
pub fn basic_auth(header: &str) -> Option<(String, String)> {
    let (scheme, value) = header.trim().split_at_checked(6)?;
    if !scheme.eq_ignore_ascii_case("basic ") {
        return None;
    }
    let decoded = decode_header(&mercurio::__private::b64_decode(value.trim())?);
    let (user, pass) = decoded.split_once(':')?;
    Some((user.trim().to_string(), pass.to_string()))
}

/// `(text|application)/(x-)?json` at the start of `s`.
pub fn is_json_mime(s: &str) -> bool {
    let s = s.trim_start().to_ascii_lowercase();
    ["text/json", "text/x-json", "application/json", "application/x-json"].iter().any(|m| s.starts_with(m))
}

/// Parse `a=b&c=d` (form or query string).
pub fn form_pairs(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (unquote_plus(k), unquote_plus(v)),
            None => (unquote_plus(p), String::new()),
        })
        .collect()
}

/// A loose boolean: the first character decides (`y`, `1`, `t`, `e`, `a`, `+` are true).
pub fn parse_bool(value: Option<&str>, default: bool) -> bool {
    match value.map(|v| v.trim().to_ascii_lowercase()) {
        Some(v) if !v.is_empty() => matches!(v.as_bytes().first(), Some(b'a' | b'y' | b'1' | b't' | b'e' | b'+')),
        _ => default,
    }
}

pub enum Body {
    Bytes(Vec<u8>),
    /// A finished axum response (a live stream), sent as it is.
    Response(Box<axum::response::Response>),
}

pub struct Reply {
    pub status: u16,
    pub ctype: String,
    pub body: Body,
    pub headers: Vec<(String, String)>,
}

impl Reply {
    pub fn new(status: u16, ctype: &str, body: Vec<u8>) -> Reply {
        Reply { status, ctype: ctype.to_string(), body: Body::Bytes(body), headers: Vec::new() }
    }

    pub fn text(status: u16, msg: &str) -> Reply {
        Reply::new(status, "text/plain; charset=utf-8", msg.as_bytes().to_vec())
    }

    pub fn json(status: u16, v: &Value) -> Reply {
        Reply::new(status, "application/json", serde_json::to_vec(v).unwrap_or_default())
    }

    pub fn empty(status: u16) -> Reply {
        Reply::new(status, "", Vec::new())
    }

    pub fn header(mut self, k: &str, v: &str) -> Reply {
        self.headers.push((k.to_string(), v.to_string()));
        self
    }

    /// `{"error": msg}` for JSON clients, text otherwise.
    pub fn error(req: &Req, status: u16, msg: &str) -> Reply {
        req.note(|ev| ev.error = Some(msg.to_string()));
        Reply::error_as(req.wants_json(), status, msg)
    }

    /// [`Reply::error`] as JSON when `json`.
    pub fn error_as(json: bool, status: u16, msg: &str) -> Reply {
        if json { Reply::json(status, &json!({"error": msg})) } else { Reply::text(status, msg) }
    }

    /// [`Reply::error`] naming the offending field.
    pub fn field_error(req: &Req, status: u16, msg: &str, field: &str) -> Reply {
        req.note(|ev| ev.error = Some(format!("{field}: {msg}")));
        if req.wants_json() {
            Reply::json(status, &json!({"error": msg, "field": field}))
        } else {
            Reply::text(status, msg)
        }
    }

    /// A success message; `{"error": null}` for JSON clients.
    pub fn ok(req: &Req, msg: &str) -> Reply {
        if req.wants_json() { Reply::json(200, &json!({"error": null})) } else { Reply::text(200, msg) }
    }
}

/// A header that would not survive (a line break, an invalid name) is dropped.
impl axum::response::IntoResponse for Reply {
    fn into_response(self) -> axum::response::Response {
        use axum::http::{HeaderName, HeaderValue, header};
        let Reply { status, ctype, body, headers } = self;
        let body = match body {
            Body::Bytes(b) => axum::body::Body::from(b),
            Body::Response(r) => return *r,
        };
        let mut res = axum::response::Response::new(body);
        *res.status_mut() =
            axum::http::StatusCode::from_u16(status).unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        let map = res.headers_mut();
        if let Ok(v) = HeaderValue::from_str(&ctype)
            && !ctype.is_empty()
        {
            map.insert(header::CONTENT_TYPE, v);
        }
        for (k, v) in headers {
            if let (Ok(k), Ok(v)) = (HeaderName::try_from(k), HeaderValue::try_from(v)) {
                map.append(k, v);
            }
        }
        res
    }
}
