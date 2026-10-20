//! Request and response plumbing between axum and the handlers.
//!
//! Header values are read as UTF-8 (clients send UTF-8 titles in `X-Apprise-Title`). Values that are not valid UTF-8 are read as Latin-1.

use std::net::SocketAddr;
use std::sync::{Mutex, PoisonError};

use mercurio::url::unquote_plus;
use serde_json::{Value, json};

/// Largest request body read.
pub const MAX_BODY: usize = 64 * 1024 * 1024;
/// How long a client may take to send a request head (and how long an idle connection stays open), and then its body.
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

pub struct Req {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub remote: String,
    /// Who this request has proven to be.
    pub role: Slot<super::auth::Role>,
    /// A key whose valid login is disabled (answered with 403).
    pub disabled_key: Slot<Option<String>>,
}

/// The request as the handlers see it; a body over [`MAX_BODY`] gets 413, one that does not arrive within [`IO_TIMEOUT`] 408, one that can not be read 400.
pub async fn read(request: axum::extract::Request, remote: SocketAddr) -> Result<Req, Reply> {
    let (parts, body) = request.into_parts();
    let Ok(body) = tokio::time::timeout(IO_TIMEOUT, axum::body::to_bytes(body, MAX_BODY)).await else {
        return Err(Reply::text(408, "The request timed out"));
    };
    let body = match body {
        Ok(b) => b.to_vec(),
        Err(e) if std::error::Error::source(&e).is_some_and(|s| s.is::<http_body_util::LengthLimitError>()) => {
            return Err(Reply::text(413, "The request body is too large"));
        }
        Err(e) => return Err(Reply::text(400, &format!("The request body could not be read: {e}"))),
    };
    Ok(Req {
        method: parts.method.as_str().to_ascii_uppercase(),
        path: unquote_plus(parts.uri.path()),
        query: form_pairs(parts.uri.query().unwrap_or("")),
        headers: parts.headers.iter().map(|(k, v)| (k.as_str().to_string(), decode_header(v.as_bytes()))).collect(),
        body,
        remote: remote.ip().to_string(),
        role: Slot::default(),
        disabled_key: Slot::default(),
    })
}

/// A header value: UTF-8 when valid, Latin-1 otherwise.
fn decode_header(value: &[u8]) -> String {
    match std::str::from_utf8(value) {
        Ok(s) => s.to_string(),
        Err(_) => value.iter().map(|&b| char::from(b)).collect(),
    }
}

impl Req {
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

    /// The media type of the body, lower-cased, without parameters.
    pub fn content_type(&self) -> String {
        self.header("content-type").unwrap_or("").split(';').next().unwrap_or("").trim().to_ascii_lowercase()
    }

    /// `true` when the body is JSON (`(text|application)/(x-)?json`).
    pub fn json_payload(&self) -> bool {
        is_json_mime(&self.content_type())
    }

    /// Either an `Accept` asking for JSON or a missing / wildcard `Accept` on a request with a JSON body.
    pub fn wants_json(&self) -> bool {
        let accept = self.header("accept").unwrap_or("");
        let accept_all = matches!(accept.trim(), "" | "*/*");
        is_json_mime(accept) || (accept_all && self.json_payload())
    }

    /// Accept (the request type when absent) prefers HTML: `text/html` or `text/*`.
    pub fn wants_html_logs(&self) -> bool {
        let accept = self.header("accept").map(str::to_string).unwrap_or_else(|| self.content_type());
        let accept = accept.to_ascii_lowercase();
        accept.contains("text/*") || accept.contains("text/html")
    }

    /// Basic Auth credentials; `None` when absent or malformed.
    pub fn basic_auth(&self) -> Option<(String, String)> {
        let h = self.header("authorization")?;
        let (scheme, value) = h.split_at_checked(6)?;
        if !scheme.eq_ignore_ascii_case("basic ") {
            return None;
        }
        let decoded = String::from_utf8(mercurio::crypto::b64_decode(value.trim())?).ok()?;
        let (user, pass) = decoded.split_once(':')?;
        Some((user.trim().to_string(), pass.to_string()))
    }
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
    /// Streamed (chunked on HTTP/1.1).
    Stream(axum::body::Body),
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
        if req.wants_json() { Reply::json(status, &json!({"error": msg})) } else { Reply::text(status, msg) }
    }

    /// [`Reply::error`] naming the offending field.
    pub fn field_error(req: &Req, status: u16, msg: &str, field: &str) -> Reply {
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

impl Reply {
    /// The axum response; a header that would not survive (a line break, an invalid name) is dropped.
    pub fn into_response(self) -> axum::response::Response {
        use axum::http::{HeaderName, HeaderValue, header};
        let Reply { status, ctype, body, headers } = self;
        let body = match body {
            Body::Bytes(b) => axum::body::Body::from(b),
            Body::Stream(s) => s,
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
