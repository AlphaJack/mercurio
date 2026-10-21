//! Plain-data HTTP request/response types. Services build [`Request`]s; a [`crate::Transport`] executes them.

use std::fmt;
use std::time::Duration;

use bytes::Bytes;
use serde_json::{Map, Value};

use crate::url::form_urlencode;

/// HTTP request method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `PATCH`.
    Patch,
    /// `DELETE`.
    Delete,
    /// `HEAD`.
    Head,
    /// `OPTIONS`.
    Options,
    /// Non-standard `UPDATE` verb accepted by the custom webhook services.
    Update,
}

impl Method {
    /// Upper-case method name, e.g. `"POST"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Update => "UPDATE",
        }
    }

    /// Parse a method name (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "PATCH" => Some(Self::Patch),
            "DELETE" => Some(Self::Delete),
            "HEAD" => Some(Self::Head),
            "OPTIONS" => Some(Self::Options),
            "UPDATE" => Some(Self::Update),
            _ => None,
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Default connect timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default read timeout.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Redirects followed before the last 3xx response is returned as is.
pub(crate) const MAX_REDIRECTS: u32 = 10;

/// [`Request::max_body`] by default: response bodies larger than this fail (as a transport error).
pub const MAX_BODY: u64 = 16 * 1024 * 1024;

/// The error of a response body longer than `limit` ([`Request::max_body`]); every transport returns this one.
pub fn body_too_large(limit: u64) -> crate::Error {
    crate::Error::Transport(format!("the response body is larger than request limit: {limit}"))
}

/// Stands for a message's text inside a JSON payload until [`json_with_text`] writes the real text.
pub(crate) const TEXT: &str = "\u{0}text\u{0}";

/// Compact JSON of `value` with `text` written (escaped) wherever the [`TEXT`] placeholder stands, in a buffer sized for it.
pub(crate) fn json_with_text(value: &Value, text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + text.len() / 64 + 1024);
    write_json_text(&mut out, value, text).map(|()| out).unwrap_or_default()
}

/// A size for the JSON of `value`: its text and a little for the structure around it.
fn json_size_hint(value: &Value) -> usize {
    fn texts(v: &Value) -> usize {
        match v {
            Value::String(s) => s.len(),
            Value::Array(a) => a.iter().map(texts).sum(),
            Value::Object(m) => m.values().map(texts).sum(),
            Value::Null | Value::Bool(_) | Value::Number(_) => 0,
        }
    }
    let n = texts(value);
    n + n / 64 + 256
}

/// The length [`json_with_text`] would produce, without building it.
pub(crate) fn json_text_len(value: &Value, text: &str) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    write_json_text(&mut count, value, text).map_or(0, |()| count.0)
}

/// Write `value` as compact JSON, `text` in place of the [`TEXT`] placeholder.
pub(crate) fn write_json_text<W: std::io::Write>(w: &mut W, value: &Value, text: &str) -> std::io::Result<()> {
    match value {
        Value::String(s) if s == TEXT => serde_json::to_writer(&mut *w, text)?,
        Value::Array(items) => {
            w.write_all(b"[")?;
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    w.write_all(b",")?;
                }
                write_json_text(w, item, text)?;
            }
            w.write_all(b"]")?;
        }
        Value::Object(map) => {
            w.write_all(b"{")?;
            for (i, (key, item)) in map.iter().enumerate() {
                if i > 0 {
                    w.write_all(b",")?;
                }
                serde_json::to_writer(&mut *w, key)?;
                w.write_all(b":")?;
                write_json_text(w, item, text)?;
            }
            w.write_all(b"}")?;
        }
        other @ (Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)) => {
            serde_json::to_writer(&mut *w, other)?;
        }
    }
    Ok(())
}

/// An outgoing HTTP request.
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    /// Request method.
    pub method: Method,
    /// Absolute URL including any query string.
    pub url: String,
    /// Header order is preserved; names compare case-insensitively.
    pub headers: Vec<(String, String)>,
    /// Raw body bytes; empty for no body. Shared, so a retry or a redirect sends the same buffer instead of a copy.
    pub body: Bytes,
    /// Connect timeout (5 s unless the URL sets `cto=`).
    pub connect_timeout: Duration,
    /// Read timeout (30 s unless the URL sets `rto=`).
    pub read_timeout: Duration,
    /// Verify the TLS certificate (`verify=no` turns this off).
    pub verify_tls: bool,
    /// Follow HTTP redirects.
    pub follow_redirects: bool,
    /// Largest response body read, in bytes: a longer one fails with [`body_too_large`] while it is read, not after. [`MAX_BODY`] by default; 0 reads any size. A custom [`crate::Transport`] should honour it.
    pub max_body: u64,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // URLs and headers routinely hold tokens; show shape only.
        let host = self.url.split("://").nth(1).and_then(|r| r.split('/').next()).unwrap_or("");
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("host", &host)
            .field("headers", &self.headers.iter().map(|(k, _)| k).collect::<Vec<_>>())
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl Request {
    /// A request with no headers or body, default timeouts, TLS verification and redirects on.
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: Bytes::new(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            read_timeout: DEFAULT_READ_TIMEOUT,
            verify_tls: true,
            follow_redirects: true,
            max_body: MAX_BODY,
        }
    }

    /// Read at most `bytes` of the response body (see [`Request::max_body`]; 0 reads any size).
    pub fn max_body(mut self, bytes: u64) -> Self {
        self.max_body = bytes;
        self
    }

    /// A `GET` request.
    pub fn get(url: impl Into<String>) -> Self {
        Self::new(Method::Get, url)
    }
    /// A `POST` request.
    pub fn post(url: impl Into<String>) -> Self {
        Self::new(Method::Post, url)
    }
    /// A `PUT` request.
    pub fn put(url: impl Into<String>) -> Self {
        Self::new(Method::Put, url)
    }
    /// A `PATCH` request.
    pub fn patch(url: impl Into<String>) -> Self {
        Self::new(Method::Patch, url)
    }
    /// A `DELETE` request.
    pub fn delete(url: impl Into<String>) -> Self {
        Self::new(Method::Delete, url)
    }

    /// Append a header (does not replace).
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set a header, replacing any with the same name (case-insensitive).
    pub fn set_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(&name));
        self.headers.push((name, value.into()));
        self
    }

    /// Remove every header named `name` (case-insensitive).
    pub fn remove_header(mut self, name: &str) -> Self {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        self
    }

    /// Apply several headers with `set_header` semantics (e.g. `?+Header=` overrides).
    pub fn headers<'a, I>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        for (k, v) in headers {
            self = self.set_header(k, v);
        }
        self
    }

    /// First value of header `name` (case-insensitive).
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// JSON body with `Content-Type: application/json` (unless already set).
    pub fn json(mut self, value: &Value) -> Self {
        // Sized from the text in the value, so a large message does not regrow the buffer by doubling.
        let mut out = Vec::with_capacity(json_size_hint(value));
        self.body = if serde_json::to_writer(&mut out, value).is_ok() { out } else { Vec::new() }.into();
        if self.header_value("content-type").is_none() {
            self = self.header("Content-Type", "application/json");
        }
        self
    }

    /// JSON body like [`Request::json`], writing `text` wherever `value` holds the [`TEXT`] placeholder, so a large message is not copied into a `Value` first.
    pub(crate) fn json_text(mut self, value: &Value, text: &str) -> Self {
        self.body = Bytes::from(json_with_text(value, text));
        if self.header_value("content-type").is_none() {
            self = self.header("Content-Type", "application/json");
        }
        self
    }

    /// Form body (`application/x-www-form-urlencoded`).
    pub fn form<K: AsRef<str>, V: AsRef<str>>(mut self, pairs: &[(K, V)]) -> Self {
        self.body = form_urlencode(pairs.iter()).into_bytes().into();
        if self.header_value("content-type").is_none() {
            self = self.header("Content-Type", "application/x-www-form-urlencoded");
        }
        self
    }

    /// Raw body with a content type.
    pub fn body(mut self, body: impl Into<Bytes>, content_type: Option<&str>) -> Self {
        self.body = body.into();
        if let Some(ct) = content_type {
            self = self.set_header("Content-Type", ct);
        }
        self
    }

    /// Text body with no content type change.
    pub fn text(mut self, body: impl Into<String>) -> Self {
        self.body = Bytes::from(body.into().into_bytes());
        self
    }

    /// Multipart body.
    pub fn multipart(mut self, form: Multipart) -> Self {
        let (ct, body) = form.finish();
        self.body = body.into();
        self.set_header("Content-Type", ct)
    }

    /// Append query parameters, `application/x-www-form-urlencoded` encoded.
    pub fn query<K: AsRef<str>, V: AsRef<str>>(mut self, pairs: &[(K, V)]) -> Self {
        if pairs.is_empty() {
            return self;
        }
        let encoded = form_urlencode(pairs.iter());
        let sep = if self.url.contains('?') {
            if self.url.ends_with('?') || self.url.ends_with('&') { "" } else { "&" }
        } else {
            "?"
        };
        self.url = format!("{}{}{}", self.url, sep, encoded);
        self
    }

    /// HTTP basic authentication.
    pub fn basic_auth(self, user: &str, password: Option<&str>) -> Self {
        use base64::Engine;
        let creds = format!("{}:{}", user, password.unwrap_or(""));
        let token = base64::engine::general_purpose::STANDARD.encode(creds);
        self.set_header("Authorization", format!("Basic {token}"))
    }

    /// HTTP basic authentication when a user is set.
    pub fn basic_auth_opt(self, user: Option<&str>, password: Option<&str>) -> Self {
        match user {
            Some(user) => self.basic_auth(user, password),
            None => self,
        }
    }

    /// `Authorization: Bearer <token>`.
    pub fn bearer(self, token: &str) -> Self {
        self.set_header("Authorization", format!("Bearer {token}"))
    }

    /// Set connect and read timeouts.
    pub fn timeouts(mut self, connect: Duration, read: Duration) -> Self {
        self.connect_timeout = connect;
        self.read_timeout = read;
        self
    }

    /// Turn TLS certificate verification on or off.
    pub fn verify(mut self, verify: bool) -> Self {
        self.verify_tls = verify;
        self
    }

    /// Follow redirects or not.
    pub fn redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    /// Body as UTF-8 text (lossy).
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// A received HTTP response.
#[derive(Clone, PartialEq, Eq)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Header order is preserved; names compare case-insensitively.
    pub headers: Vec<(String, String)>,
    /// Raw body bytes; empty for no body.
    pub body: Vec<u8>,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response").field("status", &self.status).field("body_len", &self.body.len()).finish()
    }
}

impl Response {
    /// A response with `status` and `body` and no headers (handy for fakes).
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self { status, headers: Vec::new(), body: body.into() }
    }

    /// Add a header (builder style).
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// `true` for a 2xx status.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// First value of header `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// Body as UTF-8 text (lossy).
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Parsed JSON body, if it is JSON.
    pub fn json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }

    /// A short, single-line excerpt of the body for error messages.
    pub fn snippet(&self) -> String {
        let t = self.text();
        let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
        if t.chars().count() > 200 { format!("{}...", t.chars().take(200).collect::<String>()) } else { t }
    }

    /// The error for this (unaccepted) response: [`crate::Error::RateLimited`] for a 429 or 503 with a valid `Retry-After`, else [`crate::Error::Http`].
    pub fn http_error(&self) -> crate::Error {
        self.http_error_with(self.snippet())
    }

    /// [`Response::http_error`] with a service-specific reason.
    pub fn http_error_with(&self, reason: impl Into<String>) -> crate::Error {
        self.limited_or_http(reason.into(), None)
    }

    /// [`Response::http_error`], with `hint` (a wait the service put in the body) when there is no `Retry-After` header: a 429 or 503 with either is [`crate::Error::RateLimited`], anything else [`crate::Error::Http`].
    pub fn rate_limited_or_http(&self, hint: Option<std::time::Duration>) -> crate::Error {
        self.limited_or_http(self.snippet(), hint)
    }

    /// [`crate::Error::RateLimited`] whatever the status, for a service's own throttling signal (e.g. AWS `Throttling` in a 400); `Retry-After` is the wait when present.
    pub fn rate_limited(&self) -> crate::Error {
        crate::Error::RateLimited { status: self.status, reason: self.snippet(), retry_after: self.retry_after() }
    }

    fn limited_or_http(&self, reason: String, hint: Option<std::time::Duration>) -> crate::Error {
        match self.retry_after().or(hint).filter(|_| matches!(self.status, 429 | 503)) {
            Some(d) => crate::Error::RateLimited { status: self.status, reason, retry_after: Some(d) },
            None => crate::Error::Http { status: self.status, reason },
        }
    }

    /// The `Retry-After` header as a wait from now.
    #[expect(clippy::disallowed_methods, reason = "a wait on the real clock, not request content")]
    pub fn retry_after(&self) -> Option<std::time::Duration> {
        crate::error::parse_retry_after(self.header("retry-after")?, crate::env::system().now())
    }

    /// Convert a non-2xx status into an error (see [`Response::http_error`]).
    pub fn error_for_status(&self) -> crate::Result<()> {
        self.error_unless(&[])
    }

    /// Fail unless status is 2xx or in `ok`.
    pub fn error_unless(&self, ok: &[u16]) -> crate::Result<()> {
        if self.is_success() || ok.contains(&self.status) { Ok(()) } else { Err(self.http_error()) }
    }
}

/// `multipart/form-data` builder (requests' `files=` / `data=`).
#[derive(Debug, Clone)]
pub struct Multipart {
    boundary: String,
    parts: Vec<Part>,
}

#[derive(Debug, Clone)]
struct Part {
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    data: Bytes,
}

impl Default for Multipart {
    #[expect(clippy::disallowed_methods, reason = "for callers outside a send")]
    fn default() -> Self {
        Self::new()
    }
}

impl Multipart {
    /// Empty form with a random boundary from the system generator. Services use [`crate::Context::multipart`].
    #[expect(clippy::disallowed_methods, reason = "for callers outside a send")]
    pub fn new() -> Self {
        Self::with_env(crate::env::system().as_ref())
    }

    /// Empty form with a random boundary from `env`.
    pub fn with_env(env: &dyn crate::Env) -> Self {
        Self::with_boundary(env.random_hex(16))
    }

    /// Empty form with `boundary`.
    pub fn with_boundary(boundary: String) -> Self {
        Self { boundary, parts: Vec::new() }
    }

    /// Add a text field.
    pub fn text(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.parts.push(Part {
            name: name.into(),
            filename: None,
            content_type: None,
            data: Bytes::from(value.into().into_bytes()),
        });
        self
    }

    /// File part. An empty `content_type` omits the part's `Content-Type` header.
    pub fn file(
        mut self,
        name: impl Into<String>,
        filename: impl Into<String>,
        content_type: impl Into<String>,
        data: impl Into<Bytes>,
    ) -> Self {
        self.parts.push(Part {
            name: name.into(),
            filename: Some(filename.into()),
            content_type: Some(content_type.into()),
            data: data.into(),
        });
        self
    }

    /// `(content_type, body)`.
    pub fn finish(self) -> (String, Vec<u8>) {
        // Sized for the data and a head per part, so the body is written once, without regrowing.
        let mut body =
            Vec::with_capacity(self.parts.iter().map(|p| p.data.len() + 256 + p.name.len()).sum::<usize>() + 64);
        for p in &self.parts {
            body.extend_from_slice(format!("--{}\r\n", self.boundary).as_bytes());
            let mut disp = format!("Content-Disposition: form-data; name=\"{}\"", escape_quotes(&p.name));
            if let Some(f) = &p.filename {
                disp.push_str(&format!("; filename=\"{}\"", escape_quotes(f)));
            }
            body.extend_from_slice(disp.as_bytes());
            body.extend_from_slice(b"\r\n");
            if let Some(ct) = p.content_type.as_ref().filter(|c| !c.is_empty()) {
                body.extend_from_slice(format!("Content-Type: {ct}\r\n").as_bytes());
            }
            body.extend_from_slice(b"\r\n");
            body.extend_from_slice(&p.data);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{}--\r\n", self.boundary).as_bytes());
        (format!("multipart/form-data; boundary={}", self.boundary), body)
    }
}

fn escape_quotes(s: &str) -> String {
    s.replace('"', "%22")
}

/// One part of a `multipart/form-data` body; `data` borrows the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartPart<'a> {
    /// The `name` of the form field, if the part has one.
    pub name: Option<String>,
    /// The `filename`: set for a file upload.
    pub filename: Option<String>,
    /// The part's `Content-Type`, as sent.
    pub content_type: Option<String>,
    /// The part's bytes.
    pub data: &'a [u8],
}

/// Split a `multipart/form-data` body into its parts without copying their data.
pub fn multipart_parts<'a>(content_type: &str, body: &'a [u8]) -> Vec<MultipartPart<'a>> {
    let Some(boundary) = content_type.split(';').find_map(|p| p.trim().strip_prefix("boundary=")) else {
        return Vec::new();
    };
    let boundary = boundary.trim_matches('"');
    let delim = format!("--{boundary}").into_bytes();
    let mut parts = Vec::new();
    let mut pos = 0;
    let find = |hay: &[u8], needle: &[u8], from: usize| -> Option<usize> {
        hay.get(from..)?.windows(needle.len()).position(|w| w == needle).map(|i| i + from)
    };
    while let Some(start) = find(body, &delim, pos) {
        let after = start + delim.len();
        if body.get(after..after + 2) == Some(b"--") {
            break;
        }
        let Some(next) = find(body, &delim, after) else { break };
        let mut chunk = &body[after..next];
        if chunk.starts_with(b"\r\n") {
            chunk = &chunk[2..];
        }
        if chunk.ends_with(b"\r\n") {
            chunk = &chunk[..chunk.len() - 2];
        }
        let split = find(chunk, b"\r\n\r\n", 0).unwrap_or(chunk.len());
        let head = String::from_utf8_lossy(&chunk[..split]).to_string();
        let data = chunk.get(split + 4..).unwrap_or(&[]);
        let mut part = MultipartPart { name: None, filename: None, content_type: None, data };
        for line in head.split("\r\n") {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("content-disposition:") {
                for attr in line.split(';').skip(1) {
                    let attr = attr.trim();
                    if let Some(v) = attr.strip_prefix("name=") {
                        part.name = Some(v.trim_matches('"').to_string());
                    } else if let Some(v) = attr.strip_prefix("filename=") {
                        part.filename = Some(v.trim_matches('"').to_string());
                    }
                }
            } else if lower.starts_with("content-type:") {
                part.content_type = Some(line.get(13..).unwrap_or_default().trim().to_string());
            }
        }
        parts.push(part);
        pos = next;
    }
    parts
}

/// Parse `multipart/form-data` into `[{name, filename, content_type, value|b64}]`. [`multipart_parts`] does not copy the data.
pub fn parse_multipart(content_type: &str, body: &[u8]) -> Vec<Value> {
    multipart_parts(content_type, body)
        .into_iter()
        .map(|part| {
            let mut obj = Map::new();
            for (key, value) in
                [("name", &part.name), ("filename", &part.filename), ("content_type", &part.content_type)]
            {
                if let Some(v) = value {
                    obj.insert(key.into(), Value::String(v.clone()));
                }
            }
            match std::str::from_utf8(part.data) {
                Ok(s) if part.filename.is_none() => {
                    obj.insert("value".into(), Value::String(s.to_string()));
                }
                _ => {
                    obj.insert("b64".into(), Value::String(crate::crypto::b64(part.data)));
                }
            }
            Value::Object(obj)
        })
        .collect()
}

#[cfg(test)]
mod multipart_tests {
    use super::*;

    const BODY: &[u8] = b"--b\r\nContent-Disposition: form-data; name=\"body\"\r\n\r\nhello\r\n--b\r\nContent-Disposition: form-data; name=\"attach\"; filename=\"a.bin\"\r\nContent-Type: Application/Octet-Stream\r\n\r\n\x00\xffdata\r\n--b--\r\n";

    #[test]
    fn parts_borrow_the_body() {
        let parts = multipart_parts("multipart/form-data; boundary=b", BODY);
        assert_eq!(parts.len(), 2);
        assert_eq!(
            (parts[0].name.as_deref(), parts[0].filename.as_deref(), parts[0].data),
            (Some("body"), None, &b"hello"[..])
        );
        assert_eq!(parts[1].filename.as_deref(), Some("a.bin"));
        assert_eq!(parts[1].content_type.as_deref(), Some("Application/Octet-Stream"));
        assert_eq!(parts[1].data, b"\x00\xffdata");
        assert!(multipart_parts("multipart/form-data", BODY).is_empty());
    }

    #[test]
    fn json_form_keeps_value_and_b64() {
        let parts = parse_multipart("multipart/form-data; boundary=b", BODY);
        assert_eq!(parts[0]["value"], "hello");
        assert_eq!(parts[1]["b64"], crate::crypto::b64(b"\x00\xffdata"));
        assert_eq!(parts[1]["filename"], "a.bin");
    }
}
