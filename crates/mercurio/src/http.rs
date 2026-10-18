//! Plain-data HTTP request/response types. Services build [`Request`]s; a [`crate::Transport`] executes them.

use std::fmt;
use std::time::Duration;

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

/// An outgoing HTTP request.
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    /// Request method.
    pub method: Method,
    /// Absolute URL including any query string.
    pub url: String,
    /// Header order is preserved; names compare case-insensitively.
    pub headers: Vec<(String, String)>,
    /// Raw body bytes; empty for no body.
    pub body: Vec<u8>,
    /// Connect timeout (5 s unless the URL sets `cto=`).
    pub connect_timeout: Duration,
    /// Read timeout (30 s unless the URL sets `rto=`).
    pub read_timeout: Duration,
    /// Verify the TLS certificate (`verify=no` turns this off).
    pub verify_tls: bool,
    /// Follow HTTP redirects.
    pub follow_redirects: bool,
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
            body: Vec::new(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            read_timeout: DEFAULT_READ_TIMEOUT,
            verify_tls: true,
            follow_redirects: true,
        }
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
        self.body = serde_json::to_vec(value).unwrap_or_default();
        if self.header_value("content-type").is_none() {
            self = self.header("Content-Type", "application/json");
        }
        self
    }

    /// Form body (`application/x-www-form-urlencoded`).
    pub fn form<K: AsRef<str>, V: AsRef<str>>(mut self, pairs: &[(K, V)]) -> Self {
        self.body = form_urlencode(pairs.iter()).into_bytes();
        if self.header_value("content-type").is_none() {
            self = self.header("Content-Type", "application/x-www-form-urlencoded");
        }
        self
    }

    /// Raw body with a content type.
    pub fn body(mut self, body: impl Into<Vec<u8>>, content_type: Option<&str>) -> Self {
        self.body = body.into();
        if let Some(ct) = content_type {
            self = self.set_header("Content-Type", ct);
        }
        self
    }

    /// Text body with no content type change.
    pub fn text(mut self, body: impl Into<String>) -> Self {
        self.body = body.into().into_bytes();
        self
    }

    /// Multipart body.
    pub fn multipart(mut self, form: Multipart) -> Self {
        let (ct, body) = form.finish();
        self.body = body;
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
        let reason = reason.into();
        match self.retry_after().filter(|_| matches!(self.status, 429 | 503)) {
            Some(d) => crate::Error::RateLimited { status: self.status, reason, retry_after: Some(d) },
            None => crate::Error::Http { status: self.status, reason },
        }
    }

    /// The `Retry-After` header as a wait from now.
    pub fn retry_after(&self) -> Option<std::time::Duration> {
        crate::error::parse_retry_after(self.header("retry-after")?, std::time::SystemTime::now())
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
    data: Vec<u8>,
}

impl Default for Multipart {
    fn default() -> Self {
        Self::new()
    }
}

impl Multipart {
    /// Empty form with a random boundary.
    pub fn new() -> Self {
        let mut b = [0u8; 16];
        crate::crypto::random_bytes(&mut b);
        let boundary = b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        Self { boundary, parts: Vec::new() }
    }

    /// Add a text field.
    pub fn text(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.parts.push(Part {
            name: name.into(),
            filename: None,
            content_type: None,
            data: value.into().into_bytes(),
        });
        self
    }

    /// File part. An empty `content_type` omits the part's `Content-Type` header.
    pub fn file(
        mut self,
        name: impl Into<String>,
        filename: impl Into<String>,
        content_type: impl Into<String>,
        data: impl Into<Vec<u8>>,
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
        let mut body = Vec::new();
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

/// Parse `multipart/form-data` into `[{name, filename, content_type, value|b64}]`.
pub fn parse_multipart(content_type: &str, body: &[u8]) -> Vec<Value> {
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
        let mut obj = Map::new();
        for line in head.split("\r\n") {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("content-disposition:") {
                for attr in line.split(';').skip(1) {
                    let attr = attr.trim();
                    if let Some(v) = attr.strip_prefix("name=") {
                        obj.insert("name".into(), Value::String(v.trim_matches('"').to_string()));
                    } else if let Some(v) = attr.strip_prefix("filename=") {
                        obj.insert("filename".into(), Value::String(v.trim_matches('"').to_string()));
                    }
                }
            } else if lower.starts_with("content-type:") {
                obj.insert("content_type".into(), Value::String(line.get(13..).unwrap_or_default().trim().to_string()));
            }
        }
        match std::str::from_utf8(data) {
            Ok(s) if obj.get("filename").is_none() => {
                obj.insert("value".into(), Value::String(s.to_string()));
            }
            _ => {
                obj.insert("b64".into(), Value::String(crate::crypto::b64(data)));
            }
        }
        parts.push(Value::Object(obj));
        pos = next;
    }
    parts
}
