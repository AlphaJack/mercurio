//! Request and response plumbing.
//!
//! HTTP/1.0 and 1.1 on a plain `TcpStream`. Header values are read as UTF-8 (clients send UTF-8 titles in `X-Apprise-Title`). Values that are not valid UTF-8 are read as Latin-1. Any malformed request gets a 400 answer.

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

use mercurio::url::unquote_plus;
use serde_json::{Value, json};

/// Largest request body read.
pub const MAX_BODY: usize = 64 * 1024 * 1024;
/// Largest request line or header line.
const MAX_LINE: usize = 64 * 1024;
/// Most header lines in one request.
const MAX_HEADERS: usize = 200;

pub struct Req {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub remote: String,
    /// Who this request has proven to be.
    pub role: std::cell::Cell<super::auth::Role>,
    /// A key whose valid login is disabled (answered with 403).
    pub disabled_key: std::cell::RefCell<Option<String>>,
    /// `(major, minor)` HTTP version.
    pub version: (u8, u8),
    /// The connection may serve another request after this one.
    pub keep_alive: bool,
}

/// Why no request was read from a connection.
pub enum ReadError {
    /// The client closed or idled out between requests: close quietly.
    Closed,
    /// Answer with this reply, then close the connection.
    Reply(Reply),
}

fn bad(msg: &str) -> ReadError {
    ReadError::Reply(Reply::text(400, msg))
}

pub struct Conn {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    remote: String,
}

impl Conn {
    pub fn new(stream: TcpStream, timeout: Duration) -> std::io::Result<Conn> {
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let remote = stream.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
        Ok(Conn { reader: BufReader::new(stream.try_clone()?), writer: stream, remote })
    }

    /// Read one line (without its `\r\n` / `\n`). `Ok(None)` is end of input before any byte; a line cut short by the end of input is an error.
    fn line(&mut self, limit: usize) -> Result<Option<Vec<u8>>, ReadError> {
        let mut buf = Vec::new();
        match (&mut self.reader).take(limit as u64 + 1).read_until(b'\n', &mut buf) {
            Ok(0) => return Ok(None),
            Ok(_) => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(ReadError::Reply(Reply::text(408, "The request timed out")));
            }
            Err(_) => return Err(ReadError::Closed),
        }
        if buf.pop() != Some(b'\n') {
            return Err(if buf.len() >= limit {
                ReadError::Reply(Reply::text(431, "A request line or header is too large"))
            } else {
                bad("The request ended before it was complete")
            });
        }
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        Ok(Some(buf))
    }

    /// Read the next request: request line, headers and (bounded) body.
    pub fn read(&mut self) -> Result<Req, ReadError> {
        // Blank lines before a request line are ignored (RFC 9112 2.2); a quiet end of input or idle timeout here ends the connection.
        let line = loop {
            match self.line(MAX_LINE) {
                Ok(Some(l)) if l.is_empty() => continue,
                Ok(Some(l)) => break l,
                Ok(None) => return Err(ReadError::Closed),
                Err(ReadError::Reply(r)) if r.status == 408 => return Err(ReadError::Closed),
                Err(e) => return Err(e),
            }
        };
        let (method, target, version) = parse_request_line(&line)?;
        let mut headers: Vec<(String, String)> = Vec::new();
        loop {
            let line = self.line(MAX_LINE)?.ok_or_else(|| bad("The request ended before it was complete"))?;
            if line.is_empty() {
                break;
            }
            if headers.len() >= MAX_HEADERS {
                return Err(ReadError::Reply(Reply::text(431, "The request has too many headers")));
            }
            if matches!(line.first(), Some(b' ' | b'\t')) {
                // Obsolete line folding: continue the previous value.
                let (_, value) = headers.last_mut().ok_or_else(|| bad("Malformed header line"))?;
                value.push(' ');
                value.push_str(&decode_header(line.trim_ascii()));
                continue;
            }
            headers.push(parse_header(&line)?);
        }
        let header = |name: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str());
        let connection = header("connection").unwrap_or("").to_ascii_lowercase();
        let keep_alive = version == (1, 1) && !connection.contains("close") && !connection.contains("upgrade");
        let chunked = match header("transfer-encoding") {
            Some(te) if te.rsplit(',').next().is_some_and(|t| t.trim().eq_ignore_ascii_case("chunked")) => true,
            Some(_) => return Err(bad("Unsupported Transfer-Encoding")),
            None => false,
        };
        let length = match (chunked, header("content-length")) {
            (false, Some(v)) => match v.trim() {
                v if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => v.parse::<usize>().unwrap_or(usize::MAX),
                _ => return Err(bad("Invalid Content-Length")),
            },
            _ => 0,
        };
        if length > MAX_BODY {
            return Err(ReadError::Reply(Reply::text(413, "The request body is too large")));
        }
        if let Some(expect) = header("expect") {
            if !expect.trim().eq_ignore_ascii_case("100-continue") {
                return Err(ReadError::Reply(Reply::text(417, "Unsupported Expect header")));
            }
            if version == (1, 1) && (chunked || length > 0) {
                self.writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").map_err(|_| ReadError::Closed)?;
            }
        }
        let body = if chunked { self.chunked_body()? } else { self.sized_body(length)? };
        let target = String::from_utf8(target).map_err(|_| bad("The request target is not valid UTF-8"))?;
        let (path, qs) = target.split_once('?').unwrap_or((&target, ""));
        Ok(Req {
            method: method.to_ascii_uppercase(),
            path: unquote_plus(path),
            query: form_pairs(qs),
            headers,
            body,
            remote: self.remote.clone(),
            role: Default::default(),
            disabled_key: Default::default(),
            version,
            keep_alive,
        })
    }

    fn sized_body(&mut self, length: usize) -> Result<Vec<u8>, ReadError> {
        let mut body = Vec::new();
        match (&mut self.reader).take(length as u64).read_to_end(&mut body) {
            Ok(n) if n == length => Ok(body),
            Ok(_) => Err(bad("The request body is shorter than its Content-Length")),
            Err(e) => Err(bad(&format!("The request body could not be read: {e}"))),
        }
    }

    fn chunked_body(&mut self) -> Result<Vec<u8>, ReadError> {
        let incomplete = || bad("The chunked request body is incomplete");
        let mut body = Vec::new();
        loop {
            let line = self.line(1024)?.ok_or_else(incomplete)?;
            let size = line.split(|&b| b == b';').next().unwrap_or_default().trim_ascii();
            let size = std::str::from_utf8(size)
                .ok()
                .filter(|s| !s.is_empty())
                .and_then(|s| usize::from_str_radix(s, 16).ok())
                .ok_or_else(|| bad("Invalid chunk size in the request body"))?;
            if size == 0 {
                // Trailer fields, up to the final blank line, are ignored.
                while !self.line(MAX_LINE)?.ok_or_else(incomplete)?.is_empty() {}
                return Ok(body);
            }
            if body.len().saturating_add(size) > MAX_BODY {
                return Err(ReadError::Reply(Reply::text(413, "The request body is too large")));
            }
            let start = body.len();
            body.resize(start + size, 0);
            let tail = body.get_mut(start..).unwrap_or_default();
            self.reader.read_exact(tail).map_err(|_| incomplete())?;
            if !self.line(2)?.ok_or_else(incomplete)?.is_empty() {
                return Err(bad("Invalid chunk in the request body"));
            }
        }
    }

    /// Write `reply`. Returns `true` when the connection can serve another request (`req` asked for keep-alive and the write succeeded).
    pub fn send(&mut self, reply: Reply, req: Option<&Req>) -> bool {
        let keep_alive = req.is_some_and(|r| r.keep_alive);
        let (major, minor) = req.map_or((1, 1), |r| r.version);
        let head = req.is_some_and(|r| r.method == "HEAD");
        let result = write_reply(&mut self.writer, reply, (major, minor), keep_alive, head);
        match result {
            Ok(()) => keep_alive,
            Err(e) => {
                log::debug!("connection error: {e}");
                false
            }
        }
    }

    /// Close after an error reply: stop writing, then drain what the client is still sending (bounded) so the close does not reset the connection before the client has read the reply.
    pub fn close(mut self) {
        self.writer.shutdown(Shutdown::Write).ok();
        self.writer.set_read_timeout(Some(Duration::from_millis(500))).ok();
        std::io::copy(&mut (&mut self.reader).take(MAX_LINE as u64), &mut std::io::sink()).ok();
    }
}

/// Write status line, headers and body. Byte bodies carry a `Content-Length`; streams are sent chunked (HTTP/1.1, one chunk per read, flushed so events arrive as they happen) or buffered (HTTP/1.0). 1xx and 204 replies have neither; HEAD, 1xx, 204 and 304 replies have no body.
fn write_reply(
    w: &mut TcpStream,
    reply: Reply,
    version: (u8, u8),
    keep_alive: bool,
    head: bool,
) -> std::io::Result<()> {
    let Reply { status, ctype, body, headers } = reply;
    let body = match body {
        Body::Stream(mut r) if version == (1, 0) => {
            let mut buf = Vec::new();
            r.read_to_end(&mut buf)?;
            Body::Bytes(buf)
        }
        body @ (Body::Bytes(_) | Body::Stream(_)) => body,
    };
    let mut out = std::io::BufWriter::new(w);
    write!(out, "HTTP/{}.{} {status} {}\r\n", version.0, version.1, reason(status))?;
    let date = mercurio::crypto::rfc2822_utc(mercurio::crypto::unix_time()).replace("+0000", "GMT");
    write!(out, "Date: {date}\r\n")?;
    if !ctype.is_empty() {
        write!(out, "Content-Type: {ctype}\r\n")?;
    }
    // A value with a line break would split the header: drop it.
    for (k, v) in headers.iter().filter(|(k, v)| ![k, v].iter().any(|s| s.contains(['\r', '\n']))) {
        write!(out, "{k}: {v}\r\n")?;
    }
    if !keep_alive {
        out.write_all(b"Connection: close\r\n")?;
    }
    let bodiless = status < 200 || status == 204;
    match &body {
        _ if bodiless => {}
        Body::Bytes(b) => write!(out, "Content-Length: {}\r\n", b.len())?,
        Body::Stream(_) => out.write_all(b"Transfer-Encoding: chunked\r\n")?,
    }
    out.write_all(b"\r\n")?;
    if head || bodiless || status == 304 {
        return out.flush();
    }
    match body {
        Body::Bytes(b) => out.write_all(&b)?,
        Body::Stream(mut r) => {
            let mut buf = vec![0; 8192];
            loop {
                let n = match r.read(&mut buf) {
                    Ok(n) => n,
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                };
                let chunk = buf.get(..n).unwrap_or_default();
                write!(out, "{n:x}\r\n")?;
                out.write_all(chunk)?;
                out.write_all(b"\r\n")?;
                out.flush()?;
                if n == 0 {
                    break;
                }
            }
        }
    }
    out.flush()
}

/// The reason phrase of the status codes this server sends.
fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        204 => "No Content",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Content Too Large",
        417 => "Expectation Failed",
        424 => "Failed Dependency",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "",
    }
}

/// Method, raw target and `(major, minor)` version.
type RequestLine = (String, Vec<u8>, (u8, u8));

/// `METHOD target HTTP/x.y`.
fn parse_request_line(line: &[u8]) -> Result<RequestLine, ReadError> {
    let mut parts = line.split(|&b| b == b' ').filter(|p| !p.is_empty());
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad("Malformed request line"));
    };
    if !method.iter().all(|&b| is_tchar(b)) {
        return Err(bad("Malformed request method"));
    }
    let version = match version {
        b"HTTP/1.1" => (1, 1),
        b"HTTP/1.0" => (1, 0),
        b"HTTP/2" | b"HTTP/2.0" | b"HTTP/3" | b"HTTP/3.0" => {
            return Err(ReadError::Reply(Reply::text(505, "This server only supports HTTP versions 1.0 and 1.1")));
        }
        _ => return Err(bad("Malformed HTTP version")),
    };
    Ok((String::from_utf8_lossy(method).into_owned(), target.to_vec(), version))
}

/// `Name: value`, the value decoded and trimmed.
fn parse_header(line: &[u8]) -> Result<(String, String), ReadError> {
    let colon = line.iter().position(|&b| b == b':').ok_or_else(|| bad("Malformed header line"))?;
    let (name, value) = line.split_at(colon);
    if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
        return Err(bad("Malformed header name"));
    }
    let value = value.get(1..).unwrap_or_default().trim_ascii();
    Ok((String::from_utf8_lossy(name).into_owned(), decode_header(value)))
}

/// A header value: UTF-8 when valid, Latin-1 otherwise.
fn decode_header(value: &[u8]) -> String {
    match std::str::from_utf8(value) {
        Ok(s) => s.to_string(),
        Err(_) => value.iter().map(|&b| char::from(b)).collect(),
    }
}

/// An RFC 9110 token character.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
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
    /// Streamed with chunked transfer encoding.
    Stream(Box<dyn Read + Send>),
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
