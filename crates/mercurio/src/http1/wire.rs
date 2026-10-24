//! HTTP/1.1 on the wire, without I/O: the request bytes, the response head and how its body is framed.

use bytes::Bytes;

use crate::error::{Error, Result};
use crate::http::{Method, Request};
use crate::http1::proxy::Proxy;
use crate::http1::url::Url;

/// The most a response head (or a chunk-size line) may take.
pub(crate) const MAX_HEAD: usize = 64 * 1024;
/// Bodies up to this size go out in the same write as the head.
pub(crate) const COALESCE: usize = 16 * 1024;

/// How the body of a response is delimited.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Framing {
    /// No body (`HEAD`, 1xx, 204, 304).
    None,
    /// `Content-Length` bytes.
    Length(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// Until the server closes the connection.
    Close,
}

/// A parsed response head.
pub(crate) struct Head {
    pub(crate) status: u16,
    /// Names are lower-case.
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) framing: Framing,
    /// The server will close the connection after this response.
    pub(crate) close: bool,
}

impl Head {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

pub(crate) fn parse_head(raw: &[u8], method: Method) -> Result<Head> {
    let bad = |what: &str| Error::Unconfirmed(format!("bad response: {what}"));
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split_whitespace();
    let version = first.next().unwrap_or_default();
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(bad("not HTTP/1.x"));
    }
    let status: u16 =
        first.next().and_then(|s| s.parse().ok()).filter(|s| (100..1000).contains(s)).ok_or_else(|| bad("status"))?;
    let mut headers = Vec::new();
    for line in lines.filter(|l| !l.is_empty()) {
        if line.starts_with([' ', '\t']) {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or_else(|| bad("header"))?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    fn values<'a>(headers: &'a [(String, String)], name: &'a str) -> impl Iterator<Item = &'a str> {
        headers.iter().filter(move |(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    let named = |name: &'static str| values(&headers, name);
    let tokens = |name: &'static str| {
        named(name).flat_map(|v| v.split(',')).map(|t| t.trim().to_ascii_lowercase()).collect::<Vec<_>>()
    };
    let length = {
        let mut lengths = named("content-length").flat_map(|v| v.split(',')).map(|v| digits(v.trim(), 10).ok_or(()));
        match lengths.next() {
            None => None,
            Some(first) => {
                let first = first.map_err(|_| bad("content-length"))?;
                if lengths.any(|l| l != Ok(first)) {
                    return Err(bad("conflicting content-length"));
                }
                Some(first)
            }
        }
    };
    let connection = tokens("connection");
    let close = connection.iter().any(|t| t == "close")
        || (version == "HTTP/1.0" && !connection.iter().any(|t| t == "keep-alive"));
    let framing = if method == Method::Head || status == 204 || status == 304 || (100..200).contains(&status) {
        Framing::None
    } else if tokens("transfer-encoding").last().is_some_and(|t| t == "chunked") {
        Framing::Chunked
    } else if let Some(n) = length {
        Framing::Length(n)
    } else {
        Framing::Close
    };
    Ok(Head { status, headers, framing, close })
}

pub(crate) fn build_request(
    user_agent: &str,
    method: Method,
    url: &Url,
    headers: &[(String, String)],
    body: &Bytes,
    plain_proxy: Option<&Proxy>,
) -> Vec<u8> {
    let has = |name: &str| headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));
    let mut out = Vec::with_capacity(256 + body.len().min(COALESCE));
    let target =
        if plain_proxy.is_some() { format!("http://{}{}", url.authority(), url.target) } else { url.target.clone() };
    out.extend_from_slice(format!("{} {target} HTTP/1.1\r\n", method.as_str()).as_bytes());
    let mut line = |k: &str, v: &str| out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    if !has("host") {
        line("Host", &url.authority());
    }
    for (k, v) in headers {
        if !matches!(lower(k).as_str(), "content-length" | "transfer-encoding") {
            line(k, v);
        }
    }
    if !has("user-agent") {
        line("User-Agent", user_agent);
    }
    if !has("accept") {
        line("Accept", "*/*");
    }
    if !has("authorization")
        && let Some((user, pass)) = &url.userinfo
    {
        line("Authorization", &format!("Basic {}", crate::crypto::b64(format!("{user}:{pass}").as_bytes())));
    }
    if let Some(auth) = plain_proxy.and_then(|p| p.auth.as_deref())
        && !has("proxy-authorization")
    {
        line("Proxy-Authorization", auth);
    }
    if !body.is_empty() || matches!(method, Method::Post | Method::Put | Method::Patch) {
        line("Content-Length", &body.len().to_string());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// `s` as a number in `radix`: digits only, so no sign or space a lenient parser would accept (`+5`) and a proxy in front might read differently.
pub(crate) fn digits(s: &str, radix: u32) -> Option<u64> {
    let all = !s.is_empty() && s.chars().all(|c| c.is_digit(radix));
    all.then(|| u64::from_str_radix(s, radix).ok()).flatten()
}

/// 301 and 302 turn a `POST` into a `GET`, 303 turns anything but `GET` and `HEAD` into one; 307 and 308 keep the request.
pub(crate) fn redirect_becomes_get(status: u16, method: Method) -> bool {
    match status {
        301 | 302 => method == Method::Post,
        303 => !matches!(method, Method::Get | Method::Head),
        _ => false,
    }
}

/// Headers that would break the framing (or smuggle a request) are refused before anything is sent.
pub(crate) fn check_request(req: &Request) -> Result<()> {
    let token =
        |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
    if let Some((k, _)) = req.headers.iter().find(|(k, _)| !token(k)) {
        return Err(bad_request(&format!("invalid header name {k:?}")));
    }
    if let Some((k, _)) = req.headers.iter().find(|(_, v)| v.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))) {
        return Err(bad_request(&format!("invalid value for header {k}")));
    }
    Ok(())
}

pub(crate) fn lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

pub(crate) fn bad_request(what: &str) -> Error {
    Error::transport(format!("bad request: {what}"))
}

/// The `CONNECT` request that opens a tunnel to the origin of `url` through `proxy`.
pub(crate) fn connect_request(url: &Url, proxy: &Proxy) -> Vec<u8> {
    let authority =
        format!("{}:{}", if url.host.contains(':') { format!("[{}]", url.host) } else { url.host.clone() }, url.port);
    let mut text = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(auth) = &proxy.auth {
        text.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
    }
    text.push_str("\r\n");
    text.into_bytes()
}
