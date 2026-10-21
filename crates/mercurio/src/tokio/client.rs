//! A small HTTP/1.1 client on tokio and rustls: keep-alive pooling, redirects, `Content-Length`, chunked and close-delimited bodies, and forward proxies from the environment.
//!
//! It speaks what the services need and nothing else: no HTTP/2, cookies, compression or `Referer`.

use std::collections::BTreeMap;
use std::io;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::FutureExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use super::uri::{Proxy, ProxyEnv, Url};
use crate::error::{Error, Result};
use crate::http::{MAX_REDIRECTS, Method, Request, Response, body_too_large};

/// The longest response head (status line and headers) accepted.
const MAX_HEAD: usize = 64 * 1024;
/// Idle connections kept per origin.
const MAX_IDLE: usize = 32;
/// An idle connection older than this is not reused.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// A redirect's body is read (to keep the connection) only up to this size.
const MAX_REDIRECT_BODY: u64 = 64 * 1024;
/// Request bodies up to this size go out in the same write as the head.
const COALESCE: usize = 16 * 1024;

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// What a connection is for: connections are shared only between requests with the same key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PoolKey {
    tls: bool,
    host: String,
    port: u16,
    verify: bool,
    proxy: Option<(bool, String, u16)>,
}

struct Conn {
    key: PoolKey,
    io: Box<dyn Io>,
    /// Bytes read but not consumed yet.
    buf: Vec<u8>,
    /// Taken from the pool, so the server may have closed it meanwhile.
    reused: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Framing {
    None,
    Length(u64),
    Chunked,
    Close,
}

struct Head {
    status: u16,
    /// Names are lower-case.
    headers: Vec<(String, String)>,
    framing: Framing,
    /// The server will close the connection after this response.
    close: bool,
}

impl Head {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

/// Why one attempt on a connection failed.
enum Trip {
    /// A reused connection was closed by the server before anything came back; a new connection may retry.
    Stale,
    Fail(Error),
}

pub(super) struct Client {
    user_agent: String,
    proxies: ProxyEnv,
    idle: Mutex<BTreeMap<PoolKey, Vec<(Conn, Instant)>>>,
    /// TLS connectors, with and without certificate verification; they keep the session cache.
    tls: Mutex<[Option<TlsConnector>; 2]>,
}

impl Client {
    pub(super) fn new(user_agent: String) -> Self {
        Self { user_agent, proxies: ProxyEnv::from_env(), idle: Mutex::default(), tls: Mutex::default() }
    }

    pub(super) async fn send(&self, req: &Request) -> Result<Response> {
        check_request(req)?;
        let mut url = Url::parse(&req.url).map_err(|e| bad_request(&e))?;
        let (mut method, mut body, mut headers) = (req.method, req.body.clone(), req.headers.clone());
        let mut hops = 0;
        loop {
            let (head, conn) = self.exchange(req, method, &url, &headers, &body).await?;
            if req.follow_redirects
                && hops < MAX_REDIRECTS
                && matches!(head.status, 301 | 302 | 303 | 307 | 308)
                && let Some(next) = head.header("location").and_then(|l| url.join(l))
            {
                self.read_body(conn, &head, MAX_REDIRECT_BODY, 0, req.read_timeout).await.ok();
                if redirect_becomes_get(head.status, method) {
                    method = Method::Get;
                    body = Bytes::new();
                    headers.retain(|(k, _)| {
                        !matches!(
                            lower(k).as_str(),
                            "content-length" | "content-type" | "content-encoding" | "transfer-encoding"
                        )
                    });
                }
                if !url.same_host_port(&next) {
                    headers.retain(|(k, _)| {
                        !matches!(
                            lower(k).as_str(),
                            "authorization" | "cookie" | "cookie2" | "proxy-authorization" | "www-authenticate"
                        )
                    });
                }
                headers.retain(|(k, _)| !k.eq_ignore_ascii_case("referer"));
                if let Some(referer) = url.referer_for(&next) {
                    headers.push(("Referer".into(), referer));
                }
                url = next;
                hops += 1;
                continue;
            }
            let limit = if req.max_body == 0 { u64::MAX } else { req.max_body };
            let status = head.status;
            let body = self.read_body(conn, &head, limit, req.max_body, req.read_timeout).await?;
            return Ok(Response { status, headers: head.headers, body });
        }
    }

    /// Send the request on a pooled or new connection and read the response head.
    async fn exchange(
        &self,
        req: &Request,
        method: Method,
        url: &Url,
        headers: &[(String, String)],
        body: &Bytes,
    ) -> Result<(Head, Conn)> {
        let proxy = self.proxies.for_url(url);
        let key = PoolKey {
            tls: url.tls,
            host: url.host.clone(),
            port: url.port,
            verify: req.verify_tls,
            proxy: proxy.map(|p| (p.tls, p.host.clone(), p.port)),
        };
        let mut conn = match self.checkout(&key) {
            Some(c) => c,
            None => self.connect(req, url, proxy, key).await?,
        };
        let wire = self.build_request(method, url, headers, body, proxy.filter(|_| !url.tls));
        loop {
            match round_trip(&mut conn, method, &wire, body, req.read_timeout).await {
                Ok(head) => return Ok((head, conn)),
                Err(Trip::Fail(e)) => return Err(e),
                Err(Trip::Stale) => {
                    let key = conn.key.clone();
                    conn = self.connect(req, url, proxy, key).await?;
                }
            }
        }
    }

    fn build_request(
        &self,
        method: Method,
        url: &Url,
        headers: &[(String, String)],
        body: &Bytes,
        plain_proxy: Option<&Proxy>,
    ) -> Vec<u8> {
        let has = |name: &str| headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));
        let mut out = Vec::with_capacity(256 + body.len().min(COALESCE));
        let target = if plain_proxy.is_some() {
            format!("http://{}{}", url.authority(), url.target)
        } else {
            url.target.clone()
        };
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
            line("User-Agent", &self.user_agent);
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

    fn checkout(&self, key: &PoolKey) -> Option<Conn> {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        let list = idle.get_mut(key)?;
        let found = loop {
            let Some((mut conn, since)) = list.pop() else { break None };
            if since.elapsed() < IDLE_TIMEOUT && !closed_by_peer(&mut conn) {
                conn.reused = true;
                break Some(conn);
            }
        };
        if list.is_empty() {
            idle.remove(key);
        }
        found
    }

    fn release(&self, conn: Conn) {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        let list = idle.entry(conn.key.clone()).or_default();
        list.retain(|(_, since)| since.elapsed() < IDLE_TIMEOUT);
        if list.len() >= MAX_IDLE {
            list.remove(0);
        }
        list.push((conn, Instant::now()));
    }

    fn connector(&self, verify: bool) -> Result<TlsConnector> {
        let mut cache = self.tls.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = &mut cache[usize::from(verify)];
        if let Some(c) = slot {
            return Ok(c.clone());
        }
        let mut config = (*crate::net::tls_config(verify).map_err(|e| bad_request(&e.to_string()))?).clone();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(std::sync::Arc::new(config));
        *slot = Some(connector.clone());
        Ok(connector)
    }

    /// A new connection to the origin of `url` (or its proxy), through TLS when `url` is `https`, within the connect timeout.
    async fn connect(&self, req: &Request, url: &Url, proxy: Option<&Proxy>, key: PoolKey) -> Result<Conn> {
        let open = async {
            let (host, port) = proxy.map_or((url.host.as_str(), url.port), |p| (p.host.as_str(), p.port));
            let tcp = tcp_connect(host, port, req.connect_timeout)
                .await
                .map_err(|e| Error::transport(format!("{host}:{port}: {e}")))?;
            tcp.set_nodelay(true).ok();
            let mut io: Box<dyn Io> = Box::new(tcp);
            if let Some(p) = proxy.filter(|p| p.tls) {
                io = self
                    .handshake(io, &p.host, req.verify_tls)
                    .await
                    .map_err(|e| e.context(format!("proxy {}:{}", p.host, p.port)))?;
            }
            if url.tls {
                if let Some(p) = proxy {
                    io = tunnel(io, url, p, key.clone(), req.read_timeout).await?;
                }
                io = self.handshake(io, &url.host, req.verify_tls).await?;
            }
            Ok(Conn { key: key.clone(), io, buf: Vec::new(), reused: false })
        };
        timeout(req.connect_timeout, open).await.unwrap_or_else(|_| Err(Error::Transport("timed out (connect)".into())))
    }

    async fn handshake(&self, io: Box<dyn Io>, host: &str, verify: bool) -> Result<Box<dyn Io>> {
        let name = crate::net::server_name(host)?;
        let tls = self
            .connector(verify)?
            .connect(name, io)
            .await
            .map_err(|e| Error::transport(format!("TLS handshake: {e}")))?;
        Ok(Box::new(tls))
    }

    /// The whole body of the response, at most `limit` bytes (`max_body` names the limit in the error). The connection goes back to the pool when it can be reused.
    async fn read_body(&self, mut conn: Conn, head: &Head, limit: u64, max_body: u64, rt: Duration) -> Result<Vec<u8>> {
        let too_large = || if max_body == 0 { body_too_large(limit) } else { body_too_large(max_body) };
        let mut body = Vec::new();
        match head.framing {
            Framing::None => {}
            Framing::Length(n) => {
                if n > limit {
                    return Err(too_large());
                }
                body.reserve(usize::try_from(n).unwrap_or(0).min(1 << 20));
                take(&mut conn, n, &mut body, rt).await?;
            }
            Framing::Chunked => loop {
                let line = read_line(&mut conn, rt).await?;
                let size = line.split(';').next().unwrap_or_default().trim();
                let size = u64::from_str_radix(size, 16).map_err(|_| Error::Unconfirmed("bad chunk size".into()))?;
                if size == 0 {
                    while !read_line(&mut conn, rt).await?.is_empty() {}
                    break;
                }
                if body.len() as u64 + size > limit {
                    return Err(too_large());
                }
                take(&mut conn, size, &mut body, rt).await?;
                if !read_line(&mut conn, rt).await?.is_empty() {
                    return Err(Error::Unconfirmed("bad chunk".into()));
                }
            },
            Framing::Close => loop {
                if !conn.buf.is_empty() {
                    if (body.len() + conn.buf.len()) as u64 > limit {
                        return Err(too_large());
                    }
                    body.append(&mut conn.buf);
                }
                match fill(&mut conn, rt).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) => return Err(unconfirmed(&e, "receive body")),
                }
            },
        }
        if !head.close && head.framing != Framing::Close && conn.buf.is_empty() {
            self.release(conn);
        }
        Ok(body)
    }
}

/// Write the request and read the response head.
async fn round_trip(
    conn: &mut Conn,
    method: Method,
    wire: &[u8],
    body: &Bytes,
    rt: Duration,
) -> std::result::Result<Head, Trip> {
    let sent = async {
        if body.len() <= COALESCE {
            let mut all = Vec::with_capacity(wire.len() + body.len());
            all.extend_from_slice(wire);
            all.extend_from_slice(body);
            conn.io.write_all(&all).await
        } else {
            conn.io.write_all(wire).await?;
            conn.io.write_all(body).await
        }?;
        conn.io.flush().await
    };
    match timeout(rt, sent).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) if conn.reused => return Err(Trip::Stale),
        Ok(Err(e)) => return Err(Trip::Fail(unconfirmed(&e, "send request"))),
        Err(_) => return Err(Trip::Fail(Error::Unconfirmed("timed out (send request)".into()))),
    }
    match read_head(conn, method, rt).await {
        Ok(head) => Ok(head),
        // The server closed an idle connection as the request went out: retried for idempotent methods only, as RFC 9110 9.2.2 allows.
        Err(None) if conn.reused && !matches!(method, Method::Post | Method::Patch | Method::Update) => {
            Err(Trip::Stale)
        }
        Err(None) => Err(Trip::Fail(Error::Unconfirmed("connection closed before a response".into()))),
        Err(Some(e)) => Err(Trip::Fail(e)),
    }
}

/// `Err(None)`: the connection ended before the first byte of a response.
async fn read_head(conn: &mut Conn, method: Method, rt: Duration) -> std::result::Result<Head, Option<Error>> {
    loop {
        if let Some(end) = conn.buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4) {
            let head = parse_head(conn.buf.get(..end).unwrap_or_default(), method).map_err(Some);
            conn.buf.drain(..end);
            let head = head?;
            if (100..200).contains(&head.status) && head.status != 101 {
                continue;
            }
            return Ok(head);
        }
        if conn.buf.len() > MAX_HEAD {
            return Err(Some(Error::Unconfirmed("the response head is too large".into())));
        }
        let started = !conn.buf.is_empty();
        match fill(conn, rt).await {
            Ok(0) if started => return Err(Some(Error::Unconfirmed("connection closed mid-response".into()))),
            Ok(0) => return Err(None),
            Ok(_) => {}
            Err(e) if !started && is_reset(&e) => return Err(None),
            Err(e) => return Err(Some(unconfirmed(&e, "receive response"))),
        }
    }
}

fn parse_head(raw: &[u8], method: Method) -> Result<Head> {
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
        let mut lengths = named("content-length").flat_map(|v| v.split(',')).map(|v| v.trim().parse::<u64>());
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

/// Read more into `conn.buf`; 0 is the end of the stream. Gives up after `rt`.
async fn fill(conn: &mut Conn, rt: Duration) -> io::Result<usize> {
    conn.buf.reserve(16 * 1024);
    timeout(rt, conn.io.read_buf(&mut conn.buf)).await.unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
}

/// Move exactly `n` bytes of the body into `out`.
async fn take(conn: &mut Conn, mut n: u64, out: &mut Vec<u8>, rt: Duration) -> Result<()> {
    while n > 0 {
        if conn.buf.is_empty() {
            match fill(conn, rt).await {
                Ok(0) => return Err(Error::Unconfirmed("connection closed before the body ended".into())),
                Ok(_) => {}
                Err(e) => return Err(unconfirmed(&e, "receive body")),
            }
        }
        let k = usize::try_from(n).unwrap_or(usize::MAX).min(conn.buf.len());
        out.extend(conn.buf.drain(..k));
        n -= k as u64;
    }
    Ok(())
}

/// One line of chunked framing, without its `\r\n`.
async fn read_line(conn: &mut Conn, rt: Duration) -> Result<String> {
    loop {
        if let Some(end) = conn.buf.windows(2).position(|w| w == b"\r\n") {
            let line = String::from_utf8_lossy(conn.buf.get(..end).unwrap_or_default()).into_owned();
            conn.buf.drain(..end + 2);
            return Ok(line);
        }
        if conn.buf.len() > MAX_HEAD {
            return Err(Error::Unconfirmed("bad chunk framing".into()));
        }
        match fill(conn, rt).await {
            Ok(0) => return Err(Error::Unconfirmed("connection closed before the body ended".into())),
            Ok(_) => {}
            Err(e) => return Err(unconfirmed(&e, "receive body")),
        }
    }
}

/// `CONNECT` to the origin through `proxy`; the stream is the tunnel afterwards.
async fn tunnel(io: Box<dyn Io>, url: &Url, proxy: &Proxy, key: PoolKey, rt: Duration) -> Result<Box<dyn Io>> {
    let authority =
        format!("{}:{}", if url.host.contains(':') { format!("[{}]", url.host) } else { url.host.clone() }, url.port);
    let mut text = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(auth) = &proxy.auth {
        text.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
    }
    text.push_str("\r\n");
    let mut conn = Conn { key, io, buf: Vec::new(), reused: false };
    let failed = |e: &dyn std::fmt::Display| Error::transport(format!("proxy {}:{}: {e}", proxy.host, proxy.port));
    timeout(rt, conn.io.write_all(text.as_bytes()))
        .await
        .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
        .map_err(|e| failed(&e))?;
    let head = read_head(&mut conn, Method::Get, rt)
        .await
        .map_err(|e| e.map_or_else(|| failed(&"closed the connection"), |e| failed(&e)))?;
    if !(200..300).contains(&head.status) {
        return Err(failed(&format!("refused CONNECT with status {}", head.status)));
    }
    Ok(conn.io)
}

/// The first address of `host` that accepts a connection. Each address gets an equal share of what is left of `budget`, so an unreachable first address (a broken IPv6 route) leaves time for the others.
async fn tcp_connect(host: &str, port: u16, budget: Duration) -> io::Result<TcpStream> {
    let start = Instant::now();
    let addrs: Vec<_> = tokio::net::lookup_host((host, port)).await?.collect();
    let mut last = None;
    for (i, addr) in addrs.iter().enumerate() {
        let left = budget.saturating_sub(start.elapsed());
        let share = left / u32::try_from(addrs.len() - i).unwrap_or(u32::MAX);
        match timeout(share, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = Some(e),
            Err(_) => last = Some(io::ErrorKind::TimedOut.into()),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("cannot resolve {host}"))))
}

/// An idle connection the server has closed (or sent unexpected bytes on) is not worth reusing.
fn closed_by_peer(conn: &mut Conn) -> bool {
    if !conn.buf.is_empty() {
        return true;
    }
    let mut probe = [0u8; 1];
    conn.io.read(&mut probe).now_or_never().is_some()
}

fn is_reset(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    )
}

fn unconfirmed(e: &io::Error, what: &str) -> Error {
    if e.kind() == io::ErrorKind::TimedOut {
        Error::Unconfirmed(format!("timed out ({what})"))
    } else {
        Error::Unconfirmed(format!("{what}: {e}"))
    }
}

fn bad_request(what: &str) -> Error {
    Error::transport(format!("bad request: {what}"))
}

fn lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// 301 and 302 turn a `POST` into a `GET`, 303 turns anything but `GET` and `HEAD` into one; 307 and 308 keep the request.
fn redirect_becomes_get(status: u16, method: Method) -> bool {
    match status {
        301 | 302 => method == Method::Post,
        303 => !matches!(method, Method::Get | Method::Head),
        _ => false,
    }
}

/// Headers that would break the framing (or smuggle a request) are refused before anything is sent.
fn check_request(req: &Request) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::net::TcpListener;

    use super::*;

    type Seen = Arc<Mutex<Vec<(usize, String)>>>;

    /// Appended to an answer: close the connection after writing it.
    const CLOSE: &str = "\0close";

    /// A keep-alive server: `answer(connection, request)` is written back, `None` closes the connection unanswered. Every request is recorded with the index of its connection.
    async fn serve(answer: impl Fn(usize, &str) -> Option<String> + Send + Sync + 'static) -> (u16, Seen) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Seen::default();
        let (answer, log) = (Arc::new(answer), seen.clone());
        tokio::spawn(async move {
            for conn in 0..usize::MAX {
                let (mut s, _) = listener.accept().await.unwrap();
                let (answer, log) = (answer.clone(), log.clone());
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    loop {
                        let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4) else {
                            let mut b = [0u8; 4096];
                            match s.read(&mut b).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&b[..n]),
                            }
                            continue;
                        };
                        let head = String::from_utf8_lossy(&buf[..end]).to_string();
                        let len = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_string())
                            })
                            .and_then(|v| v.parse::<usize>().ok())
                            .unwrap_or(0);
                        while buf.len() < end + len {
                            let mut b = [0u8; 4096];
                            let n = s.read(&mut b).await.unwrap();
                            buf.extend_from_slice(&b[..n]);
                        }
                        let req = String::from_utf8_lossy(&buf[..end + len]).to_string();
                        buf.drain(..end + len);
                        log.lock().unwrap().push((conn, req.clone()));
                        match answer(conn, &req) {
                            Some(a) if a.ends_with(CLOSE) => {
                                s.write_all(a.trim_end_matches(CLOSE).as_bytes()).await.unwrap();
                                return;
                            }
                            Some(a) => s.write_all(a.as_bytes()).await.unwrap(),
                            None => return,
                        }
                    }
                });
            }
        });
        (port, seen)
    }

    fn ok(body: &str) -> String {
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len())
    }

    fn client() -> Client {
        Client { proxies: ProxyEnv::default(), ..Client::new("test/1".into()) }
    }

    #[tokio::test]
    async fn keeps_connections_alive_and_reads_every_framing() {
        let (port, seen) = serve(|_, req| {
            Some(if req.starts_with("GET /chunked") {
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;x=y\r\nhello\r\n6\r\n world\r\n0\r\nX-T: 1\r\n\r\n".into()
            } else {
                ok("plain")
            })
        })
        .await;
        let c = client();
        let base = format!("http://127.0.0.1:{port}");
        assert_eq!(c.send(&Request::get(format!("{base}/a"))).await.unwrap().body, b"plain");
        assert_eq!(c.send(&Request::get(format!("{base}/chunked"))).await.unwrap().body, b"hello world");
        assert_eq!(c.send(&Request::get(format!("{base}/b"))).await.unwrap().body, b"plain");
        let seen = seen.lock().unwrap();
        assert!(seen.iter().all(|(conn, _)| *conn == 0), "one connection for all three: {seen:?}");
        let first = &seen[0].1;
        assert!(first.starts_with("GET /a HTTP/1.1\r\nHost: 127.0.0.1:"), "{first}");
        assert!(first.contains("User-Agent: test/1\r\n") && first.contains("Accept: */*\r\n"), "{first}");
    }

    #[tokio::test]
    async fn close_delimited_bodies_are_not_pooled() {
        let (port, seen) = serve(|_, _| Some(format!("HTTP/1.0 200 OK\r\n\r\nuntil close{CLOSE}"))).await;
        let c = client();
        let url = format!("http://127.0.0.1:{port}/");
        assert_eq!(c.send(&Request::get(&url)).await.unwrap().body, b"until close");
        assert_eq!(c.send(&Request::get(&url)).await.unwrap().body, b"until close");
        let conns: Vec<_> = seen.lock().unwrap().iter().map(|(c, _)| *c).collect();
        assert_eq!(conns, [0, 1]);
    }

    #[tokio::test]
    async fn stale_connections_are_retried_for_idempotent_methods_only() {
        // Each connection answers once, then closes on the next request without answering it.
        let answered = Arc::new(Mutex::new(std::collections::BTreeSet::new()));
        let (port, seen) = serve(move |conn, _| answered.lock().unwrap().insert(conn).then(|| ok("x"))).await;
        let c = client();
        let url = format!("http://127.0.0.1:{port}/");
        assert_eq!(c.send(&Request::get(&url)).await.unwrap().status, 200);
        assert_eq!(c.send(&Request::get(&url)).await.unwrap().status, 200, "the GET is retried on a new connection");

        let mut post = Request::new(Method::Post, &url);
        post.body = Bytes::from_static(b"once");
        let err = c.send(&post).await.unwrap_err();
        assert!(matches!(err, Error::Unconfirmed(_)), "a POST is not sent twice: {err:?}");
        let conns: Vec<_> = seen.lock().unwrap().iter().map(|(c, _)| *c).collect();
        assert_eq!(conns, [0, 0, 1, 1]);
    }

    #[tokio::test]
    async fn redirects_follow_reqwest_rules() {
        let (other, other_seen) = serve(|_, _| Some(ok("done"))).await;
        let (port, seen) = serve(move |_, req| {
            Some(if req.starts_with("POST /form") {
                "HTTP/1.1 303 See Other\r\nLocation: /result\r\nContent-Length: 4\r\n\r\nmove".into()
            } else if req.starts_with("GET /result") {
                format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://localhost:{other}/x\r\nContent-Length: 0\r\n\r\n")
            } else {
                ok("?")
            })
        })
        .await;
        let c = client();
        let mut req = Request::new(Method::Post, format!("http://127.0.0.1:{port}/form?k=1"));
        req.body = Bytes::from_static(b"a=b");
        req.headers = vec![
            ("Content-Type".into(), "application/x-www-form-urlencoded".into()),
            ("Authorization".into(), "Bearer secret".into()),
        ];
        let res = c.send(&req).await.unwrap();
        assert_eq!((res.status, res.body.as_slice()), (200, &b"done"[..]));

        let seen = seen.lock().unwrap();
        let second = &seen[1].1;
        assert!(second.starts_with("GET /result HTTP/1.1"), "303 turns the POST into a GET: {second}");
        assert!(!second.contains("Content-Type") && !second.contains("Content-Length"), "{second}");
        assert!(second.contains("Authorization: Bearer secret"), "same host keeps credentials: {second}");
        assert!(second.contains(&format!("Referer: http://127.0.0.1:{port}/form?k=1\r\n")), "{second}");
        let last = &other_seen.lock().unwrap()[0].1;
        assert!(!last.contains("Authorization"), "another host gets no credentials: {last}");
        assert!(last.contains(&format!("Referer: http://127.0.0.1:{port}/result\r\n")), "{last}");
    }

    #[tokio::test]
    async fn plain_and_tunnelled_proxies() {
        let (proxy, seen) = serve(|_, req| {
            Some(if req.starts_with("CONNECT") {
                "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".into()
            } else {
                ok("via proxy")
            })
        })
        .await;
        let env = ProxyEnv::from_lookup(|n| match n {
            "HTTP_PROXY" | "HTTPS_PROXY" => Some(format!("http://u:p@127.0.0.1:{proxy}")),
            _ => None,
        });
        let c = Client { proxies: env, ..client() };
        let res = c.send(&Request::get("http://origin.test/path?q")).await.unwrap();
        assert_eq!(res.body, b"via proxy");
        let first = seen.lock().unwrap()[0].1.clone();
        assert!(first.starts_with("GET http://origin.test/path?q HTTP/1.1\r\nHost: origin.test\r\n"), "{first}");
        assert!(first.contains("Proxy-Authorization: Basic dTpw\r\n"), "{first}");

        let err = c.send(&Request::get("https://origin.test/")).await.unwrap_err();
        assert!(matches!(&err, Error::Transport(m) if m.contains("refused CONNECT with status 403")), "{err:?}");
        let connect = seen.lock().unwrap()[1].1.clone();
        assert!(
            connect.starts_with(
                "CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test:443\r\nProxy-Authorization: Basic dTpw\r\n"
            ),
            "{connect}"
        );
    }

    #[tokio::test]
    async fn refuses_header_injection_and_bad_urls() {
        let c = client();
        let mut req = Request::get("http://127.0.0.1:9/");
        req.headers.push(("X-A".into(), "1\r\nX-B: 2".into()));
        assert!(matches!(c.send(&req).await.unwrap_err(), Error::Transport(m) if m.starts_with("bad request")));
        req.headers = vec![("Bad Name".into(), "1".into())];
        assert!(matches!(c.send(&req).await.unwrap_err(), Error::Transport(m) if m.starts_with("bad request")));
        let err = c.send(&Request::get("ftp://x/")).await.unwrap_err();
        assert!(matches!(&err, Error::Transport(m) if m.starts_with("bad request")), "{err:?}");
    }
}
