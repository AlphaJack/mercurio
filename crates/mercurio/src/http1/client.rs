//! The HTTP/1.1 client both transports use: keep-alive pooling, redirects, retries on stale connections and forward proxies from the environment, over the connections a [`Dial`] opens. The bytes are [`super::wire`]'s, the exchanges [`super::exchange`]'s machines.
//!
//! It speaks what the services need and nothing else: no HTTP/2, cookies or compression.

use std::collections::BTreeMap;
use std::io;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::error::{Error, Result};
use crate::http::{MAX_REDIRECTS, Method, Request, Response};
use crate::http1::exchange::{self, ReadBody, SendRequest};
use crate::http1::proxy::{Proxy, ProxyEnv};
use crate::http1::url::Url;
use crate::http1::wire::{
    Framing, Head, bad_request, build_request, check_request, connect_request, lower, redirect_becomes_get,
};
use crate::transport::{AsyncConn, BoxFuture};

/// Idle connections kept per key.
const MAX_IDLE: usize = 32;
/// An idle connection older than this is not reused.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// The most read from a connection at once: large bodies arrive in few reads.
const READ_CHUNK: usize = 64 * 1024;
/// A redirect's body is read (to keep the connection) only up to this size.
const MAX_REDIRECT_BODY: u64 = 64 * 1024;

/// How a transport opens connections for the [`Client`].
pub(crate) trait Dial: Send + Sync {
    /// A connection's byte stream.
    type Stream: Stream;
    /// A TCP connection to the first address of `host` that answers within `limit`.
    fn tcp<'a>(&'a self, host: &'a str, port: u16, limit: Duration) -> BoxFuture<'a, io::Result<Self::Stream>>;
    /// TLS to `host` over `io` (ALPN `http/1.1`), checking its certificate when `verify`.
    fn tls<'a>(&'a self, io: Self::Stream, host: &'a str, verify: bool) -> BoxFuture<'a, Result<Self::Stream>>;
    /// `open`, given up after `limit` where the transport can (a blocking one relies on its socket timeouts instead).
    fn within<'a, T: Send + 'a>(&'a self, limit: Duration, open: BoxFuture<'a, Result<T>>) -> BoxFuture<'a, Result<T>>;
}

/// A connection's byte stream for the [`Client`].
pub(crate) trait Stream: AsyncConn + Send + 'static {
    /// Reads and writes give up after `rt` from now on.
    fn set_timeout(&mut self, rt: Duration);
    /// The server closed this idle connection, or sent bytes on it: it is not worth reusing.
    fn closed(&mut self) -> bool;
}

/// What a connection is for: connections are shared only between requests with the same key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PoolKey {
    tls: bool,
    host: String,
    port: u16,
    verify: bool,
    proxy: Option<(bool, String, u16)>,
}

struct Conn<S> {
    key: PoolKey,
    io: S,
    /// Bytes read but not consumed yet.
    buf: Vec<u8>,
    /// Taken from the pool, so the server may have closed it meanwhile.
    reused: bool,
    /// Where reads land, [`READ_CHUNK`] bytes, kept for the connection's life.
    scratch: Box<[u8]>,
}

/// Why one attempt on a connection failed.
enum Attempt {
    /// A reused connection was closed by the server before anything came back; a new connection may retry.
    Stale,
    Fail(Error),
}

/// Idle connections by key, each with when it was released.
type Idle<S> = BTreeMap<PoolKey, Vec<(Conn<S>, Instant)>>;

/// An HTTP/1.1 client over the connections `D` dials.
pub(crate) struct Client<D: Dial> {
    dial: D,
    user_agent: String,
    proxies: ProxyEnv,
    idle: Mutex<Idle<D::Stream>>,
}

impl<D: Dial> Client<D> {
    /// A client sending `user_agent` by default, with the proxies of the environment.
    pub(crate) fn new(dial: D, user_agent: String) -> Self {
        Self::with_proxies(dial, user_agent, ProxyEnv::from_env())
    }

    pub(crate) fn with_proxies(dial: D, user_agent: String, proxies: ProxyEnv) -> Self {
        Self { dial, user_agent, proxies, idle: Mutex::default() }
    }

    /// Send `req`, following redirects when it asks to.
    pub(crate) async fn send(&self, req: &Request) -> Result<Response> {
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
                if !url.same_origin(&next) {
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
    ) -> Result<(Head, Conn<D::Stream>)> {
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
        let wire = build_request(&self.user_agent, method, url, headers, body, proxy.filter(|_| !url.tls));
        loop {
            match round_trip(&mut conn, method, wire.clone(), body, req.read_timeout).await {
                Ok(head) => return Ok((head, conn)),
                Err(Attempt::Fail(e)) => return Err(e),
                Err(Attempt::Stale) => {
                    let key = conn.key.clone();
                    conn = self.connect(req, url, proxy, key).await?;
                }
            }
        }
    }

    fn checkout(&self, key: &PoolKey) -> Option<Conn<D::Stream>> {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        let list = idle.get_mut(key)?;
        let found = loop {
            let Some((mut conn, since)) = list.pop() else { break None };
            if since.elapsed() < IDLE_TIMEOUT && conn.buf.is_empty() && !conn.io.closed() {
                conn.reused = true;
                break Some(conn);
            }
        };
        if list.is_empty() {
            idle.remove(key);
        }
        found
    }

    fn release(&self, conn: Conn<D::Stream>) {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        let list = idle.entry(conn.key.clone()).or_default();
        list.retain(|(_, since)| since.elapsed() < IDLE_TIMEOUT);
        if list.len() >= MAX_IDLE {
            list.remove(0);
        }
        list.push((conn, Instant::now()));
    }

    /// A new connection to the origin of `url` (or its proxy), through TLS when `url` is `https`, within the connect timeout.
    async fn connect(&self, req: &Request, url: &Url, proxy: Option<&Proxy>, key: PoolKey) -> Result<Conn<D::Stream>> {
        let deadline = Instant::now() + req.connect_timeout;
        // Each step after TCP waits at most the read timeout, and never past the deadline: a blocking stream cannot be abandoned midway, so its timeouts are the only bound.
        let step = |io: &mut D::Stream| -> Result<()> {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(connect_timed_out());
            }
            io.set_timeout(req.read_timeout.min(left));
            Ok(())
        };
        let late = |e: Error| if Instant::now() >= deadline { connect_timed_out() } else { e };
        let open = async {
            let (host, port) = proxy.map_or((url.host.as_str(), url.port), |p| (p.host.as_str(), p.port));
            let mut io = self
                .dial
                .tcp(host, port, req.connect_timeout)
                .await
                .map_err(|e| Error::transport(format!("{host}:{port}: {e}")))?;
            if let Some(p) = proxy.filter(|p| p.tls) {
                step(&mut io)?;
                io = self
                    .dial
                    .tls(io, &p.host, req.verify_tls)
                    .await
                    .map_err(|e| late(e.context(format!("proxy {}:{}", p.host, p.port))))?;
            }
            if url.tls {
                if let Some(p) = proxy {
                    step(&mut io)?;
                    tunnel(&mut io, url, p).await.map_err(late)?;
                }
                step(&mut io)?;
                io = self.dial.tls(io, &url.host, req.verify_tls).await.map_err(late)?;
            }
            io.set_timeout(req.read_timeout);
            Ok(Conn { key: key.clone(), io, buf: Vec::new(), reused: false, scratch: vec![0; READ_CHUNK].into() })
        };
        self.dial.within(req.connect_timeout, Box::pin(open)).await
    }

    /// The whole body of the response, at most `limit` bytes (`max_body` names the limit in the error). The connection goes back to the pool when it can be reused.
    async fn read_body(
        &self,
        mut conn: Conn<D::Stream>,
        head: &Head,
        limit: u64,
        max_body: u64,
        rt: Duration,
    ) -> Result<Vec<u8>> {
        let mut machine = ReadBody::new(&head.framing, limit, max_body, std::mem::take(&mut conn.buf));
        conn.io.set_timeout(rt);
        crate::machine::run(&mut machine, &mut conn.io, &mut conn.scratch).await?;
        let (body, rest) = machine.finish();
        conn.buf = rest;
        let body = body?;
        if !head.close && head.framing != Framing::Close && conn.buf.is_empty() {
            self.release(conn);
        }
        Ok(body)
    }
}

/// Write the request and read the response head.
async fn round_trip<S: Stream>(
    conn: &mut Conn<S>,
    method: Method,
    wire: Vec<u8>,
    body: &Bytes,
    rt: Duration,
) -> std::result::Result<Head, Attempt> {
    let mut machine = SendRequest::new(wire, body, method, std::mem::take(&mut conn.buf));
    conn.io.set_timeout(rt);
    let ran = crate::machine::run(&mut machine, &mut conn.io, &mut conn.scratch).await;
    let (head, rest) = machine.finish();
    conn.buf = rest;
    ran.map_err(Attempt::Fail)?;
    match head {
        Ok(head) => Ok(head),
        Err(exchange::Trip::WriteFailed(e)) if conn.reused && e.kind() != io::ErrorKind::TimedOut => {
            Err(Attempt::Stale)
        }
        Err(exchange::Trip::WriteFailed(e)) => Err(Attempt::Fail(exchange::unconfirmed(&e, "send request"))),
        // The server closed an idle connection as the request went out: retried for idempotent methods only, as RFC 9110 9.2.2 allows.
        Err(exchange::Trip::NoResponse)
            if conn.reused && !matches!(method, Method::Post | Method::Patch | Method::Update) =>
        {
            Err(Attempt::Stale)
        }
        Err(exchange::Trip::NoResponse) => {
            Err(Attempt::Fail(Error::Unconfirmed("connection closed before a response".into())))
        }
        Err(exchange::Trip::Fail(e)) => Err(Attempt::Fail(e)),
    }
}

/// What connecting past the connect timeout reports, on both transports.
fn connect_timed_out() -> Error {
    Error::Transport("timed out (connect)".into())
}

/// `CONNECT` to the origin through `proxy`; `io` is the tunnel afterwards.
async fn tunnel<S: Stream>(io: &mut S, url: &Url, proxy: &Proxy) -> Result<()> {
    let failed = |e: &dyn std::fmt::Display| Error::transport(format!("proxy {}:{}: {e}", proxy.host, proxy.port));
    let mut machine = SendRequest::new(connect_request(url, proxy), &[], Method::Get, Vec::new());
    crate::machine::run(&mut machine, io, &mut [0u8; 4096]).await.map_err(|e| failed(&e))?;
    let head = match machine.finish().0 {
        Ok(head) => head,
        Err(exchange::Trip::WriteFailed(e)) => return Err(failed(&e)),
        Err(exchange::Trip::NoResponse) => return Err(failed(&"closed the connection")),
        Err(exchange::Trip::Fail(e)) => return Err(failed(&e)),
    };
    if !(200..300).contains(&head.status) {
        return Err(failed(&format!("refused CONNECT with status {}", head.status)));
    }
    Ok(())
}

/// Every case runs on both transports' connections against the same tokio server (on another worker, as the blocking client holds its own).
#[cfg(test)]
#[cfg(all(feature = "transport-tokio", feature = "transport-blocking"))]
mod tests {
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::blocking::client::StdDial;
    use crate::tokio::client::TokioDial;

    /// `case` once on tokio connections, once on blocking ones.
    macro_rules! both {
        ($name:ident, $case:ident) => {
            #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            async fn $name() {
                $case(TokioDial::default()).await;
                $case(StdDial::default()).await;
            }
        };
    }

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

    fn client<D: Dial>(dial: D) -> Client<D> {
        Client::with_proxies(dial, "test/1".into(), ProxyEnv::default())
    }

    both!(keeps_connections_alive_and_reads_every_framing, keeps_connections_alive_and_reads_every_framing_case);
    async fn keeps_connections_alive_and_reads_every_framing_case<D: Dial>(dial: D) {
        let (port, seen) = serve(|_, req| {
            Some(if req.starts_with("GET /chunked") {
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;x=y\r\nhello\r\n6\r\n world\r\n0\r\nX-T: 1\r\n\r\n".into()
            } else {
                ok("plain")
            })
        })
        .await;
        let c = client(dial);
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

    both!(close_delimited_bodies_are_not_pooled, close_delimited_bodies_are_not_pooled_case);
    async fn close_delimited_bodies_are_not_pooled_case<D: Dial>(dial: D) {
        let (port, seen) = serve(|_, _| Some(format!("HTTP/1.0 200 OK\r\n\r\nuntil close{CLOSE}"))).await;
        let c = client(dial);
        let url = format!("http://127.0.0.1:{port}/");
        assert_eq!(c.send(&Request::get(&url)).await.unwrap().body, b"until close");
        assert_eq!(c.send(&Request::get(&url)).await.unwrap().body, b"until close");
        let conns: Vec<_> = seen.lock().unwrap().iter().map(|(c, _)| *c).collect();
        assert_eq!(conns, [0, 1]);
    }

    both!(
        stale_connections_are_retried_for_idempotent_methods_only,
        stale_connections_are_retried_for_idempotent_methods_only_case
    );
    async fn stale_connections_are_retried_for_idempotent_methods_only_case<D: Dial>(dial: D) {
        // Each connection answers once, then closes on the next request without answering it.
        let answered = Arc::new(Mutex::new(std::collections::BTreeSet::new()));
        let (port, seen) = serve(move |conn, _| answered.lock().unwrap().insert(conn).then(|| ok("x"))).await;
        let c = client(dial);
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

    both!(redirects_follow_reqwest_rules, redirects_follow_reqwest_rules_case);
    async fn redirects_follow_reqwest_rules_case<D: Dial>(dial: D) {
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
        let c = client(dial);
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

    both!(plain_and_tunnelled_proxies, plain_and_tunnelled_proxies_case);
    async fn plain_and_tunnelled_proxies_case<D: Dial>(dial: D) {
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
        let c = Client::with_proxies(dial, "test/1".into(), env);
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

    both!(stalled_handshakes_end_at_the_connect_deadline, stalled_handshakes_end_at_the_connect_deadline_case);
    async fn stalled_handshakes_end_at_the_connect_deadline_case<D: Dial>(dial: D) {
        // Accepts every connection and never answers the TLS ClientHello.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        let c = client(dial);
        let mut req = Request::get(format!("https://127.0.0.1:{port}/"));
        req.connect_timeout = Duration::from_millis(300);
        req.read_timeout = Duration::from_secs(10);
        let start = Instant::now();
        let err = c.send(&req).await.unwrap_err();
        assert!(start.elapsed() < Duration::from_secs(3), "the read timeout did not apply: {:?}", start.elapsed());
        assert!(matches!(&err, Error::Transport(m) if m.contains("timed out")), "{err:?}");
    }

    both!(refuses_header_injection_and_bad_urls, refuses_header_injection_and_bad_urls_case);
    async fn refuses_header_injection_and_bad_urls_case<D: Dial>(dial: D) {
        let c = client(dial);
        let mut req = Request::get("http://127.0.0.1:9/");
        req.headers.push(("X-A".into(), "1\r\nX-B: 2".into()));
        assert!(matches!(c.send(&req).await.unwrap_err(), Error::Transport(m) if m.starts_with("bad request")));
        req.headers = vec![("Bad Name".into(), "1".into())];
        assert!(matches!(c.send(&req).await.unwrap_err(), Error::Transport(m) if m.starts_with("bad request")));
        let err = c.send(&Request::get("ftp://x/")).await.unwrap_err();
        assert!(matches!(&err, Error::Transport(m) if m.starts_with("bad request")), "{err:?}");
    }
}
