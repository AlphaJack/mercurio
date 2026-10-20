//! The blocking transport (feature `transport-blocking`): [`BlockingTransport`] does HTTP with `ureq`, and [`NetConn`] streams with `std::net` + rustls.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::OnceLock;
use std::time::Duration;

use rustls::{ClientConnection, StreamOwned};

use crate::error::{Error, Result};
use crate::http::{MAX_REDIRECTS, Method, Request, Response};
use crate::net::{server_name, tls_config};
use crate::transport::{Command, CommandOutput, Conn, Datagram, DatagramTarget, Endpoint, Transport, unbound_addr};

/// Real network I/O: `ureq` + rustls (ring), Mozilla roots from `webpki-roots`.
pub struct BlockingTransport {
    user_agent: String,
    verified: OnceLock<ureq::Agent>,
    unverified: OnceLock<ureq::Agent>,
}

impl fmt::Debug for BlockingTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingTransport").field("user_agent", &self.user_agent).finish()
    }
}

impl Default for BlockingTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockingTransport {
    /// A transport whose `User-Agent` is `Mercurio/<version>`; requests that set their own keep it.
    pub fn new() -> Self {
        Self::with_user_agent(format!("Mercurio/{}", env!("CARGO_PKG_VERSION")))
    }

    /// A transport with a custom default `User-Agent`.
    pub fn with_user_agent(ua: impl Into<String>) -> Self {
        Self { user_agent: ua.into(), verified: OnceLock::new(), unverified: OnceLock::new() }
    }

    fn agent(&self, verify: bool) -> &ureq::Agent {
        let cell = if verify { &self.verified } else { &self.unverified };
        cell.get_or_init(|| {
            let mut tls = ureq::tls::TlsConfig::builder().disable_verification(!verify);
            if let Some(certs) = crate::net::ca_bundle() {
                let certs: Vec<_> = certs.iter().map(|c| ureq::tls::Certificate::from_der(c).to_owned()).collect();
                tls = tls.root_certs(ureq::tls::RootCerts::new_with_certs(&certs));
            }
            let tls = tls.build();
            ureq::Agent::config_builder()
                .tls_config(tls)
                .http_status_as_error(false)
                .user_agent(&self.user_agent)
                .max_redirects_will_error(false)
                .build()
                .into()
        })
    }
}

impl Transport for BlockingTransport {
    fn http(&self, req: &Request) -> Result<Response> {
        use ureq::RequestExt;
        let mut builder = ureq::http::Request::builder().method(req.method.as_str()).uri(&req.url);
        let mut has_ua = false;
        for (k, v) in &req.headers {
            has_ua |= k.eq_ignore_ascii_case("user-agent");
            builder = builder.header(k.as_str(), v.as_str());
        }
        if !has_ua {
            builder = builder.header("User-Agent", self.user_agent.as_str());
        }
        let http_req = builder.body(req.body.clone()).map_err(|e| Error::transport(format!("bad request: {e}")))?;
        let agent = self.agent(req.verify_tls);
        let configured = http_req
            .with_agent(agent)
            .configure()
            .http_status_as_error(false)
            .timeout_connect(Some(req.connect_timeout))
            .timeout_resolve(Some(req.connect_timeout))
            .timeout_recv_response(Some(req.read_timeout))
            .timeout_recv_body(Some(req.read_timeout))
            .max_redirects(if req.follow_redirects { MAX_REDIRECTS } else { 0 });
        let mut res = configured.run().map_err(map_ureq_error)?;
        let status = res.status().as_u16();
        let headers = res
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
            .collect();
        let body = if req.method == Method::Head {
            Vec::new()
        } else {
            let limit = if req.max_body == 0 { u64::MAX } else { req.max_body };
            res.body_mut().with_config().limit(limit).read_to_vec().map_err(|e| {
                if matches!(e, ureq::Error::BodyExceedsLimit(_)) {
                    crate::http::body_too_large(req.max_body)
                } else {
                    map_ureq_error(e)
                }
            })?
        };
        Ok(Response { status, headers, body })
    }

    fn connect(&self, ep: &Endpoint) -> Result<Box<dyn Conn>> {
        Ok(Box::new(NetConn::connect(ep)?))
    }

    #[expect(clippy::disallowed_methods, reason = "the blocking transport")]
    fn datagram(&self, dg: &Datagram) -> Result<()> {
        match &dg.target {
            DatagramTarget::Udp { host, port } => {
                let addr = (host.as_str(), *port)
                    .to_socket_addrs()
                    .map_err(Error::transport)?
                    .next()
                    .ok_or_else(|| Error::transport(format!("cannot resolve {host}")))?;
                let sock = UdpSocket::bind(unbound_addr(&addr)).map_err(Error::transport)?;
                sock.send_to(&dg.payload, addr).map_err(Error::transport)?;
                Ok(())
            }
            #[cfg(unix)]
            DatagramTarget::Unix(path) => {
                let sock = std::os::unix::net::UnixDatagram::unbound().map_err(Error::transport)?;
                sock.send_to(&dg.payload, path).map_err(Error::transport)?;
                Ok(())
            }
            #[cfg(not(unix))]
            DatagramTarget::Unix(_) => Err(Error::Unsupported("unix sockets".into())),
        }
    }

    #[expect(clippy::disallowed_methods, reason = "the blocking transport")]
    fn command(&self, cmd: &Command) -> Result<CommandOutput> {
        use std::process::{Command as Proc, Stdio};
        for (path, bytes) in &cmd.files {
            let path = std::path::Path::new(path);
            if std::fs::read(path).ok().as_deref() != Some(*bytes) {
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir).map_err(|e| Error::transport(format!("{}: {e}", dir.display())))?;
                }
                std::fs::write(path, bytes).map_err(|e| Error::transport(format!("{}: {e}", path.display())))?;
            }
        }
        let mut child = Proc::new(&cmd.program)
            .args(&cmd.args)
            .stdin(if cmd.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::transport(format!("{}: {e}", cmd.program)))?;
        if let Some(input) = &cmd.stdin
            && let Some(mut stdin) = child.stdin.take()
        {
            stdin.write_all(input).map_err(Error::transport)?;
        }
        let out = child.wait_with_output().map_err(Error::transport)?;
        Ok(CommandOutput { status: out.status.code().unwrap_or(-1), stdout: out.stdout, stderr: out.stderr })
    }
}

/// Failures before the request left (resolve, connect) are [`Error::Transport`]; later ones are [`Error::Unconfirmed`] because the service may already have acted on the request.
#[expect(clippy::wildcard_enum_match_arm, reason = "io::ErrorKind and ureq::Error are non-exhaustive")]
fn map_ureq_error(e: ureq::Error) -> Error {
    use std::io::ErrorKind;
    use ureq::Timeout;
    match e {
        ureq::Error::Timeout(t @ (Timeout::Resolve | Timeout::Connect)) => Error::Transport(format!("timed out ({t})")),
        ureq::Error::Timeout(t) => Error::Unconfirmed(format!("timed out ({t})")),
        ureq::Error::Io(io) => match io.kind() {
            ErrorKind::ConnectionRefused
            | ErrorKind::NotFound
            | ErrorKind::AddrNotAvailable
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable
            | ErrorKind::NetworkDown => Error::Transport(io.to_string()),
            _ => Error::Unconfirmed(io.to_string()),
        },
        ureq::Error::Protocol(p) => Error::Unconfirmed(p.to_string()),
        other => Error::Transport(other.to_string()),
    }
}

/// Plain TCP connect honouring a timeout across all resolved addresses.
#[expect(clippy::disallowed_methods, reason = "the blocking transport")]
fn tcp_connect(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let mut last = None;
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("cannot resolve {host}"))))
}

enum Inner {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
    Swapping,
}

/// A TCP stream that can be upgraded to TLS in place.
pub struct NetConn {
    inner: Inner,
    host: String,
    verify: bool,
}

impl NetConn {
    pub fn connect(ep: &Endpoint) -> Result<Self> {
        let tcp = tcp_connect(&ep.host, ep.port, ep.connect_timeout)
            .map_err(|e| Error::transport(format!("{}:{}: {e}", ep.host, ep.port)))?;
        tcp.set_read_timeout(Some(ep.read_timeout)).ok();
        tcp.set_write_timeout(Some(ep.read_timeout)).ok();
        let mut c = NetConn { inner: Inner::Plain(tcp), host: ep.host.clone(), verify: ep.verify_tls };
        if ep.tls {
            c.start_tls()?;
        }
        Ok(c)
    }
}

impl Conn for NetConn {
    fn start_tls(&mut self) -> Result<()> {
        let tcp = match std::mem::replace(&mut self.inner, Inner::Swapping) {
            Inner::Plain(t) => t,
            other @ (Inner::Tls(_) | Inner::Swapping) => {
                self.inner = other;
                return Err(Error::transport("connection already uses TLS"));
            }
        };
        let conn = ClientConnection::new(tls_config(self.verify).map_err(Error::transport)?, server_name(&self.host)?)
            .map_err(Error::transport)?;
        let mut stream = StreamOwned::new(conn, tcp);
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock).map_err(|e| Error::transport(format!("TLS handshake: {e}")))?;
        }
        self.inner = Inner::Tls(Box::new(stream));
        Ok(())
    }

    fn is_tls(&self) -> bool {
        matches!(self.inner, Inner::Tls(_))
    }
}

impl Read for NetConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            Inner::Plain(t) => t.read(buf),
            Inner::Tls(s) => s.read(buf),
            Inner::Swapping => Err(io::Error::other("connection unavailable")),
        }
    }
}

impl Write for NetConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.inner {
            Inner::Plain(t) => t.write(buf),
            Inner::Tls(s) => s.write(buf),
            Inner::Swapping => Err(io::Error::other("connection unavailable")),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match &mut self.inner {
            Inner::Plain(t) => t.flush(),
            Inner::Tls(s) => s.flush(),
            Inner::Swapping => Ok(()),
        }
    }
}

impl std::fmt::Debug for NetConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetConn").field("host", &self.host).field("tls", &self.is_tls()).finish()
    }
}
