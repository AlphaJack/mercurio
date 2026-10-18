//! I/O backends. [`DefaultTransport`] uses blocking `ureq` for HTTP and `std::net` + `rustls` for raw sockets.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::http::{DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT, Method, Request, Response};

/// Executes the I/O a [`crate::Plan`] asks for.
///
/// Implement this to plug in another HTTP client, a proxy or a test double. Only [`Transport::http`] is required.
///
/// Outside this crate only `http` and `sleep` can be implemented: the argument types of `connect`, `datagram` and `command` are private. A custom transport, including a wrapper around [`DefaultTransport`], makes the services that need them (e-mail and other socket protocols, syslog, desktop notifications) fail with [`Error::Unsupported`].
///
/// Return an error from `http` only when no response arrived: [`Error::transport`] when nothing was sent (DNS, refused, connect timeout; `?retry=` repeats it), [`Error::Unconfirmed`] when the request may have arrived (read timeout, reset after sending; not repeated).
pub trait Transport: Send + Sync {
    /// Execute one HTTP request. Non-2xx statuses are responses, not errors.
    fn http(&self, req: &Request) -> Result<Response>;

    /// Open a stream to `ep` (TLS from the start when `ep.tls`). Default: unsupported.
    fn connect(&self, ep: &Endpoint) -> Result<Box<dyn Conn>> {
        let _ = ep;
        Err(Error::Unsupported("raw sockets are not available with this transport".into()))
    }

    /// Send one datagram. Default: unsupported.
    fn datagram(&self, dg: &Datagram) -> Result<()> {
        let _ = dg;
        Err(Error::Unsupported("datagrams are not available with this transport".into()))
    }

    /// Run a local program and collect its output. Default: unsupported.
    fn command(&self, cmd: &Command) -> Result<CommandOutput> {
        let _ = cmd;
        Err(Error::Unsupported("running local programs is not available with this transport".into()))
    }

    /// Block for `d` (throttling, retry waits). Default: `std::thread::sleep`.
    #[expect(clippy::disallowed_methods, reason = "the real transport really waits")]
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

impl<T: Transport + ?Sized> Transport for Arc<T> {
    fn http(&self, req: &Request) -> Result<Response> {
        (**self).http(req)
    }
    fn connect(&self, ep: &Endpoint) -> Result<Box<dyn Conn>> {
        (**self).connect(ep)
    }
    fn datagram(&self, dg: &Datagram) -> Result<()> {
        (**self).datagram(dg)
    }
    fn command(&self, cmd: &Command) -> Result<CommandOutput> {
        (**self).command(cmd)
    }
    fn sleep(&self, d: Duration) {
        (**self).sleep(d)
    }
}

/// Where to open a stream.
#[derive(Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    /// TLS from the first byte (e.g. SMTPS on 465).
    pub tls: bool,
    pub verify_tls: bool,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Endpoint({}:{}, tls={})", self.host, self.port, self.tls)
    }
}

impl Endpoint {
    pub fn new(host: impl Into<String>, port: u16, tls: bool) -> Self {
        Self {
            host: host.into(),
            port,
            tls,
            verify_tls: true,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            read_timeout: DEFAULT_READ_TIMEOUT,
        }
    }
}

/// A connected byte stream.
pub trait Conn: Read + Write + Send {
    /// Upgrade a plain connection to TLS in place (STARTTLS).
    fn start_tls(&mut self) -> Result<()> {
        Err(Error::Unsupported("STARTTLS not supported by this connection".into()))
    }
    /// Whether the stream is currently encrypted.
    fn is_tls(&self) -> bool {
        false
    }
}

/// Destination of a [`Datagram`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatagramTarget {
    Udp {
        host: String,
        port: u16,
    },
    /// Unix datagram socket path (e.g. `/dev/log`).
    Unix(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub target: DatagramTarget,
    pub payload: Vec<u8>,
}

/// A local program to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub program: String,
    pub args: Vec<String>,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Duration,
    /// Files the program reads, written by the transport before it runs (bundled assets such as the icon; skipped when already up to date).
    pub files: Vec<(String, &'static [u8])>,
}

impl Command {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            stdin: None,
            timeout: Duration::from_secs(10),
            files: Vec::new(),
        }
    }
    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }
    pub fn args<I: IntoIterator<Item = S>, S: Into<String>>(mut self, a: I) -> Self {
        self.args.extend(a.into_iter().map(Into::into));
        self
    }
    /// A bundled file the transport writes to `path` before running the program.
    pub fn file(mut self, path: impl Into<String>, bytes: &'static [u8]) -> Self {
        self.files.push((path.into(), bytes));
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Real network I/O: `ureq` + rustls (ring), Mozilla roots from `webpki-roots`.
pub struct DefaultTransport {
    user_agent: String,
    verified: OnceLock<ureq::Agent>,
    unverified: OnceLock<ureq::Agent>,
}

impl fmt::Debug for DefaultTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DefaultTransport").field("user_agent", &self.user_agent).finish()
    }
}

impl Default for DefaultTransport {
    fn default() -> Self {
        Self::new()
    }
}

/// Response bodies larger than this are truncated.
const MAX_BODY: u64 = 16 * 1024 * 1024;

impl DefaultTransport {
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

impl Transport for DefaultTransport {
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
            .max_redirects(if req.follow_redirects { 10 } else { 0 });
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
            res.body_mut().with_config().limit(MAX_BODY).read_to_vec().map_err(map_ureq_error)?
        };
        Ok(Response { status, headers, body })
    }

    fn connect(&self, ep: &Endpoint) -> Result<Box<dyn Conn>> {
        Ok(Box::new(crate::net::NetConn::connect(ep)?))
    }

    fn datagram(&self, dg: &Datagram) -> Result<()> {
        match &dg.target {
            DatagramTarget::Udp { host, port } => {
                let addr = (host.as_str(), *port)
                    .to_socket_addrs()
                    .map_err(Error::transport)?
                    .next()
                    .ok_or_else(|| Error::transport(format!("cannot resolve {host}")))?;
                let bind = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
                let sock = UdpSocket::bind(bind).map_err(Error::transport)?;
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
pub(crate) fn tcp_connect(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let mut last = None;
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("cannot resolve {host}"))))
}
