//! The blocking transport (feature `transport-blocking`): [`BlockingTransport`] does HTTP with the in-house client ([`crate::http1::client`]) on `std::net` + rustls, and [`NetConn`] streams the same way.

pub(crate) mod client;

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use rustls::{ClientConnection, StreamOwned};

use crate::error::{Error, Result};
use crate::http::{Request, Response};
use crate::net::{server_name, tls_config};
use crate::transport::{
    Command, CommandOutput, Conn, Datagram, DatagramTarget, Endpoint, NativeCall, Transport, unbound_addr,
};
use client::{Client, StdDial};

/// Real network I/O on `std::net` + rustls (ring): HTTP through the same client as the tokio transport.
pub struct BlockingTransport {
    user_agent: String,
    client: Client,
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
        let user_agent = ua.into();
        Self { client: Client::new(StdDial::default(), user_agent.clone()), user_agent }
    }
}

impl Transport for BlockingTransport {
    fn http(&self, req: &Request) -> Result<Response> {
        // Every future of the blocking client is complete when polled, so this never parks.
        pollster::block_on(self.client.send(req))
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

    fn native(&self, call: &NativeCall) -> Result<()> {
        match call {
            #[cfg(windows)]
            NativeCall::Toast(toast) => crate::winrt::show(toast),
            #[cfg(not(windows))]
            NativeCall::Toast(_) => Err(crate::transport::no_native()),
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
        let mut proc = Proc::new(&cmd.program);
        proc.args(&cmd.args)
            .stdin(if cmd.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        std::os::windows::process::CommandExt::creation_flags(&mut proc, crate::transport::NO_WINDOW);
        let mut child = proc.spawn().map_err(|e| Error::transport(format!("{}: {e}", cmd.program)))?;
        if let Some(input) = &cmd.stdin
            && let Some(mut stdin) = child.stdin.take()
        {
            stdin.write_all(input).map_err(Error::transport)?;
        }
        let out = child.wait_with_output().map_err(Error::transport)?;
        Ok(CommandOutput { status: out.status.code().unwrap_or(-1), stdout: out.stdout, stderr: out.stderr })
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
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
    Swapping,
}

/// A TCP stream that can be upgraded to TLS in place, or a Unix stream socket.
pub struct NetConn {
    inner: Inner,
    host: String,
    verify: bool,
}

impl NetConn {
    pub fn connect(ep: &Endpoint) -> Result<Self> {
        if let Some(path) = &ep.unix {
            return Self::connect_unix(ep, path);
        }
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

    #[cfg(unix)]
    fn connect_unix(ep: &Endpoint, path: &str) -> Result<Self> {
        let sock = crate::net::unix_connect(path).map_err(|e| Error::transport(format!("{}: {e}", ep.address())))?;
        sock.set_read_timeout(Some(ep.read_timeout)).ok();
        sock.set_write_timeout(Some(ep.read_timeout)).ok();
        Ok(NetConn { inner: Inner::Unix(sock), host: String::new(), verify: ep.verify_tls })
    }

    #[cfg(not(unix))]
    fn connect_unix(_: &Endpoint, _: &str) -> Result<Self> {
        Err(Error::Unsupported("unix sockets".into()))
    }
}

impl Conn for NetConn {
    fn start_tls(&mut self) -> Result<()> {
        let tcp = match std::mem::replace(&mut self.inner, Inner::Swapping) {
            Inner::Plain(t) => t,
            #[cfg(unix)]
            other @ Inner::Unix(_) => {
                self.inner = other;
                return Err(Error::transport("TLS over a Unix socket"));
            }
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

    fn channel_binding(&self, kind: crate::transport::ChannelBinding) -> Option<Vec<u8>> {
        match &self.inner {
            Inner::Tls(s) => crate::net::channel_binding(&s.conn, kind),
            #[cfg(unix)]
            Inner::Unix(_) => None,
            Inner::Plain(_) | Inner::Swapping => None,
        }
    }
}

impl Read for NetConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            Inner::Plain(t) => t.read(buf),
            Inner::Tls(s) => s.read(buf),
            #[cfg(unix)]
            Inner::Unix(u) => u.read(buf),
            Inner::Swapping => Err(io::Error::other("connection unavailable")),
        }
    }
}

impl Write for NetConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.inner {
            Inner::Plain(t) => t.write(buf),
            Inner::Tls(s) => s.write(buf),
            #[cfg(unix)]
            Inner::Unix(u) => u.write(buf),
            Inner::Swapping => Err(io::Error::other("connection unavailable")),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match &mut self.inner {
            Inner::Plain(t) => t.flush(),
            Inner::Tls(s) => s.flush(),
            #[cfg(unix)]
            Inner::Unix(u) => u.flush(),
            Inner::Swapping => Ok(()),
        }
    }
}

impl std::fmt::Debug for NetConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetConn").field("host", &self.host).field("tls", &self.is_tls()).finish()
    }
}
