//! The blocking side of the HTTP client ([`crate::http1::client`]): [`StdDial`] opens TCP and TLS connections with `std::net` and rustls, [`StdStream`] reads and writes them under socket timeouts. Every future it returns is complete when polled.

use std::future::ready;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::error::{Error, Result};
use crate::http::DEFAULT_READ_TIMEOUT;
use crate::http1::client::{Dial, Stream};
use crate::http1::wire::bad_request;
use crate::transport::{AsyncConn, BoxFuture};

/// The HTTP client of [`super::BlockingTransport`].
pub(super) type Client = crate::http1::client::Client<StdDial>;

trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

/// TLS over another stream: TCP, or the TLS to an HTTPS proxy that a tunnel runs through.
type TlsStream = StreamOwned<ClientConnection, Box<dyn ReadWrite>>;

/// Opens connections with `std::net`.
#[derive(Default)]
pub(crate) struct StdDial {
    /// TLS configurations, with and without certificate verification; they keep the session cache.
    tls: Mutex<[Option<Arc<ClientConfig>>; 2]>,
}

impl StdDial {
    fn config(&self, verify: bool) -> Result<Arc<ClientConfig>> {
        let mut cache = self.tls.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = &mut cache[usize::from(verify)];
        if let Some(c) = slot {
            return Ok(c.clone());
        }
        let mut config = (*crate::net::tls_config(verify).map_err(|e| bad_request(&e.to_string()))?).clone();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        *slot = Some(config.clone());
        Ok(config)
    }

    fn handshake(&self, io: StdStream, host: &str, verify: bool) -> Result<StdStream> {
        let conn =
            ClientConnection::new(self.config(verify)?, crate::net::server_name(host)?).map_err(Error::transport)?;
        let inner: Box<dyn ReadWrite> = match io.io {
            Layer::Plain(t) => Box::new(t),
            Layer::Tls(s) => s,
        };
        let mut tls = StreamOwned::new(conn, inner);
        while tls.conn.is_handshaking() {
            tls.conn
                .complete_io(&mut tls.sock)
                .map_err(|e| Error::transport(format!("TLS handshake: {}", timed_out(e))))?;
        }
        Ok(StdStream { io: Layer::Tls(Box::new(tls)), socket: io.socket })
    }
}

impl Dial for StdDial {
    type Stream = StdStream;

    fn tcp<'a>(&'a self, host: &'a str, port: u16, limit: Duration) -> BoxFuture<'a, io::Result<StdStream>> {
        Box::pin(ready(tcp_connect(host, port, limit).map(|tcp| {
            tcp.set_nodelay(true).ok();
            let tcp = Arc::new(tcp);
            let mut stream = StdStream { socket: tcp.clone(), io: Layer::Plain(Tcp(tcp)) };
            stream.set_timeout(DEFAULT_READ_TIMEOUT);
            stream
        })))
    }

    fn tls<'a>(&'a self, io: StdStream, host: &'a str, verify: bool) -> BoxFuture<'a, Result<StdStream>> {
        Box::pin(ready(self.handshake(io, host, verify)))
    }

    /// A blocking call cannot be abandoned: the client bounds each step by the time left instead (TCP by its budget, the rest by socket timeouts).
    fn within<'a, T: Send + 'a>(
        &'a self,
        _limit: Duration,
        open: BoxFuture<'a, Result<T>>,
    ) -> BoxFuture<'a, Result<T>> {
        open
    }
}

enum Layer {
    Plain(Tcp),
    Tls(Box<TlsStream>),
}

/// The TCP socket that a [`Layer`] reads and writes. The same handle as [`StdStream::socket`]: on Windows, a clone
/// from `try_clone` keeps timeouts of its own, which reads on the original ignore.
struct Tcp(Arc<TcpStream>);

impl Read for Tcp {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self.0).read(buf)
    }
}

impl Write for Tcp {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        (&*self.0).write(data)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&*self.0).flush()
    }
}

/// A plain or TLS stream; `socket` is its TCP socket, for its timeouts and the idle probe.
pub(crate) struct StdStream {
    io: Layer,
    socket: Arc<TcpStream>,
}

impl StdStream {
    fn read_now(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.io {
            Layer::Plain(t) => t.read(buf),
            Layer::Tls(s) => s.read(buf),
        }
        .map_err(timed_out)
    }

    fn write_now(&mut self, data: &[u8]) -> io::Result<()> {
        match &mut self.io {
            Layer::Plain(t) => t.write_all(data),
            Layer::Tls(s) => s.write_all(data),
        }
        .map_err(timed_out)
    }

    fn flush_now(&mut self) -> io::Result<()> {
        match &mut self.io {
            Layer::Plain(t) => t.flush(),
            Layer::Tls(s) => s.flush(),
        }
        .map_err(timed_out)
    }
}

impl AsyncConn for StdStream {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(ready(self.read_now(buf)))
    }
    fn write_all<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(ready(self.write_now(data)))
    }
    fn flush(&mut self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(ready(self.flush_now()))
    }
    fn start_tls(&mut self) -> BoxFuture<'_, Result<()>> {
        Box::pin(ready(Err(Error::Unsupported("STARTTLS on an HTTP connection".into()))))
    }
    fn is_tls(&self) -> bool {
        false
    }
}

impl Stream for StdStream {
    fn set_timeout(&mut self, rt: Duration) {
        // A zero timeout is refused by the socket; the shortest one stands for it.
        let rt = Some(rt.max(Duration::from_millis(1)));
        self.socket.set_read_timeout(rt).ok();
        self.socket.set_write_timeout(rt).ok();
    }

    fn closed(&mut self) -> bool {
        if let Layer::Tls(s) = &mut self.io {
            match s.conn.process_new_packets() {
                Ok(state) if state.plaintext_bytes_to_read() == 0 && !state.peer_has_closed() => {}
                _ => return true,
            }
        }
        if self.socket.set_nonblocking(true).is_err() {
            return true;
        }
        let peeked = self.socket.peek(&mut [0u8; 1]);
        let restored = self.socket.set_nonblocking(false);
        restored.is_err() || !matches!(peeked, Err(e) if e.kind() == io::ErrorKind::WouldBlock)
    }
}

/// A socket timeout reads as `WouldBlock` on Unix: report it as the timeout it is.
fn timed_out(e: io::Error) -> io::Error {
    if e.kind() == io::ErrorKind::WouldBlock { io::ErrorKind::TimedOut.into() } else { e }
}

/// The first address of `host` that accepts a connection. Each address gets an equal share of what is left of `budget`, so an unreachable first address (a broken IPv6 route) leaves time for the others.
#[expect(clippy::disallowed_methods, reason = "the blocking transport")]
fn tcp_connect(host: &str, port: u16, budget: Duration) -> io::Result<TcpStream> {
    let start = Instant::now();
    let addrs: Vec<_> = (host, port).to_socket_addrs()?.collect();
    let mut last = None;
    for (i, addr) in addrs.iter().enumerate() {
        let left = budget.saturating_sub(start.elapsed());
        let share = left / u32::try_from(addrs.len() - i).unwrap_or(u32::MAX);
        match TcpStream::connect_timeout(addr, share.max(Duration::from_millis(1))) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("cannot resolve {host}"))))
}
