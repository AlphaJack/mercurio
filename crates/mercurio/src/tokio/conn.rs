//! TCP + rustls streams on tokio, upgraded to TLS in place for STARTTLS, and Unix stream sockets: the async twin of `net::NetConn`.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::error::{Error, Result};
use crate::transport::{AsyncConn, BoxFuture, Endpoint};

enum Inner {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    Swapping,
}

/// A connected stream; every read and write gives up after the endpoint's read timeout.
pub(super) struct TokioConn {
    inner: Inner,
    host: String,
    verify: bool,
    timeout: Duration,
}

fn timed_out(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("timed out ({what})"))
}

fn unavailable() -> io::Error {
    io::Error::other("connection unavailable")
}

/// The first address of `host` that accepts a connection within `limit`.
async fn tcp_connect(host: &str, port: u16, limit: Duration) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    let mut last = None;
    for addr in addrs {
        match timeout(limit, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = Some(e),
            Err(_) => last = Some(timed_out("connect")),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("cannot resolve {host}"))))
}

impl TokioConn {
    pub(super) async fn connect(ep: &Endpoint) -> Result<Self> {
        if let Some(path) = &ep.unix {
            return Self::connect_unix(ep, path);
        }
        let tcp = tcp_connect(&ep.host, ep.port, ep.connect_timeout)
            .await
            .map_err(|e| Error::transport(format!("{}:{}: {e}", ep.host, ep.port)))?;
        let mut c = TokioConn {
            inner: Inner::Plain(tcp),
            host: ep.host.clone(),
            verify: ep.verify_tls,
            timeout: ep.read_timeout,
        };
        if ep.tls {
            c.tls().await?;
        }
        Ok(c)
    }

    /// Connecting a local socket does not block, so the std connect (which also reaches Linux abstract sockets) is used.
    #[cfg(unix)]
    fn connect_unix(ep: &Endpoint, path: &str) -> Result<Self> {
        let failed = |e: io::Error| Error::transport(format!("{}: {e}", ep.address()));
        let sock = crate::net::unix_connect(path).map_err(failed)?;
        sock.set_nonblocking(true).map_err(failed)?;
        let sock = tokio::net::UnixStream::from_std(sock).map_err(failed)?;
        Ok(TokioConn { inner: Inner::Unix(sock), host: String::new(), verify: ep.verify_tls, timeout: ep.read_timeout })
    }

    #[cfg(not(unix))]
    fn connect_unix(_: &Endpoint, _: &str) -> Result<Self> {
        Err(Error::Unsupported("unix sockets".into()))
    }

    async fn tls(&mut self) -> Result<()> {
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
        let connector = TlsConnector::from(crate::net::tls_config(self.verify).map_err(Error::transport)?);
        let stream = timeout(self.timeout, connector.connect(crate::net::server_name(&self.host)?, tcp))
            .await
            .unwrap_or_else(|_| Err(timed_out("TLS handshake")))
            .map_err(|e| Error::transport(format!("TLS handshake: {e}")))?;
        self.inner = Inner::Tls(Box::new(stream));
        Ok(())
    }
}

impl AsyncConn for TokioConn {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            let read = async {
                match &mut self.inner {
                    Inner::Plain(t) => t.read(buf).await,
                    Inner::Tls(s) => s.read(buf).await,
                    #[cfg(unix)]
                    Inner::Unix(u) => u.read(buf).await,
                    Inner::Swapping => Err(unavailable()),
                }
            };
            timeout(self.timeout, read).await.unwrap_or_else(|_| Err(timed_out("receive")))
        })
    }

    fn write_all<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let write = async {
                match &mut self.inner {
                    Inner::Plain(t) => t.write_all(data).await,
                    Inner::Tls(s) => s.write_all(data).await,
                    #[cfg(unix)]
                    Inner::Unix(u) => u.write_all(data).await,
                    Inner::Swapping => Err(unavailable()),
                }
            };
            timeout(self.timeout, write).await.unwrap_or_else(|_| Err(timed_out("send")))
        })
    }

    fn flush(&mut self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move {
            match &mut self.inner {
                Inner::Plain(t) => t.flush().await,
                Inner::Tls(s) => s.flush().await,
                #[cfg(unix)]
                Inner::Unix(u) => u.flush().await,
                Inner::Swapping => Ok(()),
            }
        })
    }

    fn start_tls(&mut self) -> BoxFuture<'_, Result<()>> {
        Box::pin(self.tls())
    }

    fn is_tls(&self) -> bool {
        matches!(self.inner, Inner::Tls(_))
    }

    fn channel_binding(&self, kind: crate::transport::ChannelBinding) -> Option<Vec<u8>> {
        match &self.inner {
            Inner::Tls(s) => crate::net::channel_binding(s.get_ref().1, kind),
            #[cfg(unix)]
            Inner::Unix(_) => None,
            Inner::Plain(_) | Inner::Swapping => None,
        }
    }
}
