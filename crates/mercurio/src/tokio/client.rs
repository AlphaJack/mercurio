//! The tokio side of the HTTP client ([`crate::http1::client`]): [`TokioDial`] opens TCP and TLS connections, [`TokioStream`] reads and writes them with a timeout.

use std::io;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use futures_util::FutureExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::error::{Error, Result};
use crate::http::DEFAULT_READ_TIMEOUT;
use crate::http1::client::{Dial, Stream};
use crate::http1::wire::bad_request;
use crate::transport::{AsyncConn, BoxFuture};

/// The HTTP client of [`super::TokioTransport`].
pub(super) type Client = crate::http1::client::Client<TokioDial>;

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// Opens connections on tokio.
#[derive(Default)]
pub(crate) struct TokioDial {
    /// TLS connectors, with and without certificate verification; they keep the session cache.
    tls: Mutex<[Option<TlsConnector>; 2]>,
}

impl TokioDial {
    fn connector(&self, verify: bool) -> Result<TlsConnector> {
        let mut cache = self.tls.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = &mut cache[usize::from(verify)];
        if let Some(c) = slot {
            return Ok(c.clone());
        }
        let mut config = (*crate::net::tls_config(verify).map_err(|e| bad_request(&e.to_string()))?).clone();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(config));
        *slot = Some(connector.clone());
        Ok(connector)
    }
}

impl Dial for TokioDial {
    type Stream = TokioStream;

    fn tcp<'a>(&'a self, host: &'a str, port: u16, limit: Duration) -> BoxFuture<'a, io::Result<TokioStream>> {
        Box::pin(async move {
            let tcp = tcp_connect(host, port, limit).await?;
            tcp.set_nodelay(true).ok();
            Ok(TokioStream { io: Box::new(tcp), rt: DEFAULT_READ_TIMEOUT })
        })
    }

    fn tls<'a>(&'a self, io: TokioStream, host: &'a str, verify: bool) -> BoxFuture<'a, Result<TokioStream>> {
        Box::pin(async move {
            let name = crate::net::server_name(host)?;
            let tls = self
                .connector(verify)?
                .connect(name, io.io)
                .await
                .map_err(|e| Error::transport(format!("TLS handshake: {e}")))?;
            Ok(TokioStream { io: Box::new(tls), rt: io.rt })
        })
    }

    fn within<'a, T: Send + 'a>(&'a self, limit: Duration, open: BoxFuture<'a, Result<T>>) -> BoxFuture<'a, Result<T>> {
        Box::pin(async move {
            timeout(limit, open).await.unwrap_or_else(|_| Err(Error::Transport("timed out (connect)".into())))
        })
    }
}

/// A plain or TLS stream whose reads and writes give up after `rt`.
pub(crate) struct TokioStream {
    io: Box<dyn Io>,
    rt: Duration,
}

impl AsyncConn for TokioStream {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            timeout(self.rt, self.io.read(buf)).await.unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
        })
    }
    fn write_all<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            timeout(self.rt, self.io.write_all(data)).await.unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
        })
    }
    fn flush(&mut self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move {
            timeout(self.rt, self.io.flush()).await.unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
        })
    }
    fn start_tls(&mut self) -> BoxFuture<'_, Result<()>> {
        Box::pin(std::future::ready(Err(Error::Unsupported("STARTTLS on an HTTP connection".into()))))
    }
    fn is_tls(&self) -> bool {
        false
    }
}

impl Stream for TokioStream {
    fn set_timeout(&mut self, rt: Duration) {
        self.rt = rt;
    }

    fn closed(&mut self) -> bool {
        let mut probe = [0u8; 1];
        self.io.read(&mut probe).now_or_never().is_some()
    }
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
