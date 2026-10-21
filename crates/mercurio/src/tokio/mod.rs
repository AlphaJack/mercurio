//! [`TokioTransport`]: the I/O of [`crate::AsyncMercurio`] on tokio and rustls (feature `transport-tokio`).
//!
//! The only module that names tokio or tokio-rustls; HTTP is the in-house client of `client`. It gives the same results as `BlockingTransport` (feature `transport-blocking`): rustls with ring, the Mozilla roots or `SSL_CERT_FILE`, HTTP/1.1, at most 10 redirects (the last 3xx is returned), 16 MiB bodies, `HTTP(S)_PROXY` / `NO_PROXY` from the environment and the same error classes.

mod client;
mod conn;
mod uri;

use std::fmt;
use std::io;
use std::path::Path;
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use crate::error::{Error, Result};
use crate::http::{Request, Response};
use crate::transport::{
    AsyncConn, AsyncTransport, BoxFuture, Command, CommandOutput, Datagram, DatagramTarget, Endpoint, FileOp,
    FileOutput, file_meta, staging, unbound_addr,
};

/// Network, process and file I/O on tokio; HTTP through the in-house client. Needs a tokio runtime with I/O and time enabled.
pub struct TokioTransport {
    user_agent: String,
    client: client::Client,
}

impl fmt::Debug for TokioTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokioTransport").field("user_agent", &self.user_agent).finish_non_exhaustive()
    }
}

impl Default for TokioTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl TokioTransport {
    /// A transport whose `User-Agent` is `Mercurio/<version>`; requests that set their own keep it.
    pub fn new() -> Self {
        Self::with_user_agent(format!("Mercurio/{}", env!("CARGO_PKG_VERSION")))
    }

    /// A transport with a custom default `User-Agent`.
    pub fn with_user_agent(ua: impl Into<String>) -> Self {
        let user_agent = ua.into();
        Self { client: client::Client::new(user_agent.clone()), user_agent }
    }

    async fn send(&self, req: &Request) -> Result<Response> {
        self.client.send(req).await
    }

    async fn datagram(dg: &Datagram) -> Result<()> {
        match &dg.target {
            DatagramTarget::Udp { host, port } => {
                let addr = tokio::net::lookup_host((host.as_str(), *port))
                    .await
                    .map_err(Error::transport)?
                    .next()
                    .ok_or_else(|| Error::transport(format!("cannot resolve {host}")))?;
                let sock = tokio::net::UdpSocket::bind(unbound_addr(&addr)).await.map_err(Error::transport)?;
                sock.send_to(&dg.payload, addr).await.map_err(Error::transport)?;
            }
            #[cfg(unix)]
            DatagramTarget::Unix(path) => {
                let sock = tokio::net::UnixDatagram::unbound().map_err(Error::transport)?;
                sock.send_to(&dg.payload, path).await.map_err(Error::transport)?;
            }
            #[cfg(not(unix))]
            DatagramTarget::Unix(_) => return Err(Error::Unsupported("unix sockets".into())),
        }
        Ok(())
    }

    async fn command(cmd: &Command) -> Result<CommandOutput> {
        use std::process::Stdio;
        for (path, bytes) in &cmd.files {
            let path = Path::new(path);
            if tokio::fs::read(path).await.ok().as_deref() != Some(*bytes) {
                if let Some(dir) = path.parent() {
                    tokio::fs::create_dir_all(dir)
                        .await
                        .map_err(|e| Error::transport(format!("{}: {e}", dir.display())))?;
                }
                tokio::fs::write(path, bytes)
                    .await
                    .map_err(|e| Error::transport(format!("{}: {e}", path.display())))?;
            }
        }
        let mut child = tokio::process::Command::new(&cmd.program)
            .args(&cmd.args)
            .stdin(if cmd.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| Error::transport(format!("{}: {e}", cmd.program)))?;
        if let Some(input) = &cmd.stdin
            && let Some(mut stdin) = child.stdin.take()
        {
            stdin.write_all(input).await.map_err(Error::transport)?;
        }
        let out = tokio::time::timeout(cmd.timeout, child.wait_with_output())
            .await
            .map_err(|_| Error::transport(format!("{}: timed out", cmd.program)))?
            .map_err(Error::transport)?;
        Ok(CommandOutput { status: out.status.code().unwrap_or(-1), stdout: out.stdout, stderr: out.stderr })
    }

    async fn file(op: &FileOp) -> Result<FileOutput> {
        use tokio::fs;
        let path = op.path();
        let err = |e: io::Error| Error::transport(format!("{}: {e}", path.display()));
        match op {
            FileOp::Stat { .. } => match fs::metadata(path).await {
                Ok(m) => Ok(FileOutput::Meta(Some(file_meta(&m)))),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(FileOutput::Meta(None)),
                Err(e) => Err(err(e)),
            },
            FileOp::Read { max, .. } => {
                let m = fs::metadata(path).await.map_err(err)?;
                if !m.is_file() || (*max > 0 && m.len() > *max) {
                    return Err(Error::Message(format!("{}: not a file of at most {max} bytes", path.display())));
                }
                fs::read(path).await.map(FileOutput::Bytes).map_err(err)
            }
            FileOp::Append { data, .. } => {
                let mut f = fs::OpenOptions::new().append(true).create(true).open(path).await.map_err(err)?;
                f.write_all(data).await.map_err(err)?;
                Ok(FileOutput::Done)
            }
            FileOp::WriteAtomic { data, private, .. } => {
                write_atomic(path, data, *private).await.map_err(err)?;
                Ok(FileOutput::Done)
            }
            FileOp::CreateDir { private, .. } => {
                create_dir(path, *private).await.map_err(err)?;
                Ok(FileOutput::Done)
            }
            FileOp::Remove { .. } => match fs::remove_file(path).await {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(err(e)),
                _ => Ok(FileOutput::Done),
            },
            FileOp::Touch { .. } => {
                let f = fs::File::options().write(true).open(path).await.map_err(err)?;
                #[expect(clippy::disallowed_methods, reason = "the transport touches files on the real clock")]
                let now = std::time::SystemTime::now();
                f.into_std().await.set_modified(now).map_err(err)?;
                Ok(FileOutput::Done)
            }
        }
    }
}

async fn create_dir(dir: &Path, private: bool) -> io::Result<()> {
    let mut b = tokio::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    if private {
        b.mode(crate::transport::PRIVATE_DIR_MODE);
    }
    #[cfg(not(unix))]
    let _ = private;
    b.create(dir).await
}

/// As [`FileOp::WriteAtomic`]: a fresh staging file, synced, then renamed over `path`.
async fn write_atomic(path: &Path, data: &[u8], private: bool) -> io::Result<()> {
    let (tmp_dir, tmp) = staging(path);
    create_dir(&tmp_dir, private).await?;
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        opts.mode(crate::transport::PRIVATE_FILE_MODE);
    }
    let written = async {
        let mut f = opts.open(&tmp).await?;
        f.write_all(data).await?;
        f.sync_all().await?;
        tokio::fs::rename(&tmp, path).await
    }
    .await;
    if written.is_err() {
        tokio::fs::remove_file(&tmp).await.ok();
    }
    written
}

impl AsyncTransport for TokioTransport {
    fn http<'a>(&'a self, req: &'a Request) -> BoxFuture<'a, Result<Response>> {
        Box::pin(self.send(req))
    }
    fn connect<'a>(&'a self, ep: &'a Endpoint) -> BoxFuture<'a, Result<Box<dyn AsyncConn>>> {
        Box::pin(async move { Ok(Box::new(conn::TokioConn::connect(ep).await?) as Box<dyn AsyncConn>) })
    }
    fn datagram<'a>(&'a self, dg: &'a Datagram) -> BoxFuture<'a, Result<()>> {
        Box::pin(Self::datagram(dg))
    }
    fn command<'a>(&'a self, cmd: &'a Command) -> BoxFuture<'a, Result<CommandOutput>> {
        Box::pin(Self::command(cmd))
    }
    fn file<'a>(&'a self, op: &'a FileOp) -> BoxFuture<'a, Result<FileOutput>> {
        Box::pin(Self::file(op))
    }
    fn sleep(&self, d: Duration) -> BoxFuture<'_, ()> {
        Box::pin(tokio::time::sleep(d))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// Answer each connection with the next of `answers` after reading the request head; `None` never answers.
    async fn serve(answers: Vec<Option<Vec<u8>>>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            for answer in answers {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut head = Vec::new();
                let mut b = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut b).await.unwrap();
                    head.extend_from_slice(&b[..n]);
                }
                match answer {
                    Some(a) => s.write_all(&a).await.unwrap(),
                    None => std::future::pending::<()>().await,
                }
            }
        });
        port
    }

    fn get(port: u16, path: &str) -> Request {
        Request::get(format!("http://127.0.0.1:{port}{path}"))
    }

    #[tokio::test]
    async fn status_headers_and_redirects() {
        let ok =
            b"HTTP/1.1 201 Created\r\nX-A: 1\r\nX-A: 2\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi".to_vec();
        let moved = |port: u16| {
            format!("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .into_bytes()
        };
        let t = TokioTransport::new();
        let port = serve(vec![Some(ok.clone())]).await;
        let res = t.http(&get(port, "/")).await.unwrap();
        assert_eq!((res.status, res.body.as_slice()), (201, &b"hi"[..]));
        let xa: Vec<_> = res.headers.iter().filter(|(k, _)| k == "x-a").map(|(_, v)| v.as_str()).collect();
        assert_eq!(xa, ["1", "2"]);

        let target = serve(vec![Some(ok)]).await;
        let port = serve(vec![Some(moved(target))]).await;
        assert_eq!(t.http(&get(port, "/a")).await.unwrap().status, 201, "redirects are followed");
        let port = serve(vec![Some(moved(target))]).await;
        let res = t.http(&get(port, "/a").redirects(false)).await.unwrap();
        assert_eq!(res.status, 302, "with redirects off the 3xx is returned");
    }

    #[tokio::test]
    async fn errors_keep_their_classes() {
        let t = TokioTransport::new();
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
        let refused = t.http(&get(closed, "/")).await.unwrap_err();
        assert!(matches!(refused, Error::Transport(_)), "{refused:?}");

        let port = serve(vec![None]).await;
        let slow = get(port, "/").timeouts(Duration::from_secs(2), Duration::from_millis(200));
        let err = t.http(&slow).await.unwrap_err();
        assert_eq!(err, Error::Unconfirmed("timed out (receive response)".into()));

        // The default limit, then a request's own, smaller one, both while reading.
        let max = crate::MAX_BODY;
        let big = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", max + 1).into_bytes();
        let mut answer = big;
        answer.resize(answer.len() + max as usize + 1, b'x');
        let port = serve(vec![Some(answer.clone())]).await;
        assert_eq!(t.http(&get(port, "/")).await.unwrap_err(), crate::body_too_large(max));
        let port = serve(vec![Some(answer)]).await;
        assert_eq!(t.http(&get(port, "/").max_body(1024)).await.unwrap_err(), crate::body_too_large(1024));
    }

    #[tokio::test]
    async fn sockets_files_and_commands() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            s.write_all(b"220 hi\r\n").await.unwrap();
        });
        let t = TokioTransport::new();
        let mut conn = t.connect(&Endpoint::new("127.0.0.1", port, false)).await.unwrap();
        let mut buf = [0u8; 8];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"220 hi\r\n");

        #[expect(clippy::disallowed_methods, reason = "temporary directories need names unique across runs")]
        let unique = crate::env::system().random_hex(6);
        let dir = std::env::temp_dir().join(format!("mercurio-tokio-{unique}"));
        let path = dir.join("f");
        let write = FileOp::WriteAtomic { path: path.clone(), data: b"abc".to_vec(), private: true };
        assert_eq!(t.file(&write).await.unwrap(), FileOutput::Done);
        assert_eq!(
            t.file(&FileOp::Read { path: path.clone(), max: 0 }).await.unwrap(),
            FileOutput::Bytes(b"abc".to_vec())
        );
        assert!(t.file(&FileOp::Touch { path: path.clone() }).await.is_ok());
        assert!(t.file(&FileOp::Remove { path: path.clone() }).await.is_ok());
        assert_eq!(t.file(&FileOp::Stat { path }).await.unwrap(), FileOutput::Meta(None));
        tokio::fs::remove_dir_all(dir).await.ok();

        #[cfg(unix)]
        {
            let mut cmd = Command::new("cat");
            cmd.stdin = Some(b"in".to_vec());
            assert_eq!(t.command(&cmd).await.unwrap().stdout, b"in");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    #[expect(clippy::disallowed_methods, reason = "the test serves a real socket from a temporary directory")]
    async fn unix_sockets() {
        let dir = std::env::temp_dir().join(format!("mercurio-tokio-unix-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("echo.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut s, _) = listener.accept().unwrap();
            let mut b = [0u8; 4];
            s.read_exact(&mut b).unwrap();
            s.write_all(&b).unwrap();
        });
        let t = TokioTransport::new();
        let mut conn = t.connect(&Endpoint::unix(path.to_string_lossy())).await.unwrap();
        conn.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 4];
        conn.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"ping");
        assert!(!conn.is_tls() && conn.start_tls().await.is_err());
        let missing = dir.join("missing.sock").to_string_lossy().into_owned();
        let err = t.connect(&Endpoint::unix(missing.clone())).await.err().unwrap();
        assert!(matches!(&err, Error::Transport(m) if m.starts_with(&missing)), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
