//! The I/O interface of the core: the blocking [`Transport`] and the [`AsyncTransport`], their connections, datagrams, programs and file operations, and the [`Blocking`] adapter.

use std::fmt;
use std::future::{Future, ready};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use crate::env::Env;
use crate::error::{Error, Result};
use crate::http::{DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT, Request, Response};

/// Executes the I/O a [`crate::Plan`] asks for.
///
/// Implement this to plug in another HTTP client, a proxy or a test double. Only [`Transport::http`] is required; [`Transport::file`] defaults to `std::fs`, so stores, templates and key files keep working. `connect`, `datagram` and `command` default to [`Error::Unsupported`]: a wrapper around `BlockingTransport` forwards them so socket protocols, syslog and desktop notifications keep working.
///
/// Return an error from `http` only when no response arrived: [`Error::transport`] when nothing was sent (DNS, refused, connect timeout; `?retry=` repeats it), [`Error::Unconfirmed`] when the request may have arrived (read timeout, reset after sending; not repeated).
pub trait Transport: Send + Sync {
    /// Execute one HTTP request. Non-2xx statuses are responses, not errors.
    fn http(&self, req: &Request) -> Result<Response>;

    /// Open a stream to `ep` (TLS from the start when `ep.tls`). Default: unsupported.
    fn connect(&self, ep: &Endpoint) -> Result<Box<dyn Conn>> {
        let _ = ep;
        Err(no_sockets())
    }

    /// Send one datagram. Default: unsupported.
    fn datagram(&self, dg: &Datagram) -> Result<()> {
        let _ = dg;
        Err(no_datagrams())
    }

    /// Run a local program and collect its output. Default: unsupported.
    fn command(&self, cmd: &Command) -> Result<CommandOutput> {
        let _ = cmd;
        Err(no_commands())
    }

    /// Run a file system operation (stores, templates, key files, `file://`). Default: `std::fs`.
    fn file(&self, op: &FileOp) -> Result<FileOutput> {
        std_file(op)
    }

    /// Block for `d` (throttling, retry waits). Default: `std::thread::sleep`.
    #[expect(clippy::disallowed_methods, reason = "the real transport really waits")]
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }

    /// The clock and random source services plan with. Default: [`crate::SystemEnv`].
    #[expect(clippy::disallowed_methods, reason = "the default Env")]
    fn env(&self) -> Arc<dyn Env> {
        crate::env::system().clone()
    }
}

impl<T: Transport + ?Sized> Transport for &T {
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
    fn file(&self, op: &FileOp) -> Result<FileOutput> {
        (**self).file(op)
    }
    fn sleep(&self, d: Duration) {
        (**self).sleep(d)
    }
    fn env(&self) -> Arc<dyn Env> {
        (**self).env()
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
    fn file(&self, op: &FileOp) -> Result<FileOutput> {
        (**self).file(op)
    }
    fn sleep(&self, d: Duration) {
        (**self).sleep(d)
    }
    fn env(&self) -> Arc<dyn Env> {
        (**self).env()
    }
}

fn no_sockets() -> Error {
    Error::Unsupported("raw sockets are not available with this transport".into())
}

fn no_datagrams() -> Error {
    Error::Unsupported("datagrams are not available with this transport".into())
}

fn no_commands() -> Error {
    Error::Unsupported("running local programs is not available with this transport".into())
}

/// A boxed, `Send` future: what [`AsyncTransport`] and [`AsyncConn`] methods return.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The asynchronous counterpart of [`Transport`]; the delivery core runs on it.
///
/// Object-safe: methods return boxed futures, so `Arc<dyn AsyncTransport>` works. Error rules are those of [`Transport`].
pub trait AsyncTransport: Send + Sync {
    /// Execute one HTTP request. Non-2xx statuses are responses, not errors.
    fn http<'a>(&'a self, req: &'a Request) -> BoxFuture<'a, Result<Response>>;

    /// Open a stream to `ep`. Default: unsupported.
    fn connect<'a>(&'a self, ep: &'a Endpoint) -> BoxFuture<'a, Result<Box<dyn AsyncConn>>> {
        let _ = ep;
        Box::pin(ready(Err(no_sockets())))
    }

    /// Send one datagram. Default: unsupported.
    fn datagram<'a>(&'a self, dg: &'a Datagram) -> BoxFuture<'a, Result<()>> {
        let _ = dg;
        Box::pin(ready(Err(no_datagrams())))
    }

    /// Run a local program and collect its output. Default: unsupported.
    fn command<'a>(&'a self, cmd: &'a Command) -> BoxFuture<'a, Result<CommandOutput>> {
        let _ = cmd;
        Box::pin(ready(Err(no_commands())))
    }

    /// Run a file system operation (stores, templates, key files, `file://`).
    fn file<'a>(&'a self, op: &'a FileOp) -> BoxFuture<'a, Result<FileOutput>>;

    /// Wait for `d` (throttling, retry waits).
    fn sleep(&self, d: Duration) -> BoxFuture<'_, ()>;

    /// The clock and random source services plan with. Default: [`crate::SystemEnv`].
    #[expect(clippy::disallowed_methods, reason = "the default Env")]
    fn env(&self) -> Arc<dyn Env> {
        crate::env::system().clone()
    }
}

/// A connected byte stream, read and written asynchronously. I/O errors stay [`io::Error`]s, so each protocol classifies them as before.
pub trait AsyncConn: Send {
    /// Read into `buf`; `Ok(0)` when the peer closed the stream.
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>>;
    /// Write all of `data`.
    fn write_all<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, io::Result<()>>;
    /// Flush buffered writes.
    fn flush(&mut self) -> BoxFuture<'_, io::Result<()>>;
    /// Upgrade a plain connection to TLS in place (STARTTLS).
    fn start_tls(&mut self) -> BoxFuture<'_, Result<()>>;
    /// Whether the stream is currently encrypted.
    fn is_tls(&self) -> bool;

    /// Fill `buf` completely, like [`std::io::Read::read_exact`] (same error when the stream ends first).
    fn read_exact<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            let mut filled = 0;
            while filled < buf.len() {
                match self.read(&mut buf[filled..]).await {
                    Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer")),
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        })
    }
}

/// A [`Transport`] (borrowed or in an `Arc`) behind [`AsyncTransport`]: every future is already complete when returned (the I/O happens inside the call), so `pollster::block_on` never parks. On an async runtime it blocks the worker thread while the I/O runs.
#[derive(Debug, Clone)]
pub struct Blocking<T>(pub T);

impl<T: Transport> AsyncTransport for Blocking<T> {
    fn http<'a>(&'a self, req: &'a Request) -> BoxFuture<'a, Result<Response>> {
        Box::pin(ready(self.0.http(req)))
    }
    fn connect<'a>(&'a self, ep: &'a Endpoint) -> BoxFuture<'a, Result<Box<dyn AsyncConn>>> {
        Box::pin(ready(self.0.connect(ep).map(|c| Box::new(c) as Box<dyn AsyncConn>)))
    }
    fn datagram<'a>(&'a self, dg: &'a Datagram) -> BoxFuture<'a, Result<()>> {
        Box::pin(ready(self.0.datagram(dg)))
    }
    fn command<'a>(&'a self, cmd: &'a Command) -> BoxFuture<'a, Result<CommandOutput>> {
        Box::pin(ready(self.0.command(cmd)))
    }
    fn file<'a>(&'a self, op: &'a FileOp) -> BoxFuture<'a, Result<FileOutput>> {
        Box::pin(ready(self.0.file(op)))
    }
    fn sleep(&self, d: Duration) -> BoxFuture<'_, ()> {
        self.0.sleep(d);
        Box::pin(ready(()))
    }
    fn env(&self) -> Arc<dyn Env> {
        self.0.env()
    }
}

/// A blocking connection behind [`AsyncConn`]: every future is complete when returned.
impl AsyncConn for Box<dyn Conn> {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(ready(Read::read(self, buf)))
    }
    fn write_all<'a>(&'a mut self, data: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(ready(Write::write_all(self, data)))
    }
    fn flush(&mut self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(ready(Write::flush(self)))
    }
    fn start_tls(&mut self) -> BoxFuture<'_, Result<()>> {
        Box::pin(ready(Conn::start_tls(self.as_mut())))
    }
    fn is_tls(&self) -> bool {
        Conn::is_tls(self.as_ref())
    }
    fn read_exact<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(ready(Read::read_exact(self, buf)))
    }
}

/// Where to open a stream.
#[derive(Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Host name or IP address.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// TLS from the first byte (e.g. SMTPS on 465).
    pub tls: bool,
    /// Check the server certificate (`?verify=`).
    pub verify_tls: bool,
    /// Limit for connecting (`?cto=`).
    pub connect_timeout: Duration,
    /// Limit for each read and write (`?rto=`).
    pub read_timeout: Duration,
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Endpoint({}:{}, tls={})", self.host, self.port, self.tls)
    }
}

impl Endpoint {
    /// `host:port`, certificate checked, default timeouts.
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
    /// A UDP host and port.
    Udp {
        /// Host name or IP address.
        host: String,
        /// UDP port.
        port: u16,
    },
    /// Unix datagram socket path (e.g. `/dev/log`).
    Unix(String),
}

/// One datagram (syslog, UDP services).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    /// Where it goes.
    pub target: DatagramTarget,
    /// What is sent.
    pub payload: Vec<u8>,
}

/// A local program to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// The program, found on `PATH` unless it is a path.
    pub program: String,
    /// Its arguments.
    pub args: Vec<String>,
    /// Bytes written to its standard input, which is then closed; `None`: no input.
    pub stdin: Option<Vec<u8>>,
    /// Limit for the whole run.
    pub timeout: Duration,
    /// Files the program reads, written by the transport before it runs (bundled assets such as the icon; skipped when already up to date).
    pub files: Vec<(String, &'static [u8])>,
}

/// [`Command::timeout`] unless a service sets its own.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

impl Command {
    /// `program` without arguments or input.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            stdin: None,
            timeout: DEFAULT_COMMAND_TIMEOUT,
            files: Vec::new(),
        }
    }
    /// Add one argument.
    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }
    /// Add arguments.
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

/// What a [`Command`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Exit code; `-1` when a signal ended it.
    pub status: i32,
    /// Everything it wrote to standard output.
    pub stdout: Vec<u8>,
    /// Everything it wrote to standard error.
    pub stderr: Vec<u8>,
}

/// A file system operation. Services return them as [`crate::Plan::file`] steps instead of touching the file system.
#[derive(Clone, PartialEq, Eq)]
#[expect(missing_docs, reason = "the variant docs describe their fields")]
pub enum FileOp {
    /// Metadata: [`FileOutput::Meta`], `None` when `path` does not exist.
    Stat { path: PathBuf },
    /// The bytes of a regular file of at most `max` bytes (`0`: no limit): [`FileOutput::Bytes`].
    Read { path: PathBuf, max: u64 },
    /// Append `data` in one write, creating the file when missing (its directory must exist).
    Append { path: PathBuf, data: Vec<u8> },
    /// Replace `path` with `data` atomically: staged in a [`crate::store::STAGING_DIR`] directory next to it (created when missing), then renamed. `private`: `0600` files, `0700` directories.
    WriteAtomic { path: PathBuf, data: Vec<u8>, private: bool },
    /// Create `path` and its parents; `private`: `0700`.
    CreateDir { path: PathBuf, private: bool },
    /// Delete a file; a missing one is not an error.
    Remove { path: PathBuf },
    /// Set the modification time to now.
    Touch { path: PathBuf },
}

impl FileOp {
    /// Stat `path`, then read it: the steps behind [`crate::Context::local_file`].
    pub fn local_file(path: impl Into<PathBuf>) -> [FileOp; 2] {
        let path = path.into();
        [FileOp::Stat { path: path.clone() }, FileOp::Read { path, max: 0 }]
    }

    /// The path the operation acts on.
    pub fn path(&self) -> &Path {
        match self {
            FileOp::Stat { path }
            | FileOp::Read { path, .. }
            | FileOp::Append { path, .. }
            | FileOp::WriteAtomic { path, .. }
            | FileOp::CreateDir { path, .. }
            | FileOp::Remove { path }
            | FileOp::Touch { path } => path,
        }
    }
}

impl fmt::Debug for FileOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            FileOp::Stat { .. } => "Stat",
            FileOp::Read { .. } => "Read",
            FileOp::Append { .. } => "Append",
            FileOp::WriteAtomic { .. } => "WriteAtomic",
            FileOp::CreateDir { .. } => "CreateDir",
            FileOp::Remove { .. } => "Remove",
            FileOp::Touch { .. } => "Touch",
        };
        write!(f, "{name}({})", self.path().display())
    }
}

/// What [`FileOp::Stat`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMeta {
    /// A regular file (not a directory).
    pub is_file: bool,
    /// Size in bytes.
    pub len: u64,
    /// A file with an execute bit (any file on non-Unix systems).
    pub executable: bool,
}

/// The result of a [`FileOp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileOutput {
    /// A write, append, removal or directory creation succeeded.
    Done,
    /// What [`FileOp::Stat`] found.
    Meta(Option<FileMeta>),
    /// What [`FileOp::Read`] read.
    Bytes(Vec<u8>),
}

/// [`Transport::file`] on `std::fs`.
#[expect(clippy::disallowed_methods, reason = "the default file system access")]
pub(crate) fn std_file(op: &FileOp) -> Result<FileOutput> {
    use std::fs;
    let path = op.path();
    let err = |e: io::Error| Error::transport(format!("{}: {e}", path.display()));
    match op {
        FileOp::Stat { .. } => match fs::metadata(path) {
            Ok(m) => Ok(FileOutput::Meta(Some(file_meta(&m)))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(FileOutput::Meta(None)),
            Err(e) => Err(err(e)),
        },
        FileOp::Read { max, .. } => {
            let m = fs::metadata(path).map_err(err)?;
            if !m.is_file() || (*max > 0 && m.len() > *max) {
                return Err(Error::Message(format!("{}: not a file of at most {max} bytes", path.display())));
            }
            fs::read(path).map(FileOutput::Bytes).map_err(err)
        }
        FileOp::Append { data, .. } => {
            fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .and_then(|mut f| f.write_all(data))
                .map_err(err)?;
            Ok(FileOutput::Done)
        }
        FileOp::WriteAtomic { data, private, .. } => {
            let (dir, tmp) = staging(path);
            create_dir(&dir, *private).and_then(|()| write_atomic(&tmp, path, data, *private)).map_err(err)?;
            Ok(FileOutput::Done)
        }
        FileOp::CreateDir { private, .. } => {
            create_dir(path, *private).map_err(err)?;
            Ok(FileOutput::Done)
        }
        FileOp::Remove { .. } => match fs::remove_file(path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(err(e)),
            _ => Ok(FileOutput::Done),
        },
        FileOp::Touch { .. } => {
            fs::File::options()
                .write(true)
                .open(path)
                .and_then(|f| f.set_modified(std::time::SystemTime::now()))
                .map_err(err)?;
            Ok(FileOutput::Done)
        }
    }
}

pub(crate) fn file_meta(m: &std::fs::Metadata) -> FileMeta {
    FileMeta { is_file: m.is_file(), len: m.len(), executable: executable(m) }
}

/// The local address to send a datagram to `addr` from.
pub(crate) fn unbound_addr(addr: &std::net::SocketAddr) -> &'static str {
    if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }
}

#[cfg(unix)]
fn executable(m: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    m.is_file() && m.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable(m: &std::fs::Metadata) -> bool {
    m.is_file()
}

#[expect(clippy::disallowed_methods, reason = "the default file system access")]
fn create_dir(dir: &Path, private: bool) -> io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(PRIVATE_DIR_MODE);
    }
    #[cfg(not(unix))]
    let _ = private;
    b.create(dir)
}

/// Mode of a private file.
#[cfg(unix)]
pub(crate) const PRIVATE_FILE_MODE: u32 = 0o600;
/// Mode of a private directory.
#[cfg(unix)]
pub(crate) const PRIVATE_DIR_MODE: u32 = 0o700;

/// The staging directory of `path` and a fresh file name in it.
#[expect(clippy::disallowed_methods, reason = "transports name their temporary files")]
pub(crate) fn staging(path: &Path) -> (PathBuf, PathBuf) {
    let dir = path.parent().unwrap_or(Path::new(".")).join(crate::store::STAGING_DIR);
    let file = dir.join(format!(".{}-{}.tmp", std::process::id(), crate::env::system().random_hex(6)));
    (dir, file)
}

/// Write `data` to `tmp`, sync it and rename it over `dest` (atomic on POSIX filesystems).
#[expect(clippy::disallowed_methods, reason = "the default file system access")]
fn write_atomic(tmp: &Path, dest: &Path, data: &[u8], private: bool) -> io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(PRIVATE_FILE_MODE);
    }
    #[cfg(not(unix))]
    let _ = private;
    let res = opts.open(tmp).and_then(|mut f| {
        f.write_all(data)?;
        f.sync_all()
    });
    let res = res.and_then(|()| std::fs::rename(tmp, dest));
    if res.is_err() {
        std::fs::remove_file(tmp).ok();
    }
    res
}

#[cfg(test)]
#[expect(clippy::disallowed_methods, reason = "tests check the real file system")]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_is_private_and_stages_in_tmp() {
        let dir = std::env::temp_dir().join(format!("mercurio-transport-{}", crate::env::system().random_hex(6)));
        let path = dir.join("ns").join("key.pem");
        let op = FileOp::WriteAtomic { path: path.clone(), data: b"k".to_vec(), private: true };
        assert_eq!(std_file(&op).unwrap(), FileOutput::Done);
        assert_eq!(std::fs::read(&path).unwrap(), b"k");
        assert_eq!(std::fs::read_dir(dir.join("ns").join(crate::store::STAGING_DIR)).unwrap().count(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!((mode(&path), mode(&dir.join("ns"))), (PRIVATE_FILE_MODE, PRIVATE_DIR_MODE));
        }
        let meta = std_file(&FileOp::Stat { path: path.clone() }).unwrap();
        assert_eq!(meta, FileOutput::Meta(Some(FileMeta { is_file: true, len: 1, executable: false })));
        assert_eq!(std_file(&FileOp::Read { path: path.clone(), max: 1 }).unwrap(), FileOutput::Bytes(b"k".to_vec()));
        assert!(std_file(&FileOp::Read { path: dir.join("ns"), max: 0 }).is_err(), "not a file");
        assert!(std_file(&FileOp::Remove { path: path.clone() }).is_ok());
        assert_eq!(std_file(&FileOp::Stat { path: path.clone() }).unwrap(), FileOutput::Meta(None));
        assert!(std_file(&FileOp::Remove { path }).is_ok(), "a missing file is removed");
        std::fs::remove_dir_all(dir).ok();
    }
}
