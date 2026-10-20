//! Test doubles: run any plan with zero network access.
//!
//! ```
//! use mercurio::testing::FakeTransport;
//! use mercurio::{Message, Mercurio};
//! use std::sync::Arc;
//!
//! let fake = Arc::new(FakeTransport::new());
//! fake.respond(200, "{}");
//! let mut m = Mercurio::with_transport(fake.clone());
//! m.add("json://localhost/hook").unwrap();
//! assert!(m.notify(&Message::new("hi")).is_success());
//! assert_eq!(fake.requests()[0].url, "http://localhost/hook");
//! ```

#[cfg(any(test, feature = "testing"))]
pub mod fixtures;

use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::env::Env;
use crate::error::{Error, Result};
use crate::http::{Request, Response};
use crate::transport::{
    Command, CommandOutput, Conn, Datagram, Endpoint, FileMeta, FileOp, FileOutput, Transport, std_file,
};

/// Call `f` with a context holding the results of `ops` run on `transport`, as [`crate::Notify::files`] would see them.
#[cfg(test)]
pub(crate) fn file_context<R>(
    ops: Vec<FileOp>,
    transport: &dyn Transport,
    f: impl FnOnce(&crate::Context<'_>) -> R,
) -> R {
    let (asset, store, memo) =
        (crate::Asset::default(), crate::PersistentStore::memory().shared(), crate::Memo::disabled());
    let files = pollster::block_on(crate::plan::read_files(ops, &crate::Blocking(transport)));
    f(&crate::Context::new(&asset, &store, &memo).with_files(&files))
}

/// Run a plan of file steps on a blocking transport.
#[cfg(test)]
pub(crate) fn run_files(plan: crate::Plan, transport: &dyn Transport) {
    pollster::block_on(crate::plan::run_files(plan, &crate::Blocking(transport)));
}

type Rule = (Box<dyn Fn(&Request) -> bool + Send + Sync>, Result<Response>);

/// Records every request and answers from a script.
///
/// Matching order: the first rule whose predicate accepts the request (rules are reusable), then the next queued response, then the default (`200` with body `{}`).
///
/// File operations never change the disk (unless [`FakeTransport::on_disk`]): writes, appends and removals land in an in-memory file system ([`FakeTransport::files`]); reads see it first and fall back to the disk.
///
/// ```
/// use std::sync::Arc;
/// use mercurio::testing::FakeTransport;
/// use mercurio::{Error, ErrorClass, Mercurio, Message, Response};
///
/// let fake = Arc::new(FakeTransport::new());
/// fake.on_url("/flaky", Response::new(503, "busy").with_header("Retry-After", "1"));
/// fake.fail(Error::transport("connection refused"));
///
/// let mut m = Mercurio::with_transport(fake.clone());
/// m.add("json://localhost/down")?; // gets the queued transport failure
/// m.add("json://localhost/flaky")?; // matches the rule
/// let report = m.sequential().notify(&Message::new("hi"));
///
/// let classes: Vec<ErrorClass> = report.failures().map(|(_, o)| o.result.as_ref().unwrap_err().class()).collect();
/// assert_eq!(classes[0], ErrorClass::Transient);
/// assert!(matches!(classes[1], ErrorClass::RateLimited { .. }));
/// # Ok::<(), mercurio::Error>(())
/// ```
pub struct FakeTransport {
    state: Mutex<State>,
}

struct State {
    queue: VecDeque<Result<Response>>,
    rules: Vec<Rule>,
    default: Response,
    requests: Vec<Request>,
    endpoints: Vec<Endpoint>,
    conns: VecDeque<ScriptedConn>,
    datagrams: Vec<Datagram>,
    commands: Vec<Command>,
    command_outputs: VecDeque<Result<CommandOutput>>,
    sleeps: Vec<Duration>,
    /// `None`: removed.
    files: BTreeMap<PathBuf, Option<Vec<u8>>>,
    disk: bool,
    file_ops: Vec<FileOp>,
    env: Arc<dyn Env>,
}

impl Default for FakeTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeTransport {
    /// A fake with no scripted responses: every request gets `200` with body `{}`.
    #[expect(clippy::disallowed_methods, reason = "the default Env")]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                queue: VecDeque::new(),
                rules: Vec::new(),
                default: Response::new(200, "{}").with_header("Content-Type", "application/json"),
                requests: Vec::new(),
                endpoints: Vec::new(),
                conns: VecDeque::new(),
                datagrams: Vec::new(),
                commands: Vec::new(),
                command_outputs: VecDeque::new(),
                sleeps: Vec::new(),
                files: BTreeMap::new(),
                file_ops: Vec::new(),
                disk: false,
                env: crate::env::system().clone(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Plan with `env` instead of the system clock and random generator, e.g. a [`FixedEnv`] for byte-exact requests (signatures, nonces, boundaries, `Date:` headers).
    #[must_use]
    pub fn with_env(self, env: impl Env + 'static) -> Self {
        self.lock().env = Arc::new(env);
        self
    }

    /// Queue a response.
    pub fn respond(&self, status: u16, body: impl Into<Vec<u8>>) -> &Self {
        self.lock().queue.push_back(Ok(Response::new(status, body)));
        self
    }

    /// Queue a JSON response.
    pub fn respond_json(&self, status: u16, body: serde_json::Value) -> &Self {
        let r =
            Response::new(status, serde_json::to_vec(&body).unwrap()).with_header("Content-Type", "application/json");
        self.lock().queue.push_back(Ok(r));
        self
    }

    /// Queue a full response.
    pub fn respond_with(&self, response: Response) -> &Self {
        self.lock().queue.push_back(Ok(response));
        self
    }

    /// Queue a transport failure.
    pub fn fail(&self, error: Error) -> &Self {
        self.lock().queue.push_back(Err(error));
        self
    }

    /// Answer every request whose URL contains `needle` with `response`.
    pub fn on_url(&self, needle: impl Into<String>, response: Response) -> &Self {
        let needle = needle.into();
        self.lock().rules.push((Box::new(move |r: &Request| r.url.contains(&needle)), Ok(response)));
        self
    }

    /// Replace the fallback response.
    pub fn default_response(&self, response: Response) -> &Self {
        self.lock().default = response;
        self
    }

    /// Every HTTP request received, in order.
    pub fn requests(&self) -> Vec<Request> {
        self.lock().requests.clone()
    }

    /// The most recent HTTP request.
    pub fn last_request(&self) -> Option<Request> {
        self.lock().requests.last().cloned()
    }

    /// Queue a connection to hand out on the next `connect`.
    pub fn push_conn(&self, conn: ScriptedConn) -> &Self {
        self.lock().conns.push_back(conn);
        self
    }

    /// Every endpoint a stream was opened to, in order.
    pub fn endpoints(&self) -> Vec<Endpoint> {
        self.lock().endpoints.clone()
    }

    /// Every datagram sent, in order.
    pub fn datagrams(&self) -> Vec<Datagram> {
        self.lock().datagrams.clone()
    }

    /// Every local program run, in order.
    pub fn commands(&self) -> Vec<Command> {
        self.lock().commands.clone()
    }

    /// Queue the result of the next local program run (default: exit 0, no output).
    pub fn push_command_output(&self, out: Result<CommandOutput>) -> &Self {
        self.lock().command_outputs.push_back(out);
        self
    }

    /// Every sleep requested (throttling, retry waits); the fake never sleeps.
    pub fn sleeps(&self) -> Vec<Duration> {
        self.lock().sleeps.clone()
    }

    /// Run file operations on the real file system (still recorded) instead of the in-memory one.
    pub fn on_disk(self) -> Self {
        self.lock().disk = true;
        self
    }

    /// Put a file in the in-memory file system.
    pub fn file(&self, path: impl Into<PathBuf>, bytes: impl Into<Vec<u8>>) -> &Self {
        self.lock().files.insert(path.into(), Some(bytes.into()));
        self
    }

    /// The in-memory file system: scripted files and everything written.
    pub fn files(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        self.lock().files.iter().filter_map(|(p, b)| Some((p.clone(), b.clone()?))).collect()
    }

    /// Every file operation, in order.
    pub fn file_ops(&self) -> Vec<FileOp> {
        self.lock().file_ops.clone()
    }
}

impl Transport for FakeTransport {
    fn http(&self, req: &Request) -> Result<Response> {
        let mut s = self.lock();
        s.requests.push(req.clone());
        if let Some((_, res)) = s.rules.iter().find(|(pred, _)| pred(req)) {
            return res.clone();
        }
        if let Some(res) = s.queue.pop_front() {
            return res;
        }
        Ok(s.default.clone())
    }

    fn connect(&self, ep: &Endpoint) -> Result<Box<dyn Conn>> {
        let mut s = self.lock();
        s.endpoints.push(ep.clone());
        match s.conns.pop_front() {
            Some(mut c) => {
                if ep.tls {
                    c.tls = true;
                }
                Ok(Box::new(c))
            }
            None => Err(Error::transport(format!("no scripted connection for {}:{}", ep.host, ep.port))),
        }
    }

    fn datagram(&self, dg: &Datagram) -> Result<()> {
        self.lock().datagrams.push(dg.clone());
        Ok(())
    }

    fn command(&self, cmd: &Command) -> Result<CommandOutput> {
        let mut s = self.lock();
        s.commands.push(cmd.clone());
        s.command_outputs.pop_front().unwrap_or(Ok(CommandOutput { status: 0, stdout: Vec::new(), stderr: Vec::new() }))
    }

    fn file(&self, op: &FileOp) -> Result<FileOutput> {
        let mut s = self.lock();
        s.file_ops.push(op.clone());
        let path = op.path().to_path_buf();
        let known = s.files.get(&path).cloned();
        match (op, known) {
            _ if s.disk => {
                drop(s);
                std_file(op)
            }
            (FileOp::Stat { .. } | FileOp::Read { .. }, None) => {
                drop(s);
                std_file(op)
            }
            (FileOp::Stat { .. }, Some(f)) => {
                Ok(FileOutput::Meta(f.map(|b| FileMeta { is_file: true, len: b.len() as u64, executable: false })))
            }
            (FileOp::Read { max, .. }, Some(Some(b))) if *max == 0 || b.len() as u64 <= *max => {
                Ok(FileOutput::Bytes(b))
            }
            (FileOp::Read { max, .. }, Some(_)) => {
                Err(Error::Message(format!("{}: not a file of at most {max} bytes", path.display())))
            }
            (FileOp::Append { data, .. }, known) => {
                let mut b = known.flatten().unwrap_or_default();
                b.extend_from_slice(data);
                s.files.insert(path, Some(b));
                Ok(FileOutput::Done)
            }
            (FileOp::WriteAtomic { data, .. }, _) => {
                s.files.insert(path, Some(data.clone()));
                Ok(FileOutput::Done)
            }
            (FileOp::Remove { .. }, _) => {
                s.files.insert(path, None);
                Ok(FileOutput::Done)
            }
            (FileOp::CreateDir { .. } | FileOp::Touch { .. }, _) => Ok(FileOutput::Done),
        }
    }

    fn sleep(&self, d: Duration) {
        self.lock().sleeps.push(d);
    }

    fn env(&self) -> Arc<dyn Env> {
        self.lock().env.clone()
    }
}

/// One [`FixedEnv`] shared by the unit tests, so keys made in one test differ from each other.
#[cfg(test)]
pub(crate) fn test_env() -> &'static FixedEnv {
    static ENV: std::sync::LazyLock<FixedEnv> = std::sync::LazyLock::new(|| FixedEnv::new(1_700_000_000));
    &ENV
}

/// A frozen clock and a deterministic byte stream: two runs that ask for the same things get the same answers.
///
/// The bytes are SHA-256 of a counter, so they are not secret; use it in tests only.
///
/// ```
/// use mercurio::Env;
/// use mercurio::testing::{FakeTransport, FixedEnv};
///
/// let (a, b) = (FixedEnv::new(1_700_000_000), FixedEnv::new(1_700_000_000));
/// assert_eq!(a.unix_time(), 1_700_000_000);
/// assert_eq!(a.uuid4(), b.uuid4());
/// assert_ne!(a.random_hex(8), a.random_hex(8));
///
/// let fake = FakeTransport::new().with_env(FixedEnv::new(1_700_000_000));
/// ```
#[derive(Debug)]
pub struct FixedEnv {
    now: SystemTime,
    counter: AtomicU64,
}

impl FixedEnv {
    /// A clock stopped at `unix_secs`, with the byte stream at its start.
    pub fn new(unix_secs: u64) -> Self {
        Self { now: UNIX_EPOCH + Duration::from_secs(unix_secs), counter: AtomicU64::new(0) }
    }
}

impl Env for FixedEnv {
    fn now(&self) -> SystemTime {
        self.now
    }

    fn fill_random(&self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(32) {
            let n = self.counter.fetch_add(1, Ordering::Relaxed);
            let block = crate::crypto::sha256(&n.to_be_bytes());
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
}

type Handler = Box<dyn FnMut(&[u8]) -> Vec<u8> + Send>;

/// An in-memory stream driven by a handler that sees every write and returns bytes for the client to read next.
///
/// `written()` exposes everything the client sent for assertions.
pub struct ScriptedConn {
    greeting: Vec<u8>,
    readable: VecDeque<u8>,
    handler: Handler,
    written: Arc<Mutex<Vec<u8>>>,
    pending_line: Vec<u8>,
    line_mode: bool,
    tls: bool,
    allow_tls: bool,
}

impl ScriptedConn {
    /// Handler called once per complete line (`\n`-terminated) the client writes.
    pub fn lines(
        greeting: impl Into<Vec<u8>>,
        mut on_line: impl FnMut(&str) -> Option<String> + Send + 'static,
    ) -> Self {
        let handler: Handler = Box::new(move |line: &[u8]| {
            let text = String::from_utf8_lossy(line);
            let text = text.trim_end_matches(['\r', '\n']);
            on_line(text).map(String::into_bytes).unwrap_or_default()
        });
        Self::build(greeting.into(), handler, true)
    }

    /// Handler called with every raw write.
    pub fn bytes(greeting: impl Into<Vec<u8>>, handler: impl FnMut(&[u8]) -> Vec<u8> + Send + 'static) -> Self {
        Self::build(greeting.into(), Box::new(handler), false)
    }

    fn build(greeting: Vec<u8>, handler: Handler, line_mode: bool) -> Self {
        Self {
            greeting: greeting.clone(),
            readable: greeting.into_iter().collect(),
            handler,
            written: Arc::new(Mutex::new(Vec::new())),
            pending_line: Vec::new(),
            line_mode,
            tls: false,
            allow_tls: true,
        }
    }

    /// Refuse STARTTLS upgrades.
    pub fn without_tls(mut self) -> Self {
        self.allow_tls = false;
        self
    }

    /// Shared handle to every byte written by the client.
    pub fn written(&self) -> Arc<Mutex<Vec<u8>>> {
        self.written.clone()
    }

    /// Bytes the peer sends when the connection opens.
    pub fn greeting(&self) -> &[u8] {
        &self.greeting
    }
}

impl Read for ScriptedConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.readable.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min(self.readable.len());
        for b in buf.iter_mut().take(n) {
            *b = self.readable.pop_front().unwrap();
        }
        Ok(n)
    }
}

impl Write for ScriptedConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written.lock().unwrap().extend_from_slice(buf);
        if self.line_mode {
            for &b in buf {
                self.pending_line.push(b);
                if b == b'\n' {
                    let line = std::mem::take(&mut self.pending_line);
                    let reply = (self.handler)(&line);
                    self.readable.extend(reply);
                }
            }
        } else {
            let reply = (self.handler)(buf);
            self.readable.extend(reply);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Conn for ScriptedConn {
    fn start_tls(&mut self) -> Result<()> {
        if !self.allow_tls {
            return Err(Error::transport("TLS not available"));
        }
        self.tls = true;
        Ok(())
    }
    fn is_tls(&self) -> bool {
        self.tls
    }
}

impl std::fmt::Debug for FakeTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeTransport").field("requests", &self.lock().requests.len()).finish()
    }
}

impl std::fmt::Debug for ScriptedConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScriptedConn").field("tls", &self.tls).finish()
    }
}
