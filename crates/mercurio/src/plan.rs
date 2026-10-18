//! Sans-IO delivery plans.
//!
//! A service never performs I/O. It returns a [`Plan`]: a tree of HTTP requests (with continuations that look at each response), raw socket sessions, datagrams and process invocations. [`execute`] walks the tree against any [`Transport`]. Tests swap in [`crate::testing::FakeTransport`] and inspect every request without touching the network.

use std::fmt;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::http::{DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT, Request, Response};
use crate::transport::{Command, CommandOutput, Conn, Datagram, Endpoint, Transport};

/// Continuation receiving the outcome of an HTTP request.
pub type Then = Box<dyn FnOnce(Result<Response>) -> Plan + Send>;
/// Continuation receiving the outcome of a process run.
pub type ThenCommand = Box<dyn FnOnce(Result<CommandOutput>) -> Plan + Send>;
/// A blocking conversation over a connected stream (SMTP, IRC, MQTT, ...).
pub type Session = Box<dyn FnOnce(&mut dyn Conn) -> Result<()> + Send>;

/// What a service wants done.
///
/// A plan is a value: building one does no I/O. The constructors cover the common shapes; a service returns one from [`Notify::plan`](crate::Notify::plan).
///
/// ```
/// use mercurio::{Plan, Request};
///
/// // Two targets, each with its own outcome; `b` logs in first and stops
/// // if the login is not answered with 200.
/// let plan = Plan::all([
///     Plan::send(Request::post("https://example.com/a")).target("a"),
///     Plan::chain([
///         Plan::send_expect(Request::post("https://example.com/login"), &[200]),
///         Plan::send(Request::post("https://example.com/b")),
///     ])
///     .target("b"),
/// ]);
/// assert!(matches!(plan, Plan::All(ref plans) if plans.len() == 2));
/// ```
#[must_use]
pub enum Plan {
    /// Nothing (left) to do.
    Done,
    /// Record a failure for the current target.
    Fail(Error),
    /// Send a request, then continue with the closure.
    Http(Request, Then),
    /// Run every plan, even after failures (one per target, typically).
    All(Vec<Plan>),
    /// Run plans in order; stop at the first failure.
    Chain(Vec<Plan>),
    /// Attribute the outcome of the inner plan to a named target.
    Target(String, Box<Plan>),
    /// Open a stream (TCP, optionally TLS) and run a session on it.
    Socket(Endpoint, Session),
    /// Send one datagram (UDP or Unix socket).
    Datagram(Datagram),
    /// Run a local program.
    Command(Command, ThenCommand),
    /// Build the plan lazily when execution reaches it.
    Defer(Box<dyn FnOnce() -> Plan + Send>),
    /// Wait before continuing (e.g. server-advised back-off).
    Sleep(Duration),
}

impl fmt::Debug for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Plan::Done => f.write_str("Done"),
            Plan::Fail(e) => write!(f, "Fail({e})"),
            Plan::Http(r, _) => write!(f, "Http({r:?})"),
            Plan::All(v) => f.debug_tuple("All").field(v).finish(),
            Plan::Chain(v) => f.debug_tuple("Chain").field(v).finish(),
            Plan::Target(t, p) => f.debug_tuple("Target").field(t).field(p).finish(),
            Plan::Socket(e, _) => write!(f, "Socket({}:{})", e.host, e.port),
            Plan::Datagram(_) => f.write_str("Datagram"),
            Plan::Command(c, _) => write!(f, "Command({})", c.program),
            Plan::Defer(_) => f.write_str("Defer"),
            Plan::Sleep(d) => write!(f, "Sleep({d:?})"),
        }
    }
}

impl Plan {
    /// Send `req` and continue with `then`.
    pub fn http(req: Request, then: impl FnOnce(Result<Response>) -> Plan + Send + 'static) -> Plan {
        Plan::Http(req, Box::new(then))
    }

    /// Send `req`; succeed on any 2xx.
    pub fn send(req: Request) -> Plan {
        Plan::send_ok(req, &[])
    }

    /// Send `req`; succeed on 2xx or any status in `ok`.
    pub fn send_ok(req: Request, ok: &'static [u16]) -> Plan {
        Plan::http(req, move |res| match res {
            Ok(r) => match r.error_unless(ok) {
                Ok(()) => Plan::Done,
                Err(e) => Plan::Fail(e),
            },
            Err(e) => Plan::Fail(e),
        })
    }

    /// Send `req`; succeed only when the status is one of `statuses` (e.g. `&[200]`).
    pub fn send_expect(req: Request, statuses: &'static [u16]) -> Plan {
        Plan::http(req, move |res| match res {
            Ok(r) if statuses.contains(&r.status) => Plan::Done,
            Ok(r) => Plan::Fail(r.http_error()),
            Err(e) => Plan::Fail(e),
        })
    }

    /// Send `req`; transport errors fail, otherwise `check` decides.
    pub fn send_check(req: Request, check: impl FnOnce(&Response) -> Result<()> + Send + 'static) -> Plan {
        Plan::http(req, move |res| match res.and_then(|r| check(&r)) {
            Ok(()) => Plan::Done,
            Err(e) => Plan::Fail(e),
        })
    }

    /// Send `req`; on a successful response continue with `next(response)`. Non-2xx (outside `ok`) and transport errors fail.
    pub fn send_then(req: Request, next: impl FnOnce(Response) -> Plan + Send + 'static) -> Plan {
        Plan::http(req, move |res| match res {
            Ok(r) if r.is_success() => next(r),
            Ok(r) => Plan::Fail(r.http_error()),
            Err(e) => Plan::Fail(e),
        })
    }

    /// Record `e` as the failure of the current target.
    pub fn fail(e: Error) -> Plan {
        Plan::Fail(e)
    }

    /// Build the plan only when execution reaches it.
    pub fn defer(f: impl FnOnce() -> Plan + Send + 'static) -> Plan {
        Plan::Defer(Box::new(f))
    }

    /// Open a stream to `ep` and run `session` on it (SMTP, IRC, MQTT, ...).
    pub fn socket(ep: Endpoint, session: impl FnOnce(&mut dyn Conn) -> Result<()> + Send + 'static) -> Plan {
        Plan::Socket(ep, Box::new(session))
    }

    /// Run a local program, then continue with `then`.
    pub fn command(cmd: Command, then: impl FnOnce(Result<CommandOutput>) -> Plan + Send + 'static) -> Plan {
        Plan::Command(cmd, Box::new(then))
    }

    /// Run all plans independently (failures do not stop the rest).
    pub fn all(plans: impl IntoIterator<Item = Plan>) -> Plan {
        Plan::All(plans.into_iter().collect())
    }

    /// Run plans in order and stop at the first failure.
    pub fn chain(plans: impl IntoIterator<Item = Plan>) -> Plan {
        Plan::Chain(plans.into_iter().collect())
    }

    /// Label this plan's outcome as `target` in the delivery report.
    pub fn target(self, target: impl Into<String>) -> Plan {
        Plan::Target(target.into(), Box::new(self))
    }

    /// Name the step this plan performs in failures it produces itself (see [`Error::context`]): a `Fail`, a failed socket session, the failure an `Http` or `Command` continuation returns directly, and the same for every plan inside `All`, `Chain`, `Target` and `Defer`. Plans a continuation hands on (the next steps) are left alone.
    ///
    /// ```
    /// use mercurio::{Error, Plan};
    ///
    /// let Plan::Fail(e) = Plan::Fail(Error::service("no token")).context("login") else { unreachable!() };
    /// assert_eq!(e.to_string(), "login: service error: no token");
    /// ```
    pub fn context(self, context: impl Into<String>) -> Plan {
        let context = context.into();
        match self {
            Plan::Fail(e) => Plan::Fail(e.context(context)),
            Plan::Http(req, then) => Plan::http(req, move |res| then(res).fail_context(context)),
            Plan::Command(cmd, then) => Plan::command(cmd, move |res| then(res).fail_context(context)),
            Plan::Socket(ep, session) => Plan::socket(ep, move |c| session(c).map_err(|e| e.context(context))),
            Plan::Defer(f) => Plan::defer(move || f().context(context)),
            Plan::All(v) => Plan::All(v.into_iter().map(|p| p.context(context.clone())).collect()),
            Plan::Chain(v) => Plan::Chain(v.into_iter().map(|p| p.context(context.clone())).collect()),
            Plan::Target(t, p) => Plan::Target(t, Box::new(p.context(context))),
            p @ (Plan::Done | Plan::Datagram(_) | Plan::Sleep(_)) => p,
        }
    }

    fn fail_context(self, context: String) -> Plan {
        if let Plan::Fail(e) = self { Plan::Fail(e.context(context)) } else { self }
    }

    /// `Ok(())` -> Done, `Err` -> Fail.
    pub fn from_result(r: Result<()>) -> Plan {
        match r {
            Ok(()) => Plan::Done,
            Err(e) => Plan::Fail(e),
        }
    }
}

impl From<Result<Plan>> for Plan {
    fn from(r: Result<Plan>) -> Self {
        r.unwrap_or_else(Plan::Fail)
    }
}

/// Outcome for one target (or for the whole URL when the service has no per-target split).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Target label set with [`Plan::target`]; `None` for the URL as a whole.
    pub target: Option<String>,
    /// `Ok` when this target accepted the notification.
    pub result: std::result::Result<(), Error>,
}

/// Every outcome of one plan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Delivery {
    /// Outcomes in the order they were recorded.
    pub outcomes: Vec<Outcome>,
}

impl Delivery {
    /// `true` when there is at least one outcome and every outcome succeeded.
    pub fn is_success(&self) -> bool {
        !self.outcomes.is_empty() && self.outcomes.iter().all(|o| o.result.is_ok())
    }

    /// Errors of the failed outcomes.
    pub fn errors(&self) -> impl Iterator<Item = &Error> {
        self.outcomes.iter().filter_map(|o| o.result.as_ref().err())
    }

    /// Append the outcomes of `other`.
    pub fn merge(&mut self, other: Delivery) {
        self.outcomes.extend(other.outcomes);
    }
}

/// URL-level settings applied to every request of a plan.
#[derive(Debug, Clone, Copy)]
pub struct ExecOptions {
    /// Verify TLS certificates (`?verify=`).
    pub verify_tls: bool,
    /// Follow HTTP redirects.
    pub follow_redirects: bool,
    /// Connect timeout for requests that use the default (`?cto=`).
    pub connect_timeout: Option<Duration>,
    /// Read timeout for requests that use the default (`?rto=`).
    pub read_timeout: Option<Duration>,
    /// Minimum gap between consecutive requests.
    pub throttle: Duration,
}

impl Default for ExecOptions {
    fn default() -> Self {
        Self {
            verify_tls: true,
            follow_redirects: true,
            connect_timeout: None,
            read_timeout: None,
            throttle: Duration::ZERO,
        }
    }
}

/// Which message pieces and targets accepted a notification, so a retry skips them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeliveryTracker {
    delivered: std::collections::HashSet<(usize, Option<String>)>,
}

impl DeliveryTracker {
    /// An empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// `target == None` tracks the whole piece.
    pub fn is_delivered(&self, piece: usize, target: Option<&str>) -> bool {
        self.delivered.contains(&(piece, target.map(str::to_string)))
    }

    /// Record piece `piece` (and `target`; the whole piece for `None`) as delivered.
    pub fn mark_delivered(&mut self, piece: usize, target: Option<&str>) {
        self.delivered.insert((piece, target.map(str::to_string)));
    }
}

struct Runner<'a> {
    transport: &'a dyn Transport,
    opts: ExecOptions,
    last_io: Option<Instant>,
    out: Vec<Outcome>,
    tracker: Option<&'a mut DeliveryTracker>,
    piece: usize,
}

/// Execute a plan to completion.
pub fn execute(plan: Plan, transport: &dyn Transport, opts: ExecOptions) -> Delivery {
    let mut ex = Executor::new(transport, opts);
    let ok = ex.run(plan);
    ex.finish(ok)
}

/// Runs several plans (the pieces of one message) on one transport, keeping the throttle between them and, optionally, a [`DeliveryTracker`] that skips targets an earlier attempt delivered.
pub struct Executor<'a> {
    runner: Runner<'a>,
}

impl fmt::Debug for Executor<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Executor").field("piece", &self.runner.piece).finish_non_exhaustive()
    }
}

impl<'a> Executor<'a> {
    /// An executor without a delivery tracker.
    pub fn new(transport: &'a dyn Transport, opts: ExecOptions) -> Self {
        Self { runner: Runner { transport, opts, last_io: None, out: Vec::new(), tracker: None, piece: 0 } }
    }

    /// Skip and record targets through `tracker`.
    pub fn with_tracker(mut self, tracker: &'a mut DeliveryTracker) -> Self {
        self.runner.tracker = Some(tracker);
        self
    }

    /// Message piece the next plan belongs to (tracking key).
    pub fn set_piece(&mut self, piece: usize) {
        self.runner.piece = piece;
    }

    /// `true` when the tracker says the current piece was delivered.
    pub fn piece_delivered(&self) -> bool {
        self.runner.tracker.as_deref().is_some_and(|t| t.is_delivered(self.runner.piece, None))
    }

    /// Run one plan; returns whether it succeeded. A successful plan marks the current piece delivered.
    pub fn run(&mut self, plan: Plan) -> bool {
        let ok = self.runner.run(plan, None);
        if ok && let Some(t) = self.runner.tracker.as_deref_mut() {
            t.mark_delivered(self.runner.piece, None);
        }
        ok
    }

    /// Outcomes so far (a generic one when no target reported any).
    pub fn finish(self, ok: bool) -> Delivery {
        let mut out = self.runner.out;
        if out.is_empty() {
            out.push(Outcome {
                target: None,
                result: if ok { Ok(()) } else { Err(Error::Service("delivery failed".into())) },
            });
        }
        Delivery { outcomes: out }
    }
}

impl Runner<'_> {
    fn throttle(&mut self) {
        if let Some(last) = self.last_io {
            let elapsed = last.elapsed();
            if elapsed < self.opts.throttle {
                self.transport.sleep(self.opts.throttle - elapsed);
            }
        }
        self.last_io = Some(Instant::now());
    }

    fn apply(&self, mut req: Request) -> Request {
        req.verify_tls &= self.opts.verify_tls;
        req.follow_redirects &= self.opts.follow_redirects;
        if let Some(c) = self.opts.connect_timeout
            && req.connect_timeout == DEFAULT_CONNECT_TIMEOUT
        {
            req.connect_timeout = c;
        }
        if let Some(rt) = self.opts.read_timeout
            && req.read_timeout == DEFAULT_READ_TIMEOUT
        {
            req.read_timeout = rt;
        }
        req
    }

    fn fail(&mut self, target: Option<&str>, e: Error) -> bool {
        log::warn!("{}{}", target.map(|t| format!("{t}: ")).unwrap_or_default(), e);
        self.out.push(Outcome { target: target.map(str::to_string), result: Err(e) });
        false
    }

    fn run(&mut self, plan: Plan, target: Option<&str>) -> bool {
        match plan {
            Plan::Done => true,
            Plan::Fail(e) => self.fail(target, e),
            Plan::Http(req, then) => {
                let req = self.apply(req);
                self.throttle();
                log::debug!("{} {}", req.method, redact_url(&req.url));
                let res = self.transport.http(&req);
                if let Ok(r) = &res {
                    log::debug!("-> HTTP {}", r.status);
                }
                self.run(then(res), target)
            }
            Plan::All(plans) => {
                let mut ok = true;
                for p in plans {
                    ok &= self.run(p, target);
                }
                ok
            }
            Plan::Chain(plans) => {
                for p in plans {
                    if !self.run(p, target) {
                        return false;
                    }
                }
                true
            }
            Plan::Target(label, inner) => {
                let piece = self.piece;
                if self.tracker.as_deref().is_some_and(|t| t.is_delivered(piece, Some(&label))) {
                    log::debug!("{label}: already accepted this message; skipping");
                    self.out.push(Outcome { target: Some(label), result: Ok(()) });
                    return true;
                }
                let ok = self.run(*inner, Some(&label));
                if ok {
                    if let Some(t) = self.tracker.as_deref_mut() {
                        t.mark_delivered(piece, Some(&label));
                    }
                    self.out.push(Outcome { target: Some(label), result: Ok(()) });
                }
                ok
            }
            Plan::Socket(mut ep, session) => {
                ep.verify_tls &= self.opts.verify_tls;
                if let Some(c) = self.opts.connect_timeout {
                    ep.connect_timeout = c;
                }
                if let Some(rt) = self.opts.read_timeout {
                    ep.read_timeout = rt;
                }
                self.throttle();
                let res = self.transport.connect(&ep).and_then(|mut conn| session(conn.as_mut()));
                match res {
                    Ok(()) => true,
                    Err(e) => self.fail(target, e),
                }
            }
            Plan::Datagram(dg) => {
                self.throttle();
                match self.transport.datagram(&dg) {
                    Ok(()) => true,
                    Err(e) => self.fail(target, e),
                }
            }
            Plan::Command(cmd, then) => {
                let res = self.transport.command(&cmd);
                self.run(then(res), target)
            }
            Plan::Defer(f) => self.run(f(), target),
            Plan::Sleep(d) => {
                self.transport.sleep(d);
                true
            }
        }
    }
}

/// Strip userinfo, path and query from a URL for logging.
pub fn redact_url(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let host = rest.split(['/', '?']).next().unwrap_or("");
            let host = host.rsplit('@').next().unwrap_or(host);
            format!("{scheme}://{host}/...")
        }
        None => "<url>".into(),
    }
}
