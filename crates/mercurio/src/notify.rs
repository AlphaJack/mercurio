//! High-level API: parse URLs into [`Target`]s and fan a [`Message`] out.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use async_lock::Semaphore;

use crate::asset::Asset;
#[cfg(feature = "transport-blocking")]
use crate::blocking::BlockingTransport;
use crate::config::template::TemplateVars;
use crate::config::{Config, ConfigFormat, ConfigOptions, ConfigService, PendingTarget};
use crate::error::{Error, Result};
use crate::message::{Message, Prepared};
use crate::plan::{Delivery, Outcome, Plan};
use crate::report::{Attempt, Report, ReportEntry};
use crate::service::ServiceDef;
use crate::tag::TagFilter;
use crate::target::{Target, parse};
use crate::transport::Transport;

/// Most sends in progress at once across every [`Mercurio`] and [`crate::AsyncMercurio`] in the process. Targets of a service with a [`ServiceDef::throttle`] go one at a time, with the throttle between them.
const MAX_PARALLEL: usize = 128;

/// The process-wide budget of [`MAX_PARALLEL`] sends, shared by both facades so that concurrent `notify` calls (the HTTP server's requests, or a blocking and an async notifier) cannot multiply it.
pub(crate) static SEND_PERMITS: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(max_parallel()));

/// [`MAX_PARALLEL`], or `MERCURIO_BENCH_MAX_PARALLEL` (`0` = unlimited) for the benchmark harness only.
fn max_parallel() -> usize {
    match std::env::var("MERCURIO_BENCH_MAX_PARALLEL").ok().and_then(|v| v.parse().ok()) {
        Some(0) => usize::MAX,
        Some(n) => n,
        None => MAX_PARALLEL,
    }
}

/// A set of notification targets sharing a transport and branding.
///
/// ```no_run
/// let mut m = mercurio::Mercurio::new();
/// m.add("ntfy://my-topic").unwrap();
/// let report = m.notify(&mercurio::Message::new("Backup finished").title("cron"));
/// assert!(report.is_success());
/// ```
///
/// Configuration files add tagged targets; [`Mercurio::notify_tagged`] selects them by tag:
///
/// ```no_run
/// use mercurio::{Mercurio, Message, TagFilter};
///
/// let mut m = Mercurio::new();
/// m.add_config("~/.config/apprise/apprise.yml").unwrap();
/// m.notify_tagged(&Message::new("deployed"), &TagFilter::parse("devops"));
/// ```
pub struct Mercurio {
    core: Core,
    transport: Arc<dyn Transport>,
    pub(crate) sequential: bool,
}

/// Targets, template entries and settings shared by [`Mercurio`] and [`crate::AsyncMercurio`].
#[derive(Default)]
pub(crate) struct Core {
    pub(crate) targets: Vec<Target>,
    pub(crate) pending: Vec<PendingTarget>,
    pub(crate) asset: Asset,
    pub(crate) config: ConfigOptions,
}

impl Core {
    pub(crate) fn add(&mut self, url: &str) -> Result<()> {
        self.targets.push(parse(url)?);
        Ok(())
    }

    pub(crate) fn add_all(&mut self, urls: &str) -> Vec<Error> {
        crate::parse::parse_urls([urls], true).iter().filter_map(|url| self.add(url).err()).collect()
    }

    pub(crate) fn add_loaded(&mut self, cfg: Config) -> usize {
        for w in &cfg.warnings {
            log::warn!("{w}");
        }
        let n = cfg.services.len();
        for s in cfg.services {
            match s {
                ConfigService::Ready(t) => self.targets.push(t),
                ConfigService::Pending(p) => self.pending.push(*p),
            }
        }
        n
    }

    pub(crate) fn len(&self) -> usize {
        self.targets.len() + self.pending.len()
    }

    pub(crate) fn select(&self, filter: &TagFilter, vars: &TemplateVars) -> Selection<'_> {
        let mut sel = Selection {
            targets: self.targets.iter().filter(|t| filter.matches(t.tag_set())).collect(),
            ..Selection::default()
        };
        for p in self.pending.iter().filter(|p| filter.matches(&p.tags)) {
            match p.resolve(vars) {
                Ok(t) => sel.resolved.push(t),
                Err(e) => sel.unresolved.push((p, e)),
            }
        }
        sel
    }

    /// The asset `t` sends with: this notifier's, with the target's configuration overrides.
    pub(crate) fn asset_for(&self, t: &Target) -> Cow<'_, Asset> {
        t.effective_asset(&self.asset).map_or(Cow::Borrowed(&self.asset), Cow::Owned)
    }

    pub(crate) fn entry(&self, t: &Target, attempts: Vec<Attempt>) -> ReportEntry {
        ReportEntry {
            label: t.label(),
            service: t.def.id,
            delivery: attempts.last().map(|a| a.delivery.clone()).unwrap_or_default(),
            attempts,
            url_id: t.url_id(&self.asset_for(t)),
        }
    }

    /// The report of a selection: `entries` for its targets, then a failed entry per unresolved template entry.
    pub(crate) fn report(entries: Vec<ReportEntry>, unresolved: Vec<(&PendingTarget, Error)>) -> Report {
        let mut report = Report { entries };
        for (p, e) in unresolved {
            report.entries.push(ReportEntry {
                label: p.label(),
                service: p.service().id,
                delivery: Delivery { outcomes: vec![Outcome { target: None, result: Err(e) }] },
                attempts: Vec::new(),
                url_id: None,
            });
        }
        report
    }
}

/// Targets of a throttled service share one lane, sent in order; every other target is a lane of its own.
pub(crate) fn lanes(targets: &[&Target]) -> Vec<Vec<usize>> {
    let mut lanes: Vec<Vec<usize>> = Vec::new();
    let mut lane_of: BTreeMap<&str, usize> = BTreeMap::new();
    for (i, t) in targets.iter().enumerate() {
        if t.def.throttle.is_zero() {
            lanes.push(vec![i]);
        } else if let Some(&l) = lane_of.get(t.def.id) {
            lanes[l].push(i);
        } else {
            lane_of.insert(t.def.id, lanes.len());
            lanes.push(vec![i]);
        }
    }
    lanes
}

/// What is left of the service's throttle since its previous target finished at `last`, so a throttled service keeps its throttle between targets too.
pub(crate) fn throttle_wait(t: &Target, last: Option<Instant>) -> Option<Duration> {
    last.map(|at| t.def.throttle.saturating_sub(at.elapsed())).filter(|g| !g.is_zero())
}

impl fmt::Debug for Mercurio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mercurio")
            .field("targets", &self.core.targets.len())
            .field("pending", &self.core.pending.len())
            .finish()
    }
}

#[cfg(feature = "transport-blocking")]
impl Default for Mercurio {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Mercurio {
    fn drop(&mut self) {
        self.close();
    }
}

/// Targets chosen by a tag filter, with pending template entries resolved.
#[derive(Debug, Default)]
pub struct Selection<'a> {
    /// Ready targets that matched.
    pub targets: Vec<&'a Target>,
    /// Template entries built for this call.
    pub resolved: Vec<Target>,
    /// Template entries that matched but could not be built (missing values).
    pub unresolved: Vec<(&'a PendingTarget, Error)>,
}

impl Selection<'_> {
    /// Every target that would be notified.
    pub fn iter(&self) -> impl Iterator<Item = &Target> {
        self.targets.iter().copied().chain(self.resolved.iter())
    }

    /// Number of targets that would be notified (unresolved template entries excluded).
    pub fn len(&self) -> usize {
        self.targets.len() + self.resolved.len()
    }

    /// Nothing matched at all (not even an unresolved entry).
    pub fn is_empty(&self) -> bool {
        self.len() == 0 && self.unresolved.is_empty()
    }
}

impl Mercurio {
    /// Register a closure as the notifier for `scheme://` URLs, for every notifier in this process. See [`crate::register`].
    pub fn register_scheme<F>(scheme: &str, handler: F) -> Result<&'static ServiceDef>
    where
        F: Fn(&Prepared<'_>, &crate::registry::Hook<'_>) -> Plan + Send + Sync + 'static,
    {
        crate::registry::register_scheme(scheme, handler)
    }

    /// Add a full service definition at runtime ([`crate::register`]).
    pub fn register(def: &'static ServiceDef) -> Result<()> {
        crate::registry::register(def)
    }

    /// A notifier using [`BlockingTransport`] and the default [`Asset`] (feature `transport-blocking`).
    #[cfg(feature = "transport-blocking")]
    pub fn new() -> Self {
        Self::with_transport(Arc::new(BlockingTransport::new()))
    }

    /// A notifier using `transport` for all I/O (e.g. [`crate::testing::FakeTransport`]).
    pub fn with_transport(transport: Arc<dyn Transport>) -> Self {
        Self { core: Core::default(), transport, sequential: false }
    }

    /// Replace the [`Asset`] (branding, pipeline defaults, storage).
    pub fn asset(mut self, asset: Asset) -> Self {
        self.core.asset = asset;
        self
    }

    /// Send to targets one after another instead of in parallel threads.
    pub fn sequential(mut self) -> Self {
        self.sequential = true;
        self
    }

    /// Options for [`Mercurio::add_config`] (include depth, templates, ...).
    pub fn config_options(mut self, opts: ConfigOptions) -> Self {
        self.core.config = opts;
        self
    }

    /// Parse and add one URL.
    pub fn add(&mut self, url: &str) -> Result<&mut Self> {
        self.core.add(url)?;
        Ok(self)
    }

    /// Add several URLs separated by whitespace, commas or semicolons. Returns the errors for URLs that did not parse.
    pub fn add_all(&mut self, urls: &str) -> Vec<Error> {
        self.core.add_all(urls)
    }

    /// Add an already parsed target.
    pub fn push(&mut self, target: Target) -> &mut Self {
        self.core.targets.push(target);
        self
    }

    /// Load a configuration file or URL (path, `file://`, `http(s)://`) and add its services. Remote configurations are fetched through this notifier's transport. Returns the number of services added.
    pub fn add_config(&mut self, source: &str) -> Result<usize> {
        let cfg = Config::load(source, self.transport.as_ref(), &self.core.config)?;
        Ok(self.add_loaded(cfg))
    }

    /// Add configuration text (TEXT or YAML; detected when `format` is `None`).
    pub fn add_config_text(&mut self, content: &str, format: Option<ConfigFormat>) -> Result<usize> {
        let cfg = Config::from_text(content, format, self.transport.as_ref(), &self.core.config)?;
        Ok(self.add_loaded(cfg))
    }

    /// Add the services of an already loaded [`Config`].
    pub fn add_loaded(&mut self, cfg: Config) -> usize {
        self.core.add_loaded(cfg)
    }

    /// Keep only targets for which `keep` returns true (e.g. tag filtering).
    pub fn retain(&mut self, keep: impl FnMut(&Target) -> bool) -> &mut Self {
        self.core.targets.retain(keep);
        self
    }

    /// Targets ready to notify (pending template entries are separate).
    pub fn targets(&self) -> &[Target] {
        &self.core.targets
    }

    /// Configuration entries still waiting for template values.
    pub fn pending(&self) -> &[PendingTarget] {
        &self.core.pending
    }

    /// Number of targets plus pending template entries.
    pub fn len(&self) -> usize {
        self.core.len()
    }

    /// Nothing matched at all (not even an unresolved entry).
    pub fn is_empty(&self) -> bool {
        self.core.len() == 0
    }

    /// Targets matching `filter`, with matching template entries built from `vars`. Sends nothing (the CLI's `--dry-run`). Targets built from template entries live only for the call, so their in-memory store does not carry over between calls.
    pub fn select(&self, filter: &TagFilter, vars: &TemplateVars) -> Selection<'_> {
        self.core.select(filter, vars)
    }

    /// Send `msg` to every target; template entries use their defaults and `APPRISE_TEMPLATE_*` values. Never panics; failures are in the report.
    pub fn notify(&self, msg: &Message) -> Report {
        self.notify_with(msg, &TagFilter::all(), &TemplateVars::new())
    }

    /// Send to the targets matching `filter`.
    pub fn notify_tagged(&self, msg: &Message, filter: &TagFilter) -> Report {
        self.notify_with(msg, filter, &TemplateVars::new())
    }

    /// Send to the targets matching `filter`, filling templates from `vars`. Template entries that can not be built appear as failed entries.
    ///
    /// ```
    /// use std::sync::Arc;
    /// use mercurio::testing::FakeTransport;
    /// use mercurio::{Mercurio, Message, TagFilter, TemplateVars};
    ///
    /// let yaml = "
    /// version: 1
    /// template:
    ///   - host: localhost
    /// urls:
    ///   - json://${HOST}/hook
    /// ";
    /// let fake = Arc::new(FakeTransport::new());
    /// let mut m = Mercurio::with_transport(fake.clone());
    /// m.add_config_text(yaml, None)?;
    /// let vars = TemplateVars::new().with("host", "example.com");
    /// m.notify_with(&Message::new("hi"), &TagFilter::all(), &vars);
    /// assert_eq!(fake.last_request().unwrap().url, "http://example.com/hook");
    /// # Ok::<(), mercurio::Error>(())
    /// ```
    pub fn notify_with(&self, msg: &Message, filter: &TagFilter, vars: &TemplateVars) -> Report {
        let sel = self.core.select(filter, vars);
        let entries = self.send_all(msg, sel.iter().collect());
        // Template targets only live for this call.
        for t in &sel.resolved {
            self.close_target(t);
        }
        Core::report(entries, sel.unresolved)
    }

    fn close_target(&self, t: &Target) {
        t.close(self.transport.as_ref(), &self.core.asset_for(t));
    }

    /// The targets and settings, and the transport; nothing is closed.
    pub(crate) fn into_parts(mut self) -> (Core, Arc<dyn Transport>) {
        (std::mem::take(&mut self.core), self.transport.clone())
    }

    /// Run every target's clean-up now (log out, revoke tokens). Also done on drop.
    pub fn close(&mut self) {
        for t in &self.core.targets {
            self.close_target(t);
        }
    }

    fn send_all(&self, msg: &Message, targets: Vec<&Target>) -> Vec<ReportEntry> {
        let send = |t: &Target| self.core.entry(t, t.deliver(msg, self.transport.as_ref(), &self.core.asset_for(t)));
        let wait = |t: &Target, last: Option<Instant>| {
            if let Some(gap) = throttle_wait(t, last) {
                self.transport.sleep(gap);
            }
        };
        if self.sequential || targets.len() < 2 {
            let _permit = SEND_PERMITS.acquire_blocking();
            let mut last: BTreeMap<&str, Instant> = BTreeMap::new();
            return targets
                .into_iter()
                .map(|t| {
                    wait(t, last.get(t.def.id).copied());
                    let entry = send(t);
                    last.insert(t.def.id, Instant::now());
                    entry
                })
                .collect();
        }
        let run_lane = |lane: &[usize]| {
            let mut last = None;
            lane.iter()
                .map(|&i| {
                    wait(targets[i], last);
                    let entry = send(targets[i]);
                    last = Some(Instant::now());
                    (i, entry)
                })
                .collect::<Vec<_>>()
        };
        let lanes = lanes(&targets);
        let mut done: Vec<(usize, ReportEntry)> = std::thread::scope(|s| {
            let handles: Vec<_> = lanes
                .iter()
                .map(|lane| {
                    let permit = SEND_PERMITS.acquire_blocking();
                    s.spawn(move || {
                        let _permit = permit;
                        run_lane(lane)
                    })
                })
                .collect();
            handles.into_iter().flat_map(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p))).collect()
        });
        done.sort_by_key(|(i, _)| *i);
        done.into_iter().map(|(_, entry)| entry).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorClass;
    use crate::report::Status;
    use crate::service::{Context, Notify};
    use crate::transport::Blocking;

    #[test]
    fn async_entry_points_are_send() {
        fn assert_send<T: Send>(_: &T) {}
        let fake = crate::testing::FakeTransport::new();
        let (t, msg, asset) = (crate::parse("json://localhost").unwrap(), Message::new("x"), Asset::default());
        let blocking = Blocking(&fake);
        assert_send(&t.deliver_async(&msg, &blocking, &asset));
        assert_send(&t.close_async(&blocking, &asset));
        assert_send(&Config::load_async("/nowhere", &blocking, &ConfigOptions::default()));
        assert_send(&crate::AttachmentSet::default().load_async(&blocking, &asset));
    }

    #[test]
    fn blocking_sends_wait_for_the_shared_budget() {
        let fake = Arc::new(crate::testing::FakeTransport::new());
        fake.respond(200, "{}");
        let mut m = Mercurio::with_transport(fake.clone());
        m.add("json://localhost/budget").unwrap();
        let held: Vec<_> = (0..max_parallel()).map(|_| SEND_PERMITS.acquire_blocking()).collect();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|s| {
            s.spawn(|| tx.send(m.notify(&Message::new("b"))).unwrap());
            assert!(rx.recv_timeout(Duration::from_millis(100)).is_err(), "sent without a permit");
            drop(held);
            assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap().is_success());
        });
    }

    #[test]
    fn throttled_service_waits_between_targets() {
        use crate::testing::FakeTransport;

        #[derive(Debug)]
        struct Throttled;
        impl Notify for Throttled {
            fn plan(&self, _: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
                Plan::send(ctx.post("http://localhost/throttled"))
            }
        }
        static THROTTLED: ServiceDef = ServiceDef {
            id: "throttled_test",
            name: "Throttled",
            schemes: &["throttledtest"],
            parse: |_| Ok(Box::new(Throttled)),
            throttle: Duration::from_secs(5),
            ..ServiceDef::DEFAULTS
        };
        Mercurio::register(&THROTTLED).unwrap();

        for sequential in [false, true] {
            let fake = Arc::new(FakeTransport::new());
            fake.default_response(crate::Response::new(200, b"{}".to_vec()));
            let mut m = Mercurio::with_transport(fake.clone());
            if sequential {
                m = m.sequential();
            }
            for i in 0..3 {
                m.add(&format!("throttledtest://t{i}")).unwrap();
                m.add(&format!("json://localhost/t{i}/")).unwrap();
            }
            assert!(m.notify(&Message::new("b")).is_success());
            assert_eq!(fake.requests().len(), 6);
            let sleeps = fake.sleeps();
            assert_eq!(sleeps.len(), 2, "sequential={sequential}");
            assert!(sleeps.iter().all(|d| *d > Duration::from_secs(4)), "{sleeps:?}");
        }
    }

    #[test]
    fn parallel_pool_sends_every_target_in_order() {
        use crate::testing::FakeTransport;
        let fake = Arc::new(FakeTransport::new());
        fake.default_response(crate::Response::new(200, b"{}".to_vec()));
        let n = MAX_PARALLEL * 3 + 1;
        let mut m = Mercurio::with_transport(fake.clone());
        for i in 0..n {
            if i % 2 == 1 {
                fake.on_url(format!("/t{i}/"), crate::Response::new(500, b"{}".to_vec()));
            }
            m.add(&format!("json://localhost/t{i}/")).unwrap();
        }
        let r = m.notify(&Message::new("b"));
        assert_eq!(fake.requests().len(), n);
        let statuses: Vec<_> = r.entries.iter().map(ReportEntry::status).collect();
        let expected: Vec<_> = (0..n).map(|i| if i % 2 == 1 { Status::Failure } else { Status::Success }).collect();
        assert_eq!(statuses, expected);
    }

    #[test]
    fn report_statuses_and_attempts() {
        use crate::testing::FakeTransport;
        let fake = Arc::new(FakeTransport::new());
        let notifier = |urls: &[&str]| {
            let mut m = Mercurio::with_transport(fake.clone()).sequential();
            for u in urls {
                m.add(u).unwrap();
            }
            m
        };
        let msg = Message::new("b");
        assert_eq!(notifier(&[]).notify(&msg).status(), Status::NoMatch);
        fake.respond_with(crate::Response::new(200, b"{}".to_vec()));
        fake.respond_with(crate::Response::new(500, b"{}".to_vec()));
        let r = notifier(&["json://localhost/a", "json://localhost/b"]).notify(&msg);
        assert_eq!(
            (r.status(), r.entries[0].status(), r.entries[1].status()),
            (Status::Partial, Status::Success, Status::Failure)
        );
        // Retries are reported per attempt; the first attempt timed out.
        fake.fail(Error::transport("timed out (read)"));
        fake.respond_with(crate::Response::new(200, b"{}".to_vec()));
        let r = notifier(&["json://localhost/a?retry=2&wait=0"]).notify(&msg);
        let e = &r.entries[0];
        assert_eq!(e.attempts.iter().map(Attempt::status).collect::<Vec<_>>(), [Status::Timeout, Status::Success]);
        assert_eq!((r.status(), e.status()), (Status::Success, Status::Success));
        assert!(e.url_id.as_deref().is_some_and(|id| id.len() == 8));
        fake.fail(Error::transport("timed out (connect)"));
        let r = notifier(&["json://localhost/a"]).notify(&msg);
        assert_eq!((r.status(), r.entries[0].status()), (Status::Timeout, Status::Timeout));
    }

    #[test]
    fn asset_redirect_default_yields_to_the_url() {
        use crate::testing::FakeTransport;
        let fake = FakeTransport::new();
        let asset = Asset { http_redirects: false, ..Asset::default() };
        let follows = |url: &str| {
            fake.respond(200, "");
            parse(url).unwrap().send(&Message::new("b"), &fake, &asset);
            fake.last_request().unwrap().follow_redirects
        };
        assert!(!follows("json://localhost/a"));
        assert!(follows("json://localhost/a?redirect=yes"));
    }

    /// Statuses of each attempt and the pauses between them, for a URL answered with `replies` in order.
    fn retry_run(url: &str, replies: Vec<Result<crate::Response>>) -> (Vec<Status>, Vec<Duration>) {
        let fake = Arc::new(crate::testing::FakeTransport::new());
        for reply in replies {
            match reply {
                Ok(r) => fake.respond_with(r),
                Err(e) => fake.fail(e),
            };
        }
        let mut m = Mercurio::with_transport(fake.clone());
        m.add(url).unwrap();
        let r = m.notify(&Message::new("b"));
        (r.entries[0].attempts.iter().map(Attempt::status).collect(), fake.sleeps())
    }

    #[test]
    fn retries_only_retryable_failures() {
        use crate::Response;
        let url = "json://localhost/a?retry=3&wait=1";
        let secs = Duration::from_secs;
        let ok = || Ok(Response::new(200, "{}"));
        let status = |code| Ok(Response::new(code, "no"));
        let retry_after = |code, v| Ok(Response::new(code, "slow").with_header("Retry-After", v));
        // 429 + Retry-After: wait what the service asked (longer than ?wait=).
        let (s, sleeps) = retry_run(url, vec![retry_after(429, "7"), ok()]);
        assert_eq!((s, sleeps), (vec![Status::Failure, Status::Success], vec![secs(7)]));
        // Retry-After shorter than ?wait= keeps ?wait=.
        assert_eq!(retry_run(url, vec![retry_after(503, "0"), ok()]).1, vec![secs(1)]);
        // 503 without Retry-After and connect failures: retried after ?wait=.
        let (s, sleeps) = retry_run(url, vec![status(503), Err(Error::transport("connection refused")), ok()]);
        assert_eq!((s.len(), sleeps), (3, vec![secs(1), secs(1)]));
        // Rejected credentials, bad requests, ambiguous outcomes and a Retry-After beyond MAX_RETRY_AFTER: one attempt, no wait.
        for reply in [
            status(401),
            status(400),
            Err(Error::unconfirmed("timed out (receive response)")),
            retry_after(429, "3600"),
        ] {
            let (s, sleeps) = retry_run(url, vec![reply, ok()]);
            assert_eq!((s.len(), sleeps), (1, vec![]));
        }
    }

    #[test]
    fn step_context_keeps_rate_limit_retry() {
        use crate::Response;
        // SendPulse fetches a token first: a 429 there is reported as "token: ..." and still waits the service's Retry-After before the second attempt.
        let fake = Arc::new(crate::testing::FakeTransport::new());
        fake.respond_with(Response::new(429, "slow").with_header("Retry-After", "7"));
        fake.respond_with(Response::new(500, "{}"));
        let mut m = Mercurio::with_transport(fake.clone());
        m.add("sendpulse://user@example.com/client_id/cs1/?retry=1&wait=1").unwrap();
        let r = m.notify(&Message::new("b"));
        let attempts = &r.entries[0].attempts;
        assert_eq!(attempts.len(), 2);
        let first = attempts[0].delivery.errors().next().expect("a failure");
        assert_eq!(first.to_string(), "token: HTTP 429: slow");
        assert_eq!(first.class(), ErrorClass::RateLimited { retry_after: Some(Duration::from_secs(7)) });
        assert_eq!(fake.sleeps(), vec![Duration::from_secs(7)]);
        let (_, outcome) = r.failures().next().expect("reported failure");
        assert_eq!(outcome.result.as_ref().unwrap_err().to_string(), "token: HTTP 500: {}");
    }

    /// The class of the first failure a single send of `url` reports.
    fn first_error(url: &str, replies: Vec<crate::Response>) -> crate::ErrorClass {
        let fake = crate::testing::FakeTransport::new();
        for r in replies {
            fake.respond_with(r);
        }
        let t = parse(url).unwrap();
        let d = t.send(&Message::new("b").title("t"), &fake, &Asset::default());
        d.outcomes.into_iter().find_map(|o| o.result.err()).expect("a failure").class()
    }

    #[test]
    fn services_carry_retry_after() {
        use crate::{ErrorClass, Response};
        let limited = |d| ErrorClass::RateLimited { retry_after: Some(Duration::from_secs(d)) };
        let slow = || Response::new(429, "slow").with_header("Retry-After", "9");
        assert_eq!(first_error("pbul://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", vec![slow()]), limited(9));
        assert_eq!(
            first_error("pbul://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", vec![Response::new(401, "no")]),
            ErrorClass::Auth
        );
        // Discord retries a 429 once itself, then reports Retry-After.
        assert_eq!(first_error("discord://1234/abcd", vec![slow(), slow()]), limited(9));
        // Without Retry-After, the bucket reset (plus 10 s clock skew) is the wait.
        let reset =
            (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 30).to_string();
        let bucket = || {
            Response::new(429, "slow")
                .with_header("X-RateLimit-Remaining", "1")
                .with_header("X-RateLimit-Reset", &reset)
        };
        let class = first_error("discord://1234/abcd", vec![bucket(), bucket()]);
        let ErrorClass::RateLimited { retry_after: Some(d) } = class else { panic!("{class:?}") };
        assert!((35..=41).contains(&d.as_secs()), "{d:?}");
    }
}
