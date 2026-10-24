//! High-level API: parse URLs into [`Target`]s and fan a [`Message`] out.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use crate::asset::Asset;
#[cfg(feature = "transport-blocking")]
use crate::blocking::BlockingTransport;
use crate::config::template::TemplateVars;
use crate::config::{Config, ConfigFormat, ConfigOptions, ConfigService, PendingTarget};
use crate::error::{Error, Result};
use crate::message::Message;
use crate::plan::{Delivery, Outcome};
use crate::registry::Registry;
use crate::report::{Attempt, Report, ReportEntry};
use crate::semaphore::Semaphore;
use crate::tag::TagFilter;
use crate::target::Target;
use crate::transport::{Blocking, Transport};

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
/// Configuration files add tagged targets; [`Mercurio::notify_with`] selects them by tag:
///
/// ```no_run
/// use mercurio::{Mercurio, Message, NotifyOptions, TagFilter};
///
/// let mut m = Mercurio::new();
/// m.add_config("~/.config/apprise/apprise.yml").unwrap();
/// m.notify_with(&Message::new("deployed"), NotifyOptions::new().tags(&TagFilter::parse("devops")));
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
        self.targets.push(self.config.registry.parse(url)?);
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
            escalated: false,
        }
    }

    /// The entries of the rounds sent, in selection order, with the failures a later priority group made up for marked [`ReportEntry::escalated`].
    pub(crate) fn in_order(esc: &Escalation, mut sent: Vec<(usize, ReportEntry)>) -> Vec<ReportEntry> {
        sent.sort_by_key(|(i, _)| *i);
        sent.into_iter()
            .map(|(i, mut e)| {
                e.escalated = !e.delivery.is_success() && esc.escalated(i);
                e
            })
            .collect()
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
                escalated: false,
            });
        }
        report
    }
}

/// Apprise's priority escalation over a selection: each tag chain sends its most urgent priority group first and moves on to the next group only when one of its services failed. Chains run their groups together, one round at a time. A filter naming an exact priority (`2:tag`) sends everything in one round.
pub(crate) struct Escalation {
    /// Per chain, its groups of selection indices from most to least urgent.
    chains: Vec<Vec<Vec<usize>>>,
    /// Per chain, the group it sends next.
    next: Vec<usize>,
    /// Per chain, the group that delivered.
    done: Vec<Option<usize>>,
}

impl Escalation {
    pub(crate) fn new(filter: &TagFilter, targets: &[&Target]) -> Self {
        let mut chains: Vec<(String, BTreeMap<u64, Vec<usize>>)> = Vec::new();
        for (i, t) in targets.iter().enumerate() {
            let (key, priority) =
                if filter.has_explicit_priority() { (String::new(), 0) } else { filter.chain_of(t.tag_set()) };
            let at = chains.iter().position(|(k, _)| *k == key).unwrap_or_else(|| {
                chains.push((key, BTreeMap::new()));
                chains.len() - 1
            });
            chains[at].1.entry(priority).or_default().push(i);
        }
        let chains: Vec<Vec<Vec<usize>>> = chains.into_iter().map(|(_, g)| g.into_values().collect()).collect();
        Escalation { next: vec![0; chains.len()], done: vec![None; chains.len()], chains }
    }

    /// The chains still sending: not delivered and with a group left.
    fn pending(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.chains.len()).filter(|&c| self.done[c].is_none() && self.next[c] < self.chains[c].len())
    }

    /// The selection indices to send in the next round, in order; `None` when every chain is finished.
    pub(crate) fn round(&self) -> Option<Vec<usize>> {
        let mut batch: Vec<usize> = self.pending().flat_map(|c| self.chains[c][self.next[c]].iter().copied()).collect();
        batch.sort_unstable();
        (!batch.is_empty()).then_some(batch)
    }

    /// Record the round: a chain whose group all delivered is done, any other moves on to its next group.
    pub(crate) fn settle(&mut self, delivered: impl Fn(usize) -> bool) {
        for c in self.pending().collect::<Vec<_>>() {
            if self.chains[c][self.next[c]].iter().all(|&i| delivered(i)) {
                self.done[c] = Some(self.next[c]);
            } else {
                self.next[c] += 1;
            }
        }
    }

    /// Whether a later group of `i`'s chain delivered (so `i`'s failure does not count).
    pub(crate) fn escalated(&self, i: usize) -> bool {
        self.chains
            .iter()
            .zip(&self.done)
            .any(|(groups, done)| done.is_some_and(|d| groups[..d].iter().any(|g| g.contains(&i))))
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

/// Which targets a `notify_with` call sends to and how it reports progress. The default sends to every target, fills templates from their defaults and `APPRISE_TEMPLATE_*` values, and reports nothing until the call returns.
///
/// ```
/// use mercurio::{NotifyOptions, TagFilter, TemplateVars};
///
/// let filter = TagFilter::parse("devops");
/// let vars = TemplateVars::new().with("host", "example.com");
/// let opts = NotifyOptions::new().tags(&filter).vars(&vars).on_entry(&|e| eprintln!("{}: {}", e.label, e.status()));
/// # let _ = opts;
/// ```
#[derive(Clone, Copy, Default)]
pub struct NotifyOptions<'a> {
    pub(crate) filter: Option<&'a TagFilter>,
    pub(crate) vars: Option<&'a TemplateVars>,
    pub(crate) on_entry: Option<&'a (dyn Fn(&ReportEntry) + Sync)>,
}

impl fmt::Debug for NotifyOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotifyOptions")
            .field("filter", &self.filter)
            .field("vars", &self.vars.is_some())
            .field("on_entry", &self.on_entry.is_some())
            .finish()
    }
}

impl<'a> NotifyOptions<'a> {
    /// Every target, default template values, no progress callback.
    pub fn new() -> Self {
        Self::default()
    }

    /// Send only to the targets matching `filter` (default [`TagFilter::all`]).
    #[must_use]
    pub fn tags(mut self, filter: &'a TagFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Fill `${NAME}` templates from `vars` first. Template entries that can not be built appear as failed entries.
    #[must_use]
    pub fn vars(mut self, vars: &'a TemplateVars) -> Self {
        self.vars = Some(vars);
        self
    }

    /// Call `on_entry` with each URL's entry as soon as it is final, so a caller can report progress (e.g. stream it). Entries of template URLs that could not be resolved come last. The blocking notifier calls it from the sending thread.
    #[must_use]
    pub fn on_entry(mut self, on_entry: &'a (dyn Fn(&ReportEntry) + Sync)) -> Self {
        self.on_entry = Some(on_entry);
        self
    }
}

/// Targets chosen by a tag filter, with pending template entries resolved.
#[derive(Debug, Default)]
#[non_exhaustive]
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
    #[must_use]
    pub fn asset(mut self, asset: Asset) -> Self {
        self.core.asset = asset;
        self
    }

    /// Send to targets one after another instead of in parallel threads.
    #[must_use]
    pub fn sequential(mut self) -> Self {
        self.sequential = true;
        self
    }

    /// Options for [`Mercurio::add_config`] (include depth, templates, ...). `opts.registry` replaces this notifier's [`Registry`].
    #[must_use]
    pub fn config_options(mut self, opts: ConfigOptions) -> Self {
        self.core.config = opts;
        self
    }

    /// The runtime services of this notifier: register custom schemes here before adding their URLs.
    pub fn registry_mut(&mut self) -> &mut Registry {
        &mut self.core.config.registry
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
        self.notify_with(msg, NotifyOptions::new())
    }

    /// Send `msg` with [`NotifyOptions`]: a tag filter, template values, a progress callback.
    ///
    /// ```
    /// use std::sync::Arc;
    /// use mercurio::testing::FakeTransport;
    /// use mercurio::{Mercurio, Message, NotifyOptions, TemplateVars};
    /// # if !cfg!(feature = "config-yaml") { return Ok(()); }
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
    /// m.notify_with(&Message::new("hi"), NotifyOptions::new().vars(&vars));
    /// assert_eq!(fake.last_request().unwrap().url, "http://example.com/hook");
    /// # Ok::<(), mercurio::Error>(())
    /// ```
    pub fn notify_with(&self, msg: &Message, opts: NotifyOptions<'_>) -> Report {
        let (all, none) = (TagFilter::all(), TemplateVars::new());
        let filter = opts.filter.unwrap_or(&all);
        let vars = opts.vars.unwrap_or(&none);
        let on_entry = opts.on_entry.unwrap_or(&|_| {});
        self.send_selected(msg, filter, vars, on_entry)
    }

    fn send_selected(
        &self,
        msg: &Message,
        filter: &TagFilter,
        vars: &TemplateVars,
        on_entry: &(dyn Fn(&ReportEntry) + Sync),
    ) -> Report {
        let sel = self.core.select(filter, vars);
        let targets: Vec<&Target> = sel.iter().collect();
        let mut esc = Escalation::new(filter, &targets);
        let mut sent = Vec::new();
        while let Some(round) = esc.round() {
            let entries = self.send_all(msg, round.iter().map(|&i| targets[i]).collect(), filter, on_entry);
            let delivered: BTreeMap<usize, bool> =
                round.iter().copied().zip(entries.iter().map(|e| e.delivery.is_success())).collect();
            esc.settle(|i| delivered.get(&i).copied().unwrap_or(false));
            sent.extend(round.into_iter().zip(entries));
        }
        let entries = Core::in_order(&esc, sent);
        // Template targets only live for this call.
        for t in &sel.resolved {
            self.close_target(t);
        }
        let sent = entries.len();
        let report = Core::report(entries, sel.unresolved);
        for entry in &report.entries[sent..] {
            on_entry(entry);
        }
        report
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

    fn send_all(
        &self,
        msg: &Message,
        targets: Vec<&Target>,
        filter: &TagFilter,
        on_entry: &(dyn Fn(&ReportEntry) + Sync),
    ) -> Vec<ReportEntry> {
        let send = |t: &Target| {
            let retry = filter.retry_for(t.tag_set()).map(|r| u32::try_from(r).unwrap_or(u32::MAX));
            let transport = Blocking(self.transport.as_ref());
            let attempts =
                pollster::block_on(t.send_attempts_with_retry(msg, &transport, &self.core.asset_for(t), retry));
            let entry = self.core.entry(t, attempts);
            on_entry(&entry);
            entry
        };
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
    use crate::message::Prepared;
    use crate::plan::Plan;
    use crate::report::Status;
    use crate::service::{Context, Notify, ServiceDef};
    use crate::target::parse;
    use crate::transport::FileOp;

    #[cfg(feature = "service-json")]
    #[test]
    fn async_entry_points_are_send() {
        fn assert_send<T: Send>(_: &T) {}
        let fake = crate::testing::FakeTransport::new();
        let (t, msg, asset) = (crate::parse("json://localhost").unwrap(), Message::new("x"), Asset::default());
        let blocking = Blocking(&fake);
        assert_send(&t.send_attempts_async(&msg, &blocking, &asset));
        assert_send(&t.close_async(&blocking, &asset));
        assert_send(&Config::load_async("/nowhere", &blocking, &ConfigOptions::default()));
        assert_send(&crate::AttachmentSet::default().load_async(&blocking, &asset));
    }

    #[cfg(feature = "service-json")]
    #[test]
    fn blocking_sends_wait_for_the_shared_budget() {
        let fake = Arc::new(crate::testing::FakeTransport::new());
        fake.respond(200, "{}");
        let mut m = Mercurio::with_transport(fake);
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

    /// Apprise's escalation: the most urgent group first, the next only after a failure, every chain on its own.
    #[cfg(feature = "service-json")]
    #[test]
    fn priority_groups_escalate_only_after_a_failure() {
        use crate::testing::FakeTransport;
        let notifier = |fake: &Arc<FakeTransport>| {
            let mut m = Mercurio::with_transport(fake.clone()).sequential();
            m.add("json://localhost/a1?tag=1:ops").unwrap();
            m.add("json://localhost/a2?tag=2:ops").unwrap();
            m.add("json://localhost/b1?tag=1:db").unwrap();
            m.add("json://localhost/b2?tag=2:db").unwrap();
            m
        };
        let paths = |fake: &FakeTransport| fake.requests().iter().map(|r| r.url.clone()).collect::<Vec<_>>();

        // Both chains deliver at priority 1: priority 2 never runs.
        let fake = Arc::new(FakeTransport::new());
        fake.default_response(crate::Response::new(200, b"{}".to_vec()));
        let r =
            notifier(&fake).notify_with(&Message::new("b"), NotifyOptions::new().tags(&TagFilter::parse("ops, db")));
        assert!(r.is_success());
        assert_eq!(paths(&fake), ["http://localhost/a1", "http://localhost/b1"]);
        assert_eq!(r.entries.len(), 2);

        // ops@1 fails: ops escalates to priority 2 in the next round, db is done.
        let fake = Arc::new(FakeTransport::new());
        fake.default_response(crate::Response::new(200, b"{}".to_vec()));
        fake.on_url("/a1", crate::Response::new(500, b"{}".to_vec()));
        let r =
            notifier(&fake).notify_with(&Message::new("b"), NotifyOptions::new().tags(&TagFilter::parse("ops, db")));
        assert_eq!(paths(&fake), ["http://localhost/a1", "http://localhost/b1", "http://localhost/a2"]);
        assert!(r.is_success(), "a later group made up for a1");
        assert_eq!(r.status(), Status::Success);
        let escalated: Vec<_> = r.entries.iter().map(|e| e.escalated).collect();
        assert_eq!(escalated, [true, false, false]);
        assert_eq!(r.failures().count(), 1, "the failure is still reported");

        // Every group of a chain fails: the call fails.
        let fake = Arc::new(FakeTransport::new());
        fake.default_response(crate::Response::new(500, b"{}".to_vec()));
        let r = notifier(&fake).notify_with(&Message::new("b"), NotifyOptions::new().tags(&TagFilter::parse("ops")));
        assert_eq!(r.entries.len(), 2);
        assert!(r.entries.iter().all(|e| !e.escalated));
        assert_eq!(r.status(), Status::Failure);

        // An exact priority sends one flat round.
        let fake = Arc::new(FakeTransport::new());
        fake.default_response(crate::Response::new(200, b"{}".to_vec()));
        notifier(&fake).notify_with(&Message::new("b"), NotifyOptions::new().tags(&TagFilter::parse("2:ops")));
        assert_eq!(paths(&fake), ["http://localhost/a2"]);
    }

    #[cfg(feature = "service-json")]
    #[test]
    fn retry_suffix_overrides_the_url_retry() {
        use crate::testing::FakeTransport;
        let fake = Arc::new(FakeTransport::new());
        fake.default_response(crate::Response::new(500, b"{}".to_vec()));
        let mut m = Mercurio::with_transport(fake.clone());
        m.add("json://localhost/x?tag=ops&wait=0").unwrap();
        m.notify_with(&Message::new("b"), NotifyOptions::new().tags(&TagFilter::parse("ops:2")));
        assert_eq!(fake.requests().len(), 3, "one attempt plus two retries");
        let before = fake.requests().len();
        m.notify_with(&Message::new("b"), NotifyOptions::new().tags(&TagFilter::parse("ops")));
        assert_eq!(fake.requests().len() - before, 1, "no suffix: the URL's retry (none)");
    }

    #[test]
    fn storage_mode_decides_when_stores_reach_the_disk() {
        use crate::StorageMode;
        use crate::testing::FakeTransport;

        /// Saves an entry, sends, saves another, sends again.
        #[derive(Debug)]
        struct Saver;
        impl Notify for Saver {
            fn plan(&self, _: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
                let store = ctx.store();
                store.set("a", serde_json::json!(1), None);
                let second = ctx.post("http://localhost/second");
                Plan::http(ctx.post("http://localhost/first"), move |_| {
                    store.set("b", serde_json::json!(2), None);
                    Plan::send(second)
                })
            }
        }
        static SAVER: ServiceDef = ServiceDef {
            id: "saver_test",
            name: "Saver",
            schemes: &["savertest"],
            parse: |_| Ok(Box::new(Saver)),
            ..ServiceDef::DEFAULTS
        };

        // Flush writes before the second request and is then clean; auto writes once at the end; memory never.
        for (mode, writes) in [(StorageMode::Flush, 2), (StorageMode::Auto, 1), (StorageMode::Memory, 0)] {
            let fake = Arc::new(FakeTransport::new());
            fake.default_response(crate::Response::new(200, b"{}".to_vec()));
            let asset = Asset { storage_mode: mode, ..Asset::default() }.with_storage("/data");
            let mut m = Mercurio::with_transport(fake.clone()).asset(asset);
            m.registry_mut().register(&SAVER).unwrap();
            m.add("savertest://host/x").unwrap();
            assert!(m.notify(&Message::new("b")).is_success());
            let written = fake
                .file_ops()
                .iter()
                .filter(|op| matches!(op, FileOp::WriteAtomic { path, .. } if path.ends_with("cache.json")))
                .count();
            assert_eq!(written, writes, "{mode:?}");
            assert_eq!(fake.requests().len(), 2);
        }
    }

    #[cfg(feature = "service-json")]
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

        for sequential in [false, true] {
            let fake = Arc::new(FakeTransport::new());
            fake.default_response(crate::Response::new(200, b"{}".to_vec()));
            let mut m = Mercurio::with_transport(fake.clone());
            if sequential {
                m = m.sequential();
            }
            m.registry_mut().register(&THROTTLED).unwrap();
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

    #[cfg(feature = "service-json")]
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

    #[cfg(feature = "service-json")]
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

    #[cfg(feature = "service-json")]
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

    #[cfg(feature = "service-json")]
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

    #[cfg(feature = "service-sendpulse")]
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
    /// The clock of [`first_error`]'s transport.
    const NOW: u64 = 1_700_000_000;

    fn first_error(url: &str, replies: Vec<crate::Response>) -> crate::ErrorClass {
        let fake = crate::testing::FakeTransport::new().with_env(crate::testing::FixedEnv::new(NOW));
        for r in replies {
            fake.respond_with(r);
        }
        let t = parse(url).unwrap();
        let d = t.send(&Message::new("b").title("t"), &fake, &Asset::default());
        d.outcomes.into_iter().find_map(|o| o.result.err()).expect("a failure").class()
    }

    #[cfg(all(feature = "service-discord", feature = "service-pushbullet"))]
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
        let reset = (NOW + 30).to_string();
        let bucket = || {
            Response::new(429, "slow")
                .with_header("X-RateLimit-Remaining", "1")
                .with_header("X-RateLimit-Reset", &reset)
        };
        let class = first_error("discord://1234/abcd", vec![bucket(), bucket()]);
        let ErrorClass::RateLimited { retry_after: Some(d) } = class else { panic!("{class:?}") };
        assert_eq!(d.as_secs(), 40, "{d:?}");
    }
}
