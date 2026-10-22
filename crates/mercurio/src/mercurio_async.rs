//! [`AsyncMercurio`]: the notifier on an [`AsyncTransport`].

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use futures_util::future::join_all;

use crate::config::template::TemplateVars;
use crate::config::{Config, ConfigFormat, ConfigOptions, PendingTarget};
use crate::error::{Error, Result};
use crate::notify::{Core, Escalation, Mercurio, NotifyOptions, SEND_PERMITS, Selection, lanes, throttle_wait};
use crate::report::{Report, ReportEntry};
use crate::target::Target;
use crate::transport::{AsyncTransport, Blocking};
use crate::{Asset, Message, Registry, TagFilter};

/// A set of notification targets sending through an [`AsyncTransport`].
///
/// It works on any async runtime and spawns nothing: the targets of one `notify` call run concurrently inside the calling task (a lane per target, or per throttled service), at most 128 sends at once across the process. One call therefore runs on one thread; to spread CPU-heavy fan-out (thousands of TLS handshakes) over several cores, spawn several calls. Every returned future is `Send`.
///
/// ```
/// use std::sync::Arc;
/// use mercurio::testing::FakeTransport;
/// use mercurio::{AsyncMercurio, transport::Blocking, Message};
///
/// let fake = Arc::new(FakeTransport::new());
/// let mut m = AsyncMercurio::with_transport(Arc::new(Blocking(fake.clone())));
/// m.add("json://localhost/hook")?;
/// let report = pollster::block_on(m.notify(&Message::new("Backup finished")));
/// assert!(report.is_success());
/// # Ok::<(), mercurio::Error>(())
/// ```
pub struct AsyncMercurio {
    core: Core,
    transport: Arc<dyn AsyncTransport>,
    sequential: bool,
    closed: bool,
}

impl fmt::Debug for AsyncMercurio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncMercurio")
            .field("targets", &self.core.targets.len())
            .field("pending", &self.core.pending.len())
            .finish()
    }
}

#[cfg(feature = "transport-tokio")]
impl Default for AsyncMercurio {
    fn default() -> Self {
        Self::new()
    }
}

/// `close` can not run on drop (it is async): a target that sent something keeps its session.
impl Drop for AsyncMercurio {
    fn drop(&mut self) {
        if !self.closed && self.core.targets.iter().any(Target::has_sent) {
            log::debug!("AsyncMercurio dropped without close(); sessions were not cleaned up");
        }
    }
}

/// Moves the targets and settings over; the blocking transport keeps doing the I/O (see [`Blocking`]).
impl From<Mercurio> for AsyncMercurio {
    fn from(m: Mercurio) -> Self {
        let sequential = m.sequential;
        let (core, transport) = m.into_parts();
        Self { core, transport: Arc::new(Blocking(transport)), sequential, closed: false }
    }
}

impl AsyncMercurio {
    /// A notifier on [`crate::TokioTransport`] and the default [`Asset`].
    #[cfg(feature = "transport-tokio")]
    pub fn new() -> Self {
        Self::with_transport(Arc::new(crate::TokioTransport::new()))
    }

    /// A notifier using `transport` for all I/O.
    pub fn with_transport(transport: Arc<dyn AsyncTransport>) -> Self {
        Self { core: Core::default(), transport, sequential: false, closed: false }
    }

    /// Send to targets one after another instead of concurrently.
    #[must_use]
    pub fn sequential(mut self) -> Self {
        self.sequential = true;
        self
    }

    /// Replace the [`Asset`] (branding, pipeline defaults, storage).
    #[must_use]
    pub fn asset(mut self, asset: Asset) -> Self {
        self.core.asset = asset;
        self
    }

    /// Options for [`AsyncMercurio::add_config`] (include depth, templates, ...). `opts.registry` replaces this notifier's [`Registry`].
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

    /// Load a configuration file or URL (path, `file://`, `http(s)://`) through the transport and add its services. Returns the number of services added.
    pub async fn add_config(&mut self, source: &str) -> Result<usize> {
        let cfg = Config::load_async(source, self.transport.as_ref(), &self.core.config).await?;
        Ok(self.core.add_loaded(cfg))
    }

    /// Add configuration text (TEXT or YAML; detected when `format` is `None`). Includes are read through the transport.
    pub async fn add_config_text(&mut self, content: &str, format: Option<ConfigFormat>) -> Result<usize> {
        let cfg = Config::from_text_async(content, format, self.transport.as_ref(), &self.core.config).await?;
        Ok(self.core.add_loaded(cfg))
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

    /// No targets and no template entries.
    pub fn is_empty(&self) -> bool {
        self.core.len() == 0
    }

    /// Targets matching `filter`, with matching template entries built from `vars` (see [`Mercurio::select`]).
    pub fn select(&self, filter: &TagFilter, vars: &TemplateVars) -> Selection<'_> {
        self.core.select(filter, vars)
    }

    /// Send `msg` to every target (see [`Mercurio::notify`]).
    pub async fn notify(&self, msg: &Message) -> Report {
        self.notify_with(msg, NotifyOptions::new()).await
    }

    /// Send `msg` with [`NotifyOptions`]: a tag filter, template values, a progress callback (see [`Mercurio::notify_with`]).
    pub async fn notify_with(&self, msg: &Message, opts: NotifyOptions<'_>) -> Report {
        let (all, none) = (TagFilter::all(), TemplateVars::new());
        let filter = opts.filter.unwrap_or(&all);
        let vars = opts.vars.unwrap_or(&none);
        let on_entry = opts.on_entry.unwrap_or(&|_| {});
        self.send_selected(msg, filter, vars, on_entry).await
    }

    async fn send_selected(
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
            let entries = self.send_all(msg, round.iter().map(|&i| targets[i]).collect(), filter, on_entry).await;
            let delivered: BTreeMap<usize, bool> =
                round.iter().copied().zip(entries.iter().map(|e| e.delivery.is_success())).collect();
            esc.settle(|i| delivered.get(&i).copied().unwrap_or(false));
            sent.extend(round.into_iter().zip(entries));
        }
        let entries = Core::in_order(&esc, sent);
        for t in &sel.resolved {
            t.close_async(self.transport.as_ref(), &self.core.asset_for(t)).await;
        }
        let sent = entries.len();
        let report = Core::report(entries, sel.unresolved);
        for entry in &report.entries[sent..] {
            on_entry(entry);
        }
        report
    }

    /// Run every target's clean-up (log out, revoke tokens). Call it before dropping a notifier whose targets keep sessions.
    pub async fn close(&mut self) {
        for t in &self.core.targets {
            t.close_async(self.transport.as_ref(), &self.core.asset_for(t)).await;
        }
        self.closed = true;
    }

    async fn send_all(
        &self,
        msg: &Message,
        targets: Vec<&Target>,
        filter: &TagFilter,
        on_entry: &(dyn Fn(&ReportEntry) + Sync),
    ) -> Vec<ReportEntry> {
        let (transport, targets) = (self.transport.as_ref(), &targets);
        let lanes = if self.sequential { vec![(0..targets.len()).collect()] } else { lanes(targets) };
        let lanes = lanes.into_iter().map(|lane: Vec<usize>| async move {
            let _permit = SEND_PERMITS.acquire().await;
            let mut last: BTreeMap<&str, Instant> = BTreeMap::new();
            let mut done = Vec::with_capacity(lane.len());
            for i in lane {
                let t = targets[i];
                if let Some(gap) = throttle_wait(t, last.get(t.def.id).copied()) {
                    transport.sleep(gap).await;
                }
                let retry = filter.retry_for(t.tag_set()).map(|r| u32::try_from(r).unwrap_or(u32::MAX));
                let attempts = t.send_attempts_with_retry(msg, transport, &self.core.asset_for(t), retry).await;
                let entry = self.core.entry(t, attempts);
                on_entry(&entry);
                done.push((i, entry));
                last.insert(t.def.id, Instant::now());
            }
            done
        });
        let mut done: Vec<(usize, ReportEntry)> = join_all(lanes).await.into_iter().flatten().collect();
        done.sort_by_key(|(i, _)| *i);
        done.into_iter().map(|(_, entry)| entry).collect()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::service::{Context, Notify, ServiceDef};
    use crate::testing::FakeTransport;
    use crate::{Plan, Prepared};

    fn notifier(fake: &Arc<FakeTransport>) -> AsyncMercurio {
        AsyncMercurio::with_transport(Arc::new(Blocking(fake.clone())))
    }

    #[test]
    fn lanes_keep_target_order_and_throttle_waits() {
        #[derive(Debug)]
        struct Throttled;
        impl Notify for Throttled {
            fn plan(&self, _: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
                Plan::send(ctx.post("http://localhost/throttled"))
            }
        }
        static THROTTLED: ServiceDef = ServiceDef {
            id: "throttled_async_test",
            name: "Throttled",
            schemes: &["throttledasynctest"],
            parse: |_| Ok(Box::new(Throttled)),
            throttle: Duration::from_secs(5),
            ..ServiceDef::DEFAULTS
        };
        let fake = Arc::new(FakeTransport::new());
        let mut m = notifier(&fake);
        m.registry_mut().register(&THROTTLED).unwrap();
        for i in 0..3 {
            m.add(&format!("throttledasynctest://t{i}")).unwrap();
            m.add(&format!("json://localhost/t{i}/")).unwrap();
        }
        let report = pollster::block_on(m.notify(&Message::new("b")));
        assert!(report.is_success());
        let services: Vec<_> = report.entries.iter().map(|e| e.service).collect();
        assert_eq!(services, ["throttled_async_test", "json"].repeat(3));
        assert_eq!(fake.requests().len(), 6);
        let sleeps = fake.sleeps();
        assert_eq!(sleeps.len(), 2);
        assert!(sleeps.iter().all(|d| *d > Duration::from_secs(4)), "{sleeps:?}");
    }

    #[test]
    fn conversion_keeps_targets_and_settings() {
        let fake = Arc::new(FakeTransport::new());
        let mut sync = Mercurio::with_transport(fake.clone());
        sync.add("json://localhost/a").unwrap();
        sync.add("json://localhost/b").unwrap();
        let m = AsyncMercurio::from(sync);
        assert_eq!(m.len(), 2);
        let report = pollster::block_on(m.notify(&Message::new("hi")));
        assert!(report.is_success());
        let urls: Vec<_> = fake.requests().iter().map(|r| r.url.clone()).collect();
        assert_eq!(urls, ["http://localhost/a", "http://localhost/b"]);
        assert!(!m.sequential);
        assert!(AsyncMercurio::from(Mercurio::with_transport(fake).sequential()).sequential);
    }

    #[test]
    fn progress_sees_every_entry_once() {
        let fake = Arc::new(FakeTransport::new());
        fake.on_url("/b", crate::Response::new(500, b"{}".to_vec()));
        let yaml = "version: 1\ntemplate:\n  - missing\nurls:\n  - json://localhost/a\n  - json://localhost/b\n  - json://localhost/${MISSING}\n";
        let seen = std::sync::Mutex::new(Vec::new());
        let record = |e: &ReportEntry| seen.lock().unwrap().push((e.label.clone(), e.delivery.is_success()));

        let mut m = notifier(&fake);
        pollster::block_on(m.add_config_text(yaml, None)).unwrap();
        let report = pollster::block_on(m.notify_with(&Message::new("b"), NotifyOptions::new().on_entry(&record)));
        let mut blocking = Mercurio::with_transport(fake);
        blocking.add_config_text(yaml, None).unwrap();
        let report2 = blocking.notify_with(&Message::new("b"), NotifyOptions::new().on_entry(&record));

        let seen = seen.into_inner().unwrap();
        assert_eq!(seen.len(), 6, "{seen:?}");
        for (half, report) in [(&seen[..3], &report), (&seen[3..], &report2)] {
            let labels: Vec<_> = report.entries.iter().map(|e| e.label.clone()).collect();
            let mut got: Vec<_> = half.iter().map(|(l, _)| l.clone()).collect();
            // Sent entries arrive as they finish; the unresolved one is last.
            assert_eq!(got.last(), labels.last());
            got.sort();
            let mut want = labels;
            want.sort();
            assert_eq!(got, want);
            assert_eq!(half.iter().filter(|(_, ok)| *ok).count(), 1);
        }
    }

    #[test]
    fn same_api_as_the_blocking_notifier() {
        let fake = Arc::new(FakeTransport::new());
        let mut m = notifier(&fake);
        m.registry_mut()
            .register_scheme("asyncparity", |msg, _| {
                Plan::send(crate::Request::post(format!("http://localhost/{}", msg.body)))
            })
            .unwrap();
        m.add("asyncparity://x").unwrap();
        m.add("json://localhost/dropped").unwrap();
        m.retain(|t| t.service().id != "json");
        let report = pollster::block_on(m.notify(&Message::new("kept")));
        assert!(report.is_success());
        let urls: Vec<_> = fake.requests().iter().map(|r| r.url.clone()).collect();
        assert_eq!(urls, ["http://localhost/kept"]);
    }
}
