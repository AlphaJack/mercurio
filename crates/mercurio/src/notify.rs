//! High-level API: parse URLs into [`Target`]s and fan a [`Message`] out.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Condvar, LazyLock, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use crate::asset::Asset;
#[cfg(feature = "transport-blocking")]
use crate::blocking::BlockingTransport;
use crate::config::template::TemplateVars;
use crate::config::{AssetValue, Config, ConfigFormat, ConfigOptions, ConfigService, PendingTarget};
use crate::error::{Error, ErrorClass, Result};
use crate::message::{Message, NotifyFormat, OverflowMode, Prepared};
use crate::plan::{Delivery, DeliveryTracker, ExecOptions, Executor, Outcome, Plan, read_files, run_files};
use crate::prepare::{PipelineOptions, PreparedMessage};
use crate::service::{Context, Notify, ServiceDef, UrlIdentifier};
use crate::store::{Memo, PersistentStore, StoreRef};
use crate::tag::{Tag, TagFilter};
use crate::transport::{AsyncTransport, Blocking, Transport};
use crate::url::{ParseOptions, ParsedUrl, parse_url_with, scheme_of};

/// Every service compiled into this build (services added at runtime with [`crate::register`] are not listed).
pub fn services() -> &'static [&'static ServiceDef] {
    crate::services::ALL
}

/// The service handling `scheme`: compiled-in services first, then those registered at runtime ([`crate::register`], [`crate::register_scheme`]).
pub fn service_for_scheme(scheme: &str) -> Option<&'static ServiceDef> {
    // Compiled-in schemes by ASCII-lowercased name; the first service listing a scheme wins, as with a scan of `services()`.
    static BY_SCHEME: LazyLock<BTreeMap<String, &'static ServiceDef>> = LazyLock::new(|| {
        let mut map = BTreeMap::new();
        for def in services() {
            for s in def.schemes {
                map.entry(s.to_ascii_lowercase()).or_insert(*def);
            }
        }
        map
    });
    // `handles` compares ignoring ASCII case.
    let found = if scheme.bytes().any(|b| b.is_ascii_uppercase()) {
        BY_SCHEME.get(&scheme.to_ascii_lowercase())
    } else {
        BY_SCHEME.get(scheme)
    };
    found.copied().or_else(|| crate::registry::lookup(scheme))
}

/// Longest `Retry-After` a `?retry=` loop waits for; longer requests end the retries instead of blocking the caller.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);
/// Most extra attempts `?retry=` asks for.
const MAX_RETRY: u32 = 10;
/// Seconds between attempts without `?wait=`.
const DEFAULT_WAIT: f64 = 0.5;
/// Longest `?wait=` in seconds.
const MAX_WAIT: f64 = 60.0;

/// A parsed URL bound to its service, ready to send.
pub struct Target {
    def: &'static ServiceDef,
    service: Box<dyn Notify>,
    format_override: Option<NotifyFormat>,
    overflow: OverflowMode,
    exec: ExecOptions,
    /// The URL sets `?redirect=`, which wins over [`Asset::http_redirects`].
    redirect_set: bool,
    retry: u32,
    wait: Duration,
    scheme: String,
    tags: Vec<String>,
    tag_set: Vec<Tag>,
    url: String,
    asset_overrides: Option<Arc<Vec<(String, AssetValue)>>>,
    storage: Box<Storage>,
}

#[derive(Debug)]
struct Storage {
    /// Bytes hashed (with the asset salt) into the URL id; `None`: no id.
    id_material: Option<Vec<u8>>,
    /// `?store=no` keeps this target's store in memory.
    persistent: bool,
    store: OnceLock<StoreRef>,
}

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Target").field("service", &self.def.id).field("config", &self.service).finish()
    }
}

/// Parse a service URL into a [`Target`].
pub fn parse(url: &str) -> Result<Target> {
    // `/#channel` is a literal '#', not a fragment.
    let url = url.replace("/#", "/%23");
    let scheme = scheme_of(&url).ok_or_else(|| Error::InvalidUrl(crate::plan::redact_url(&url)))?;
    if let Some(def) = service_for_scheme(&scheme) {
        return build(def, &url);
    }
    for def in services().iter().copied().chain(crate::registry::registered()) {
        if let Some(native) = def.parse_native
            && let Some(mapped) = native(&url)
        {
            let mapped = mapped.replace("/#", "/%23");
            let scheme = scheme_of(&mapped).unwrap_or_default();
            let target_def = service_for_scheme(&scheme).unwrap_or(def);
            return build(target_def, &mapped);
        }
    }
    Err(Error::UnknownScheme(scheme))
}

fn build(def: &'static ServiceDef, url: &str) -> Result<Target> {
    let opts = ParseOptions { verify_host: false, ..Default::default() };
    let parsed = parse_url_with(url, opts).ok_or_else(|| Error::InvalidUrl(format!("{}://...", def.schemes[0])))?;
    let service = (def.parse)(&parsed)?;
    Ok(Target::new(def, service, &parsed))
}

impl Target {
    /// Wrap an already-built service with URL-level options from `parsed`.
    pub fn new(def: &'static ServiceDef, service: Box<dyn Notify>, parsed: &ParsedUrl) -> Self {
        let id_material = match service.url_identifier() {
            UrlIdentifier::Disabled => None,
            UrlIdentifier::Parts(parts) => Some(parts.concat().into_bytes()),
            UrlIdentifier::Default => Some(default_url_identifier(parsed)),
        };
        Target {
            storage: Box::new(Storage {
                id_material,
                persistent: parsed.param("store").is_none_or(|v| crate::parse::parse_bool(v, true)),
                store: OnceLock::new(),
            }),
            def,
            service,
            format_override: parsed.format,
            overflow: parsed.overflow.unwrap_or_default(),
            exec: ExecOptions {
                verify_tls: parsed.verify,
                follow_redirects: parsed.redirect,
                connect_timeout: parsed.cto.filter(|v| *v > 0.0).map(Duration::from_secs_f64),
                read_timeout: parsed.rto.filter(|v| *v > 0.0).map(Duration::from_secs_f64),
                throttle: def.throttle,
            },
            redirect_set: parsed.query.get("redirect").is_some(),
            retry: parsed.retry.unwrap_or(0).min(MAX_RETRY),
            wait: Duration::from_secs_f64(parsed.wait.unwrap_or(DEFAULT_WAIT).clamp(0.0, MAX_WAIT)),
            scheme: parsed.scheme.clone(),
            tags: Vec::new(),
            tag_set: Vec::new(),
            url: parsed.original.clone(),
            asset_overrides: None,
        }
        .with_tags(parsed.param("tag").map(|t| crate::parse::parse_list([t])).unwrap_or_default())
    }

    /// The service definition behind this target.
    pub fn service(&self) -> &'static ServiceDef {
        self.def
    }

    /// The configured service instance.
    pub fn config(&self) -> &dyn Notify {
        self.service.as_ref()
    }

    /// Tags from `?tag=` (or a config file line); used for routing.
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Add routing tags (deduplicated, sorted, lower-cased).
    pub fn with_tags<I: IntoIterator<Item = S>, S: Into<String>>(self, tags: I) -> Self {
        let parsed: Vec<Tag> = tags.into_iter().map(|t| Tag::parse(&t.into())).collect();
        self.with_tag_set(parsed)
    }

    /// Add parsed tags (keeps priorities such as `2:endpoint`).
    pub fn with_tag_set(mut self, tags: impl IntoIterator<Item = Tag>) -> Self {
        for t in tags {
            if !t.name.is_empty() && !self.tag_set.contains(&t) {
                self.tag_set.push(t);
            }
        }
        self.tag_set.sort_by(|a, b| a.name.cmp(&b.name));
        self.tags = self.tag_set.iter().map(|t| t.name.clone()).collect();
        self
    }

    /// Tags with their priority metadata.
    pub fn tag_set(&self) -> &[Tag] {
        &self.tag_set
    }

    /// The URL this target was built from. Contains secrets: never log it; use [`Target::label`] or [`crate::plan::redact_url`].
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Use configuration `asset:` overrides for this target.
    pub fn set_asset_overrides(&mut self, overrides: Vec<(String, AssetValue)>) {
        self.asset_overrides = if overrides.is_empty() { None } else { Some(Arc::new(overrides)) };
    }

    /// The asset this target sends with, given the notifier's base asset.
    fn effective_asset(&self, base: &Asset) -> Option<Asset> {
        let ov = self.asset_overrides.as_ref()?;
        let cfg = Config { asset: ov.as_ref().clone(), ..Config::default() };
        Some(cfg.asset_for(base))
    }

    /// The URL's settings, with the asset's redirect default unless the URL sets `?redirect=`.
    fn exec_for(&self, asset: &Asset) -> ExecOptions {
        let mut exec = self.exec;
        if !self.redirect_set {
            exec.follow_redirects = asset.http_redirects;
        }
        exec
    }

    /// Scheme plus service name; never includes credentials.
    pub fn label(&self) -> String {
        format!("{}:// ({})", self.scheme, self.def.name)
    }

    /// Run the message pipeline (payload cap, escapes, conversion, title merging, overflow) without planning anything.
    pub fn prepare(&self, msg: &Message, asset: &Asset) -> Result<PreparedMessage> {
        self.prepare_in(msg, &Context::new(asset, self.store(asset), &Memo::disabled()))
    }

    fn prepare_in(&self, msg: &Message, ctx: &Context<'_>) -> Result<PreparedMessage> {
        let opts = PipelineOptions { format_override: self.format_override, overflow: self.overflow };
        crate::prepare::prepare(self.def, self.service.as_ref(), opts, msg, ctx)
    }

    fn piece<'a>(&self, prep: &'a PreparedMessage, msg: &'a Message, index: usize) -> Prepared<'a> {
        let piece = &prep.pieces[index];
        let attachments: &[crate::message::Attachment] = if !piece.attach {
            &[]
        } else if prep.first_attachment_only {
            &msg.attachments[..1]
        } else {
            &msg.attachments
        };
        Prepared {
            title: &piece.title,
            body: &piece.body,
            kind: msg.kind,
            format: prep.format,
            passthrough: prep.input_format.is_none(),
            input_format: prep.input_format,
            attachments,
            message: msg,
            index,
            total: prep.pieces.len(),
        }
    }

    /// URL id: the first 8 hex characters of a SHA-256 of the URL's identifying parts. Names the store.
    pub fn url_id(&self, _asset: &Asset) -> Option<String> {
        let material = self.storage.id_material.as_ref()?;
        let mut id = crate::crypto::hex(&crate::crypto::sha256(material));
        id.truncate(8);
        Some(id)
    }

    /// Whether a send created this target's store (closing it then has something to clean up).
    pub(crate) fn has_sent(&self) -> bool {
        self.storage.store.get().is_some()
    }

    /// `false` when the URL has `?store=no`.
    pub fn persistent_storage(&self) -> bool {
        self.storage.persistent
    }

    /// This target's store, created on first use under `asset.storage_path`. It lives as long as the target.
    pub fn store(&self, asset: &Asset) -> &StoreRef {
        self.storage.store.get_or_init(|| {
            let id = self.url_id(asset);
            let path = asset.storage_path.as_deref().filter(|_| id.is_some() && self.storage.persistent);
            PersistentStore::new(path, id.as_deref().unwrap_or("default")).shared()
        })
    }

    /// Use `store` instead of the built-in one (call before the first send).
    pub fn with_store(self, store: StoreRef) -> Self {
        self.storage.store.set(store).ok();
        self
    }

    /// Plan and execute delivery of `msg` (the last attempt's outcomes).
    pub fn send(&self, msg: &Message, transport: &dyn Transport, asset: &Asset) -> Delivery {
        self.deliver(msg, transport, asset).pop().map(|a| a.delivery).unwrap_or_default()
    }

    /// Plan and execute delivery of `msg`, returning every attempt.
    ///
    /// With `?retry=N`, failed attempts are repeated after `?wait=`; message pieces and targets (`Plan::Target`) that an earlier attempt delivered are skipped and reported as delivered.
    pub fn deliver(&self, msg: &Message, transport: &dyn Transport, asset: &Asset) -> Vec<Attempt> {
        pollster::block_on(self.deliver_async(msg, &Blocking(transport), asset))
    }

    /// [`Target::deliver`] on an [`AsyncTransport`].
    pub async fn deliver_async(&self, msg: &Message, transport: &dyn AsyncTransport, asset: &Asset) -> Vec<Attempt> {
        let started = Instant::now();
        let store = self.store(asset);
        let memo = if self.retry > 0 { Memo::enabled() } else { Memo::disabled() };
        let ctx = Context::new(asset, store, &memo);
        let stores = self.stores(&ctx);
        for s in &stores {
            run_files(s.clone().load(), transport).await;
        }
        let prep = match self.prepare_in(msg, &ctx) {
            Ok(p) => p,
            Err(e) => {
                let delivery = Delivery { outcomes: vec![Outcome { target: None, result: Err(e) }] };
                return vec![Attempt::new(delivery, started)];
            }
        };
        let mut tracker = DeliveryTracker::new();
        let mut attempts = Vec::new();
        loop {
            let started = Instant::now();
            let mut ex = Executor::new(transport, self.exec_for(asset)).with_stores(stores.clone());
            if self.retry > 0 {
                ex = ex.with_tracker(&mut tracker);
            }
            // Pieces of a split message go out in order; stop if one fails. Each piece is planned when the previous one is done, so it sees what that piece stored.
            let mut ok = true;
            for index in 0..prep.pieces.len() {
                ex.set_piece(index);
                if ex.piece_delivered() {
                    log::debug!("{}: piece {} already accepted; skipping", self.def.name, index + 1);
                    continue;
                }
                let prepared = self.piece(&prep, msg, index);
                let plan = self.plan_piece(&prepared, &ctx, transport).await;
                if !ex.run(plan).await {
                    ok = false;
                    break;
                }
            }
            let delivery = ex.finish(ok).await;
            let done = delivery.is_success();
            attempts.push(Attempt::new(delivery, started));
            if done || attempts.len() > self.retry as usize {
                break;
            }
            let Some(wait) = self.retry_wait(&attempts[attempts.len() - 1].delivery) else {
                break;
            };
            log::warn!("{}: attempt {}/{} failed; trying again", self.def.name, attempts.len(), self.retry + 1);
            transport.sleep(wait).await;
        }
        attempts
    }

    /// The target's store and those its service opens.
    fn stores(&self, ctx: &Context<'_>) -> Vec<StoreRef> {
        let mut stores = vec![ctx.store()];
        stores.extend(self.service.stores(ctx));
        stores
    }

    /// The service's plan for one piece, after running the file reads it asks for.
    async fn plan_piece(&self, msg: &Prepared<'_>, ctx: &Context<'_>, transport: &dyn AsyncTransport) -> Plan {
        let files = read_files(self.service.files(ctx), transport).await;
        self.service.plan(msg, &ctx.with_files(&files))
    }

    /// The pause before retrying a failed attempt. `None` means stop: either some failure is not retryable ([`ErrorClass::is_retryable`]) or the service asked to wait longer than [`MAX_RETRY_AFTER`].
    fn retry_wait(&self, failed: &Delivery) -> Option<Duration> {
        let mut retry_after = None;
        for e in failed.errors() {
            match e.class() {
                ErrorClass::RateLimited { retry_after: ra } => retry_after = retry_after.max(ra),
                ErrorClass::Transient => {}
                class @ (ErrorClass::Auth | ErrorClass::InvalidTarget | ErrorClass::Unknown) => {
                    log::warn!("{}: not retrying ({class}): {e}", self.def.name);
                    return None;
                }
            }
        }
        if let Some(ra) = retry_after.filter(|ra| *ra > MAX_RETRY_AFTER) {
            log::warn!("{}: not retrying; the service asked to wait {}s", self.def.name, ra.as_secs());
            return None;
        }
        Some(self.wait.max(retry_after.unwrap_or_default()))
    }

    /// Run the service's clean-up (log out, revoke a token) if this target has sent something. Returns its outcome; `None` when there was nothing to do. Later sends start a new session.
    pub fn close(&self, transport: &dyn Transport, asset: &Asset) -> Option<Delivery> {
        pollster::block_on(self.close_async(&Blocking(transport), asset))
    }

    /// [`Target::close`] on an [`AsyncTransport`].
    pub async fn close_async(&self, transport: &dyn AsyncTransport, asset: &Asset) -> Option<Delivery> {
        let store = self.storage.store.get()?;
        let memo = Memo::disabled();
        let ctx = Context::new(asset, store, &memo);
        let plan = self.service.close(&ctx)?;
        let mut ex = Executor::new(transport, self.exec_for(asset)).with_stores(self.stores(&ctx));
        let ok = ex.run(plan).await;
        Some(ex.finish(ok).await)
    }

    /// Build the plan for the first piece without executing it (for inspection).
    pub fn plan(&self, msg: &Message, asset: &Asset) -> Result<Plan> {
        let memo = Memo::disabled();
        let ctx = Context::new(asset, self.store(asset), &memo);
        let prep = self.prepare_in(msg, &ctx)?;
        Ok(self.service.plan(&self.piece(&prep, msg, 0), &ctx))
    }
}

/// Store namespace input for URLs without a custom identifier:
/// Scheme, password, user, host, port (a NUL byte when absent), path without trailing `/`, then `s`/`i` for secure/insecure.
fn default_url_identifier(p: &ParsedUrl) -> Vec<u8> {
    let mut out = p.scheme.to_lowercase().into_bytes();
    let mut push = |v: Option<String>| match v {
        Some(v) => out.extend_from_slice(v.as_bytes()),
        None => out.push(0),
    };
    push(p.password());
    push(p.user());
    push(Some(p.host()).filter(|h| !h.is_empty()));
    push(p.port.map(|n| n.to_string()));
    let path = crate::url::unquote(p.fullpath.as_deref().filter(|f| !f.is_empty()).unwrap_or("/"));
    out.extend_from_slice(path.trim_end_matches('/').as_bytes());
    out.push(if p.secure { b's' } else { b'i' });
    out
}

/// Overall outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    /// Everything was delivered.
    Success,
    /// Some deliveries worked, others failed.
    Partial,
    /// Nothing was delivered.
    Failure,
    /// There was nothing to notify.
    NoMatch,
    /// Nothing was delivered and every failure was a timeout.
    Timeout,
}

impl Status {
    /// Lower-case name: `success`, `partial`, `failure`, `nomatch` or `timeout`.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Success => "success",
            Status::Partial => "partial",
            Status::Failure => "failure",
            Status::NoMatch => "nomatch",
            Status::Timeout => "timeout",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One delivery attempt of one URL.
#[derive(Debug, Clone)]
pub struct Attempt {
    /// What happened to each target in this attempt.
    pub delivery: Delivery,
    /// Time the attempt took.
    pub elapsed: Duration,
}

impl Attempt {
    fn new(delivery: Delivery, started: Instant) -> Self {
        Self { delivery, elapsed: started.elapsed() }
    }

    /// `Success`, `Partial` (some targets delivered), `Timeout` (every failure timed out) or `Failure`.
    pub fn status(&self) -> Status {
        if self.delivery.is_success() {
            Status::Success
        } else if self.delivery.outcomes.iter().any(|o| o.result.is_ok()) {
            Status::Partial
        } else if self.delivery.errors().all(Error::is_timeout) {
            Status::Timeout
        } else {
            Status::Failure
        }
    }
}

/// Result of [`Mercurio::notify`]: one entry per URL.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// One entry per URL notified, in the order they were added.
    pub entries: Vec<ReportEntry>,
}

/// What happened to one URL.
#[derive(Debug, Clone)]
pub struct ReportEntry {
    /// Redacted label like `tgram:// (Telegram)`.
    pub label: String,
    /// Service id ([`ServiceDef::id`]), e.g. `"telegram"`.
    pub service: &'static str,
    /// Outcome of the last attempt.
    pub delivery: Delivery,
    /// Every attempt, in order (more than one with `?retry=`).
    pub attempts: Vec<Attempt>,
    /// The URL id naming this target's persistent store.
    pub url_id: Option<String>,
}

impl ReportEntry {
    /// `Success` when the last attempt delivered everything, `Timeout` when attempts only timed out, `Failure` otherwise.
    pub fn status(&self) -> Status {
        if self.delivery.is_success() {
            return Status::Success;
        }
        let timed_out = |a: &Attempt| a.status() == Status::Timeout;
        if self.attempts.last().is_some_and(timed_out) && self.attempts.iter().all(timed_out) {
            Status::Timeout
        } else {
            Status::Failure
        }
    }
}

impl Report {
    /// `true` when every URL delivered (and there was at least one).
    pub fn is_success(&self) -> bool {
        !self.entries.is_empty() && self.entries.iter().all(|e| e.delivery.is_success())
    }

    /// Aggregate status: `Partial` when not everything worked but some attempt delivered something.
    pub fn status(&self) -> Status {
        if self.entries.is_empty() {
            return Status::NoMatch;
        }
        if self.is_success() {
            return Status::Success;
        }
        let some = self
            .entries
            .iter()
            .flat_map(|e| &e.attempts)
            .any(|a| matches!(a.status(), Status::Success | Status::Partial));
        if some {
            Status::Partial
        } else if self.entries.iter().all(|e| e.status() == Status::Timeout) {
            Status::Timeout
        } else {
            Status::Failure
        }
    }

    /// Every failed outcome, with the entry it belongs to.
    pub fn failures(&self) -> impl Iterator<Item = (&ReportEntry, &Outcome)> {
        self.entries.iter().flat_map(|e| e.delivery.outcomes.iter().filter(|o| o.result.is_err()).map(move |o| (e, o)))
    }
}

/// Most sends in progress at once across every [`Mercurio`] in the process. Targets of a service with a [`ServiceDef::throttle`] go one at a time, with the throttle between them.
const MAX_PARALLEL: usize = 128;

/// The process-wide budget of [`MAX_PARALLEL`] sends, shared so that concurrent `notify` calls (the HTTP server's requests) cannot multiply it.
static SEND_SLOTS: Slots = Slots { used: Mutex::new(0), freed: Condvar::new(), max: LazyLock::new(max_parallel) };

/// [`MAX_PARALLEL`], or `MERCURIO_BENCH_MAX_PARALLEL` (`0` = unlimited) for the benchmark harness only.
pub(crate) fn max_parallel() -> usize {
    match std::env::var("MERCURIO_BENCH_MAX_PARALLEL").ok().and_then(|v| v.parse().ok()) {
        Some(0) => usize::MAX,
        Some(n) => n,
        None => MAX_PARALLEL,
    }
}

/// A counting semaphore.
struct Slots {
    used: Mutex<usize>,
    freed: Condvar,
    max: LazyLock<usize>,
}

impl Slots {
    /// Block until a slot is free and take it; the guard gives it back.
    fn acquire(&'static self) -> SlotGuard {
        let mut used = self.used.lock().unwrap_or_else(PoisonError::into_inner);
        while *used >= *self.max {
            used = self.freed.wait(used).unwrap_or_else(PoisonError::into_inner);
        }
        *used += 1;
        SlotGuard(self)
    }
}

struct SlotGuard(&'static Slots);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        *self.0.used.lock().unwrap_or_else(PoisonError::into_inner) -= 1;
        self.0.freed.notify_one();
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
    parallel: bool,
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
        Self { core: Core::default(), transport, parallel: true }
    }

    /// Replace the [`Asset`] (branding, pipeline defaults, storage).
    pub fn asset(mut self, asset: Asset) -> Self {
        self.core.asset = asset;
        self
    }

    /// Send to targets one after another instead of in parallel threads.
    pub fn sequential(mut self) -> Self {
        self.parallel = false;
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
        if !self.parallel || targets.len() < 2 {
            let _slot = SEND_SLOTS.acquire();
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
                    let slot = SEND_SLOTS.acquire();
                    s.spawn(move || {
                        let _slot = slot;
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
    fn send_slots_block_beyond_the_budget() {
        static SLOTS: Slots = Slots { used: Mutex::new(0), freed: Condvar::new(), max: LazyLock::new(|| 2) };
        let (first, second) = (SLOTS.acquire(), SLOTS.acquire());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|s| {
            s.spawn(move || {
                let _third = SLOTS.acquire();
                tx.send(()).unwrap();
            });
            assert!(rx.recv_timeout(Duration::from_millis(100)).is_err(), "a third slot was handed out");
            drop(first);
            rx.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        drop(second);
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
