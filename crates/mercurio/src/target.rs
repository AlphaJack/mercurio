//! [`Target`]: a parsed URL bound to its service, and its delivery with `?retry=` / `?wait=` handling.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant};

use crate::asset::Asset;
use crate::config::{AssetValue, Config};
use crate::error::{Error, ErrorClass, Result};
use crate::message::{Message, NotifyFormat, OverflowMode, Prepared};
use crate::plan::{Delivery, DeliveryTracker, ExecOptions, Executor, Outcome, Plan, read_files, run_files};
use crate::prepare::{PipelineOptions, PreparedMessage};
use crate::report::Attempt;
use crate::service::{Context, Notify, ServiceDef, UrlIdentifier};
use crate::store::{Memo, PersistentStore, StoreRef};
use crate::tag::Tag;
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
/// Longest `?wait=` in seconds (Apprise's `APPRISE_MAX_SERVICE_WAIT`).
const MAX_WAIT: f64 = 20.0;

/// A parsed URL bound to its service, ready to send.
pub struct Target {
    pub(crate) def: &'static ServiceDef,
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
    pub(crate) fn effective_asset(&self, base: &Asset) -> Option<Asset> {
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
