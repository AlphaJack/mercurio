//! Direct (non-webhook) delivery and everything it needs (requests, discovery, login/register/whoami, room join/create/alias lookup, direct-message rooms, media upload, logout).
//!
//! Every step is a continuation over an owned [`Session`]: a step sends one request with [`Session::fetch`] and continues with the updated session.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use super::{Config, Mode, Msg, Version};
use crate::error::Error;
use crate::http::{Method, Request, Response};
use crate::store::{Memo, StoreRef};
use crate::url::quote;
use crate::{Plan, regex};

pub(super) const V3_API: &str = "/_matrix/client/v3";
pub(super) const V2_API: &str = "/_matrix/client/r0";
pub(super) const V3_MEDIA: &str = "/_matrix/media/v3";
pub(super) const V2_MEDIA: &str = "/_matrix/media/r0";

pub(super) const CACHE_EXPIRY: Option<Duration> = Some(Duration::from_secs(60 * 60 * 24 * 20));
const DISCOVERY_CACHE: Duration = Duration::from_secs(86400);
/// For login and discovery answers.
pub(super) const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const DEFAULT_RETRIES: u32 = 2;
const DEFAULT_WAIT_MS: f64 = 1000.0;
/// Upper bound for a server-requested back-off.
const MAX_WAIT: Duration = Duration::from_secs(300);

const DISCOVERY_BASE_KEY: &str = "__discovery_base";
const DISCOVERY_IDENTITY_KEY: &str = "__discovery_identity";

/// Continuation over the session.
pub(super) type K<T> = Box<dyn FnOnce(Session, T) -> Plan + Send>;

/// Matrix transaction id: a counter; a random UUID for raw access tokens (no counter can be kept for those).
#[derive(Debug, Clone)]
pub(super) enum Txn {
    Counter(u64),
    Uuid(String),
}

impl std::fmt::Display for Txn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Txn::Counter(n) => write!(f, "{n}"),
            Txn::Uuid(u) => f.write_str(u),
        }
    }
}

/// Where a request goes.
#[derive(Debug, Clone)]
pub(super) enum Path {
    /// Client-server API path below `/_matrix/client/{v3,r0}`.
    Api(String),
    /// `POST /_matrix/media/{v3,r0}/upload`.
    Upload,
    /// Absolute URL (discovery probes).
    Url(String),
}

#[derive(Debug, Clone)]
pub(super) enum Body {
    Json(Value),
    /// No body (GETs).
    Empty,
    Raw(Arc<Vec<u8>>, String),
}

#[derive(Debug, Clone)]
pub(super) struct Fetch {
    pub method: Method,
    pub path: Path,
    pub body: Body,
    pub params: Vec<(String, String)>,
    /// Statuses that fail silently.
    pub ok_status: &'static [u16],
    pub auth: bool,
    /// The payload carries a password: no redirects.
    pub credentials: bool,
    pub max_bytes: Option<usize>,
    pub timeout: Option<Duration>,
    /// Shared 429 back-off budget.
    pub max_retry_wait: Option<Duration>,
}

impl Fetch {
    fn new(method: Method, path: Path, body: Body) -> Self {
        Fetch {
            method,
            path,
            body,
            params: Vec::new(),
            ok_status: &[],
            auth: true,
            credentials: false,
            max_bytes: None,
            timeout: None,
            max_retry_wait: None,
        }
    }
    pub fn post(path: impl Into<String>, payload: Value) -> Self {
        Self::new(Method::Post, Path::Api(path.into()), Body::Json(payload))
    }
    pub fn put(path: impl Into<String>, payload: Value) -> Self {
        Self::new(Method::Put, Path::Api(path.into()), Body::Json(payload))
    }
    pub fn get(path: impl Into<String>) -> Self {
        Self::new(Method::Get, Path::Api(path.into()), Body::Empty)
    }
    pub fn get_url(url: impl Into<String>) -> Self {
        Self::new(Method::Get, Path::Url(url.into()), Body::Empty)
    }
    pub fn upload(name: &str, mime: &str, data: Arc<Vec<u8>>) -> Self {
        let mut f = Self::new(Method::Post, Path::Upload, Body::Raw(data, mime.to_string()));
        f.params.push(("filename".into(), name.into()));
        f
    }
    pub fn param(mut self, k: &str, v: impl Into<String>) -> Self {
        self.params.push((k.into(), v.into()));
        self
    }
    #[cfg_attr(not(feature = "extra"), expect(dead_code, reason = "used by end-to-end encryption only"))]
    pub fn ok_status(mut self, s: &'static [u16]) -> Self {
        self.ok_status = s;
        self
    }
    pub fn no_auth(mut self) -> Self {
        self.auth = false;
        self
    }
    pub fn credentials(mut self) -> Self {
        self.credentials = true;
        self
    }
    pub fn bounded(mut self, max: usize) -> Self {
        self.max_bytes = Some(max);
        self
    }
    #[cfg_attr(not(feature = "extra"), expect(dead_code, reason = "used by end-to-end encryption only"))]
    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = Some(t);
        self
    }
    #[cfg_attr(not(feature = "extra"), expect(dead_code, reason = "used by end-to-end encryption only"))]
    pub fn retry_budget(mut self, t: Duration) -> Self {
        self.max_retry_wait = Some(t);
        self
    }
}

#[derive(Debug, Clone)]
pub(super) struct Fetched {
    pub ok: bool,
    pub json: Value,
    pub status: u16,
    /// The transport error when the request got no response (`status` is then a placeholder 500).
    pub transport: Option<Error>,
}

impl Fetched {
    fn fail(json: Value, status: u16) -> Self {
        Fetched { ok: false, json, status, transport: None }
    }
    /// The failure as an [`Error`]: the transport error itself, so its class survives, else the HTTP status with `reason`.
    pub fn error(&self, reason: &str) -> Error {
        match &self.transport {
            Some(e) => e.clone(),
            None => Error::Http { status: self.status, reason: reason.into() },
        }
    }
    /// The reply body when the call succeeded and the body is a JSON object.
    pub fn object(&self) -> Option<&Map<String, Value>> {
        if self.ok { self.json.as_object() } else { None }
    }
}

fn empty() -> Value {
    Value::Object(Map::new())
}

pub(super) use crate::util::json_has_value as has_value;

/// `key` as a string; `None` for other types.
pub(super) fn get_str(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

fn non_empty(s: &Option<String>) -> bool {
    s.as_deref().is_some_and(|s| !s.is_empty())
}

/// The homeserver part of a user id.
pub(super) fn hs_of(user_id: &str) -> Option<String> {
    user_id.split_once(':').map(|(_, hs)| hs.to_string())
}

/// Matrix room id / alias / user patterns.
pub(super) fn match_room_id(s: &str) -> Option<(String, Option<String>)> {
    let c = regex!(r"(?i)^\s*(?:!|&#33;|%21)([A-Za-z0-9._=-]+)(?:(?::|%3A)([A-Za-z0-9.-]+))?\s*$").captures(s)?;
    Some((c[1].to_string(), c.get(2).map(|m| m.as_str().to_string())))
}

pub(super) fn match_room_alias(s: &str) -> Option<(String, Option<String>)> {
    let c = regex!(r"(?i)^\s*(?:#|%23)?([A-Za-z0-9._=-]+)(?:(?::|%3A)([A-Za-z0-9.-]+))?\s*$").captures(s)?;
    Some((c[1].to_string(), c.get(2).map(|m| m.as_str().to_string())))
}

pub(super) fn match_user(s: &str) -> Option<(String, Option<String>)> {
    let c = regex!(r"(?i)^\s*(?:@|%40)([A-Za-z0-9._=+/-]+)(?:(?::|%3A)([A-Za-z0-9.-]+))?\s*$").captures(s)?;
    Some((c[1].to_string(), c.get(2).map(|m| m.as_str().to_string())))
}

/// Percent-encode `s`, keeping `/`.
pub(super) fn quote_path(s: &str) -> String {
    quote(s, "/")
}

/// Whether `url` is a plain `https://` URL: a valid host and port, no user info, no fragment.
pub(super) fn is_secure_http_url(url: &str) -> bool {
    if url.contains('#') {
        return false;
    }
    let Some(rest) = url.get(..8).filter(|p| p.eq_ignore_ascii_case("https://")).and_then(|_| url.get(8..)) else {
        return false;
    };
    let netloc = rest.split(['/', '?']).next().unwrap_or("");
    if netloc.contains('@') {
        return false;
    }
    let (host, port) = if let Some(stripped) = netloc.strip_prefix('[') {
        match stripped.split_once(']') {
            Some((h, p)) => (h, p.strip_prefix(':')),
            None => return false,
        }
    } else {
        match netloc.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (netloc, None),
        }
    };
    if let Some(p) = port
        && !p.is_empty()
    {
        match p.parse::<u32>() {
            Ok(n) if (1..=65535).contains(&n) && p.bytes().all(|b| b.is_ascii_digit()) => {}
            _ => return false,
        }
    }
    !host.is_empty() && crate::parse::is_hostname(&host.to_lowercase(), true, true, true).is_some()
}

/// Mutable delivery state threaded through every step.
pub(super) struct Session {
    pub cfg: Arc<Config>,
    pub msg: Arc<Msg>,
    pub store: StoreRef,
    /// Rooms that took the message in an earlier `?retry=` attempt.
    pub memo: Memo,
    pub access_token: Option<String>,
    pub user_id: Option<String>,
    pub device_id: Option<String>,
    pub home_server: Option<String>,
    pub txn: Txn,
    queue: VecDeque<(String, Value)>,
    outcomes: Vec<(String, Option<Error>)>,
    /// Plaintext attachment events, uploaded once per send.
    attachments: Option<Vec<Value>>,
    #[cfg(feature = "extra")]
    pub e2ee: super::e2ee_flow::E2ee,
}

impl Session {
    // A new session, with identity values restored from the store.
    pub fn new(cfg: Arc<Config>, msg: Arc<Msg>, store: StoreRef) -> Self {
        let mut s = Session {
            cfg,
            msg,
            store,
            memo: Memo::disabled(),
            access_token: None,
            user_id: None,
            device_id: None,
            home_server: None,
            txn: Txn::Counter(0),
            queue: VecDeque::new(),
            outcomes: Vec::new(),
            attachments: None,
            #[cfg(feature = "extra")]
            e2ee: Default::default(),
        };
        if s.cfg.mode != Mode::T2bot {
            let get = |k: &str| s.store.get(k).and_then(|v| v.as_str().map(str::to_string));
            s.home_server = get("home_server");
            s.user_id = get("user_id");
            s.access_token = get("access_token");
            s.device_id = get("device_id");
            if !non_empty(&s.home_server)
                && let Some(u) = &s.user_id
            {
                s.home_server = hs_of(u);
            }
        }
        if s.access_token.is_some() {
            let n = s.store.get("transaction_id").and_then(|v| v.as_u64()).unwrap_or(0);
            s.txn = Txn::Counter(n);
        }
        #[cfg(feature = "extra")]
        super::e2ee_flow::restore(&mut s);
        s
    }

    pub fn password(&self) -> Option<&str> {
        self.cfg.password.as_ref().map(|p| p.expose())
    }

    fn host_base(&self) -> String {
        let port = self.cfg.port.map(|p| format!(":{p}")).unwrap_or_default();
        format!("{}://{}{}", if self.cfg.secure { "https" } else { "http" }, self.cfg.host, port)
    }

    pub fn e2ee_wanted(&self) -> bool {
        cfg!(feature = "extra") && self.cfg.e2ee && self.cfg.secure
    }

    fn token_is_not_password(&self) -> bool {
        self.access_token.as_deref() != self.password()
    }

    /// Advance and persist the transaction id after an event send.
    ///
    /// A raw token gets a fresh UUID per event: reusing one for the whole send makes homeservers drop the later events as duplicates.
    pub fn bump_txn(&mut self) {
        if !self.token_is_not_password() {
            if let Txn::Uuid(u) = &mut self.txn {
                *u = crate::crypto::uuid4();
            }
            return;
        }
        if let Txn::Counter(n) = &mut self.txn {
            *n += 1;
            let n = *n;
            self.store.set("transaction_id", json!(n), CACHE_EXPIRY);
        }
    }

    pub fn api_prefix(&self) -> &'static str {
        if self.cfg.version == Version::V3 { V3_API } else { V2_API }
    }

    pub fn media_prefix(&self) -> &'static str {
        if self.cfg.version == Version::V3 { V3_MEDIA } else { V2_MEDIA }
    }

    pub fn fail_target_with(&mut self, label: impl Into<String>, error: Error) {
        self.outcomes.push((label.into(), Some(error)));
    }

    pub fn ok_target(&mut self, label: impl Into<String>) {
        let label = label.into();
        self.memo.mark_delivered(&delivery_key(&label));
        self.outcomes.push((label, None));
    }

    /// A retry skips rooms and users that already took the message.
    fn delivered(&mut self, label: &str) -> bool {
        if !self.memo.is_delivered(&delivery_key(label)) {
            return false;
        }
        self.outcomes.push((label.to_string(), None));
        true
    }

    /// `None` means discovery must run first.
    pub fn base_url(&self) -> Option<String> {
        if !(self.cfg.discovery && self.cfg.secure) {
            return Some(self.host_base());
        }
        let base = self.store.get(DISCOVERY_BASE_KEY);
        let identity = self.store.get(DISCOVERY_IDENTITY_KEY);
        if base.is_none() && identity.is_none() {
            return None;
        }
        match base {
            Some(Value::String(b)) if !b.is_empty() => Some(b),
            _ => Some(self.host_base()),
        }
    }

    /// Resolve the base URL (running discovery when needed), then `k`. `Err(())` when discovery failed.
    pub fn with_base(self, k: impl FnOnce(Session, std::result::Result<String, ()>) -> Plan + Send + 'static) -> Plan {
        match self.base_url() {
            Some(b) => k(self, Ok(b)),
            None => self.discover(Box::new(move |s, ok| {
                if ok {
                    let b = s.base_url().unwrap_or_else(|| s.host_base());
                    k(s, Ok(b))
                } else {
                    k(s, Err(()))
                }
            })),
        }
    }

    /// Send one request; returns `(ok, response, status)` to `k`.
    pub fn fetch(self, f: Fetch, k: impl FnOnce(Session, Fetched) -> Plan + Send + 'static) -> Plan {
        if let Path::Url(u) = &f.path {
            let url = u.clone();
            return self.start_attempts(f, url, Box::new(k));
        }
        self.with_base(move |s, base| match base {
            Err(()) => k(s, Fetched::fail(empty(), 500)),
            Ok(base) => {
                let url = match &f.path {
                    Path::Api(p) => format!("{base}{}{p}", s.api_prefix()),
                    Path::Upload => format!("{base}{}/upload", s.media_prefix()),
                    Path::Url(u) => u.clone(),
                };
                s.start_attempts(f, url, Box::new(k))
            }
        })
    }

    fn start_attempts(self, f: Fetch, url: String, k: K<Fetched>) -> Plan {
        let deadline = f.max_retry_wait.map(|d| Instant::now() + d);
        let f = Arc::new(f);
        self.attempt(f, url, DEFAULT_RETRIES.max(1), empty(), 500, deadline, k)
    }

    fn request(&self, f: &Fetch, url: &str) -> Request {
        let mut req = Request::new(f.method, url)
            .header("User-Agent", self.msg.app_id.clone())
            .header("Accept", "application/json");
        if f.auth
            && let Some(t) = &self.access_token
        {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        req = match &f.body {
            Body::Json(v) => {
                req.header("Content-Type", "application/json").body(serde_json::to_vec(v).unwrap_or_default(), None)
            }
            Body::Empty => req,
            Body::Raw(data, mime) => req.header("Content-Type", mime.clone()).body(data.as_ref().clone(), None),
        };
        req = req.query(&f.params);
        if f.credentials {
            req = req.redirects(false);
        }
        if let Some(t) = f.timeout {
            req = req.timeouts(t, t);
        }
        req
    }

    #[expect(clippy::too_many_arguments, reason = "retry state is passed along explicitly")]
    fn attempt(
        self,
        f: Arc<Fetch>,
        url: String,
        left: u32,
        last: Value,
        status: u16,
        deadline: Option<Instant>,
        k: K<Fetched>,
    ) -> Plan {
        if left == 0 {
            return k(self, Fetched::fail(empty(), status));
        }
        let req = self.request(&f, &url);
        Plan::http(req, move |res| {
            let r: Response = match res {
                Ok(r) => r,
                Err(e) => return k(self, Fetched { transport: Some(e), ..Fetched::fail(last, status) }),
            };
            let status = r.status;
            if let Some(max) = f.max_bytes
                && r.body.len() > max
            {
                log::warn!("Matrix response exceeded {max} bytes; discarding it.");
                return k(self, Fetched::fail(empty(), status));
            }
            let Ok(json) = serde_json::from_slice::<Value>(&r.body) else {
                log::warn!("Invalid response from Matrix server.");
                return k(self, Fetched::fail(empty(), status));
            };
            if status == 429 {
                let Some(obj) = json.as_object() else { return k(self, Fetched::fail(empty(), status)) };
                let wait = match obj.get("retry_after_ms") {
                    Some(v) => Some(v.clone()),
                    None => match obj.get("error") {
                        Some(Value::Object(e)) => e.get("retry_after_ms").cloned(),
                        Some(_) => return k(self, Fetched::fail(empty(), status)),
                        None => None,
                    },
                };
                let mut wait_ms = match wait {
                    None => DEFAULT_WAIT_MS,
                    Some(Value::Number(n)) => n.as_f64().unwrap_or(DEFAULT_WAIT_MS),
                    Some(Value::Bool(b)) => f64::from(u8::from(b)),
                    Some(_) => return k(self, Fetched::fail(empty(), status)),
                };
                if let Some(d) = deadline {
                    let remaining = d.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        log::warn!("Matrix server requested we throttle back, but our retry budget is exhausted.");
                        return k(self, Fetched::fail(json, status));
                    }
                    wait_ms = wait_ms.min(remaining.as_secs_f64() * 1000.0);
                }
                log::warn!("Matrix server requested we throttle back {wait_ms}ms; retries left {}.", left - 1);
                let wait = if wait_ms.is_finite() && wait_ms > 0.0 {
                    Duration::from_secs_f64((wait_ms / 1000.0).min(MAX_WAIT.as_secs_f64()))
                } else {
                    Duration::ZERO
                };
                return Plan::chain([
                    Plan::Sleep(wait),
                    Plan::defer(move || {
                        if deadline.is_some_and(|d| Instant::now() >= d) {
                            return k(self, Fetched::fail(json, status));
                        }
                        self.attempt(f, url, left - 1, json, status, deadline, k)
                    }),
                ]);
            }
            if status != 200 && status != 202 {
                if !f.ok_status.contains(&status) {
                    log::warn!("Failed to handshake with Matrix server: error={status}.");
                }
                return k(self, Fetched::fail(json, status));
            }
            k(self, Fetched { ok: true, json, status, transport: None })
        })
    }

    fn cache_discovery(&self, base: &str, identity: &str) {
        self.store.set(DISCOVERY_BASE_KEY, json!(base), Some(DISCOVERY_CACHE));
        self.store.set(DISCOVERY_IDENTITY_KEY, json!(identity), Some(DISCOVERY_CACHE + Duration::from_secs(2)));
    }

    fn discovery_failed(self, why: &str, k: K<bool>) -> Plan {
        log::warn!("Matrix Well-Known {why}");
        self.store.clear(&[DISCOVERY_BASE_KEY, DISCOVERY_IDENTITY_KEY]);
        k(self, false)
    }

    /// Homeserver discovery (`.well-known`); `k(false)` when it failed.
    fn discover(self, k: K<bool>) -> Plan {
        let url = format!("{}/.well-known/matrix/client", self.host_base());
        let probe = |u: String| Fetch::get_url(u).bounded(MAX_RESPONSE_BYTES).no_auth();
        self.fetch(probe(url), move |s, r| {
            if r.status == 404 {
                s.cache_discovery("", "");
                return k(s, true);
            }
            if r.status != 200 {
                return s.discovery_failed("Base URI Discovery Failed", k);
            }
            if !has_value(&r.json) {
                s.cache_discovery("", "");
                return k(s, true);
            }
            let base = r
                .json
                .get("m.homeserver")
                .and_then(|h| h.get("base_url"))
                .and_then(Value::as_str)
                .map(|b| b.trim_end_matches('/').to_string())
                .filter(|b| is_secure_http_url(b) && !b.contains('?'));
            let Some(base) = base else {
                return s.discovery_failed("Base URI Discovery Failed (m.homeserver)", k);
            };
            let response = r.json;
            s.fetch(probe(format!("{base}/_matrix/client/versions")), move |s, r| {
                if r.status != 200 {
                    return s.discovery_failed("Base URI Discovery Verification Failed", k);
                }
                let Some(id) = response.as_object().and_then(|o| o.get("m.identity_server")) else {
                    s.cache_discovery(&base, "");
                    return k(s, true);
                };
                let identity = id
                    .get("base_url")
                    .and_then(Value::as_str)
                    .map(|b| b.trim_end_matches('/').to_string())
                    .filter(|b| is_secure_http_url(b) && !b.contains('?'));
                let Some(identity) = identity else {
                    return s.discovery_failed("Identity URI Discovery Failed", k);
                };
                s.fetch(probe(format!("{identity}/_matrix/identity/v2")), move |s, r| {
                    if r.status != 200 {
                        return s.discovery_failed("Identity URI Discovery Failed", k);
                    }
                    s.cache_discovery(&base, &identity);
                    k(s, true)
                })
            })
        })
    }

    fn set_identity(&mut self, resp: &Value) {
        self.access_token = get_str(resp, "access_token");
        self.user_id = get_str(resp, "user_id");
        self.device_id = get_str(resp, "device_id");
        match get_str(resp, "home_server").filter(|h| !h.is_empty()) {
            Some(hs) => self.home_server = Some(hs),
            None => {
                if !non_empty(&self.home_server)
                    && let Some(u) = &self.user_id
                    && let Some(hs) = hs_of(u)
                {
                    self.home_server = Some(hs);
                }
            }
        }
    }

    fn store_identity(&self) {
        self.store.set("access_token", json!(self.access_token), CACHE_EXPIRY);
        if non_empty(&self.home_server) {
            self.store.set("home_server", json!(self.home_server), CACHE_EXPIRY);
        }
        self.store.set("user_id", json!(self.user_id), CACHE_EXPIRY);
        if non_empty(&self.device_id) {
            self.store.set("device_id", json!(self.device_id), CACHE_EXPIRY);
        }
    }

    fn login(self, k: K<bool>) -> Plan {
        if non_empty(&self.access_token) {
            return k(self, true);
        }
        let (Some(user), Some(password)) = (self.cfg.user.clone(), self.password().map(str::to_string)) else {
            log::warn!("Failed to login to Matrix server: token or user/pass combo is missing.");
            return k(self, false);
        };
        let mut payload = if self.cfg.version == Version::V3 {
            json!({"type": "m.login.password", "identifier": {"type": "m.id.user", "user": user}, "password": password})
        } else {
            json!({"type": "m.login.password", "user": user, "password": password})
        };
        match &self.device_id {
            Some(d) if !d.is_empty() => payload["device_id"] = json!(d),
            _ => payload["initial_device_display_name"] = json!(self.msg.app_id),
        }
        let f = Fetch::post("/login", payload).credentials().bounded(MAX_RESPONSE_BYTES);
        self.fetch(f, move |mut s, r| {
            let Some(resp) = r.object().map(|m| Value::Object(m.clone())) else { return k(s, false) };
            s.set_identity(&resp);
            if !non_empty(&s.access_token) {
                return k(s, false);
            }
            s.store_identity();
            k(s, true)
        })
    }

    fn register(self, k: K<bool>) -> Plan {
        let mut payload = json!({"kind": "user", "auth": {"type": "m.login.dummy"}});
        if let Some(u) = &self.cfg.user {
            payload["username"] = json!(u);
        }
        if let Some(p) = self.password() {
            payload["password"] = json!(p);
        }
        match &self.device_id {
            Some(d) if !d.is_empty() => payload["device_id"] = json!(d),
            _ => payload["initial_device_display_name"] = json!(self.msg.app_id),
        }
        let f = Fetch::post("/register", payload).param("kind", "user");
        self.fetch(f, move |mut s, r| {
            let Some(resp) = r.object().map(|m| Value::Object(m.clone())) else { return k(s, false) };
            s.set_identity(&resp);
            s.store_identity();
            let ok = s.access_token.is_some();
            k(s, ok)
        })
    }

    fn whoami(self, k: K<()>) -> Plan {
        self.fetch(Fetch::get("/account/whoami"), move |mut s, r| {
            let Some(resp) = r.object().map(|m| Value::Object(m.clone())) else { return k(s, ()) };
            if let Some(u) = get_str(&resp, "user_id").filter(|u| !u.is_empty()) {
                s.user_id = Some(u);
            }
            if let Some(d) = get_str(&resp, "device_id").filter(|d| !d.is_empty()) {
                s.device_id = Some(d);
            }
            if !non_empty(&s.home_server)
                && let Some(u) = &s.user_id
                && let Some(hs) = hs_of(u)
            {
                s.home_server = Some(hs);
            }
            if non_empty(&s.user_id) {
                s.store.set("user_id", json!(s.user_id), CACHE_EXPIRY);
            }
            if non_empty(&s.device_id) {
                s.store.set("device_id", json!(s.device_id), CACHE_EXPIRY);
            }
            if non_empty(&s.home_server) {
                s.store.set("home_server", json!(s.home_server), CACHE_EXPIRY);
            }
            k(s, ())
        })
    }

    pub fn run(mut self) -> Plan {
        if self.access_token.is_none() && self.password().is_some_and(|p| !p.is_empty()) && self.cfg.user.is_none() {
            self.access_token = self.password().map(str::to_string);
            self.txn = Txn::Uuid(crate::crypto::uuid4());
        }
        if self.access_token.is_none() {
            return self.login(Box::new(|s, ok| {
                if ok {
                    return s.after_auth();
                }
                s.register(Box::new(|s, ok| {
                    if ok {
                        s.after_auth()
                    } else {
                        s.finish(Some(Error::Service("Matrix login and registration failed".into()).context("login")))
                    }
                }))
            }));
        }
        self.after_auth()
    }

    fn after_auth(self) -> Plan {
        if !non_empty(&self.user_id) {
            return self.whoami(Box::new(|s, ()| s.after_identity()));
        }
        self.after_identity()
    }

    fn after_identity(mut self) -> Plan {
        if !non_empty(&self.home_server) {
            self.home_server = Some(self.cfg.host.clone());
        }
        if self.cfg.rooms.is_empty() && self.cfg.users.is_empty() {
            return self.joined_rooms(Box::new(|mut s, rooms| {
                if rooms.is_empty() {
                    log::warn!("There were no Matrix rooms specified to notify.");
                    let e = Error::Service("there were no Matrix rooms to notify".into());
                    return s.finish(Some(e.context("room lookup")));
                }
                s.queue = rooms.into_iter().map(|r| (label_of(&r), r)).collect();
                s.resolve_users(VecDeque::new())
            }));
        }
        self.queue = self.cfg.rooms.iter().map(|r| (r.clone(), json!(r))).collect();
        let users: VecDeque<String> = self.cfg.users.iter().cloned().collect();
        self.resolve_users(users)
    }

    fn resolve_users(mut self, mut users: VecDeque<String>) -> Plan {
        let Some(user) = users.pop_front() else { return self.after_dm_rooms() };
        if self.delivered(&user) {
            return self.resolve_users(users);
        }
        self.dm_room(
            user.clone(),
            Box::new(move |mut s, room| {
                match room {
                    Some(r) => s.queue.push_back((user, r)),
                    None => {
                        log::warn!("Could not find or create a DM room for Matrix user {user}.");
                        let e = Error::Service("could not find or create a direct-message room".into());
                        s.fail_target_with(user, e.context("room lookup"));
                    }
                }
                s.resolve_users(users)
            }),
        )
    }

    fn after_dm_rooms(self) -> Plan {
        #[cfg(feature = "extra")]
        if self.e2ee_wanted() {
            return super::e2ee_flow::setup(self, Box::new(|s, ()| s.next_room()));
        }
        self.next_room()
    }

    pub fn next_room(mut self) -> Plan {
        let Some((label, room)) = self.queue.pop_front() else { return self.after_rooms() };
        if self.delivered(&label) {
            return self.next_room();
        }
        self.room_join(
            room,
            Box::new(move |mut s, room_id| match room_id {
                None => {
                    log::warn!("Could not join Matrix room {label}.");
                    s.fail_target_with(label, Error::Service("could not join the room".into()).context("room join"));
                    s.next_room()
                }
                Some(rid) => s.deliver(label, rid),
            }),
        )
    }

    fn deliver(self, label: String, room_id: String) -> Plan {
        // With E2EE wanted, a room is sent plaintext only after the server said it has no encryption state; an encrypted room never gets plaintext, even when E2EE setup failed.
        #[cfg(feature = "extra")]
        if self.e2ee_wanted() {
            return super::e2ee_flow::room_encrypted(
                self,
                room_id.clone(),
                Box::new(move |mut s, encrypted| match encrypted {
                    Ok(false) => s.deliver_plain(label, room_id),
                    Ok(true) if s.e2ee.capable => super::e2ee_flow::deliver_encrypted(s, label, room_id),
                    Ok(true) => {
                        log::warn!("Matrix room {label} is encrypted but E2EE is unavailable; message not sent.");
                        let e = s
                            .e2ee
                            .setup_error
                            .clone()
                            .unwrap_or_else(|| Error::Service("Matrix E2EE setup failed".into()));
                        s.fail_target_with(label, e);
                        s.next_room()
                    }
                    Err(e) => {
                        s.fail_target_with(label, e);
                        s.next_room()
                    }
                }),
            );
        }
        self.deliver_plain(label, room_id)
    }

    fn message_path(&self, room_id: &str) -> String {
        format!("/rooms/{}/send/m.room.message/{}", quote_path(room_id), self.txn)
    }

    /// Unencrypted delivery to one room.
    fn deliver_plain(self, label: String, room_id: String) -> Plan {
        if !self.msg.attachments.is_empty() && self.attachments.is_none() {
            return self.upload_attachments(Box::new(move |s, ok| {
                if ok {
                    s.deliver_plain(label, room_id)
                } else {
                    s.finish(Some(Error::Service("Matrix attachment upload failed".into()).context("upload")))
                }
            }));
        }
        if let Some(image) = self.msg.image_url.clone()
            && self.cfg.version == Version::V2
        {
            let body =
                if self.msg.title.is_empty() { self.msg.kind.as_str().to_string() } else { self.msg.title.clone() };
            let payload = json!({"msgtype": "m.image", "url": image, "body": body});
            let path = self.message_path(&room_id);
            return self.fetch(Fetch::put(path, payload), move |mut s, r| {
                if !r.ok {
                    s.fail_target_with(label, Error::Service("image post failed".into()).context("send"));
                    return s.next_room();
                }
                s.bump_txn();
                s.post_attachments(label, room_id, 0, false)
            });
        }
        self.post_attachments(label, room_id, 0, false)
    }

    fn post_attachments(mut self, label: String, room_id: String, idx: usize, target_error: bool) -> Plan {
        let payload = match self.attachments.as_mut().and_then(|a| a.get_mut(idx)) {
            Some(p) => {
                p["room_id"] = json!(room_id);
                p["type"] = json!("m.room.message");
                p.clone()
            }
            None => return self.post_message(label, room_id, target_error),
        };
        let path = self.message_path(&room_id);
        self.fetch(Fetch::put(path, payload), move |mut s, r| {
            s.bump_txn();
            s.post_attachments(label, room_id, idx + 1, target_error || !r.ok)
        })
    }

    fn post_message(self, label: String, room_id: String, target_error: bool) -> Plan {
        let payload = super::message_content(&self.cfg, &self.msg);
        let path = self.message_path(&room_id);
        self.fetch(Fetch::put(path, payload), move |mut s, r| {
            s.bump_txn();
            if !r.ok {
                log::warn!("Could not send notification Matrix room {label}.");
                // Keeps the failure's class: a 5xx is retried, a 4xx or a request that may have been sent is not.
                s.fail_target_with(label, r.error("message post failed").context("send"));
            } else if target_error {
                s.fail_target_with(label, Error::Service("attachment post failed".into()).context("send"));
            } else {
                s.ok_target(label);
            }
            s.next_room()
        })
    }

    fn after_rooms(self) -> Plan {
        #[cfg(feature = "extra")]
        if self.e2ee.capable && self.cfg.autoverify && self.outcomes.iter().all(|(_, e)| e.is_none()) {
            super::sas::refresh_verified_state(&self);
        }
        self.finish(None)
    }

    /// End of `send()`. The session stays open; [`Session::logout`] runs when the target is closed.
    pub fn finish(self, fatal: Option<Error>) -> Plan {
        let done = move |s: Session| -> Plan {
            if let Some(e) = fatal {
                return Plan::Fail(e);
            }
            if s.outcomes.is_empty() {
                return Plan::Done;
            }
            Plan::all(s.outcomes.into_iter().map(|(label, e)| match e {
                None => Plan::Done.target(label),
                Some(e) => Plan::Fail(e).target(label),
            }))
        };
        done(self)
    }

    /// Log out of a session kept in a memory store (persistent stores keep it for the next run). `None` when there is nothing to do.
    pub fn logout(self) -> Option<Plan> {
        let token_is_password =
            self.access_token.is_some() && self.access_token.as_deref() == self.password() && self.cfg.user.is_none();
        if self.cfg.mode == Mode::T2bot
            || self.store.path().is_some()
            || token_is_password
            || !non_empty(&self.access_token)
        {
            return None;
        }
        Some(self.fetch(Fetch::post("/logout", json!({})), |s, _| {
            s.store.clear(&[
                "access_token",
                "home_server",
                "user_id",
                "transaction_id",
                "device_id",
                "e2ee_keys_uploaded",
            ]);
            Plan::Done
        }))
    }

    fn joined_rooms(self, k: K<Vec<Value>>) -> Plan {
        if self.access_token.is_none() {
            return k(self, Vec::new());
        }
        self.fetch(Fetch::get("/joined_rooms"), move |s, r| {
            let rooms = if r.ok {
                r.json.get("joined_rooms").and_then(Value::as_array).cloned().unwrap_or_default()
            } else {
                Vec::new()
            };
            k(s, rooms)
        })
    }

    fn cached_room(&self, key: &str) -> Option<Option<String>> {
        let v = self.store.get(key)?;
        let id = v.as_object()?.get("id")?;
        Some(id.as_str().map(str::to_string))
    }

    /// Room id or alias to a joined room id.
    fn room_join(self, room: Value, k: K<Option<String>>) -> Plan {
        if self.access_token.is_none() {
            return k(self, None);
        }
        let Some(room) = room.as_str().map(str::to_string) else { return k(self, None) };
        if let Some((token, explicit_hs)) = match_room_id(&room) {
            let home_server = explicit_hs.clone().or_else(|| self.home_server.clone()).unwrap_or_default();
            let cache_key =
                if home_server.is_empty() { format!("!{token}") } else { format!("!{token}:{home_server}") };
            let room_id = if explicit_hs.is_some() || self.cfg.hsreq { cache_key.clone() } else { format!("!{token}") };
            if let Some(cached) = self.cached_room(&cache_key) {
                return k(self, cached);
            }
            let path = format!("/join/{}", quote_path(&room_id));
            return self.fetch(Fetch::post(path, json!({})), move |s, r| {
                if !r.ok {
                    return k(s, None);
                }
                let joined = r.json.get("room_id").filter(|v| has_value(v)).cloned().unwrap_or(json!(room_id));
                s.store.set(&cache_key, json!({"id": joined, "home_server": home_server}), None);
                k(s, joined.as_str().map(str::to_string))
            });
        }
        let Some((name, explicit_hs)) = match_room_alias(&room) else {
            log::warn!("Ignoring illegally formed room {room} from Matrix server list.");
            return k(self, None);
        };
        let mut home_server = explicit_hs.or_else(|| self.home_server.clone()).filter(|h| !h.is_empty());
        if home_server.is_none()
            && let Some(u) = &self.user_id
        {
            home_server = hs_of(u);
        }
        let Some(home_server) = home_server.filter(|h| !h.is_empty()) else {
            log::warn!("Could not resolve a homeserver for Matrix room alias {room}.");
            return k(self, None);
        };
        let alias = format!("#{name}:{home_server}");
        if let Some(cached) = self.cached_room(&alias) {
            return k(self, cached);
        }
        let path = format!("/join/{}", quote_path(&alias));
        self.fetch(Fetch::post(path, json!({})), move |s, r| {
            if r.ok {
                let id = r.json.get("room_id").cloned().unwrap_or(Value::Null);
                s.store.set(&alias, json!({"id": id, "home_server": home_server}), None);
                return k(s, id.as_str().map(str::to_string));
            }
            if r.status == 404 || r.json.get("errcode").and_then(Value::as_str) == Some("M_NOT_FOUND") {
                return s.room_create(alias, k);
            }
            log::warn!(
                "Could not join Matrix room alias {alias} (error={}). If this is a private room, ensure the \
                 user is invited or already joined. Otherwise specify the room_id (!...).",
                r.status
            );
            k(s, None)
        })
    }

    fn encryption_state() -> Value {
        json!([{"type": "m.room.encryption", "state_key": "", "content": {"algorithm": "m.megolm.v1.aes-sha2"}}])
    }

    fn room_create(self, room: String, k: K<Option<String>>) -> Plan {
        let Some((name, explicit_hs)) = match_room_alias(&room) else { return k(self, None) };
        let mut home_server = explicit_hs.or_else(|| self.home_server.clone()).filter(|h| !h.is_empty());
        if home_server.is_none()
            && let Some(u) = &self.user_id
        {
            home_server = hs_of(u);
        }
        let Some(home_server) = home_server.filter(|h| !h.is_empty()) else { return k(self, None) };
        let room = format!("#{name}:{home_server}");
        let mut payload = json!({
            "room_alias_name": name,
            "name": format!("#{name} - {}", self.msg.app_desc),
            "visibility": "private",
            "preset": "trusted_private_chat",
        });
        let e2ee = self.e2ee_wanted();
        if e2ee {
            payload["initial_state"] = Self::encryption_state();
        }
        self.fetch(Fetch::post("/createRoom", payload), move |s, r| {
            if !r.ok {
                if r.json.get("errcode").and_then(Value::as_str) == Some("M_ROOM_IN_USE") {
                    return s.room_id_lookup(room, k);
                }
                return k(s, None);
            }
            let room_id = r.json.get("room_id").cloned().unwrap_or(Value::Null);
            if let Some(alias) = r.json.get("room_alias").and_then(Value::as_str) {
                s.store.set(alias, json!({"id": room_id, "home_server": home_server}), None);
            }
            let room_id = room_id.as_str().map(str::to_string);
            if e2ee && let Some(rid) = room_id.as_deref().filter(|r| !r.is_empty()) {
                s.store.set(&format!("e2ee_room_enc_{rid}"), json!(true), CACHE_EXPIRY);
            }
            k(s, room_id)
        })
    }

    /// Alias to room id via the room directory.
    fn room_id_lookup(self, room: String, k: K<Option<String>>) -> Plan {
        let Some((name, explicit_hs)) = match_room_alias(&room) else { return k(self, None) };
        let mut home_server = explicit_hs.or_else(|| self.home_server.clone()).filter(|h| !h.is_empty());
        if home_server.is_none()
            && let Some(u) = &self.user_id
        {
            home_server = hs_of(u);
        }
        let Some(home_server) = home_server.filter(|h| !h.is_empty()) else { return k(self, None) };
        let path = format!("/directory/room/{}", quote_path(&format!("#{name}:{home_server}")));
        self.fetch(Fetch::get(path), move |s, r| {
            let id = if r.ok { get_str(&r.json, "room_id") } else { None };
            k(s, id)
        })
    }

    /// Find or create the direct-message room with `user`.
    fn dm_room(self, user: String, k: K<Option<Value>>) -> Plan {
        let Some((local, explicit_hs)) = match_user(&user) else {
            log::warn!("Matrix DM: invalid user identifier {user:?}.");
            return k(self, None);
        };
        let Some(home_server) = explicit_hs.or_else(|| self.home_server.clone()).filter(|h| !h.is_empty()) else {
            log::warn!("Matrix DM: no home server known for user {user:?}.");
            return k(self, None);
        };
        let user_id = format!("@{local}:{home_server}");
        let cache_key = format!("dm_room_{user_id}");
        if let Some(cached) = self.store.get(&cache_key).filter(has_value) {
            return k(self, Some(cached));
        }
        let Some(me) = self.user_id.clone().filter(|u| !u.is_empty()) else {
            return self.dm_create(user_id, Map::new(), k);
        };
        let path = format!("/user/{}/account_data/m.direct", quote_path(&me));
        self.fetch(Fetch::get(path), move |s, r| {
            let mut mdirect = Map::new();
            if let Some(m) = r.object() {
                mdirect = m.clone();
                let rooms = mdirect.get(&user_id).cloned().unwrap_or(json!([]));
                if has_value(&rooms) {
                    let first = match &rooms {
                        Value::Array(a) => a[0].clone(),
                        Value::String(_) => rooms.clone(),
                        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_) => return k(s, None),
                    };
                    s.store.set(&cache_key, first.clone(), CACHE_EXPIRY);
                    return k(s, Some(first));
                }
            }
            s.dm_create(user_id, mdirect, k)
        })
    }

    fn dm_create(self, user_id: String, mut mdirect: Map<String, Value>, k: K<Option<Value>>) -> Plan {
        let mut payload = json!({"is_direct": true, "preset": "trusted_private_chat", "invite": [user_id]});
        let e2ee = self.e2ee_wanted();
        if e2ee {
            payload["initial_state"] = Self::encryption_state();
        }
        self.fetch(Fetch::post("/createRoom", payload), move |s, r| {
            if r.object().is_none() {
                log::warn!("Matrix DM: failed to create room for {user_id}.");
                return k(s, None);
            }
            let Some(room_id) = r.json.get("room_id").filter(|v| has_value(v)).cloned() else { return k(s, None) };
            s.store.set(&format!("dm_room_{user_id}"), room_id.clone(), CACHE_EXPIRY);
            if e2ee && let Some(rid) = room_id.as_str() {
                s.store.set(&format!("e2ee_room_enc_{rid}"), json!(true), CACHE_EXPIRY);
            }
            let Some(me) = s.user_id.clone().filter(|u| !u.is_empty()) else { return k(s, Some(room_id)) };
            let mut list: Vec<Value> = match mdirect.get(&user_id) {
                Some(Value::Array(a)) => a.clone(),
                _ => Vec::new(),
            };
            list.push(room_id.clone());
            mdirect.insert(user_id, Value::Array(list));
            let path = format!("/user/{}/account_data/m.direct", quote_path(&me));
            s.fetch(Fetch::put(path, Value::Object(mdirect)), move |s, _| k(s, Some(room_id)))
        })
    }

    /// Upload every attachment once.
    fn upload_attachments(self, k: K<bool>) -> Plan {
        self.upload_one(0, Vec::new(), k)
    }

    fn upload_one(self, idx: usize, mut payloads: Vec<Value>, k: K<bool>) -> Plan {
        let Some(att) = self.msg.attachments.get(idx).cloned() else {
            let mut s = self;
            s.attachments = Some(payloads);
            return k(s, true);
        };
        let is_image = att.mime.to_ascii_lowercase().starts_with("image/");
        if !is_image && self.cfg.version == Version::V2 {
            return self.upload_one(idx + 1, payloads, k);
        }
        let f = Fetch::upload(&att.name, &att.mime, Arc::new(att.data.clone()));
        self.fetch(f, move |s, r| {
            let Some(resp) = r.object() else { return k(s, false) };
            let uri = resp.get("content_uri").cloned().unwrap_or(Value::Null);
            if s.cfg.version == Version::V3 {
                let mut p = json!({
                    "body": att.name,
                    "info": {"mimetype": att.mime, "size": att.data.len()},
                    "msgtype": if is_image { "m.image" } else { "m.file" },
                    "url": uri,
                });
                if !is_image {
                    p["filename"] = json!(att.name);
                }
                payloads.push(p);
            } else {
                payloads.push(json!({
                    "info": {"mimetype": att.mime},
                    "msgtype": "m.image",
                    "body": "tta.webp",
                    "url": uri,
                }));
            }
            s.upload_one(idx + 1, payloads, k)
        })
    }
}

fn label_of(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), str::to_string)
}

/// Build a session for one send and run it.
pub(super) fn plan(cfg: Arc<Config>, msg: Msg, store: StoreRef, memo: Memo) -> Plan {
    let msg = Arc::new(msg);
    Plan::defer(move || Session { memo, ..Session::new(cfg, msg, store) }.run())
}

fn delivery_key(label: &str) -> String {
    format!("target:{label}")
}

/// Clean-up when the target is closed.
pub(super) fn close(cfg: Arc<Config>, msg: Msg, store: StoreRef) -> Option<Plan> {
    Session::new(cfg, Arc::new(msg), store).logout()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns() {
        assert_eq!(match_room_id("!abc:example.com"), Some(("abc".into(), Some("example.com".into()))));
        assert_eq!(match_room_id("%21abc%3Aexample.com"), Some(("abc".into(), Some("example.com".into()))));
        assert_eq!(match_room_id("abc"), None);
        assert_eq!(match_room_alias("#room"), Some(("room".into(), None)));
        assert_eq!(match_room_alias("room:hs.org"), Some(("room".into(), Some("hs.org".into()))));
        assert_eq!(match_room_alias("bad room"), None);
        assert_eq!(match_user("@bob:hs"), Some(("bob".into(), Some("hs".into()))));
        assert_eq!(match_user("bob"), None);
    }

    #[test]
    fn secure_urls() {
        assert!(is_secure_http_url("https://matrix.example.com"));
        assert!(is_secure_http_url("https://matrix.example.com:8448/path"));
        assert!(is_secure_http_url("https://[::1]:8448"));
        assert!(!is_secure_http_url("http://matrix.example.com"));
        assert!(!is_secure_http_url("https://user@matrix.example.com"));
        assert!(!is_secure_http_url("https://@matrix.example.com"));
        assert!(!is_secure_http_url("https://matrix.example.com#x"));
        assert!(!is_secure_http_url("https://matrix.example.com:0"));
        assert!(!is_secure_http_url("https://matrix.example.com:99999"));
        assert!(!is_secure_http_url("https://"));
    }
}
