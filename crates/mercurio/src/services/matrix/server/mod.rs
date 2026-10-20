//! Direct (non-webhook) delivery: the [`Session`], its requests with retries, and the helpers its phases share. The phases live in submodules: `auth` (discovery, login/register/whoami, logout), `rooms` (join/create/alias lookup, direct-message rooms) and `send` (the delivery flow and media upload).
//!
//! Every step is a continuation over an owned [`Session`]: a step sends one request with [`Session::fetch`] and continues with the updated session.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use super::{Config, Mode, Msg, Version};
use crate::env::Env;
use crate::error::Error;
use crate::http::{Method, Request, Response};
use crate::store::{Memo, StoreRef};
use crate::url::quote;
use crate::{Plan, regex};

mod auth;
mod rooms;
mod send;

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
    #[cfg_attr(not(feature = "service-matrix-e2ee"), expect(dead_code, reason = "used by end-to-end encryption only"))]
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
    #[cfg_attr(not(feature = "service-matrix-e2ee"), expect(dead_code, reason = "used by end-to-end encryption only"))]
    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = Some(t);
        self
    }
    #[cfg_attr(not(feature = "service-matrix-e2ee"), expect(dead_code, reason = "used by end-to-end encryption only"))]
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

/// `e` (below its step names) as a 429 that asked to wait `wait`, when it is a plain HTTP 429 or a service failure.
fn limit(e: Error, wait: Duration) -> Error {
    if let Error::Context { context, source } = e {
        return Error::Context { context, source: Box::new(limit(*source, wait)) };
    }
    if let Error::Http { status: 429, reason: r } | Error::Service(r) = &e {
        return Error::RateLimited { status: 429, reason: r.clone(), retry_after: Some(wait) };
    }
    e
}

/// A 429 body's `retry_after_ms` (top level or under `error`), when positive.
fn retry_hint(json: &Value) -> Option<Duration> {
    let ms = json.get("retry_after_ms").or_else(|| json.get("error")?.get("retry_after_ms"))?.as_f64()?;
    (ms.is_finite() && ms > 0.0).then(|| Duration::from_secs_f64(ms / 1000.0))
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
        && crate::parse::port(p).is_none()
    {
        return false;
    }
    !host.is_empty() && crate::parse::is_hostname(&host.to_lowercase(), true, true, true).is_some()
}

/// Mutable delivery state threaded through every step.
pub(super) struct Session {
    pub cfg: Arc<Config>,
    pub msg: Arc<Msg>,
    pub store: StoreRef,
    /// The clock and random source of the send.
    pub env: Arc<dyn Env>,
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
    /// The wait a 429 asked for when the back-off gave up on it; the next failure is reported as rate limited, so `?retry=` waits that long.
    throttled: Option<Duration>,
    #[cfg(feature = "service-matrix-e2ee")]
    pub e2ee: super::e2ee_flow::E2ee,
}

impl Session {
    // A new session, with identity values restored from the store.
    pub fn new(cfg: Arc<Config>, msg: Arc<Msg>, store: StoreRef, env: Arc<dyn Env>) -> Self {
        let mut s = Session {
            cfg,
            msg,
            store,
            env,
            memo: Memo::disabled(),
            access_token: None,
            user_id: None,
            device_id: None,
            home_server: None,
            txn: Txn::Counter(0),
            queue: VecDeque::new(),
            outcomes: Vec::new(),
            attachments: None,
            throttled: None,
            #[cfg(feature = "service-matrix-e2ee")]
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
        #[cfg(feature = "service-matrix-e2ee")]
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
        cfg!(feature = "service-matrix-e2ee") && self.cfg.e2ee && self.cfg.secure
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
                *u = self.env.uuid4();
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
        let error = self.rate_limited(error);
        self.outcomes.push((label.into(), Some(error)));
    }

    /// `e` as [`Error::RateLimited`] when a 429 the back-off gave up on caused it (the step names stay).
    fn rate_limited(&mut self, e: Error) -> Error {
        let Some(wait) = self.throttled.take() else { return e };
        limit(e, wait)
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
        mut self,
        f: Arc<Fetch>,
        url: String,
        left: u32,
        last: Value,
        status: u16,
        deadline: Option<Instant>,
        k: K<Fetched>,
    ) -> Plan {
        if left == 0 {
            if status == 429 {
                self.throttled = retry_hint(&last);
            }
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
                        self.throttled = retry_hint(&json);
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
                            self.throttled = retry_hint(&json);
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
            self.throttled = None;
            k(self, Fetched { ok: true, json, status, transport: None })
        })
    }
}

fn label_of(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), str::to_string)
}

/// Build a session for one send and run it.
pub(super) fn plan(cfg: Arc<Config>, msg: Msg, store: StoreRef, memo: Memo, env: Arc<dyn Env>) -> Plan {
    let msg = Arc::new(msg);
    Plan::defer(move || Session { memo, ..Session::new(cfg, msg, store, env) }.run())
}

fn delivery_key(label: &str) -> String {
    format!("target:{label}")
}

/// Clean-up when the target is closed.
pub(super) fn close(cfg: Arc<Config>, msg: Msg, store: StoreRef, env: Arc<dyn Env>) -> Option<Plan> {
    Session::new(cfg, Arc::new(msg), store, env).logout()
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
