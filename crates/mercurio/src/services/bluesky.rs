//! BlueSky (`bsky://`, `bluesky://`): posts to a BlueSky account through the AT Protocol API.
//!
//! Flow per message: resolve the handle to a DID, fetch the DID document to find the PDS endpoint, create a session, upload image blobs, then create one record per blob (or a single text record).
//!
//! The persistent store keeps the DID and PDS endpoint of each handle (`did.<handle>`, `endpoint.<handle>`) and the session (`access_token`, `refresh_token` for an hour less 10 s, `endpoint`), so later sends skip the lookups and the login.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::time::{iso8601_utc, unix_time};
use crate::error::Error;
use crate::http::Request;
use crate::message::Attachment;
use crate::parse::is_hostname;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef, UrlIdentifier};
use crate::store::StoreRef;
use crate::url::ParsedUrl;
use crate::util::json_has_value;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "bluesky",
    name: "BlueSky",
    schemes: &["bsky", "bluesky"],
    service_url: "https://bluesky.us/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 280, body_max_line_count: 0 },
    attachments: true,
    templates: &[
        "{schema}://{user}@{password}",
    ],
    tokens: &[
        Param::new("password", "Password").required().secret(),
        Param::new("user", "Username").required(),
    ],
    ..ServiceDef::DEFAULTS
};

const DEFAULT_HOST: &str = "bsky.social";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const XRPC_DID: &str = "/xrpc/com.atproto.identity.resolveHandle";
const XRPC_SESSION: &str = "/xrpc/com.atproto.server.createSession";
const XRPC_RECORD: &str = "/xrpc/com.atproto.repo.createRecord";
const XRPC_BLOB: &str = "/xrpc/com.atproto.repo.uploadBlob";
/// Session lifetime: one hour less 10 s of clock skew.
const SESSION_TTL: Duration = Duration::from_secs(3590);

#[derive(Debug)]
struct BlueSky {
    user: String,
    host: String,
    password: Option<Secret>,
    /// The user as given, for the URL id.
    raw_user: String,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut password = u.password();
    if password.as_deref().is_none_or(str::is_empty) && !u.host.is_empty() {
        password = Some(u.host());
    }
    let user =
        u.user().filter(|s| !s.is_empty()).ok_or_else(|| SERVICE.err("a BlueSky UserID/Handle must be specified"))?;
    let raw_user = user.clone();
    let (user, host) = match crate::regex!(r"^(?P<handle>[^.]+)\.+(?P<host>.+)$").captures(&user) {
        Some(c) => (c["handle"].trim().to_string(), c["host"].trim().to_string()),
        None => (user, DEFAULT_HOST.to_string()),
    };
    Ok(Box::new(BlueSky { user, host, password: password.map(Secret::new), raw_user }))
}

/// Whether a URL is a usable PDS endpoint: HTTPS, a valid host, no credentials, a usable port and no fragment.
fn is_secure_http_url(url: &str) -> bool {
    if url.contains('#') {
        return false;
    }
    let Some((scheme, rest)) = url.split_once(':') else { return false };
    if !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let Some(rest) = rest.strip_prefix("//") else { return false };
    let netloc = rest.split(['/', '?']).next().unwrap_or_default();
    if netloc.contains('@') {
        return false;
    }
    let (hostname, port) = match netloc.split_once('[') {
        Some((_, bracketed)) => {
            let Some((h, after)) = bracketed.split_once(']') else { return false };
            (h, after.split_once(':').map(|(_, p)| p).unwrap_or(""))
        }
        None => match netloc.split_once(':') {
            Some((h, p)) => (h, p),
            None => (netloc, ""),
        },
    };
    if !port.is_empty() && crate::parse::port(port).is_none() {
        return false;
    }
    let hostname = hostname.to_lowercase();
    !hostname.is_empty() && is_hostname(&hostname, true, true, true).is_some()
}

/// Server-advertised rate limit (`ratelimit-remaining` / `ratelimit-reset`).
#[derive(Debug, Clone, Copy)]
struct RateLimit {
    remaining: i64,
    reset: f64,
}

fn now_f64() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

impl RateLimit {
    fn new() -> Self {
        RateLimit { remaining: 1, reset: now_f64() }
    }

    fn wait(&self) -> Option<Duration> {
        let now = now_f64();
        (self.remaining == 0 && now < self.reset).then(|| Duration::from_secs_f64(self.reset - now + 0.3))
    }

    /// Returns `false` when the reset value cannot be represented as a date (the request then fails).
    fn update(&mut self, r: &crate::http::Response) -> bool {
        let Some(remaining) = r.header("ratelimit-remaining").and_then(|v| v.trim().parse::<i64>().ok()) else {
            return true;
        };
        self.remaining = remaining;
        let Some(reset) = r.header("ratelimit-reset").and_then(|v| v.trim().parse::<i64>().ok()) else {
            return true;
        };
        if !(-62_135_596_800..=253_402_300_799).contains(&reset) {
            return false;
        }
        self.reset = reset as f64;
        true
    }
}

/// Send, track rate limits, require HTTP 200, parse JSON (falling back to `{}`), then continue with `next`. Failures name `step`.
fn fetch(
    mut rl: RateLimit,
    req: Request,
    step: &'static str,
    bounded: bool,
    next: impl FnOnce(RateLimit, Value) -> Plan + Send + 'static,
) -> Plan {
    let wait = rl.wait();
    let plan = Plan::http(req, move |res| {
        let r = match res {
            Ok(r) => r,
            Err(e) => return Plan::Fail(e),
        };
        if bounded && r.body.len() > MAX_RESPONSE_BYTES {
            return Plan::Fail(Error::Service("BlueSky reply too large; discarding it".into()));
        }
        let content = r.json().unwrap_or_else(|| json!({}));
        if !rl.update(&r) {
            return Plan::Fail(Error::Service("BlueSky returned an invalid rate limit reset".into()));
        }
        if r.status != 200 {
            return Plan::Fail(r.http_error());
        }
        next(rl, content)
    })
    .context(step);
    match wait {
        Some(d) => Plan::chain([Plan::Sleep(d), plan]),
        None => plan,
    }
}

/// Everything learned while logging in.
#[derive(Clone)]
struct Session {
    ua: String,
    /// The PDS endpoint blobs go to.
    endpoint: String,
    token: Option<String>,
    handle: String,
    store: StoreRef,
}

impl Session {
    fn post(&self, url: String, ct: &str) -> Request {
        let mut req = Request::post(url).header("User-Agent", &self.ua).header("Content-Type", ct);
        if let Some(t) = &self.token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        req
    }
}

fn lookup(ua: &str, url: String) -> Request {
    Request::get(url)
        .header("User-Agent", ua)
        .header("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
}

fn bearer_value(v: Option<&Value>) -> Option<String> {
    v.filter(|v| json_has_value(v)).map(crate::util::json_text)
}

fn created_at() -> String {
    iso8601_utc(unix_time())
}

/// Upload image attachments one by one; non-images and replies without a blob are skipped, a failed upload stops everything.
fn upload(
    rl: RateLimit,
    s: Session,
    mut atts: std::vec::IntoIter<(usize, Attachment)>,
    mut blobs: Vec<(Value, String)>,
    body: String,
) -> Plan {
    let next = loop {
        match atts.next() {
            None => return post_records(rl, s, blobs, body),
            Some((no, a)) => {
                if crate::regex!(r"(?i)^image/").is_match(&a.mime) {
                    break (no, a);
                }
                log::warn!("BlueSky: ignoring unsupported attachment");
            }
        }
    };
    let (no, a) = next;
    let filename = if a.name.is_empty() { format!("file{no:03}.dat") } else { a.name.clone() };
    let req = s.post(format!("{}{XRPC_BLOB}", s.endpoint), &a.mime).body(a.data, None);
    fetch(rl, req, "upload", false, move |rl, content| {
        match content.as_object().and_then(|o| o.get("blob")).filter(|b| json_has_value(b)) {
            Some(blob) => blobs.push((blob.clone(), filename)),
            None => log::warn!("BlueSky: could not attach the file"),
        }
        upload(rl, s, atts, blobs, body)
    })
}

/// The handle's DID and PDS endpoint, from the store or looked up (and then stored).
fn resolve(
    rl: RateLimit,
    ua: String,
    handle: String,
    store: StoreRef,
    next: impl FnOnce(RateLimit, String, String) -> Plan + Send + 'static,
) -> Plan {
    let (did_key, endpoint_key) = (format!("did.{handle}"), format!("endpoint.{handle}"));
    let cached = |k: &str| {
        store.get_some(k).filter(json_has_value).map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_string))
    };
    if let (Some(did), Some(endpoint)) = (cached(&did_key), cached(&endpoint_key)) {
        return next(rl, did, endpoint);
    }
    let req = lookup(&ua, format!("https://public.api.bsky.app{XRPC_DID}")).query(&[("handle", handle.as_str())]);
    fetch(rl, req, "handle lookup", true, move |rl, content| {
        let Some(did) = content.as_object().and_then(|o| o.get("did")).and_then(Value::as_str).map(str::to_string)
        else {
            return Plan::Fail(Error::Service("an unparseable BlueSky DID was returned".into()));
        };
        let did_url = if did.starts_with("did:plc:") {
            format!("https://plc.directory/{did}")
        } else if let Some(rest) = did.strip_prefix("did:web:") {
            format!("https://{rest}/.well-known/did.json")
        } else {
            return Plan::Fail(Error::Service("unknown BlueSky DID scheme".into()));
        };
        fetch(rl, lookup(&ua, did_url), "did lookup", true, move |rl, doc| {
            let Some(doc) = doc.as_object() else {
                return Plan::Fail(Error::Service("could not fetch the BlueSky DID document".into()));
            };
            let endpoint = doc
                .get("service")
                .and_then(Value::as_array)
                .and_then(|services| {
                    services
                        .iter()
                        .filter_map(Value::as_object)
                        .find(|s| s.get("type").and_then(Value::as_str) == Some("AtprotoPersonalDataServer"))
                })
                .and_then(|s| s.get("serviceEndpoint"))
                .and_then(Value::as_str)
                .filter(|e| is_secure_http_url(e) && !e.contains('?'))
                .map(str::to_string);
            let Some(endpoint) = endpoint else {
                return Plan::Fail(Error::Service("failed to resolve a usable BlueSky PDS endpoint".into()));
            };
            store.set(&did_key, json!(did), None);
            store.set(&endpoint_key, json!(endpoint), None);
            next(rl, did, endpoint)
        })
    })
}

fn post_records(rl: RateLimit, s: Session, blobs: Vec<(Value, String)>, body: String) -> Plan {
    let (ua, handle, store) = (s.ua.clone(), s.handle.clone(), s.store.clone());
    resolve(rl, ua, handle, store, move |rl, did, endpoint| {
        let s = Session { endpoint, ..s };
        records(rl, s, did, blobs, body)
    })
}

fn records(rl: RateLimit, s: Session, did: String, blobs: Vec<(Value, String)>, body: String) -> Plan {
    let base = json!({
        "collection": "app.bsky.feed.post",
        "repo": did,
        "record": {"text": body, "createdAt": created_at(), "$type": "app.bsky.feed.post"},
    });
    let mut payloads = Vec::new();
    if blobs.is_empty() {
        payloads.push(base);
    } else {
        let total = blobs.len();
        for (i, (blob, alt)) in blobs.into_iter().enumerate() {
            let mut p = base.clone();
            if i > 0 {
                p["record"]["createdAt"] = json!(created_at());
                p["record"]["text"] = json!(format!("{:02}/{total:02}", i + 1));
            }
            p["record"]["embed"] = json!({
                "images": [{"image": blob, "alt": alt}],
                "$type": "app.bsky.embed.images",
            });
            payloads.push(p);
        }
    }
    send_records(rl, s, payloads.into_iter())
}

fn send_records(rl: RateLimit, s: Session, mut payloads: std::vec::IntoIter<Value>) -> Plan {
    let Some(p) = payloads.next() else { return Plan::Done };
    let req = s.post(format!("{}{XRPC_RECORD}", s.endpoint), "application/json").json(&p);
    fetch(rl, req, "post", false, move |rl, _| send_records(rl, s, payloads))
}

impl Notify for BlueSky {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let ua = ctx.app_id().to_string();
        let handle = if self.user.contains('.') { self.user.clone() } else { format!("{}.{}", self.user, self.host) };
        let password = self.password.as_ref().map(|p| p.expose().to_string());
        let atts: Vec<(usize, Attachment)> =
            msg.attachments.iter().cloned().enumerate().map(|(i, a)| (i + 1, a)).collect();
        let body = msg.body.to_string();
        let store = ctx.store();

        // A stored session skips the login.
        let token = bearer_value(store.get("access_token").as_ref());
        let endpoint = store.get_str("endpoint");
        if let (Some(token), Some(endpoint)) = (token, endpoint) {
            let session = Session { ua, endpoint, token: Some(token), handle, store };
            return upload(RateLimit::new(), session, atts.into_iter(), Vec::new(), body);
        }

        resolve(RateLimit::new(), ua.clone(), handle.clone(), store.clone(), move |rl, did, endpoint| {
            let session = Session { ua, endpoint, token: None, handle, store };
            let req = session
                .post(format!("{}{XRPC_SESSION}", session.endpoint), "application/json")
                .json(&json!({"identifier": did, "password": password}))
                .redirects(false);
            fetch(rl, req, "login", true, move |rl, resp| {
                let Some(obj) = resp.as_object().filter(|o| !o.is_empty()) else {
                    return Plan::Fail(Error::Service("BlueSky authentication failed".into()));
                };
                let access = obj.get("accessJwt").cloned().unwrap_or(Value::Null);
                let refresh = obj.get("refreshJwt").cloned().unwrap_or(Value::Null);
                session.store.set("access_token", access.clone(), Some(SESSION_TTL));
                session.store.set("refresh_token", refresh, Some(SESSION_TTL));
                session.store.set("endpoint", json!(session.endpoint), None);
                let session = Session { token: bearer_value(Some(&access)), ..session };
                upload(rl, session, atts.into_iter(), Vec::new(), body)
            })
        })
    }

    fn url_identifier(&self) -> UrlIdentifier {
        let pw = self.password.as_ref().map(|p| p.expose());
        UrlIdentifier::Parts(vec!["bsky".into(), self.raw_user.clone(), pw.unwrap_or_default().to_string()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_urls() {
        assert!(is_secure_http_url("https://example.pds.io"));
        assert!(is_secure_http_url("https://example.pds.io:443/path"));
        assert!(!is_secure_http_url("http://attacker.example.com"));
        assert!(!is_secure_http_url("https://attacker:secret@attacker.example.com"));
        assert!(!is_secure_http_url("https://-invalid-.example.com"));
        assert!(!is_secure_http_url("https://host:0"));
        assert!(!is_secure_http_url("https://host/#x"));
        assert!(!is_secure_http_url("https://"));
    }
}
