//! The Emby API engine shared by `emby.rs` and `jellyfin.rs`: messages to the active client sessions.
//!
//! The login session lives as long as the parsed URL (a non-persistent store entry): later sends only look up the client sessions and post. [`Target::close`](crate::Target::close) logs out.

use md5::{Digest, Md5};
use serde_json::{Map, Value, json};

use crate::util::scalar_text;
use crate::error::Error;
use crate::http::{Request, Response};
use crate::service::{Context, Notify, Secret, ServiceDef, UrlIdentifier};
use crate::store::Store;
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

const MESSAGE_TIMEOUT_MS: u64 = 60000;
const DEFAULT_PORT: u16 = 8096;

#[derive(Debug, Clone)]
pub(crate) struct Emby {
    /// Display name of the service, for logs.
    name: &'static str,
    base: String,
    user: String,
    password: Option<Secret>,
    modal: bool,
    /// URL identifier parts.
    id: Vec<String>,
}

pub(crate) fn parse_with(u: &ParsedUrl, def: &'static ServiceDef) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, def)?;
    let user = u.user().filter(|s| !s.is_empty()).ok_or_else(|| def.err("no username was specified"))?;
    let port = u.port.filter(|p| *p != 0).unwrap_or(DEFAULT_PORT);
    let base = format!("{}://{}:{}", u.http_scheme(), u.host(), port);
    let id = vec![
        format!("{}s", def.schemes[0]),
        user.clone(),
        u.password().as_deref().unwrap_or_default().to_string(),
        u.host(),
        u.port.filter(|p| *p != 0).unwrap_or(DEFAULT_PORT).to_string(),
    ];
    Ok(Box::new(Emby {
        name: def.name,
        base,
        user,
        password: u.password().filter(|p| !p.is_empty()).map(Secret::new),
        modal: def.flag(u, "modal"),
        id,
    }))
}

/// Stable per-target `DeviceId`: SHA-256 over (app id, `scheme://host:port`, user), first 16 bytes shaped as a version-5 RFC 4122 UUID.
fn device_id(app_id: &str, base: &str, user: &str) -> String {
    let input = [app_id, base, user].join("\0");
    let mut b = crate::crypto::sha256(input.as_bytes());
    b.truncate(16);
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    [&b[..4], &b[4..6], &b[6..8], &b[8..10], &b[10..]].map(crate::crypto::hex).join("-")
}

/// Logged-in state.
#[derive(Clone)]
struct Session {
    token: String,
    user_id: String,
}

/// Store key of the login session (kept in memory only).
const SESSION_KEY: &str = "session";

impl Session {
    fn load(store: &dyn Store) -> Option<Session> {
        let v = store.get_some(SESSION_KEY)?;
        Some(Session { token: v.get("token")?.as_str()?.to_string(), user_id: v.get("user_id")?.as_str()?.to_string() })
    }

    fn save(&self, store: &dyn Store) {
        store.remember(SESSION_KEY, json!({"token": self.token, "user_id": self.user_id}), None);
    }
}

impl Emby {
    fn auth_header(&self, ua: &str, authenticated: bool) -> String {
        let device = device_id(ua, &self.base, &self.user);
        let mut args = vec![
            ("MediaBrowser Client", ua),
            ("Device", ua),
            ("DeviceId", device.as_str()),
            ("Version", env!("CARGO_PKG_VERSION")),
        ];
        if authenticated {
            args.push(("UserId", &self.user));
        }
        args.iter().map(|(k, v)| format!("{k}=\"{v}\"")).collect::<Vec<_>>().join(", ")
    }

    fn request(&self, req: Request, ua: &str, session: Option<&Session>) -> Request {
        let req = req
            .header("User-Agent", ua)
            .header("Content-Type", "application/json")
            .header("X-Emby-Authorization", self.auth_header(ua, session.is_some()));
        match session {
            Some(s) => req.header("X-MediaBrowser-Token", &s.token),
            None => req,
        }
    }

    fn login(&self, ua: &str) -> Request {
        let payload = match &self.password {
            Some(pw) => {
                let pw = pw.expose();
                json!({
                    "Username": self.user,
                    "pw": pw,
                    "passwordMd5": crate::crypto::hex(&Md5::digest(pw.as_bytes())),
                    "password": crate::crypto::hex(&crate::crypto::sha1(pw.as_bytes())),
                })
            }
            None => json!({"Username": self.user, "password": "", "passwordMd5": "", "pw": ""}),
        };
        let req = self.request(Request::post(format!("{}/Users/AuthenticateByName", self.base)), ua, None);
        req.body(serde_json::to_vec(&payload).unwrap_or_default(), None)
    }

    fn logout(&self, ua: &str, s: &Session) -> Request {
        self.request(Request::post(format!("{}/Sessions/Logout", self.base)), ua, Some(s))
    }
}

/// `login()` response -> session (`None`: not authenticated).
fn parse_login(r: &Response) -> std::result::Result<Option<Session>, Error> {
    let Some(v) = r.json() else { return Ok(None) };
    let Some(obj) = v.as_object() else {
        return Err(Error::service("unexpected Emby login response"));
    };
    let token = obj.get("AccessToken").and_then(scalar_text);
    let mut user_id = obj.get("Id").and_then(scalar_text);
    if user_id.is_none()
        && let Some(user) = obj.get("User")
    {
        match user.as_object() {
            Some(u) => user_id = u.get("Id").and_then(scalar_text),
            None => return Err(Error::service("unexpected Emby login response")),
        }
    }
    Ok(match (token, user_id) {
        (Some(token), Some(user_id)) => Some(Session { token, user_id }),
        _ => None,
    })
}

/// `sessions()` response -> session ids in first-seen order.
fn parse_sessions(r: &Response) -> std::result::Result<Vec<String>, Error> {
    let bad = || Error::service("unexpected Emby sessions response");
    let Some(v) = r.json() else { return Ok(Vec::new()) };
    let entries: Vec<&Map<String, Value>> = match &v {
        Value::Array(a) => a.iter().map(|e| e.as_object().ok_or_else(bad)).collect::<std::result::Result<_, _>>()?,
        Value::Object(m) if m.is_empty() => Vec::new(),
        Value::String(s) if s.is_empty() => Vec::new(),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Object(_) => return Err(bad()),
    };
    let mut ids: Vec<String> = Vec::new();
    for e in entries {
        if let Some(id) = e.get("Id").and_then(scalar_text)
            && !ids.contains(&id)
        {
            ids.push(id);
        }
    }
    Ok(ids)
}

impl Emby {
    /// Look up the client sessions and message each one.
    fn notify(self, session: Session, ua: String, payload: Value) -> Plan {
        let url = format!("{}/Sessions?ControllableByUserId={}", self.base, session.user_id);
        let req = self.request(Request::get(url), &ua, Some(&session));
        Plan::http(req, move |res| {
            let ids = match res {
                Ok(r) if r.status == 200 => parse_sessions(&r),
                _ => Ok(Vec::new()),
            };
            match ids {
                Err(e) => Plan::Fail(e),
                Ok(ids) if ids.is_empty() => {
                    log::warn!("{}: there were no sessions to notify", self.name);
                    Plan::Done
                }
                Ok(ids) => Plan::all(ids.into_iter().map(|id| {
                    let req = self
                        .request(Request::post(format!("{}/Sessions/{}/Message", self.base, id)), &ua, Some(&session))
                        .body(serde_json::to_vec(&payload).unwrap_or_default(), None);
                    Plan::send_expect(req, &[200, 204]).context("send").target(id)
                })),
            }
        })
        .context("session lookup")
    }
}

impl Notify for Emby {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let me = self.clone();
        let ua = ctx.app_id().to_string();
        let mut payload = json!({"Header": msg.title, "Text": msg.body});
        if !self.modal {
            payload["TimeoutMs"] = json!(MESSAGE_TIMEOUT_MS);
        }
        if let Some(session) = Session::load(ctx.store.as_ref()) {
            return me.notify(session, ua, payload);
        }
        let store = ctx.store();
        Plan::http(self.login(&ua), move |res| {
            let r = match res {
                Ok(r) if r.status == 200 => r,
                Ok(r) => return Plan::Fail(r.http_error()),
                Err(e) => return Plan::Fail(e),
            };
            let session = match parse_login(&r) {
                Ok(Some(s)) => s,
                Ok(None) => return Plan::Fail(Error::service("Emby authentication failed")),
                Err(e) => return Plan::Fail(e),
            };
            session.save(store.as_ref());
            me.notify(session, ua, payload)
        })
        .context("login")
    }

    fn close(&self, ctx: &Context<'_>) -> Option<Plan> {
        let session = Session::load(ctx.store.as_ref())?;
        ctx.store.clear(&[SESSION_KEY]);
        Some(Plan::http(self.logout(ctx.app_id(), &session), |_| Plan::Done))
    }

    fn url_identifier(&self) -> UrlIdentifier {
        UrlIdentifier::Parts(self.id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests() {
        assert_eq!(crate::crypto::hex(&Md5::digest(b"l2gpass")), "6e91367d1f17ac820620de2c47d76da4");
        let e = Emby { name: "Emby", base: "http://h:8096".into(), user: "l2g".into(), password: None, modal: false, id: Vec::new() };
        assert_eq!(
            e.auth_header("Mercurio", true),
            format!(
                "MediaBrowser Client=\"Mercurio\", Device=\"Mercurio\", \
                 DeviceId=\"{}\", Version=\"{}\", UserId=\"l2g\"",
                device_id("Mercurio", "http://h:8096", "l2g"),
                env!("CARGO_PKG_VERSION")
            )
        );
    }

    #[test]
    fn device_id_is_stable_and_per_target() {
        let a = device_id("Mercurio", "http://h:8096", "l2g");
        assert_eq!(a, device_id("Mercurio", "http://h:8096", "l2g"));
        assert_eq!(a.len(), 36);
        assert_eq!(a, a.to_lowercase());
        let parts: Vec<&str> = a.split('-').collect();
        assert_eq!(parts.iter().map(|p| p.len()).collect::<Vec<_>>(), [8, 4, 4, 4, 12]);
        assert!(parts[2].starts_with('5'));
        assert!(matches!(parts[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b'));
        assert_ne!(a, device_id("Mercurio", "http://other:8096", "l2g"));
        assert_ne!(a, device_id("Mercurio", "http://h:8097", "l2g"));
        assert_ne!(a, device_id("Mercurio", "https://h:8096", "l2g"));
        assert_ne!(a, device_id("Mercurio", "http://h:8096", "bob"));
        assert_ne!(a, device_id("Other", "http://h:8096", "l2g"));
        assert_ne!(a, "48df9504-6843-49be-9f2d-a685e25a0bc8");
    }
}
