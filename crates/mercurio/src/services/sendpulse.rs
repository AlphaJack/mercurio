//! SendPulse (`sendpulse://`): e-mail through the SendPulse API.
//!
//! `sendpulse://{user}@{domain}/{client_id}/{client_secret}[/{to_email}...]` `sendpulse://{to_domain}?id=..&secret=..&from=..` (`?user=` also accepted) `?from=..&cc=..&bcc=..&to=..&template={id}&+var=value`
//!
//! An OAuth access token (`POST /oauth/access_token`, client credentials) is obtained when the persistent store has none and kept there until it expires (`expires_in` minus 10 s, at most an hour). One e-mail is posted per target; a `401` triggers one re-login and retry.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Map, Value, json};

use super::_email_api::{attachment_b64, attachment_name, html_to_text};
use crate::crypto::b64;
use crate::http::{Request, Response};
use crate::parse::{is_email, parse_emails, validate_regex};
use crate::service::{Context, Notify, Param, Secret, ServiceDef, UrlIdentifier};
use crate::store::StoreRef;
use crate::url::{ParsedUrl, unquote};
use crate::{Error, NotifyFormat, Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "sendpulse",
    name: "SendPulse",
    schemes: &["sendpulse"],
    service_url: "https://sendpulse.com",
    parse,
    formats: &[NotifyFormat::Html, NotifyFormat::Text],
    attachments: true,
    throttle: Duration::from_millis(200),
    templates: &[
        "{schema}://{user}@{host}/{client_secret}/",
        "{schema}://{user}@{host}/{client_id}/{client_secret}/{targets}",
    ],
    tokens: &[
        Param::new("client_id", "Client ID").required().secret().pattern("^[A-Z0-9._-]+$"),
        Param::new("client_secret", "Client Secret").required().secret().pattern("^[A-Z0-9._-]+$"),
        Param::new("host", "Domain").required(),
        Param::new("target_email", "Target Email").email(),
        Param::new("targets", "Targets").list("/").group(&["target_email"]),
        Param::new("user", "User Name").required(),
    ],
    params: &[
        Param::new("bcc", "Blind Carbon Copy").list(", "),
        Param::new("cc", "Carbon Copy").list(", "),
        Param::new("from", "From Email"),
        Param::sets("id", &["client_id"]),
        Param::sets("secret", &["client_secret"]),
        Param::new("template", "Template ID").int(),
        Param::sets("to", &["targets"]),
        Param::new("template_data", "Template Data").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

const EMAIL_URL: &str = "https://api.sendpulse.com/smtp/emails";
const OAUTH_URL: &str = "https://api.sendpulse.com/oauth/access_token";
const TOKEN_EXPIRY_EDGE: i64 = 10;
/// Default token lifetime, in seconds.
const TOKEN_EXPIRY: i64 = 3600;
const KEY_RE: &str = r"^[A-Z0-9._-]+$";

/// A display name; `None` stands for the app id (only known at send time).
type Name = Option<String>;

#[derive(Debug)]
struct SendPulse {
    client_id: Secret,
    client_secret: Secret,
    from_addr: String,
    names: Vec<(String, Name)>,
    targets: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    template: Option<i64>,
    template_data: Vec<(String, String)>,
}

fn set_name(names: &mut Vec<(String, Name)>, email: &str, name: Name) {
    names.retain(|(k, _)| k != email);
    names.push((email.to_owned(), name));
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut host = u.host();
    let mut targets_in: Vec<String> = Vec::new();
    let mut from_param: Option<String> = None;
    if let Some(f) = u.param("from") {
        let f = unquote(f.trim_end());
        if is_email(&f).is_some() {
            targets_in.push(host.clone());
            host.clear();
        }
        from_param = Some(f);
    }
    if u.has_param("user") && is_email(&unquote(u.user.as_deref().unwrap_or(""))).is_some() {
        targets_in.push(host.clone());
        host.clear();
    }
    targets_in.extend(u.path_segments());
    let client_id = match SERVICE.text(u, "id") {
        Some(v) => Some(v),
        None if !targets_in.is_empty() => Some(targets_in.remove(0)),
        None => None,
    };
    let client_secret = match SERVICE.text(u, "secret") {
        Some(v) => Some(v),
        None if !targets_in.is_empty() => Some(targets_in.remove(0)),
        None => None,
    };
    if let Some(to) = u.param_nonempty("to") {
        targets_in.push(unquote(to));
    }
    let cc = SERVICE.text(u, "cc");
    let bcc = SERVICE.text(u, "bcc");

    let user = u.user().unwrap_or_default();
    let mut from: (Name, String) = (None, String::new());
    if !user.is_empty() {
        if !host.is_empty() {
            let local = crate::regex!(r"[\s@]+").split(&user).next().unwrap_or("").to_owned();
            from = (None, format!("{local}@{host}"));
        } else if let Some(e) = is_email(&user) {
            from = (if e.name.is_empty() { None } else { Some(e.name) }, user.clone());
        }
    }
    if let Some(f) = from_param {
        match is_email(&f) {
            Some(e) => from = (if e.name.is_empty() { from.0 } else { Some(e.name) }, e.full_email),
            None => from.0 = Some(f),
        }
    }
    if is_email(&from.1).is_none() {
        return Err(SERVICE.err("invalid ~From~ email specified"));
    }
    let mut names = Vec::new();
    set_name(&mut names, &from.1, from.0.clone());

    let client_id = client_id
        .and_then(|c| validate_regex(&c, KEY_RE, "i", true))
        .ok_or_else(|| SERVICE.err("an invalid SendPulse Client ID was specified"))?;
    let client_secret = client_secret
        .and_then(|c| validate_regex(&c, KEY_RE, "i", true))
        .ok_or_else(|| SERVICE.err("an invalid SendPulse Client Secret was specified"))?;

    let template = match SERVICE.text(u, "template") {
        Some(t) => Some(t.trim().parse::<i64>().ok().ok_or_else(|| SERVICE.err("the SendPulse Template ID is invalid"))?),
        None => None,
    };
    let template_data = u.query_plus.iter().map(|(k, v)| (k.to_owned(), v.to_owned())).collect();

    let mut targets = Vec::new();
    for r in parse_emails(&targets_in, true) {
        if let Some(e) = is_email(&r) {
            if !e.name.is_empty() {
                set_name(&mut names, &e.full_email, Some(e.name));
            }
            targets.push(e.full_email);
        }
    }
    let mut collect = |value: Option<String>| {
        let mut set: Vec<String> = Vec::new();
        for r in parse_emails(value, true) {
            if let Some(e) = is_email(&r) {
                if !e.name.is_empty() {
                    set_name(&mut names, &e.full_email, Some(e.name));
                }
                if !set.contains(&e.full_email) {
                    set.push(e.full_email);
                }
            }
        }
        set
    };
    let cc = collect(cc);
    let bcc = collect(bcc);
    if targets.is_empty() {
        targets.push(from.1.clone());
    }
    Ok(Box::new(SendPulse {
        client_id: Secret::new(client_id),
        client_secret: Secret::new(client_secret),
        from_addr: from.1,
        names,
        targets,
        cc,
        bcc,
        template,
        template_data,
    }))
}

/// Read the login response: the token and how long to keep it.
fn token_from(r: &Response) -> Result<(String, Duration)> {
    if !matches!(r.status, 200 | 202) {
        return Err(r.http_error());
    }
    let json = r.json().ok_or_else(|| Error::Service("invalid response from SendPulse server".into()))?;
    let obj = json.as_object().ok_or_else(|| Error::Service("invalid response from SendPulse server".into()))?;
    let token = obj.get("access_token").and_then(crate::util::scalar_text);
    let expires = match obj.get("expires_in") {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f.trunc() as i64)),
        Some(Value::String(s)) => s.trim().parse::<i64>().ok(),
        Some(Value::Bool(b)) => Some(*b as i64),
        _ => None,
    };
    let keep = match expires.map(|e| e - TOKEN_EXPIRY_EDGE) {
        Some(e) if e <= TOKEN_EXPIRY_EDGE => {
            return Err(Error::Service("SendPulse token expiry limit returned was invalid".into()));
        }
        Some(e) if e <= TOKEN_EXPIRY => e,
        _ => TOKEN_EXPIRY - TOKEN_EXPIRY_EDGE,
    };
    let token = token.ok_or_else(|| Error::Service("SendPulse returned no access token".into()))?;
    Ok((token, Duration::from_secs(keep as u64)))
}

/// Log in and keep the token in the store (the cached token is cleared first). A failed login reports `fail` when given (the error that prompted it).
fn login(
    req: Request,
    store: StoreRef,
    fail: Option<Error>,
    then: impl FnOnce(String) -> Plan + Send + 'static,
) -> Plan {
    store.clear(&["access_token"]);
    Plan::http(req, move |res| match res.and_then(|r| token_from(&r)) {
        Ok((t, keep)) => {
            store.set("access_token", json!(t), Some(keep));
            then(t)
        }
        Err(e) => Plan::Fail(fail.unwrap_or(e)),
    })
    .context("token")
}

impl SendPulse {
    fn name_of(&self, email: &str, app_id: &str) -> Option<String> {
        self.names.iter().find(|(k, _)| k == email).map(|(_, v)| v.clone().unwrap_or_else(|| app_id.to_owned()))
    }

    fn login_request(&self, app_id: &str) -> Request {
        Request::post(OAUTH_URL).header("User-Agent", app_id).header("Content-Type", "application/json").json(&json!({
            "grant_type": "client_credentials",
            "client_id": self.client_id.expose(),
            "client_secret": self.client_secret.expose(),
        }))
    }
}

type Token = Arc<Mutex<String>>;
/// The login request and the store the token goes to.
type Auth = (Request, StoreRef);

/// One e-mail post; on `401` log in again once and retry (`_fetch(retry=1)`).
fn send_email(payload: Arc<Value>, token: Token, auth: Auth, app_id: String, retry: bool) -> Plan {
    Plan::defer(move || {
        let bearer = token.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        let req = Request::post(EMAIL_URL)
            .header("User-Agent", app_id.as_str())
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {bearer}"))
            .json(&payload);
        Plan::http(req, move |res| {
            let r = match res {
                Ok(r) => r,
                Err(e) => return Plan::Fail(e),
            };
            if r.json().is_none() {
                return Plan::Fail(Error::Service("invalid response from SendPulse server".into()));
            }
            if r.status == 401 && retry {
                let fail = r.http_error();
                let (req, store) = auth.clone();
                return login(req, store, Some(fail), move |t| {
                    *token.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = t;
                    send_email(payload, token, auth, app_id, false)
                });
            }
            if matches!(r.status, 200 | 202) { Plan::Done } else { Plan::Fail(r.http_error()) }
        })
        .context("send")
    })
}

impl Notify for SendPulse {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let app_id = ctx.app_id().to_owned();
        let mut email = Map::new();
        email.insert("from".into(), json!({"name": self.name_of(&self.from_addr, &app_id), "email": self.from_addr}));
        email.insert("subject".into(), json!(if msg.title.is_empty() { "<no subject>" } else { msg.title }));
        if msg.format == NotifyFormat::Html {
            email.insert("text".into(), json!(html_to_text(msg.body)));
            email.insert("html".into(), json!(b64(msg.body.as_bytes())));
        } else {
            email.insert("text".into(), json!(msg.body));
        }
        if !msg.attachments.is_empty() {
            let mut atts = Map::new();
            for (i, a) in msg.attachments.iter().enumerate() {
                atts.insert(attachment_name(a, i, "dat"), json!(attachment_b64(a)));
            }
            email.insert("attachments_binary".into(), Value::Object(atts));
        }
        if let Some(t) = self.template {
            let vars: Map<String, Value> = self.template_data.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
            email.insert("template".into(), json!({"id": t, "variables": vars}));
        }
        let recipient = |e: &String| {
            let mut item = json!({"email": e});
            if let Some(n) = self.name_of(e, &app_id) {
                item["name"] = json!(n);
            }
            item
        };
        let mut payloads = Vec::new();
        for target in &self.targets {
            // Every cc/bcc entry is sent, built afresh for each target.
            let cc: Vec<Value> =
                self.cc.iter().filter(|e| !self.bcc.contains(e) && *e != target).map(recipient).collect();
            let bcc: Vec<Value> = self.bcc.iter().filter(|e| *e != target).map(recipient).collect();
            let mut email = email.clone();
            email.insert("to".into(), json!([recipient(target)]));
            if !cc.is_empty() {
                email.insert("cc".into(), Value::Array(cc));
            }
            if !bcc.is_empty() {
                email.insert("bcc".into(), Value::Array(bcc));
            }
            payloads.push((target.clone(), Arc::new(json!({"email": email}))));
        }

        let auth: Auth = (self.login_request(&app_id), ctx.store());
        let send_all = move |t: String| {
            let token = Arc::new(Mutex::new(t));
            Plan::all(
                payloads
                    .into_iter()
                    .map(|(target, p)| send_email(p, token.clone(), auth.clone(), app_id.clone(), true).target(target))
                    .collect::<Vec<_>>(),
            )
        };
        match ctx.store.get_str("access_token").filter(|t| !t.is_empty()) {
            Some(t) => send_all(t),
            None => {
                let (req, store) = (self.login_request(ctx.app_id()), ctx.store());
                login(req, store, None, send_all)
            }
        }
    }

    fn url_identifier(&self) -> UrlIdentifier {
        UrlIdentifier::parts(["sendpulse", self.client_id.expose(), self.client_secret.expose()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(url: &str) -> Result<Box<dyn Notify>> {
        parse(&crate::url::parse_url_unverified(url).unwrap())
    }

    #[test]
    fn validation() {
        assert!(p("sendpulse://abcd@host.com").is_err());
        assert!(p("sendpulse://user@example.com/client_id/cs/?template=invalid").is_err());
        assert!(p("sendpulse://?id=ci&secret=cs&user=chris").is_err());
    }

    #[test]
    fn token_parsing() {
        let r = |b: &str| Response::new(200, b.as_bytes().to_vec());
        assert_eq!(token_from(&r(r#"{"access_token":"abc","expires_in":3600}"#)).unwrap().0, "abc");
        assert_eq!(token_from(&r(r#"{"access_token":"abc"}"#)).unwrap().1, Duration::from_secs(3590));
        assert_eq!(token_from(&r(r#"{"access_token":"a","expires_in":99999}"#)).unwrap().1, Duration::from_secs(3590));
        assert_eq!(token_from(&r(r#"{"access_token":"a","expires_in":100}"#)).unwrap().1, Duration::from_secs(90));
        assert!(token_from(&r(r#"{"access_token":"abc","expires_in":20}"#)).is_err());
        assert!(token_from(&r(r#"{"expires_in":3600}"#)).is_err());
        assert!(token_from(&r("{")).is_err());
    }
}
