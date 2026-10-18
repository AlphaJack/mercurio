//! Office 365 / Microsoft Graph mail (`azure://`, `o365://`): e-mail through the Microsoft Graph API.
//!
//! Organisation (client credentials) mode: `o365://{source}/{tenant}/{client_id}/{secret}[/{to_email}...]` Personal (refresh token) mode, picked automatically for outlook.com, hotmail.*, live.* and msn.com senders or with `?mode=personal`: `o365://{source}/{client_id}/{refresh_token}[/{to_email}...]`
//!
//! `{source}` is the sender e-mail (or, in org mode, a user object id). Options: `?from=..&tenant=..&oauth_id=..&oauth_secret=..&to=..&cc=..&bcc=..` `&reply_to=..&mode=org|personal&savesent=yes|no`.
//!
//! The access token is kept (in memory) until `expires_in` minus 10 s, a rotated refresh token (personal mode) and the looked-up sender (org mode, `from` / `name`) go to the persistent store. Attachments above 3 MiB go through a draft + upload session.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Map, Value, json};

use super::_email_api::{attachment_b64, attachment_name, copy_list, email_pairs};
use crate::http::{Request, Response};
use crate::message::Attachment;
use crate::parse::{is_email, parse_list, validate_nonblank, validate_regex};
use crate::service::{Context, Notify, Param, Secret, ServiceDef, UrlIdentifier};
use crate::store::StoreRef;
use crate::url::{ParsedUrl, unquote};
use crate::util::{json_int, scalar_text};
use crate::{Error, NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "office365",
    name: "Office 365",
    schemes: &["azure", "o365"],
    service_url: "https://office.com/",
    parse,
    formats: &[NotifyFormat::Html],
    attachments: true,
    throttle: Duration::from_millis(200),
    templates: &[
        "{schema}://{source}/{tenant}/{client_id}/{secret}",
        "{schema}://{source}/{tenant}/{client_id}/{secret}/{targets}",
        "{schema}://{source}/{client_id}/{secret}",
        "{schema}://{source}/{client_id}/{secret}/{targets}",
    ],
    tokens: &[
        Param::new("client_id", "Client ID").required().secret().pattern("^[a-z0-9-]+$"),
        Param::new("secret", "Client Secret").required().secret(),
        Param::new("source", "Account Email or Object ID").required(),
        Param::new("target_email", "Target Email").email(),
        Param::new("targets", "Targets").list("/").group(&["target_email"]),
        Param::new("tenant", "Tenant Domain").required().secret().pattern("^[a-z0-9-]+$"),
    ],
    params: &[
        Param::new("bcc", "Blind Carbon Copy").list(", "),
        Param::new("cc", "Carbon Copy").list(", "),
        Param::new("mode", "Mode").choice(&["org", "personal"]).default("org").inferred(),
        Param::sets("oauth_id", &["client_id"]),
        Param::sets("oauth_secret", &["secret"]),
        Param::new("reply_to", "Reply To").list(", "),
        Param::new("savesent", "Save to Sent Items").bool(true),
        Param::sets("to", &["targets"]),
        Param::sets("from", &["source"]),
    ],
    ..ServiceDef::DEFAULTS
};

const GRAPH_URL: &str = "https://graph.microsoft.com";
const PERSONAL_AUTH_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
const PERSONAL_SCOPE: &str = "https://graph.microsoft.com/Mail.Send offline_access";
const INLINE_MAX: usize = 3_145_728;
const CHUNK_SIZE: usize = 5_242_880;

const PERSONAL_DOMAINS: &[&str] = &[
    "outlook.com",
    "outlook.at",
    "outlook.be",
    "outlook.ca",
    "outlook.cl",
    "outlook.co.nz",
    "outlook.co.uk",
    "outlook.com.ar",
    "outlook.com.au",
    "outlook.com.br",
    "outlook.com.mx",
    "outlook.cz",
    "outlook.de",
    "outlook.dk",
    "outlook.es",
    "outlook.fi",
    "outlook.fr",
    "outlook.hu",
    "outlook.ie",
    "outlook.in",
    "outlook.it",
    "outlook.jp",
    "outlook.kr",
    "outlook.lv",
    "outlook.my",
    "outlook.nl",
    "outlook.ph",
    "outlook.pt",
    "outlook.rs",
    "outlook.sa",
    "outlook.sg",
    "outlook.sk",
    "hotmail.com",
    "hotmail.at",
    "hotmail.be",
    "hotmail.ca",
    "hotmail.cl",
    "hotmail.co.uk",
    "hotmail.com.ar",
    "hotmail.com.au",
    "hotmail.com.br",
    "hotmail.com.mx",
    "hotmail.cz",
    "hotmail.de",
    "hotmail.dk",
    "hotmail.es",
    "hotmail.fi",
    "hotmail.fr",
    "hotmail.gr",
    "hotmail.hu",
    "hotmail.ie",
    "hotmail.it",
    "hotmail.nl",
    "hotmail.no",
    "hotmail.pt",
    "hotmail.rs",
    "hotmail.se",
    "live.at",
    "live.be",
    "live.ca",
    "live.cl",
    "live.co.nz",
    "live.co.uk",
    "live.com",
    "live.com.ar",
    "live.com.au",
    "live.com.mx",
    "live.de",
    "live.dk",
    "live.es",
    "live.fi",
    "live.fr",
    "live.gr",
    "live.hu",
    "live.ie",
    "live.in",
    "live.it",
    "live.jp",
    "live.mx",
    "live.my",
    "live.nl",
    "live.no",
    "live.ph",
    "live.pt",
    "live.rs",
    "live.se",
    "live.sg",
    "msn.com",
];

#[derive(Debug, Clone)]
struct Config {
    personal: bool,
    source: String,
    tenant: Option<String>,
    client_id: String,
    secret: Secret,
    save_sent: bool,
    targets: Vec<(String, String)>,
    cc: Vec<String>,
    bcc: Vec<String>,
    reply_to: Vec<String>,
    names: Vec<(String, String)>,
    from_email: Option<String>,
    from_name: Option<String>,
    source_is_object_id: bool,
    inline_max: usize,
}

#[derive(Debug)]
struct Office365(Arc<Config>);

fn is_personal_source(source: &str) -> bool {
    is_email(source).is_some_and(|e| PERSONAL_DOMAINS.contains(&e.domain.to_lowercase().as_str()))
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    Ok(Box::new(Office365(Arc::new(parse_config(u)?))))
}

fn parse_config(u: &ParsedUrl) -> Result<Config> {
    let mut entries = u.path_segments();
    let source = if let Some(f) = u.param_nonempty("from") {
        unquote(f)
    } else if u.user.as_deref().is_some_and(|s| !s.is_empty()) {
        format!("{}@{}", u.user().unwrap_or_default(), u.host())
    } else {
        u.host()
    };
    let personal = match u.param_nonempty("mode").map(str::to_lowercase).as_deref() {
        Some("personal") => true,
        Some("org") => false,
        _ => is_personal_source(&source),
    };
    let mut tenant = None;
    if !personal {
        if let Some(t) = u.param_nonempty("tenant") {
            tenant = Some(unquote(t));
        } else if !entries.is_empty() {
            tenant = Some(unquote(&entries.remove(0)));
        }
    }
    let client_id = match u.param_nonempty("oauth_id") {
        Some(c) => Some(unquote(c)),
        None if !entries.is_empty() => Some(unquote(&entries.remove(0))),
        None => None,
    };
    let mut targets_in = Vec::new();
    while let Some(last) = entries.last() {
        let entry = unquote(last);
        if is_email(&entry).is_none() {
            break;
        }
        targets_in.push(entry);
        entries.pop();
    }
    let secret = SERVICE.text(u, "oauth_secret").unwrap_or_else(|| entries.iter().map(|e| unquote(e)).collect::<Vec<_>>().join("/"));
    if let Some(to) = u.param_nonempty("to") {
        targets_in.extend(parse_list([to]));
    }

    let client_id = client_id
        .and_then(|c| validate_regex(&c, r"^[a-z0-9-]+$", "i", true))
        .ok_or_else(|| SERVICE.err("an invalid Office 365 Client OAuth2 ID was specified"))?;
    let secret = validate_nonblank(&secret)
        .ok_or_else(|| SERVICE.err("an invalid Office 365 Client OAuth2 Secret was specified"))?;
    let tenant = if personal {
        None
    } else {
        Some(
            tenant
                .and_then(|t| validate_regex(&t, r"^[a-z0-9-]+$", "i", true))
                .ok_or_else(|| SERVICE.err("an invalid Office 365 Tenant was specified"))?,
        )
    };
    let save_sent = SERVICE.flag(u, "savesent");

    let targets = if targets_in.is_empty() {
        is_email(&source).map(|_| (String::new(), source.clone())).into_iter().collect()
    } else {
        email_pairs(&targets_in)
    };
    let mut names = Vec::new();
    let cc = copy_list(&mut names, u.param_nonempty("cc"));
    let bcc = copy_list(&mut names, u.param_nonempty("bcc"));
    let reply_to = copy_list(&mut names, u.param_nonempty("reply_to"));

    let src = is_email(&source);
    let (from_email, from_name, source_is_object_id) = if personal {
        let e = src.ok_or_else(|| SERVICE.err("a valid source email address is required for personal mode"))?;
        (Some(e.full_email), Some(e.name).filter(|n| !n.is_empty()), false)
    } else {
        match src {
            Some(e) => (Some(e.full_email), Some(e.name).filter(|n| !n.is_empty()), false),
            None => (
                None,
                None,
                validate_regex(&source, r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$", "i", true).is_some(),
            ),
        }
    };
    Ok(Config {
        personal,
        source,
        tenant,
        client_id,
        secret: Secret::new(secret),
        save_sent,
        targets,
        cc,
        bcc,
        reply_to,
        names,
        from_email,
        from_name,
        source_is_object_id,
        inline_max: INLINE_MAX,
    })
}

/// Mutable per-send state (the token outlives the send through a non-persistent store entry).
struct State {
    cfg: Arc<Config>,
    app_id: String,
    token: Option<String>,
    store: StoreRef,
}

const TOKEN_KEY: &str = "access_token";

type Shared = Arc<Mutex<State>>;
type Cont = Box<dyn FnOnce(bool) -> Plan + Send>;

/// Success: 200, 201 or 202. The body is parsed leniently.
fn fetch_ok(res: Result<Response>) -> Option<Value> {
    match res {
        Ok(r) if matches!(r.status, 200..=202) => Some(r.json().unwrap_or_else(|| json!({}))),
        _ => None,
    }
}

fn json_request(st: &State, req: Request) -> Request {
    let req = req.header("User-Agent", st.app_id.as_str()).header("Content-Type", "application/json");
    match &st.token {
        Some(t) => req.header("Authorization", format!("Bearer {t}")),
        None => req,
    }
}

/// Reuse a valid token or log in, then continue.
fn ensure_auth(shared: Shared, k: Cont) -> Plan {
    let req = {
        let mut st = shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(t) = st.store.get_str(TOKEN_KEY) {
            st.token = Some(t);
            drop(st);
            return k(true);
        }
        let cfg = &st.cfg;
        let (url, form): (String, Vec<(&str, String)>) = if cfg.personal {
            (
                PERSONAL_AUTH_URL.into(),
                vec![
                    ("grant_type", "refresh_token".into()),
                    ("client_id", cfg.client_id.clone()),
                    (
                        "refresh_token",
                        st.store
                            .get_str("refresh_token")
                            .filter(|t| !t.is_empty())
                            .unwrap_or_else(|| cfg.secret.expose().into()),
                    ),
                    ("scope", PERSONAL_SCOPE.into()),
                ],
            )
        } else {
            (
                format!("https://login.microsoftonline.com/{}/oauth2/v2.0/token", cfg.tenant.as_deref().unwrap_or("")),
                vec![
                    ("grant_type", "client_credentials".into()),
                    ("client_id", cfg.client_id.clone()),
                    ("client_secret", cfg.secret.expose().into()),
                    ("scope", format!("{GRAPH_URL}/.default")),
                ],
            )
        };
        Request::post(url)
            .header("User-Agent", st.app_id.as_str())
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&form)
    };
    Plan::http(req, move |res| {
        let Some(body) = fetch_ok(res) else { return k(false) };
        let mut st = shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        st.token = None;
        let Some(obj) = body.as_object() else {
            drop(st);
            return k(false);
        };
        let Some(secs) = obj.get("expires_in").and_then(json_int) else {
            drop(st);
            return k(false);
        };
        let secs = secs - 10;
        if st.cfg.personal
            && let Some(r) = obj.get("refresh_token").and_then(scalar_text)
        {
            st.store.set("refresh_token", json!(r), None);
        }
        st.token = obj.get("access_token").and_then(scalar_text);
        match &st.token {
            Some(t) if secs > 0 => {
                st.store.remember(TOKEN_KEY, json!(t), Some(Duration::from_secs(secs as u64)));
            }
            _ => {
                st.store.clear(&[TOKEN_KEY]);
            }
        }
        let ok = st.token.is_some();
        drop(st);
        k(ok)
    })
}

fn auth_failed() -> Plan {
    Plan::Fail(Error::Service("Office 365 authentication failed".into()).context("token"))
}

impl Notify for Office365 {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let cfg = self.0.clone();
        if cfg.targets.is_empty() {
            return Plan::Fail(Error::Service("there are no Email recipients to notify".into()));
        }
        let store = ctx.store();
        let shared: Shared = Arc::new(Mutex::new(State {
            cfg: cfg.clone(),
            app_id: ctx.app_id().to_string(),
            token: None,
            store: store.clone(),
        }));
        let message = Message {
            subject: msg.title.to_string(),
            body: msg.body.to_string(),
            html: msg.format == NotifyFormat::Html,
            attachments: msg.attachments.to_vec(),
        };
        // Org mode: the sender comes from the URL or from an earlier lookup (`false`: the lookup gave nothing usable; not tried again).
        let (from_email, from_name) = if cfg.personal {
            (cfg.from_email.clone().map(Value::String), cfg.from_name.clone())
        } else {
            let stored_name = store.get_str("name").filter(|n| !n.is_empty());
            match &cfg.from_email {
                Some(e) => (Some(Value::String(e.clone())), cfg.from_name.clone().or(stored_name)),
                None => (store.get_some("from"), stored_name),
            }
        };
        if !cfg.personal && from_email.is_none() {
            let sh = shared.clone();
            return ensure_auth(
                shared,
                Box::new(move |ok| {
                    if !ok {
                        return auth_failed();
                    }
                    let req = {
                        let st = sh.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        json_request(&st, Request::get(format!("{GRAPH_URL}/v1.0/users/{}", cfg.source)))
                            .body(b"null".to_vec(), None)
                    };
                    Plan::http(req, move |res| match fetch_ok(res) {
                        None if cfg.source_is_object_id => {
                            Plan::Fail(Error::Service("the Office 365 object id could not be resolved".into()))
                        }
                        None => deliver(sh, message, None),
                        Some(Value::Object(o)) => {
                            let found = o.get("mail").and_then(scalar_text).or_else(|| o.get("userPrincipalName").and_then(scalar_text));
                            match found.as_deref().and_then(is_email) {
                                Some(e) => {
                                    let name = o.get("displayName").and_then(scalar_text);
                                    store.set("from", json!(e.full_email), None);
                                    if let Some(n) = &name {
                                        store.set("name", json!(n), None);
                                    }
                                    deliver(sh, message, Some((e.full_email, name)))
                                }
                                None => {
                                    store.remember("from", Value::Bool(false), None);
                                    deliver(sh, message, None)
                                }
                            }
                        }
                        Some(_) => Plan::Fail(Error::Service("unexpected Office 365 user lookup response".into())),
                    })
                    .context("user lookup")
                }),
            );
        }
        let from = from_email.and_then(|e| e.as_str().map(str::to_string)).map(|e| (e, from_name));
        deliver(shared, message, from)
    }

    fn url_identifier(&self) -> UrlIdentifier {
        let c = &self.0;
        let mut parts = vec!["azure".to_string(), c.source.clone()];
        if let Some(t) = c.tenant.as_ref().filter(|_| !c.personal) {
            parts.push(t.clone());
        }
        parts.push(c.client_id.clone());
        parts.push(c.secret.expose().to_string());
        UrlIdentifier::Parts(parts)
    }
}

/// The message as needed by the deferred continuations.
#[derive(Clone)]
struct Message {
    subject: String,
    body: String,
    html: bool,
    attachments: Vec<Attachment>,
}

struct Prepared365 {
    large: Vec<(String, Attachment)>,
    send_url: String,
    draft_url: String,
    base: String,
}

fn deliver(shared: Shared, msg: Message, from: Option<(String, Option<String>)>) -> Plan {
    let (cfg, app_id) = {
        let st = shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        (st.cfg.clone(), st.app_id.clone())
    };
    let mut message = Map::new();
    message.insert("subject".into(), json!(msg.subject));
    message.insert("body".into(), json!({"contentType": if msg.html { "HTML" } else { "Text" }, "content": msg.body}));
    if let Some((email, name)) = &from {
        message.insert(
            "from".into(),
            json!({"emailAddress": {"address": email, "name": name.clone().unwrap_or_else(|| app_id.clone())}}),
        );
    }
    let name_of = |a: &String| cfg.names.iter().find(|(k, _)| k == a).map(|(_, v)| v.clone()).filter(|n| !n.is_empty());
    let addr = |a: &String| {
        let mut e = json!({"address": a});
        if let Some(n) = name_of(a) {
            e["name"] = json!(n);
        }
        json!({"emailAddress": e})
    };
    if !cfg.reply_to.is_empty() {
        message.insert("replyTo".into(), Value::Array(cfg.reply_to.iter().map(addr).collect()));
    }
    let mut small = Vec::new();
    let mut large = Vec::new();
    for (i, a) in msg.attachments.iter().enumerate() {
        let name = attachment_name(a, i, "dat");
        if a.data.len() > cfg.inline_max {
            large.push((name, a.clone()));
            continue;
        }
        small.push(json!({
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": name,
            "contentType": a.mime,
            "contentBytes": attachment_b64(a),
        }));
    }
    if !small.is_empty() {
        message.insert("attachments".into(), Value::Array(small));
    }
    let base =
        if cfg.personal { format!("{GRAPH_URL}/v1.0/me") } else { format!("{GRAPH_URL}/v1.0/users/{}", cfg.source) };

    let mut per_target = Vec::new();
    for (name, to) in &cfg.targets {
        let mut m = message.clone();
        let mut recipient = json!({"address": to});
        if !name.is_empty() {
            recipient["name"] = json!(name);
        }
        m.insert("toRecipients".into(), json!([{"emailAddress": recipient}]));
        // Each target gets a fresh payload: cc/bcc never leak between targets.
        let cc: Vec<Value> = cfg.cc.iter().filter(|e| !cfg.bcc.contains(e) && *e != to).map(addr).collect();
        let bcc: Vec<Value> = cfg.bcc.iter().filter(|e| *e != to).map(addr).collect();
        if !cc.is_empty() {
            m.insert("ccRecipients".into(), Value::Array(cc));
        }
        if !bcc.is_empty() {
            m.insert("bccRecipients".into(), Value::Array(bcc));
        }
        let payload = json!({"message": m, "saveToSentItems": if cfg.save_sent { "true" } else { "false" }});
        per_target.push((to.clone(), payload));
    }
    let prep = Arc::new(Prepared365 {
        large,
        send_url: format!("{base}/sendMail"),
        draft_url: format!("{base}/messages"),
        base,
    });
    next_target(shared, prep, per_target, 0)
}

/// The per-target loop: authenticate (stop on failure), send, keep going after per-target failures.
fn next_target(shared: Shared, prep: Arc<Prepared365>, targets: Vec<(String, Value)>, idx: usize) -> Plan {
    if idx >= targets.len() {
        return Plan::Done;
    }
    let sh = shared.clone();
    ensure_auth(
        shared,
        Box::new(move |ok| {
            if !ok {
                return auth_failed();
            }
            let (label, payload) = targets[idx].clone();
            let one = send_one(sh.clone(), prep.clone(), payload).target(label);
            Plan::all([one, Plan::defer(move || next_target(sh, prep, targets, idx + 1))])
        }),
    )
}

fn send_one(shared: Shared, prep: Arc<Prepared365>, payload: Value) -> Plan {
    let url = if prep.large.is_empty() { prep.send_url.clone() } else { prep.draft_url.clone() };
    let req = json_request(&shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner), Request::post(url))
        .json(&payload);
    Plan::http(req, move |res| {
        let res = match res {
            Ok(r) if !matches!(r.status, 200..=202) => {
                return Plan::Fail(r.http_error_with("Office 365 delivery failed"));
            }
            Err(e) => return Plan::Fail(e),
            ok => ok,
        };
        let Some(body) = fetch_ok(res) else {
            return Plan::Fail(Error::Service("Office 365 delivery failed".into()));
        };
        if prep.large.is_empty() {
            return Plan::Done;
        }
        let Some(id) = body.as_object().and_then(|o| o.get("id").and_then(scalar_text)) else {
            return Plan::Fail(Error::Service("Email Draft ID could not be retrieved".into()));
        };
        upload_all(shared, prep, id, 0)
    })
    .context("send")
}

fn upload_all(shared: Shared, prep: Arc<Prepared365>, id: String, idx: usize) -> Plan {
    if idx >= prep.large.len() {
        let url = format!("{}/messages/{id}/send", prep.base);
        let req = json_request(&shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner), Request::post(url))
            .body(b"null".to_vec(), None);
        return Plan::http(req, |res| match fetch_ok(res) {
            Some(_) => Plan::Done,
            None => Plan::Fail(Error::Service("could not send drafted Office 365 email".into())),
        })
        .context("send");
    }
    let sh = shared.clone();
    ensure_auth(
        shared,
        Box::new(move |ok| {
            if !ok {
                return Plan::Fail(Error::Service("could not prepare Office 365 attachment session".into()).context("token"));
            }
            let (name, att) = prep.large[idx].clone();
            let url = format!("{}/message/{id}/attachments/createUploadSession", prep.base);
            let payload = json!({"AttachmentItem": {
                "attachmentType": "file",
                "name": name,
                "contentType": att.mime,
                "size": att.data.len(),
            }});
            let req = json_request(&sh.lock().unwrap_or_else(std::sync::PoisonError::into_inner), Request::post(url))
                .json(&payload);
            Plan::http(req, move |res| {
                let upload_url =
                    fetch_ok(res).and_then(|b| b.as_object().and_then(|o| o.get("uploadUrl").and_then(scalar_text)));
                let Some(upload_url) = upload_url else {
                    return Plan::Fail(Error::Service("could not prepare Office 365 attachment session".into()));
                };
                upload_chunks(sh, prep, id, idx, upload_url, att, 0)
            })
            .context("upload")
        }),
    )
}

fn upload_chunks(
    shared: Shared,
    prep: Arc<Prepared365>,
    id: String,
    idx: usize,
    upload_url: String,
    att: Attachment,
    start: usize,
) -> Plan {
    let total = att.data.len();
    if start >= total {
        return upload_all(shared, prep, id, idx + 1);
    }
    let end = (start + CHUNK_SIZE).min(total);
    let req = {
        let st = shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut req = Request::put(upload_url.clone())
            .header("User-Agent", st.app_id.as_str())
            .header("Content-Range", format!("bytes {start}-{}/{total}", end - 1));
        if let Some(t) = &st.token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        req.body(att.data[start..end].to_vec(), None)
    };
    Plan::http(req, move |res| match fetch_ok(res) {
        Some(_) => upload_chunks(shared, prep, id, idx, upload_url, att, end),
        None => Plan::Fail(Error::Service("could not upload Office 365 attachment".into())),
    })
    .context("upload")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeTransport;

    fn cfg(url: &str) -> Result<Config> {
        let opts = crate::url::ParseOptions { verify_host: false, ..Default::default() };
        parse_config(&crate::url::parse_url_with(url, opts).unwrap())
    }

    fn p(url: &str) -> Result<Box<dyn Notify>> {
        cfg(url).map(|c| Box::new(Office365(Arc::new(c))) as Box<dyn Notify>)
    }

    #[test]
    fn modes() {
        assert!(p("o365://user@live.com/client-id/token/").is_ok());
        assert!(p("o365://user@example.com/client-id/token/?mode=personal").is_ok());
        assert!(p("o365://user@example.com/client-id/token/").is_err(), "org mode needs a tenant");
        assert!(p("o365://user@live.com/tenant-id/client-id/token/?mode=org").is_ok());
    }

    #[test]
    fn large_attachment_uses_upload_session() {
        let mut c = cfg("o365://user@example.com/tenant/ab-cd/secret/to@example.com").unwrap();
        c.inline_max = 4;
        let svc = Office365(Arc::new(c));
        let fake = FakeTransport::new();
        fake.respond_with(Response::new(200, br#"{"access_token":"tok","expires_in":3600}"#.to_vec()));
        fake.respond_with(Response::new(201, br#"{"id":"MSG1"}"#.to_vec()));
        fake.respond_with(Response::new(200, br#"{"uploadUrl":"https://upload.example/u"}"#.to_vec()));
        fake.respond_with(Response::new(200, b"{}".to_vec()));
        fake.respond_with(Response::new(202, b"".to_vec()));
        let att = [Attachment::new("big.bin", "application/octet-stream", vec![1u8; 10])];
        let msg = Prepared {
            title: "t",
            body: "b",
            kind: crate::NotifyType::Info,
            format: NotifyFormat::Html,
            passthrough: false,
            input_format: None,
            attachments: &att,
            message: &crate::Message::new("b"),
            index: 0,
            total: 1,
        };
        let asset = crate::Asset::default();
        let (store, memo) = (crate::PersistentStore::memory().shared(), crate::Memo::disabled());
        let plan = svc.plan(&msg, &Context::new(&asset, &store, &memo));
        let d = crate::plan::execute(plan, &fake, Default::default());
        assert!(d.is_success(), "{d:?}");
        let reqs = fake.requests();
        assert_eq!(reqs.len(), 5);
        assert!(reqs[1].url.ends_with("/v1.0/users/user@example.com/messages"));
        assert!(reqs[2].url.ends_with("/message/MSG1/attachments/createUploadSession"));
        assert_eq!(reqs[3].url, "https://upload.example/u");
        assert_eq!(reqs[3].header_value("Content-Range"), Some("bytes 0-9/10"));
        assert!(reqs[4].url.ends_with("/messages/MSG1/send"));
        assert_eq!(reqs[4].header_value("Authorization"), Some("Bearer tok"));
    }

    #[test]
    fn auth_failure_stops_everything() {
        let n = p("o365://user@example.com/tenant/ab-cd/secret/a@example.com/b@example.com").unwrap();
        let fake = FakeTransport::new();
        fake.respond_with(Response::new(400, b"{}".to_vec()));
        let msg = Prepared {
            title: "t",
            body: "b",
            kind: crate::NotifyType::Info,
            format: NotifyFormat::Html,
            passthrough: false,
            input_format: None,
            attachments: &[],
            message: &crate::Message::new("b"),
            index: 0,
            total: 1,
        };
        let asset = crate::Asset::default();
        let (store, memo) = (crate::PersistentStore::memory().shared(), crate::Memo::disabled());
        let d = crate::plan::execute(n.plan(&msg, &Context::new(&asset, &store, &memo)), &fake, Default::default());
        assert!(!d.is_success());
        assert_eq!(fake.requests().len(), 1);
    }
}
