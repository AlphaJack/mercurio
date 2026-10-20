//! RingCentral (`ringc://`): SMS through the RingCentral API.
//!
//! Logs in (OAuth password or JWT grant) and sends one SMS/MMS per target. A token with a positive lifetime is kept in memory (a non-persistent store entry) and reused until it expires; [`Target::close`](crate::Target::close) revokes it.
//!
//! # Differences with Apprise
//!
//! - `?env=sandbox` sends to `platform.devtest.ringcentral.com` in Apprise -> mercurio rejects it: RingCentral retired that sandbox on 2025-01-01. *intentional*

use serde_json::{Value, json};

use super::_telephony::{Form, http_err, param_unquoted, unquote_or_empty, valid_phones};
use crate::crypto::b64;
use crate::error::Error;
use crate::http::Request;
use crate::message::Attachment;
use crate::parse::{is_phone_no, parse_phone_no_unquoted, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef, UrlIdentifier};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "ringcentral",
    name: "RingCentral",
    schemes: &["ringc"],
    service_url: "https://ringcentral.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    attachments: true,
    templates: &[
        "{schema}://{from_phone}:{token}@{client_id}/{secret}/",
        "{schema}://{from_phone}:{token}@{client_id}/{secret}/{targets}",
        "{schema}://{token}@{client_id}/{secret}/{from_phone}",
        "{schema}://{token}@{client_id}/{secret}/{from_phone}/{targets}",
    ],
    tokens: &[
        Param::new("client_id", "Client ID").required().secret().pattern("^[a-z0-9_-]+$"),
        Param::new("from_phone", "From Phone No").required(),
        Param::new("secret", "Client Secret").required().secret().pattern("^[a-z0-9_-]+$"),
        Param::new("target_phone", "Target Phone No").prefix("+"),
        Param::new("targets", "Targets").list("/").group(&["target_phone"]),
        Param::new("token", "Token / Password").required().secret(),
    ],
    params: &[
        Param::new("env", "Environment")
            .choice(&["prod"])
            .default("prod")
            .note("`sandbox` is rejected: RingCentral retired its sandbox on 2025-01-01"),
        Param::sets("from", &["from_phone"]),
        Param::new("mode", "Authentication Mode").choice(&["basic", "jwt"]),
        Param::sets("secret", &["secret"]),
        Param::sets("source", &["from_phone"]),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

const BASE_URL: &str = "https://platform.ringcentral.com/restapi";
const ACCESS_TOKEN_TTL: u32 = 3600;
const REFRESH_TOKEN_TTL: u32 = 604800;

#[derive(Debug, Clone)]
struct RingCentral {
    jwt: bool,
    client_id: String,
    client_secret: Secret,
    token: Secret,
    source: String,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let client_id = u.host();
    let mut client_secret = if targets.is_empty() { None } else { Some(targets.remove(0)) };
    let (mut source, mut token) = if u.password.as_deref().is_none_or(str::is_empty) {
        let s = if targets.is_empty() { None } else { Some(targets.remove(0)) };
        (s, unquote_or_empty(u.user.as_deref()))
    } else {
        (Some(unquote_or_empty(u.user.as_deref())), unquote_or_empty(u.password.as_deref()))
    };
    let environment = param_unquoted(u, "env");
    if let Some(t) = param_unquoted(u, "token") {
        token = t;
    }
    let mode = param_unquoted(u, "mode").unwrap_or_else(|| if token.chars().count() > 60 { "jwt" } else { "basic" }.to_string());
    if let Some(s) = param_unquoted(u, "secret") {
        client_secret = Some(s);
    }
    if let Some(s) = param_unquoted(u, "from") {
        source = Some(s);
    }
    if let Some(s) = param_unquoted(u, "source") {
        source = Some(s);
    }
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_phone_no_unquoted([to], false));
    }

    let m = mode.trim().to_lowercase();
    let jwt = match ["basic", "jwt"].iter().find(|x| !m.is_empty() && x.starts_with(&m)) {
        Some(&"jwt") => true,
        Some(_) => false,
        None => return Err(SERVICE.err("an invalid RingCentral Authentication Mode was specified")),
    };
    let client_id = validate_regex(&client_id, r"^[a-z0-9_-]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid RingCentral Client ID was specified"))?;
    let client_secret = client_secret
        .as_deref()
        .and_then(|s| validate_regex(s, r"^[a-z0-9_-]+$", "i", true))
        .ok_or_else(|| SERVICE.err("an invalid RingCentral Client Secret was specified"))?;
    let token = if jwt {
        validate_regex(&token, r"^[a-z0-9._-]+$", "i", true)
            .ok_or_else(|| SERVICE.err("an invalid RingCentral JWT Token was specified"))?
    } else {
        token
    };
    let source = source
        .as_deref()
        .and_then(|s| is_phone_no(s, 10))
        .ok_or_else(|| SERVICE.err("the RingCentral source (From) phone # is invalid"))?
        .full;
    let env = environment.map(|e| e.trim().to_lowercase()).unwrap_or_else(|| "prod".into());
    match ["prod", "sandbox"].iter().find(|x| !env.is_empty() && x.starts_with(&env)) {
        Some(&"prod") => {}
        Some(_) => {
            return Err(SERVICE.err(
                "the RingCentral sandbox (platform.devtest.ringcentral.com) was retired on 2025-01-01; \
                 remove ?env= to use production",
            ));
        }
        None => return Err(SERVICE.err("an invalid RingCentral environment was specified")),
    }
    Ok(Box::new(RingCentral {
        jwt,
        client_id,
        client_secret: Secret::new(client_secret),
        token: Secret::new(token),
        source,
        targets: valid_phones(&targets, 10),
    }))
}

impl RingCentral {
    fn oauth_request(&self, path: &str, user_agent: &str) -> Request {
        let creds = b64(format!("{}:{}", self.client_id, self.client_secret.expose()).as_bytes());
        Request::post(format!("{BASE_URL}/oauth/{path}"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Authorization", format!("Basic {creds}"))
            .header("User-Agent", user_agent)
            .header("Accept", "application/json")
    }

    /// Everything after a successful login.
    fn deliver(&self, access_token: &str, body: &str, attachments: &[Attachment], user_agent: &str) -> Plan {
        let mms = !attachments.is_empty();
        let url = format!("{BASE_URL}/v1.0/account/~/extension/~/{}", if mms { "mms" } else { "sms" });
        let targets = if self.targets.is_empty() { vec![self.source.clone()] } else { self.targets.clone() };
        Plan::all(targets.into_iter().map(|t| {
            let metadata = json!({
                "from": {"phoneNumber": format!("+{}", self.source)},
                "to": [{"phoneNumber": format!("+{t}")}],
                "text": body,
            });
            let req = Request::post(&url);
            let req = if mms {
                let mut form = Form::new().part(
                    "json",
                    None,
                    Some("application/json"),
                    serde_json::to_vec(&metadata).unwrap_or_default(),
                );
                for a in attachments {
                    form = form.part("attachment", Some(&a.name), Some(&a.mime), a.data.clone());
                }
                form.apply(req.header("Authorization", format!("Bearer {access_token}")))
            } else {
                req.header("Content-Type", "application/json")
                    .header("Authorization", format!("Bearer {access_token}"))
                    .json(&metadata)
            };
            let req = req.header("User-Agent", user_agent).header("Accept", "application/json");
            Plan::send_expect(req, &[200]).context("send").target(t)
        }))
    }
}

impl Notify for RingCentral {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let ua = ctx.app_id().to_string();
        let payload: Vec<(&str, String)> = if self.jwt {
            vec![
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer".into()),
                ("assertion", self.token.expose().into()),
            ]
        } else {
            vec![
                ("grant_type", "password".into()),
                ("username", format!("+{}", self.source)),
                ("password", self.token.expose().into()),
                ("access_token_ttl", ACCESS_TOKEN_TTL.to_string()),
                ("refresh_token_ttl", REFRESH_TOKEN_TTL.to_string()),
            ]
        };
        if let Some(token) = ctx.store.get_str("access_token").filter(|t| !t.is_empty()) {
            return self.deliver(&token, msg.body, msg.attachments, &ua);
        }
        let store = ctx.store();
        let login = self.oauth_request("token", &ua).form(&payload);
        let me = self.clone();
        let body = msg.body.to_string();
        let attachments = msg.attachments.to_vec();
        Plan::http(login, move |res| {
            let r = match res {
                Ok(r) => r,
                Err(e) => return Plan::Fail(e),
            };
            if r.status != 200 {
                return Plan::Fail(http_err(&r));
            }
            let content = match r.json() {
                Some(Value::Object(m)) => m,
                _ => return Plan::Fail(Error::Service("RingCentral login returned no access token".into())),
            };
            let expires_in = match content.get("expires_in") {
                None => 0.0,
                Some(v) => match v.as_f64() {
                    Some(f) => f,
                    None => return Plan::Fail(Error::Service("RingCentral login returned a bad expiry".into())),
                },
            };
            let token = match content.get("access_token") {
                Some(Value::String(s)) if !s.is_empty() => s.clone(),
                Some(v) if super::_telephony::has_value(v) => v.to_string(),
                _ => return Plan::Fail(Error::Service("RingCentral login returned no access token".into())),
            };
            // The token is reused until it expires and revoked on close under the same condition.
            if expires_in > 0.0 {
                let ttl = std::time::Duration::from_secs_f64(expires_in.min(1e9));
                store.remember("access_token", json!(token), Some(ttl));
            }
            me.deliver(&token, &body, &attachments, &ua)
        })
        .context("login")
    }

    fn close(&self, ctx: &Context<'_>) -> Option<Plan> {
        let token = ctx.store.get_str("access_token")?;
        ctx.store.clear(&["access_token"]);
        let logout = self.oauth_request("revoke", ctx.app_id()).form(&[("token", token.as_str())]);
        Some(Plan::http(logout, |_| Plan::Done))
    }

    fn url_identifier(&self) -> UrlIdentifier {
        UrlIdentifier::Parts(vec![
            "ringc".into(),
            self.client_id.clone(),
            self.client_secret.expose().to_string(),
            self.token.expose().to_string(),
            self.source.clone(),
        ])
    }

}
