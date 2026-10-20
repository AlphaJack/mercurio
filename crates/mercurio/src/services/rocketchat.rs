//! Rocket.Chat (`rocket://`, `rockets://`): messages to Rocket.Chat channels and users.
//!
//! Webhook URLs (`rocket://[user:]abc/def@host`) put a `/` inside the userinfo; the raw URL is rewritten and parsed again.

use serde_json::{Value, json};

use crate::asset::ImageSize;
use crate::http::Request;
use crate::parse::{parse_bool, parse_list};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParseOptions, ParsedUrl, parse_url_with, unquote};
use crate::{Error, NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "rocketchat",
    name: "Rocket.Chat",
    schemes: &["rocket", "rockets"],
    service_url: "https://rocket.chat/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 1000, body_max_line_count: 0 },
    formats: &[NotifyFormat::Markdown],
    templates: &[
        "{schema}://{user}:{password}@{host}:{port}/{targets}",
        "{schema}://{user}:{password}@{host}/{targets}",
        "{schema}://{user}:{token}@{host}:{port}/{targets}",
        "{schema}://{user}:{token}@{host}/{targets}",
        "{schema}://{webhook}@{host}",
        "{schema}://{webhook}@{host}:{port}",
        "{schema}://{webhook}@{host}/{targets}",
        "{schema}://{webhook}@{host}:{port}/{targets}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("password", "Password").secret(),
        Param::new("port", "Port").port(),
        Param::new("target_channel", "Target Channel").prefix("#"),
        Param::new("target_room", "Target Room ID"),
        Param::new("target_user", "Target User").prefix("@"),
        Param::new("targets", "Targets").list("/").group(&["target_channel", "target_room", "target_user"]),
        Param::new("token", "API Token").secret(),
        Param::new("user", "Username"),
        Param::new("webhook", "Webhook"),
    ],
    params: &[
        Param::new("avatar", "Use Avatar").bool(false).inferred(),
        Param::new("mode", "Webhook Mode").choice(&["webhook", "token", "basic"]),
        Param::sets("to", &["targets"]),
        Param::sets("webhook", &["webhook"]),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Webhook,
    Token,
    Basic,
}

#[derive(Debug)]
struct RocketChat {
    api_url: String,
    mode: Mode,
    user: Option<String>,
    password: Option<Secret>,
    webhook: Option<Secret>,
    channels: Vec<String>,
    rooms: Vec<String>,
    users: Vec<String>,
    avatar: bool,
}

fn parse(raw: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let invalid = || SERVICE.err("invalid Rocket.Chat URL");
    let re = crate::regex!(
        r"(?i)^\s*(?P<schema>[^:]+://)((?P<user>[^:]+):)?(?P<webhook>[a-z0-9]+(/|%2F)[a-z0-9]+)@(?P<url>.+)\n?\z"
    );
    let m = re.captures(&raw.original);
    let u = match &m {
        Some(c) => {
            let user = c.name("user").map(|u| format!("{}@", u.as_str())).unwrap_or_default();
            parse_url_with(&format!("{}{user}{}", &c["schema"], &c["url"]), ParseOptions::default())
        }
        None => parse_url_with(&raw.original, ParseOptions::default()),
    }
    .ok_or_else(invalid)?;

    let mut webhook = None;
    let mut password = u.password();
    if let Some(c) = &m {
        webhook = Some(unquote(&c["webhook"]));
        password = Some(unquote(&c["webhook"]));
    }
    let mut targets = u.path_segments();
    let mode = SERVICE.text(&u, "mode");
    let avatar = u.param_nonempty("avatar").map(|a| parse_bool(a, false));
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }
    if let Some(w) = u.param_nonempty("webhook") {
        webhook = Some(unquote(w));
    }
    let user = u.user().filter(|s| !s.is_empty());
    let password = password.filter(|s| !s.is_empty());

    let mode = match mode.map(|m| m.to_lowercase()).as_deref() {
        Some("webhook") => Mode::Webhook,
        Some("token") => Mode::Token,
        Some("basic") => Mode::Basic,
        Some(_) => return Err(SERVICE.err("the authentication mode specified is invalid")),
        None if webhook.is_some() => Mode::Webhook,
        None if password.as_ref().is_some_and(|p| p.chars().count() > 32) => Mode::Token,
        None => Mode::Basic,
    };
    match mode {
        Mode::Basic | Mode::Token if user.is_none() || password.is_none() => {
            return Err(SERVICE.err("no Rocket.Chat user/password was specified"));
        }
        Mode::Webhook if webhook.as_deref().is_none_or(str::is_empty) => {
            return Err(SERVICE.err("no Rocket.Chat Incoming Webhook was specified"));
        }
        Mode::Webhook | Mode::Token | Mode::Basic => {}
    }
    let (mut channels, mut rooms, mut users) = (Vec::new(), Vec::new(), Vec::new());
    for t in parse_list(targets) {
        if let Some(c) = crate::regex!(r"^#(?P<name>[A-Za-z0-9_-]+)$").captures(&t) {
            channels.push(c["name"].to_string());
        } else if crate::regex!(r"^[A-Za-z0-9]+$").is_match(&t) {
            rooms.push(t);
        } else if let Some(c) = crate::regex!(r"^@(?P<name>[A-Za-z0-9._-]+)$").captures(&t) {
            users.push(c["name"].to_string());
        }
    }
    if mode == Mode::Basic && rooms.is_empty() && channels.is_empty() {
        return Err(SERVICE.err("no Rocket.Chat room and/or channels specified to notify"));
    }
    let avatar = avatar.unwrap_or(mode != Mode::Basic);
    let mut api_url = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = u.port {
        api_url.push_str(&format!(":{p}"));
    }
    Ok(Box::new(RocketChat {
        api_url,
        mode,
        user,
        password: password.map(Secret::new),
        webhook: webhook.map(Secret::new),
        channels,
        rooms,
        users,
        avatar,
    }))
}

/// Auth headers; `None` values are dropped by requests, non-strings make it raise.
type AuthHeaders = Vec<(&'static str, Value)>;

fn post(api_url: &str, path: &str, auth: &AuthHeaders, ua: &str, payload: &Value) -> Plan {
    let mut req = Request::post(format!("{api_url}/{path}"));
    for (k, v) in auth {
        match v {
            Value::Null => {}
            Value::String(s) => req = req.header(*k, s.as_str()),
            Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => {
                return Plan::Fail(Error::transport("invalid Rocket.Chat auth header value"));
            }
        }
    }
    let req = req.header("User-Agent", ua).json(payload);
    Plan::send_expect(req, &[200])
}

impl RocketChat {
    fn sends(&self, base: &Value, auth: &AuthHeaders, ua: &str, path: &str, webhook: bool) -> Vec<Plan> {
        let mut plans = Vec::new();
        let named = self.users.iter().map(|u| format!("@{u}")).chain(self.channels.iter().map(|c| format!("#{c}")));
        for t in named {
            let mut p = base.clone();
            p["channel"] = json!(t);
            plans.push(post(&self.api_url, path, auth, ua, &p).target(t));
        }
        for r in &self.rooms {
            let mut p = base.clone();
            p[if webhook { "channel" } else { "roomId" }] = json!(r);
            plans.push(post(&self.api_url, path, auth, ua, &p).target(r.clone()));
        }
        plans
    }
}

impl Notify for RocketChat {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let ua = ctx.app_id().to_string();
        let mut payload = json!({"text": msg.body});
        if self.avatar
            && let Some(img) = ctx.asset.image_url(msg.kind, ImageSize::Xy128)
        {
            payload["avatar"] = json!(img);
        }
        match self.mode {
            Mode::Webhook => {
                let path = format!("hooks/{}", self.webhook.as_ref().map_or("", Secret::expose));
                let plans = self.sends(&payload, &Vec::new(), &ua, &path, true);
                if plans.is_empty() { post(&self.api_url, &path, &Vec::new(), &ua, &payload) } else { Plan::all(plans) }
            }
            Mode::Token => {
                let auth: AuthHeaders = vec![
                    ("X-User-Id", json!(self.user.as_deref().unwrap_or(""))),
                    ("X-Auth-Token", json!(self.password.as_ref().map_or("", Secret::expose))),
                ];
                Plan::all(self.sends(&payload, &auth, &ua, "api/v1/chat.postMessage", false))
            }
            Mode::Basic => {
                let user = self.user.clone().unwrap_or_default();
                let pass = self.password.as_ref().map_or("", Secret::expose).to_string();
                let login = Request::post(format!("{}/api/v1/login", self.api_url))
                    .form(&[("username", user.as_str()), ("password", pass.as_str())]);
                let api_url = self.api_url.clone();
                let this = Sends {
                    users: self.users.clone(),
                    channels: self.channels.clone(),
                    rooms: self.rooms.clone(),
                };
                Plan::http(login, move |res| {
                    let r = match res {
                        Ok(r) => r,
                        Err(e) => return Plan::Fail(e),
                    };
                    if r.status != 200 {
                        return Plan::Fail(r.http_error());
                    }
                    let fail = || Plan::Fail(Error::service("could not authenticate with Rocket.Chat"));
                    let Some(resp) = r.json() else { return fail() };
                    let Some(obj) = resp.as_object() else { return fail() };
                    if obj.get("status").and_then(Value::as_str) != Some("success") {
                        return fail();
                    }
                    let (token, uid) = match obj.get("data") {
                        None => (Value::Null, Value::Null),
                        Some(Value::Object(d)) => (
                            d.get("authToken").cloned().unwrap_or(Value::Null),
                            d.get("userId").cloned().unwrap_or(Value::Null),
                        ),
                        Some(_) => return fail(),
                    };
                    let auth: AuthHeaders = vec![("X-Auth-Token", token), ("X-User-Id", uid)];
                    let rc = RocketChat {
                        api_url: api_url.clone(),
                        mode: Mode::Basic,
                        user: None,
                        password: None,
                        webhook: None,
                        channels: this.channels,
                        rooms: this.rooms,
                        users: this.users,
                        avatar: false,
                    };
                    let sends = rc.sends(&payload, &auth, &ua, "api/v1/chat.postMessage", false);
                    let mut plans: Vec<Plan> = sends.into_iter().map(|p| p.context("post")).collect();
                    let mut logout = Request::post(format!("{api_url}/api/v1/logout"));
                    let mut valid = true;
                    for (k, v) in &auth {
                        match v {
                            Value::Null => {}
                            Value::String(s) => logout = logout.header(*k, s.as_str()),
                            Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => valid = false,
                        }
                    }
                    if valid {
                        plans.push(Plan::http(logout, |_| Plan::Done));
                    }
                    Plan::all(plans)
                })
                .context("login")
            }
        }
    }

}

/// Targets moved into the login continuation.
struct Sends {
    users: Vec<String>,
    channels: Vec<String>,
    rooms: Vec<String>,
}
