//! OneBot 11 HTTP API (`onebot://`, `onebots://`): messages through a OneBot 11 HTTP API server.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use crate::crypto::b64;
use crate::error::Error;
use crate::http::{Request, Response};
use crate::parse::{parse_list, parse_list_unquoted};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "onebot",
    name: "OneBot",
    schemes: &["onebot", "onebots"],
    service_url: "https://github.com/botuniverse/onebot-11",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 4500, body_max_line_count: 0 },
    formats: &[NotifyFormat::Text],
    attachments: true,
    templates: &[
        "{schema}://{host}/{targets}",
        "{schema}://{host}:{port}/{targets}",
        "{schema}://{token}@{host}/{targets}",
        "{schema}://{token}@{host}:{port}/{targets}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("port", "Port").int().range(1, 65535),
        Param::new("target_group", "Target Group ID").pattern("^[0-9]{1,19}$").prefix("#"),
        Param::new("target_user", "Target User ID").pattern("^[0-9]{1,19}$").prefix("@"),
        Param::new("targets", "Targets").list("/").group(&["target_group", "target_user"]),
        Param::new("token", "Access Token").secret(),
    ],
    params: &[
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct OneBot {
    base: String,
    token: Option<Secret>,
    users: Vec<String>,
    groups: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let token_raw = u.param_nonempty("token").map(str::to_string).or_else(|| u.user.clone()).unwrap_or_default();
    let token = unquote(&token_raw);
    let token = if token.is_empty() { None } else { Some(Secret::new(token)) };

    let mut targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list_unquoted([to]));
    }

    let re = crate::regex!(r"^([@#])?([0-9]{1,19})$");
    let mut users = Vec::new();
    let mut groups = Vec::new();
    for target in parse_list(&targets) {
        match re.captures(&target) {
            Some(c) => {
                let id = c[2].to_string();
                if c.get(1).map(|m| m.as_str()) == Some("#") {
                    groups.push(id);
                } else {
                    users.push(id);
                }
            }
            None => log::warn!("dropped invalid OneBot target"),
        }
    }

    let mut base = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = u.port.filter(|p| *p != 0) {
        base.push_str(&format!(":{p}"));
    }
    Ok(Box::new(OneBot { base, token, users, groups }))
}

/// `true` when the retcode is absent, a bool, 0 or 1.
fn retcode_ok(v: Option<&Value>) -> bool {
    match v {
        None => true,
        Some(Value::Bool(_)) => true,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f == 0.0 || f == 1.0),
        _ => false,
    }
}

fn check(res: Result<Response>) -> Result<()> {
    let r = res?;
    if r.status != 200 {
        return Err(r.http_error());
    }
    if let Some(Value::Object(m)) = r.json()
        && (m.get("status").and_then(Value::as_str) == Some("failed") || !retcode_ok(m.get("retcode")))
    {
        let why = m.get("wording").or_else(|| m.get("message")).and_then(Value::as_str).unwrap_or("").to_string();
        return Err(Error::Service(format!(
            "OneBot action failed: retcode={}, {why}",
            m.get("retcode").unwrap_or(&Value::Null)
        )));
    }
    Ok(())
}

type Failed = Arc<Mutex<HashSet<String>>>;

impl OneBot {
    fn request(&self, action: &str, payload: &Value, ctx: &Context<'_>) -> Request {
        let mut req = ctx.post(format!("{}/{action}", self.base)).header("Content-Type", "application/json");
        if let Some(t) = &self.token {
            req = req.header("Authorization", format!("Bearer {}", t.expose()));
        }
        req.body(serde_json::to_vec(payload).unwrap_or_default(), None)
    }

    fn target_list(&self) -> Vec<(&'static str, &'static str, String)> {
        self.users
            .iter()
            .map(|u| ("send_private_msg", "user_id", u.clone()))
            .chain(self.groups.iter().map(|g| ("send_group_msg", "group_id", g.clone())))
            .collect()
    }
}

fn post(req: Request, key: String, failed: Failed) -> Plan {
    Plan::http(req, move |res| match check(res) {
        Ok(()) => Plan::Done,
        Err(e) => {
            failed.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(key);
            Plan::Fail(e)
        }
    })
}

fn payload(field: &str, id: &str, message: Value) -> Value {
    let mut m = serde_json::Map::new();
    m.insert(field.to_string(), json!(id.parse::<u64>().unwrap_or(0)));
    m.insert("message".into(), message);
    Value::Object(m)
}

fn label(field: &str, id: &str) -> String {
    format!("{}:{id}", if field == "user_id" { "@" } else { "#" })
}

impl Notify for OneBot {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.users.is_empty() && self.groups.is_empty() {
            return Plan::Fail(Error::Service("there are no OneBot targets to notify".into()));
        }
        let targets = self.target_list();
        let failed: Failed = Arc::new(Mutex::new(HashSet::new()));
        let mut plans = Vec::new();
        if !msg.body.is_empty() {
            for (action, field, id) in &targets {
                let payload = payload(field, id, json!([{"type": "text", "data": {"text": msg.body}}]));
                let key = format!("{field}:{id}");
                plans.push(post(self.request(action, &payload, ctx), key, failed.clone()).target(label(field, id)));
            }
        }
        for att in msg.attachments {
            let mut data = json!({"file": format!("base64://{}", b64(&att.data))});
            let kind = [("image/", "image"), ("audio/", "record"), ("video/", "video")]
                .iter()
                .find(|(p, _)| att.mime.starts_with(p))
                .map(|(_, k)| *k);
            let kind = match kind {
                Some(k) => k,
                None => {
                    let name = if att.name.is_empty() { "attachment.dat" } else { att.name.as_str() };
                    data["name"] = json!(name);
                    "file"
                }
            };
            let segment = json!({"type": kind, "data": data});
            // Build every target's request now; skip failed targets when reached.
            let reqs: Vec<(String, String, Request)> = targets
                .iter()
                .map(|(action, field, id)| {
                    let payload = payload(field, id, json!([segment]));
                    (format!("{field}:{id}"), label(field, id), self.request(action, &payload, ctx))
                })
                .collect();
            for (key, lbl, req) in reqs {
                let failed = failed.clone();
                plans.push(
                    Plan::defer(move || {
                        if failed.lock().unwrap_or_else(std::sync::PoisonError::into_inner).contains(&key) {
                            Plan::Done
                        } else {
                            post(req, key, failed)
                        }
                    })
                    .target(lbl),
                );
            }
        }
        Plan::all(plans)
    }

}
