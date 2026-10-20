//! Pinglet (`pinglet://`, `pinglets://`): notifications through Pinglet.

use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::message::NotifyType;
use crate::parse::validate_nonblank;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{PATH_SAFE, ParsedUrl, quote, unquote};
use crate::util::truncate_chars;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "pinglet",
    name: "Pinglet",
    schemes: &["pinglet", "pinglets"],
    service_url: "https://pinglet.co.uk/",
    parse,
    limits: Limits { title_maxlen: 250, body_maxlen: 3000, body_max_line_count: 0 },
    throttle: Duration::from_millis(500),
    templates: &[
        "{schema}://{token}@{host}/{namespace}/{topic}",
        "{schema}://{token}@{host}:{port}/{namespace}/{topic}",
        "{schema}://{token}@{host}{path}{namespace}/{topic}",
        "{schema}://{token}@{host}:{port}{path}{namespace}/{topic}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("namespace", "Namespace").required(),
        Param::new("path", "Path").default("/"),
        Param::new("port", "Port").port(),
        Param::new("token", "API Key").required().secret(),
        Param::new("topic", "Topic").required(),
    ],
    params: &[
        Param::new("priority", "Priority").choice(&["silent", "normal", "urgent"]).default("normal"),
        Param::sets("token", &["token"]),
        Param::new("badges", "Badges").prefix(":"),
        Param::new("data", "Metadata").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

const MAX_BADGE_COUNT: usize = 3;
const MAX_BADGE_KEY_LEN: usize = 24;
const MAX_BADGE_VALUE_LEN: usize = 32;
const MAX_DATA_KEY_LEN: usize = 64;
const MAX_DATA_VALUE_LEN: usize = 256;

#[derive(Debug)]
struct Pinglet {
    url: String,
    token: Secret,
    priority: &'static str,
    badges: Vec<(String, String)>,
    data: Vec<(String, String)>,
}

/// Map-style insert: overwrite in place, otherwise append.
fn upsert(v: &mut Vec<(String, String)>, k: String, val: String) {
    if let Some(slot) = v.iter_mut().find(|(key, _)| *key == k) {
        slot.1 = val;
    } else {
        v.push((k, val));
    }
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let mut entries = u.path_segments();
    let topic = entries.pop();
    let namespace = entries.pop();
    let fullpath = if entries.is_empty() { "/".to_string() } else { format!("/{}/", entries.join("/")) };

    let mut token = u.user.as_deref().filter(|s| !s.is_empty()).map(unquote);
    if let Some(t) = u.param_nonempty("token") {
        token = Some(unquote(t));
    }
    let token = token
        .as_deref()
        .and_then(validate_nonblank)
        .ok_or_else(|| SERVICE.err("an invalid Pinglet API Key was specified"))?;
    let namespace = namespace
        .as_deref()
        .and_then(validate_nonblank)
        .ok_or_else(|| SERVICE.err("an invalid Pinglet Namespace was specified"))?;
    let topic = topic
        .as_deref()
        .and_then(validate_nonblank)
        .ok_or_else(|| SERVICE.err("an invalid Pinglet Topic was specified"))?;

    let priority = match u.param_nonempty("priority") {
        None => "normal",
        Some(p) => {
            let p = unquote(p).to_lowercase();
            [("s", "silent"), ("n", "normal"), ("u", "urgent")]
                .iter()
                .find(|(k, _)| p.starts_with(k))
                .map(|(_, v)| *v)
                .unwrap_or("normal")
        }
    };

    let mut badges = Vec::new();
    for (k, v) in u.query_colon.iter() {
        if badges.len() >= MAX_BADGE_COUNT {
            break;
        }
        let (k, v) = (unquote(k), unquote(v));
        upsert(&mut badges, truncate_chars(&k, MAX_BADGE_KEY_LEN), truncate_chars(&v, MAX_BADGE_VALUE_LEN));
    }
    let mut data = Vec::new();
    for (k, v) in u.query_plus.iter() {
        let (k, v) = (unquote(k), unquote(v));
        upsert(&mut data, truncate_chars(&k, MAX_DATA_KEY_LEN), truncate_chars(&v, MAX_DATA_VALUE_LEN));
    }

    let mut url = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = u.port {
        url.push_str(&format!(":{p}"));
    }
    url.push_str(&quote(&format!("{fullpath}{namespace}/{topic}"), PATH_SAFE));

    Ok(Box::new(Pinglet { url, token: Secret::new(token), priority, badges, data }))
}

fn to_map(v: &[(String, String)]) -> Value {
    Value::Object(v.iter().map(|(k, v)| (k.clone(), json!(v))).collect::<Map<_, _>>())
}

impl Notify for Pinglet {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let level = match msg.kind {
            NotifyType::Info => "info",
            NotifyType::Success => "success",
            NotifyType::Warning => "warning",
            NotifyType::Failure => "error",
        };
        let mut payload = json!({"message": msg.body, "priority": self.priority, "level": level});
        if !msg.title.is_empty() {
            payload["title"] = json!(msg.title);
        }
        if !self.badges.is_empty() {
            payload["badges"] = to_map(&self.badges);
        }
        if !self.data.is_empty() {
            payload["data"] = to_map(&self.data);
        }
        let req = ctx
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.token.expose()))
            .json(&payload);
        Plan::send_expect(req, &[200])
    }
}
