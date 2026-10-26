//! GoAlert (`goalert://`, `goalerts://`): alerts through a GoAlert generic incoming integration.

use serde_json::{Map, Value, json};

use crate::parse::parse_list;
use crate::service::{Context, Limits, Notify, Param, ServiceDef};
use crate::url::{PATH_SAFE, ParsedUrl, quote, unquote};
use crate::{Error, NotifyFormat, NotifyType, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "goalert",
    name: "GoAlert",
    schemes: &["goalert", "goalerts"],
    service_url: "https://goalert.me/",
    parse,
    limits: Limits { title_maxlen: 1024, body_maxlen: 6144, body_max_line_count: 0 },
    formats: &[NotifyFormat::Markdown],
    templates: &[
        "{schema}://{host}/{targets}",
        "{schema}://{host}:{port}/{targets}",
        "{schema}://{host}{path}{targets}",
        "{schema}://{host}:{port}{path}{targets}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("path", "Path").default("/"),
        Param::new("port", "Port").port(),
        Param::new("targets", "Integration Keys").list("/").required().secret(),
    ],
    params: &[
        Param::new("action", "Action").choice(&["map", "trigger", "close"]).default("map"),
        Param::new("dedup", "Deduplication Key"),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["targets"]),
        Param::new("meta", "Metadata").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

const TITLE_MAXLEN: usize = 1024;
const ACTIONS: &[&str] = &["map", "trigger", "close"];
const API_PATH: &str = "api/v2/generic/incoming";

#[derive(Debug)]
struct GoAlert {
    url: String,
    action: &'static str,
    dedup: Option<String>,
    meta: Vec<(String, String)>,
    /// Integration keys (lower-cased). Kept as plain strings: they are target labels in the delivery report.
    targets: Vec<String>,
}

/// `IS_INTEGRATION_KEY`: a UUID, optionally surrounded by whitespace.
fn integration_key(s: &str) -> Option<String> {
    let re = crate::regex!(r"(?i)^\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\s*$");
    re.captures(s).map(|c| c[1].to_string())
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let mut targets: Vec<String> = Vec::new();
    let mut path = Vec::new();
    for entry in u.path_segments() {
        if integration_key(&entry).is_some() {
            targets.push(entry);
        } else {
            path.push(entry);
        }
    }
    for key in ["to", "token"] {
        if let Some(v) = u.param_nonempty(key) {
            targets.extend(parse_list([unquote(v)]));
        }
    }
    let action = match u.param_nonempty("action") {
        None => SERVICE.default_of("action"),
        Some(a) => {
            let a = unquote(a).trim().to_lowercase();
            ACTIONS
                .iter()
                .copied()
                .find(|x| x.starts_with(&a))
                .ok_or_else(|| SERVICE.err("the GoAlert action specified is invalid"))?
        }
    };
    let dedup = SERVICE.text(u, "dedup").map(|d| d.trim().to_string());
    let meta = u.query_plus.iter().map(|(k, v)| (unquote(k), unquote(v))).collect();

    let mut keys = Vec::new();
    for t in parse_list(&targets) {
        match integration_key(&t) {
            Some(k) => keys.push(k.to_lowercase()),
            None => crate::warning!("GoAlert: ignoring an invalid integration key"),
        }
    }

    let fullpath = path.join("/");
    let mut url = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = u.port.filter(|p| *p != 0) {
        url.push_str(&format!(":{p}"));
    }
    url.push('/');
    if !fullpath.is_empty() {
        url.push_str(&quote(&format!("{fullpath}/"), PATH_SAFE));
    }
    url.push_str(API_PATH);

    Ok(Box::new(GoAlert { url, action, dedup, meta, targets: keys }))
}

/// Report label for a key without revealing it .
fn mask(key: &str) -> String {
    let first = key.chars().next().unwrap_or_default();
    let last = key.chars().last().unwrap_or_default();
    format!("{first}...{last}")
}

impl Notify for GoAlert {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Service("there are no GoAlert integration keys to notify".into()));
        }
        let close = self.action == "close" || (self.action == "map" && msg.kind == NotifyType::Success);
        let summary = if !msg.title.is_empty() {
            msg.title.to_string()
        } else {
            let body = if msg.passthrough { msg.body.to_string() } else { crate::convert::markup::unescape(msg.body) };
            body.chars().take(TITLE_MAXLEN).collect()
        };
        let mut payload = Map::new();
        payload.insert("summary".into(), json!(summary));
        payload.insert("details".into(), json!(crate::http::TEXT));
        if close {
            payload.insert("action".into(), json!("close"));
        }
        if let Some(d) = self.dedup.as_ref().filter(|d| !d.is_empty()) {
            payload.insert("dedup".into(), json!(d));
        }
        if !self.meta.is_empty() {
            let meta: Map<String, Value> = self.meta.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
            payload.insert("meta".into(), Value::Object(meta));
        }
        let payload = Value::Object(payload);
        Plan::all(self.targets.iter().map(|key| {
            let req = ctx
                .post(&self.url)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {key}"))
                .json_text(&payload, msg.body);
            Plan::send_expect(req, &[200, 201, 202, 204]).target(mask(key))
        }))
    }

}
