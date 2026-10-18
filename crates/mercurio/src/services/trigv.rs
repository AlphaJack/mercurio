//! Trigv (`trigv://`, `trigvs://`): notifications through Trigv.

use serde_json::json;

use crate::util::parse_int;
use crate::parse::{parse_list, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{NotifyType, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "trigv",
    name: "Trigv",
    schemes: &["trigv", "trigvs"],
    service_url: "https://trigv.com/",
    parse,
    limits: Limits { title_maxlen: 255, body_maxlen: 1000, body_max_line_count: 0 },
    templates: &[
        "{schema}://{api_key}",
        "{schema}://{api_key}/{targets}",
        "{schema}://{api_key}@{host}/{targets}",
        "{schema}://{api_key}@{host}:{port}/{targets}",
        "{schema}://{api_key}@{host}",
    ],
    tokens: &[
        Param::new("api_key", "API Key").required().secret().pattern("^trgv_[a-zA-Z0-9]{8}_[a-zA-Z0-9]{32}$"),
        Param::new("host", "API Hostname"),
        Param::new("port", "Port").int().range(1, 65535),
        Param::new("target_channel", "Target Channel"),
        Param::new("targets", "Targets").list("/").group(&["target_channel"]),
    ],
    params: &[
        Param::new("event_type", "Event type"),
        Param::new("image_url", "Image URL"),
        Param::new("priority", "Priority (Pushover compatibility)").int(),
        Param::sets("to", &["targets"]),
        Param::new("urgency", "Urgency").choice(&["standard", "time_sensitive"]).default("standard"),
        Param::new("url", "URL"),
    ],
    ..ServiceDef::DEFAULTS
};

const DEFAULT_NOTIFY_URL: &str = "https://api.trigv.com/api/v1/events";
const TITLE_MAXLEN: usize = 255;
const BODY_MAXLEN: usize = 1000;

#[derive(Debug)]
struct Trigv {
    api_key: Secret,
    targets: Vec<String>,
    notify_url: String,
    supplemental_url: Option<String>,
    image_url: Option<String>,
    urgency: String,
    event_type: Option<String>,
    priority: Option<i64>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let (api_key, host) = match u.user.as_deref().filter(|s| !s.is_empty()) {
        Some(user) => (unquote(user), Some(u.host())),
        None => (u.host(), None),
    };
    let q = |k: &str| u.param_nonempty(k);
    if let Some(to) = q("to") {
        targets.extend(parse_list([to]));
    }
    let api_key = validate_regex(&api_key, r"^trgv_[a-zA-Z0-9]{8}_[a-zA-Z0-9]{32}$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Trigv API Key was specified"))?;
    let mut channels = Vec::new();
    for t in parse_list(targets) {
        let c = validate_regex(&t, r"^[a-z0-9][a-z0-9_-]{0,119}$", "i", true)
            .ok_or_else(|| SERVICE.err("an invalid Trigv channel slug was specified"))?;
        channels.push(c);
    }
    if channels.is_empty() {
        channels.push("general".to_string());
    }
    let urgency = q("urgency").map(|v| unquote(v).to_lowercase()).unwrap_or_else(|| SERVICE.default_of("urgency").into());
    if !matches!(urgency.as_str(), "standard" | "time_sensitive") {
        return Err(SERVICE.err("an invalid Trigv urgency was specified"));
    }
    let notify_url = match host.filter(|h| !h.is_empty()) {
        Some(h) => {
            let port = u.port.filter(|p| *p != 0).map(|p| format!(":{p}")).unwrap_or_default();
            format!("{}://{}{}/api/v1/events", u.http_scheme(), h, port)
        }
        None => DEFAULT_NOTIFY_URL.to_string(),
    };
    Ok(Box::new(Trigv {
        api_key: Secret::new(api_key),
        targets: channels,
        notify_url,
        supplemental_url: q("url").map(unquote),
        image_url: q("image_url").map(unquote),
        urgency,
        event_type: q("event_type").map(unquote),
        priority: q("priority").and_then(parse_int),
    }))
}

impl Trigv {
    fn urgency(&self, kind: NotifyType) -> &str {
        if self.urgency != "standard" {
            &self.urgency
        } else if self.priority.is_some_and(|p| p >= 1) || kind == NotifyType::Failure {
            "time_sensitive"
        } else {
            "standard"
        }
    }
}

impl Notify for Trigv {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let resolved_title = if !msg.title.is_empty() {
            msg.title.to_string()
        } else if !ctx.app_desc().is_empty() {
            ctx.app_desc().to_string()
        } else {
            format!("{} Alert", ctx.app_id())
        };
        let body = if msg.body.is_empty() && msg.title.is_empty() { resolved_title.clone() } else { msg.body.to_string() };
        let level = match msg.kind {
            NotifyType::Failure => "error",
            k @ (NotifyType::Info | NotifyType::Success | NotifyType::Warning) => k.as_str(),
        };
        let urgency = self.urgency(msg.kind);
        Plan::all(self.targets.iter().map(|channel| {
            let mut payload = json!({
                "channel": channel,
                "title": resolved_title.chars().take(TITLE_MAXLEN).collect::<String>(),
                "level": level,
            });
            if !body.is_empty() {
                payload["description"] = json!(body.chars().take(BODY_MAXLEN).collect::<String>());
            }
            if let Some(v) = &self.supplemental_url {
                payload["url"] = json!(v);
            }
            if let Some(v) = &self.image_url {
                payload["image_url"] = json!(v);
            }
            if let Some(v) = &self.event_type {
                payload["event_type"] = json!(v);
            }
            payload["delivery_urgency"] = json!(urgency);
            let req = ctx.post(&self.notify_url)
                .header("Accept", "application/json")
                .bearer(self.api_key.expose())
                .json(&payload);
            Plan::send_expect(req, &[200, 202]).target(channel.clone())
        }))
    }

}
