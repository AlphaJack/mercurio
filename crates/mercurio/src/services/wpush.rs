//! WPUSH (`wpush://`): push notifications through WPUSH.

use serde_json::{Map, Value, json};

use crate::error::Error;
use crate::parse::{parse_list, validate_regex};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Limits, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "wpush",
    name: "WPUSH",
    schemes: &["wpush"],
    service_url: "https://wpush.cn/",
    parse,
    parse_native: Some(parse_native),
    limits: Limits { title_maxlen: 255, body_maxlen: 10000, body_max_line_count: 0 },
    templates: &[
        "{schema}://{apikey}",
        "{schema}://{apikey}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret().pattern("^WPUSH[a-z0-9]{27}$"),
        Param::new("targets", "Topics").list("/"),
    ],
    params: &[
        Param::sets("apikey", &["apikey"]),
        Param::new("channel", "Channel").list(", ").values(&["wechat", "app", "sms", "mail", "webhook", "dingtalk", "feishu", "wechat_work", "clawbot", "qqbot"]),
        Param::new("group", "Group / Option Code").aliases(&["option"]),
        Param::sets("to", &["targets"]),
        Param::sets("topic", &["targets"]),
        Param::sets("topic_code", &["targets"]),
        Param::new("url", "Click URL"),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.wpush.cn/api/v1/send";

const CHANNELS: &[&str] =
    &["wechat", "app", "sms", "mail", "webhook", "dingtalk", "feishu", "wechat_work", "clawbot", "qqbot"];

#[derive(Debug)]
struct WPush {
    apikey: Secret,
    channels: Vec<String>,
    topics: Vec<String>,
    group: Option<String>,
    click_url: Option<String>,
}

fn non_blank(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.trim().is_empty())
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let apikey = SERVICE.text(u, "apikey").unwrap_or_else(|| u.host());
    let mut targets = u.path_segments();
    for key in ["to", "topic_code", "topic"] {
        if let Some(v) = u.param_nonempty(key) {
            targets.extend(parse_list([v]));
        }
    }
    let channel = SERVICE.text(u, "channel");
    let mut group = u.text("option");
    if let Some(g) = u.param_nonempty("group") {
        group = Some(unquote(g));
    }
    let click_url = SERVICE.text(u, "url");

    let apikey = validate_regex(&apikey, r"^WPUSH[a-z0-9]{27}$", "i", true)
        .ok_or_else(|| SERVICE.err("the WPUSH API Key is invalid"))?;
    let channels = match channel.filter(|c| !c.is_empty()) {
        None => vec!["wechat".to_string()],
        Some(c) => {
            let mut out: Vec<String> = Vec::new();
            for entry in parse_list([c.as_str()]) {
                let lower = entry.to_lowercase();
                let resolved = CHANNELS
                    .iter()
                    .find(|ch| **ch == lower)
                    .ok_or_else(|| SERVICE.err(format!("the WPUSH channel ({entry}) is not valid")))?;
                if !out.iter().any(|o| o == resolved) {
                    out.push(resolved.to_string());
                }
            }
            out.sort();
            out
        }
    };
    let topics = parse_list(targets);
    let group = non_blank(group);
    if group.is_some() && !topics.is_empty() {
        return Err(SERVICE.err("the WPUSH option/group cannot be combined with topic targets"));
    }
    Ok(Box::new(WPush { apikey: Secret::new(apikey), channels, topics, group, click_url: non_blank(click_url) }))
}

/// `https://api.wpush.cn/api/v1/send?apikey=KEY[&...]` -> `wpush://KEY/?...`.
fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(r"(?i)^https?://api\.wpush\.cn/api/v1/send(?:\?(?P<params>[^#]+))?\n?$");
    let c = re.captures(url)?;
    let params = c.name("params").map(|p| p.as_str()).unwrap_or("");
    let key_re = crate::regex!(r"(?i)(?:^|&)apikey=(?P<apikey>[^&]+)");
    let key = key_re.captures(params)?;
    Some(format!("wpush://{}/?{}", unquote(&key["apikey"]), params))
}

fn check(r: &crate::Response) -> Result<()> {
    if r.status != 200 {
        return Err(r.http_error());
    }
    let content = r.json().and_then(|v| v.as_object().cloned()).unwrap_or_default();
    let code = content.get("code");
    let ok = match code {
        Some(Value::Number(n)) => n.as_f64() == Some(0.0),
        _ => false,
    };
    if ok {
        return Ok(());
    }
    let message = content.get("message").map(|m| m.as_str().map(str::to_string).unwrap_or_else(|| m.to_string()));
    Err(Error::Service(format!(
        "WPUSH code={}: {}",
        code.map(Value::to_string).unwrap_or_else(|| "None".into()),
        message.unwrap_or_else(|| "Unknown error".into())
    )))
}

impl Notify for WPush {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let channel = self.channels.join(",");
        let topics: Vec<Option<&String>> =
            if self.topics.is_empty() { vec![None] } else { self.topics.iter().map(Some).collect() };
        Plan::all(topics.into_iter().map(|topic| {
            let mut payload = Map::new();
            payload.insert("apikey".into(), json!(self.apikey.expose()));
            payload.insert("title".into(), json!(if msg.title.is_empty() { msg.body } else { msg.title }));
            payload.insert("content".into(), json!(msg.body));
            payload.insert("channel".into(), json!(channel));
            if let Some(u) = &self.click_url {
                payload.insert("url".into(), json!(u));
            }
            if let Some(t) = topic {
                payload.insert("topic_code".into(), json!(t));
            } else if let Some(g) = &self.group {
                payload.insert("option".into(), json!(g));
            }
            let req = ctx.post(NOTIFY_URL)
                .header("Content-Type", "application/json")
                .header("X-API-Key", self.apikey.expose())
                .header("X-Idempotency-Key", ctx.env().uuid4())
                .body(serde_json::to_vec(&Value::Object(payload)).unwrap_or_default(), None);
            let plan = Plan::send_check(req, check);
            match topic {
                Some(t) => plan.target(t.clone()),
                None => plan,
            }
        }))
    }

}
