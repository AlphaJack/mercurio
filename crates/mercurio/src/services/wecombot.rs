//! WeCom Bot (`wecombot://`): messages through WeCom group bot webhooks.

use serde_json::json;

use crate::parse::validate_regex;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "wecombot",
    name: "WeCom Bot",
    schemes: &["wecombot"],
    service_url: "https://weixin.qq.com/",
    parse,
    parse_native: Some(parse_native),
    limits: Limits { title_maxlen: 0, ..Limits::DEFAULT },
    templates: &[
        "{schema}://{key}",
    ],
    tokens: &[
        Param::new("key", "Bot Webhook Key").required().secret().pattern("^[a-z0-9_-]+$"),
    ],
    params: &[
        Param::sets("key", &["key"]),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct WeComBot {
    key: Secret,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let key = SERVICE.text(u, "key").unwrap_or_else(|| u.host());
    let key = validate_regex(&key, r"^[a-z0-9_-]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid WeCom Bot Webhook Key was specified"))?;
    Ok(Box::new(WeComBot { key: Secret::new(key) }))
}

fn parse_native(url: &str) -> Option<String> {
    let caps = crate::regex!(
        r"(?i)^https?://qyapi\.weixin\.qq\.com/cgi-bin/webhook/send/?\?key=(?P<key>[A-Z0-9_-]+)/?&?(?P<params>.+)?$"
    )
    .captures(url)?;
    let params = caps.name("params").map(|m| format!("?{}", m.as_str())).unwrap_or_default();
    Some(format!("wecombot://{}{params}", &caps["key"]))
}

impl Notify for WeComBot {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let req = ctx.post(format!("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={}", self.key.expose()))
            .header("Content-Type", "application/json; charset=utf-8")
            .json(&json!({"msgtype": "text", "text": {"content": msg.body}}));
        Plan::send_expect(req, &[200])
    }
}
