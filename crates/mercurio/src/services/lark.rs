//! Lark (`lark://`): messages to a Lark group bot webhook.

use serde_json::json;

use crate::parse::validate_regex;
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "lark",
    name: "Lark (Feishu)",
    schemes: &["lark"],
    service_url: "https://open.larksuite.com/",
    parse,
    parse_native: Some(parse_native),
    templates: &[
        "{schema}://{token}",
    ],
    tokens: &[
        Param::new("token", "Bot Token").required().secret().pattern("^[a-z0-9-]+$"),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Lark {
    token: Secret,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let token = u.text("token").unwrap_or_else(|| u.host());
    let token = validate_regex(&token, r"^[a-z0-9-]+$", "i", true)
        .ok_or_else(|| SERVICE.err("the Lark Bot Token specified is invalid"))?;
    Ok(Box::new(Lark { token: Secret::new(token) }))
}

fn parse_native(url: &str) -> Option<String> {
    let caps = crate::regex!(r"(?i)^https://open\.larksuite\.com/open-apis/bot/v2/hook/([\w-]+)$").captures(url)?;
    Some(format!("lark://{}", &caps[1]))
}

impl Notify for Lark {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let text = if msg.title.is_empty() { msg.body.to_string() } else { format!("{}\n{}", msg.title, msg.body) };
        let req = ctx.post(format!("https://open.larksuite.com/open-apis/bot/v2/hook/{}", self.token.expose()))
            .header("Content-Type", "application/json")
            .json(&json!({"msg_type": "text", "content": {"text": text}}));
        Plan::send_expect(req, &[200])
    }
}
