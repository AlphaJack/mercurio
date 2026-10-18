//! Feishu (`feishu://`): messages to a Feishu group bot webhook.

use serde_json::json;

use crate::parse::validate_regex;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "feishu",
    name: "Feishu",
    schemes: &["feishu"],
    service_url: "https://open.feishu.cn/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 19985, body_max_line_count: 0 },
    templates: &[
        "{schema}://{token}",
    ],
    tokens: &[
        Param::new("token", "Token").required().secret().pattern("^[A-Z0-9_-]+$"),
    ],
    params: &[
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Feishu {
    token: Secret,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let token = SERVICE.text(u, "token").unwrap_or_else(|| u.host());
    let token = validate_regex(&token, r"^[A-Z0-9_-]+$", "i", true)
        .ok_or_else(|| SERVICE.err("the Feishu token specified is invalid"))?;
    Ok(Box::new(Feishu { token: Secret::new(token) }))
}

impl Notify for Feishu {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let req = ctx.post(format!("https://open.feishu.cn/open-apis/bot/v2/hook/{}/", self.token.expose()))
            .header("Content-Type", "application/json")
            .json(&json!({"msg_type": "text", "content": {"text": msg.body}}));
        Plan::send_expect(req, &[200])
    }
}
