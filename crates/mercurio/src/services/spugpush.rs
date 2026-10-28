//! SpugPush (`spugpush://`): `POST https://push.spug.cc/send/{token}`.

use serde_json::json;

use crate::parse::validate_regex;
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "spugpush",
    name: "SpugPush",
    schemes: &["spugpush"],
    service_url: "https://push.spug.cc/",
    parse,
    parse_native: Some(parse_native),
    templates: &[
        "{schema}://{token}",
    ],
    tokens: &[
        Param::new("token", "Access Token").required().secret().pattern("^[a-zA-Z0-9_-]{32,64}$"),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct SpugPush {
    token: Secret,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let token = u.text("token").unwrap_or_else(|| u.host());
    let token = validate_regex(&token, r"^[a-zA-Z0-9_-]{32,64}$", "i", true)
        .ok_or_else(|| SERVICE.err("the SpugPush token is invalid"))?;
    Ok(Box::new(SpugPush { token: Secret::new(token) }))
}

/// `https://push.spug.cc/send/TOKEN` or the retired `push.spug.dev` host.
fn parse_native(url: &str) -> Option<String> {
    let caps = crate::regex!(r"(?i)^https://push\.spug\.(?:cc|dev)/send/([a-z0-9_-]+)$").captures(url)?;
    Some(format!("spugpush://{}", &caps[1]))
}

impl Notify for SpugPush {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let title = if msg.title.is_empty() { msg.body } else { msg.title };
        let req = ctx.post(format!("https://push.spug.cc/send/{}", self.token.expose()))
            .header("Content-Type", "application/json")
            .json_text(&json!({"title": title, "content": crate::http::TEXT}), msg.body);
        Plan::send_expect(req, &[200])
    }
}
