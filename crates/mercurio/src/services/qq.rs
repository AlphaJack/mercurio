//! QQ Push via Qmsg (`qq://`): `POST https://qmsg.zendee.cn/v3/send/{key}` with a `msg` form field; the reply's `success` decides the outcome.
//!
//! # Differences
//!
//! - Apprise posts to the legacy `/send/{key}` endpoint (which Qmsg is retiring) and trusts any 200 -> mercurio posts to `/v3/send/{key}` and fails when the reply says `"success": false`. *intentional*

use serde_json::Value;

use crate::error::Error;
use crate::parse::validate_regex;
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "qq",
    name: "QQ Push",
    schemes: &["qq"],
    service_url: "https://qmsg.zendee.cn/",
    parse,
    parse_native: Some(parse_native),
    templates: &[
        "{schema}://{token}",
    ],
    tokens: &[
        Param::new("token", "User Token").required().secret().pattern("^[a-z0-9]{24,64}$"),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://qmsg.zendee.cn/v3/send/";

#[derive(Debug)]
struct Qq {
    token: Secret,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let raw = u.text("token").unwrap_or_else(|| u.host());
    let token = validate_regex(&raw, r"^[a-z0-9]{24,64}$", "i", true)
        .ok_or_else(|| SERVICE.err("the QQ Push token is invalid"))?;
    Ok(Box::new(Qq { token: Secret::new(token) }))
}

/// `https://qmsg.zendee.cn/v3/send/KEY` or the legacy `/send/KEY`.
fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(r"(?i)^https://qmsg\.zendee\.cn/(?:v3/)?send/([a-z0-9]+)$");
    let caps = re.captures(url)?;
    Some(format!("qq://{}", &caps[1]))
}

impl Notify for Qq {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let text = if msg.title.is_empty() { msg.body.to_string() } else { format!("{}\n{}", msg.title, msg.body) };
        let req = ctx.post(format!("{NOTIFY_URL}{}", self.token.expose()))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&[("msg", text)]);
        Plan::send_check(req, |r| {
            if r.status != 200 {
                return Err(r.http_error());
            }
            // `{"success": false, "reason": ...}` arrives with a 200.
            let reply: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
            match reply.get("success").and_then(Value::as_bool) {
                Some(false) => Err(Error::Service(format!(
                    "Qmsg refused the message: {}",
                    reply.get("reason").or_else(|| reply.get("message")).and_then(Value::as_str).unwrap_or("no reason")
                ))),
                Some(true) | None => Ok(()),
            }
        })
    }
}
