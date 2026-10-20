//! 800.com (`eight00com://`): SMS through the 800.com messaging API.

use serde_json::json;

use super::_telephony::{Form, param_unquoted, source_and_targets, unquote_or_empty};
use crate::parse::validate_nonblank;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "eighthundredcom",
    name: "800.com",
    schemes: &["eight00com"],
    service_url: "https://www.800.com",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 600, body_max_line_count: 0 },
    attachments: true,
    templates: &[
        "{schema}://{token}@{from_phone}",
        "{schema}://{token}@{from_phone}/{targets}",
    ],
    tokens: &[
        Param::new("from_phone", "From Phone No").required().pattern(r"^\+?[0-9\s)(+-]+$"),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").group(&["target_phone"]),
        Param::new("token", "API Token").required().secret(),
    ],
    params: &[
        Param::new("from", "From Phone No"),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.800.com/message";

#[derive(Debug)]
struct Eight00com {
    token: Secret,
    source: String,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let token = param_unquoted(u, "token").unwrap_or_else(|| unquote_or_empty(u.user.as_deref()));
    let token =
        validate_nonblank(&token).ok_or_else(|| SERVICE.err("an 800.com Personal Access Token must be specified"))?;
    let (source, targets) =
        source_and_targets(u, 10).ok_or_else(|| SERVICE.err("the 800.com from phone # is invalid"))?;
    Ok(Box::new(Eight00com { token: Secret::new(token), source, targets }))
}

impl Notify for Eight00com {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(SERVICE.err("there are no valid 800.com targets to notify"));
        }
        let sender = format!("+{}", self.source);
        Plan::all(self.targets.iter().map(|t| {
            let recipient = format!("+{t}");
            let req = ctx.post(NOTIFY_URL)
                .header("Authorization", format!("Bearer {}", self.token.expose()));
            let req = if msg.attachments.is_empty() {
                req.header("Content-Type", "application/json").json(&json!({
                    "sender": sender,
                    "recipient": recipient,
                    "message": msg.body,
                }))
            } else {
                let mut form =
                    Form::new().text("sender", &sender).text("recipient", &recipient).text("message", msg.body);
                for a in msg.attachments {
                    form = form.part("media[]", Some(&a.name), Some(&a.mime), a.data.clone());
                }
                form.apply(req)
            };
            Plan::send_expect(req, &[200]).target(t.clone())
        }))
    }

}
