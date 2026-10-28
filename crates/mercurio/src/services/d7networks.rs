//! D7 Networks (`d7sms://`): SMS through the D7 Networks messaging API.

use std::time::Duration;

use serde_json::{Value, json};

use super::_sms::{expect, full_numbers, no_targets, per_target, to_param};
use crate::parse::validate_nonblank;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "d7networks",
    name: "D7 Networks",
    schemes: &["d7sms"],
    service_url: "https://d7networks.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    throttle: Duration::from_millis(200),
    templates: &[
        "{schema}://{token}@{targets}",
    ],
    tokens: &[
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").required().group(&["target_phone"]),
        Param::new("token", "API Access Token").required().secret(),
    ],
    params: &[
        Param::new("batch", "Batch Mode").bool(false),
        Param::new("source", "Originating Address").aliases(&["from"]),
        Param::sets("to", &["targets"]),
        Param::new("unicode", "Unicode Characters").bool(false),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct D7Networks {
    token: Secret,
    source: Option<String>,
    unicode: bool,
    batch: bool,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let user = u.user.as_deref().filter(|s| !s.is_empty());
    let password = u.password.as_deref().filter(|s| !s.is_empty());
    let token = match u.text("token") {
        Some(t) => Some(t),
        None => match (user, password) {
            (Some(us), Some(pw)) => Some(format!("{}:{}", unquote(us), unquote(pw))),
            (Some(us), None) => Some(unquote(us)),
            (None, Some(pw)) => Some(format!(":{}", unquote(pw))),
            (None, None) => None,
        },
    };
    let mut targets = vec![u.host()];
    targets.extend(u.path_segments());
    let batch = SERVICE.flag(u, "batch");
    let unicode = SERVICE.flag(u, "unicode");
    targets.extend(to_param(u));
    let source = u.text("from").or_else(|| u.text("source")).map(|s| s.trim().to_owned());

    let token = token
        .and_then(|t| validate_nonblank(&t))
        .ok_or_else(|| SERVICE.err("the D7 Networks token specified is invalid"))?;
    Ok(Box::new(D7Networks {
        token: Secret::new(token),
        source: source.filter(|s| !s.is_empty()),
        unicode,
        batch,
        targets: full_numbers(&targets),
    }))
}

impl Notify for D7Networks {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return no_targets("D7 Networks");
        }
        let mut globals = json!({"channel": "sms"});
        if let Some(s) = &self.source {
            globals["originator"] = json!(s);
        }
        let items: Vec<(String, Value)> = if self.batch {
            vec![(format!("{} targets", self.targets.len()), json!(self.targets))]
        } else {
            self.targets.iter().map(|t| (t.clone(), json!([t]))).collect()
        };
        per_target(items, |(label, _)| label.clone(), |(_, recipients)| {
            let payload = json!({
                "message_globals": globals,
                "messages": [{
                    "recipients": recipients,
                    "content": crate::http::TEXT,
                    "data_coding": if self.unicode { "unicode" } else { "auto" },
                }],
            });
            let req = ctx.post("https://api.d7networks.com/messages/v1/send")
                .header("Accept", "application/json")
                .bearer(self.token.expose())
                .json_text(&payload, msg.body);
            Plan::send_check(req, |r| expect(r, &[201, 200]))
        })
    }

}
