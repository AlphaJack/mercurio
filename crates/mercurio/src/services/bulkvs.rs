//! BulkVS (`bulkvs://`): SMS through the BulkVS messaging API.

use serde_json::{Value, json};

use super::_sms::{expect, no_targets, per_target, to_param};
use crate::parse::{is_phone_no, parse_phone_no, parse_phone_no_unquoted};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "bulkvs",
    name: "BulkVS",
    schemes: &["bulkvs"],
    service_url: "https://www.bulkvs.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    templates: &[
        "{schema}://{user}:{password}@{from_phone}/{targets}",
        "{schema}://{user}:{password}@{from_phone}",
    ],
    tokens: &[
        Param::new("from_phone", "From Phone No").required().pattern(r"^\+?[0-9\s)(+-]+$"),
        Param::new("password", "Password").required().secret(),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").required().group(&["target_phone"]),
        Param::new("user", "User Name").required(),
    ],
    params: &[
        Param::new("batch", "Batch Mode").bool(false),
        Param::new("from", "From Phone No").pattern(r"^\+?[0-9\s)(+-]+$"),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const BATCH_SIZE: usize = 4000;

#[derive(Debug)]
struct BulkVs {
    user: String,
    password: Secret,
    source: String,
    batch: bool,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let (source, mut targets) = match SERVICE.text(u, "from") {
        Some(s) => {
            let mut t = if u.host.is_empty() { Vec::new() } else { parse_phone_no_unquoted([u.host.as_str()], false) };
            t.extend(u.path_segments());
            (s, t)
        }
        None => (u.host(), u.path_segments()),
    };
    targets.extend(to_param(u));
    let batch = SERVICE.flag_strict(u, "batch");

    let user = u.user().unwrap_or_default();
    let password = u.password().unwrap_or_default();
    if user.is_empty() || password.is_empty() {
        return Err(SERVICE.err("a BulkVS user/pass was not provided"));
    }
    let source =
        is_phone_no(&source, 10).ok_or_else(|| SERVICE.err("the Account (From) Phone # specified is invalid"))?.full;
    let mut out = Vec::new();
    let mut has_error = false;
    for target in parse_phone_no(&targets, true, false) {
        match is_phone_no(&target, 10) {
            Some(p) => out.push(p.full),
            None => has_error = true,
        }
    }
    if targets.is_empty() && !has_error {
        out.push(source.clone());
    }
    Ok(Box::new(BulkVs { user, password: Secret::new(password), source, batch, targets: out }))
}

impl Notify for BulkVs {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return no_targets("BulkVS");
        }
        let items: Vec<(String, Value)> = if self.batch {
            self.targets.chunks(BATCH_SIZE).map(|c| (format!("{} targets", c.len()), json!(c))).collect()
        } else {
            self.targets.iter().map(|t| (t.clone(), json!(t))).collect()
        };
        per_target(items, |(label, _)| label.clone(), |(_, to)| {
            let payload = json!({"From": self.source, "To": to, "Message": crate::http::TEXT});
            let req = ctx.post("https://portal.bulkvs.com/api/v1.0/messageSend")
                .header("Accept", "application/json")
                .basic_auth(&self.user, Some(self.password.expose()))
                .json_text(&payload, msg.body);
            Plan::send_check(req, |r| expect(r, &[200]))
        })
    }

}
