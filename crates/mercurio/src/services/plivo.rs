//! Plivo SMS (`plivo://`): SMS through the Plivo API.
//!
//! # Differences with Apprise
//!
//! - Apprise posts to a literal `{auth_id}` URL, while mercurio fills it in. *intentional*

use serde_json::json;

use super::_sms::{expect, no_targets, per_target, to_param, valid_phones};
use crate::parse::{is_phone_no, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "plivo",
    name: "Plivo",
    schemes: &["plivo"],
    service_url: "https://plivo.com",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 140, body_max_line_count: 0 },
    templates: &[
        "{schema}://{auth_id}@{token}/{source}",
        "{schema}://{auth_id}@{token}/{source}/{targets}",
    ],
    tokens: &[
        Param::new("auth_id", "Auth ID").required().pattern("^[a-z0-9]{20,30}$"),
        Param::new("source", "Source Phone No").required().pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").group(&["target_phone"]),
        Param::new("token", "Auth Token").required().pattern("^[a-z0-9]{30,50}$"),
    ],
    params: &[
        Param::new("batch", "Batch Mode").bool(false),
        Param::sets("from", &["source"]),
        Param::sets("id", &["auth_id"]),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

const BATCH_SIZE: usize = 20;

#[derive(Debug)]
struct Plivo {
    auth_id: Secret,
    token: Secret,
    source: String,
    targets: Vec<String>,
    batch: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let auth_id = SERVICE.text(u, "id").unwrap_or_else(|| u.user().unwrap_or_default());
    let mut targets = u.path_segments();
    let token = match SERVICE.text(u, "token") {
        Some(t) => {
            if !u.host.is_empty() {
                targets.insert(0, u.host());
            }
            t
        }
        None => u.host(),
    };
    let source = match SERVICE.text(u, "from") {
        Some(s) => Some(s),
        None if !targets.is_empty() => Some(targets.remove(0)),
        None => None,
    };
    targets.extend(to_param(u, false));
    let batch = SERVICE.flag_strict(u, "batch");

    let auth_id = validate_regex(&auth_id, r"^[a-z0-9]{20,30}$", "i", true)
        .ok_or_else(|| SERVICE.err("the Plivo authentication ID specified is invalid"))?;
    let token = validate_regex(&token, r"^[a-z0-9]{30,50}$", "i", true)
        .ok_or_else(|| SERVICE.err("the Plivo authentication token specified is invalid"))?;
    let source =
        source.and_then(|s| is_phone_no(&s, 10)).ok_or_else(|| SERVICE.err("the Plivo source specified is invalid"))?;
    let source = format!("+{}", source.full);
    let targets = if targets.is_empty() {
        vec![source.clone()]
    } else {
        valid_phones(&targets, false, 10).into_iter().map(|(_, p)| format!("+{}", p.full)).collect()
    };
    Ok(Box::new(Plivo { auth_id: Secret::new(auth_id), token: Secret::new(token), source, targets, batch }))
}

impl Notify for Plivo {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return no_targets("Plivo");
        }
        let url = format!("https://api.plivo.com/v1/Account/{}/Message/", self.auth_id.expose());
        let size = if self.batch { BATCH_SIZE } else { 1 };
        let chunks: Vec<String> = self.targets.chunks(size).map(|c| c.join("<")).collect();
        per_target(chunks, String::clone, |dst| {
            let payload = json!({"src": self.source, "dst": dst, "text": msg.body});
            let req = ctx.post(&url)
                .basic_auth(self.auth_id.expose(), Some(self.token.expose()))
                .json(&payload);
            Plan::send_check(req, |r| expect(r, &[200, 201, 202]))
        })
    }

}
