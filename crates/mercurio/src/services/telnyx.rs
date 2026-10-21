//! Telnyx (`telnyx://`): SMS through the Telnyx API.

use serde_json::json;

use super::_telephony::{param_unquoted, source_and_targets};
use crate::parse::validate_nonblank;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "telnyx",
    name: "Telnyx",
    schemes: &["telnyx"],
    service_url: "https://telnyx.com",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    templates: &[
        "{schema}://{apikey}@{from_phone}",
        "{schema}://{apikey}@{from_phone}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret(),
        Param::new("from_phone", "From Phone No").required().pattern(r"^\+?[0-9\s)(+-]+$"),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").required().group(&["target_phone"]),
    ],
    params: &[
        Param::new("from", "From Phone No").pattern(r"^\+?[0-9\s)(+-]+$"),
        Param::sets("key", &["apikey"]),
        Param::new("profile", "Messaging Profile ID"),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.telnyx.com/v2/messages";

#[derive(Debug)]
struct Telnyx {
    apikey: Secret,
    source: String,
    profile: Option<String>,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let apikey = param_unquoted(u, "key").unwrap_or_else(|| super::_telephony::unquote_or_empty(u.user.as_deref()));
    let profile = param_unquoted(u, "profile");
    let apikey = validate_nonblank(&apikey).ok_or_else(|| SERVICE.err("an invalid Telnyx API Key was specified"))?;
    let (source, targets) =
        source_and_targets(u, 10).ok_or_else(|| SERVICE.err("the Account (From) Phone # specified is invalid"))?;
    let profile = profile.and_then(|p| validate_nonblank(&p));
    Ok(Box::new(Telnyx { apikey: Secret::new(apikey), source, profile, targets }))
}

impl Notify for Telnyx {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(SERVICE.err("there are no valid Telnyx targets to notify"));
        }
        Plan::all(self.targets.iter().map(|t| {
            let mut payload = json!({"from": format!("+{}", self.source), "to": format!("+{t}"), "text": crate::http::TEXT});
            if let Some(p) = &self.profile {
                payload["messaging_profile_id"] = json!(p);
            }
            let req = ctx.post(NOTIFY_URL)
                .header("Authorization", format!("Bearer {}", self.apikey.expose()))
                .header("Accept", "application/json")
                .json_text(&payload, msg.body);
            Plan::send_expect(req, &[200]).target(t.clone())
        }))
    }

}
