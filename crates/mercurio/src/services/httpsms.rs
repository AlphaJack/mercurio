//! httpSMS (`httpsms://`): SMS sent from your Android phone through the httpSMS API.

use serde_json::json;

use super::_telephony::{param_unquoted, source_and_targets, unquote_or_empty};
use crate::parse::validate_nonblank;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "httpsms",
    name: "httpSMS",
    schemes: &["httpsms"],
    service_url: "https://httpsms.com",
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
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.httpsms.com/v1/messages/send";

#[derive(Debug)]
struct HttpSms {
    apikey: Secret,
    source: String,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let apikey = param_unquoted(u, "key").unwrap_or_else(|| unquote_or_empty(u.user.as_deref()));
    let apikey = validate_nonblank(&apikey).ok_or_else(|| SERVICE.err("an invalid API Key was specified"))?;
    let (source, targets) =
        source_and_targets(u, 10).ok_or_else(|| SERVICE.err("the Account (From) Phone # specified is invalid"))?;
    Ok(Box::new(HttpSms { apikey: Secret::new(apikey), source, targets }))
}

impl Notify for HttpSms {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(SERVICE.err("there are no valid httpSMS targets to notify"));
        }
        Plan::all(self.targets.iter().map(|t| {
            let payload = json!({"from": format!("+{}", self.source), "to": format!("+{t}"), "content": crate::http::TEXT});
            let req = ctx.post(NOTIFY_URL)
                .header("x-api-key", self.apikey.expose())
                .json_text(&payload, msg.body);
            Plan::send_expect(req, &[200]).target(t.clone())
        }))
    }

}
