//! Techulus Push (`push://`): push notifications through Techulus Push.

use serde_json::json;

use crate::parse::validate_regex;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "techuluspush",
    name: "Techulus Push",
    schemes: &["push"],
    service_url: "https://push.techulus.com",
    parse,
    limits: Limits { title_maxlen: 250, body_maxlen: 1000, body_max_line_count: 0 },
    templates: &[
        "{schema}://{apikey}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret().pattern("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://push.techulus.com/api/v1/notify";
const UUID4_RE: &str = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";

#[derive(Debug)]
struct TechulusPush {
    apikey: Secret,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let apikey = validate_regex(&u.host(), UUID4_RE, "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Techulus Push API key was specified"))?;
    Ok(Box::new(TechulusPush { apikey: Secret::new(apikey) }))
}

impl Notify for TechulusPush {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let req = ctx.post(NOTIFY_URL)
            .header("Content-Type", "application/json")
            .header("x-api-key", self.apikey.expose())
            .json(&json!({"title": msg.title, "body": msg.body}));
        Plan::send_expect(req, &[200, 204])
    }
}
