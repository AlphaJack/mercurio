//! Spike.sh (`spike://`): alerts through a Spike.sh integration.

use serde_json::json;

use crate::parse::validate_regex;
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "spike",
    name: "Spike.sh",
    schemes: &["spike"],
    service_url: "https://www.spike.sh/",
    parse,
    parse_native: Some(parse_native),
    templates: &[
        "{schema}://{token}",
    ],
    tokens: &[
        Param::new("token", "Integration Key").required().secret().pattern("^[a-z0-9]{32}$"),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.spike.sh/v1/alerts/";

#[derive(Debug)]
struct Spike {
    token: Secret,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let token = u.text("token").unwrap_or_else(|| u.host());
    let token = validate_regex(&token, r"^[a-z0-9]{32}$", "i", true)
        .ok_or_else(|| SERVICE.err("the Spike.sh integration key is invalid"))?;
    Ok(Box::new(Spike { token: Secret::new(token) }))
}

fn parse_native(url: &str) -> Option<String> {
    let c = crate::regex!(r"(?i)^https://api\.spike\.sh/v1/alerts/([a-z0-9]{32})\n?$").captures(url)?;
    Some(format!("spike://{}", &c[1]))
}

impl Notify for Spike {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let payload = json!({
            "message": if msg.title.is_empty() { msg.body } else { msg.title },
            "description": msg.body,
        });
        let req = ctx.post(format!("{NOTIFY_URL}{}", self.token.expose()))
            .json(&payload);
        Plan::send_expect(req, &[200])
    }
}
