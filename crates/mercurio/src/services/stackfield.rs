//! Stackfield (`stackfield://`): messages to Stackfield rooms through webhooks.

use std::time::Duration;

use serde_json::json;

use crate::parse::validate_regex;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "stackfield",
    name: "Stackfield",
    schemes: &["stackfield"],
    service_url: "https://www.stackfield.com/",
    parse,
    parse_native: Some(parse_native),
    limits: Limits { title_maxlen: 0, body_maxlen: 4000, body_max_line_count: 0 },
    throttle: Duration::from_secs(1),
    templates: &[
        "{schema}://{token}",
    ],
    tokens: &[
        Param::new("token", "Webhook Token").required().secret().pattern("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"),
    ],
    params: &[
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

const TOKEN_RE: &str = r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$";

#[derive(Debug)]
struct Stackfield {
    token: Secret,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let token = SERVICE.text(u, "token").unwrap_or_else(|| u.host());
    let token = validate_regex(&token, TOKEN_RE, "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Stackfield webhook token was specified"))?;
    Ok(Box::new(Stackfield { token: Secret::new(token) }))
}

fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(
        r"(?i)^https?://(?:www\.)?stackfield\.com/apiwh/(?P<token>[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/?(?P<params>\?.+)?\n?\z"
    );
    let c = re.captures(url)?;
    Some(format!("stackfield://{}/{}", &c["token"], c.name("params").map_or("", |m| m.as_str())))
}

impl Notify for Stackfield {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let req = ctx.post(format!("https://www.stackfield.com/apiwh/{}", self.token.expose()))
            .header("Content-Type", "application/json")
            .json(&json!({"Title": msg.body}));
        Plan::send_expect(req, &[200])
    }
}
