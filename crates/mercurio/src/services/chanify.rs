//! Chanify (`chanify://`): push notifications to the Chanify app.

use crate::parse::validate_regex;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "chanify",
    name: "Chanify",
    schemes: &["chanify"],
    service_url: "https://chanify.net/",
    parse,
    limits: Limits { title_maxlen: 0, ..Limits::DEFAULT },
    templates: &[
        "{schema}://{token}",
    ],
    tokens: &[
        Param::new("token", "Token").required().secret().pattern("^[A-Z0-9._-]+$"),
    ],
    params: &[
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Chanify {
    token: Secret,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let token = SERVICE.text(u, "token").unwrap_or_else(|| u.host());
    let token = validate_regex(&token, r"^[A-Z0-9._-]+$", "i", true)
        .ok_or_else(|| SERVICE.err("the Chanify token specified is invalid"))?;
    Ok(Box::new(Chanify { token: Secret::new(token) }))
}

impl Notify for Chanify {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let req = ctx.post(format!("https://api.chanify.net/v1/sender/{}/", self.token.expose()))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&[("text", msg.body)]);
        Plan::send_expect(req, &[200])
    }
}
