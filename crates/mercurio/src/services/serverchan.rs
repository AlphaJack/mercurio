//! ServerChan (`schan://`): messages through ServerChan.

use crate::http::Request;
use crate::parse::validate_regex;
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "serverchan",
    name: "ServerChan",
    schemes: &["schan"],
    service_url: "https://sct.ftqq.com/",
    parse,
    templates: &[
        "{schema}://{token}",
    ],
    tokens: &[
        Param::new("token", "Token").required().secret().pattern("^[a-z0-9-]+$"),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct ServerChan {
    token: Secret,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    // The token is read from the raw URL: `schan://([a-zA-Z0-9]+)/` (the slash is optional unless the URL ends with one).
    let url = u.original.as_str();
    let token = url
        .strip_prefix("schan://")
        .map(|rest| {
            let end = rest.find(|c: char| !c.is_ascii_alphanumeric()).unwrap_or(rest.len());
            let (tok, after) = rest.split_at(end);
            if tok.is_empty() || (url.ends_with('/') && !after.starts_with('/')) { "" } else { tok }
        })
        .unwrap_or("");
    let token = validate_regex(token, r"^[a-z0-9-]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid ServerChan API Token was specified"))?;
    Ok(Box::new(ServerChan { token: Secret::new(token) }))
}

impl Notify for ServerChan {
    fn plan(&self, msg: &Prepared<'_>, _ctx: &Context<'_>) -> Plan {
        let req = Request::post(format!("https://sctapi.ftqq.com/{}.send", self.token.expose()))
            .form(&[("title", msg.title), ("desp", msg.body)]);
        Plan::send_expect(req, &[200])
    }
}
