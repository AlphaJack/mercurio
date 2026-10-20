//! PushDeer (`pushdeer://`, `pushdeers://`): push notifications through PushDeer.

use crate::http::Request;
use crate::parse::validate_regex;
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "pushdeer",
    name: "PushDeer",
    schemes: &["pushdeer", "pushdeers"],
    service_url: "https://www.pushdeer.com/",
    parse,
    templates: &[
        "{schema}://{pushkey}",
        "{schema}://{host}/{pushkey}",
        "{schema}://{host}:{port}/{pushkey}",
    ],
    tokens: &[
        Param::new("host", "Hostname"),
        Param::new("port", "Port").port(),
        Param::new("pushkey", "Pushkey").required().secret().pattern("^[a-z0-9]+$"),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct PushDeer {
    url: String,
    push_key: Secret,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut paths = u.path_segments();
    let (key, host) = match paths.pop() {
        None => (u.host.clone(), String::new()),
        Some(k) => (k, u.host()),
    };
    let push_key = validate_regex(&key, r"^[a-z0-9]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid PushDeer API Pushkey was specified"))?;
    let host = if host.is_empty() { "api2.pushdeer.com".to_string() } else { host };
    let port = match u.port {
        Some(p) if p != 0 => p,
        _ if u.secure => 443,
        _ => 80,
    };
    let url = format!("{}://{host}:{port}/message/push", u.http_scheme());
    Ok(Box::new(PushDeer { url, push_key: Secret::new(push_key) }))
}

impl Notify for PushDeer {
    fn plan(&self, msg: &Prepared<'_>, _ctx: &Context<'_>) -> Plan {
        let has_title = !msg.title.is_empty();
        let text = if has_title { msg.title } else { msg.body };
        let desp = if has_title { msg.body } else { "" };
        let req = Request::post(format!("{}?pushkey={}", self.url, self.push_key.expose())).form(&[
            ("text", text),
            ("type", "text"),
            ("desp", desp),
        ]);
        Plan::send_expect(req, &[200])
    }
}
