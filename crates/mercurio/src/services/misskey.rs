//! Misskey notes (`misskey://`, `misskeys://`): posts a note to a Misskey instance.

use serde_json::json;

use crate::parse::validate_nonblank;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "misskey",
    name: "Misskey",
    schemes: &["misskey", "misskeys"],
    service_url: "https://misskey-hub.net/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 512, body_max_line_count: 0 },
    templates: &[
        "{schema}://{token}@{host}",
        "{schema}://{token}@{host}:{port}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("port", "Port").int().range(1, 65535),
        Param::new("token", "Access Token").required(),
    ],
    params: &[
        Param::sets("token", &["token"]),
        Param::new("visibility", "Visibility").choice(&["public", "home", "followers", "specified"]).default("public"),
    ],
    ..ServiceDef::DEFAULTS
};

const VISIBILITIES: &[&str] = &["public", "home", "followers", "specified"];

#[derive(Debug)]
struct Misskey {
    api_url: String,
    token: Secret,
    visibility: &'static str,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let token = if let Some(t) = u.param_nonempty("token") {
        Some(unquote(t))
    } else if u.password.as_deref().is_none_or(str::is_empty) && u.user.as_deref().is_some_and(|s| !s.is_empty()) {
        u.user.as_deref().map(unquote)
    } else {
        None
    };
    let token = token
        .and_then(|t| validate_nonblank(&t))
        .ok_or_else(|| SERVICE.err("an invalid Misskey Access Token was specified"))?;

    let visibility = {
        let v = SERVICE.text_or_default(u, "visibility").to_lowercase();
        let v = v.trim();
        VISIBILITIES
            .iter()
            .copied()
            .find(|x| x.starts_with(v))
            .ok_or_else(|| SERVICE.err("the Misskey visibility specified is invalid"))?
    };

    let mut api_url = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = u.port {
        api_url.push_str(&format!(":{p}"));
    }
    Ok(Box::new(Misskey { api_url, token: Secret::new(token), visibility }))
}

impl Notify for Misskey {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let payload = json!({"i": self.token.expose(), "text": msg.body, "visibility": self.visibility});
        let req = ctx.post(format!("{}/api/notes/create", self.api_url))
            .json(&payload);
        Plan::send_expect(req, &[200])
    }
}
