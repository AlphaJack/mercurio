//! Notica (`notica://`, `noticas://`): browser notifications through Notica.

use crate::http::Request;
use crate::parse::validate_nonblank;
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Limits, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "notica",
    name: "Notica",
    schemes: &["notica", "noticas"],
    service_url: "https://notica.us/",
    parse,
    parse_native: Some(parse_native),
    limits: Limits { title_maxlen: 0, ..Limits::DEFAULT },
    templates: &[
        "{schema}://{token}",
        "{schema}://{host}/{token}",
        "{schema}://{host}:{port}/{token}",
        "{schema}://{user}@{host}/{token}",
        "{schema}://{user}@{host}:{port}/{token}",
        "{schema}://{user}:{password}@{host}/{token}",
        "{schema}://{user}:{password}@{host}:{port}/{token}",
        "{schema}://{host}{path}/{token}",
        "{schema}://{host}:{port}/{path}/{token}",
        "{schema}://{user}@{host}/{path}/{token}",
        "{schema}://{user}@{host}:{port}{path}/{token}",
        "{schema}://{user}:{password}@{host}{path}/{token}",
        "{schema}://{user}:{password}@{host}:{port}/{path}/{token}",
    ],
    tokens: &[
        Param::new("host", "Hostname"),
        Param::new("password", "Password").secret(),
        Param::new("path", "Path").default("/"),
        Param::new("port", "Port").port(),
        Param::new("token", "Token").required().secret().pattern(r"^\?*(?P<token>[^/]+)\s*$"),
        Param::new("user", "Username"),
    ],
    params: &[
        Param::new("headers", "HTTP Header").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
enum Mode {
    Official,
    SelfHosted { base: String, user: Option<String>, password: Option<Secret>, headers: Vec<(String, String)> },
}

#[derive(Debug)]
struct Notica {
    token: Secret,
    mode: Mode,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut entries = u.path_segments();
    let invalid = || SERVICE.err("an invalid Notica token was specified");
    if entries.is_empty() {
        let token = validate_nonblank(&u.host()).ok_or_else(invalid)?;
        return Ok(Box::new(Notica { token: Secret::new(token), mode: Mode::Official }));
    }
    let token = entries.pop().unwrap_or_default();
    let token = validate_nonblank(&token).ok_or_else(invalid)?;
    let fullpath = if entries.is_empty() { "/".to_string() } else { format!("/{}/", entries.join("/")) };
    let host = u.host();
    if host.is_empty() {
        return Ok(Box::new(Notica { token: Secret::new(token), mode: Mode::Official }));
    }
    let mut base = format!("{}://{}", u.http_scheme(), host);
    if let Some(port) = u.port {
        base.push_str(&format!(":{port}"));
    }
    base.push_str(&fullpath);
    let headers = u.query_plus.iter().map(|(k, v)| (unquote(k), unquote(v))).collect();
    Ok(Box::new(Notica {
        token: Secret::new(token),
        mode: Mode::SelfHosted { base, user: u.user(), password: u.password().map(Secret::new), headers },
    }))
}

/// `https://notica.us/?abc123` -> `notica://abc123/`.
fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(r"(?i)^https?://notica\.us/?\??(?P<token>[^&]+)([&\s]*(?P<params>.+))?\n?$");
    let c = re.captures(url)?;
    let params = c.name("params").map(|p| format!("?{}", p.as_str())).unwrap_or_default();
    Some(format!("notica://{}/{}", &c["token"], params))
}

impl Notify for Notica {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut req = match &self.mode {
            Mode::Official => Request::post(format!("https://notica.us/?{}", self.token.expose())),
            Mode::SelfHosted { base, .. } => Request::post(format!("{base}?token={}", self.token.expose())),
        }
        .header("User-Agent", ctx.app_id())
        .header("Content-Type", "application/x-www-form-urlencoded");
        if let Mode::SelfHosted { user, password, headers, .. } = &self.mode {
            req = req.headers(headers.iter().map(|(k, v)| (k.as_str(), v.as_str())));
            if let Some(user) = user.as_deref().filter(|u| !u.is_empty()) {
                req = req.basic_auth(user, password.as_ref().map(Secret::expose));
            }
        }
        Plan::send_expect(req.text(format!("d:{}", msg.body)), &[200])
    }
}
