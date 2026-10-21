//! Synology Chat (`synology://`, `synologys://`): messages through Synology Chat incoming webhooks.
//!
//! # Differences with Apprise
//!
//! - Apprise crashes on URLs without a path, while mercurio handles them.

use serde_json::json;

use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "synology",
    name: "Synology Chat",
    schemes: &["synology", "synologys"],
    service_url: "https://www.synology.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 32768, body_max_line_count: 0 },
    templates: &[
        "{schema}://{host}/{token}",
        "{schema}://{host}:{port}/{token}",
        "{schema}://{user}@{host}/{token}",
        "{schema}://{user}@{host}:{port}/{token}",
        "{schema}://{user}:{password}@{host}/{token}",
        "{schema}://{user}:{password}@{host}:{port}/{token}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("password", "Password").secret(),
        Param::new("port", "Port").port(),
        Param::new("token", "Token").required().secret(),
        Param::new("user", "Username"),
    ],
    params: &[
        Param::new("file_url", "Upload"),
        Param::sets("token", &["token"]),
        Param::new("headers", "HTTP Header").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Synology {
    url: String,
    token: Secret,
    user: Option<String>,
    password: Option<Secret>,
    file_url: Option<String>,
    headers: Vec<(String, String)>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let headers = u.query_plus.iter().map(|(k, v)| (unquote(k), unquote(v))).collect();
    let mut fullpath = u.fullpath.clone();
    let token = match u.param_nonempty("token") {
        Some(t) => Some(unquote(t)),
        None => {
            let entries = u.path_segments();
            entries.into_iter().next().inspect(|t| {
                // Drop the token (decoded length) from the front of the raw path.
                let skip = t.chars().count() + 1;
                fullpath = fullpath.as_deref().map(|p| p.chars().skip(skip).collect());
            })
        }
    };
    let token =
        token.filter(|t| !t.is_empty()).ok_or_else(|| SERVICE.err("an invalid Synology token was specified"))?;
    let file_url = SERVICE.text(u, "file_url");

    // A missing path is treated as empty.
    let mut url = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = u.port {
        url.push_str(&format!(":{p}"));
    }
    url.push_str(fullpath.as_deref().unwrap_or(""));
    url.push_str("/webapi/entry.cgi");

    Ok(Box::new(Synology {
        url,
        token: Secret::new(token),
        user: u.user().filter(|s| !s.is_empty()),
        password: u.password().map(Secret::new),
        file_url,
        headers,
    }))
}

impl Notify for Synology {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut payload = json!({"text": msg.body});
        if let Some(f) = &self.file_url {
            payload["file_url"] = json!(f);
        }
        let params =
            [("api", "SYNO.Chat.External"), ("method", "incoming"), ("version", "2"), ("token", self.token.expose())];
        let mut req = ctx
            .post(&self.url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .headers(self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .query(&params)
            .form(&[("payload", payload.to_string())]);
        req = req.basic_auth_opt(self.user.as_deref(), self.password.as_ref().map(Secret::expose));
        Plan::send(req)
    }
}
