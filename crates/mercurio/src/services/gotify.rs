//! Gotify (`gotify://`, `gotifys://`): push messages to a Gotify server.

use serde_json::json;

use crate::parse::validate_nonblank;
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "gotify",
    name: "Gotify",
    schemes: &["gotify", "gotifys"],
    service_url: "https://github.com/gotify/server",
    parse,
    templates: &[
        "{schema}://{host}/{token}",
        "{schema}://{host}:{port}/{token}",
        "{schema}://{host}{path}{token}",
        "{schema}://{host}:{port}{path}{token}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("path", "Path").default("/"),
        Param::new("port", "Port").port(),
        Param::new("token", "Token").required().secret(),
    ],
    params: &[
        Param::new("priority", "Priority").choice(&["0", "3", "5", "8", "10"]).default("5"),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Gotify {
    base: String,
    token: Secret,
    priority: i64,
}

/// Prefix -> priority, checked in order.
const PRIORITY_MAP: &[(&str, i64)] = &[
    ("l", 0),
    ("m", 3),
    ("n", 5),
    ("h", 8),
    ("e", 10),
    ("10", 10),
    ("0", 0),
    ("1", 0),
    ("2", 0),
    ("3", 3),
    ("4", 3),
    ("5", 5),
    ("6", 5),
    ("7", 5),
    ("8", 8),
    ("9", 8),
];

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let mut entries = u.path_segments();
    let token = entries.pop().unwrap_or_default();
    let token = validate_nonblank(&token).ok_or_else(|| SERVICE.err("an invalid Gotify token was specified"))?;
    let fullpath = if entries.is_empty() { "/".to_owned() } else { format!("/{}/", entries.join("/")) };
    let priority = match u.param_nonempty("priority") {
        None => 5,
        Some(p) => {
            let p = unquote(p).to_lowercase();
            PRIORITY_MAP.iter().find(|(k, _)| p.starts_with(k)).map(|(_, v)| *v).unwrap_or(5)
        }
    };
    let mut base = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(port) = u.port {
        base.push_str(&format!(":{port}"));
    }
    base.push_str(&fullpath);
    Ok(Box::new(Gotify { base, token: Secret::new(token), priority }))
}

impl Notify for Gotify {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut payload = json!({
            "priority": self.priority,
            "title": msg.title,
            "message": crate::http::TEXT,
        });
        if msg.format == NotifyFormat::Markdown {
            payload["extras"] = json!({"client::display": {"contentType": "text/markdown"}});
        }
        let req = ctx.post(format!("{}message", self.base))
            .header("X-Gotify-Key", self.token.expose())
            .json_text(&payload, msg.body);
        Plan::send_expect(req, &[200])
    }
}
