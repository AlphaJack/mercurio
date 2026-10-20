//! Flowtriq (`flowtriq://`, `flowtriqs://`): posts the notification as a JSON event to a Flowtriq endpoint.

use serde_json::json;

use crate::parse::validate_nonblank;
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{NotifyType, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "flowtriq",
    name: "Flowtriq",
    schemes: &["flowtriq", "flowtriqs"],
    service_url: "https://flowtriq.com",
    parse,
    templates: &[
        "{schema}://{apikey}@{host}/{path}/",
        "{schema}://{apikey}@{host}:{port}/{path}/",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret(),
        Param::new("host", "Hostname").required(),
        Param::new("path", "Webhook Path").required(),
        Param::new("port", "Port").port(),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Flowtriq {
    url: String,
    apikey: Secret,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let apikey = u
        .user()
        .filter(|s| !s.is_empty())
        .and_then(|k| validate_nonblank(&k))
        .ok_or_else(|| SERVICE.err("an invalid Flowtriq API Key was specified"))?;
    let path = u.fullpath.as_deref().unwrap_or("").trim_matches('/');
    if path.is_empty() {
        return Err(SERVICE.err("a Flowtriq Webhook Path must be specified"));
    }
    let host = u.host();
    if host.is_empty() {
        return Err(SERVICE.err("a Flowtriq hostname must be specified"));
    }
    let mut url = format!("{}://{}", u.http_scheme(), host);
    if let Some(p) = u.port {
        url.push_str(&format!(":{p}"));
    }
    url.push('/');
    url.push_str(path);
    Ok(Box::new(Flowtriq { url, apikey: Secret::new(apikey) }))
}

impl Notify for Flowtriq {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let severity = match msg.kind {
            NotifyType::Failure => "critical",
            k @ (NotifyType::Info | NotifyType::Success | NotifyType::Warning) => k.as_str(),
        };
        let payload = json!({
            "title": msg.title,
            "body": msg.body,
            "severity": severity,
            "type": msg.kind.as_str(),
            "source": "apprise",
        });
        let req = ctx.post(&self.url)
            .header("X-API-Key", self.apikey.expose())
            .json(&payload);
        Plan::send_expect(req, &[200, 201, 202, 204])
    }
}
