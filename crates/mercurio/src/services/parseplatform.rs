//! Parse Platform push (`parsep://`, `parseps://`): push notifications through a Parse server.

use serde_json::json;

use crate::parse::validate_nonblank;
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "parseplatform",
    name: "Parse Platform",
    schemes: &["parsep", "parseps"],
    service_url: "https://parseplatform.org/",
    parse,
    templates: &[
        "{schema}://{app_id}:{master_key}@{host}",
        "{schema}://{app_id}:{master_key}@{host}:{port}",
    ],
    tokens: &[
        Param::new("app_id", "App ID").required().secret(),
        Param::new("host", "Hostname").required(),
        Param::new("master_key", "Master Key").required().secret(),
        Param::new("port", "Port").int().range(1, 65535),
    ],
    params: &[
        Param::sets("app_id", &["app_id"]),
        Param::new("device", "Device").choice(&["all", "ios", "android"]).default("all"),
        Param::sets("master_key", &["master_key"]),
    ],
    ..ServiceDef::DEFAULTS
};

const DEVICES: &[&str] = &["all", "ios", "android"];

#[derive(Debug)]
struct ParsePlatform {
    url: String,
    app_id: Secret,
    master_key: Secret,
    devices: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let mut app_id = u.user.as_deref().map(unquote).unwrap_or_default();
    let mut master_key = u.password.as_deref().map(unquote).unwrap_or_default();
    if let Some(v) = u.param_nonempty("app_id") {
        app_id = v.to_string();
    }
    if let Some(v) = u.param_nonempty("master_key") {
        master_key = v.to_string();
    }
    let app_id = validate_nonblank(&app_id)
        .ok_or_else(|| SERVICE.err("an invalid Parse Platform Application ID was specified"))?;
    let master_key = validate_nonblank(&master_key)
        .ok_or_else(|| SERVICE.err("an invalid Parse Platform Master Key was specified"))?;
    // Validated and sent as given (case-sensitive); only `all` is matched case-insensitively.
    let device = SERVICE.raw(u, "device").filter(|d| !d.is_empty()).unwrap_or(SERVICE.default_of("device"));
    if !DEVICES.contains(&device) {
        return Err(SERVICE.err("an invalid Parse Platform device was specified"));
    }
    let devices = if device.to_lowercase() == "all" {
        vec!["ios".to_string(), "android".to_string()]
    } else {
        vec![device.to_string()]
    };
    let mut url = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(port) = u.port {
        url.push_str(&format!(":{port}"));
    }
    url.push_str(u.fullpath.as_deref().unwrap_or("/").trim_end_matches('/'));
    url.push_str("/parse/push/");
    Ok(Box::new(ParsePlatform { url, app_id: Secret::new(app_id), master_key: Secret::new(master_key), devices }))
}

impl Notify for ParsePlatform {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let payload = json!({
            "where": {"deviceType": {"$in": self.devices}},
            "data": {"title": msg.title, "alert": msg.body},
        });
        let req = ctx.post(&self.url)
            .header("Content-Type", "application/json")
            .header("X-Parse-Application-Id", self.app_id.expose())
            .header("X-Parse-Master-Key", self.master_key.expose())
            .body(serde_json::to_vec(&payload).unwrap_or_default(), None);
        Plan::send_expect(req, &[200])
    }
}
