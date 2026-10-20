//! Kodi / XBMC (`kodi://`, `xbmc://`, `kodis://`, `xbmcs://`): on-screen notifications through the Kodi JSON-RPC API.

use serde_json::json;

use crate::asset::ImageSize;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{NotifyType, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "kodi",
    name: "Kodi/XBMC",
    schemes: &["kodi", "xbmc", "kodis", "xbmcs"],
    service_url: "http://kodi.tv/",
    parse,
    limits: Limits { title_maxlen: 250, body_maxlen: 32768, body_max_line_count: 2 },
    templates: &[
        "{schema}://{host}",
        "{schema}://{host}:{port}",
        "{schema}://{user}:{password}@{host}",
        "{schema}://{user}:{password}@{host}:{port}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("password", "Password").secret(),
        Param::new("port", "Port").port(),
        Param::new("user", "Username"),
    ],
    params: &[
        Param::new("duration", "Duration").int().default("12").min(1),
        Param::new("image", "Include Image").bool(true),
    ],
    ..ServiceDef::DEFAULTS
};

const XBMC_REMOTE_PROTOCOL: u8 = 2;
const KODI_REMOTE_PROTOCOL: u8 = 6;
const XBMC_DEFAULT_PORT: u16 = 8080;

#[derive(Debug)]
struct Kodi {
    url: String,
    user: Option<String>,
    password: Option<Secret>,
    protocol: u8,
    duration: i64,
    include_image: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let (protocol, port) = if u.scheme.starts_with("xbmc") {
        (XBMC_REMOTE_PROTOCOL, Some(u.port.unwrap_or(XBMC_DEFAULT_PORT)))
    } else {
        (KODI_REMOTE_PROTOCOL, u.port)
    };
    let duration = SERVICE.int_or_default(u, "duration").saturating_abs();
    let mut url = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = port.filter(|p| *p != 0) {
        url.push_str(&format!(":{p}"));
    }
    url.push_str("/jsonrpc");
    Ok(Box::new(Kodi {
        url,
        user: u.user().filter(|s| !s.is_empty()),
        password: u.password().map(Secret::new),
        protocol,
        duration,
        include_image: SERVICE.flag_strict(u, "image"),
    }))
}

impl Notify for Kodi {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut payload = json!({
            "jsonrpc": "2.0",
            "method": "GUI.ShowNotification",
            "params": {
                "title": msg.title,
                "message": msg.body,
                "displaytime": self.duration.saturating_mul(1000),
            },
            "id": 1,
        });
        let image = if self.include_image { ctx.asset.image_url(msg.kind, ImageSize::Xy128) } else { None };
        if let Some(image) = image {
            payload["params"]["image"] = json!(image);
            if self.protocol != XBMC_REMOTE_PROTOCOL {
                payload["type"] = json!(match msg.kind {
                    NotifyType::Failure => "error",
                    NotifyType::Warning => "warning",
                    NotifyType::Info | NotifyType::Success => "info",
                });
            }
        }
        let mut req = ctx.post(&self.url)
            .json(&payload);
        req = req.basic_auth_opt(self.user.as_deref(), self.password.as_ref().map(Secret::expose));
        Plan::send_expect(req, &[200])
    }
}
