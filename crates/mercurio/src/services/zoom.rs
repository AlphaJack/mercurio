//! Zoom Team Chat incoming webhooks (`zoom://`).
//!
//! `POST https://integrations.zoom.us/chat/webhooks/incomingwebhook/{id}` with the verification token in `Authorization`: either `?format=full` with a JSON message card or `?format=message` with the text as the body.
//!
//! # Differences with Apprise
//!
//! - Apprise posts to `inbots.zoom.us/incoming/hook/{id}`, while mercurio posts to the current `integrations.zoom.us/chat/webhooks/incomingwebhook/{id}` (`?format=full`; `?format=message` for `mode=simple`); native URLs on either host are accepted.

use serde_json::json;

use crate::parse::{validate_nonblank, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, quote, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "zoom",
    name: "Zoom",
    schemes: &["zoom"],
    service_url: "https://zoom.us/",
    parse,
    parse_native: Some(parse_native),
    // Title and body share one 4000-character field.
    limits: Limits { title_maxlen: 250, body_maxlen: 3750, body_max_line_count: 0 },
    templates: &[
        "{schema}://{webhook_id}/{token}",
    ],
    tokens: &[
        Param::new("token", "Verification Token").required().secret(),
        Param::new("webhook_id", "Webhook ID").required().secret(),
    ],
    params: &[
        Param::new("mode", "Mode")
            .choice(&["simple", "full"])
            .default("full")
            .note("`simple` sends `?format=message` with plain text"),
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

const MODES: &[&str] = &["simple", "full"];

#[derive(Debug)]
struct Zoom {
    webhook_id: Secret,
    token: Secret,
    full: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let webhook_id = u.host();
    let mut token = u.path_segments().into_iter().next().map(|t| unquote(&t));
    if let Some(t) = u.param_nonempty("token") {
        token = Some(unquote(t));
    }
    let mode = SERVICE.text(u, "mode");

    let webhook_id = validate_regex(&webhook_id, r"^[A-Za-z0-9_-]+$", "i", true).ok_or_else(|| {
        SERVICE
            .err("a Zoom webhook ID must be specified and contain only alphanumeric, hyphen, or underscore characters")
    })?;
    let token = token
        .as_deref()
        .and_then(validate_nonblank)
        .ok_or_else(|| SERVICE.err("a Zoom verification token must be specified"))?;
    let mode = match mode {
        None => SERVICE.default_of("mode"),
        Some(m) => {
            let m = m.trim().to_lowercase();
            MODES
                .iter()
                .copied()
                .find(|x| !m.is_empty() && x.starts_with(&m))
                .ok_or_else(|| SERVICE.err("the Zoom mode is invalid"))?
        }
    };
    Ok(Box::new(Zoom { webhook_id: Secret::new(webhook_id), token: Secret::new(token), full: mode == "full" }))
}

const NOTIFY_URL: &str = "https://integrations.zoom.us/chat/webhooks/incomingwebhook";

/// `https://integrations.zoom.us/chat/webhooks/incomingwebhook/ID` or the older `https://inbots.zoom.us/incoming/hook/ID`.
fn parse_native(url: &str) -> Option<String> {
    let caps = crate::regex!(
        r"(?i)^https?://(?:integrations\.zoom\.us/chat/webhooks/incomingwebhook|inbots\.zoom\.us/incoming/hook)/(?P<webhook_id>[A-Za-z0-9_-]+)/?(?P<params>\?.+)?$"
    )
    .captures(url)?;
    let params = caps.name("params").map(|m| m.as_str()).unwrap_or("");
    Some(format!("zoom://{}/{params}", &caps["webhook_id"]))
}

impl Notify for Zoom {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let base = format!("{NOTIFY_URL}/{}", quote(self.webhook_id.expose(), ""));
        let req = if self.full {
            let mut content = serde_json::Map::new();
            if !msg.title.is_empty() {
                content.insert("head".into(), json!({"text": msg.title}));
            }
            content.insert("body".into(), json!([{"type": "message", "text": crate::http::TEXT}]));
            ctx.post(format!("{base}?format=full"))
                .header("Authorization", self.token.expose())
                .header("Content-Type", "application/json")
                .json_text(&json!({"content": content}), msg.body)
        } else {
            let text = if msg.title.is_empty() { msg.body.to_string() } else { format!("{}: {}", msg.title, msg.body) };
            ctx.post(format!("{base}?format=message"))
                .header("Authorization", self.token.expose())
                .text(text)
        };
        Plan::send_expect(req, &[200, 204])
    }
}
