//! Streamlabs (`strmlabs://`): API v2.0 alerts and donations.
//!
//! `POST https://streamlabs.com/api/v2.0/{alerts,donations}` with the access token as a Bearer header (v2.0 refuses it in the body) and a JSON body.
//!
//! # Differences with Apprise
//!
//! - Apprise posts forms to API v1.0 with `access_token` in the body -> mercurio uses API v2.0 (Bearer header, JSON, empty options left out), since Streamlabs is disabling v1.0. *intentional*
//! - The donation `identifier` defaults to the application id and `sound_href` keeps its case (Apprise upper-cases the URL). *intentional*

use serde_json::{Map, Value, json};

use crate::parse::validate_regex;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "streamlabs",
    name: "Streamlabs",
    schemes: &["strmlabs"],
    service_url: "https://streamlabs.com/",
    parse,
    limits: Limits { title_maxlen: 250, body_maxlen: 255, body_max_line_count: 0 },
    templates: &[
        "{schema}://{access_token}/",
    ],
    tokens: &[
        Param::new("access_token", "Access Token").required().secret().pattern(TOKEN_RE),
    ],
    params: &[
        Param::new("alert_type", "Alert Type").choice(&["follow", "subscription", "donation", "host"]).default("donation"),
        Param::new("amount", "Amount").int().default("0").min(0),
        Param::new("call", "Call").choice(&["ALERTS", "DONATIONS"]).default("ALERTS"),
        Param::new("currency", "Currency").default("USD").pattern("^[A-Z]{3}$"),
        Param::new("duration", "Duration").int().default("1000").min(0),
        Param::new("identifier", "Identifier").note("defaults to the application id"),
        Param::new("image_href", "Image Link"),
        Param::new("name", "Name").default("Anon").pattern(r"^[^\s].{1,24}$").inferred(),
        Param::new("sound_href", "Sound Link"),
        Param::new("special_text_color", "Special Text Color").pattern("^[A-Z]$"),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://streamlabs.com/api/v2.0/";
const TOKEN_RE: &str = "^[a-z0-9._-]{20,}$";
const CALLS: &[&str] = &["ALERTS", "DONATIONS"];
const ALERTS: &[&str] = &["follow", "subscription", "donation", "host"];

#[derive(Debug)]
struct Streamlabs {
    access_token: Secret,
    call: String,
    alert_type: String,
    image_href: String,
    sound_href: String,
    duration: String,
    special_text_color: String,
    amount: String,
    currency: String,
    name: String,
    /// `None`: the application id.
    identifier: Option<String>,
}

/// `query[key]` when present and non-empty, transformed then unquoted.
fn opt(u: &ParsedUrl, key: &str, upper: bool) -> Option<String> {
    u.param_nonempty(key).map(|v| if upper { unquote(&v.trim().to_uppercase()) } else { unquote(v) })
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let token = validate_regex(&u.host(), TOKEN_RE, "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Streamlabs access token was specified"))?;
    let call = opt(u, "call", true).unwrap_or_else(|| SERVICE.default_of("call").into());
    if !CALLS.contains(&call.as_str()) {
        return Err(SERVICE.err("the streamlabs call specified is invalid"));
    }
    let alert_type = opt(u, "alert_type", false).unwrap_or_else(|| SERVICE.default_of("alert_type").into());
    if !ALERTS.contains(&alert_type.as_str()) {
        return Err(SERVICE.err("the streamlabs alert type specified is invalid"));
    }
    let currency = opt(u, "currency", true).unwrap_or_else(|| SERVICE.default_of("currency").into());
    let currency = validate_regex(&currency, r"^[A-Z]{3}$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Streamlabs currency was specified"))?;
    let name = opt(u, "name", true).unwrap_or_else(|| SERVICE.default_of("name").into());
    let name = validate_regex(&name, r"^[^\s].{1,24}$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Streamlabs donor was specified"))?;
    Ok(Box::new(Streamlabs {
        access_token: Secret::new(token),
        call,
        alert_type,
        image_href: opt(u, "image_href", false).unwrap_or_default(),
        sound_href: opt(u, "sound_href", false).unwrap_or_default(),
        duration: opt(u, "duration", true).unwrap_or_else(|| SERVICE.default_of("duration").into()),
        special_text_color: opt(u, "special_text_color", true).unwrap_or_default(),
        amount: opt(u, "amount", false).unwrap_or_else(|| SERVICE.default_of("amount").into()),
        currency,
        name,
        identifier: opt(u, "identifier", true),
    }))
}

impl Notify for Streamlabs {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let url = format!("{NOTIFY_URL}{}", self.call.to_lowercase());
        let mut body = Map::new();
        if self.call == "ALERTS" {
            let has_title = !msg.title.is_empty();
            body.insert("type".into(), json!(self.alert_type.to_lowercase()));
            body.insert("message".into(), json!(if has_title { msg.title } else { msg.body }));
            if has_title {
                body.insert("user_message".into(), json!(msg.body));
            }
            for (key, value) in [
                ("image_href", &self.image_href),
                ("sound_href", &self.sound_href),
                ("special_text_color", &self.special_text_color),
            ] {
                if !value.is_empty() {
                    body.insert(key.into(), json!(value));
                }
            }
            body.insert("duration".into(), number(&self.duration));
        } else {
            let message =
                if msg.title.is_empty() { msg.body.to_string() } else { format!("{}\r\n{}", msg.title, msg.body) };
            body.insert("name".into(), json!(self.name));
            body.insert("identifier".into(), json!(self.identifier.as_deref().unwrap_or(ctx.app_id())));
            body.insert("amount".into(), number(&self.amount));
            body.insert("currency".into(), json!(self.currency));
            body.insert("message".into(), json!(message.chars().take(254).collect::<String>()));
        }
        let req = ctx
            .post(url)
            .header("Authorization", format!("Bearer {}", self.access_token.expose()))
            .json(&Value::Object(body));
        Plan::send_expect(req, &[200])
    }
}

/// A numeric option as a JSON number; as given when it is not one.
fn number(v: &str) -> Value {
    let v = v.trim();
    match (v.parse::<i64>(), v.parse::<f64>()) {
        (Ok(i), _) => json!(i),
        (_, Ok(f)) if f.is_finite() => json!(f),
        _ => json!(v),
    }
}
