//! PushWard (`pushward://`): push notifications through PushWard.
//!
//! # Differences with Apprise
//!
//! - Apprise accepts `volume=nan`, while mercurio does not.

use serde_json::json;

use crate::asset::ImageSize;
use crate::message::NotifyType;
use crate::parse::validate_regex;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "pushward",
    name: "PushWard",
    schemes: &["pushward"],
    service_url: "https://pushward.app/",
    parse,
    limits: Limits { title_maxlen: 256, body_maxlen: 3000, body_max_line_count: 0 },
    templates: &[
        "{schema}://{apikey}",
    ],
    tokens: &[
        Param::new("apikey", "Integration Key").required().secret().pattern("^hlk_[A-Za-z0-9]+$"),
    ],
    params: &[
        Param::sets("apikey", &["apikey"]),
        Param::new("failure", "Failure Level").choice(&["passive", "active", "time-sensitive", "critical"]).default("time-sensitive"),
        Param::new("info", "Info Level").choice(&["passive", "active", "time-sensitive", "critical"]).default("active"),
        Param::new("level", "Level").choice(&["passive", "active", "time-sensitive", "critical"]),
        Param::new("success", "Success Level").choice(&["passive", "active", "time-sensitive", "critical"]).default("active"),
        Param::new("volume", "Volume").float().range(0, 1),
        Param::new("warning", "Warning Level").choice(&["passive", "active", "time-sensitive", "critical"]).default("time-sensitive"),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.pushward.app/notifications";
const LEVELS: &[&str] = &["passive", "active", "time-sensitive", "critical"];

#[derive(Debug)]
struct PushWard {
    apikey: Secret,
    level: Option<&'static str>,
    /// info, success, warning, failure.
    level_map: [&'static str; 4],
    volume: Option<f64>,
}

/// Full or short-form level to its canonical name.
fn level(value: &str) -> Option<&'static str> {
    let v = value.trim().to_lowercase();
    if v.is_empty() {
        return None;
    }
    LEVELS.iter().copied().find(|l| l.starts_with(&v))
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut apikey = u.host();
    if let Some(k) = u.param_nonempty("apikey") {
        apikey = unquote(k);
    }
    let apikey = validate_regex(&apikey, r"^hlk_[A-Za-z0-9]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid PushWard Integration Key was specified"))?;

    let lvl = match u.param_nonempty("level") {
        Some(l) => Some(level(&unquote(l)).ok_or_else(|| SERVICE.err("an invalid PushWard level was specified"))?),
        None => None,
    };

    let mut level_map = [""; 4];
    for (i, key) in ["info", "success", "warning", "failure"].iter().enumerate() {
        level_map[i] = level(&SERVICE.text_or_default(u, key))
            .ok_or_else(|| SERVICE.err("an invalid PushWard level was specified"))?;
    }

    let volume = match u.param_nonempty("volume") {
        Some(v) => {
            let f: f64 =
                unquote(v).trim().parse().map_err(|_| SERVICE.err("an invalid PushWard volume was specified"))?;
            if !(0.0..=1.0).contains(&f) {
                return Err(SERVICE.err("an invalid PushWard volume was specified"));
            }
            Some(f)
        }
        None => None,
    };

    Ok(Box::new(PushWard { apikey: Secret::new(apikey), level: lvl, level_map, volume }))
}

impl Notify for PushWard {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let idx = match msg.kind {
            NotifyType::Info => 0,
            NotifyType::Success => 1,
            NotifyType::Warning => 2,
            NotifyType::Failure => 3,
        };
        let level = self.level.unwrap_or(self.level_map[idx]);
        let title = if !msg.title.is_empty() {
            msg.title
        } else if !ctx.app_desc().is_empty() {
            ctx.app_desc()
        } else {
            ctx.app_id()
        };
        let mut payload = json!({"title": title, "body": crate::http::TEXT, "level": level});
        if let Some(img) = ctx.asset.image_url(msg.kind, ImageSize::Xy128) {
            payload["icon_url"] = json!(img);
        }
        if level == "critical"
            && let Some(v) = self.volume
        {
            payload["volume"] = json!(v);
        }
        let req = ctx.post(NOTIFY_URL)
            .header("Content-Type", "application/json; charset=utf-8")
            .header("Authorization", format!("Bearer {}", self.apikey.expose()))
            .json_text(&payload, msg.body);
        Plan::send_expect(req, &[200, 201])
    }
}
