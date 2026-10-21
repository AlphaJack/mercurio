//! YouLMK (`youlmk://`): notifications through YouLMK.

use std::time::Duration;

use serde_json::json;

use crate::asset::ImageSize;
use crate::parse::validate_regex;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{NotifyType, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "youlmk",
    name: "YouLMK",
    schemes: &["youlmk"],
    service_url: "https://youlmk.com/",
    parse,
    parse_native: Some(parse_native),
    limits: Limits { title_maxlen: 120, body_maxlen: 2000, body_max_line_count: 0 },
    throttle: Duration::from_secs(1),
    templates: &[
        "{schema}://{token}",
    ],
    tokens: &[
        Param::new("token", "Token or Key").required().secret().pattern("^(ylk_[a-z0-9]{32}|k_[a-z0-9]{14})$"),
    ],
    params: &[
        Param::new("failure", "Failure Priority").choice(&["low", "normal", "high", "critical"]).default("high"),
        Param::new("group", "Group"),
        Param::new("image", "Include Image").bool(false),
        Param::new("info", "Info Priority").choice(&["low", "normal", "high", "critical"]).default("normal"),
        Param::new("priority", "Priority").choice(&["low", "normal", "high", "critical"]),
        Param::new("success", "Success Priority").choice(&["low", "normal", "high", "critical"]).default("normal"),
        Param::sets("token", &["token"]),
        Param::new("url", "Link"),
        Param::new("url_label", "Link Label"),
        Param::new("warning", "Warning Priority").choice(&["low", "normal", "high", "critical"]).default("high"),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://youlmk.com/v1/notify";
const PRIORITIES: &[&str] = &["low", "normal", "high", "critical"];
const URL_LABEL_MAXLEN: usize = 24;

#[derive(Debug)]
struct YouLmk {
    token: Secret,
    priority: Option<&'static str>,
    /// info, success, warning, failure
    priority_map: [&'static str; 4],
    link: Option<String>,
    url_label: Option<String>,
    group: Option<String>,
    include_image: bool,
}

/// Full or short-form priority (`crit`, `c`) -> one of the four, if any.
fn youlmk_priority(value: &str) -> Option<&'static str> {
    let v = value.trim().to_lowercase();
    if v.is_empty() {
        return None;
    }
    PRIORITIES.iter().copied().find(|p| p.starts_with(&v))
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let q = |k: &str| SERVICE.text(u, k);
    let token = q("token").unwrap_or_else(|| u.host());
    let token = validate_regex(&token, r"^(ylk_[a-z0-9]{32}|k_[a-z0-9]{14})$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid YouLMK token or key was specified"))?;
    let invalid = || SERVICE.err("an invalid YouLMK priority was specified");
    let priority = match q("priority").filter(|p| !p.is_empty()) {
        Some(p) => Some(youlmk_priority(&p).ok_or_else(invalid)?),
        None => None,
    };
    let mut priority_map = [""; 4];
    for (slot, key) in priority_map.iter_mut().zip(["info", "success", "warning", "failure"]) {
        *slot = youlmk_priority(&SERVICE.text_or_default(u, key)).ok_or_else(invalid)?;
    }
    Ok(Box::new(YouLmk {
        token: Secret::new(token),
        priority,
        priority_map,
        link: q("url").filter(|s| !s.is_empty()),
        url_label: q("url_label").filter(|s| !s.is_empty()).map(|s| s.chars().take(URL_LABEL_MAXLEN).collect()),
        group: q("group").filter(|s| !s.is_empty()),
        include_image: SERVICE.flag(u, "image"),
    }))
}

/// `https://youlmk.com/k/{key}` -> `youlmk://{key}/{params}`.
fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(r"(?i)^https?://(www\.)?youlmk\.com/k/(?P<key>k_[a-z0-9]+)/?(?P<params>\?.+)?$");
    let c = re.captures(url)?;
    Some(format!("youlmk://{}/{}", &c["key"], c.name("params").map(|m| m.as_str()).unwrap_or("")))
}

impl Notify for YouLmk {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let token = self.token.expose();
        let is_token = token.to_lowercase().starts_with("ylk_");
        let url = if is_token { NOTIFY_URL.to_string() } else { format!("https://youlmk.com/k/{token}") };
        let idx = match msg.kind {
            NotifyType::Info => 0,
            NotifyType::Success => 1,
            NotifyType::Warning => 2,
            NotifyType::Failure => 3,
        };
        let priority = self.priority.unwrap_or(self.priority_map[idx]);
        let title = if !msg.title.is_empty() {
            msg.title
        } else if !ctx.app_desc().is_empty() {
            ctx.app_desc()
        } else {
            ctx.app_id()
        };
        let mut payload = json!({"title": title, "body": crate::http::TEXT, "priority": priority});
        if let Some(link) = &self.link {
            payload["url"] = json!(link);
            if let Some(label) = &self.url_label {
                payload["url_label"] = json!(label);
            }
        }
        if let Some(group) = &self.group {
            payload["group"] = json!(group);
        }
        if self.include_image
            && let Some(image) = ctx.asset.image_url(msg.kind, ImageSize::Xy256)
        {
            payload["image"] = json!(image);
        }
        let mut req = ctx.post(url)
            .header("Content-Type", "application/json; charset=utf-8");
        if is_token {
            req = req.bearer(token);
        }
        Plan::send_expect(req.json_text(&payload, msg.body), &[200])
    }
}
