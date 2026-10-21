//! Lauther (`lauther://`): push notifications through the Lauther API.

use serde_json::json;

use crate::util::parse_int;
use crate::parse::validate_regex;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "lauther",
    name: "Lauther",
    schemes: &["lauther"],
    service_url: "https://lauther.app/",
    parse,
    limits: Limits { title_maxlen: 250, body_maxlen: 2000, body_max_line_count: 0 },
    templates: &[
        "{schema}://{token}",
    ],
    tokens: &[
        Param::new("token", "Token").required().secret().pattern("^lpt_[a-z0-9]+$"),
    ],
    params: &[
        Param::new("click", "Click URL"),
        Param::new("color", "Color"),
        Param::new("group", "Group"),
        Param::new("icon", "Icon URL"),
        Param::new("priority", "Priority").choice(&["-2", "-1", "0", "1", "2"]).default("0"),
        Param::new("route", "Route"),
        Param::new("sound", "Sound"),
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.lauther.id/v1/push";

/// Priority names, longest first.
const PRIORITY_MAP: &[(&str, i64)] =
    &[("emergency", 2), ("lowest", -2), ("normal", 0), ("high", 1), ("low", -1)];

#[derive(Debug)]
struct Lauther {
    token: Secret,
    priority: i64,
    /// `(payload key, value)` optional fields, in payload order.
    extras: Vec<(&'static str, String)>,
}

fn priority(raw: Option<String>) -> Result<i64> {
    let Some(p) = raw else { return Ok(0) };
    let lower = p.to_lowercase();
    if let Some((_, v)) = PRIORITY_MAP.iter().find(|(k, _)| lower.starts_with(k)) {
        return Ok(*v);
    }
    let rest = p.trim_start_matches(['+', '-']);
    let v = if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
        // e.g. "+-1" is not an integer: the URL fails to load.
        parse_int(&p).ok_or_else(|| SERVICE.err("the Lauther priority specified is invalid"))?
    } else {
        0
    };
    if (-2..=2).contains(&v) { Ok(v) } else { Err(SERVICE.err("the Lauther priority specified is invalid")) }
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let q = |k: &str| SERVICE.text(u, k);
    let token = q("token").unwrap_or_else(|| u.host());
    let token = validate_regex(&token, r"^lpt_[a-z0-9]+$", "i", true)
        .ok_or_else(|| SERVICE.err("the Lauther token specified is invalid"))?;
    let priority = priority(q("priority"))?;
    let extras = [("sound", "sound"), ("click", "url"), ("icon", "icon"), ("color", "color"), ("group", "tag"), ("route", "path")]
        .into_iter()
        .filter_map(|(arg, key)| q(arg).map(|v| (key, v)))
        .collect();
    Ok(Box::new(Lauther { token: Secret::new(token), priority, extras }))
}

impl Notify for Lauther {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut payload = json!({
            "title": msg.title,
            "message": crate::http::TEXT,
            "priority": self.priority,
        });
        for (k, v) in &self.extras {
            payload[*k] = json!(v);
        }
        let req = ctx.post(NOTIFY_URL)
            .bearer(self.token.expose())
            .json_text(&payload, msg.body);
        Plan::send_expect(req, &[200])
    }
}
