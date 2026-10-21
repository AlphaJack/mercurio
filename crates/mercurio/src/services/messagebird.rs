//! Bird, formerly MessageBird, SMS (`msgbird://`).
//!
//! `POST https://{region}.platform.bird.com/v1/sms/messages` with a Bird API key (`bk_{region}_...`) as a Bearer token, one request per target. Classic MessageBird keys (25 characters, `rest.messagebird.com`) stop working on 2026-12-31 and are rejected.
//!
//! # Differences with Apprise
//!
//! - Apprise posts to the classic `rest.messagebird.com/messages` API with a 25-character key, while mercurio uses Bird's SMS API (`{region}.platform.bird.com/v1/sms/messages`, `bk_...` key as Bearer, JSON `from`/`to`/`text`/`category`, new `?category=`); classic keys, which stop working on 2026-12-31, are rejected.

use serde_json::json;

use super::_sms::{expect, no_targets, per_target, to_param};
use crate::parse::{is_phone_no, parse_phone_no, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "messagebird",
    name: "Bird (MessageBird)",
    schemes: &["msgbird"],
    service_url: "https://bird.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    templates: &[
        "{schema}://{apikey}/{source}",
        "{schema}://{apikey}/{source}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret().pattern(KEY_RE),
        Param::new("source", "Source Phone No").required().pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").group(&["target_phone"]),
    ],
    params: &[
        Param::new("category", "Category")
            .choice(&["transactional", "marketing", "authentication", "service"])
            .default("transactional"),
        Param::sets("from", &["source"]),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

/// `bk_{region}_{payload}`: the region picks the API host.
const KEY_RE: &str = "^bk_[a-z0-9]+_[a-z0-9_-]+$";
const CATEGORIES: &[&str] = &["transactional", "marketing", "authentication", "service"];

#[derive(Debug)]
struct MessageBird {
    apikey: Secret,
    region: String,
    category: &'static str,
    source: String,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let mut source = if targets.is_empty() { None } else { Some(targets.remove(0)) };
    let apikey = u.host();
    targets.extend(to_param(u, false));
    if let Some(v) = SERVICE.text(u, "from") {
        source = Some(v);
    }

    if validate_regex(&apikey, r"^[a-z0-9]{25}$", "i", true).is_some() {
        return Err(SERVICE.err(
            "classic MessageBird API keys stop working on 2026-12-31 and are not supported: \
             create a Bird API key (bk_...)",
        ));
    }
    let apikey =
        validate_regex(&apikey, KEY_RE, "i", true).ok_or_else(|| SERVICE.err("an invalid Bird API Key was specified"))?;
    let region = apikey.split('_').nth(1).unwrap_or_default().to_lowercase();
    let category = match SERVICE.text(u, "category").map(|c| c.trim().to_lowercase()) {
        None => SERVICE.default_of("category"),
        Some(c) => CATEGORIES
            .iter()
            .copied()
            .find(|x| *x == c)
            .ok_or_else(|| SERVICE.err("an invalid Bird SMS category was specified"))?,
    };
    let source = source
        .and_then(|s| is_phone_no(&s, 10))
        .ok_or_else(|| SERVICE.err("the Bird source specified is invalid"))?
        .full;
    let parsed = parse_phone_no(&targets, true, false);
    let targets = if parsed.is_empty() {
        vec![source.clone()]
    } else {
        parsed.iter().filter_map(|t| is_phone_no(t, 10)).map(|p| p.full).collect()
    };
    Ok(Box::new(MessageBird { apikey: Secret::new(apikey), region, category, source, targets }))
}

impl Notify for MessageBird {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return no_targets("Bird");
        }
        let url = format!("https://{}.platform.bird.com/v1/sms/messages", self.region);
        let from = format!("+{}", self.source);
        per_target(self.targets.clone(), String::clone, |target| {
            let body = json!({"from": from, "to": format!("+{target}"), "text": msg.body, "category": self.category});
            let req = ctx.post(&url).header("Authorization", format!("Bearer {}", self.apikey.expose())).json(&body);
            Plan::send_check(req, |r| expect(r, &[200, 201, 202]))
        })
    }
}
