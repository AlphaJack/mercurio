//! SIGNL4 (`signl4://`): alerts through SIGNL4.
//!
//! `?action=` sets the alert status: `trigger` (default) raises a new alert, `acknowledge` and `resolve` update one, `map` resolves on a success notification and raises otherwise. `?status=` still wins when given. Every action but `trigger` needs the same external ID from one notification to the next: `?external_id=` (alias `dedup`), else the SHA-256 of the title (or of the body's first line when there is no title), as Apprise.

use serde_json::{Map, Value, json};

use crate::http::Request;
use crate::message::NotifyType;
use crate::parse::{parse_bool, validate_nonblank};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "signl4",
    name: "SIGNL4",
    schemes: &["signl4"],
    service_url: "https://signl4.com/",
    parse,
    templates: &[
        "{schema}://{secret}",
    ],
    tokens: &[
        Param::new("secret", "Secret").required().secret(),
    ],
    params: &[
        Param::new("action", "Action").choice(ACTIONS).default("trigger"),
        Param::new("alerting_scenario", "Alerting Scenario"),
        Param::new("external_id", "External ID").aliases(&["dedup"]),
        Param::new("filtering", "Filtering").bool(false),
        Param::new("location", "Location"),
        Param::new("service", "Service"),
        Param::new("status", "Status"),
    ],
    ..ServiceDef::DEFAULTS
};

/// Actions, in lookup order (a prefix such as `r` names one).
const ACTIONS: &[&str] = &["trigger", "map", "acknowledge", "resolve"];

#[derive(Debug)]
struct Signl4 {
    secret: Secret,
    service: Option<String>,
    location: Option<String>,
    alerting_scenario: Option<String>,
    filtering: bool,
    external_id: Option<String>,
    status: Option<String>,
    action: &'static str,
}

fn param_unquoted(u: &ParsedUrl, key: &str) -> Option<String> {
    u.param_nonempty(key).map(unquote)
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let secret = param_unquoted(u, "secret").unwrap_or_else(|| u.host());
    let secret = validate_nonblank(&secret)
        .ok_or_else(|| SERVICE.err("an invalid SIGNL4 team or integration secret was specified"))?;
    let action = match SERVICE.text(u, "action") {
        None => "trigger",
        Some(a) => {
            let a = a.trim().to_lowercase();
            ACTIONS
                .iter()
                .copied()
                .find(|x| x.starts_with(a.as_str()))
                .ok_or_else(|| SERVICE.err("the SIGNL4 action specified is invalid"))?
        }
    };
    Ok(Box::new(Signl4 {
        secret: Secret::new(secret),
        service: SERVICE.text(u, "service"),
        location: SERVICE.text(u, "location"),
        alerting_scenario: SERVICE.text(u, "alerting_scenario"),
        filtering: param_unquoted(u, "filtering").map(|f| parse_bool(&f, false)).unwrap_or(false),
        external_id: SERVICE.text(u, "external_id").or_else(|| u.param_nonempty("dedup").map(unquote)),
        status: SERVICE.text(u, "status"),
        action,
    }))
}

impl Notify for Signl4 {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut payload = Map::new();
        let title = if msg.title.is_empty() { ctx.app_desc() } else { msg.title };
        payload.insert("title".into(), json!(title));
        payload.insert("body".into(), json!(crate::http::TEXT));
        payload.insert("X-S4-SourceSystem".into(), json!(ctx.app_id()));
        let mut opt = |k: &str, v: &Option<String>| {
            if let Some(v) = v {
                payload.insert(k.into(), json!(v));
            }
        };
        opt("X-S4-Service", &self.service);
        opt("X-S4-AlertingScenario", &self.alerting_scenario);
        opt("X-S4-Location", &self.location);
        if self.filtering {
            payload.insert("X-S4-Filtering".into(), json!(true));
        }
        let mut opt = |k: &str, v: &Option<String>| {
            if let Some(v) = v {
                payload.insert(k.into(), json!(v));
            }
        };
        let status = self.status.clone().or(match self.action {
            "resolve" => Some("resolved".into()),
            "map" if msg.kind == NotifyType::Success => Some("resolved".into()),
            "acknowledge" => Some("acknowledged".into()),
            _ => None,
        });
        let external_id = self.external_id.clone().or_else(|| {
            let key = if msg.title.is_empty() { msg.body.split('\n').next().unwrap_or_default().trim() } else { msg.title };
            (self.action != "trigger").then(|| crate::crypto::hex(&crate::crypto::sha256(key.as_bytes())))
        });
        opt("X-S4-ExternalID", &external_id);
        opt("X-S4-Status", &status);
        let req = Request::post(format!("https://connect.signl4.com/webhook/{}/", self.secret.expose()))
            .json_text(&Value::Object(payload), msg.body);
        Plan::send_expect(req, &[200, 201, 202])
    }
}
