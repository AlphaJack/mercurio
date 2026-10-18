//! SIGNL4 (`signl4://`): alerts through SIGNL4.

use serde_json::{Map, Value, json};

use crate::http::Request;
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
        Param::new("alerting_scenario", "Alerting Scenario"),
        Param::new("external_id", "External ID"),
        Param::new("filtering", "Filtering").bool(false),
        Param::new("location", "Location"),
        Param::new("service", "Service"),
        Param::new("status", "Status"),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Signl4 {
    secret: Secret,
    service: Option<String>,
    location: Option<String>,
    alerting_scenario: Option<String>,
    filtering: bool,
    external_id: Option<String>,
    status: Option<String>,
}

fn param_unquoted(u: &ParsedUrl, key: &str) -> Option<String> {
    u.param_nonempty(key).map(unquote)
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let secret = param_unquoted(u, "secret").unwrap_or_else(|| u.host());
    let secret = validate_nonblank(&secret)
        .ok_or_else(|| SERVICE.err("an invalid SIGNL4 team or integration secret was specified"))?;
    Ok(Box::new(Signl4 {
        secret: Secret::new(secret),
        service: SERVICE.text(u, "service"),
        location: SERVICE.text(u, "location"),
        alerting_scenario: SERVICE.text(u, "alerting_scenario"),
        filtering: param_unquoted(u, "filtering").map(|f| parse_bool(&f, false)).unwrap_or(false),
        external_id: SERVICE.text(u, "external_id"),
        status: SERVICE.text(u, "status"),
    }))
}

impl Notify for Signl4 {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut payload = Map::new();
        let title = if msg.title.is_empty() { ctx.app_desc() } else { msg.title };
        payload.insert("title".into(), json!(title));
        payload.insert("body".into(), json!(msg.body));
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
        opt("X-S4-ExternalID", &self.external_id);
        opt("X-S4-Status", &self.status);
        let req = Request::post(format!("https://connect.signl4.com/webhook/{}/", self.secret.expose()))
            .json(&Value::Object(payload));
        Plan::send_expect(req, &[200, 201, 202])
    }
}
