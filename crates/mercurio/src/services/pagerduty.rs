//! PagerDuty (`pagerduty://`): events through the PagerDuty Events API.
//!
//! `?action=` picks the event: `trigger` (default) raises or updates an incident, `resolve` resolves one, `map` resolves on a success notification and raises otherwise. `map` and `resolve` need the same deduplication key from one notification to the next: `?dedup=`, else the SHA-256 of the first line of the body (where the title is), as Apprise.

use serde_json::{Map, Value, json};

use crate::asset::ImageSize;
use crate::message::NotifyType;
use crate::parse::validate_nonblank;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "pagerduty",
    name: "Pager Duty",
    schemes: &["pagerduty"],
    service_url: "https://pagerduty.com/",
    parse,
    limits: Limits { title_maxlen: 0, ..Limits::DEFAULT },
    templates: &[
        "{schema}://{integrationkey}@{apikey}",
        "{schema}://{integrationkey}@{apikey}/{source}",
        "{schema}://{integrationkey}@{apikey}/{source}/{component}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret(),
        Param::new("component", "Component").default("Notification"),
        Param::new("integrationkey", "Integration Key").required().secret(),
        Param::new("source", "Source").note("defaults to the app id"),
    ],
    params: &[
        Param::new("action", "Action").choice(ACTIONS).default("trigger"),
        Param::new("class", "Class"),
        Param::new("click", "Click"),
        Param::new("dedup", "Deduplication Key"),
        Param::new("group", "Group"),
        Param::new("image", "Include Image").bool(true),
        Param::new("region", "Region Name").choice(&["us", "eu"]).default("us"),
        Param::new("severity", "Severity").choice(&["info", "warning", "critical", "error"]),
        Param::new("details", "Custom Details").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

/// Actions, in lookup order (a prefix such as `r` names one).
const ACTIONS: &[&str] = &["trigger", "map", "resolve"];

/// Severities, in lookup order.
const SEVERITIES: &[&str] = &["info", "warning", "critical", "error"];

#[derive(Debug)]
struct PagerDuty {
    apikey: Secret,
    integration_key: Secret,
    /// `None`: the app id.
    source: Option<String>,
    component: String,
    group: Option<String>,
    class_id: Option<String>,
    click: Option<String>,
    details: Vec<(String, String)>,
    eu: bool,
    severity: Option<&'static str>,
    include_image: bool,
    action: &'static str,
    /// `None`: derived from the body for `map` and `resolve`, none for `trigger`.
    dedup: Option<String>,
}

/// Non-empty query value, unquoted a second time.
fn param_unquoted(u: &ParsedUrl, key: &str) -> Option<String> {
    u.param_nonempty(key).map(unquote)
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let apikey = param_unquoted(u, "apikey").unwrap_or_else(|| u.host());
    let integration = param_unquoted(u, "integrationkey").unwrap_or_else(|| u.user().unwrap_or_default());
    let mut path = u.path_segments().into_iter();
    let source = param_unquoted(u, "source").or_else(|| path.next());
    let component = param_unquoted(u, "component").or_else(|| path.next());

    let apikey =
        validate_nonblank(&apikey).ok_or_else(|| SERVICE.err("an invalid Pager Duty API Key was specified"))?;
    let integration_key = validate_nonblank(&integration)
        .ok_or_else(|| SERVICE.err("an invalid Pager Duty Routing Key was specified"))?;
    let source = match source.filter(|s| !s.is_empty()) {
        Some(s) => Some(
            validate_nonblank(&s)
                .ok_or_else(|| SERVICE.err("an invalid Pager Duty Notification Source was specified"))?,
        ),
        None => None,
    };
    let component = match component.filter(|s| !s.is_empty()) {
        Some(c) => validate_nonblank(&c)
            .ok_or_else(|| SERVICE.err("an invalid Pager Duty Notification Component was specified"))?,
        None => "Notification".to_owned(),
    };
    let eu = match SERVICE.text_or_default(u, "region").to_lowercase().as_str() {
        "us" => false,
        "eu" => true,
        _ => return Err(SERVICE.err("the PagerDuty region specified is invalid")),
    };
    let severity = match SERVICE.text(u, "severity") {
        None => None,
        Some(s) => Some(
            SEVERITIES
                .iter()
                .copied()
                .find(|x| x.starts_with(s.as_str()))
                .ok_or_else(|| SERVICE.err("the PagerDuty severity specified is invalid"))?,
        ),
    };
    let action = match SERVICE.text(u, "action") {
        None => "trigger",
        Some(a) => {
            let a = a.trim().to_lowercase();
            ACTIONS
                .iter()
                .copied()
                .find(|x| x.starts_with(a.as_str()))
                .ok_or_else(|| SERVICE.err("the PagerDuty action specified is invalid"))?
        }
    };
    let details = u.query_plus.iter().map(|(k, v)| (unquote(k), unquote(v))).collect();
    Ok(Box::new(PagerDuty {
        apikey: Secret::new(apikey),
        integration_key: Secret::new(integration_key),
        source,
        component,
        group: SERVICE.text(u, "group"),
        class_id: SERVICE.text(u, "class"),
        click: SERVICE.text(u, "click"),
        details,
        eu,
        severity,
        include_image: SERVICE.flag(u, "image"),
        action,
        dedup: SERVICE.text(u, "dedup").map(|d| d.trim().to_owned()).filter(|d| !d.is_empty()),
    }))
}

impl Notify for PagerDuty {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let resolve = self.action == "resolve" || (self.action == "map" && msg.kind == NotifyType::Success);
        let dedup = self.dedup.clone().or_else(|| {
            let first = msg.body.split('\n').next().unwrap_or_default().trim();
            (self.action != "trigger").then(|| crate::crypto::hex(&crate::crypto::sha256(first.as_bytes())))
        });
        let url = if self.eu {
            "https://events.eu.pagerduty.com/v2/enqueue"
        } else {
            "https://events.pagerduty.com/v2/enqueue"
        };
        if resolve {
            // A resolve only names the incident, as in PagerDuty's own example.
            let payload = json!({
                "routing_key": self.integration_key.expose(),
                "event_action": "resolve",
                "dedup_key": dedup,
            });
            let req = ctx
                .post(url)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Token token={}", self.apikey.expose()))
                .json(&payload);
            return Plan::send_expect(req, &[200, 201, 202]);
        }
        let severity = self.severity.unwrap_or(match msg.kind {
            NotifyType::Info | NotifyType::Success => "info",
            NotifyType::Warning => "warning",
            NotifyType::Failure => "critical",
        });
        let mut inner = json!({
            "summary": crate::http::TEXT,
            "severity": severity,
            "source": self.source.as_deref().unwrap_or(ctx.app_id()),
            "component": self.component,
        });
        if let Some(g) = &self.group {
            inner["group"] = json!(g);
        }
        if let Some(c) = &self.class_id {
            inner["class"] = json!(c);
        }
        if !self.details.is_empty() {
            let mut m = Map::new();
            for (k, v) in &self.details {
                m.insert(k.clone(), json!(v));
            }
            inner["custom_details"] = Value::Object(m);
        }
        let mut payload = json!({
            "routing_key": self.integration_key.expose(),
            "payload": inner,
            "client": ctx.app_id(),
            "event_action": "trigger",
        });
        if let Some(d) = &dedup {
            payload["dedup_key"] = json!(d);
        }
        if let Some(c) = &self.click {
            payload["links"] = json!([{"href": c}]);
        }
        if self.include_image
            && let Some(img) = ctx.asset.image_url(msg.kind, ImageSize::Xy128)
        {
            payload["images"] = json!([{"src": img, "alt": msg.kind.as_str()}]);
        }
        let req = ctx.post(url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Token token={}", self.apikey.expose()))
            .json_text(&payload, msg.body);
        Plan::send_expect(req, &[200, 201, 202])
    }
}
