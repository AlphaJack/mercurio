//! Splunk On-Call / VictorOps (`splunk://`, `victorops://`): incidents through the Splunk On-Call REST endpoint.

use serde_json::json;

use crate::message::NotifyType;
use crate::parse::validate_regex;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "splunk",
    name: "Splunk On-Call",
    schemes: &["splunk", "victorops"],
    service_url: "https://www.splunk.com/en_us/products/on-call.html",
    parse,
    parse_native: Some(parse_native),
    limits: Limits { title_maxlen: 60, body_maxlen: 400, body_max_line_count: 0 },
    templates: &[
        "{schema}://{routing_key}@{apikey}",
        "{schema}://{routing_key}@{apikey}/{entity_id}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").secret_key("^[A-Z0-9_-]+$"),
        Param::new("entity_id", "Entity ID"),
        Param::new("routing_key", "Target Routing Key").required().pattern("^[A-Z0-9_-]+$"),
    ],
    params: &[
        Param::new("action", "Action").choice(&["map", "info", "acknowledgement", "warning", "recovery", "resolve", "critical"]).default("map"),
        Param::sets("apikey", &["apikey"]),
        Param::sets("entity_id", &["entity_id"]),
        Param::sets("routing_key", &["routing_key"]).aliases(&["route"]),
        Param::new("mapping", "Action Mapping").prefix(":"),
    ],
    ..ServiceDef::DEFAULTS
};

/// Actions, in lookup order.
const ACTIONS: &[&str] = &["map", "info", "acknowledgement", "warning", "recovery", "resolve", "critical"];
const MESSAGE_TYPES: &[&str] = &["CRITICAL", "WARNING", "ACKNOWLEDGEMENT", "INFO", "RECOVERY"];

#[derive(Debug)]
struct Splunk {
    apikey: Secret,
    routing_key: String,
    /// `None`: `{app_id}/{routing_key}`.
    entity_id: Option<String>,
    action: &'static str,
    /// Message type per notify type: info, success, warning, failure.
    mapping: [&'static str; 4],
}

fn kind_index(k: NotifyType) -> usize {
    NotifyType::ALL.iter().position(|x| *x == k).unwrap_or(0)
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let entity = u.text("entity_id").unwrap_or_else(|| unquote(u.fullpath.as_deref().unwrap_or("")));
    let apikey = u.text("apikey").unwrap_or_else(|| u.host());
    let routing = u.text("routing_key").or_else(|| u.text("route")).unwrap_or_else(|| u.user().unwrap_or_default());

    let apikey = validate_regex(&apikey, r"^[A-Z0-9_-]+$", "i", true)
        .ok_or_else(|| SERVICE.err("the Splunk API Key specified is invalid"))?;
    let routing_key = validate_regex(&routing, r"^[A-Z0-9_-]+$", "i", true)
        .ok_or_else(|| SERVICE.err("the Splunk Routing Key specified is invalid"))?;
    let entity = entity.trim_matches([' ', '\r', '\n', '\t', '\x0b', '/']);
    let entity_id = (!entity.is_empty()).then(|| entity.to_owned());

    let action = match u.text("action") {
        None => "map",
        Some(a) => crate::util::starting_with(ACTIONS, &a)
            .ok_or_else(|| SERVICE.err("the Splunk action specified is invalid"))?,
    };

    let mut mapping = ["INFO", "RECOVERY", "WARNING", "CRITICAL"];
    for (k, v) in u.query_colon.iter() {
        let (k, v) = (unquote(k), unquote(v));
        let kind = NotifyType::starting_with(&k)
            .ok_or_else(|| SERVICE.err("the Splunk mapping key specified is invalid"))?;
        let upper = v.to_uppercase();
        let mt = MESSAGE_TYPES
            .iter()
            .copied()
            .find(|m| m.starts_with(upper.as_str()))
            .ok_or_else(|| SERVICE.err("the Splunk mapping value specified is invalid"))?;
        mapping[kind_index(kind)] = mt;
    }
    Ok(Box::new(Splunk { apikey: Secret::new(apikey), routing_key, entity_id, action, mapping }))
}

/// `https://alert.victorops.com/integrations/generic/{ver}/alert/{apikey}/{routing_key}[/{entity_id}]`.
fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(
        r"(?i)^https?://alert\.victorops\.com/integrations/generic/(?P<version>[0-9]+)/alert/(?P<apikey>[0-9a-z_-]+)(?:/(?P<routing_key>[^?/]+))(?:/(?P<entity_id>[^?]+))?/*(?P<params>\?.+)?\n?$"
    );
    let c = re.captures(url)?;
    Some(format!(
        "splunk://{}@{}/{}{}",
        &c["routing_key"],
        &c["apikey"],
        c.name("entity_id").map(|m| m.as_str()).unwrap_or(""),
        c.name("params").map(|m| m.as_str()).unwrap_or("")
    ))
}

impl Notify for Splunk {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let message_type = match self.action {
            "map" => self.mapping[kind_index(msg.kind)],
            "acknowledgement" => "ACKNOWLEDGEMENT",
            "info" => "INFO",
            "critical" => "CRITICAL",
            "warning" => "WARNING",
            _ => "RECOVERY",
        };
        let payload = json!({
            "entity_id": self.entity_id.clone().unwrap_or_else(|| format!("{}/{}", ctx.app_id(), self.routing_key)),
            "message_type": message_type,
            "entity_display_name": if msg.title.is_empty() { ctx.app_desc() } else { msg.title },
            "state_message": crate::http::TEXT,
            "monitoring_tool": ctx.app_id(),
        });
        let url = format!(
            "https://alert.victorops.com/integrations/generic/20131114/alert/{}/{}",
            self.apikey.expose(),
            self.routing_key
        );
        let req = ctx.post(url)
            .json_text(&payload, msg.body);
        Plan::send_expect(req, &[200])
    }
}
