//! PagerTree (`pagertree://`): alerts through a PagerTree integration.

use serde_json::{Map, Value, json};

use crate::parse::{parse_list, validate_nonblank, validate_regex};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{Pairs, ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "pagertree",
    name: "PagerTree",
    schemes: &["pagertree"],
    service_url: "https://pagertree.com/",
    parse,
    templates: &[
        "{schema}://{integration}",
    ],
    tokens: &[
        Param::new("integration", "Integration ID").required().secret(),
    ],
    params: &[
        Param::new("action", "Action").choice(&["create", "acknowledge", "resolve"]).default("create"),
        Param::new("tags", "Tags"),
        Param::new("thirdparty", "Third Party ID"),
        Param::new("urgency", "Urgency").choice(&["silent", "low", "medium", "high", "critical"]),
        Param::new("headers", "HTTP Header").prefix("+"),
        Param::new("meta_extras", "Meta Extras").prefix("-"),
        Param::new("payload_extras", "Payload Extras").prefix(":"),
    ],
    ..ServiceDef::DEFAULTS
};

const ACTIONS: &[&str] = &["create", "acknowledge", "resolve"];
const URGENCIES: &[&str] = &["silent", "low", "medium", "high", "critical"];

#[derive(Debug)]
struct PagerTree {
    integration: Secret,
    action: &'static str,
    thirdparty: Option<String>,
    urgency: Option<&'static str>,
    tags: Vec<String>,
    headers: Vec<(String, String)>,
    payload_extras: Vec<(String, String)>,
    meta_extras: Vec<(String, String)>,
}

fn param_unquoted(u: &ParsedUrl, key: &str) -> Option<String> {
    u.param_nonempty(key).map(unquote)
}

fn twice(p: &Pairs) -> Vec<(String, String)> {
    // Later duplicate keys replace earlier ones in place.
    let pairs: Pairs = p.iter().map(|(k, v)| (unquote(k), unquote(v))).collect();
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let integration = param_unquoted(u, "id").or_else(|| param_unquoted(u, "integration")).unwrap_or_else(|| u.host());
    let integration = validate_regex(&integration, r"^int_[a-zA-Z0-9\-_]{7,14}$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid PagerTree Integration ID was specified"))?;
    let thirdparty = match param_unquoted(u, "tid").or_else(|| param_unquoted(u, "thirdparty")) {
        Some(t) => Some(
            validate_nonblank(&t).ok_or_else(|| SERVICE.err("an invalid PagerTree third party ID was specified"))?,
        ),
        None => None,
    };
    let action = param_unquoted(u, "action").and_then(|a| ACTIONS.iter().copied().find(|x| *x == a)).unwrap_or(SERVICE.default_of("action"));
    let urgency = param_unquoted(u, "urgency").and_then(|a| URGENCIES.iter().copied().find(|x| *x == a));
    let tags = match param_unquoted(u, "tags") {
        Some(t) => parse_list(parse_list([t])),
        None => Vec::new(),
    };
    Ok(Box::new(PagerTree {
        integration: Secret::new(integration),
        action,
        thirdparty,
        urgency,
        tags,
        headers: twice(&u.query_plus),
        payload_extras: twice(&u.query_colon),
        meta_extras: twice(&u.query_minus),
    }))
}

impl Notify for PagerTree {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut payload = Map::new();
        payload.insert("id".into(), json!(self.thirdparty.clone().unwrap_or_else(|| ctx.env().uuid4())));
        payload.insert("event_type".into(), json!(self.action));
        if self.action == "create" {
            let title = if msg.title.is_empty() { ctx.app_desc() } else { msg.title };
            payload.insert("title".into(), json!(title));
            payload.insert("description".into(), json!(msg.body));
            let meta: Map<String, Value> = self.meta_extras.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
            payload.insert("meta".into(), Value::Object(meta));
            payload.insert("tags".into(), json!(self.tags));
            if let Some(urg) = self.urgency {
                payload.insert("urgency".into(), json!(urg));
            }
        }
        for (k, v) in &self.payload_extras {
            payload.insert(k.clone(), json!(v));
        }
        let req = ctx
            .post(format!("https://api.pagertree.com/integration/{}", self.integration.expose()))
            .headers(self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .json(&Value::Object(payload));
        Plan::send_expect(req, &[200, 201, 202])
    }
}
