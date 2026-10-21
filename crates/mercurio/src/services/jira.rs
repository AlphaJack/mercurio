//! Jira Service Management (`jira://`, `opsgenie://`): creates and manages alerts through the JSM Operations alert API.
//!
//! `opsgenie://` URLs land here too: Opsgenie shuts down on 2027-04-05 and its alert API lives on unchanged as JSM Operations (`api.atlassian.com/jsm/ops/integration/v2/alerts`, `GenieKey` auth).
//!
//! The `requestId`s of created alerts are kept in the persistent store (60 days) so later `close`/`acknowledge`/`note`/`delete` actions act on them.
//!
//! # Differences with Apprise
//!
//! - `opsgenie://` URLs are sent by the `jira` service to Jira Service Management Operations (Apprise posts them to `api(.eu).opsgenie.com`, which shuts down on 2027-04-05); the key must come from a JSM Operations API integration. `?region=eu` no longer changes the host.

use serde_json::{Map, Value, json};

use crate::parse::{is_uuid, parse_list, validate_nonblank};
use super::_alerts::AlertJob;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef, UrlIdentifier};
use crate::url::{ParsedUrl, unquote};
use crate::{NotifyType, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "jira",
    name: "Jira",
    schemes: &["jira", "opsgenie"],
    service_url: "https://atlassian.com/",
    parse,
    limits: Limits { title_maxlen: 250, body_maxlen: 15000, body_max_line_count: 0 },
    templates: &[
        "{schema}://{apikey}",
        "{schema}://{user}@{apikey}",
        "{schema}://{apikey}/{targets}",
        "{schema}://{user}@{apikey}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret(),
        Param::new("target_escalation", "Target Escalation").prefix("^"),
        Param::new("target_schedule", "Target Schedule").prefix("*"),
        Param::new("target_team", "Target Team").prefix("#"),
        Param::new("target_user", "Target User").prefix("@"),
        Param::new("targets", "Targets ").list("/").group(&["target_escalation", "target_schedule", "target_team", "target_user"]),
        Param::new("user", "Username"),
    ],
    params: &[
        Param::new("action", "Action").choice(&["map", "new", "close", "delete", "acknowledge", "note"]).default("map"),
        Param::new("alias", "Alias"),
        Param::new("batch", "Batch Mode").bool(false),
        Param::new("entity", "Entity"),
        Param::new("priority", "Priority").choice(&["1", "2", "3", "4", "5"]).default("3"),
        Param::new("region", "Region Name").choice(&["us", "eu"]).default("us"),
        Param::new("tags", "Tags"),
        Param::sets("to", &["targets"]),
        Param::new("details", "Details").prefix("+"),
        Param::new("mapping", "Action Mapping").prefix(":"),
    ],
    ..ServiceDef::DEFAULTS
};

const BODY_MINLEN: usize = 130;
const BATCH_SIZE: usize = 50;
const ACTIONS: &[&str] = &["map", "new", "close", "delete", "acknowledge", "note"];
const PRIORITY_MAP: &[(&str, u8)] = &[
    ("l", 1),
    ("m", 2),
    ("n", 3),
    ("h", 4),
    ("e", 5),
    ("1", 1),
    ("2", 2),
    ("3", 3),
    ("4", 4),
    ("5", 5),
    ("p1", 1),
    ("p2", 2),
    ("p3", 3),
    ("p4", 4),
    ("p5", 5),
];

#[derive(Debug)]
struct Jira {
    apikey: Secret,
    region: &'static str,
    url: &'static str,
    user: Option<String>,
    priority: u8,
    action: &'static str,
    /// Action per notify type (info, success, warning, failure).
    mapping: [&'static str; 4],
    details: Vec<(String, String)>,
    batch_size: usize,
    tags: Vec<String>,
    entity: Option<String>,
    alias: Option<String>,
    targets: Vec<Value>,
}

fn kind_index(k: NotifyType) -> usize {
    NotifyType::ALL.iter().position(|t| *t == k).unwrap_or(0)
}


fn char_tail(s: &str) -> &str {
    let mut chars = s.chars();
    chars.next();
    chars.as_str()
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut apikey = u.host();
    if let Some(k) = u.text("apikey") {
        apikey = k;
    }
    let apikey = validate_nonblank(&apikey).ok_or_else(|| SERVICE.err("an invalid Jira API Key was specified"))?;

    let priority = {
        let p = SERVICE.text_or_default(u, "priority").to_lowercase();
        PRIORITY_MAP.iter().find(|(k, _)| p.starts_with(k)).map(|(_, v)| *v).unwrap_or(3)
    };

    let url = "https://api.atlassian.com/jsm/ops/integration/v2/alerts";
    let region = match SERVICE.text(u, "region").map(|r| r.to_lowercase()).as_deref() {
        None | Some("us") => "us",
        Some("eu") => "eu",
        Some(_) => return Err(SERVICE.err("the Jira region specified is invalid")),
    };

    let action = match SERVICE.text(u, "action") {
        None => SERVICE.default_of("action"),
        Some(a) => ACTIONS
            .iter()
            .copied()
            .find(|x| x.starts_with(a.as_str()))
            .ok_or_else(|| SERVICE.err(format!("the Jira action specified ({a}) is invalid")))?,
    };

    let mut mapping = ["note", "close", "new", "new"];
    for (k, v) in u.query_colon.iter() {
        let (k, v) = (unquote(k), unquote(v));
        let idx = NotifyType::ALL
            .iter()
            .position(|t| t.as_str().starts_with(k.as_str()))
            .ok_or_else(|| SERVICE.err(format!("the Jira mapping key specified ({k}) is invalid")))?;
        let lower = v.to_lowercase();
        let action = ACTIONS[1..]
            .iter()
            .copied()
            .find(|x| x.starts_with(lower.as_str()))
            .ok_or_else(|| SERVICE.err(format!("the Jira mapping value specified ({v}) is invalid")))?;
        mapping[idx] = action;
    }

    let mut details: Vec<(String, String)> = Vec::new();
    for (k, v) in u.query_plus.iter() {
        let (k, v) = (unquote(k), unquote(v));
        if let Some(slot) = details.iter_mut().find(|(x, _)| *x == k) {
            slot.1 = v;
        } else {
            details.push((k, v));
        }
    }

    let batch = SERVICE.flag(u, "batch");
    let tags = match SERVICE.text(u, "tags") {
        Some(t) => parse_list(parse_list([t])),
        None => Vec::new(),
    };

    let mut raw_targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        raw_targets.push(to.to_string());
    }
    let mut targets = Vec::new();
    for t in parse_list(raw_targets) {
        let target = t.trim();
        if target.chars().count() < 2 {
            continue;
        }
        let rest = char_tail(target);
        let (kind, id, name_key) = match target.chars().next() {
            Some('#') => ("team", rest, "name"),
            Some('*') => ("schedule", rest, "name"),
            Some('^') => ("escalation", rest, "name"),
            Some('@') => ("user", rest, "username"),
            _ => ("user", target, "username"),
        };
        let key = if is_uuid(id) { "id" } else { name_key };
        targets.push(json!({"type": kind, key: id}));
    }

    Ok(Box::new(Jira {
        apikey: Secret::new(apikey),
        region,
        url,
        user: u.user().filter(|s| !s.is_empty()),
        priority,
        action,
        mapping,
        details,
        batch_size: if batch { BATCH_SIZE } else { 1 },
        tags,
        entity: SERVICE.text(u, "entity"),
        alias: SERVICE.text(u, "alias"),
        targets,
    }))
}

impl Notify for Jira {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let action = if self.action == "map" { self.mapping[kind_index(msg.kind)] } else { self.action };
        let key_source = self
            .entity
            .clone()
            .or_else(|| self.alias.clone())
            .unwrap_or_else(|| if msg.title.is_empty() { ctx.app_id().to_string() } else { msg.title.to_string() });
        let headers = vec![
            ("User-Agent", ctx.app_id().to_string()),
            ("Accepts", "application/json".to_string()),
            ("Content-Type", "application/json".to_string()),
            ("Authorization", format!("GenieKey {}", self.apikey.expose())),
        ];
        let mut note = json!({"source": ctx.app_desc(), "note": msg.body});
        if let Some(u) = &self.user {
            note["user"] = json!(u);
        }
        let mut job = AlertJob {
            name: "Jira",
            url: self.url,
            headers,
            action,
            key_source,
            payload: Value::Null,
            batches: Vec::new(),
            note,
            piece: msg.index,
        };
        if action != "new" {
            return job.plan(ctx);
        }
        let mut details = Map::new();
        for (k, v) in &self.details {
            details.insert(k.clone(), json!(v));
        }
        if !details.contains_key("type") {
            details.insert("type".into(), json!(msg.kind.as_str()));
        }
        let title_body = if msg.title.is_empty() { msg.body } else { msg.title };
        let message = if title_body.chars().count() > BODY_MINLEN {
            format!("{}...", title_body.chars().take(BODY_MINLEN - 3).collect::<String>())
        } else {
            title_body.to_string()
        };
        let mut payload = json!({
            "source": ctx.app_desc(),
            "message": message,
            "description": msg.body,
            "details": Value::Object(details),
            "priority": format!("P{}", self.priority),
        });
        if !self.tags.is_empty() {
            payload["tags"] = json!(self.tags);
        }
        if let Some(e) = &self.entity {
            payload["entity"] = json!(e);
        }
        if let Some(a) = &self.alias {
            payload["alias"] = json!(a);
        }
        if let Some(u) = &self.user {
            payload["user"] = json!(u);
        }

        let length = if self.targets.is_empty() { 1 } else { self.targets.len() };
        job.batches = (0..length)
            .step_by(self.batch_size)
            .map(|index| {
                let responders = (!self.targets.is_empty()).then(|| {
                    let end = (index + self.batch_size).min(self.targets.len());
                    Value::Array(self.targets[index..end].to_vec())
                });
                (index, responders)
            })
            .collect();
        job.payload = payload;
        job.plan(ctx)
    }

    fn url_identifier(&self) -> UrlIdentifier {
        UrlIdentifier::parts(["jira", self.region, self.apikey.expose()])
    }

}
