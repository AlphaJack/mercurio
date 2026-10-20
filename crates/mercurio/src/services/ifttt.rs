//! IFTTT (`ifttt://`): triggers IFTTT Webhooks events with the notification as values.
//!
//! # Differences with Apprise
//!
//! - Apprise ignores `+`/`-` options (attribute typo), while mercurio applies them. *intentional*

use serde_json::{Map, Value, json};

use crate::parse::{parse_list, validate_nonblank};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, quote, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "ifttt",
    name: "IFTTT",
    schemes: &["ifttt"],
    service_url: "https://ifttt.com/",
    parse,
    parse_native: Some(parse_native),
    templates: &[
        "{schema}://{webhook_id}/{events}",
    ],
    tokens: &[
        Param::new("events", "Events").list("/").required(),
        Param::new("webhook_id", "Webhook ID").required().secret(),
    ],
    params: &[
        Param::sets("to", &["events"]),
        Param::new("add_tokens", "Add Tokens").prefix("+"),
        Param::new("del_tokens", "Remove Tokens").prefix("-"),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Ifttt {
    webhook_id: Secret,
    events: Vec<String>,
    add_tokens: Vec<(String, String)>,
    del_tokens: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let raw = match u.user.as_deref() {
        Some(user) if !user.is_empty() => user,
        _ => u.host.as_str(),
    };
    let webhook_id =
        validate_nonblank(&unquote(raw)).ok_or_else(|| SERVICE.err("an invalid IFTTT Webhook ID was specified"))?;
    let mut events = Vec::new();
    if u.user.as_deref().is_some_and(|s| !s.is_empty()) {
        events.push(u.host());
    }
    events.extend(u.path_segments());
    if let Some(to) = u.param_nonempty("to") {
        events.extend(parse_list([to]));
    }
    let events = parse_list(events);
    if events.is_empty() {
        return Err(SERVICE.err("you must specify at least one event you wish to trigger on"));
    }
    // `+key=value` adds and `-key` removes payload values (see the module docs).
    let add_tokens = u.query_plus.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let del_tokens = u.query_minus.iter().map(|(k, _)| k.to_string()).collect();
    Ok(Box::new(Ifttt { webhook_id: Secret::new(webhook_id), events, add_tokens, del_tokens }))
}

/// `https://maker.ifttt.com/use/WEBHOOK_ID/EVENT_ID` -> `ifttt://WEBHOOK_ID@/EVENT_ID`.
fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(
        r"(?i)^https?://maker\.ifttt\.com/use/(?P<webhook_id>[A-Z0-9_-]+)(?P<events>(/[A-Z0-9_-]+)+)?/?(?P<params>\?.+)?\n?$"
    );
    let c = re.captures(url)?;
    let events = c.name("events").map(|e| format!("@{}", e.as_str())).unwrap_or_default();
    let params = c.name("params").map(|p| p.as_str()).unwrap_or("");
    Some(format!("ifttt://{}{}{}", &c["webhook_id"], events, params))
}

impl Notify for Ifttt {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut raw: Vec<(String, Value)> = vec![
            ("value1".into(), json!(msg.title)),
            ("value2".into(), json!(msg.body)),
            ("value3".into(), json!(msg.kind.as_str())),
        ];
        for (k, v) in &self.add_tokens {
            match raw.iter_mut().find(|(rk, _)| rk == k) {
                Some(slot) => slot.1 = json!(v),
                None => raw.push((k.clone(), json!(v))),
            }
        }
        let mut payload = Map::new();
        for (k, v) in raw {
            if !self.del_tokens.contains(&k) {
                payload.insert(k.to_lowercase(), v);
            }
        }
        let payload = Value::Object(payload);
        Plan::all(self.events.iter().map(|event| {
            let url = format!(
                "https://maker.ifttt.com/trigger/{}/with/key/{}",
                quote(event, "/"),
                quote(self.webhook_id.expose(), "/")
            );
            let req = ctx.post(url)
                .header("Content-Type", "application/json")
                .body(serde_json::to_vec(&payload).unwrap_or_default(), None);
            Plan::send_expect(req, &[200]).target(event.clone())
        }))
    }

}
