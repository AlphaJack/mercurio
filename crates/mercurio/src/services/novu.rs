//! Novu (`novu://`): triggers a Novu workflow for subscribers. Written from the Novu API reference (<https://docs.novu.co/api-reference/events/trigger-event>).
//!
//! `novu://{api_key}/{workflow_id}/{subscriber}[/{subscriber}...]`
//!
//! Options:
//! - `?region=eu` uses `https://eu.api.novu.co` (default `https://api.novu.co`).
//! - `?host=novu.example.com[:port][/path]` (or a full `http(s)://` URL) points at a self-hosted Novu API; it wins over `region`.
//! - `?to=a,b` adds subscribers; `?transaction=..` sets `transactionId`.
//! - `:key=value` adds `key` to the trigger `payload`; `+Header=value` adds an HTTP header.
//!
//! Each subscriber is a subscriber id, an e-mail (`{"subscriberId": email, "email": email}`) or `+<phone>` (`{"subscriberId": phone, "phone": phone}`). One `POST /v1/events/trigger` is sent per 100 subscribers with `Authorization: ApiKey {api_key}` and `{"name": workflow_id, "to": [...], "payload": {"title", "body", "type"}}`. Success is any 2xx whose body (or its `data` object) does not say `"acknowledged": false`.
//!
//! # Differences with Apprise
//!
//! - Not in Apprise; written from the vendor documentation (hand-written fixtures).

use serde_json::{Map, Value, json};

use super::_email_api::{Recipient, api_base, colon_data, recipient};
use crate::parse::{parse_list, validate_regex};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Error, NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "novu",
    name: "Novu",
    schemes: &["novu"],
    service_url: "https://novu.co/",
    parse,
    formats: &[NotifyFormat::Text, NotifyFormat::Html, NotifyFormat::Markdown],
    templates: &[
        "novu://{api_key}/{workflow_id}/{targets}",
    ],
    tokens: &[
        Param::new("api_key", "API Key").secret().required(),
        Param::new("targets", "Subscribers").list("/").required().note("subscriber id, e-mail or `+phone`"),
        Param::new("workflow_id", "Workflow ID").required(),
    ],
    params: &[
        Param::new("host", "API Host").note("self-hosted API, `host[:port][/path]` or a full `http(s)://` URL; wins over `region`"),
        Param::new("region", "Region").choice(&["us", "eu"]).default("us"),
        Param::sets("to", &["targets"]),
        Param::new("transaction", "Transaction ID"),
        Param::new("payload", "Payload Extras").prefix(":"),
        Param::new("headers", "HTTP Header").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

const US_API: &str = "https://api.novu.co";
const EU_API: &str = "https://eu.api.novu.co";
const BATCH: usize = 100;

#[derive(Debug)]
struct Novu {
    api_key: Secret,
    base: String,
    workflow: String,
    to: Vec<Value>,
    labels: Vec<String>,
    transaction: Option<String>,
    data: Vec<(String, String)>,
    headers: Vec<(String, String)>,
}

fn subscriber(entry: &str) -> Value {
    match recipient(entry) {
        Recipient::Id(id) => json!(id),
        Recipient::Email(e) => json!({"subscriberId": e, "email": e}),
        Recipient::Phone(p) => json!({"subscriberId": p, "phone": p}),
    }
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let api_key = validate_regex(&u.host(), r"^[^\s/]+$", "", true)
        .ok_or_else(|| SERVICE.err("an invalid Novu API key was specified"))?;
    let mut segs = u.path_segments();
    if segs.is_empty() {
        return Err(SERVICE.err("no Novu workflow id was specified"));
    }
    let workflow = segs.remove(0);
    if let Some(to) = u.param_nonempty("to") {
        segs.extend(parse_list([unquote(to)]));
    }
    let mut labels: Vec<String> = Vec::new();
    for s in segs {
        if !labels.contains(&s) {
            labels.push(s);
        }
    }
    if labels.is_empty() {
        return Err(SERVICE.err("no Novu subscribers were specified"));
    }
    let default = match u.param_nonempty("region").map(str::to_lowercase).as_deref() {
        None | Some("us") => US_API,
        Some("eu") => EU_API,
        Some(_) => return Err(SERVICE.err("the Novu region specified is invalid")),
    };
    let base = api_base(u, default).map_err(|_| SERVICE.err("an invalid Novu host was specified"))?;
    Ok(Box::new(Novu {
        api_key: Secret::new(api_key),
        base,
        workflow,
        to: labels.iter().map(|s| subscriber(s)).collect(),
        labels,
        transaction: SERVICE.text(u, "transaction"),
        data: colon_data(u),
        headers: u.query_plus.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
    }))
}

impl Notify for Novu {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut data = Map::new();
        data.insert("title".into(), json!(msg.title));
        data.insert("body".into(), json!(crate::http::TEXT));
        data.insert("type".into(), json!(msg.kind.as_str()));
        for (k, v) in &self.data {
            data.insert(k.clone(), json!(v));
        }
        let url = format!("{}/v1/events/trigger", self.base);
        let plans = self.to.chunks(BATCH).zip(self.labels.chunks(BATCH)).map(|(to, labels)| {
            let mut payload = json!({"name": self.workflow, "to": to, "payload": data});
            if let Some(t) = &self.transaction {
                payload["transactionId"] = json!(t);
            }
            let req = ctx.post(&url)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("Authorization", format!("ApiKey {}", self.api_key.expose()))
                .headers(self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                .json_text(&payload, msg.body);
            Plan::send_check(req, |r| {
                r.error_for_status()?;
                // The v1 API wraps the response in `data`; accept both shapes.
                let ack = r.json().and_then(|j| j.get("acknowledged").or(j.pointer("/data/acknowledged")).cloned());
                if ack == Some(Value::Bool(false)) {
                    return Err(Error::Service("Novu did not acknowledge the trigger".into()));
                }
                Ok(())
            })
            .target(labels.join(", "))
        });
        Plan::all(plans.collect::<Vec<_>>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Request;
    use crate::testing::FakeTransport;

    fn send(url: &str, status: u16, body: &str) -> (bool, Vec<Request>) {
        let t = crate::parse(url).unwrap();
        let fake = FakeTransport::new();
        fake.respond(status, body.as_bytes().to_vec());
        let d = t.send(&crate::Message::new("b").title("t"), &fake, &crate::Asset::default());
        (d.is_success(), fake.requests())
    }

    #[test]
    fn validation() {
        assert!(crate::parse("novu://key").is_err());
        assert!(crate::parse("novu://key/wf").is_err());
        assert!(crate::parse("novu://key/wf/sub?region=mars").is_err());
        assert!(crate::parse("novu://key/wf/sub").is_ok());
    }

    #[test]
    fn payload_and_recipients() {
        let (ok, reqs) = send("novu://key/wf/sub1/a@example.com/+15551234567?:extra=1", 201, "{}");
        assert!(ok);
        assert_eq!(reqs[0].url, "https://api.novu.co/v1/events/trigger");
        assert_eq!(reqs[0].header_value("Authorization"), Some("ApiKey key"));
        let body: Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["name"], "wf");
        assert_eq!(body["to"][0], "sub1");
        assert_eq!(body["to"][1], json!({"subscriberId": "a@example.com", "email": "a@example.com"}));
        assert_eq!(body["to"][2], json!({"subscriberId": "+15551234567", "phone": "+15551234567"}));
        assert_eq!(body["payload"], json!({"title": "t", "body": "b", "type": "info", "extra": "1"}));
    }

    #[test]
    fn hosts_and_ack() {
        let (_, reqs) = send("novu://key/wf/s?region=eu", 201, "{}");
        assert_eq!(reqs[0].url, "https://eu.api.novu.co/v1/events/trigger");
        let (_, reqs) = send("novu://key/wf/s?host=novu.example.com:3000/api", 201, "{}");
        assert_eq!(reqs[0].url, "https://novu.example.com:3000/api/v1/events/trigger");
        let (ok, _) = send("novu://key/wf/s", 201, r#"{"data":{"acknowledged":true}}"#);
        assert!(ok);
        let (ok, _) = send("novu://key/wf/s", 201, r#"{"acknowledged":false}"#);
        assert!(!ok);
        let (ok, _) = send("novu://key/wf/s", 201, r#"{"data":{"acknowledged":false}}"#);
        assert!(!ok);
        let (ok, _) = send("novu://key/wf/s", 401, "{}");
        assert!(!ok);
    }
}
