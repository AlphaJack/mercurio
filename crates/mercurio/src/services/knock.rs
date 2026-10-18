//! Knock (`knock://`): triggers a Knock workflow for the recipients, written from the API reference (<https://docs.knock.app/api-reference/workflows/trigger>).
//!
//! `knock://{api_key}/{workflow_key}/{recipient}[/{recipient}...]`
//!
//! Options:
//! - `?host=api.example.com[:port][/path]` (or a full `http(s)://` URL) overrides the API base (default `https://api.knock.app`).
//! - `?to=a,b` adds recipients; `?actor=..`, `?tenant=..` and `?cancel=..` (`cancellation_key`) are passed through.
//! - `:key=value` adds `key` to the workflow `data`; `+Header=value` adds an HTTP header.
//!
//! Each recipient is a user id, an e-mail (inline identification `{"id": email, "email": email}`) or `+<phone>` (`{"id": phone, "phone_number": phone}`). One `POST /v1/workflows/{key}/trigger` is sent per 1000 recipients with `Authorization: Bearer {api_key}` and `{"recipients": [...], "data": {"title", "body", "type"}}`; any 2xx is success.
//!
//! # Differences
//!
//! - Not in Apprise; written from the vendor documentation (hand-written fixtures). *intentional*

use serde_json::{Map, Value, json};

use super::_email_api::{Recipient, api_base, colon_data, recipient};
use crate::parse::{parse_list, validate_regex};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, quote, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "knock",
    name: "Knock",
    schemes: &["knock"],
    service_url: "https://knock.app/",
    parse,
    formats: &[NotifyFormat::Text, NotifyFormat::Html, NotifyFormat::Markdown],
    templates: &[
        "knock://{api_key}/{workflow_key}/{targets}",
    ],
    tokens: &[
        Param::new("api_key", "API Key").secret().required(),
        Param::new("targets", "Recipients").list("/").required().note("user id, e-mail or `+phone`"),
        Param::new("workflow_key", "Workflow Key").required(),
    ],
    params: &[
        Param::new("actor", "Actor"),
        Param::new("cancel", "Cancellation Key"),
        Param::new("host", "API Host").default("api.knock.app").note("`host[:port][/path]` or a full `http(s)://` URL"),
        Param::new("tenant", "Tenant"),
        Param::sets("to", &["targets"]),
        Param::new("data", "Workflow Data").prefix(":"),
        Param::new("headers", "HTTP Header").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

const DEFAULT_API: &str = "https://api.knock.app";
const BATCH: usize = 1000;

#[derive(Debug)]
struct Knock {
    api_key: Secret,
    base: String,
    workflow: String,
    recipients: Vec<Value>,
    labels: Vec<String>,
    extra: Vec<(&'static str, String)>,
    data: Vec<(String, String)>,
    headers: Vec<(String, String)>,
}

fn knock_recipient(entry: &str) -> Value {
    match recipient(entry) {
        Recipient::Id(id) => json!(id),
        Recipient::Email(e) => json!({"id": e, "email": e}),
        Recipient::Phone(p) => json!({"id": p, "phone_number": p}),
    }
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let api_key = validate_regex(&u.host(), r"^[^\s/]+$", "", true)
        .ok_or_else(|| SERVICE.err("an invalid Knock API key was specified"))?;
    let mut segs = u.path_segments();
    if segs.is_empty() {
        return Err(SERVICE.err("no Knock workflow key was specified"));
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
        return Err(SERVICE.err("no Knock recipients were specified"));
    }
    let base = api_base(u, DEFAULT_API).map_err(|_| SERVICE.err("an invalid Knock host was specified"))?;
    let mut extra = Vec::new();
    for (param, key) in [("actor", "actor"), ("tenant", "tenant"), ("cancel", "cancellation_key")] {
        if let Some(v) = u.param_nonempty(param) {
            extra.push((key, unquote(v)));
        }
    }
    Ok(Box::new(Knock {
        api_key: Secret::new(api_key),
        base,
        workflow,
        recipients: labels.iter().map(|s| knock_recipient(s)).collect(),
        labels,
        extra,
        data: colon_data(u),
        headers: u.query_plus.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
    }))
}

impl Notify for Knock {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut data = Map::new();
        data.insert("title".into(), json!(msg.title));
        data.insert("body".into(), json!(msg.body));
        data.insert("type".into(), json!(msg.kind.as_str()));
        for (k, v) in &self.data {
            data.insert(k.clone(), json!(v));
        }
        let url = format!("{}/v1/workflows/{}/trigger", self.base, quote(&self.workflow, ""));
        let plans = self.recipients.chunks(BATCH).zip(self.labels.chunks(BATCH)).map(|(rcpts, labels)| {
            let mut payload = json!({"recipients": rcpts, "data": data});
            for (k, v) in &self.extra {
                payload[*k] = json!(v);
            }
            let req = ctx.post(&url)
                .header("Accept", "application/json")
                .bearer(self.api_key.expose())
                .headers(self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                .json(&payload);
            Plan::send(req).target(labels.join(", "))
        });
        Plan::all(plans.collect::<Vec<_>>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeTransport;

    #[test]
    fn validation() {
        assert!(crate::parse("knock://key").is_err());
        assert!(crate::parse("knock://key/wf").is_err());
        assert!(crate::parse("knock://key/wf/u?host=bad_host!").is_err());
        assert!(crate::parse("knock://key/wf/u").is_ok());
    }

    #[test]
    fn request_shape() {
        let t = crate::parse("knock://sk_test/new-comment/u1/a@example.com?actor=bot&:k=v")
            .unwrap();
        let fake = FakeTransport::new();
        fake.respond(200, br#"{"workflow_run_id":"x"}"#.to_vec());
        let d = t.send(&crate::Message::new("b").title("t"), &fake, &crate::Asset::default());
        assert!(d.is_success());
        let r = &fake.requests()[0];
        assert_eq!(r.url, "https://api.knock.app/v1/workflows/new-comment/trigger");
        assert_eq!(r.header_value("Authorization"), Some("Bearer sk_test"));
        let body: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(body["recipients"], json!(["u1", {"id": "a@example.com", "email": "a@example.com"}]));
        assert_eq!(body["actor"], "bot");
        assert_eq!(body["data"], json!({"title": "t", "body": "b", "type": "info", "k": "v"}));
    }
}
