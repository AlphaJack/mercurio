//! Courier (`courier://`): notifications through the Courier send API, written from the API reference (<https://www.courier.com/docs/reference/send/message>).
//!
//! `courier://{auth_token}/{recipient}[/{recipient}...]`
//!
//! Options:
//! - `?host=api.example.com[:port][/path]` (or a full `http(s)://` URL) overrides the API base (default `https://api.courier.com`).
//! - `?to=a,b` adds recipients.
//! - `?template={id|alias}` sends a template instead of inline content; the title and body are then only available as `data.title`/`data.body`.
//! - `?channels=email,sms` sets `routing: {"method": "single", "channels": [...]}`.
//! - `:key=value` adds `key` to `message.data`; `+Header=value` adds an HTTP header.
//!
//! Each recipient is an e-mail (`{"email": ..}`), `+<phone>` (`{"phone_number": ..}`) or a user id (`{"user_id": ..}`). One `POST /send` carries all recipients (`message.to` is an object for one, an array for several), with `Authorization: Bearer {auth_token}` and `{"message": {"to", "content": {"title", "body"}, "data": {"type", ...}}}`. Any 2xx (Courier answers 202) is success.
//!
//! # Differences with Apprise
//!
//! - Not in Apprise; written from the vendor documentation (hand-written fixtures).

use serde_json::{Map, Value, json};

use super::_email_api::{Recipient, api_base, colon_data, recipient};
use crate::parse::{parse_list, validate_regex};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "courier",
    name: "Courier",
    schemes: &["courier"],
    service_url: "https://www.courier.com/",
    parse,
    formats: &[NotifyFormat::Text, NotifyFormat::Html, NotifyFormat::Markdown],
    templates: &[
        "courier://{auth_token}/{targets}",
    ],
    tokens: &[
        Param::new("auth_token", "Auth Token").secret().required(),
        Param::new("targets", "Recipients").list("/").required().note("e-mail, `+phone` or user id"),
    ],
    params: &[
        Param::new("channels", "Routing Channels").list(", "),
        Param::new("host", "API Host").default("api.courier.com").note("`host[:port][/path]` or a full `http(s)://` URL"),
        Param::new("template", "Template").note("template id or alias; title and body go to `data`"),
        Param::sets("to", &["targets"]),
        Param::new("data", "Message Data").prefix(":"),
        Param::new("headers", "HTTP Header").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

const DEFAULT_API: &str = "https://api.courier.com";

#[derive(Debug)]
struct Courier {
    token: Secret,
    base: String,
    to: Vec<Value>,
    labels: Vec<String>,
    template: Option<String>,
    channels: Vec<String>,
    data: Vec<(String, String)>,
    headers: Vec<(String, String)>,
}

fn courier_recipient(entry: &str) -> Value {
    match recipient(entry) {
        Recipient::Id(id) => json!({"user_id": id}),
        Recipient::Email(e) => json!({"email": e}),
        Recipient::Phone(p) => json!({"phone_number": p}),
    }
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let token = validate_regex(&u.host(), r"^[^\s/]+$", "", true)
        .ok_or_else(|| SERVICE.err("an invalid Courier auth token was specified"))?;
    let mut segs = u.path_segments();
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
        return Err(SERVICE.err("no Courier recipients were specified"));
    }
    let base = api_base(u, DEFAULT_API).ok().ok_or_else(|| SERVICE.err("an invalid Courier host was specified"))?;
    Ok(Box::new(Courier {
        token: Secret::new(token),
        base,
        to: labels.iter().map(|s| courier_recipient(s)).collect(),
        labels,
        template: SERVICE.text(u, "template"),
        channels: u.param_nonempty("channels").map(|c| crate::parse::parse_list_unsorted([unquote(c)])).unwrap_or_default(),
        data: colon_data(u),
        headers: u.query_plus.iter().map(|(k, v)| (k.to_owned(), v.to_owned())).collect(),
    }))
}

impl Notify for Courier {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut data = Map::new();
        data.insert("type".into(), json!(msg.kind.as_str()));
        let mut message = Map::new();
        message.insert("to".into(), if self.to.len() == 1 { self.to[0].clone() } else { Value::Array(self.to.clone()) });
        match &self.template {
            Some(t) => {
                message.insert("template".into(), json!(t));
                data.insert("title".into(), json!(msg.title));
                data.insert("body".into(), json!(crate::http::TEXT));
            }
            None => {
                message.insert("content".into(), json!({"title": msg.title, "body": crate::http::TEXT}));
            }
        }
        for (k, v) in &self.data {
            data.insert(k.clone(), json!(v));
        }
        message.insert("data".into(), Value::Object(data));
        if !self.channels.is_empty() {
            message.insert("routing".into(), json!({"method": "single", "channels": self.channels}));
        }
        let req = ctx.post(format!("{}/send", self.base))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .bearer(self.token.expose())
            .headers(self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .json_text(&json!({"message": message}), msg.body);
        Plan::send(req).target(self.labels.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeTransport;

    fn body(url: &str) -> Value {
        let t = crate::parse(url).unwrap();
        let fake = FakeTransport::new();
        fake.respond(202, br#"{"requestId":"1-abc"}"#.to_vec());
        let d = t.send(&crate::Message::new("b").title("t"), &fake, &crate::Asset::default());
        assert!(d.is_success());
        serde_json::from_slice(&fake.requests()[0].body).unwrap()
    }

    #[test]
    fn validation() {
        assert!(crate::parse("courier://tok").is_err());
        assert!(crate::parse("courier://tok/user1").is_ok());
    }

    #[test]
    fn single_and_multi() {
        assert_eq!(body("courier://tok/user1")["message"]["to"], json!({"user_id": "user1"}));
        let b = body("courier://tok/a@example.com/+15551234567?channels=email,sms&template=nt_1");
        assert_eq!(b["message"]["to"], json!([{"email": "a@example.com"}, {"phone_number": "+15551234567"}]));
        assert_eq!(b["message"]["template"], "nt_1");
        assert_eq!(b["message"]["routing"], json!({"method": "single", "channels": ["email", "sms"]}));
        assert_eq!(b["message"]["data"], json!({"type": "info", "title": "t", "body": "b"}));
    }
}
