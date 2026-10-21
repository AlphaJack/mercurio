//! SendGrid (`sendgrid://`): e-mail through the SendGrid API.
//!
//! `sendgrid://{apikey}:{from_email}[/{to_email}...][?cc=..&bcc=..&template=..&+key=value]`
//!
//! `+key=value` entries become the dynamic template data. Without targets the message goes to the sender.

use std::time::Duration;

use serde_json::{Map, Value, json};

use super::_email_api::{attachments_json, unique_emails};
use crate::error::Error;
use crate::parse::{is_email, parse_list, validate_regex};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "sendgrid",
    name: "SendGrid",
    schemes: &["sendgrid"],
    service_url: "https://sendgrid.com",
    parse,
    formats: &[NotifyFormat::Html],
    attachments: true,
    throttle: Duration::from_millis(200),
    templates: &[
        "{schema}://{apikey}:{from_email}",
        "{schema}://{apikey}:{from_email}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret().pattern("^[A-Z0-9._-]+$"),
        Param::new("from_email", "Source Email").email().required(),
        Param::new("target_email", "Target Email").email(),
        Param::new("targets", "Targets").list("/").group(&["target_email"]),
    ],
    params: &[
        Param::new("bcc", "Blind Carbon Copy").list(", "),
        Param::new("cc", "Carbon Copy").list(", "),
        Param::new("template", "Template"),
        Param::sets("to", &["targets"]),
        Param::new("template_data", "Template Data").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.sendgrid.com/v3/mail/send";

#[derive(Debug)]
struct SendGrid {
    apikey: Secret,
    from_email: String,
    targets: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    template: Option<String>,
    template_data: Vec<(String, String)>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let user = u.user.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| SERVICE.err("no API key specified"))?;
    let password =
        u.password.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| SERVICE.err("no from email specified"))?;
    let apikey = unquote(user);
    let from = format!("{}@{}", unquote(password), u.host());

    let apikey = validate_regex(&apikey, r"^[A-Z0-9._-]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid SendGrid API Key was specified"))?;
    let from_email = is_email(&from).ok_or_else(|| SERVICE.err("invalid ~From~ email specified"))?.full_email;

    let mut targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }
    let has_targets = !targets.is_empty();
    let mut targets: Vec<String> =
        parse_list(targets).iter().filter_map(|r| is_email(r)).map(|e| e.full_email).collect();
    if !has_targets {
        targets.push(from_email.clone());
    }
    let cc = unique_emails(u.param_nonempty("cc"));
    let bcc = unique_emails(u.param_nonempty("bcc"));
    let template = SERVICE.text(u, "template");
    let template_data = u.query_plus.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    Ok(Box::new(SendGrid { apikey: Secret::new(apikey), from_email, targets, cc, bcc, template, template_data }))
}

impl Notify for SendGrid {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Service("there are no SendGrid email recipients to notify".into()));
        }
        let mut base = Map::new();
        base.insert("from".into(), json!({"email": self.from_email}));
        base.insert("subject".into(), json!(if msg.title.is_empty() { "<no subject>" } else { msg.title }));
        let ctype = if msg.format == NotifyFormat::Text { "text/plain" } else { "text/html" };
        base.insert("content".into(), json!([{"type": ctype, "value": crate::http::TEXT}]));
        if !msg.attachments.is_empty() {
            base.insert("attachments".into(), attachments_json(msg.attachments, "dat", |name, data, _| json!({
                        "content": data,
                        "filename": name,
                        "type": "application/octet-stream",
                        "disposition": "attachment",
                    })));
        }
        if let Some(t) = &self.template {
            base.insert("template_id".into(), json!(t));
        }

        let plans = self.targets.iter().map(|target| {
            // Each target gets a fresh payload: cc/bcc never leak between targets.
            let mut p13n = Map::new();
            p13n.insert("to".into(), json!([{"email": target}]));
            let cc: Vec<Value> =
                self.cc.iter().filter(|e| !self.bcc.contains(e) && *e != target).map(|e| json!({"email": e})).collect();
            let bcc: Vec<Value> = self.bcc.iter().filter(|e| *e != target).map(|e| json!({"email": e})).collect();
            if !cc.is_empty() {
                p13n.insert("cc".into(), Value::Array(cc));
            }
            if !bcc.is_empty() {
                p13n.insert("bcc".into(), Value::Array(bcc));
            }
            if self.template.is_some() && !self.template_data.is_empty() {
                let data: Map<String, Value> =
                    self.template_data.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect();
                p13n.insert("dynamic_template_data".into(), Value::Object(data));
            }
            let mut payload = base.clone();
            payload.insert("personalizations".into(), json!([p13n]));
            let req = ctx
                .post(NOTIFY_URL)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", self.apikey.expose()))
                .json_text(&Value::Object(payload), msg.body);
            Plan::send_expect(req, &[200, 202]).target(target.clone())
        });
        Plan::all(plans.collect::<Vec<_>>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_key() {
        let u = crate::url::parse_url("sendgrid://bad+*key:user@example.com").unwrap();
        assert!(parse(&u).is_err());
    }

    #[test]
    fn defaults_to_sender() {
        let u = crate::url::parse_url("sendgrid://abcd:user@example.com").unwrap();
        assert!(parse(&u).is_ok());
    }
}
