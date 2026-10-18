//! MailerSend (`mailersend://`): e-mail through the MailerSend API.
//!
//! `mailersend://{apikey}:{from_user}@{from_domain}[/{to_email}...][?cc=..&bcc=..&reply=..&to=..]`
//!
//! Both an HTML and a plain-text part are sent; the one not given is converted from the other. Without targets the message goes to the sender.

use std::time::Duration;

use serde_json::{Value, json};

use super::_email_api::{attachments_json, html_to_text, text_to_html, unique_emails};
use crate::parse::{is_email, parse_list, validate_regex};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Error, NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "mailersend",
    name: "MailerSend",
    schemes: &["mailersend"],
    service_url: "https://www.mailersend.com/",
    parse,
    formats: &[NotifyFormat::Html, NotifyFormat::Text],
    attachments: true,
    throttle: Duration::from_millis(200),
    templates: &[
        "{schema}://{apikey}:{from_email}",
        "{schema}://{apikey}:{from_email}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret().pattern("^[a-zA-Z0-9._-]+$"),
        Param::new("from_email", "Source Email").email().required(),
        Param::new("target_email", "Target Email").email(),
        Param::new("targets", "Targets").list("/").group(&["target_email"]),
    ],
    params: &[
        Param::new("bcc", "Blind Carbon Copy").list(", "),
        Param::new("cc", "Carbon Copy").list(", "),
        Param::new("reply", "Reply To"),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.mailersend.com/v1/email";

#[derive(Debug)]
struct MailerSend {
    apikey: Secret,
    from_email: String,
    reply_to: Option<String>,
    targets: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let user = u.user.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| SERVICE.err("no API key specified"))?;
    let password =
        u.password.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| SERVICE.err("no from email specified"))?;
    let apikey = validate_regex(&unquote(user), r"^[a-zA-Z0-9._-]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid MailerSend API Key was specified"))?;
    let from = format!("{}@{}", unquote(password), u.host());
    let from_email = is_email(&from).ok_or_else(|| SERVICE.err("invalid MailerSend From email specified"))?.full_email;

    let reply_to = match SERVICE.text(u, "reply").filter(|r| !r.is_empty()) {
        Some(r) => {
            Some(is_email(&r).ok_or_else(|| SERVICE.err("an invalid MailerSend Reply To was specified"))?.full_email)
        }
        None => None,
    };

    let mut targets_in = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets_in.extend(parse_list([to]));
    }
    let targets = if targets_in.is_empty() {
        vec![from_email.clone()]
    } else {
        parse_list(targets_in).iter().filter_map(|r| is_email(r)).map(|e| e.full_email).collect()
    };
    let cc = unique_emails(u.param_nonempty("cc"));
    let bcc = unique_emails(u.param_nonempty("bcc"));
    Ok(Box::new(MailerSend { apikey: Secret::new(apikey), from_email, reply_to, targets, cc, bcc }))
}

impl Notify for MailerSend {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Service("there are no MailerSend email recipients to notify".into()));
        }
        let mut base = json!({
            "from": {"email": self.from_email},
            "subject": if msg.title.is_empty() { "<no subject>" } else { msg.title },
        });
        if msg.format == NotifyFormat::Html {
            base["html"] = json!(msg.body);
            base["text"] = json!(html_to_text(msg.body));
        } else {
            base["text"] = json!(msg.body);
            base["html"] = json!(text_to_html(msg.body));
        }
        if !msg.attachments.is_empty() {
            base["attachments"] = attachments_json(msg.attachments, "dat", |name, data, _| json!({
                        "content": data,
                        "filename": name,
                        "disposition": "attachment",
                    }));
        }
        if let Some(r) = &self.reply_to {
            base["reply_to"] = json!({"email": r});
        }
        let plans = self.targets.iter().map(|target| {
            let cc: Vec<Value> =
                self.cc.iter().filter(|e| !self.bcc.contains(e) && *e != target).map(|e| json!({"email": e})).collect();
            let bcc: Vec<Value> = self.bcc.iter().filter(|e| *e != target).map(|e| json!({"email": e})).collect();
            let mut payload = base.clone();
            payload["to"] = json!([{"email": target}]);
            if !cc.is_empty() {
                payload["cc"] = Value::Array(cc);
            }
            if !bcc.is_empty() {
                payload["bcc"] = Value::Array(bcc);
            }
            let req = ctx
                .post(NOTIFY_URL)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("Authorization", format!("Bearer {}", self.apikey.expose()))
                .json(&payload);
            Plan::send_expect(req, &[200, 202]).target(target.clone())
        });
        Plan::all(plans.collect::<Vec<_>>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation() {
        let p = |s: &str| parse(&crate::url::parse_url(s).unwrap());
        assert!(p("mailersend://abcd:user@example.com?reply=invalid").is_err());
        assert!(p("mailersend://bad*key:user@example.com").is_err());
    }
}
