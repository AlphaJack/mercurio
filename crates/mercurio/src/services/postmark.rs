//! Postmark (`postmark://`): e-mail through the Postmark API.
//!
//! `postmark://{apikey}:{from_user}@{from_domain}[/{to_email}...]` `postmark://{to_email_domain}?apikey=..&from=..` (the host becomes a target) `?name=..&cc=..&bcc=..&reply=..&to=..`
//!
//! Without targets the message goes to the sender.

use std::time::Duration;

use serde_json::json;

use super::_email_api::{attachments_json};
use super::_mail::mime::formataddr;
use crate::parse::{is_email, parse_emails, parse_list, validate_nonblank};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Error, NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "postmark",
    name: "Postmark",
    schemes: &["postmark"],
    service_url: "https://postmarkapp.com/",
    parse,
    formats: &[NotifyFormat::Html],
    attachments: true,
    throttle: Duration::from_millis(1200),
    templates: &[
        "{schema}://{apikey}:{from_email}",
        "{schema}://{apikey}:{from_email}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret(),
        Param::new("from_email", "Source Email").email().required(),
        Param::new("target_email", "Target Email").email(),
        Param::new("targets", "Targets").list("/").group(&["target_email"]),
    ],
    params: &[
        Param::new("bcc", "Blind Carbon Copy").list(", "),
        Param::new("cc", "Carbon Copy").list(", "),
        Param::new("name", "From Name"),
        Param::new("reply", "Reply To Email").list(", "),
        Param::sets("to", &["targets"]),
        Param::sets("from", &["from_email"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.postmarkapp.com/email";

#[derive(Debug)]
struct Postmark {
    apikey: Secret,
    from: (String, String),
    targets: Vec<String>,
    names: Vec<(String, String)>,
    cc: Vec<String>,
    bcc: Vec<String>,
    reply_to: Vec<String>,
}

fn set_name(names: &mut Vec<(String, String)>, email: &str, name: &str) {
    names.retain(|(k, _)| k != email);
    names.push((email.to_string(), name.to_string()));
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let apikey = u.text("apikey").unwrap_or_else(|| u.user().unwrap_or_default());
    let mut targets_in: Vec<String> = Vec::new();
    let from_email = match u.param_nonempty("from") {
        Some(f) => {
            if !u.host.is_empty() {
                targets_in.push(u.host());
            }
            unquote(f)
        }
        None => {
            let local = match u.password.as_deref().filter(|p| !p.is_empty()) {
                Some(_) => u.password().unwrap_or_default(),
                None => u.user().unwrap_or_default(),
            };
            format!("{local}@{}", u.host())
        }
    };
    let from_name = SERVICE.text(u, "name");
    targets_in.extend(u.path_segments());
    if let Some(to) = u.param_nonempty("to") {
        targets_in.extend(parse_list([to]));
    }

    let apikey = validate_nonblank(&apikey).ok_or_else(|| SERVICE.err("an invalid Postmark API Key was specified"))?;
    let from = is_email(&from_email).ok_or_else(|| SERVICE.err("an invalid Postmark From email was specified"))?;
    let mut from = (from.name, from.full_email);
    if let Some(n) = from_name.filter(|n| !n.is_empty()) {
        from.0 = n;
    }

    let mut names = Vec::new();
    let mut targets = Vec::new();
    if targets_in.is_empty() {
        targets.push(from.1.clone());
    } else {
        for r in parse_emails(&targets_in, true) {
            if let Some(e) = is_email(&r) {
                set_name(&mut names, &e.full_email, &e.name);
                targets.push(e.full_email);
            }
        }
    }
    let collect =|entries: Vec<String>, named: bool, names: &mut Vec<(String, String)>| {
        let mut set: Vec<String> = Vec::new();
        for r in parse_emails(&entries, true) {
            if let Some(e) = is_email(&r) {
                if named {
                    set_name(names, &e.full_email, &e.name);
                }
                if !set.contains(&e.full_email) {
                    set.push(e.full_email);
                }
            }
        }
        set
    };
    let cc = collect(u.list("cc"), true, &mut names);
    let bcc = collect(u.list("bcc"), false, &mut names);
    let reply_to = collect(u.param_nonempty("reply").map(|v| vec![v.to_string()]).unwrap_or_default(), true, &mut names);
    Ok(Box::new(Postmark { apikey: Secret::new(apikey), from, targets, names, cc, bcc, reply_to }))
}

impl Postmark {
    fn named(&self, addrs: &[&String]) -> String {
        addrs
            .iter()
            .map(|a| {
                let n = self.names.iter().find(|(k, _)| k == *a).map(|(_, v)| v.as_str()).unwrap_or("");
                formataddr(n, a)
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl Notify for Postmark {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Service("there are no Postmark email recipients to notify".into()));
        }
        let mut base = json!({
            "From": formataddr(&self.from.0, &self.from.1),
            "Subject": if msg.title.is_empty() { "<no subject>" } else { msg.title },
        });
        let key = if msg.format == NotifyFormat::Html { "HtmlBody" } else { "TextBody" };
        base[key] = json!(msg.body);
        if !msg.attachments.is_empty() {
            base["Attachments"] = attachments_json(msg.attachments, "dat", |name, data, a| json!({
                        "Name": name,
                        "Content": data,
                        "ContentType": a.mime,
                    }));
        }
        let plans = self.targets.iter().map(|target| {
            let cc: Vec<&String> = self.cc.iter().filter(|e| !self.bcc.contains(e) && *e != target).collect();
            let bcc: Vec<&String> = self.bcc.iter().filter(|e| *e != target).collect();
            let reply: Vec<&String> = self.reply_to.iter().filter(|e| *e != target).collect();
            let mut payload = base.clone();
            payload["To"] = json!(target);
            if !cc.is_empty() {
                payload["Cc"] = json!(self.named(&cc));
            }
            if !bcc.is_empty() {
                payload["Bcc"] = json!(bcc.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(","));
            }
            if !reply.is_empty() {
                payload["ReplyTo"] = json!(self.named(&reply));
            }
            let req = ctx.post(NOTIFY_URL)
                .header("Accept", "application/json")
                .header("X-Postmark-Server-Token", self.apikey.expose())
                .json(&payload);
            Plan::send_expect(req, &[200]).target(target.clone())
        });
        Plan::all(plans.collect::<Vec<_>>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(url: &str) -> Result<Box<dyn Notify>> {
        parse(&crate::url::parse_url_unverified(url).unwrap())
    }

    #[test]
    fn from_param_moves_host_to_targets() {
        assert!(p("postmark://abc:invalid").is_err());
    }
}
