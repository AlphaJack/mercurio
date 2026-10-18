//! Resend (`resend://`): e-mail through the Resend API.
//!
//! `resend://{apikey}:{from_user}@{from_domain}[/{to_email}...]` `resend://{to_email_domain}?apikey=..&from=..` (the host becomes a target) `?name=..&cc=..&bcc=..&reply=..&to=..`
//!
//! Without targets the message goes to the sender.

use std::time::Duration;

use serde_json::json;

use super::_email_api::{attachments_json};
use super::_mail::mime::formataddr;
use crate::parse::{is_email, parse_emails, parse_list, validate_regex};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "resend",
    name: "Resend",
    schemes: &["resend"],
    service_url: "https://resend.com",
    parse,
    formats: &[NotifyFormat::Html],
    attachments: true,
    throttle: Duration::from_millis(200),
    templates: &[
        "{schema}://{apikey}:{from_addr}",
        "{schema}://{apikey}:{from_addr}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret().pattern("^[A-Z0-9._-]+$"),
        Param::new("from_addr", "Source Email").email().required(),
        Param::new("target_email", "Target Email").email(),
        Param::new("targets", "Targets").list("/").group(&["target_email"]),
    ],
    params: &[
        Param::new("apikey", "API Key"),
        Param::new("bcc", "Blind Carbon Copy").list(", "),
        Param::new("cc", "Carbon Copy").list(", "),
        Param::new("from", "From Address"),
        Param::new("name", "From Name"),
        Param::new("reply", "Reply To").list(", "),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.resend.com/emails";

#[derive(Debug)]
struct Resend {
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
    let apikey = SERVICE.text(u, "apikey").unwrap_or_else(|| u.user().unwrap_or_default());
    let mut targets_in: Vec<String> = Vec::new();
    let mut from_addr = match u.param_nonempty("from") {
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
    if let Some(n) = u.param_nonempty("name") {
        if !from_addr.is_ascii() {
            // A display name needs an ASCII address.
            return Err(SERVICE.err("invalid ~From~ email specified"));
        }
        from_addr = formataddr(&unquote(n), &from_addr);
    }
    targets_in.extend(u.path_segments());
    if let Some(to) = u.param_nonempty("to") {
        targets_in.extend(parse_list([to]));
    }

    let apikey = validate_regex(&apikey, r"^[A-Z0-9._-]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Resend API Key was specified"))?;
    let from = is_email(&from_addr).ok_or_else(|| SERVICE.err("invalid ~From~ email specified"))?;
    let from = (from.name, from.full_email);

    let mut names = Vec::new();
    set_name(&mut names, &from.1, &from.0);
    let mut targets = Vec::new();
    let parsed = parse_emails(&targets_in, true);
    if parsed.is_empty() {
        targets.push(from.1.clone());
    } else {
        for r in parsed {
            if let Some(e) = is_email(&r) {
                targets.push(e.full_email);
            }
        }
    }
    let collect = |entries: Vec<String>, named: bool, names: &mut Vec<(String, String)>| {
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
    let reply_to =
        collect(u.param_nonempty("reply").map(|v| vec![v.to_string()]).unwrap_or_default(), true, &mut names);
    Ok(Box::new(Resend { apikey: Secret::new(apikey), from, targets, names, cc, bcc, reply_to }))
}

impl Resend {
    fn named(&self, addrs: &[&String]) -> Vec<String> {
        addrs
            .iter()
            .map(|a| {
                let n = self.names.iter().find(|(k, _)| k == *a).map(|(_, v)| v.as_str()).unwrap_or("");
                formataddr(n, a)
            })
            .collect()
    }
}

impl Notify for Resend {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut base = json!({
            "from": formataddr(&self.from.0, &self.from.1),
            "subject": if msg.title.is_empty() { "<no subject>" } else { msg.title },
        });
        let key = if msg.format == NotifyFormat::Text { "text" } else { "html" };
        base[key] = json!(msg.body);
        if !msg.attachments.is_empty() {
            base["attachments"] = attachments_json(msg.attachments, "dat", |name, data, _| json!({
                        "content": data,
                        "filename": name,
                        "type": "application/octet-stream",
                        "disposition": "attachment",
                    }));
        }
        let plans = self.targets.iter().map(|target| {
            let cc: Vec<&String> = self.cc.iter().filter(|e| !self.bcc.contains(e) && *e != target).collect();
            let bcc: Vec<&String> = self.bcc.iter().filter(|e| *e != target).collect();
            let reply: Vec<&String> = self.reply_to.iter().filter(|e| *e != target).collect();
            let mut payload = base.clone();
            payload["to"] = json!(target);
            if !cc.is_empty() {
                payload["cc"] = json!(self.named(&cc));
            }
            if !bcc.is_empty() {
                payload["bcc"] = json!(bcc);
            }
            if !reply.is_empty() {
                payload["reply_to"] = json!(self.named(&reply));
            }
            let req = ctx
                .post(NOTIFY_URL)
                .header("Content-Type", "application/json")
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

    fn p(url: &str) -> Result<Box<dyn Notify>> {
        parse(&crate::url::parse_url_unverified(url).unwrap())
    }

    #[test]
    fn validates_key_and_from() {
        assert!(p("resend://bad*key:user@example.com").is_err());
        assert!(p("resend://abcd:invalid").is_err());
    }
}
