//! SMTP2Go (`smtp2go://`): e-mail through the SMTP2Go API.
//!
//! `smtp2go://{user}@{domain}/{apikey}[/{to_email}...]` `?name=..&cc=..&bcc=..&batch=yes&to=..&+Header=v`
//!
//! `+key=value` entries become custom e-mail headers. Without targets the message goes to the sender.

use std::time::Duration;

use serde_json::{Value, json};

use super::_email_api::{attachments_json, copy_list, email_pairs, unquoted_pairs};
use super::_mail::mime::formataddr;
use crate::parse::{is_email, validate_nonblank};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Error, NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "smtp2go",
    name: "SMTP2Go",
    schemes: &["smtp2go"],
    service_url: "https://www.smtp2go.com/",
    parse,
    formats: &[NotifyFormat::Html],
    attachments: true,
    throttle: Duration::from_millis(200),
    templates: &[
        "{schema}://{user}@{host}/{apikey}/",
        "{schema}://{user}@{host}/{apikey}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret(),
        Param::new("host", "Domain").required(),
        Param::new("targets", "Target Emails").list("/"),
        Param::new("user", "User Name").required(),
    ],
    params: &[
        Param::new("batch", "Batch Mode").bool(false),
        Param::new("bcc", "Blind Carbon Copy").list(", "),
        Param::new("cc", "Carbon Copy").list(", "),
        Param::new("name", "From Name"),
        Param::sets("to", &["targets"]),
        Param::new("headers", "Email Header").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.smtp2go.com/v3/email/send";
const BATCH_SIZE: usize = 100;

#[derive(Debug)]
struct Smtp2Go {
    apikey: Secret,
    from_name: Option<String>,
    from_addr: String,
    targets: Vec<(String, String)>,
    cc: Vec<String>,
    bcc: Vec<String>,
    names: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    batch: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut segs = u.path_segments();
    let apikey = if segs.is_empty() { String::new() } else { segs.remove(0) };
    let apikey = validate_nonblank(&apikey).ok_or_else(|| SERVICE.err("an invalid SMTP2Go API Key was specified"))?;
    let user = u.user().filter(|s| !s.is_empty()).ok_or_else(|| SERVICE.err("no SMTP2Go username was specified"))?;
    let from_name = SERVICE.text(u, "name");
    let from_addr = format!("{user}@{}", u.host());
    if is_email(&from_addr).is_none() {
        return Err(SERVICE.err("invalid ~From~ email format"));
    }
    if let Some(to) = u.param_nonempty("to") {
        segs.push(to.to_string());
    }
    let targets = if segs.is_empty() {
        vec![(from_name.clone().unwrap_or_default(), from_addr.clone())]
    } else {
        email_pairs(&segs)
    };
    let mut names = Vec::new();
    let cc = copy_list(&mut names, u.param_nonempty("cc"));
    let bcc = copy_list(&mut names, u.param_nonempty("bcc"));
    let headers = unquoted_pairs(&u.query_plus);
    Ok(Box::new(Smtp2Go {
        apikey: Secret::new(apikey),
        from_name,
        from_addr,
        targets,
        cc,
        bcc,
        names,
        headers,
        batch: SERVICE.flag(u, "batch"),
    }))
}

impl Smtp2Go {
    fn batch_size(&self) -> usize {
        if self.batch { BATCH_SIZE } else { 1 }
    }
}

impl Notify for Smtp2Go {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Service("there are no Email recipients to notify".into()));
        }
        let mut base = json!({
            "api_key": self.apikey.expose(),
            "sender": formataddr(self.from_name.as_deref().unwrap_or(""), &self.from_addr),
            "subject": msg.title,
        });
        if !msg.attachments.is_empty() {
            base["attachments"] = attachments_json(msg.attachments, "dat", |name, data, a| {
                json!({"filename": name, "fileblob": data, "mimetype": a.mime})
            });
        }
        let key = if msg.format == NotifyFormat::Html { "html_body" } else { "text_body" };
        base[key] = json!(msg.body);

        let mut plans = Vec::new();
        for batch in self.targets.chunks(self.batch_size()) {
            let mut cc: Vec<&String> = self.cc.iter().filter(|e| !self.bcc.contains(e)).collect();
            let mut bcc: Vec<&String> = self.bcc.iter().collect();
            let mut to = Vec::new();
            for (name, addr) in batch {
                cc.retain(|e| *e != addr);
                bcc.retain(|e| *e != addr);
                to.push(formataddr(name, addr));
            }
            let mut payload = base.clone();
            payload["to"] = json!(to);
            if !cc.is_empty() {
                let v: Vec<String> = cc
                    .iter()
                    .map(|a| {
                        let n = self.names.iter().find(|(k, _)| k == *a).map(|(_, v)| v.as_str()).unwrap_or("");
                        formataddr(n, a)
                    })
                    .collect();
                payload["cc"] = json!(v);
            }
            if !bcc.is_empty() {
                payload["bcc"] = json!(bcc);
            }
            if !self.headers.is_empty() {
                let h: Vec<Value> = self.headers.iter().map(|(k, v)| json!({"header": k, "value": v})).collect();
                payload["custom_headers"] = Value::Array(h);
            }
            let req = ctx.post(NOTIFY_URL).header("Accept", "application/json").json(&payload);
            let label = if batch.len() <= 3 {
                batch.iter().map(|(_, e)| e.as_str()).collect::<Vec<_>>().join(", ")
            } else {
                format!("{} recipients", batch.len())
            };
            plans.push(Plan::send_expect(req, &[200]).target(label));
        }
        Plan::all(plans)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(url: &str) -> Result<Box<dyn Notify>> {
        parse(&crate::url::parse_url_unverified(url).unwrap())
    }

    #[test]
    fn validation_and_batches() {
        assert!(p("smtp2go://example.com/key").is_err());
        assert!(p("smtp2go://user@example.com").is_err());
    }
}
