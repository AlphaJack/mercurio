//! SparkPost (`sparkpost://`): e-mail through the SparkPost API.
//!
//! `sparkpost://{user}@{domain}/{apikey}[/{to_email}...]` `?region=us|eu&name=..&cc=..&bcc=..&batch=yes&+Header=v&:token=v`
//!
//! `+key=value` entries become e-mail headers, `:key=value` entries the substitution data. Without targets the message goes to the sender. HTTP 429 is retried (up to 3 attempts, 5 s apart).

use std::time::Duration;

use serde_json::{Map, Value, json};

use super::_email_api::{attachment_b64, attachment_name, copy_list, email_pairs, unquoted_pairs};
use super::_mail::mime::formataddr;
use crate::http::Request;
use crate::parse::{is_email, validate_nonblank};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Error, NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "sparkpost",
    name: "SparkPost",
    schemes: &["sparkpost"],
    service_url: "https://sparkpost.com/",
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
        Param::new("region", "Region Name").choice(&["us", "eu"]).default("us"),
        Param::sets("to", &["targets"]),
        Param::new("headers", "Email Header").prefix("+"),
        Param::new("tokens", "Template Tokens").prefix(":"),
    ],
    ..ServiceDef::DEFAULTS
};

const BATCH_SIZE: usize = 2000;
const RETRY_ATTEMPTS: u32 = 3;
const RETRY_WAIT: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct SparkPost {
    apikey: Secret,
    api: &'static str,
    from_name: Option<String>,
    from_addr: String,
    targets: Vec<(String, String)>,
    cc: Vec<String>,
    bcc: Vec<String>,
    names: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    tokens: Vec<(String, String)>,
    batch: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut segs = u.path_segments();
    let apikey = if segs.is_empty() { String::new() } else { segs.remove(0) };
    let apikey = validate_nonblank(&apikey).ok_or_else(|| SERVICE.err("an invalid SparkPost API Key was specified"))?;
    let user = u.user().filter(|s| !s.is_empty()).ok_or_else(|| SERVICE.err("no SparkPost username was specified"))?;
    let api = match SERVICE.text_or_default(u, "region").to_lowercase().as_str() {
        "us" => "https://api.sparkpost.com/api/v1",
        "eu" => "https://api.eu.sparkpost.com/api/v1",
        _ => return Err(SERVICE.err("the SparkPost region specified is invalid")),
    };
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
    Ok(Box::new(SparkPost {
        apikey: Secret::new(apikey),
        api,
        from_name,
        from_addr,
        targets,
        cc,
        bcc,
        names,
        headers: unquoted_pairs(&u.query_plus),
        tokens: unquoted_pairs(&u.query_colon),
        batch: SERVICE.flag(u, "batch"),
    }))
}

/// Post, retrying on HTTP 429.
fn post(req: Request, retry: u32) -> Plan {
    let again = req.clone();
    Plan::http(req, move |res| match res {
        Ok(r) if r.status == 200 => Plan::Done,
        Ok(r) => {
            if r.status == 429 && retry > 1 {
                return Plan::chain([Plan::Sleep(RETRY_WAIT), post(again, retry - 1)]);
            }
            Plan::Fail(r.http_error())
        }
        Err(e) => Plan::Fail(e),
    })
}

impl SparkPost {
    fn batch_size(&self) -> usize {
        if self.batch { BATCH_SIZE } else { 1 }
    }
}

impl Notify for SparkPost {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Service("there are no SparkPost Email recipients to notify".into()));
        }
        let from_name = self.from_name.as_deref().filter(|n| !n.is_empty());
        let mut content = Map::new();
        content.insert("from".into(), json!({"name": from_name.unwrap_or(ctx.app_desc()), "email": self.from_addr}));
        content.insert("subject".into(), json!(if msg.title.trim().is_empty() { "." } else { msg.title }));
        content.insert("reply_to".into(), json!(formataddr(from_name.unwrap_or(""), &self.from_addr)));
        let key = if msg.format == NotifyFormat::Html { "html" } else { "text" };
        content.insert(key.into(), json!(crate::http::TEXT));
        if !msg.attachments.is_empty() {
            let atts: Vec<Value> = msg
                .attachments
                .iter()
                .enumerate()
                .map(|(i, a)| json!({"name": attachment_name(a, i, "dat"), "type": a.mime, "data": attachment_b64(a)}))
                .collect();
            content.insert("attachments".into(), Value::Array(atts));
        }
        let tokens: Map<String, Value> = self.tokens.iter().map(|(k, v)| (k.clone(), json!(v))).collect();

        let url = format!("{}/transmissions/", self.api);
        let mut plans = Vec::new();
        for batch in self.targets.chunks(self.batch_size()) {
            let mut cc: Vec<&String> = self.cc.iter().filter(|e| !self.bcc.contains(e)).collect();
            let mut bcc: Vec<&String> = self.bcc.iter().collect();
            let mut recipients = Vec::new();
            for (name, addr) in batch {
                cc.retain(|e| *e != addr);
                bcc.retain(|e| *e != addr);
                let mut entry = json!({"address": {"email": addr}});
                if !name.is_empty() {
                    entry["address"]["name"] = json!(name);
                }
                recipients.push(entry);
            }
            let header_to = &batch[0].1;
            let mut headers: Map<String, Value> = self.headers.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
            if !cc.is_empty() {
                for addr in &cc {
                    let mut entry = json!({"address": {"email": addr, "header_to": header_to}});
                    if let Some((_, n)) = self.names.iter().find(|(k, _)| k == *addr).filter(|(_, n)| !n.is_empty()) {
                        entry["address"]["name"] = json!(n);
                    }
                    recipients.push(entry);
                }
                headers.insert("CC".into(), json!(cc.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",")));
            }
            for addr in &bcc {
                recipients.push(json!({"address": {"email": addr, "header_to": header_to}}));
            }
            let mut content = content.clone();
            if !headers.is_empty() {
                content.insert("headers".into(), Value::Object(headers));
            }
            let payload = json!({
                "options": {"open_tracking": false, "click_tracking": false},
                "content": content,
                "substitution_data": tokens,
                "recipients": recipients,
            });
            let req = ctx
                .post(&url)
                .header("Accept", "application/json")
                .header("Authorization", self.apikey.expose())
                .json_text(&payload, msg.body);
            let label = if batch.len() <= 3 {
                batch.iter().map(|(_, e)| e.as_str()).collect::<Vec<_>>().join(", ")
            } else {
                format!("{} recipients", batch.len())
            };
            plans.push(post(req, RETRY_ATTEMPTS).target(label));
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
    fn validation() {
        assert!(p("sparkpost://user@example.com/key?region=mars").is_err());
        assert!(p("sparkpost://example.com/key").is_err());
        assert!(p("sparkpost://user@example.com").is_err());
        assert!(p("sparkpost://user@example.com/key/a@example.com/b@example.com?batch=yes").is_ok());
    }

    #[test]
    fn retries_on_429() {
        use crate::testing::FakeTransport;
        let fake = FakeTransport::new();
        for _ in 0..3 {
            fake.respond_with(crate::http::Response::new(429, "{}"));
        }
        let msg = crate::Message::new("body");
        let target = crate::parse("sparkpost://user@example.com/key").unwrap();
        let d = target.send(&msg, &fake, &crate::Asset::default());
        assert!(!d.is_success());
        assert_eq!(fake.requests().len(), 3);
    }
}
