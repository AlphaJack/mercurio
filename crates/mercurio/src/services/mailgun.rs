//! Mailgun (`mailgun://`): e-mail through the Mailgun API.
//!
//! `mailgun://{user}@{domain}/{apikey}[/{to_email}...]` `?region=us|eu&from=..&name=..&cc=..&bcc=..&batch=yes&+Header=v&:token=v`
//!
//! `+key=value` entries become `h:key` e-mail headers, `:key=value` entries `v:key` template variables. Without targets the message goes to the sender.

use std::time::Duration;

use super::_email_api::{attachment_name, copy_list, email_pairs, unquoted_pairs};
use super::_mail::mime::formataddr;
use crate::parse::{is_email, validate_nonblank};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Error, NotifyFormat, Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "mailgun",
    name: "Mailgun",
    schemes: &["mailgun"],
    service_url: "https://www.mailgun.com/",
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
        Param::new("target_email", "Target Email").email(),
        Param::new("targets", "Targets").list("/").group(&["target_email"]),
        Param::new("user", "User Name").required(),
    ],
    params: &[
        Param::new("batch", "Batch Mode").bool(false),
        Param::new("bcc", "Blind Carbon Copy").list(", "),
        Param::new("cc", "Carbon Copy").list(", "),
        Param::new("name", "From Name").aliases(&["from"]),
        Param::new("region", "Region Name").choice(&["us", "eu"]).default("us"),
        Param::sets("to", &["targets"]),
        Param::new("headers", "Email Header").prefix("+"),
        Param::new("tokens", "Template Tokens").prefix(":"),
    ],
    ..ServiceDef::DEFAULTS
};

const BATCH_SIZE: usize = 2000;

/// Display name of the sender; defaults to the app id.
#[derive(Debug, Clone)]
enum FromName {
    AppId,
    Name(String),
    None,
}

#[derive(Debug)]
struct Mailgun {
    apikey: Secret,
    host: String,
    api: &'static str,
    from_name: FromName,
    from_email: String,
    targets: Vec<(String, String)>,
    cc: Vec<String>,
    bcc: Vec<String>,
    names: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    tokens: Vec<(String, String)>,
    batch: bool,
    skip_verification: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut segs = u.path_segments();
    let apikey = if segs.is_empty() { String::new() } else { segs.remove(0) };
    let apikey = validate_nonblank(&apikey).ok_or_else(|| SERVICE.err("an invalid Mailgun API Key was specified"))?;
    let user = u.user().filter(|s| !s.is_empty()).ok_or_else(|| SERVICE.err("no Mailgun username was specified"))?;
    let host = u.host();

    let mut from_addr: Option<String> = None;
    if let Some(f) = u.param_nonempty("from") {
        let f = unquote(f);
        from_addr = Some(match u.param_nonempty("name") {
            Some(n) => formataddr(&unquote(n), &f),
            None => f,
        });
    } else if let Some(n) = u.param_nonempty("name") {
        from_addr = Some(unquote(n));
    }

    let api = match u.param_nonempty("region").map(|r| unquote(r).to_lowercase()) {
        None => "https://api.mailgun.net/v3/",
        Some(r) if r == "us" => "https://api.mailgun.net/v3/",
        Some(r) if r == "eu" => "https://api.eu.mailgun.net/v3/",
        Some(_) => return Err(SERVICE.err("the Mailgun region specified is invalid")),
    };

    let mut from_name = FromName::AppId;
    let mut from_email = format!("{user}@{host}");
    if let Some(f) = from_addr.filter(|f| !f.is_empty()) {
        match is_email(&f) {
            Some(e) => {
                from_name = if e.name.is_empty() { FromName::None } else { FromName::Name(e.name) };
                from_email = e.full_email;
            }
            None => from_name = FromName::Name(f),
        }
    }
    if is_email(&from_email).is_none() {
        return Err(SERVICE.err("invalid ~From~ email format"));
    }

    if let Some(to) = u.param_nonempty("to") {
        segs.push(to.to_owned());
    }
    let targets = if segs.is_empty() { vec![(String::new(), from_email.clone())] } else { email_pairs(&segs) };

    let mut names = Vec::new();
    let cc = copy_list(&mut names, u.param_nonempty("cc"));
    let bcc = copy_list(&mut names, u.param_nonempty("bcc"));

    Ok(Box::new(Mailgun {
        apikey: Secret::new(apikey),
        host,
        api,
        from_name,
        from_email,
        targets,
        cc,
        bcc,
        names,
        headers: unquoted_pairs(&u.query_plus),
        tokens: unquoted_pairs(&u.query_colon),
        batch: SERVICE.flag(u, "batch"),
        skip_verification: !u.verify,
    }))
}

impl Mailgun {
    fn batch_size(&self) -> usize {
        if self.batch { BATCH_SIZE } else { 1 }
    }

    fn name_of(&self, addr: &str) -> &str {
        self.names.iter().find(|(k, _)| k == addr).map(|(_, v)| v.as_str()).unwrap_or("")
    }
}

impl Notify for Mailgun {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Service("there are no Email recipients to notify".into()));
        }
        let from_name = match &self.from_name {
            FromName::AppId => ctx.app_id().to_owned(),
            FromName::Name(n) => n.clone(),
            FromName::None => String::new(),
        };
        let mut base: Vec<(String, String)> = vec![
            ("o:skip-verification".into(), if self.skip_verification { "True" } else { "False" }.into()),
            ("from".into(), formataddr(&from_name, &self.from_email)),
            ("subject".into(), msg.title.to_owned()),
        ];
        let key = if msg.format == NotifyFormat::Html { "html" } else { "text" };
        base.push((key.into(), msg.body.to_owned()));

        let url = format!("{}{}/messages", self.api, self.host);
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
            payload.push(("to".into(), to.join(",")));
            if !cc.is_empty() {
                let v: Vec<String> = cc.iter().map(|a| formataddr(self.name_of(a), a)).collect();
                payload.push(("cc".into(), v.join(",")));
            }
            if !bcc.is_empty() {
                payload.push(("bcc".into(), bcc.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",")));
            }
            for (k, v) in &self.tokens {
                payload.push((format!("v:{k}"), v.clone()));
            }
            for (k, v) in &self.headers {
                payload.push((format!("h:{k}"), v.clone()));
            }

            let mut req =
                ctx.post(&url).header("Accept", "application/json").basic_auth("api", Some(self.apikey.expose()));
            if msg.attachments.is_empty() {
                req = req.form(&payload);
            } else {
                let mut form = ctx.multipart();
                for (k, v) in &payload {
                    form = form.text(k, v);
                }
                for (i, a) in msg.attachments.iter().enumerate() {
                    form = form.file(format!("attachment[{i}]"), attachment_name(a, i, "dat"), "", a.data.clone());
                }
                req = req.multipart(form);
            }
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
    fn region_and_batches() {
        assert!(p("mailgun://user@example.com/key?region=mars").is_err());
        assert!(p("mailgun://example.com/key").is_err());
        assert!(p("mailgun://user@example.com/key/a@example.com/b@example.com?batch=yes").is_ok());
    }
}
