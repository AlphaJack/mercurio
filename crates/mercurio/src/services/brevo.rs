//! Brevo (`brevo://`): transactional e-mail through the Brevo API.
//!
//! `brevo://{apikey}:{from_user}@{from_domain}[/{to_email}...][?cc=..&bcc=..&reply=..&to=..]`
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
    id: "brevo",
    name: "Brevo",
    schemes: &["brevo"],
    service_url: "https://www.brevo.com/",
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
        Param::new("reply", "Reply To Email"),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.brevo.com/v3/smtp/email";

const VALID_EXTENSIONS: &[&str] = &[
    "xlsx", "xls", "ods", "docx", "docm", "doc", "csv", "pdf", "txt", "rtf", "msg", "pub", "mobi", "ppt", "pptx",
    "eps", "odt", "ics", "xml", "css", "html", "htm", "shtml", "gif", "jpg", "jpeg", "png", "tif", "tiff", "bmp",
    "cgm", "zip", "tar", "ez", "pkpass", "mp3", "m4a", "m4v", "wma", "ogg", "flac", "wav", "aif", "aifc", "aiff",
    "mp4", "mov", "avi", "mkv", "mpeg", "mpg", "wmv",
];

#[derive(Debug)]
struct Brevo {
    apikey: Secret,
    from_email: String,
    reply_to: Option<String>,
    targets: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
}

/// Extension of the last path component, dot included; empty for dotfiles.
fn extension(name: &str) -> &str {
    let base = name.rsplit('/').next().unwrap_or(name);
    match base.rfind('.') {
        Some(i) if base.split_at(i).0.chars().any(|c| c != '.') => base.split_at(i).1,
        _ => "",
    }
}

/// Brevo rejects unknown extensions; `.txt` is appended to those.
fn safe_name(raw: String) -> String {
    let ext = extension(&raw);
    if ext.is_empty() || !VALID_EXTENSIONS.contains(&ext.trim_start_matches('.').to_lowercase().as_str()) {
        format!("{raw}.txt")
    } else {
        raw
    }
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let user = u.user.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| SERVICE.err("no API key specified"))?;
    let password =
        u.password.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| SERVICE.err("no from email specified"))?;
    let apikey = validate_regex(&unquote(user), r"^[a-zA-Z0-9._-]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Brevo API Key was specified"))?;
    let from = format!("{}@{}", unquote(password), u.host());
    let from_email = is_email(&from).ok_or_else(|| SERVICE.err("invalid ~From~ email specified"))?.full_email;

    let reply_to = match SERVICE.text(u, "reply").filter(|r| !r.is_empty()) {
        Some(r) => Some(is_email(&r).ok_or_else(|| SERVICE.err("an invalid Brevo Reply To was specified"))?.full_email),
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
    Ok(Box::new(Brevo { apikey: Secret::new(apikey), from_email, reply_to, targets, cc, bcc }))
}

impl Notify for Brevo {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Service("there are no Brevo email recipients to notify".into()));
        }
        let mut base = json!({
            "sender": {"email": self.from_email},
            "subject": if msg.title.is_empty() { "<no subject>" } else { msg.title },
        });
        if msg.format == NotifyFormat::Html {
            base["htmlContent"] = json!(msg.body);
            base["textContent"] = json!(html_to_text(msg.body));
        } else {
            base["textContent"] = json!(msg.body);
            base["htmlContent"] = json!(text_to_html(msg.body));
        }
        if !msg.attachments.is_empty() {
            base["attachment"] = attachments_json(msg.attachments, "txt", |name, data, _| {
                json!({"content": data, "name": safe_name(name)})
            });
        }
        if let Some(r) = &self.reply_to {
            base["replyTo"] = json!({"email": r});
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
                .header("Accept", "application/json")
                .header("api-key", self.apikey.expose())
                .json(&payload);
            Plan::send_expect(req, &[200, 201, 202]).target(target.clone())
        });
        Plan::all(plans.collect::<Vec<_>>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attachment_names() {
        assert_eq!(safe_name("a.png".into()), "a.png");
        assert_eq!(safe_name("a.PDF".into()), "a.PDF");
        assert_eq!(safe_name("noext".into()), "noext.txt");
        assert_eq!(safe_name("x.exe".into()), "x.exe.txt");
        assert_eq!(safe_name(".png".into()), ".png.txt");
    }

    #[test]
    fn invalid_reply() {
        let u = crate::url::parse_url("brevo://abcd:user@example.com?reply=invalid").unwrap();
        assert!(parse(&u).is_err());
    }
}
