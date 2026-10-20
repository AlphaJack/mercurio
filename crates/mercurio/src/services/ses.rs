//! AWS Simple Email Service (`ses://`): `SendRawEmail` with a MIME message built by the shared mail module, signed with AWS SigV4.
//!
//! Cc/Bcc recipients are sent in sorted order.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::error::Error;
use crate::http::Request;
use crate::message::Attachment;
use crate::parse::{is_email, parse_emails, validate_nonblank, validate_regex};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::services::_aws::{AWS_FORM_CONTENT_TYPE, AwsSigner, aws_check, aws_region};
use crate::services::_mail::mime::{Part, formataddr, header_value, render};
use crate::url::{ParsedUrl, form_urlencode, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "ses",
    name: "AWS Simple Email Service (SES)",
    schemes: &["ses"],
    service_url: "https://aws.amazon.com/ses/",
    parse,
    formats: &[NotifyFormat::Html],
    attachments: true,
    templates: &[
        "{schema}://{from_email}/{access_key_id}/{secret_access_key}/{region}/{targets}",
        "{schema}://{from_email}/{access_key_id}/{secret_access_key}/{region}",
    ],
    tokens: &[
        Param::new("access_key_id", "Access Key ID").required().secret(),
        Param::new("from_email", "From Email").email().required(),
        Param::new("region", "Region").required().pattern("^[a-z]{2}-[a-z-]+?-[0-9]+$"),
        Param::new("secret_access_key", "Secret Access Key").required().secret(),
        Param::new("targets", "Target Emails").list("/"),
        Param::new("token", "Session Token").secret(),
    ],
    params: &[
        Param::sets("access", &["access_key_id"]),
        Param::new("bcc", "Blind Carbon Copy").list(", "),
        Param::new("cc", "Carbon Copy").list(", "),
        Param::sets("from", &["from_email"]),
        Param::sets("key", &["access_key_id"]),
        Param::new("name", "From Name"),
        Param::sets("region", &["region"]),
        Param::new("reply", "Reply To Email"),
        Param::sets("secret", &["secret_access_key"]),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

/// `(name, address)`; an empty name means no display name.
type Addr = (String, String);

#[derive(Debug)]
struct Ses {
    access_key_id: String,
    secret_access_key: Secret,
    region: String,
    session_token: Option<Secret>,
    from_addr: String,
    from_name: Option<String>,
    reply_to: Option<Addr>,
    targets: Vec<Addr>,
    cc: Vec<String>,
    bcc: Vec<String>,
    names: BTreeMap<String, String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut entries = u.path_segments();
    let access_from_path = if entries.is_empty() { None } else { Some(entries.remove(0)) };
    let mut secret_parts = Vec::new();
    let mut region = None;
    let mut index = 0;
    for (i, entry) in entries.iter().enumerate() {
        index = i + 1;
        if let Some(r) = aws_region(entry) {
            region = Some(r);
            break;
        } else if is_email(entry).is_some() {
            index -= 1;
            break;
        }
        secret_parts.push(entry.clone());
    }
    let secret_from_path = (!secret_parts.is_empty()).then(|| secret_parts.join("/"));
    let mut targets: Vec<String> = entries[index..].to_vec();
    let from_name = SERVICE.text(u, "name");
    if let Some(to) = u.param_nonempty("to") {
        targets.push(to.to_string());
    }
    let cc = u.param_nonempty("cc").map(str::to_string);
    let bcc = u.param_nonempty("bcc").map(str::to_string);
    let from_param = SERVICE.text(u, "from");
    let reply = SERVICE.text(u, "reply");
    let secret = SERVICE.text(u, "secret").or(secret_from_path);
    let access = u.param_nonempty("key").or_else(|| u.param_nonempty("access")).map(unquote).or(access_from_path);
    let region = SERVICE.text(u, "region").or(region);
    let mut session_token = u.password().filter(|p| !p.is_empty());
    if let Some(t) = SERVICE.text(u, "token") {
        session_token = Some(t);
    }

    let access_key_id = access
        .as_deref()
        .and_then(validate_nonblank)
        .ok_or_else(|| SERVICE.err("an invalid AWS Access Key ID was specified"))?;
    let secret_access_key = secret
        .as_deref()
        .and_then(validate_nonblank)
        .ok_or_else(|| SERVICE.err("an invalid AWS Secret Access Key was specified"))?;
    let region = region
        .as_deref()
        .and_then(|r| validate_regex(r, r"^[a-z]{2}-[a-z-]+?-[0-9]+$", "i", true))
        .ok_or_else(|| SERVICE.err("an invalid AWS Region was specified"))?;

    let user = u.user().filter(|s| !s.is_empty());
    let from_addr = match from_param {
        Some(f) => Some(f),
        None => user.map(|user| format!("{user}@{}", u.host())),
    };
    let from_addr = from_addr
        .filter(|f| is_email(f).is_some())
        .ok_or_else(|| SERVICE.err("an invalid AWS From address was specified"))?;

    let reply_to = match reply {
        None => None,
        Some(r) => {
            let e = is_email(&r).ok_or_else(|| SERVICE.err("an invalid AWS Reply To address was specified"))?;
            Some((e.name, e.full_email))
        }
    };

    let mut addrs = Vec::new();
    if !targets.is_empty() {
        for recipient in parse_emails(&targets, true) {
            match is_email(&recipient) {
                Some(e) => addrs.push((e.name, e.full_email)),
                None => log::warn!("SES: dropped invalid To email"),
            }
        }
    } else {
        addrs.push((from_name.clone().unwrap_or_default(), from_addr.clone()));
    }

    let mut names = BTreeMap::new();
    let mut collect = |raw: Option<String>| {
        let mut set = Vec::new();
        for recipient in parse_emails(raw.as_deref(), true) {
            match is_email(&recipient) {
                Some(e) => {
                    if !set.contains(&e.full_email) {
                        set.push(e.full_email.clone());
                    }
                    names.insert(e.full_email, e.name);
                }
                None => log::warn!("SES: dropped invalid Cc/Bcc email"),
            }
        }
        set.sort();
        set
    };
    let cc = collect(cc);
    let bcc = collect(bcc);

    Ok(Box::new(Arc::new(Ses {
        access_key_id,
        secret_access_key: Secret::new(secret_access_key),
        region,
        session_token: session_token.map(Secret::new),
        from_addr,
        from_name,
        reply_to,
        targets: addrs,
        cc,
        bcc,
        names,
    })))
}

impl Ses {
    fn host(&self) -> String {
        format!("email.{}.amazonaws.com", self.region)
    }

    fn post(&self, body: String, ua: &str) -> Request {
        let host = self.host();
        let signer = AwsSigner {
            access_key_id: &self.access_key_id,
            secret_access_key: self.secret_access_key.expose(),
            region: &self.region,
            service: "ses",
            host: &host,
            session_token: self.session_token.as_ref().map(Secret::expose),
        };
        let mut req = Request::post(format!("https://{host}")).header("User-Agent", ua);
        for (k, v) in signer.sign_post(&body, AWS_FORM_CONTENT_TYPE, crate::time::unix_time()) {
            req = req.header(k, v);
        }
        req.body(body, None)
    }
}

impl Notify for Arc<Ses> {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Message("there are no SES email recipients to notify".into()));
        }
        let from_name = match (&self.from_name, &self.reply_to) {
            (Some(n), _) => n.clone(),
            (None, Some((n, _))) if !n.is_empty() => n.clone(),
            _ => ctx.app_desc().to_string(),
        };
        let reply_addr = self.reply_to.as_ref().map_or(self.from_addr.clone(), |r| r.1.clone());
        let date = crate::time::rfc2822_utc(crate::time::unix_time());
        let ua = ctx.app_id().to_string();

        let mut plans = Vec::new();
        for (to_name, to_addr) in &self.targets {
            let cc_addrs: Vec<&String> = self.cc.iter().filter(|a| !self.bcc.contains(a) && *a != to_addr).collect();
            let cc: Vec<String> =
                cc_addrs.iter().map(|a| formataddr(self.names.get(*a).map_or("", String::as_str), a)).collect();
            let bcc: Vec<&String> = self.bcc.iter().filter(|a| *a != to_addr).collect();
            let mut headers = vec![
                ("Subject".to_string(), header_value(msg.title)),
                ("From".into(), formataddr(&from_name, &self.from_addr)),
                ("To".into(), formataddr(to_name, to_addr)),
            ];
            if reply_addr != self.from_addr {
                headers.push(("Reply-To".into(), formataddr(&from_name, &reply_addr)));
            }
            if !cc.is_empty() {
                headers.push(("Cc".into(), cc.join(",")));
            }
            headers.push(("Date".into(), date.clone()));
            headers.push(("X-Application".into(), header_value(&ua)));
            let raw = raw_message(&headers, msg.format == NotifyFormat::Html, msg.body, msg.attachments);
            let mut payload: Vec<(String, String)> = vec![
                ("Action".into(), "SendRawEmail".into()),
                ("Version".into(), "2010-12-01".into()),
                ("RawMessage.Data".into(), crate::crypto::b64(raw.as_bytes())),
            ];
            for (no, email) in std::iter::once(to_addr).chain(bcc).chain(cc_addrs).enumerate() {
                payload.push((format!("Destinations.member.{}", no + 1), email.clone()));
            }
            payload.push(("Source".into(), formataddr(&from_name, &self.from_addr)));
            let body = form_urlencode(payload.iter());
            let (me, ua) = (self.clone(), ua.clone());
            plans.push(
                Plan::defer(move || {
                    Plan::http(me.post(body, &ua), |res| match aws_check(res) {
                        Ok(_) => Plan::Done,
                        Err(e) => Plan::Fail(e),
                    })
                })
                .target(to_addr.clone()),
            );
        }
        Plan::all(plans)
    }
}

/// The `SendRawEmail` message: headers, then the body (a multipart/mixed tree when there are attachments).
fn raw_message(headers: &[(String, String)], html: bool, body: &str, attachments: &[Attachment]) -> String {
    let text = Part::text(if html { "html" } else { "plain" }, body);
    let tree = if attachments.is_empty() {
        text
    } else {
        let mut parts = vec![text];
        for (no, a) in attachments.iter().enumerate() {
            let filename = if a.name.is_empty() { format!("file{:03}.dat", no + 1) } else { a.name.clone() };
            parts.push(Part::file(&a.mime, &a.data, "attachment", &filename, None));
        }
        Part::Multi { subtype: "mixed", parts }
    };
    render(headers, &tree)
}

#[cfg(test)]
#[expect(clippy::disallowed_methods, reason = "tests set up real files")]
mod tests {
    use super::*;

    #[test]
    fn raw_message_layout() {
        let headers = vec![("Subject".to_string(), header_value("Tïtle")), ("To".into(), "a@b.com".into())];
        let plain = raw_message(&headers, true, "Body", &[]);
        assert!(plain.starts_with("Subject: =?utf-8?b?VMOvdGxl?=\r\nTo: a@b.com\r\nMIME-Version: 1.0\r\n"), "{plain}");
        assert!(plain.ends_with("Content-Type: text/html; charset=\"utf-8\"\r\n\
                                 Content-Transfer-Encoding: quoted-printable\r\n\r\nBody"));
        let atts = [Attachment::new("", "image/png", b"\x89PNG".to_vec())];
        let multi = raw_message(&headers, false, "Body", &atts);
        assert!(multi.contains("Content-Type: multipart/mixed; boundary="), "{multi}");
        assert!(multi.contains("Content-Disposition: attachment; filename=\"file001.dat\"\r\n\r\niVBORw=="), "{multi}");
    }

    /// The fixture masks `RawMessage.Data` (random boundary and date); snapshot it here with those two normalised.
    #[test]
    fn raw_messages() {
        use crate::testing::fixtures::{case_message, case_transport, fixture_asset, with_defaults};
        use serde_json::Value;
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/services/ses.json");
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let norm = |raw: &str| -> String {
            let raw = crate::regex!(r"Date: [^\r\n]*").replace_all(raw, "Date: <date>").to_string();
            crate::regex!(r"=+mercurio[0-9a-f]+==").replace_all(&raw, "<boundary>").to_string()
        };
        let mut out = std::collections::BTreeMap::new();
        for case in doc["cases"].as_array().unwrap() {
            let Ok(target) = crate::parse(case["url"].as_str().unwrap()) else { continue };
            let fake = case_transport(case);
            let _ = target.send(&case_message(&with_defaults(&doc, case)), fake.as_ref(), &fixture_asset(&doc));
            let raws: Vec<String> = fake
                .requests()
                .iter()
                .filter_map(|r| {
                    let body = r.body_text();
                    let b64 = body.split('&').find_map(|p| p.strip_prefix("RawMessage.Data="))?;
                    let raw = crate::crypto::b64_decode(&crate::url::unquote_plus(b64))?;
                    Some(norm(&String::from_utf8(raw).ok()?))
                })
                .collect();
            if !raws.is_empty() {
                out.insert(case["name"].as_str().unwrap().to_string(), raws);
            }
        }
        assert!(out.len() >= 5, "{}", out.len());
        crate::testing::fixtures::snapshot("unit", "ses_raw_messages", &serde_json::json!(out));
    }
}
