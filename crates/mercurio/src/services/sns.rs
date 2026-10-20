//! AWS Simple Notification Service (`sns://`): SMS and topic messages through AWS SNS.
//!
//! Requests are signed with AWS Signature Version 4 when they are sent.

use std::sync::Arc;
use std::time::Duration;

use crate::error::Error;
use crate::http::Request;
use crate::parse::{is_phone_no, parse_list, validate_nonblank, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::services::_aws::{AWS_FORM_CONTENT_TYPE, AwsSigner, aws_check, aws_region, flatten_xml};
use crate::url::{ParsedUrl, form_urlencode, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "sns",
    name: "AWS Simple Notification Service (SNS)",
    schemes: &["sns"],
    service_url: "https://aws.amazon.com/sns/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    throttle: Duration::from_millis(2500),
    templates: &[
        "{schema}://{token}@{access_key_id}/{secret_access_key}/{region}/{targets}",
        "{schema}://{access_key_id}/{secret_access_key}/{region}/{targets}",
    ],
    tokens: &[
        Param::new("access_key_id", "Access Key ID").required().secret(),
        Param::new("region", "Region").required().pattern("^[a-z]{2}-[a-z-]+?-[0-9]+$"),
        Param::new("secret_access_key", "Secret Access Key").required().secret(),
        Param::new("target_phone_no", "Target Phone No").pattern(r"^[0-9\s)(+-]+$"),
        Param::new("target_topic", "Target Topic").pattern("^[A-Za-z0-9_-]+$").prefix("#"),
        Param::new("targets", "Targets").list("/").required().group(&["target_phone_no", "target_topic"]),
        Param::new("token", "Session Token").secret(),
    ],
    params: &[
        Param::sets("access", &["access_key_id"]),
        Param::sets("key", &["access_key_id"]),
        Param::new("mode", "Mode").choice(&["sms", "topic"]).default("sms").inferred(),
        Param::sets("region", &["region"]),
        Param::sets("secret", &["secret_access_key"]),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

const TOPIC_TITLE_MAXLEN: usize = 99;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Sms,
    Topic,
}

#[derive(Debug)]
struct Sns {
    access_key_id: String,
    secret_access_key: Secret,
    region: String,
    session_token: Option<Secret>,
    phones: Vec<String>,
    topics: Vec<String>,
    mode: Mode,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let access_from_host = u.host();
    let entries = u.path_segments();
    let mut secret_parts = Vec::new();
    let mut region = None;
    let mut index = 0;
    for (i, entry) in entries.iter().enumerate() {
        if let Some(r) = aws_region(entry) {
            region = Some(r);
            index = i + 1;
            break;
        }
        secret_parts.push(entry.clone());
    }
    let secret_from_path = region.as_ref().map(|_| secret_parts.join("/"));
    let mut targets: Vec<String> = entries[index..].to_vec();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }
    let secret = SERVICE.text(u, "secret").or(secret_from_path);
    let access = match u.param_nonempty("key").or_else(|| u.param_nonempty("access")) {
        Some(k) => unquote(k),
        None => access_from_host,
    };
    let region = SERVICE.text(u, "region").or(region);
    let mut session_token = u.user().filter(|s| !s.is_empty());
    if let Some(t) = SERVICE.text(u, "token") {
        session_token = Some(t);
    }
    let mode = SERVICE.text(u, "mode");

    let access_key_id =
        validate_nonblank(&access).ok_or_else(|| SERVICE.err("an invalid AWS Access Key ID was specified"))?;
    let secret_access_key = secret
        .as_deref()
        .and_then(validate_nonblank)
        .ok_or_else(|| SERVICE.err("an invalid AWS Secret Access Key was specified"))?;
    let region = region
        .as_deref()
        .and_then(|r| validate_regex(r, r"^[a-z]{2}-[a-z-]+?-[0-9]+$", "i", true))
        .ok_or_else(|| SERVICE.err("an invalid AWS Region was specified"))?;

    let mut phones = Vec::new();
    let mut topics = Vec::new();
    for t in parse_list(&targets) {
        if let Some(p) = is_phone_no(&t, 10) {
            phones.push(format!("+{}", p.full));
        } else if let Some(c) = crate::regex!(r"^#?(?P<name>[A-Za-z0-9_-]+)\s*$").captures(&t) {
            topics.push(c["name"].to_string());
        } else {
            log::warn!("SNS: dropped invalid phone/topic");
        }
    }

    let mode = match mode.filter(|m| !m.is_empty()) {
        Some(m) => {
            let m = m.to_lowercase();
            if "sms".starts_with(&m) {
                Mode::Sms
            } else if "topic".starts_with(&m) {
                Mode::Topic
            } else {
                return Err(SERVICE.err("the AWS SNS mode specified is invalid"));
            }
        }
        None if !topics.is_empty() && phones.is_empty() => Mode::Topic,
        None => Mode::Sms,
    };

    Ok(Box::new(Arc::new(Sns {
        access_key_id,
        secret_access_key: Secret::new(secret_access_key),
        region,
        session_token: session_token.map(Secret::new),
        phones,
        topics,
        mode,
    })))
}

impl Sns {
    fn host(&self) -> String {
        format!("sns.{}.amazonaws.com", self.region)
    }

    /// A signed `POST` of `payload`, built when execution reaches it.
    fn post(self: &Arc<Self>, payload: Vec<(&'static str, String)>, user_agent: String) -> Request {
        let body = form_urlencode(payload.iter());
        let host = self.host();
        let signer = AwsSigner {
            access_key_id: &self.access_key_id,
            secret_access_key: self.secret_access_key.expose(),
            region: &self.region,
            service: "sns",
            host: &host,
            session_token: self.session_token.as_ref().map(Secret::expose),
        };
        let headers = signer.sign_post(&body, AWS_FORM_CONTENT_TYPE, crate::crypto::unix_time());
        let mut req = Request::post(format!("https://{host}/")).header("User-Agent", user_agent);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        req.body(body, None)
    }
}

/// Printable character: a space or anything that is not a control, separator or invisible format character.
fn printable(c: char) -> bool {
    c == ' '
        || !(c.is_control()
            || c.is_whitespace()
            || matches!(c, '\u{ad}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{feff}'))
}

fn subject(title: &str) -> String {
    let s: String = title.chars().map(|c| if printable(c) { c } else { ' ' }).collect();
    s.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(TOPIC_TITLE_MAXLEN).collect()
}

impl Notify for Arc<Sns> {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.phones.is_empty() && self.topics.is_empty() {
            return Plan::Fail(Error::Message("no AWS targets to notify".into()));
        }
        let ua = ctx.app_id().to_string();
        let mut plans = Vec::new();
        for no in &self.phones {
            let message = if self.mode == Mode::Topic && !msg.title.is_empty() {
                format!("{}\r\n{}", msg.title, msg.body)
            } else {
                msg.body.to_string()
            };
            let payload = vec![
                ("Action", "Publish".to_string()),
                ("Message", message),
                ("Version", "2010-03-31".to_string()),
                ("PhoneNumber", no.clone()),
            ];
            let (me, ua) = (self.clone(), ua.clone());
            plans.push(
                Plan::defer(move || {
                    Plan::http(me.post(payload, ua), |res| match aws_check(res) {
                        Ok(_) => Plan::Done,
                        Err(e) => Plan::Fail(e),
                    })
                })
                .target(no.clone()),
            );
        }
        for topic in &self.topics {
            let body = msg.body.to_string();
            let subject = (self.mode == Mode::Topic && !msg.title.is_empty()).then(|| subject(msg.title));
            let payload = vec![
                ("Action", "CreateTopic".to_string()),
                ("Version", "2010-03-31".to_string()),
                ("Name", topic.clone()),
            ];
            let (me, ua) = (self.clone(), ua.clone());
            plans.push(
                Plan::defer(move || {
                    let req = me.post(payload, ua.clone());
                    Plan::http(req, move |res| {
                        let r = match aws_check(res) {
                            Ok(r) => r,
                            Err(e) => return Plan::Fail(e),
                        };
                        let arn = flatten_xml(&r.text(), &[("TopicArn", "topic_arn")])
                            .and_then(|m| m.get("topic_arn").cloned())
                            .filter(|a| !a.is_empty());
                        let Some(arn) = arn else {
                            return Plan::Fail(Error::service("could not acquire the AWS topic ARN"));
                        };
                        let mut payload = vec![
                            ("Action", "Publish".to_string()),
                            ("Version", "2010-03-31".to_string()),
                            ("TopicArn", arn),
                            ("Message", body),
                        ];
                        if let Some(s) = subject {
                            payload.push(("Subject", s));
                        }
                        Plan::defer(move || {
                            Plan::http(me.post(payload, ua), |res| match aws_check(res) {
                                Ok(_) => Plan::Done,
                                Err(e) => Plan::Fail(e),
                            })
                        })
                        .context("publish")
                    })
                    .context("topic lookup")
                })
                .target(topic.clone()),
            );
        }
        Plan::all(plans)
    }

    fn limits(&self, _title: &str, _body: &str, _format: crate::NotifyFormat, _ctx: &Context<'_>) -> Option<Limits> {
        Some(match self.mode {
            Mode::Topic => Limits { title_maxlen: TOPIC_TITLE_MAXLEN, body_maxlen: 256_000, body_max_line_count: 0 },
            Mode::Sms => SERVICE.limits,
        })
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_is_single_line() {
        assert_eq!(subject("  a\tb\r\nc\u{7}d  "), "a b c d");
        assert_eq!(subject(&"x".repeat(150)).len(), 99);
    }
}
