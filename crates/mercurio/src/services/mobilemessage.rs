//! Mobile Message (`mobilemessage://`, `mobilemsg://`): SMS through the Mobile Message API.

use serde_json::{Value, json};

use super::_telephony::{http_err, json_object, phone_entries, param_unquoted};
use crate::error::Error;
use crate::parse::{parse_bool, parse_phone_no_unquoted, validate_nonblank, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::util::parse_int;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "mobilemessage",
    name: "Mobile Message",
    schemes: &["mobilemessage", "mobilemsg"],
    service_url: "https://mobilemessage.com.au/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 10 * GSM7_PART_SIZE, body_max_line_count: 0 },
    templates: &[
        "{schema}://{user}:{password}@{sender}/{targets}",
    ],
    tokens: &[
        Param::new("password", "API Password").required().secret(),
        Param::new("sender", "Sender ID").required().pattern(r"^\+?[a-z0-9][a-z0-9 ()_.-]{1,19}$"),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").required().group(&["target_phone"]),
        Param::new("user", "API Username").required(),
    ],
    params: &[
        Param::new("batch", "Batch Mode").bool(true),
        Param::sets("from", &["sender"]),
        Param::new("max_parts", "Max Message Parts").int().default("10").range(1, 99),
        Param::new("ref", "Custom Reference"),
        Param::sets("to", &["targets"]),
        Param::new("unicode", "Unicode Characters").bool(false),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.mobilemessage.com.au/v1/messages";
const BATCH_SIZE: usize = 10000;
const GSM7_PART_SIZE: usize = 153;
const UCS2_PART_SIZE: usize = 67;

#[derive(Debug)]
struct MobileMessage {
    user: String,
    password: Secret,
    source: String,
    unicode: bool,
    batch: bool,
    max_parts: i64,
    reference: Option<String>,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let (source, mut targets) = match param_unquoted(u, "from") {
        Some(f) => {
            let mut t = parse_phone_no_unquoted([u.host.as_str()], false);
            t.extend(u.path_segments());
            (f, t)
        }
        None => (u.host(), u.path_segments()),
    };
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_phone_no_unquoted([to], false));
    }
    let unicode = SERVICE.flag(u, "unicode");
    let batch = u.param_nonempty("batch").map(|v| parse_bool(v, false)).unwrap_or(true);
    let max_parts = SERVICE.text_or_default(u, "max_parts");
    let reference = SERVICE.text(u, "ref");

    let user = u.user().unwrap_or_default();
    let password = u.password().unwrap_or_default();
    if user.is_empty() || password.is_empty() {
        return Err(SERVICE.err("a Mobile Message API username and password must be specified"));
    }
    let mut source = validate_regex(&source, r"^\+?[a-z0-9][a-z0-9 ()_.-]{1,19}$", "i", true)
        .ok_or_else(|| SERVICE.err("the Mobile Message Sender ID specified is invalid"))?;
    if crate::regex!(r"^\+?[0-9\s()-]+$").is_match(&source) {
        source.retain(|c| c.is_ascii_digit());
    }
    let max_parts =
        parse_int(&max_parts).ok_or_else(|| SERVICE.err("the Mobile Message max_parts specified is invalid"))?;
    if !(1..=99).contains(&max_parts) {
        return Err(SERVICE.err("the Mobile Message max_parts must be between 1 and 99"));
    }
    let reference = reference.and_then(|r| validate_nonblank(&r));
    let au = crate::regex!(r"^614\d{8}$");
    let targets = phone_entries(&targets, 9)
        .into_iter()
        .filter_map(|(_, r)| r)
        .map(|p| {
            let no = p.full;
            if let Some(rest) = no.strip_prefix('0') {
                format!("61{rest}")
            } else if no.len() == 9 {
                format!("61{no}")
            } else {
                no
            }
        })
        .filter(|no| au.is_match(no))
        .collect();
    Ok(Box::new(MobileMessage {
        user,
        password: Secret::new(password),
        source,
        unicode,
        batch,
        max_parts,
        reference,
        targets,
    }))
}

impl Notify for MobileMessage {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(SERVICE.err("there are no valid Mobile Message targets to notify"));
        }
        let size = if self.batch { BATCH_SIZE } else { 1 };
        Plan::all(self.targets.chunks(size).map(|chunk| {
            let messages: Vec<Value> = chunk
                .iter()
                .map(|t| {
                    let mut e = json!({"to": t, "message": crate::http::TEXT, "sender": self.source});
                    if let Some(r) = &self.reference {
                        e["custom_ref"] = json!(r);
                    }
                    e
                })
                .collect();
            let payload = json!({"messages": messages, "enable_unicode": self.unicode, "max_parts": self.max_parts});
            let req = ctx
                .post(NOTIFY_URL)
                .header("Accept", "application/json")
                .header("Idempotency-Key", ctx.env().uuid4())
                .basic_auth(&self.user, Some(self.password.expose()))
                .json_text(&payload, msg.body);
            let targets: Vec<String> = chunk.to_vec();
            Plan::http(req, move |res| {
                let fail_all = |e: Error| Plan::all(targets.iter().map(|t| Plan::Fail(e.clone()).target(t.clone())));
                let r = match res {
                    Err(e) => return fail_all(e),
                    Ok(r) => r,
                };
                if r.status != 200 {
                    return fail_all(http_err(&r));
                }
                let content = json_object(&r).unwrap_or_default();
                let results = match content.get("results") {
                    Some(Value::Array(a))
                        if content.get("status").and_then(Value::as_str) == Some("complete")
                            && a.len() == targets.len() =>
                    {
                        a.clone()
                    }
                    _ => return fail_all(Error::Service("Mobile Message returned an unexpected response".into())),
                };
                Plan::all(targets.iter().zip(results).map(|(t, res)| {
                    if res.get("status").and_then(Value::as_str) == Some("success") {
                        Plan::Done.target(t.clone())
                    } else {
                        Plan::Fail(Error::Service("Mobile Message rejected the message".into())).target(t.clone())
                    }
                }))
            })
        }))
    }

    fn limits(&self, _title: &str, _body: &str, _format: crate::NotifyFormat, _ctx: &Context<'_>) -> Option<Limits> {
        let part = if self.unicode { UCS2_PART_SIZE } else { GSM7_PART_SIZE };
        Some(Limits { title_maxlen: 0, body_maxlen: self.max_parts as usize * part, body_max_line_count: 0 })
    }

}
