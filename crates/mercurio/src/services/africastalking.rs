//! Africa's Talking (`atalk://`): SMS through the Africa's Talking messaging API.

use std::collections::HashSet;

use serde_json::Value;

use super::_sms::{no_targets, per_target, to_param};
use crate::http::Response;
use crate::parse::{is_phone_no, parse_phone_no, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::util::{json_text, parse_int};
use crate::{Error, Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "africastalking",
    name: "Africas Talking",
    schemes: &["atalk"],
    service_url: "https://africastalking.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    templates: &[
        "{schema}://{appuser}@{apikey}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret().pattern("^[A-Z0-9_-]+$"),
        Param::new("appuser", "App User Name").required().pattern("^[A-Z0-9_-]+$"),
        Param::new("target_phone", "Target Phone"),
        Param::new("targets", "Targets").list("/").required().group(&["target_phone"]),
    ],
    params: &[
        Param::sets("apikey", &["apikey"]),
        Param::new("batch", "Batch Mode").bool(false),
        Param::new("from", "From").default("AFRICASTKNG"),
        Param::new("mode", "SMS Mode").choice(&["bulksms", "premium", "sandbox"]).default("bulksms"),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const BATCH_SIZE: usize = 50;
const MODES: &[(&str, &str)] = &[
    ("bulksms", "https://api.africastalking.com/version1/messaging"),
    ("premium", "https://content.africastalking.com/version1/messaging"),
    ("sandbox", "https://api.sandbox.africastalking.com/version1/messaging"),
];
const RECIPIENT_OK: &[i64] = &[100, 101, 102];

#[derive(Debug)]
struct AfricasTalking {
    appuser: String,
    apikey: Secret,
    sender: String,
    batch: bool,
    url: &'static str,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let appuser = u.user().unwrap_or_default();
    let mut targets = Vec::new();
    let apikey = match SERVICE.text(u, "apikey") {
        Some(k) => {
            targets.push(u.host());
            k
        }
        None => u.host(),
    };
    targets.extend(u.path_segments());
    let sender = SERVICE.text(u, "from");
    targets.extend(to_param(u));
    let mode = SERVICE.text(u, "mode");
    let batch = SERVICE.flag_strict(u, "batch");

    let appuser = validate_regex(&appuser, r"^[A-Z0-9_-]+$", "i", true)
        .ok_or_else(|| SERVICE.err("the Africas Talking appuser specified is invalid"))?;
    let apikey = validate_regex(&apikey, r"^[A-Z0-9_-]+$", "i", true)
        .ok_or_else(|| SERVICE.err("the Africas Talking apikey specified is invalid"))?;
    let url = match mode {
        Some(m) => {
            let m = m.to_lowercase();
            MODES
                .iter()
                .find(|(name, _)| name.starts_with(&m))
                .map(|(_, url)| *url)
                .ok_or_else(|| SERVICE.err("the Africas Talking mode specified is invalid"))?
        }
        None => MODES[0].1,
    };
    let targets = parse_phone_no(&targets, true, false)
        .into_iter()
        .filter_map(|t| {
            let p = is_phone_no(&t, 10)?;
            Some(if t.trim_start().starts_with('+') { format!("+{}", p.full) } else { p.full })
        })
        .collect();
    Ok(Box::new(AfricasTalking {
        appuser,
        apikey: Secret::new(apikey),
        sender: sender.unwrap_or_else(|| "AFRICASTKNG".into()),
        batch,
        url,
        targets,
    }))
}

/// `_accepted()`: the targets of `batch` the response reports as accepted.
fn accepted(r: &Response, batch: &[String]) -> Vec<String> {
    let content = r.json().unwrap_or(Value::Null);
    let recipients = content.get("SMSMessageData").filter(|d| d.is_object()).and_then(|d| d.get("Recipients"));
    let Some(Value::Array(recipients)) = recipients else {
        return batch.to_vec();
    };
    let mut numbers = HashSet::new();
    let mut ok = Vec::new();
    for entry in recipients {
        let Value::Object(entry) = entry else { continue };
        let raw = entry.get("number").map(json_text).unwrap_or_default();
        let digits: String = raw.chars().filter(|c| c.is_numeric()).collect();
        let number = digits.trim_start_matches('0').to_owned();
        numbers.insert(number.clone());
        let code = entry.get("statusCode").and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(parse_int)));
        if code.is_some_and(|c| RECIPIENT_OK.contains(&c)) {
            ok.push(number);
        }
    }
    let digits: Vec<(&String, &str)> = batch.iter().map(|t| (t, t.trim_start_matches(['+', '0']))).collect();
    let exact: HashSet<&String> = digits.iter().filter(|(_, d)| numbers.contains(*d)).map(|(t, _)| *t).collect();
    let mut result: HashSet<&String> = HashSet::new();
    for number in &ok {
        let mut matched: Vec<&String> = digits.iter().filter(|(_, d)| d == number).map(|(t, _)| *t).collect();
        if matched.is_empty() {
            matched = digits
                .iter()
                .filter(|(t, d)| !exact.contains(t) && (number.ends_with(d) || d.ends_with(number.as_str())))
                .map(|(t, _)| *t)
                .collect();
            if matched.len() != 1 {
                continue;
            }
        }
        result.extend(matched);
    }
    batch.iter().filter(|t| result.contains(t)).cloned().collect()
}

impl Notify for AfricasTalking {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return no_targets("Africas Talking");
        }
        let size = if self.batch { BATCH_SIZE } else { 1 };
        let chunks: Vec<Vec<String>> = self.targets.chunks(size).map(<[String]>::to_vec).collect();
        per_target(
            chunks,
            |c| c.join(","),
            |chunk| {
                let to = chunk.join(",");
                let form = [
                    ("username", self.appuser.as_str()),
                    ("to", to.as_str()),
                    ("from", self.sender.as_str()),
                    ("message", msg.body),
                ];
                let req = ctx
                    .post(self.url)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .header("apiKey", self.apikey.expose())
                    .form(&form);
                let chunk = chunk.clone();
                Plan::send_check(req, move |r| {
                    r.error_for_status()?;
                    let delivered = accepted(r, &chunk);
                    if chunk.iter().all(|t| delivered.contains(t)) {
                        Ok(())
                    } else {
                        Err(Error::Service("one or more recipients were rejected".into()))
                    }
                })
            },
        )
    }

}
