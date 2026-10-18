//! Kavenegar (`kavenegar://`): SMS through the Kavenegar API.

use std::time::Duration;

use super::_sms::{expect, full_numbers, no_targets, per_target, to_param};
use crate::parse::{is_phone_no, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "kavenegar",
    name: "Kavenegar",
    schemes: &["kavenegar"],
    service_url: "https://kavenegar.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    throttle: Duration::from_millis(200),
    templates: &[
        "{schema}://{apikey}/{targets}",
        "{schema}://{source}@{apikey}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret().pattern("^[a-z0-9]+$"),
        Param::new("source", "Source Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").required().group(&["target_phone"]),
    ],
    params: &[
        Param::sets("from", &["source"]),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Kavenegar {
    apikey: Secret,
    source: Option<String>,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    // The raw (still quoted) user is the source.
    let mut source = u.user.clone().filter(|s| !s.is_empty());
    let mut targets = u.path_segments();
    let apikey = u.host();
    targets.extend(to_param(u, false));
    if let Some(v) = SERVICE.text(u, "from") {
        source = Some(v);
    }

    let apikey = validate_regex(&apikey, r"^[a-z0-9]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Kavenegar API Key was specified"))?;
    let source = match source {
        Some(s) => {
            Some(is_phone_no(&s, 10).ok_or_else(|| SERVICE.err("the Kavenegar source specified is invalid"))?.full)
        }
        None => None,
    };
    Ok(Box::new(Kavenegar { apikey: Secret::new(apikey), source, targets: full_numbers(&targets, false) }))
}

impl Notify for Kavenegar {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return no_targets("Kavenegar");
        }
        let url = format!("https://api.kavenegar.com/v1/{}/sms/send.json", self.apikey.expose());
        per_target(self.targets.clone(), String::clone, |target| {
            let mut params = vec![("receptor", target.as_str()), ("message", msg.body)];
            if let Some(s) = &self.source {
                params.push(("sender", s.as_str()));
            }
            let req = ctx.post(&url)
                .header("Accept", "application/json")
                .query(&params);
            Plan::send_check(req, |r| expect(r, &[201, 200]))
        })
    }

}
