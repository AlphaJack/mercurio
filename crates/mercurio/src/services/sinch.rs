//! Sinch SMS (`sinch://`): SMS through the Sinch API.

use std::time::Duration;

use serde_json::json;

use super::_sms::{expect, no_targets, per_target, to_param, valid_phones};
use crate::parse::{is_phone_no, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "sinch",
    name: "Sinch",
    schemes: &["sinch"],
    service_url: "https://sinch.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    throttle: Duration::from_millis(200),
    templates: &[
        "{schema}://{service_plan_id}:{api_token}@{from_phone}",
        "{schema}://{service_plan_id}:{api_token}@{from_phone}/{targets}",
    ],
    tokens: &[
        Param::new("api_token", "Auth Token").required().secret().pattern("^[a-f0-9]+$"),
        Param::new("from_phone", "From Phone No").required().pattern(r"^\+?[0-9\s)(+-]+$"),
        Param::new("service_plan_id", "Account SID").required().secret().pattern("^[a-f0-9]+$"),
        Param::new("short_code", "Target Short Code").pattern("^[0-9]{5,6}$"),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").group(&["short_code", "target_phone"]),
    ],
    params: &[
        Param::sets("from", &["from_phone"]).aliases(&["source"]),
        Param::new("region", "Region").default("us").pattern("^[a-z]{2}$"),
        Param::sets("spi", &["service_plan_id"]),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["api_token"]),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Sinch {
    service_plan_id: Secret,
    api_token: Secret,
    region: String,
    source: String,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let mut source = u.host();
    let mut spi = u.user().unwrap_or_default();
    let mut token = u.password().unwrap_or_default();
    if let Some(v) = SERVICE.text(u, "token") {
        token = v;
    }
    if let Some(v) = SERVICE.text(u, "spi") {
        spi = v;
    }
    if let Some(v) = u.text("source").or_else(|| u.text("from")) {
        source = v;
    }
    let region = SERVICE.text(u, "region");
    targets.extend(to_param(u, false));

    let spi = validate_regex(&spi, r"^[a-f0-9]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Sinch Account SID was specified"))?;
    let token = validate_regex(&token, r"^[a-f0-9]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Sinch Authentication Token was specified"))?;
    let region = region.map(|r| r.to_lowercase()).unwrap_or_else(|| "us".into());
    if !region.is_empty() && region != "us" && region != "eu" {
        return Err(SERVICE.err("the region specified is invalid"));
    }
    let invalid = || SERVICE.err("the Account (From) Phone # or Short-code specified is invalid");
    let mut source = is_phone_no(&source, 5).ok_or_else(invalid)?.full;
    if source.len() < 11 || source.len() > 14 {
        if source.len() != 5 && source.len() != 6 {
            return Err(SERVICE.err("the Account (From) Phone # specified is invalid"));
        }
    } else {
        source = format!("+{source}");
    }
    let targets = valid_phones(&targets, false, 10).into_iter().map(|(_, p)| format!("+{}", p.full)).collect();
    Ok(Box::new(Sinch {
        service_plan_id: Secret::new(spi),
        api_token: Secret::new(token),
        region,
        source,
        targets,
    }))
}

impl Notify for Sinch {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() && matches!(self.source.len(), 5 | 6) {
            return no_targets("Sinch");
        }
        let url =
            format!("https://{}.sms.api.sinch.com/xms/v1/{}/batches", self.region, self.service_plan_id.expose());
        let mut targets = self.targets.clone();
        if targets.is_empty() {
            targets.push(self.source.clone());
        }
        per_target(targets, String::clone, |target| {
            let payload = json!({"body": msg.body, "from": self.source, "to": [target]});
            let req = ctx.post(&url)
                .header("Authorization", format!("Bearer {}", self.api_token.expose()))
                .json(&payload);
            Plan::send_check(req, |r| expect(r, &[201, 200]))
        })
    }

}
