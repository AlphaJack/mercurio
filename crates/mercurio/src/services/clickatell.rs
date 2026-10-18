//! Clickatell (`clickatell://`): SMS through the Clickatell API.

use super::_sms::{expect, no_targets, per_target, to_param, valid_phones};
use crate::parse::{is_phone_no, validate_nonblank};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "clickatell",
    name: "Clickatell",
    schemes: &["clickatell"],
    service_url: "https://www.clickatell.com/",
    parse,
    limits: Limits { title_maxlen: 0, ..Limits::DEFAULT },
    templates: &[
        "{schema}://{apikey}/{targets}",
        "{schema}://{source}@{apikey}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Token").required().secret(),
        Param::new("source", "From Phone No").pattern(r"^[0-9\s)(+-]+$"),
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
struct Clickatell {
    apikey: Secret,
    source: Option<String>,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let apikey = u.host();
    let mut source = u.user.as_deref().filter(|s| !s.is_empty()).map(unquote);
    targets.extend(to_param(u, false));
    if let Some(v) = SERVICE.text(u, "from") {
        source = Some(v);
    }

    let apikey = validate_nonblank(&apikey).ok_or_else(|| SERVICE.err("an invalid Clickatell API Token was specified"))?;
    let source = match source.filter(|s| !s.is_empty()) {
        Some(s) => Some(
            is_phone_no(&s, 10).ok_or_else(|| SERVICE.err("the Account (From) Phone # specified is invalid"))?.full,
        ),
        None => None,
    };
    let targets = valid_phones(&targets, true, 10).into_iter().map(|(_, p)| p.full).collect();
    Ok(Box::new(Clickatell { apikey: Secret::new(apikey), source, targets }))
}

impl Notify for Clickatell {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return no_targets("Clickatell");
        }
        per_target(self.targets.clone(), String::clone, |target| {
            let mut params = vec![("apiKey", self.apikey.expose())];
            if let Some(s) = &self.source {
                params.push(("from", s.as_str()));
            }
            params.push(("content", msg.body));
            params.push(("to", target.as_str()));
            let req = ctx.get("https://platform.clickatell.com/messages/http/send")
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .query(&params);
            Plan::send_check(req, |r| expect(r, &[200, 202]))
        })
    }

}
