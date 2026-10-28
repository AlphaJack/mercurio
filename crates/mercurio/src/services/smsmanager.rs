//! SMS Manager (`smsmgr://`, `smsmanager://`): SMS through the SMS Manager API.

use super::_telephony::{phone_entries, param_unquoted, unquote_or_empty};
use crate::parse::{parse_phone_no_unquoted, validate_nonblank};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "smsmanager",
    name: "SMS Manager",
    schemes: &["smsmgr", "smsmanager"],
    service_url: "https://smsmanager.cz",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    templates: &[
        "{schema}://{apikey}@{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret(),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").required().group(&["target_phone"]),
    ],
    params: &[
        Param::new("batch", "Batch Mode").bool(false),
        Param::new("from", "From Phone No").pattern(r"^\+?[0-9\s)(+-]+$").aliases(&["sender"]),
        Param::new("gateway", "Gateway").choice(&["high", "economy", "low", "direct"]).default("high"),
        Param::sets("key", &["apikey"]),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://http-api.smsmanager.cz/Send";
const BATCH_SIZE: usize = 4000;
const GATEWAYS: &[&str] = &["high", "economy", "low", "direct"];

#[derive(Debug)]
struct SmsManager {
    apikey: Secret,
    gateway: String,
    batch: bool,
    sender: Option<String>,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut apikey = unquote_or_empty(u.user.as_deref());
    let mut targets = parse_phone_no_unquoted([u.host.as_str()], false);
    targets.extend(u.path_segments());
    let sender = param_unquoted(u, "from").or_else(|| param_unquoted(u, "sender"));
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_phone_no_unquoted([to], false));
    }
    if let Some(k) = SERVICE.text(u, "key") {
        apikey = k;
    }
    let batch = SERVICE.flag(u, "batch");
    let gateway = SERVICE.text_or_default(u, "gateway").to_lowercase();

    let apikey = validate_nonblank(&apikey).ok_or_else(|| SERVICE.err("an invalid API Key was specified"))?;
    if !GATEWAYS.contains(&gateway.as_str()) {
        return Err(SERVICE.err("the Gateway specified is invalid"));
    }
    let sender = sender.map(|s| s.chars().take(11).collect::<String>());
    let targets = phone_entries(&targets, 9)
        .into_iter()
        .filter_map(|(raw, r)| {
            r.map(|p| if raw.trim_start().starts_with('+') { format!("+{}", p.full) } else { p.full })
        })
        .collect();
    Ok(Box::new(SmsManager { apikey: Secret::new(apikey), gateway, batch, sender, targets }))
}

impl Notify for SmsManager {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(SERVICE.err("there are no valid SMS Manager targets to notify"));
        }
        let size = if self.batch { BATCH_SIZE } else { 1 };
        Plan::all(self.targets.chunks(size).map(|chunk| {
            let number = chunk.join(";");
            let mut payload: Vec<(&str, &str)> = vec![
                ("apikey", self.apikey.expose()),
                ("gateway", &self.gateway),
                ("number", &number),
                ("message", msg.body),
            ];
            if let Some(s) = self.sender.as_deref().filter(|s| !s.is_empty()) {
                payload.push(("sender", s));
            }
            let req = ctx.get(NOTIFY_URL).query(&payload);
            let label = if self.batch { format!("{} targets", chunk.len()) } else { number };
            Plan::send_expect(req, &[200]).target(label)
        }))
    }

}
