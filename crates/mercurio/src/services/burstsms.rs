//! Burst SMS (`burstsms://`): SMS through the Burst SMS API.

use super::_sms::{expect, full_numbers, no_targets, per_target, to_param};
use crate::parse::{validate_nonblank, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::util::parse_int;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "burstsms",
    name: "Burst SMS",
    schemes: &["burstsms"],
    service_url: "https://burstsms.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    templates: &[
        "{schema}://{apikey}:{secret}@{sender_id}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret().pattern("^[a-z0-9]+$"),
        Param::new("secret", "API Secret").required().secret().pattern("^[a-z0-9]+$"),
        Param::new("sender_id", "Sender ID").required(),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").required().group(&["target_phone"]),
    ],
    params: &[
        Param::new("batch", "Batch Mode").bool(false),
        Param::new("country", "Country").choice(&["au", "nz", "gb", "us"]).default("us"),
        Param::sets("from", &["sender_id"]).aliases(&["source"]),
        Param::sets("key", &["apikey"]),
        Param::sets("secret", &["secret"]),
        Param::sets("to", &["targets"]),
        Param::new("validity", "validity").int().default("0"),
    ],
    ..ServiceDef::DEFAULTS
};

const BATCH_SIZE: usize = 500;
const COUNTRIES: &[&str] = &["au", "nz", "gb", "us"];

#[derive(Debug)]
struct BurstSms {
    apikey: Secret,
    secret: Secret,
    country: String,
    source: String,
    batch: bool,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut source = u.host();
    let mut targets = u.path_segments();
    let mut apikey = u.user().unwrap_or_default();
    let mut secret = u.password().unwrap_or_default();
    if let Some(v) = SERVICE.text(u, "key") {
        apikey = v;
    }
    if let Some(v) = SERVICE.text(u, "secret") {
        secret = v;
    }
    if let Some(v) = u.text("source").or_else(|| u.text("from")) {
        source = v;
    }
    let country = SERVICE.text(u, "country");
    let validity = SERVICE.text(u, "validity");
    let batch = SERVICE.flag(u, "batch");
    targets.extend(to_param(u));

    let apikey = validate_regex(&apikey, r"^[a-z0-9]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Burst SMS API Key was specified"))?;
    let secret = validate_regex(&secret, r"^[a-z0-9]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Burst SMS API Secret was specified"))?;
    let country = match country {
        None => "us".to_string(),
        Some(c) => {
            let c = c.trim().to_lowercase();
            if !COUNTRIES.contains(&c.as_str()) {
                return Err(SERVICE.err("an invalid Burst SMS country was specified"));
            }
            c
        }
    };
    if let Some(v) = validity
        && parse_int(&v).is_none()
    {
        return Err(SERVICE.err("the Burst SMS Validity specified is invalid"));
    }
    let source = validate_nonblank(&source).ok_or_else(|| SERVICE.err("the Account Sender ID specified is invalid"))?;
    Ok(Box::new(BurstSms {
        apikey: Secret::new(apikey),
        secret: Secret::new(secret),
        country,
        source,
        batch,
        targets: full_numbers(&targets),
    }))
}

impl Notify for BurstSms {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return no_targets("Burst SMS");
        }
        let size = if self.batch { BATCH_SIZE } else { 1 };
        let chunks: Vec<String> = self.targets.chunks(size).map(|c| c.join(",")).collect();
        per_target(chunks, String::clone, |to| {
            let form = [
                ("countrycode", self.country.as_str()),
                ("message", msg.body),
                ("from", self.source.as_str()),
                ("to", to.as_str()),
            ];
            let req = ctx
                .post("https://api.transmitsms.com/send-sms.json")
                .header("Accept", "application/json")
                .basic_auth(self.apikey.expose(), Some(self.secret.expose()))
                .form(&form);
            Plan::send_check(req, |r| expect(r, &[200]))
        })
    }

}
