//! Vonage, formerly Nexmo (`vonage://`, `nexmo://`): SMS through the Vonage API.

use super::_sms::{expect, full_numbers, per_target, to_param};
use crate::parse::{is_phone_no, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::util::parse_int;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "vonage",
    name: "Vonage",
    schemes: &["vonage", "nexmo"],
    service_url: "https://dashboard.nexmo.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    templates: &[
        "{schema}://{apikey}:{secret}@{from_phone}",
        "{schema}://{apikey}:{secret}@{from_phone}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret().pattern("^[a-z0-9]+$"),
        Param::new("from_phone", "From Phone No").required().pattern(r"^\+?[0-9\s)(+-]+$"),
        Param::new("secret", "API Secret").required().secret().pattern("^[a-z0-9]+$"),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").group(&["target_phone"]),
    ],
    params: &[
        Param::sets("from", &["from_phone"]).aliases(&["source"]),
        Param::sets("key", &["apikey"]),
        Param::sets("secret", &["secret"]),
        Param::sets("to", &["targets"]),
        Param::new("ttl", "ttl").int().default("900000").range(20000, 604800000),
    ],
    ..ServiceDef::DEFAULTS
};

const TTL_MIN: i64 = 20_000;
const TTL_MAX: i64 = 604_800_000;

#[derive(Debug)]
struct Vonage {
    apikey: Secret,
    secret: Secret,
    ttl: i64,
    source: String,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let mut source = u.host();
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
    let ttl = SERVICE.text(u, "ttl");
    targets.extend(to_param(u));

    let apikey = validate_regex(&apikey, r"^[a-z0-9]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Vonage API Key was specified"))?;
    let secret = validate_regex(&secret, r"^[a-z0-9]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Vonage API Secret was specified"))?;
    let ttl = ttl.and_then(|t| parse_int(&t)).or_else(|| parse_int(SERVICE.default_of("ttl"))).unwrap_or(0);
    if !(TTL_MIN..=TTL_MAX).contains(&ttl) {
        return Err(SERVICE.err("the Vonage TTL specified is out of range"));
    }
    let source =
        is_phone_no(&source, 10).ok_or_else(|| SERVICE.err("the Account (From) Phone # specified is invalid"))?.full;
    let targets = full_numbers(&targets);
    Ok(Box::new(Vonage { apikey: Secret::new(apikey), secret: Secret::new(secret), ttl, source, targets }))
}

impl Notify for Vonage {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut targets = self.targets.clone();
        if targets.is_empty() {
            targets.push(self.source.clone());
        }
        let ttl = self.ttl.to_string();
        per_target(targets, String::clone, |target| {
            let form = [
                ("api_key", self.apikey.expose()),
                ("api_secret", self.secret.expose()),
                ("ttl", ttl.as_str()),
                ("from", self.source.as_str()),
                ("text", msg.body),
                ("to", target.as_str()),
            ];
            let req = ctx
                .post("https://rest.nexmo.com/sms/json")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .form(&form);
            Plan::send_check(req, |r| expect(r, &[200]))
        })
    }

}
