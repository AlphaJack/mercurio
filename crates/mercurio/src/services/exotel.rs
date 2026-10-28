//! Exotel (`exotel://`): SMS through the Exotel API.

use super::_telephony::{phone_entries, param_unquoted, unquote_or_empty};
use crate::parse::{is_phone_no, parse_phone_no_unquoted, validate_nonblank};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "exotel",
    name: "Exotel",
    schemes: &["exotel"],
    service_url: "https://exotel.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 2000, body_max_line_count: 0 },
    templates: &[
        "{schema}://{sid}:{token}@{from_phone}",
        "{schema}://{sid}:{token}@{from_phone}/{targets}",
    ],
    tokens: &[
        Param::new("from_phone", "From Phone No / Sender ID").required().pattern(r"^(?:(?=.{3,16}$)(?=.*[A-Z.-])[A-Z0-9][A-Z0-9.-]*|[0-9]{6}|\+?[0-9\s)(+-]{9,})$"),
        Param::new("sid", "Account SID").required().secret(),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").group(&["target_phone"]),
        Param::new("token", "Token").required().secret(),
    ],
    params: &[
        Param::new("apikey", "API Key").secret().aliases(&["key"]),
        Param::new("batch", "Batch Mode").bool(false),
        Param::sets("from", &["from_phone"]),
        Param::new("priority", "Priority").choice(&["normal", "high"]).default("normal"),
        Param::new("region", "Region Name").choice(&["us", "in"]).default("us"),
        Param::sets("sid", &["sid"]),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
        Param::new("unicode", "Unicode Characters").bool(true),
    ],
    ..ServiceDef::DEFAULTS
};

const BATCH_SIZE: usize = 100;
/// Prefix -> priority, in lookup order.
const PRIORITY_MAP: &[(&str, &str)] = &[("normal", "normal"), ("+", "high"), ("high", "high")];

#[derive(Debug)]
struct Exotel {
    sid: Secret,
    token: Secret,
    apikey: Secret,
    region: &'static str,
    unicode: bool,
    batch: bool,
    priority: &'static str,
    source: String,
    targets: Vec<String>,
}

/// Validate the sender: a phone number or an alphanumeric sender id.
fn parse_source(source: &str) -> Option<String> {
    let source = validate_nonblank(source)?;
    if let Some(p) = is_phone_no(&source, 9) {
        return Some(p.full);
    }
    let is_digit = source.chars().all(|c| c.is_numeric());
    if crate::regex!(r"(?i)^[A-Z0-9][A-Z0-9.-]{2,15}$").is_match(&source) && (!is_digit || source.chars().count() == 6)
    {
        return Some(source);
    }
    None
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let mut source = u.host();
    let mut sid = unquote_or_empty(u.user.as_deref());
    let mut token = unquote_or_empty(u.password.as_deref());
    let region = SERVICE.text_or_default(u, "region");
    if let Some(t) = SERVICE.text(u, "token") {
        token = t;
    }
    if let Some(s) = SERVICE.text(u, "sid") {
        sid = s;
    }
    let apikey = param_unquoted(u, "apikey").or_else(|| param_unquoted(u, "key"));
    if let Some(s) = SERVICE.text(u, "from") {
        source = s;
    }
    if let Some(s) = param_unquoted(u, "source") {
        source = s;
    }
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_phone_no_unquoted([to], false));
    }
    let priority = SERVICE.text_or_default(u, "priority").to_lowercase();
    let batch = SERVICE.flag(u, "batch");
    let unicode = SERVICE.flag(u, "unicode");

    let sid_v = validate_nonblank(&sid).ok_or_else(|| SERVICE.err("an invalid Exotel SID was specified"))?;
    let token = validate_nonblank(&token).ok_or_else(|| SERVICE.err("an invalid Exotel API Token was specified"))?;
    let apikey = validate_nonblank(apikey.as_deref().filter(|k| !k.is_empty()).unwrap_or(&sid))
        .ok_or_else(|| SERVICE.err("an invalid Exotel API Key was specified"))?;
    let region = match validate_nonblank(&region).map(|r| r.to_lowercase()).as_deref() {
        Some("us") => "us",
        Some("in") => "in",
        _ => return Err(SERVICE.err("the Exotel region specified is invalid")),
    };
    let p = priority.trim();
    let found = if p.is_empty() { None } else { PRIORITY_MAP.iter().find(|(k, _)| k.starts_with(p)) };
    let priority = found.map(|(_, v)| *v).ok_or_else(|| SERVICE.err("an invalid Exotel priority was specified"))?;
    let source = parse_source(&source)
        .ok_or_else(|| SERVICE.err("the Account (From) Phone # / Sender ID specified is invalid"))?;
    let mut has_invalid = false;
    let mut out = Vec::new();
    for (_, r) in phone_entries(&targets, 9) {
        match r {
            Some(p) => out.push(p.full),
            None => has_invalid = true,
        }
    }
    if out.is_empty() && !has_invalid {
        out.push(source.clone());
    }
    Ok(Box::new(Exotel {
        sid: Secret::new(sid_v),
        token: Secret::new(token),
        apikey: Secret::new(apikey),
        region,
        unicode,
        batch,
        priority,
        source,
        targets: out,
    }))
}

impl Notify for Exotel {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(SERVICE.err("there are no valid Exotel targets to notify"));
        }
        let host = if self.region == "in" { "api.in.exotel.com" } else { "api.exotel.com" };
        let url = format!("https://{host}/v1/Accounts/{}/Sms/send", self.sid.expose());
        let size = if self.batch { BATCH_SIZE } else { 1 };
        Plan::all(self.targets.chunks(size).map(|chunk| {
            let mut payload: Vec<(&str, &str)> = vec![
                ("From", &self.source),
                ("Body", msg.body),
                ("EncodingType", if self.unicode { "unicode" } else { "plain" }),
                ("Priority", self.priority),
            ];
            payload.extend(chunk.iter().map(|t| ("To", t.as_str())));
            let req = ctx.post(&url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .basic_auth(self.apikey.expose(), Some(self.token.expose()))
                .form(&payload);
            let label = if self.batch { format!("{} targets", chunk.len()) } else { chunk[0].clone() };
            Plan::send_expect(req, &[200]).target(label)
        }))
    }

}
