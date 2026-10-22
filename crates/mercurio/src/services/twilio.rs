//! Twilio SMS / WhatsApp / voice calls (`twilio://`): messages and calls through the Twilio API.

use std::time::Duration;

use super::_sms::{expect, no_targets, per_target};
use crate::parse::{is_phone_no, parse_phone_no, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::util::xml_escape;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "twilio",
    name: "Twilio",
    schemes: &["twilio"],
    service_url: "https://www.twilio.com/",
    parse,
    limits: SMS_LIMITS,
    throttle: Duration::from_millis(200),
    templates: &[
        "{schema}://{account_sid}:{auth_token}@{from_phone}",
        "{schema}://{account_sid}:{auth_token}@{from_phone}/{targets}",
    ],
    tokens: &[
        Param::new("account_sid", "Account SID").required().secret().pattern("^AC[a-f0-9]+$"),
        Param::new("auth_token", "Auth Token").required().secret().pattern("^[a-z0-9]+$"),
        Param::new("from_phone", "From Phone No").required().pattern(r"^([a-z]+:)?\+?[0-9\s)(+-]+$"),
        Param::new("short_code", "Target Short Code").pattern("^[0-9]{5,6}$"),
        Param::new("target_phone", "Target Phone No").pattern(r"^([a-z]+:)?[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").group(&["short_code", "target_phone"]),
    ],
    params: &[
        Param::new("apikey", "API Key").secret().pattern("^SK[a-f0-9]+$"),
        Param::sets("from", &["from_phone"]).aliases(&["source"]),
        Param::new("method", "Notification Method: sms or call").choice(&["sms", "call"]).default("sms"),
        Param::sets("sid", &["account_sid"]),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["auth_token"]),
    ],
    ..ServiceDef::DEFAULTS
};

const SMS_LIMITS: Limits = Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 };
const CALL_LIMITS: Limits = Limits { title_maxlen: 250, body_maxlen: 4000, body_max_line_count: 0 };

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Sms,
    Call,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Text,
    WhatsApp,
}

#[derive(Debug)]
struct Twilio {
    account_sid: Secret,
    auth_token: Secret,
    apikey: Option<Secret>,
    method: Method,
    default_mode: Mode,
    source: String,
    targets: Vec<(Mode, String)>,
}

/// `MODE_DETECT_RE.match(s)` -> `(mode, phoneno)`.
fn mode_detect(s: &str) -> Option<(Option<String>, String)> {
    let re = crate::regex!(r"(?i)^\s*(?:([^:]+)\s*:\s*)?(.+)\n?\z");
    let caps = re.captures(s)?;
    Some((caps.get(1).map(|m| m.as_str().to_string()), caps[2].to_string()))
}

fn is_whatsapp(mode: Option<&str>) -> bool {
    mode.and_then(|m| m.chars().next()).is_some_and(|c| c.to_lowercase().eq(['w']))
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let mut source = u.host();
    let mut sid = u.user().unwrap_or_default();
    let mut token = u.password().unwrap_or_default();
    if let Some(v) = SERVICE.text(u, "token") {
        token = v;
    }
    if let Some(v) = SERVICE.text(u, "sid") {
        sid = v;
    }
    let apikey = u.param_nonempty("apikey").map(str::to_string);
    if let Some(v) = u.text("source").or_else(|| u.text("from")) {
        source = v;
    }
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(crate::parse::parse_phone_no_unquoted([to], true));
    }
    let method = SERVICE.text_or_default(u, "method");

    let account_sid = validate_regex(&sid, r"^AC[a-f0-9]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Twilio Account SID was specified"))?;
    let auth_token = validate_regex(&token, r"^[a-z0-9]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Twilio Authentication Token was specified"))?;
    let apikey = apikey.and_then(|k| validate_regex(&k, r"^SK[a-f0-9]+$", "i", true));

    let method = {
        let m = method.to_lowercase();
        [("sms", Method::Sms), ("call", Method::Call)]
            .into_iter()
            .find(|(name, _)| name.starts_with(&m))
            .map(|(_, v)| v)
            .ok_or_else(|| SERVICE.err("the Twilio notification method specified is invalid"))?
    };

    let invalid_source = || SERVICE.err("the Account (From) Phone # or Short-code specified is invalid");
    let (mode, phoneno) = mode_detect(&source).ok_or_else(invalid_source)?;
    let default_mode = if is_whatsapp(mode.as_deref()) { Mode::WhatsApp } else { Mode::Text };
    if method == Method::Call && default_mode == Mode::WhatsApp {
        return Err(SERVICE.err("the notification method Call is not valid along message mode Whatsapp"));
    }
    let mut source = is_phone_no(&phoneno, 5).ok_or_else(invalid_source)?.full;
    if source.len() < 11 || source.len() > 14 {
        if source.len() != 5 && source.len() != 6 {
            return Err(SERVICE.err("the Account (From) Phone # specified is invalid"));
        }
    } else {
        source = format!("+{source}");
    }
    let short = matches!(source.len(), 5 | 6);

    let mut out = Vec::new();
    for entry in parse_phone_no(&targets, true, true) {
        let (m, phoneno) = mode_detect(&entry).ok_or_else(|| SERVICE.err("an invalid target was specified"))?;
        let mode = if is_whatsapp(m.as_deref()) { Mode::WhatsApp } else { default_mode };
        let Some(p) = is_phone_no(&phoneno, 10) else { continue };
        if (short || method == Method::Call) && mode == Mode::WhatsApp {
            continue;
        }
        out.push((mode, format!("+{}", p.full)));
    }

    Ok(Box::new(Twilio {
        account_sid: Secret::new(account_sid),
        auth_token: Secret::new(auth_token),
        apikey: apikey.map(Secret::new),
        method,
        default_mode,
        source,
        targets: out,
    }))
}

impl Notify for Twilio {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let short = matches!(self.source.len(), 5 | 6);
        if self.targets.is_empty() && short {
            return no_targets("Twilio");
        }
        let sid = self.account_sid.expose();
        let (url, first) = match self.method {
            Method::Sms => {
                (format!("https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"), ("Body", msg.body.to_string()))
            }
            Method::Call => {
                let twiml = if msg.body.trim_start().starts_with('<') {
                    msg.body.to_string()
                } else {
                    let says: String = [msg.title, msg.body]
                        .iter()
                        .filter(|t| !t.is_empty())
                        .map(|t| format!("<Say>{}</Say>", xml_escape(t)))
                        .collect();
                    format!("<Response>{says}</Response>")
                };
                (format!("https://api.twilio.com/2010-04-01/Accounts/{sid}/Calls.json"), ("Twiml", twiml))
            }
        };
        let mut targets = self.targets.clone();
        if targets.is_empty() && self.method != Method::Call {
            targets.push((self.default_mode, self.source.clone()));
        }
        let user = self.apikey.as_ref().unwrap_or(&self.account_sid).expose().to_string();
        per_target(
            targets,
            |(_, t)| t.clone(),
            |(mode, target)| {
                let (from, to) = match mode {
                    Mode::Text => (self.source.clone(), target.clone()),
                    Mode::WhatsApp => (format!("whatsapp:{}", self.source), format!("whatsapp:{target}")),
                };
                let form = [(first.0, first.1.clone()), ("From", from), ("To", to)];
                let req = ctx.post(&url)
                    .header("Accept", "application/json")
                    .basic_auth(&user, Some(self.auth_token.expose()))
                    .form(&form);
                Plan::send_check(req, |r| expect(r, &[201, 200]))
            },
        )
    }

    fn limits(&self, _title: &str, _body: &str, _format: crate::NotifyFormat, _ctx: &Context<'_>) -> Option<Limits> {
        Some(match self.method {
            Method::Sms => SMS_LIMITS,
            Method::Call => CALL_LIMITS,
        })
    }

}
