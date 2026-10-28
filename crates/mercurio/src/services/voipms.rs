//! VoIP.ms (`voipms://`): SMS through the VoIP.ms API.

use std::sync::Arc;

use serde_json::Value;

use super::_telephony::{http_err, param_unquoted, unquote_or_empty};
use crate::error::Error;
use crate::http::Request;
use crate::parse::{is_email, is_phone_no, parse_phone_no, parse_phone_no_unquoted};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "voipms",
    name: "VoIPms",
    schemes: &["voipms"],
    service_url: "https://voip.ms",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    templates: &[
        "{schema}://{password}:{email}/{from_phone}/{targets}",
    ],
    tokens: &[
        Param::new("email", "User Email").email().required(),
        Param::new("from_phone", "From Phone No").required().pattern(r"^\+?[0-9\s)(+-]+$"),
        Param::new("password", "Password").required().secret(),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").required().group(&["target_phone"]),
    ],
    params: &[
        Param::sets("from", &["from_phone"]),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://voip.ms/api/v1/rest.php";
const COUNTRY_CODE: &str = "1";

#[derive(Debug)]
struct Voipms {
    email: String,
    password: Secret,
    source: String,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let source = match param_unquoted(u, "from") {
        Some(f) => Some(f),
        None if !targets.is_empty() => Some(targets.remove(0)),
        None => None,
    };
    // The URL is `{password}:{email user}@{email domain}`.
    let password = u.user();
    let email = format!("{}@{}", unquote_or_empty(u.password.as_deref()), u.host());
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_phone_no_unquoted([to], false));
    }

    let password = password.ok_or_else(|| SERVICE.err("password has to be specified"))?;
    let email = is_email(&email).ok_or_else(|| SERVICE.err("an invalid VoIPms user email was specified"))?.full_email;
    let src = source
        .as_deref()
        .and_then(|s| is_phone_no(s, 10))
        .ok_or_else(|| SERVICE.err("an invalid VoIPms source phone # was specified"))?;
    if !src.country.is_empty() && src.country != COUNTRY_CODE {
        return Err(SERVICE.err("VoIPms only supports +1 country code"));
    }
    let source = format!("{}{}", src.area, src.line);
    let mut out = Vec::new();
    if targets.is_empty() {
        out.push(source.clone());
    } else {
        for t in parse_phone_no(&targets, true, false) {
            let Some(r) = is_phone_no(&t, 10) else {
                crate::warning!("VoIPms: dropped invalid phone number {t:?}");
                continue;
            };
            if !r.country.is_empty() && r.country != COUNTRY_CODE {
                continue;
            }
            out.push(format!("{}{}", r.area, r.line));
        }
    }
    Ok(Box::new(Voipms { email, password: Secret::new(password), source, targets: out }))
}

struct Ctx {
    email: String,
    password: Secret,
    source: String,
    body: String,
    user_agent: String,
}

/// One target, then the rest. A `null` reply counts as success.
fn send_from(ctx: Arc<Ctx>, targets: Arc<Vec<String>>, i: usize) -> Plan {
    let Some(target) = targets.get(i).cloned() else { return Plan::Done };
    let payload = [
        ("api_username", ctx.email.as_str()),
        ("api_password", ctx.password.expose()),
        ("did", ctx.source.as_str()),
        ("message", ctx.body.as_str()),
        ("method", "sendSMS"),
        ("dst", target.as_str()),
    ];
    let req = Request::get(NOTIFY_URL)
        .header("User-Agent", ctx.user_agent.as_str())
        .header("Content-Type", "application/x-www-form-urlencoded")
        .query(&payload);
    let label = target.clone();
    Plan::http(req, move |res| {
        let next = || send_from(ctx.clone(), targets.clone(), i + 1);
        let outcome = match res {
            Err(e) => Err(e),
            Ok(r) => {
                let response = r.json();
                if r.status != 200 {
                    Err(http_err(&r))
                } else {
                    match response {
                        None => Err(Error::Service("VoIPms returned an unreadable response".into())),
                        Some(Value::Null) => Ok(()),
                        Some(Value::Object(m)) => match m.get("status") {
                            Some(s) if s.as_str() == Some("success") => Ok(()),
                            Some(s) => Err(Error::Service(format!(
                                "VoIPms error: {s}: {}",
                                m.get("message").unwrap_or(&Value::Null)
                            ))),
                            None => Err(Error::Service("VoIPms response has no status".into())),
                        },
                        Some(_) => Err(Error::Service("VoIPms response is not an object".into())),
                    }
                }
            }
        };
        Plan::all([Plan::from_result(outcome).target(label), next()])
    })
}

impl Notify for Voipms {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(SERVICE.err("there are no valid VoIPms targets to notify"));
        }
        let c = Arc::new(Ctx {
            email: self.email.clone(),
            password: self.password.clone(),
            source: self.source.clone(),
            body: msg.body.to_owned(),
            user_agent: ctx.app_id().to_owned(),
        });
        send_from(c, Arc::new(self.targets.clone()), 0)
    }

}
