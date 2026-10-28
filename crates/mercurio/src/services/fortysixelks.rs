//! 46elks (`46elks://`, `elks://`): SMS through the 46elks API.

use super::_sms::{expect, no_targets, per_target, to_param};
use crate::parse::{is_phone_no, parse_phone_no};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "fortysixelks",
    name: "46elks",
    schemes: &["46elks", "elks"],
    service_url: "https://46elks.com",
    parse,
    parse_native: Some(parse_native),
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    templates: &[
        "{schema}://{user}:{password}@{from_phone}",
        "{schema}://{user}:{password}@{from_phone}/{targets}",
    ],
    tokens: &[
        Param::new("from_phone", "From Phone No").required(),
        Param::new("password", "API Password").required().secret(),
        Param::new("target_phone", "Target Phone"),
        Param::new("targets", "Targets").list("/").group(&["target_phone"]),
        Param::new("user", "API Username").required(),
    ],
    params: &[
        Param::sets("from", &["from_phone"]),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct FortySixElks {
    user: String,
    password: Secret,
    source: Option<String>,
    targets: Vec<String>,
}

/// `https://user:pass@api.46elks.com/a1/sms?...` -> `46elks://user:pass@/?...`.
fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(r"(?i)^https?://([^@]+)@api\.46elks\.com/a1/sms/?(\?.+)\n?\z");
    let c = re.captures(url)?;
    Some(format!("46elks://{}@/{}", &c[1], &c[2]))
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut source = SERVICE.text(u, "from");
    if source.is_none() && !u.host.is_empty() {
        source = Some(u.host());
    }
    let mut targets = u.path_segments();
    targets.extend(to_param(u));

    let source = source.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
    let password = u.password().unwrap_or_default();
    let user = u.user().unwrap_or_default();
    if password.is_empty() {
        return Err(SERVICE.err("no 46elks password was specified"));
    }
    if user.is_empty() {
        return Err(SERVICE.err("no 46elks user was specified"));
    }
    if targets.is_empty()
        && let Some(s) = source.as_deref()
        && is_phone_no(s, 10).is_some()
    {
        targets = vec![s.to_owned()];
    }
    let targets = parse_phone_no(&targets, true, false)
        .into_iter()
        .filter_map(|t| {
            let p = is_phone_no(&t, 10)?;
            Some(if t.trim_start().starts_with('+') { format!("+{}", p.full) } else { p.full })
        })
        .collect();
    Ok(Box::new(FortySixElks { user, password: Secret::new(password), source, targets }))
}

impl Notify for FortySixElks {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return no_targets("46elks");
        }
        per_target(self.targets.clone(), String::clone, |target| {
            let mut form = vec![("to", target.as_str())];
            if let Some(s) = &self.source {
                form.push(("from", s.as_str()));
            }
            form.push(("message", msg.body));
            let req = ctx.post("https://api.46elks.com/a1/sms")
                .basic_auth(&self.user, Some(self.password.expose()))
                .form(&form);
            Plan::send_check(req, |r| expect(r, &[200]))
        })
    }

}
