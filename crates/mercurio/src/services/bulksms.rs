//! BulkSMS (`bulksms://`): SMS through the BulkSMS API.

use serde_json::{Value, json};

use super::_sms::{expect, per_target, to_param};
use crate::parse::{is_phone_no, parse_phone_no};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Error, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "bulksms",
    name: "BulkSMS",
    schemes: &["bulksms"],
    service_url: "https://bulksms.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    templates: &[
        "{schema}://{token_id}:{token_secret}@{targets}",
    ],
    tokens: &[
        Param::new("target_group", "Target Group").pattern("^[A-Z0-9 _-]+$").prefix("@"),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").required().group(&["target_group", "target_phone"]),
        Param::new("token_id", "Token").required(),
        Param::new("token_secret", "Secret").required().secret(),
    ],
    params: &[
        Param::new("batch", "Batch Mode").bool(false),
        Param::new("from", "From Phone No").pattern(r"^\+?[0-9\s)(+-]+$"),
        Param::new("route", "Route Group").choice(&["ECONOMY", "STANDARD", "PREMIUM"]).default("STANDARD"),
        Param::sets("to", &["targets"]),
        Param::new("unicode", "Unicode Characters").bool(true),
    ],
    ..ServiceDef::DEFAULTS
};

const BATCH_SIZE: usize = 4000;
const ROUTES: &[&str] = &["ECONOMY", "STANDARD", "PREMIUM"];

#[derive(Debug)]
struct BulkSms {
    user: Option<String>,
    password: Option<Secret>,
    source: Option<String>,
    route: String,
    unicode: bool,
    batch: bool,
    targets: Vec<String>,
    groups: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = vec![u.host()];
    targets.extend(u.path_segments());
    let source = SERVICE.text(u, "from");
    targets.extend(to_param(u));
    let unicode = SERVICE.flag_strict(u, "unicode");
    let batch = SERVICE.flag_strict(u, "batch");
    let route = SERVICE.text(u, "route");

    let source = match source {
        Some(s) => Some(format!(
            "+{}",
            is_phone_no(&s, 10).ok_or_else(|| SERVICE.err("the Account (From) Phone # specified is invalid"))?.full
        )),
        None => None,
    };
    let route = route.map(|r| r.to_uppercase()).unwrap_or_else(|| "STANDARD".into());
    if !ROUTES.contains(&route.as_str()) {
        return Err(SERVICE.err("the route specified is invalid"));
    }
    let group_re = crate::regex!(r"(?i)^@?([A-Z0-9_-]+)\n?\z");
    let mut phones = Vec::new();
    let mut groups = Vec::new();
    for target in parse_phone_no(&targets, true, false) {
        if let Some(p) = is_phone_no(&target, 10) {
            phones.push(format!("+{}", p.full));
            continue;
        }
        if let Some(c) = group_re.captures(&target)
            && !is_digits(&target)
        {
            groups.push(c[1].to_string());
        }
    }
    Ok(Box::new(BulkSms {
        user: u.user().filter(|s| !s.is_empty()),
        password: u.password().filter(|s| !s.is_empty()).map(Secret::new),
        source,
        route,
        unicode,
        batch,
        targets: phones,
        groups,
    }))
}

/// `true` for a non-empty all-digit string.
fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

impl Notify for BulkSms {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let (Some(user), Some(password)) = (&self.user, &self.password) else {
            return Plan::Fail(Error::Message("there were no valid login credentials provided".into()));
        };
        if self.targets.is_empty() && self.groups.is_empty() {
            return Plan::Fail(Error::Message("there are no BulkSMS targets to notify".into()));
        }
        let mut items: Vec<(String, Value)> = if self.batch {
            self.targets.chunks(BATCH_SIZE).map(|c| (format!("{} targets", c.len()), json!(c))).collect()
        } else {
            self.targets.iter().map(|t| (t.clone(), json!(t))).collect()
        };
        items.extend(self.groups.iter().map(|g| (g.clone(), json!({"type": "GROUP", "name": g}))));
        per_target(
            items,
            |(label, _)| label.clone(),
            |(_, to)| {
                let mut payload = json!({
                    "to": to,
                    "body": crate::http::TEXT,
                    "routingGroup": self.route,
                    "encoding": if self.unicode { "UNICODE" } else { "TEXT" },
                    "deliveryReports": "ERRORS",
                });
                if let Some(s) = &self.source {
                    payload["from"] = json!(s);
                }
                let req = ctx
                    .post("https://api.bulksms.com/v1/messages")
                    .basic_auth(user, Some(password.expose()))
                    .json_text(&payload, msg.body);
                Plan::send_check(req, |r| expect(r, &[201, 200]))
            },
        )
    }

}
