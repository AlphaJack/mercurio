//! Prowl (`prowl://`): push notifications through Prowl.

use crate::parse::validate_regex;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "prowl",
    name: "Prowl",
    schemes: &["prowl"],
    service_url: "https://www.prowlapp.com/",
    parse,
    limits: Limits { title_maxlen: 1024, body_maxlen: 10000, body_max_line_count: 0 },
    templates: &[
        "{schema}://{apikey}",
        "{schema}://{apikey}/{providerkey}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret().pattern("^[A-Za-z0-9]{40}$"),
        Param::new("providerkey", "Provider Key").secret().pattern("^[A-Za-z0-9]{40}$"),
    ],
    params: &[
        Param::new("priority", "Priority").choice(&["-2", "-1", "0", "1", "2"]).default("0"),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.prowlapp.com/publicapi/add";
const KEY_RE: &str = r"^[A-Za-z0-9]{40}$";

/// Prefix -> priority, in match order.
const PRIORITY_MAP: &[(&str, i64)] =
    &[("l", -2), ("m", -1), ("n", 0), ("h", 1), ("e", 2), ("-2", -2), ("-1", -1), ("0", 0), ("1", 1), ("2", 2)];

#[derive(Debug)]
struct Prowl {
    apikey: Secret,
    providerkey: Option<Secret>,
    priority: i64,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let apikey = u.host();
    let providerkey = u.path_segments().into_iter().next();
    let priority = {
        let p = SERVICE.text_or_default(u, "priority").to_lowercase();
        PRIORITY_MAP.iter().find(|(k, _)| p.starts_with(k)).map(|(_, v)| *v).unwrap_or(0)
    };
    let apikey = validate_regex(&apikey, KEY_RE, "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Prowl API Key was specified"))?;
    let providerkey = match providerkey.filter(|p| !p.is_empty()) {
        None => None,
        Some(p) => Some(Secret::new(
            validate_regex(&p, KEY_RE, "i", true)
                .ok_or_else(|| SERVICE.err("an invalid Prowl Provider Key was specified"))?,
        )),
    };
    Ok(Box::new(Prowl { apikey: Secret::new(apikey), providerkey, priority }))
}

impl Notify for Prowl {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut payload: Vec<(&str, String)> = vec![
            ("apikey", self.apikey.expose().to_string()),
            ("application", ctx.app_id().to_string()),
            ("event", msg.title.to_string()),
            ("description", msg.body.to_string()),
            ("priority", self.priority.to_string()),
        ];
        if let Some(pk) = &self.providerkey {
            payload.push(("providerkey", pk.expose().to_string()));
        }
        let req = ctx.post(NOTIFY_URL)
            .header("Content-type", "application/x-www-form-urlencoded")
            .form(&payload);
        Plan::send_expect(req, &[200])
    }
}
