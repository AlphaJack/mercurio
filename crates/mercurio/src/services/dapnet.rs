//! DAPNET (`dapnet://`): pager calls to amateur radio call signs through the DAPNET (hampager.de) API.

use serde_json::json;

use super::_telephony::param_unquoted;
use crate::parse::{is_call_sign, parse_call_sign, parse_list};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "dapnet",
    name: "Dapnet",
    schemes: &["dapnet"],
    service_url: "https://hampager.de/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 80, body_max_line_count: 0 },
    templates: &[
        "{schema}://{user}:{password}@{targets}",
    ],
    tokens: &[
        Param::new("password", "Password").required().secret(),
        Param::new("target_callsign", "Target Callsign").pattern("^[a-z0-9]{2,5}(-[a-z0-9]{1,2})?$"),
        Param::new("targets", "Targets").list("/").required().group(&["target_callsign"]),
        Param::new("user", "User Name").required(),
    ],
    params: &[
        Param::new("batch", "Batch Mode").bool(false),
        Param::new("priority", "Priority").choice(&["0", "1"]).default("0"),
        Param::new("to", "Target Callsign"),
        Param::new("txgroups", "Transmitter Groups").default("dl-all").secret(),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "http://www.hampager.de:8080/calls";
const BATCH_SIZE: usize = 50;
/// Prefix -> emergency flag, in lookup order.
const PRIORITY_MAP: &[(&str, bool)] = &[("n", false), ("e", true), ("0", false), ("1", true)];

#[derive(Debug)]
struct Dapnet {
    user: String,
    password: Secret,
    emergency: bool,
    txgroups: Vec<String>,
    batch: bool,
    targets: Vec<String>,
}

/// `parse_list`, then unquote each entry (empty entries dropped).
fn parse_list_unquoted(v: &str) -> Vec<String> {
    parse_list([v]).into_iter().map(|x| unquote(&x)).filter(|x| !x.is_empty()).collect()
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = vec![u.host()];
    targets.extend(u.path_segments());
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list_unquoted(to));
    }
    let priority = param_unquoted(u, "priority");
    let txgroups: Option<Vec<String>> =
        SERVICE.raw(u, "txgroups").map(|t| parse_list_unquoted(t).into_iter().map(|x| x.to_lowercase()).collect());
    let batch = SERVICE.flag(u, "batch");

    let emergency = priority
        .map(|p| {
            let p = p.to_lowercase();
            PRIORITY_MAP.iter().find(|(k, _)| p.starts_with(k)).map(|(_, v)| *v).unwrap_or(false)
        })
        .unwrap_or(false);
    let user = u.user().unwrap_or_default();
    let password = u.password().unwrap_or_default();
    if user.is_empty() || password.is_empty() {
        return Err(SERVICE.err("a Dapnet user/pass was not provided"));
    }
    let txgroups = match txgroups.filter(|t| !t.is_empty()) {
        Some(t) => parse_list(&t),
        None => vec![SERVICE.default_of("txgroups").to_string()],
    };
    let mut out: Vec<String> = Vec::new();
    for t in parse_call_sign(&targets, true) {
        if let Some(c) = is_call_sign(&t)
            && !out.contains(&c.callsign)
        {
            out.push(c.callsign);
        }
    }
    Ok(Box::new(Dapnet { user, password: Secret::new(password), emergency, txgroups, batch, targets: out }))
}

impl Notify for Dapnet {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(SERVICE.err("there are no valid Dapnet targets to notify"));
        }
        let size = if self.batch { BATCH_SIZE } else { 1 };
        Plan::all(self.targets.chunks(size).map(|chunk| {
            let payload = json!({
                "text": msg.body,
                "callSignNames": chunk,
                "transmitterGroupNames": self.txgroups,
                "emergency": self.emergency,
            });
            let req = ctx.post(NOTIFY_URL)
                .header("Content-Type", "application/json; charset=utf-8")
                .basic_auth(&self.user, Some(self.password.expose()))
                .json(&payload);
            Plan::send_expect(req, &[201]).target(chunk.join(","))
        }))
    }

}
