//! Octopush SMS (`octopush://`): SMS through the Octopush API.

use serde_json::{Value, json};

use super::_sms::{expect, full_numbers, no_targets, per_target, to_param};
use crate::parse::{is_email, validate_nonblank};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "octopush",
    name: "Octopush",
    schemes: &["octopush"],
    service_url: "https://octopush.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 1224, body_max_line_count: 0 },
    templates: &[
        "{schema}://{api_login}/{api_key}/{targets}",
        "{schema}://{sender}:{api_login}/{api_key}/{targets}",
    ],
    tokens: &[
        Param::new("api_key", "API Key").required().secret(),
        Param::new("api_login", "API Login").email().required().secret(),
        Param::new("sender", "Sender"),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").group(&["target_phone"]),
    ],
    params: &[
        Param::new("batch", "Batch Mode").bool(false),
        Param::sets("key", &["api_key"]),
        Param::sets("login", &["api_login"]),
        Param::new("purpose", "Purpose").choice(&["alert", "wholesale"]).default("alert"),
        Param::new("replies", "Accept Replies").bool(false),
        Param::sets("to", &["targets"]),
        Param::new("type", "Type").choice(&["sms_premium", "sms_low_cost"]).default("sms_premium"),
    ],
    ..ServiceDef::DEFAULTS
};

const BATCH_SIZE: usize = 500;
const TYPE_MAP: &[(&str, &str)] = &[
    ("p", "sms_premium"),
    ("sms_p", "sms_premium"),
    ("smsp", "sms_premium"),
    ("+", "sms_premium"),
    ("l", "sms_low_cost"),
    ("sms_l", "sms_low_cost"),
    ("smsl", "sms_low_cost"),
    ("-", "sms_low_cost"),
];

#[derive(Debug)]
struct Octopush {
    api_login: Secret,
    api_key: Secret,
    batch: bool,
    replies: bool,
    mtype: &'static str,
    purpose: String,
    sender: Option<String>,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut tokens = u.path_segments();
    let api_key = match SERVICE.text(u, "key") {
        Some(k) => Some(k),
        None if !tokens.is_empty() => Some(unquote(&tokens.remove(0))),
        None => None,
    };
    let mut targets = tokens;
    targets.extend(to_param(u, false));
    let user = u.user.as_deref().filter(|s| !s.is_empty());
    let password = u.password.as_deref().filter(|s| !s.is_empty());
    let api_login = match SERVICE.text(u, "login") {
        Some(l) => Some(l),
        None if user.is_some() || password.is_some() => {
            let local = match password {
                Some(p) => unquote(p),
                None => unquote(user.unwrap_or_default()),
            };
            Some(format!("{local}@{}", u.host()))
        }
        None => None,
    };
    let batch = SERVICE.flag(u, "batch");
    let replies = SERVICE.flag(u, "replies");
    let mtype = SERVICE.text_or_default(u, "type");
    let purpose = SERVICE.text_or_default(u, "purpose");
    let sender = match u.text("sender") {
        Some(s) => Some(s),
        None => match (user, password) {
            (Some(us), Some(_)) => Some(unquote(us)),
            _ => None,
        },
    };

    let api_login = api_login
        .and_then(|l| validate_nonblank(&l))
        .filter(|l| is_email(l).is_some())
        .ok_or_else(|| SERVICE.err("an invalid Octopush API Login was specified"))?;
    let api_key = api_key
        .and_then(|k| validate_nonblank(&k))
        .ok_or_else(|| SERVICE.err("an invalid Octopush API Key was specified"))?;
    let mtype = mtype.to_lowercase().trim().to_string();
    let mtype = Some(&mtype)
        .filter(|m| !m.is_empty())
        .and_then(|m| TYPE_MAP.iter().find(|(k, _)| m.starts_with(k)).map(|(_, v)| *v))
        .ok_or_else(|| SERVICE.err("the Octopush type specified is invalid"))?;
    let purpose = validate_nonblank(&purpose)
        .ok_or_else(|| SERVICE.err("the Octopush purpose specified is invalid"))?
        .to_lowercase();
    if purpose != "alert" && purpose != "wholesale" {
        return Err(SERVICE.err("the Octopush purpose specified is invalid"));
    }
    let sender = match sender.filter(|s| !s.is_empty()) {
        Some(s) => Some(validate_nonblank(&s).ok_or_else(|| SERVICE.err("an invalid Octopush sender was specified"))?),
        None => None,
    };
    Ok(Box::new(Octopush {
        api_login: Secret::new(api_login),
        api_key: Secret::new(api_key),
        batch,
        replies,
        mtype,
        purpose,
        sender,
        targets: full_numbers(&targets, true),
    }))
}

impl Notify for Octopush {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return no_targets("Octopush");
        }
        let size = if self.batch { BATCH_SIZE } else { 1 };
        let chunks: Vec<Vec<String>> = self.targets.chunks(size).map(<[String]>::to_vec).collect();
        let sender = self.sender.clone().unwrap_or_else(|| ctx.app_id().to_string());
        per_target(chunks, |c| c.join(", "), |chunk| {
            let recipients: Vec<Value> = chunk.iter().map(|p| json!({"phone_number": p})).collect();
            let payload = json!({
                "recipients": recipients,
                "text": crate::http::TEXT,
                "type": self.mtype,
                "purpose": self.purpose,
                "sender": sender,
                "with_replies": self.replies,
            });
            let req = ctx.post("https://api.octopush.com/v1/public/sms-campaign/send")
                .header("Accept", "application/json")
                .header("Content-Type", "application/json; charset=utf-8")
                .header("api-key", self.api_key.expose())
                .header("api-login", self.api_login.expose())
                .header("cache-control", "no-cache")
                .json_text(&payload, msg.body);
            Plan::send_check(req, |r| expect(r, &[201]))
        })
    }

}
