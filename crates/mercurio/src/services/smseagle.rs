//! SMSEagle (`smseagle://`, `smseagles://`): SMS through an SMSEagle device.

use serde_json::{Value, json};

use super::_telephony::{http_err, phone_entries, param_unquoted};
use crate::crypto::b64;
use crate::error::Error;
use crate::http::Response;
use crate::parse::{parse_phone_no_unquoted, validate_nonblank};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::util::parse_int;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "smseagle",
    name: "SMS Eagle",
    schemes: &["smseagle", "smseagles"],
    service_url: "https://smseagle.eu",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 1200, body_max_line_count: 0 },
    attachments: true,
    templates: &[
        "{schema}://{token}@{host}/{targets}",
        "{schema}://{token}@{host}:{port}/{targets}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("port", "Port").port(),
        Param::new("target_contact", "Target Contact").pattern("^[a-z0-9_-]+$").prefix("@"),
        Param::new("target_group", "Target Group ID").pattern("^[a-z0-9_-]+$").prefix("#"),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").required().group(&["target_contact", "target_group", "target_phone"]),
        Param::new("token", "Access Token").required(),
    ],
    params: &[
        Param::new("batch", "Batch Mode").bool(false),
        Param::new("flash", "Flash").bool(false),
        Param::new("priority", "Priority").choice(&["0", "1"]).default("0"),
        Param::new("status", "Show Status").bool(false),
        Param::new("test", "Test Only").bool(false),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

const BATCH_SIZE: usize = 10;
/// Prefix -> priority, in match order.
const PRIORITY_MAP: &[(&str, i64)] = &[("normal", 0), ("+", 1), ("high", 1)];

#[derive(Debug)]
struct SmsEagle {
    url: String,
    token: Secret,
    priority: i64,
    batch: bool,
    status: bool,
    flash: bool,
    test: bool,
    phones: Vec<String>,
    groups: Vec<String>,
    contacts: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let token = if let Some(t) = param_unquoted(u, "token") {
        Some(t)
    } else if u.password.is_none() && u.user.is_some() {
        u.user()
    } else {
        None
    };
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_phone_no_unquoted([to], false));
    }
    let batch = SERVICE.flag(u, "batch");
    let flash = SERVICE.flag(u, "flash");
    let test = SERVICE.flag(u, "test");
    let status = SERVICE.flag(u, "status");
    let priority = SERVICE.text_or_default(u, "priority");

    let token = token.filter(|t| !t.is_empty()).or_else(|| u.user());
    let token = token
        .as_deref()
        .and_then(validate_nonblank)
        .ok_or_else(|| SERVICE.err("an invalid SMSEagle Access Token was specified"))?;

    let priority = match parse_int(&priority) {
        Some(v) => v,
        None => {
            let p = priority.trim().to_lowercase();
            let found = if p.is_empty() { None } else { PRIORITY_MAP.iter().find(|(k, _)| k.starts_with(&p)) };
            found.map(|(_, v)| *v).ok_or_else(|| SERVICE.err("an invalid SMSEagle priority was specified"))?
        }
    };
    if !(0..=1).contains(&priority) {
        return Err(SERVICE.err("an invalid SMSEagle priority was specified"));
    }

    let group_re = crate::regex!(r"(?i)^\s*(\#|\%35)(?P<group>[a-z0-9_-]+)");
    let contact_re = crate::regex!(r"(?i)^\s*(\@|\%40)?(?P<contact>[a-z0-9_-]+)");
    let (mut phones, mut groups, mut contacts) = (Vec::new(), Vec::new(), Vec::new());
    for (raw, res) in phone_entries(&targets, 9) {
        if let Some(p) = res {
            phones.push(format!("{}{}", if raw.starts_with('+') { "+" } else { "" }, p.full));
        } else if let Some(c) = group_re.captures(&raw) {
            groups.push(c["group"].to_string());
        } else if let Some(c) = contact_re.captures(&raw) {
            contacts.push(c["contact"].to_string());
        }
    }

    let mut url = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(port) = u.port {
        url.push_str(&format!(":{port}"));
    }
    url.push_str("/jsonrpc/sms");
    Ok(Box::new(SmsEagle {
        url,
        token: Secret::new(token),
        priority,
        batch,
        status,
        flash,
        test,
        phones,
        groups,
        contacts,
    }))
}

fn check(r: &Response) -> Result<()> {
    let content = match r.json() {
        Some(Value::Object(m)) if m.contains_key("result") => m,
        _ => serde_json::Map::new(),
    };
    let result = content.get("result");
    let ok = (r.status == 200 || r.status == 201)
        && match result {
            Some(Value::Object(m)) => m.get("status").and_then(Value::as_str) == Some("ok"),
            Some(Value::Array(a)) => {
                !a.iter().any(|e| e.is_object() && e.get("status").and_then(Value::as_str) != Some("ok"))
            }
            _ => false,
        };
    if ok {
        Ok(())
    } else if let Some(res) = result.filter(|v| super::_telephony::has_value(v)) {
        Err(Error::Service(format!("SMSEagle error: {res}")))
    } else {
        Err(http_err(r))
    }
}

impl Notify for SmsEagle {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.phones.is_empty() && self.groups.is_empty() && self.contacts.is_empty() {
            return Plan::Fail(SERVICE.err("there are no valid SMSEagle targets to notify"));
        }
        let attachments: Vec<Value> = msg
            .attachments
            .iter()
            .filter(|a| a.mime.to_ascii_lowercase().starts_with("image/"))
            .map(|a| json!({"content_type": a.mime, "content": b64(&a.data)}))
            .collect();
        let message =
            if self.status { format!("{} {}", ctx.asset.ascii(msg.kind), msg.body) } else { msg.body.to_string() };
        let batch = if self.batch { BATCH_SIZE } else { 1 };
        let categories: [(&str, &str, &Vec<String>); 3] = [
            ("sms.send_sms", "to", &self.phones),
            ("sms.send_togroup", "groupname", &self.groups),
            ("sms.send_tocontact", "contactname", &self.contacts),
        ];
        let mut plans = Vec::new();
        for (method, field, targets) in categories {
            for chunk in targets.chunks(batch) {
                let joined = chunk.join(",");
                let mut params = json!({
                    "access_token": self.token.expose(),
                    "message": message,
                    "highpriority": self.priority,
                    "unicode": 1,
                    "message_type": "sms",
                    "responsetype": "extended",
                    "flash": if self.flash { 1 } else { 0 },
                    "test": if self.test { 1 } else { 0 },
                });
                params[field] = json!(joined);
                if !attachments.is_empty() {
                    params["message_type"] = json!("mms");
                    params["attachments"] = Value::Array(attachments.clone());
                }
                let req = ctx
                    .post(&self.url)
                    .header("Content-Type", "application/json")
                    .json(&json!({"method": method, "params": params}));
                plans.push(Plan::send_check(req, check).target(joined));
            }
        }
        Plan::all(plans)
    }

}
