//! SerwerSMS (`serwersms://`): SMS through the SerwerSMS API.

use serde_json::{Value, json};

use super::_telephony::{Form, http_err, json_object, param_unquoted, has_value};
use crate::error::Error;
use crate::http::Response;
use crate::parse::{is_phone_no, parse_list, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "serwersms",
    name: "SerwerSMS",
    schemes: &["serwersms"],
    service_url: "https://serwersms.pl",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    attachments: true,
    templates: &[
        "{schema}://{user}:{password}@{sender}/{targets}",
        "{schema}://{user}:{password}@{sender}",
    ],
    tokens: &[
        Param::new("password", "Password").required().secret(),
        Param::new("sender", "Sender Name").required().pattern("^[a-z0-9][a-z0-9 _-]{0,10}$"),
        Param::new("target_group", "Target Group ID").prefix("#"),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").group(&["target_group", "target_phone"]),
        Param::new("user", "Username").required(),
    ],
    params: &[
        Param::sets("sender", &["sender"]).aliases(&["from"]),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api2.serwersms.pl/messages/send_sms";
const NOTIFY_URL_MMS: &str = "https://api2.serwersms.pl/messages/send_mms";

#[derive(Debug)]
struct SerwerSms {
    user: String,
    password: Secret,
    sender: String,
    phones: Vec<String>,
    groups: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut sender = u.host();
    let mut targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]).into_iter().map(|t| unquote(&t)).filter(|t| !t.is_empty()));
    }
    if let Some(s) = param_unquoted(u, "from") {
        sender = s;
    }
    if let Some(s) = param_unquoted(u, "sender") {
        sender = s;
    }
    let user = u.user().unwrap_or_default();
    if user.is_empty() {
        return Err(SERVICE.err("a SerwerSMS username must be specified"));
    }
    let password = u.password().unwrap_or_default();
    if password.is_empty() {
        return Err(SERVICE.err("a SerwerSMS password must be specified"));
    }
    let sender = validate_regex(&sender, r"^[a-z0-9][a-z0-9 _-]{0,10}$", "i", true)
        .ok_or_else(|| SERVICE.err("a SerwerSMS sender name is invalid"))?;
    let group_re = crate::regex!(r"(?i)^\s*(\#|\%23)(?P<group>[0-9]+)\s*$");
    let (mut phones, mut groups) = (Vec::new(), Vec::new());
    for t in parse_list(&targets) {
        if let Some(c) = group_re.captures(&t) {
            groups.push(c["group"].to_string());
        } else if let Some(p) = is_phone_no(&t, 10) {
            phones.push(p.full);
        }
    }
    Ok(Box::new(SerwerSms { user, password: Secret::new(password), sender, phones, groups }))
}

fn check(r: &Response) -> Result<()> {
    if r.status != 200 {
        return Err(http_err(r));
    }
    let content = json_object(r).unwrap_or_default();
    if content.get("success").is_some_and(has_value) {
        return Ok(());
    }
    let error = content.get("error").cloned().unwrap_or(Value::Null);
    Err(Error::Service(if has_value(&error) {
        format!("SerwerSMS error: {error}")
    } else {
        "SerwerSMS reported failure".into()
    }))
}

impl Notify for SerwerSms {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.phones.is_empty() && self.groups.is_empty() {
            return Plan::Fail(SERVICE.err("there are no valid SerwerSMS targets to notify"));
        }
        let mms = !msg.attachments.is_empty();
        let calls = self
            .phones
            .iter()
            .map(|p| (format!("+{p}"), ("phone", format!("+{p}"))))
            .chain(self.groups.iter().map(|g| (format!("group {g}"), ("group_id", g.clone()))));
        Plan::all(calls.map(|(label, (key, value))| {
            let fields = [
                ("username", self.user.as_str()),
                ("password", self.password.expose()),
                ("text", msg.body),
                ("sender", self.sender.as_str()),
                (key, value.as_str()),
            ];
            let req = if mms {
                let mut form = Form::new();
                for (k, v) in fields {
                    form = form.text(k, v);
                }
                for a in msg.attachments {
                    form = form.part("file", Some(&a.name), Some(&a.mime), a.data.clone());
                }
                form.apply(ctx.post(NOTIFY_URL_MMS))
            } else {
                let body: serde_json::Map<String, Value> =
                    fields.iter().map(|(k, v)| (k.to_string(), json!(v))).collect();
                ctx.post(NOTIFY_URL)
                    .json(&Value::Object(body))
            };
            Plan::send_check(req, check).target(label)
        }))
    }

}
