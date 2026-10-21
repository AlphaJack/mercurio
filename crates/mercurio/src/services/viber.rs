//! Viber (`viber://`): messages through a Viber bot.

use serde_json::{Value, json};

use crate::error::Error;
use crate::http::Response;
use crate::parse::{parse_list, validate_nonblank};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "viber",
    name: "Viber",
    schemes: &["viber"],
    service_url: "https://www.viber.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 30000, body_max_line_count: 0 },
    templates: &[
        "{schema}://{token}/{targets}",
    ],
    tokens: &[
        Param::new("targets", "Receiver IDs").list("/").required(),
        Param::new("token", "Authentication Token").required().secret(),
    ],
    params: &[
        Param::new("avatar", "Bot Avatar URL"),
        Param::new("from", "Bot Name"),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

const SENDER_NAME_LIMIT: usize = 28;

#[derive(Debug)]
struct Viber {
    token: Secret,
    targets: Vec<String>,
    source: String,
    avatar: Option<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = vec![u.host()];
    targets.extend(u.path_segments());
    let token = SERVICE.text(u, "token").unwrap_or_else(|| targets.remove(0));
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }
    let source = SERVICE.text(u, "from").unwrap_or_default();
    let avatar = SERVICE.text(u, "avatar");

    let token =
        validate_nonblank(&token).ok_or_else(|| SERVICE.err("an invalid Viber authentication token was specified"))?;
    let source: String = source.trim().chars().take(SENDER_NAME_LIMIT).collect();
    let avatar = avatar.map(|a| a.trim().to_string()).filter(|a| !a.is_empty());
    Ok(Box::new(Viber { token: Secret::new(token), targets: parse_list(targets), source, avatar }))
}

fn check(r: &Response) -> Result<()> {
    let Some(content) = r.json() else {
        return Err(Error::Service("invalid JSON response from Viber".into()));
    };
    let Some(obj) = content.as_object() else {
        return Err(Error::Service("unexpected JSON response from Viber".into()));
    };
    if r.status != 200 {
        let reason = obj.get("status_message").and_then(Value::as_str).unwrap_or_default().to_string();
        return Err(r.http_error_with(reason));
    }
    // Anything but status 0 (missing counts as -1) is a failure.
    let status = match obj.get("status") {
        None => Some(-1),
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f.trunc() as i64)),
        Some(Value::String(s)) => s.trim().parse::<i64>().ok(),
        Some(Value::Bool(b)) => Some(i64::from(*b)),
        Some(_) => None,
    };
    match status {
        Some(0) => Ok(()),
        _ => {
            let msg = obj.get("status_message").and_then(Value::as_str).unwrap_or("unknown");
            Err(Error::Service(format!("Viber error: {msg}")))
        }
    }
}

impl Notify for Viber {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Service("there are no Viber receivers to notify".into()));
        }
        let name = if self.source.is_empty() {
            ctx.app_desc().chars().take(SENDER_NAME_LIMIT).collect()
        } else {
            self.source.clone()
        };
        let mut sender = json!({"name": name});
        if let Some(a) = &self.avatar {
            sender["avatar"] = json!(a);
        }
        Plan::all(self.targets.iter().map(|dest| {
            let payload = json!({"type": "text", "text": crate::http::TEXT, "sender": sender, "receiver": dest});
            let req = ctx
                .post("https://chatapi.viber.com/pa/send_message")
                .header("X-Viber-Auth-Token", self.token.expose())
                .json_text(&payload, msg.body);
            Plan::send_check(req, check).target(dest.clone())
        }))
    }

}
