//! Free Mobile (`freemobile://`): SMS to your own Free Mobile line through its notification API.

use serde_json::json;

use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "freemobile",
    name: "Free-Mobile",
    schemes: &["freemobile"],
    service_url: "https://mobile.free.fr/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    templates: &[
        "{schema}://{user}@{password}",
    ],
    tokens: &[
        Param::new("password", "Password").required().secret(),
        Param::new("user", "Username").required(),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://smsapi.free-mobile.fr/sendmsg";

#[derive(Debug)]
struct FreeMobile {
    user: String,
    password: Secret,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let password = match u.password.as_deref().filter(|p| !p.is_empty()) {
        Some(_) => u.password().unwrap_or_default(),
        None => u.host(),
    };
    let user = u.user().unwrap_or_default();
    if user.is_empty() || password.is_empty() {
        return Err(SERVICE.err("a FreeMobile user and password combination was not provided"));
    }
    Ok(Box::new(FreeMobile { user, password: Secret::new(password) }))
}

impl Notify for FreeMobile {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let payload = json!({"user": self.user, "pass": self.password.expose(), "msg": msg.body});
        let req = ctx.post(NOTIFY_URL)
            .json(&payload);
        Plan::send_expect(req, &[200])
    }
}
