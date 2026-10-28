//! ClickSend (`clicksend://`): SMS through the ClickSend API.

use serde_json::json;

use super::_sms::{expect, full_numbers, no_targets, per_target, to_param};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "clicksend",
    name: "ClickSend",
    schemes: &["clicksend"],
    service_url: "https://clicksend.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    templates: &[
        "{schema}://{user}:{apikey}@{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret(),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").required().group(&["target_phone"]),
        Param::new("user", "User Name").required(),
    ],
    params: &[
        Param::new("batch", "Batch Mode").bool(false),
        Param::sets("key", &["apikey"]),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const BATCH_SIZE: usize = 1000;

#[derive(Debug)]
struct ClickSend {
    user: String,
    password: Secret,
    targets: Vec<String>,
    batch: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = vec![u.host()];
    targets.extend(u.path_segments());
    let batch = SERVICE.flag_strict(u, "batch");
    // The password is unquoted a second time.
    let password = match SERVICE.text(u, "key") {
        Some(k) => Some(unquote(&k)),
        None => u.password(),
    };
    targets.extend(to_param(u));
    let user = u.user().unwrap_or_default();
    let password = password.unwrap_or_default();
    if user.is_empty() || password.is_empty() {
        return Err(SERVICE.err("a ClickSend user/pass was not provided"));
    }
    Ok(Box::new(ClickSend { user, password: Secret::new(password), targets: full_numbers(&targets), batch }))
}

impl Notify for ClickSend {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return no_targets("ClickSend");
        }
        let size = if self.batch { BATCH_SIZE } else { 1 };
        let chunks: Vec<Vec<String>> = self.targets.chunks(size).map(<[String]>::to_vec).collect();
        per_target(chunks, |c| c.join(","), |chunk| {
            let messages: Vec<_> =
                chunk.iter().map(|to| json!({"source": "php", "body": crate::http::TEXT, "to": format!("+{to}")})).collect();
            let req = ctx.post("https://rest.clicksend.com/v3/sms/send")
                .header("Content-Type", "application/json; charset=utf-8")
                .basic_auth(&self.user, Some(self.password.expose()))
                .json_text(&json!({"messages": messages}), msg.body);
            Plan::send_check(req, |r| expect(r, &[200]))
        })
    }

}
