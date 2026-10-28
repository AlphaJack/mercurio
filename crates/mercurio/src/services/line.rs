//! LINE (`line://`): push messages to users or groups through the LINE Messaging API.

use serde_json::json;

use crate::asset::ImageSize;
use crate::parse::{parse_list, validate_nonblank};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};


pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "line",
    name: "Line",
    schemes: &["line"],
    service_url: "https://line.me/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 5000, body_max_line_count: 0 },
    templates: &[
        "{schema}://{token}/{targets}",
    ],
    tokens: &[
        Param::new("target_user", "Target User"),
        Param::new("targets", "Targets").list("/").required().group(&["target_user"]),
        Param::new("token", "Access Token").required().secret(),
    ],
    params: &[
        Param::new("image", "Include Image").bool(true),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.line.me/v2/bot/message/push";

#[derive(Debug)]
struct Line {
    token: Secret,
    targets: Vec<String>,
    include_image: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let token = if let Some(t) = u.param_nonempty("token") {
        unquote(t)
    } else {
        let mut token = u.host();
        if !token.ends_with('=')
            && let Some(index) = targets.iter().position(|e| e.ends_with('='))
        {
            let rest = targets.split_off(index + 1);
            token = format!("{token}/{}", targets.join("/"));
            targets = rest;
        }
        token
    };
    if let Some(to) = u.param_nonempty("to") {
        let re = crate::regex!(r"[ \t\r\n,#\\/]+");
        targets.extend(re.split(&unquote(to)).filter(|s| !s.is_empty()).map(str::to_owned));
    }
    let token = validate_nonblank(&token).ok_or_else(|| SERVICE.err("an invalid Access Token was specified"))?;
    Ok(Box::new(Line { token: Secret::new(token), targets: parse_list(targets), include_image: SERVICE.flag_strict(u, "image") }))
}

impl Notify for Line {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(crate::Error::Message("there were no Line targets to notify".into()));
        }
        let mut message = json!({"type": "text", "text": crate::http::TEXT, "sender": {"name": ctx.app_id()}});
        if self.include_image
            && let Some(img) = ctx.asset.image_url(msg.kind, ImageSize::Xy128)
        {
            message["sender"]["iconUrl"] = json!(img);
        }
        Plan::all(self.targets.iter().map(|t| {
            let req = ctx.post(NOTIFY_URL)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", self.token.expose()))
                .json_text(&json!({"to": t, "messages": [message]}), msg.body);
            Plan::send_expect(req, &[200]).target(t.clone())
        }))
    }

}
