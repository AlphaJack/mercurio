//! Flock (`flock://`): messages to Flock channels or users through a webhook or bot token.

use serde_json::{Value, json};

use crate::asset::ImageSize;
use crate::parse::{parse_list, validate_regex};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::util::escape_html;
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "flock",
    name: "Flock",
    schemes: &["flock"],
    service_url: "https://flock.com/",
    parse,
    parse_native: Some(parse_native),
    templates: &[
        "{schema}://{token}",
        "{schema}://{botname}@{token}",
        "{schema}://{botname}@{token}/{targets}",
        "{schema}://{token}/{targets}",
    ],
    tokens: &[
        Param::new("botname", "Bot Name"),
        Param::new("targets", "Targets").list("/").group(&["to_channel", "to_user"]),
        Param::new("to_channel", "To Channel ID").pattern("^[A-Z0-9_]+$").prefix("#"),
        Param::new("to_user", "To User ID").pattern("^[A-Z0-9_]+$").prefix("@"),
        Param::new("token", "Access Key").required().secret().pattern("^[a-z0-9-]+$"),
    ],
    params: &[
        Param::new("image", "Include Image").bool(true),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.flock.com/hooks/sendMessage";
const NOTIFY_API: &str = "https://api.flock.co/v1/chat.sendMessage";

#[derive(Debug)]
struct Flock {
    token: Secret,
    user: Option<String>,
    targets: Vec<String>,
    include_image: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut raw = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        raw.extend(parse_list([to]));
    }
    let token = validate_regex(&u.host(), r"^[a-z0-9-]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Flock Access Key was specified"))?;
    let user_re = crate::regex!(r"(?i)^(@|u:)?(?P<id>[A-Z0-9_]+)\n?\z");
    let chan_re = crate::regex!(r"(?i)^(#|g:)(?P<id>[A-Z0-9_]+)\n?\z");
    let mut targets = Vec::new();
    let mut has_error = false;
    for t in parse_list(raw) {
        if let Some(c) = user_re.captures(&t) {
            targets.push(format!("u:{}", &c["id"]));
        } else if let Some(c) = chan_re.captures(&t) {
            targets.push(format!("g:{}", &c["id"]));
        } else {
            has_error = true;
        }
    }
    if has_error && targets.is_empty() {
        return Err(SERVICE.err("no Flock targets to notify"));
    }
    Ok(Box::new(Flock { token: Secret::new(token), user: u.user(), targets, include_image: SERVICE.flag_strict(u, "image") }))
}

fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(
        r"(?i)^https?://api\.flock\.com/hooks/sendMessage/(?P<token>[a-z0-9-]{24})/?(?P<params>\?.+)?\n?\z"
    );
    let c = re.captures(url)?;
    Some(format!("flock://{}/{}", &c["token"], c.name("params").map_or("", |m| m.as_str())))
}

impl Notify for Flock {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let title = escape_html(msg.title, false, false);
        let body =
            if msg.format != NotifyFormat::Html { escape_html(msg.body, false, false) } else { msg.body.to_string() };
        let flockml =
            format!("<flockml>{}{}</flockml>", if title.is_empty() { String::new() } else { format!("<b>{title}</b><br/>") }, body);
        let image = if self.include_image { ctx.asset.image_url(msg.kind, ImageSize::Xy72) } else { None };
        let user = self.user.as_deref().filter(|u| !u.is_empty());
        let payload = json!({
            "token": self.token.expose(),
            "flockml": flockml,
            "sendAs": {
                "name": user.unwrap_or(ctx.app_id()),
                "profileImage": image.map_or(Value::Null, Value::String),
            },
        });
        let post = |url: String, payload: &Value| {
            let req = ctx.post(url)
                .json(payload);
            Plan::send_expect(req, &[200])
        };
        if self.targets.is_empty() {
            return post(format!("{NOTIFY_URL}/{}", self.token.expose()), &payload);
        }
        Plan::all(self.targets.iter().map(|t| {
            let mut p = payload.clone();
            p["to"] = json!(t);
            post(NOTIFY_API.to_string(), &p).target(t.clone())
        }))
    }

}
