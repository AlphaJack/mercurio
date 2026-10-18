//! Ryver (`ryver://`): messages to Ryver forums through webhooks.

use serde_json::{Value, json};

use crate::asset::ImageSize;
use crate::parse::validate_regex;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Error, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "ryver",
    name: "Ryver",
    schemes: &["ryver"],
    service_url: "https://ryver.com/",
    parse,
    parse_native: Some(parse_native),
    limits: Limits { title_maxlen: 250, body_maxlen: 1000, body_max_line_count: 0 },
    templates: &[
        "{schema}://{organization}/{token}",
        "{schema}://{botname}@{organization}/{token}",
    ],
    tokens: &[
        Param::new("botname", "Bot Name"),
        Param::new("organization", "Organization").required().pattern("^[A-Z0-9_-]{3,32}$"),
        Param::new("token", "Token").required().secret().pattern("^[A-Z0-9]{15}$"),
    ],
    params: &[
        Param::new("image", "Include Image").bool(true),
        Param::new("mode", "Webhook Mode").choice(&["slack", "ryver"]).default("ryver"),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Slack,
    Ryver,
}

#[derive(Debug)]
struct Ryver {
    organization: String,
    token: Secret,
    user: Option<String>,
    mode: Mode,
    include_image: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let token = u.path_segments().into_iter().next().unwrap_or_default();
    let token = validate_regex(&token, r"^[A-Z0-9]{15}$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Ryver API Token was specified"))?;
    let organization = validate_regex(&u.host(), r"^[A-Z0-9_-]{3,32}$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Ryver Organization was specified"))?;
    let mode = match SERVICE.raw(u, "mode").map(str::to_lowercase).as_deref() {
        None | Some("ryver") => Mode::Ryver,
        Some("slack") => Mode::Slack,
        Some(_) => return Err(SERVICE.err("the Ryver webhook mode specified is invalid")),
    };
    Ok(Box::new(Ryver {
        organization,
        token: Secret::new(token),
        user: u.user(),
        mode,
        include_image: SERVICE.flag_strict(u, "image"),
    }))
}

fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(
        r"(?i)^https?://(?P<org>[A-Z0-9_-]+)\.ryver\.com/application/webhook/(?P<token>[A-Z0-9]+)/?(?P<params>\?.+)?\n?\z"
    );
    let c = re.captures(url)?;
    Some(format!("ryver://{}/{}/{}", &c["org"], &c["token"], c.name("params").map_or("", |m| m.as_str())))
}

/// Slack-mode escaping. Input containing the literal `"\r*\n"` fails.
fn slack_escape(s: &str) -> Option<String> {
    if s.contains("\r*\n") {
        return None;
    }
    Some(s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;"))
}

impl Notify for Ryver {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let (title, body) = if self.mode == Mode::Slack {
            match (slack_escape(msg.title), slack_escape(msg.body)) {
                (Some(t), Some(b)) => (t, b),
                _ => return Plan::Fail(Error::Message("unsupported formatting sequence in message".into())),
            }
        } else {
            (msg.title.to_string(), msg.body.to_string())
        };
        let avatar = if self.include_image { ctx.asset.image_url(msg.kind, ImageSize::Xy72) } else { None };
        let payload = json!({
            "body": if title.is_empty() { body } else { format!("**{title}**\r\n{body}") },
            "createSource": {
                "displayName": self.user.as_ref().map_or(Value::Null, |u| json!(u)),
                "avatar": avatar.map_or(Value::Null, Value::String),
            },
        });
        let url =
            format!("https://{}.ryver.com/application/webhook/{}", self.organization, self.token.expose());
        let req = ctx.post(url)
            .json(&payload);
        Plan::send_expect(req, &[200])
    }
}
