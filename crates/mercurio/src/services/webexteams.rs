//! Cisco Webex Teams (`wxteams://`, `webex://`): messages through Webex incoming webhooks.

use serde_json::json;

use crate::http::Multipart;
use crate::parse::{parse_list, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, split_path, unquote};
use crate::{Error, NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "webexteams",
    name: "Cisco Webex Teams",
    schemes: &["wxteams", "webex"],
    service_url: "https://webex.teams.com/",
    parse,
    parse_native: Some(parse_native),
    limits: Limits { title_maxlen: 0, body_maxlen: 1000, body_max_line_count: 0 },
    formats: &[NotifyFormat::Markdown],
    attachments: true,
    templates: &[
        "{schema}://{token}",
        "{schema}://{access_token}/{targets}",
    ],
    tokens: &[
        Param::new("access_token", "Bot Access Token").required().secret(),
        Param::new("targets", "Room IDs").list("/"),
        Param::new("token", "Webhook Token").required().secret().pattern("^[a-z0-9]{80,160}$"),
    ],
    params: &[
        Param::new("mode", "Mode").choice(&["webhook", "bot"]),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.ciscospark.com/v1/webhooks/incoming/";
const API_URL: &str = "https://webexapis.com/v1/messages";
const TOKEN_RE: &str = r"^[a-z0-9]{80,160}$";

#[derive(Debug)]
enum WebexTeams {
    Webhook { token: Secret },
    Bot { access_token: Secret, targets: Vec<String> },
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mode = SERVICE.text(u, "mode");
    let mut entries = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        entries.extend(split_path(&unquote(to), true));
    }
    let host = SERVICE.text(u, "token").unwrap_or_else(|| u.host());
    let explicit = mode.as_deref().unwrap_or("");
    let (token, access_token, targets) = if explicit == "bot" || (!entries.is_empty() && explicit != "webhook") {
        (None, Some(host), entries)
    } else {
        (Some(host), None, Vec::new())
    };
    let token = token.filter(|t| !t.is_empty());
    let access_token = access_token.filter(|t| !t.is_empty());

    let bot = match mode.as_deref().filter(|m| !m.is_empty()) {
        Some(m) => {
            if "webhook".starts_with(m) {
                false
            } else if "bot".starts_with(m) {
                true
            } else {
                return Err(SERVICE.err("the Webex Teams mode specified is invalid"));
            }
        }
        None => {
            if token.as_deref().is_some_and(|t| validate_regex(t, TOKEN_RE, "i", true).is_some()) {
                false
            } else {
                access_token.is_some() || token.is_some()
            }
        }
    };
    if bot {
        let at = access_token.or(token).ok_or_else(|| SERVICE.err("a Webex Teams bot access token must be specified"))?;
        Ok(Box::new(WebexTeams::Bot { access_token: Secret::new(at), targets: parse_list(targets) }))
    } else {
        let tok = token.or(access_token).unwrap_or_default();
        let token = validate_regex(&tok, TOKEN_RE, "i", true)
            .ok_or_else(|| SERVICE.err("the Webex Teams webhook token specified is invalid"))?;
        Ok(Box::new(WebexTeams::Webhook { token: Secret::new(token) }))
    }
}

fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(
        r"(?i)^https?://(api\.ciscospark\.com|webexapis\.com)/v[1-9][0-9]*/webhooks/incoming/(?P<token>[A-Z0-9_-]+)/?(?P<params>\?.+)?\n?\z"
    );
    let c = re.captures(url)?;
    Some(format!("wxteams://{}/{}", &c["token"], c.name("params").map_or("", |m| m.as_str())))
}

impl Notify for WebexTeams {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let text_key = if msg.format == NotifyFormat::Markdown { "markdown" } else { "text" };
        match self {
            WebexTeams::Webhook { token } => {
                let req = ctx.post(format!("{NOTIFY_URL}/{}", token.expose()))
                    .header("Content-Type", "application/json")
                    .json(&json!({ text_key: msg.body }));
                Plan::send_expect(req, &[200, 204])
            }
            WebexTeams::Bot { access_token, targets } => {
                if targets.is_empty() {
                    return Plan::Fail(Error::Message("Webex Teams Bot mode has no room IDs to notify".into()));
                }
                let bearer = format!("Bearer {}", access_token.expose());
                Plan::all(targets.iter().map(|room| {
                    let base = ctx.post(API_URL).header("Authorization", &bearer);
                    let plan = if msg.attachments.is_empty() {
                        let req = base
                            .header("Content-Type", "application/json")
                            .json(&json!({"roomId": room, text_key: msg.body}));
                        Plan::send_expect(req, &[200])
                    } else {
                        Plan::chain(msg.attachments.iter().enumerate().map(|(i, a)| {
                            let no = i + 1;
                            let name = if a.name.is_empty() { format!("file{no:03}.dat") } else { a.name.clone() };
                            let mut form = Multipart::new().text("roomId", room.as_str());
                            if no == 1 {
                                form = form.text(text_key, msg.body);
                            }
                            form = form.file("files", name, a.mime.as_str(), a.data.clone());
                            Plan::send_expect(base.clone().multipart(form), &[200])
                        }))
                    };
                    plan.target(room.clone())
                }))
            }
        }
    }

    fn limits(&self, _title: &str, _body: &str, _format: NotifyFormat, _ctx: &Context<'_>) -> Option<Limits> {
        match self {
            WebexTeams::Webhook { .. } => None,
            WebexTeams::Bot { .. } => Some(Limits { title_maxlen: 0, body_maxlen: 7439, body_max_line_count: 0 }),
        }
    }

}
