//! GroupMe (`groupme://`): messages to a GroupMe group through a bot.

use serde_json::{Value, json};

use crate::error::Error;
use crate::http::Request;
use crate::message::Attachment;
use crate::parse::{validate_nonblank, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "groupme",
    name: "GroupMe",
    schemes: &["groupme"],
    service_url: "https://groupme.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 1000, body_max_line_count: 0 },
    attachments: true,
    templates: &[
        "{schema}://{bot_id}",
        "{schema}://{bot_id}/{token}",
    ],
    tokens: &[
        Param::new("bot_id", "Bot ID").required().secret(),
        Param::new("token", "Access Token").secret(),
    ],
    params: &[
        Param::sets("bot_id", &["bot_id"]),
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

const BOT_URL: &str = "https://api.groupme.com/v3/bots/post";
const IMAGE_URL: &str = "https://image.groupme.com/pictures";

#[derive(Debug)]
struct GroupMe {
    bot_id: Secret,
    token: Option<Secret>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut bot_id = u.host();
    if let Some(b) = u.param_nonempty("bot_id") {
        bot_id = unquote(b);
    }
    let mut token = u.path_segments().into_iter().next();
    if let Some(t) = u.param_nonempty("token") {
        token = Some(unquote(t));
    }
    let bot_id = validate_regex(&bot_id, r"^[a-z0-9]+$", "i", true)
        .ok_or_else(|| SERVICE.err("a GroupMe bot_id must be specified"))?;
    let token = token.filter(|t| !t.is_empty()).and_then(|t| validate_nonblank(&t)).map(Secret::new);
    Ok(Box::new(GroupMe { bot_id: Secret::new(bot_id), token }))
}

fn error_reason(status: u16) -> String {
    match status {
        401 => "Unauthorized - Invalid or expired access token.",
        400 => "Bad Request - Malformed payload or missing required fields.",
        404 => "Not Found - The specified bot_id does not exist.",
        429 => "Too many requests; rate-limit exceeded.",
        _ => "",
    }
    .to_string()
}

/// Upload the remaining images one by one, then post the message.
fn upload_then_post(
    mut pending: std::vec::IntoIter<Attachment>,
    mut urls: Vec<Value>,
    token: String,
    user_agent: String,
    post: Box<dyn FnOnce(Vec<Value>) -> Plan + Send>,
) -> Plan {
    let Some(a) = pending.next() else { return post(urls) };
    let req = Request::post(IMAGE_URL)
        .header("User-Agent", user_agent.clone())
        .header("Content-Type", a.mime.clone())
        .header("X-Access-Token", token.clone())
        .body(a.data.clone(), None);
    Plan::http(req, move |res| {
        let r = match res {
            Ok(r) => r,
            Err(e) => return Plan::Fail(e),
        };
        if r.status != 200 {
            return Plan::Fail(r.http_error_with(error_reason(r.status)));
        }
        let url = r.json().and_then(|v| v.get("payload")?.get("url").cloned()).filter(|v| match v {
            Value::String(s) => !s.is_empty(),
            Value::Null | Value::Bool(false) => false,
            Value::Array(a) => !a.is_empty(),
            Value::Object(o) => !o.is_empty(),
            Value::Number(n) => n.as_f64() != Some(0.0),
            _ => true,
        });
        match url {
            None => Plan::Fail(Error::Service(format!("GroupMe image service returned no URL for {}", a.name))),
            Some(u) => {
                urls.push(json!({"type": "image", "url": u}));
                upload_then_post(pending, urls, token, user_agent, post)
            }
        }
    })
    .context("upload")
}

impl Notify for GroupMe {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let bot_id = self.bot_id.expose().to_string();
        let body = msg.body.to_string();
        let ua = ctx.app_id().to_string();
        let post = {
            let ua = ua.clone();
            move |attachments: Vec<Value>| {
                let mut payload = json!({"bot_id": bot_id, "text": crate::http::TEXT});
                let uploaded = !attachments.is_empty();
                if uploaded {
                    payload["attachments"] = Value::Array(attachments);
                }
                let req = Request::post(BOT_URL)
                    .header("User-Agent", ua)
                    .header("Content-Type", "application/json; charset=utf-8")
                    .json_text(&payload, &body);
                let send = Plan::http(req, |res| match res {
                    Ok(r) if r.status == 200 || r.status == 202 => Plan::Done,
                    Ok(r) => Plan::Fail(r.http_error_with(error_reason(r.status))),
                    Err(e) => Plan::Fail(e),
                });
                if uploaded { send.context("post") } else { send }
            }
        };
        let images: Vec<Attachment> = match &self.token {
            Some(_) => msg
                .attachments
                .iter()
                .filter(|a| {
                    let ok = a.mime.is_empty() || a.mime.starts_with("image/");
                    if !ok {
                        log::warn!("GroupMe image service only supports images; skipping {} ({})", a.name, a.mime);
                    }
                    ok
                })
                .cloned()
                .collect(),
            None => {
                if !msg.attachments.is_empty() {
                    log::warn!("GroupMe image attachments require an access token; skipping attachments");
                }
                Vec::new()
            }
        };
        let token = self.token.as_ref().map(|t| t.expose().to_string()).unwrap_or_default();
        upload_then_post(images.into_iter(), Vec::new(), token, ua, Box::new(post))
    }
}
