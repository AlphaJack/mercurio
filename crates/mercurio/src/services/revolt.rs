//! Revolt (`revolt://`): messages to Revolt channels.
//!
//! `revolt://{bot_token}/{channel_id}[/{channel_id}...]`

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::asset::ImageSize;
use crate::http::{Request, Response};
use crate::parse::{parse_list, validate_nonblank, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::util::{parse_int, truncate_chars};
use crate::{Error, NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "revolt",
    name: "Revolt",
    schemes: &["revolt"],
    service_url: "https://revolt.chat/",
    parse,
    limits: Limits { title_maxlen: 100, body_maxlen: 2000, body_max_line_count: 0 },
    formats: &[NotifyFormat::Text],
    attachments: false,
    throttle: Duration::from_secs(3),
    templates: &[
        "{schema}://{bot_token}/{targets}",
    ],
    tokens: &[
        Param::new("bot_token", "Bot Token").required().secret(),
        Param::new("target_channel", "Channel ID").required().secret().pattern("^[a-z0-9_-]+$"),
        Param::new("targets", "Targets").list("/").required().group(&["target_channel"]),
    ],
    params: &[
        Param::sets("bot_token", &["bot_token"]),
        Param::sets("channel", &["targets"]),
        Param::new("icon_url", "Icon URL"),
        Param::sets("to", &["targets"]),
        Param::new("url", "Embed URL"),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.revolt.chat/";
const TITLE_MAXLEN: usize = 100;
const CLOCK_SKEW: Duration = Duration::from_secs(2);

#[derive(Debug)]
struct Revolt {
    bot_token: Secret,
    targets: Vec<String>,
    icon_url: Option<String>,
    link: Option<String>,
    /// Markdown is implied unless `?format=` was given.
    implied_markdown: bool,
}

/// Rate-limit state shared by every request of one send.
#[derive(Debug)]
struct RateLimit {
    remaining: i64,
    reset: Instant,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut bot_token = u.host();
    let mut targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(crate::parse::parse_list_unquoted([to]));
    }
    if let Some(ch) = SERVICE.raw(u, "channel") {
        targets.extend(crate::parse::parse_list_unquoted([ch]));
    }
    if let Some(t) = SERVICE.raw(u, "bot_token") {
        bot_token = unquote(t);
    }
    let icon_url = SERVICE.raw(u, "icon_url").map(unquote);
    let link = SERVICE.raw(u, "url").map(unquote);
    let implied_markdown = !u.has_param("format");

    let bot_token =
        validate_nonblank(&bot_token).ok_or_else(|| SERVICE.err("an invalid Revolt Bot Token was specified"))?;
    let targets = parse_list(&targets)
        .into_iter()
        .filter(|t| {
            let ok = validate_regex(t, r"^[a-z0-9_-]+$", "i", true).is_some();
            if !ok {
                crate::warning!("Dropped invalid Revolt channel specified");
            }
            ok
        })
        .collect();
    Ok(Box::new(Revolt { bot_token: Secret::new(bot_token), targets, icon_url, link, implied_markdown }))
}

/// One send: honour a pending rate-limit block, retry once on 429.
fn send(req: Request, state: Arc<Mutex<RateLimit>>, retries: u32) -> Plan {
    Plan::defer(move || {
        let now = Instant::now();
        let wait = {
            let s = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if s.remaining <= 0 && now < s.reset { Some(s.reset - now + CLOCK_SKEW) } else { None }
        };
        let retry_req = req.clone();
        let st = state.clone();
        let http = Plan::http(req, move |res| match res {
            Err(e) => Plan::Fail(e),
            Ok(r) => {
                update_rate_limit(&st, &r, now);
                if r.status == 200 || r.status == 204 {
                    Plan::Done
                } else if r.status == 429 && retries > 0 {
                    send(retry_req, st, retries - 1)
                } else {
                    Plan::Fail(r.http_error())
                }
            }
        });
        match wait {
            Some(w) => Plan::chain([Plan::Sleep(w), http]),
            None => http,
        }
    })
}

fn update_rate_limit(state: &Mutex<RateLimit>, r: &Response, now: Instant) {
    let Some(remaining) = r.header("X-RateLimit-Remaining").and_then(parse_int) else { return };
    let mut s = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    s.remaining = remaining;
    if let Some(after) = r.header("X-RateLimit-Reset-After").and_then(parse_int) {
        let secs = (after as f64 / 1000.0).max(0.0);
        s.reset = now + Duration::from_secs_f64(secs.min(3600.0));
    }
}

impl Notify for Revolt {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Service("there were no Revolt channels to notify".into()));
        }
        let format = if self.implied_markdown { NotifyFormat::Markdown } else { msg.format };
        let payload = if format == NotifyFormat::Markdown {
            let image_url = self.icon_url.clone().or_else(|| ctx.asset.image_url(msg.kind, ImageSize::Xy256));
            let mut embed = json!({
                "title": if msg.title.is_empty() { Value::Null } else { json!(truncate_chars(msg.title, TITLE_MAXLEN)) },
                "description": crate::http::TEXT,
                "colour": ctx.asset.color(msg.kind),
                "replies": null,
            });
            if let Some(i) = image_url.filter(|s| !s.is_empty()) {
                embed["icon_url"] = json!(i);
            }
            if let Some(l) = self.link.as_ref().filter(|s| !s.is_empty()) {
                embed["url"] = json!(l);
            }
            json!({"embeds": [embed]})
        } else {
            let content =
                if msg.title.is_empty() { msg.body.to_string() } else { format!("{}\n{}", msg.title, msg.body) };
            json!({"content": content})
        };
        let body = crate::http::json_with_text(&payload, msg.body);
        let state = Arc::new(Mutex::new(RateLimit { remaining: 1, reset: Instant::now() }));
        Plan::all(self.targets.iter().map(|channel| {
            let req = ctx
                .post(format!("{NOTIFY_URL}channels/{channel}/messages"))
                .header("X-Bot-Token", self.bot_token.expose())
                .header("Content-Type", "application/json; charset=utf-8")
                .header("Accept", "application/json; charset=utf-8")
                .body(body.clone(), None);
            send(req, state.clone(), 1).target(channel.clone())
        }))
    }

}
