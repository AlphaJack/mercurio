//! Kook (`kook://`): messages through bot mode (channels, DMs, CDN attachments) and incoming-webhook mode.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};

use crate::env::Env;
use crate::error::Error;
use crate::http::{Multipart, Request, Response};
use crate::message::Attachment;
use crate::parse::{parse_list, parse_list_unquoted};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, quote};
use crate::util::json_has_value;
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "kook",
    name: "Kook",
    schemes: &["kook"],
    service_url: "https://www.kookapp.cn/",
    parse,
    parse_native: Some(parse_native),
    limits: Limits { title_maxlen: 0, body_maxlen: 5000, body_max_line_count: 0 },
    formats: &[NotifyFormat::Markdown],
    attachments: true,
    templates: &[
        "{schema}://{token}",
        "{schema}://{token}/{targets}",
    ],
    tokens: &[
        Param::new("targets", "Targets").list("/"),
        Param::new("token", "Token").required().secret(),
    ],
    params: &[
        Param::new("mode", "Mode").choice(&["bot", "webhook"]).default("bot"),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

const API: &str = "https://www.kookapp.cn/api/v3";
const TYPE_TEXT: i64 = 1;
const TYPE_IMAGE: i64 = 2;
const TYPE_FILE: i64 = 4;
const TYPE_KMARKDOWN: i64 = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Bot,
    Webhook,
}

#[derive(Debug)]
struct Kook {
    token: Secret,
    mode: Mode,
    channels: Vec<String>,
    dm_users: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let token = SERVICE.text(u, "token").unwrap_or_else(|| u.host());
    if token.is_empty() {
        return Err(SERVICE.err("a Kook token must be specified"));
    }
    let m = SERVICE.text_or_default(u, "mode").to_lowercase();
    let mode = if "bot".starts_with(&m) {
        Mode::Bot
    } else if "webhook".starts_with(&m) {
        Mode::Webhook
    } else {
        return Err(SERVICE.err("the Kook mode specified is not valid"));
    };

    let mut targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list_unquoted([to]));
    }
    let id = crate::regex!(r"^[0-9]{1,20}$");
    let mut channels = Vec::new();
    let mut dm_users = Vec::new();
    for target in parse_list(&targets) {
        if let Some(user) = target.strip_prefix('@') {
            if id.is_match(user) {
                dm_users.push(user.to_string());
            } else {
                log::warn!("dropping invalid Kook DM user ID");
            }
        } else {
            let channel = target.strip_prefix('#').unwrap_or(&target);
            if id.is_match(channel) {
                channels.push(channel.to_string());
            } else {
                log::warn!("dropping invalid Kook channel ID");
            }
        }
    }
    Ok(Box::new(Kook { token: Secret::new(token), mode, channels, dm_users }))
}

fn parse_native(url: &str) -> Option<String> {
    let re =
        crate::regex!(r"(?i)^https?://www\.kookapp\.cn/api/v3/incoming/(?P<key>[A-Za-z0-9_=+-]+)/?(?P<params>\?.+)?$");
    let c = re.captures(url)?;
    let extra = c.name("params").map(|p| format!("&{}", p.as_str().trim_start_matches('?'))).unwrap_or_default();
    Some(format!("kook://{}/?mode=webhook{extra}", &c["key"]))
}

/// `true` for a JSON number equal to zero or `false`.
fn is_zero(v: &Value) -> bool {
    v.as_bool() == Some(false) || v.as_f64() == Some(0.0)
}

/// Outcome of a Kook API call: `Err((error, abort))`; `abort` stops the whole notification.
type Checked<T> = std::result::Result<T, (Error, bool)>;

/// The JSON body, empty when it holds no value or is unparsable; `None` when it is not an object.
fn content(r: &Response) -> Option<serde_json::Map<String, Value>> {
    match serde_json::from_slice::<Value>(&r.body) {
        Ok(v) if json_has_value(&v) => if let Value::Object(m) = v { Some(m) } else { None },
        _ => Some(serde_json::Map::new()),
    }
}

fn status_ok(res: Result<Response>) -> Checked<Response> {
    let r = res.map_err(|e| (e, false))?;
    if r.status != 200 {
        return Err((r.http_error(), false));
    }
    Ok(r)
}

fn check(res: Result<Response>) -> Checked<()> {
    let r = status_ok(res)?;
    let c = content(&r).ok_or_else(|| (Error::Service("unexpected Kook response".into()), true))?;
    match c.get("code") {
        Some(code) if !is_zero(code) => {
            let msg = c.get("message").and_then(Value::as_str).unwrap_or("Unknown");
            Err((Error::Service(format!("Kook error code={code}, message={msg}")), false))
        }
        _ => Ok(()),
    }
}

fn upload_url(res: Result<Response>) -> Checked<Value> {
    let r = status_ok(res)?;
    let unexpected = || (Error::Service("unexpected Kook upload response".into()), true);
    let c = content(&r).ok_or_else(unexpected)?;
    let url = match c.get("data") {
        None => None,
        Some(Value::Object(d)) => d.get("url").cloned(),
        Some(_) => return Err(unexpected()),
    };
    url.filter(json_has_value).ok_or_else(|| (Error::Service("Kook CDN upload returned no URL".into()), false))
}

#[derive(Debug)]
struct State {
    has_error: AtomicBool,
    aborted: AtomicBool,
    env: Arc<dyn Env>,
}

type Shared = Arc<State>;

/// One JSON post whose failure sets `has_error`.
fn post(req: Request, st: Shared, label: String) -> Plan {
    Plan::defer(move || {
        if st.aborted.load(Ordering::SeqCst) {
            return Plan::Done;
        }
        Plan::http(req, move |res| match check(res) {
            Ok(()) => Plan::Done,
            Err((e, abort)) => {
                st.has_error.store(true, Ordering::SeqCst);
                if abort {
                    st.aborted.store(true, Ordering::SeqCst);
                }
                Plan::Fail(e)
            }
        })
    })
    .target(label)
}

impl Kook {
    fn json_req(&self, url: &str, payload: &Value, text: &str, ctx: &Context<'_>, bot: bool) -> Request {
        let mut req = ctx.post(url);
        if bot {
            req = req.header("Authorization", format!("Bot {}", self.token.expose()));
        }
        req.header("Content-Type", "application/json").body(crate::http::json_with_text(payload, text), None)
    }

    fn endpoints(&self) -> Vec<(String, String)> {
        self.channels
            .iter()
            .map(|c| (format!("{API}/message/create"), c.clone()))
            .chain(self.dm_users.iter().map(|u| (format!("{API}/direct-message/create"), u.clone())))
            .collect()
    }
}

/// Upload attachment `i`, post it to every target, then continue with `i + 1`.
fn attach_step(
    atts: Arc<Vec<Attachment>>,
    i: usize,
    reqs: Arc<Vec<(String, String, Request)>>,
    upload: Request,
    st: Shared,
) -> Plan {
    let Some(att) = atts.get(i) else { return Plan::Done };
    let name = if att.name.is_empty() { "attachment.dat" } else { att.name.as_str() };
    let req = upload.clone().multipart(Multipart::with_env(st.env.as_ref()).file("file", name, att.mime.as_str(), att.data.clone()));
    let kind = if att.mime.starts_with("image/") { TYPE_IMAGE } else { TYPE_FILE };
    Plan::http(req, move |res| match upload_url(res) {
        Err((e, _)) => Plan::Fail(e),
        Ok(url) => {
            let mut plans: Vec<Plan> = reqs
                .iter()
                .map(|(endpoint, tid, base)| {
                    let payload = json!({"type": kind, "target_id": tid, "content": url});
                    let req = Request { url: endpoint.clone(), ..base.clone() }
                        .body(serde_json::to_vec(&payload).unwrap_or_default(), None);
                    post(req, st.clone(), tid.clone()).context("attachment post")
                })
                .collect();
            let st2 = st.clone();
            plans.push(Plan::defer(move || {
                if st2.aborted.load(Ordering::SeqCst) {
                    Plan::Done
                } else {
                    attach_step(atts, i + 1, reqs, upload, st2)
                }
            }));
            Plan::all(plans)
        }
    })
    .context("upload")
}

impl Notify for Kook {
    /// KMarkdown has no headings: `# title` lines become bold.
    fn convert(&self, body: &str, format: NotifyFormat) -> Option<String> {
        (format == NotifyFormat::Markdown).then(|| crate::convert::markup::headings_to_bold(body))
    }

    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let kind = if msg.format == NotifyFormat::Markdown { TYPE_KMARKDOWN } else { TYPE_TEXT };

        if self.mode == Mode::Webhook {
            if msg.body.is_empty() {
                return Plan::Fail(Error::Message("Kook webhooks do not support attachments".into()));
            }
            let url = format!("{API}/incoming/{}", quote(self.token.expose(), "!#$%&'()*+,/:;=?@[]~"));
            let req = self.json_req(&url, &json!({"type": kind, "content": crate::http::TEXT}), msg.body, ctx, false);
            return Plan::http(req, |res| match check(res) {
                Ok(()) => Plan::Done,
                Err((e, _)) => Plan::Fail(e),
            });
        }

        if self.channels.is_empty() && self.dm_users.is_empty() {
            return Plan::Fail(Error::Service("Kook: no targets specified".into()));
        }
        let st: Shared =
            Arc::new(State { has_error: AtomicBool::default(), aborted: AtomicBool::default(), env: ctx.env().clone() });
        let targets = self.endpoints();
        let mut plans: Vec<Plan> = targets
            .iter()
            .map(|(endpoint, tid)| {
                let payload = json!({"type": kind, "target_id": tid, "content": crate::http::TEXT});
                post(self.json_req(endpoint, &payload, msg.body, ctx, true), st.clone(), tid.clone())
            })
            .collect();

        if !msg.attachments.is_empty() {
            let atts = Arc::new(msg.attachments.to_vec());
            let reqs: Arc<Vec<(String, String, Request)>> = Arc::new(
                targets
                    .iter()
                    .map(|(e, t)| (e.clone(), t.clone(), self.json_req(e, &Value::Null, "", ctx, true)))
                    .collect(),
            );
            let upload =
                ctx.post(format!("{API}/asset/create")).header("Authorization", format!("Bot {}", self.token.expose()));
            let st2 = st.clone();
            plans.push(Plan::defer(move || {
                if st2.has_error.load(Ordering::SeqCst) { Plan::Done } else { attach_step(atts, 0, reqs, upload, st2) }
            }));
        }
        Plan::all(plans)
    }

}
