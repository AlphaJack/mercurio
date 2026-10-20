//! Slack (`slack://`): messages through incoming webhooks (`hook`, `gov-hook`), bot tokens (`bot`, with e-mail lookups and the external file-upload flow) and workflow webhooks (`workflow`, `trigger`).
//!
//! E-mail lookups are cached for the lifetime of the parsed URL. On `?retry=`, channels that accepted the message are skipped and their remembered channel ids still receive the attachments that have not been delivered yet.
//!
//! # Differences
//!
//! - `?template=` only reads local files. *todo*

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use super::_chat::{TemplateSrc, apply_template_json, read_template, template_files, template_source};
use crate::asset::ImageSize;
use crate::http::{Method, Multipart, Request, Response};
use crate::parse::{is_email, parse_list, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::store::Memo;
use crate::url::{ParsedUrl, unquote};
use crate::util::{html_escape_noquote, json_text, json_has_value};
use crate::{Error, FileOp, NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "slack",
    name: "Slack",
    schemes: &["slack"],
    service_url: "https://slack.com/",
    parse,
    parse_native: Some(parse_native),
    limits: Limits { title_maxlen: 250, body_maxlen: 35000, body_max_line_count: 0 },
    formats: &[NotifyFormat::Markdown, NotifyFormat::Text],
    attachments: true,
    throttle: Duration::from_millis(1200),
    templates: &[
        "{schema}://{token_a}/{token_b}/{token_c}",
        "{schema}://{botname}@{token_a}/{token_b}/{token_c}",
        "{schema}://{token_a}/{token_b}/{token_c}/{targets}",
        "{schema}://{botname}@{token_a}/{token_b}/{token_c}/{targets}",
        "{schema}://{access_token}/",
        "{schema}://{access_token}/{targets}",
    ],
    tokens: &[
        Param::new("access_token", "OAuth Access Token").required().secret().pattern(r"^(?:xoxe\.)?xox[abp]-[A-Z0-9-]+$"),
        Param::new("botname", "Bot Name"),
        Param::new("target_channels", "Target Channel").prefix("#"),
        Param::new("target_email", "Target Email").email(),
        Param::new("target_encoded_id", "Target Encoded ID").prefix("+"),
        Param::new("target_user", "Target User").prefix("@"),
        Param::new("targets", "Targets").list("/").group(&["target_channels", "target_email", "target_encoded_id", "target_user"]),
        Param::new("token_a", "Token A").required().secret().pattern("^[A-Z0-9]+$"),
        Param::new("token_b", "Token B").required().secret().pattern("^[A-Z0-9]+$"),
        Param::new("token_c", "Token C").required().secret().pattern("^[A-Za-z0-9]+$"),
        Param::new("workflow_path", "Workflow Path").secret(),
    ],
    params: &[
        Param::new("blocks", "Use Blocks").bool(false),
        Param::new("footer", "Include Footer").bool(true),
        Param::new("image", "Include Image").bool(true),
        Param::new("mode", "Message Mode").choice(&["hook", "gov-hook", "bot", "workflow", "trigger"]),
        Param::new("template", "Template Path").secret(),
        Param::new("timestamp", "Include Timestamp").bool(true),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["access_token", "token_a", "token_b", "token_c"]),
        Param::new("tokens", "Template Tokens").prefix(":"),
    ],
};

const MAX_TEMPLATE_SIZE: u64 = 35000;
const MODES: [&str; 5] = ["hook", "gov-hook", "bot", "workflow", "trigger"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Webhook,
    WebhookGov,
    Bot,
    Workflow,
    Trigger,
}

impl Mode {
    fn from_prefix(s: &str) -> Option<Mode> {
        let m = MODES.iter().find(|m| m.starts_with(s))?;
        Some(match *m {
            "hook" => Mode::Webhook,
            "gov-hook" => Mode::WebhookGov,
            "bot" => Mode::Bot,
            "workflow" => Mode::Workflow,
            _ => Mode::Trigger,
        })
    }
    fn is_workflow(self) -> bool {
        matches!(self, Mode::Workflow | Mode::Trigger)
    }
}

#[derive(Debug)]
struct Slack {
    mode: Mode,
    /// Webhook URL, workflow URL or the bot `chat.postMessage` endpoint.
    url: String,
    access_token: Option<Secret>,
    user: Option<String>,
    /// `None` = no channel (webhook default).
    channels: Vec<Option<String>>,
    include_image: bool,
    include_footer: bool,
    include_timestamp: bool,
    use_blocks: bool,
    template: Option<TemplateSrc>,
    tokens: Vec<(String, String)>,
    lookup_cache: Arc<Mutex<BTreeMap<String, Value>>>,
}

fn delim_split(s: &str) -> Vec<String> {
    crate::regex!(r"[ \t\r\n,#\\/]+").split(s).filter(|x| !x.is_empty()).map(str::to_string).collect()
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let token = u.host();
    let mut entries = u.path_segments();
    let raw_mode = u.param("mode").unwrap_or("");
    let wf_mode = if raw_mode.is_empty() { None } else { Mode::from_prefix(raw_mode) };

    let mut workflow_path: Option<String> = None;
    let mut access_token: Option<String> = None;
    let (mut token_a, mut token_b, mut token_c): (Option<String>, Option<String>, Option<String>) = (None, None, None);
    let mut targets: Vec<String>;
    if wf_mode.is_some_and(Mode::is_workflow) {
        let mut parts = vec![token.clone()];
        parts.extend(entries);
        workflow_path = Some(parts.join("/"));
        targets = Vec::new();
    } else if token.starts_with("xo") {
        access_token = Some(token);
        targets = entries;
    } else {
        token_a = Some(token);
        token_b = if entries.is_empty() { None } else { Some(entries.remove(0)) };
        token_c = if entries.is_empty() { None } else { Some(entries.remove(0)) };
        targets = entries;
    }
    if let Some(t) = u.param_nonempty("token") {
        let mut e = delim_split(&unquote(t));
        if e.first().is_some_and(|x| x.starts_with("xo")) {
            access_token = Some(e.remove(0));
            (token_a, token_b, token_c) = (None, None, None);
        } else {
            access_token = None;
            let mut it = e.into_iter();
            (token_a, token_b, token_c) = (it.next(), it.next(), it.next());
        }
    }
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(delim_split(&unquote(to)));
    }
    let include_image = SERVICE.flag_strict(u, "image");
    let include_timestamp = SERVICE.flag_strict(u, "timestamp");
    let mut use_blocks = SERVICE.flag(u, "blocks");
    let include_footer = SERVICE.flag_strict(u, "footer");
    let mode_arg = SERVICE.text(u, "mode");
    let template = SERVICE.text(u, "template");

    let explicit = mode_arg.as_deref().filter(|m| !m.is_empty());
    let mut mode = match explicit {
        Some(m) => Mode::from_prefix(m).ok_or_else(|| SERVICE.err("the Slack mode specified is invalid"))?,
        None if workflow_path.is_some() => Mode::Workflow,
        None if access_token.as_deref().is_some_and(|t| !t.is_empty()) => Mode::Bot,
        None => Mode::Webhook,
    };

    let url;
    let mut bot_token = None;
    if mode.is_workflow() {
        let path: Vec<String> =
            workflow_path.as_deref().unwrap_or("").split('/').filter(|s| !s.is_empty()).map(str::to_string).collect();
        if explicit.is_some() {
            let expected = if mode == Mode::Workflow { 4 } else { 3 };
            if path.len() != expected {
                return Err(SERVICE.err(format!("a Slack {mode:?} URL requires exactly {expected} path segments")));
            }
        } else {
            mode = match path.len() {
                4 => Mode::Workflow,
                3 => Mode::Trigger,
                _ => return Err(SERVICE.err("a Slack Workflow URL requires exactly 3 or 4 path segments")),
            };
        }
        let base = if mode == Mode::Trigger {
            "https://hooks.slack.com/triggers"
        } else {
            "https://hooks.slack.com/workflows"
        };
        url = format!("{base}/{}", path.join("/"));
    } else if matches!(mode, Mode::Webhook | Mode::WebhookGov) {
        let check = |t: &Option<String>, re: &str, which: &str| {
            t.as_deref()
                .and_then(|t| validate_regex(t, re, "i", true))
                .ok_or_else(|| SERVICE.err(format!("an invalid Slack ({which}) Token was specified")))
        };
        let a = check(&token_a, r"^[A-Z0-9]+$", "first")?;
        let b = check(&token_b, r"^[A-Z0-9]+$", "second")?;
        let c = check(&token_c, r"^[A-Za-z0-9]+$", "third")?;
        let base = if mode == Mode::Webhook {
            "https://hooks.slack.com/services"
        } else {
            "https://hooks.slack-gov.com/services"
        };
        url = format!("{base}/{a}/{b}/{c}");
    } else {
        let t = access_token
            .as_deref()
            .and_then(|t| validate_regex(t, r"^(?:xoxe\.)?xox[abp]-[A-Z0-9-]+$", "i", true))
            .ok_or_else(|| SERVICE.err("an invalid Slack OAuth Access Token was specified"))?;
        bot_token = Some(Secret::new(t));
        url = "https://slack.com/api/chat.postMessage".to_string();
    }

    let mut channels: Vec<Option<String>> = parse_list(targets).into_iter().map(Some).collect();
    if channels.is_empty() {
        channels.push(if mode == Mode::Bot { Some("#general".into()) } else { None });
    }
    let template = match template {
        Some(t) => Some(template_source(&t).ok_or_else(|| SERVICE.err("the Slack template could not be loaded"))?),
        None => None,
    };
    if template.is_some() {
        use_blocks = true;
    }
    Ok(Box::new(Slack {
        mode,
        url,
        access_token: bot_token,
        user: u.user().filter(|s| !s.is_empty()),
        channels,
        include_image,
        include_footer,
        include_timestamp,
        use_blocks,
        template,
        tokens: u.query_colon.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        lookup_cache: Arc::new(Mutex::new(BTreeMap::new())),
    }))
}

fn parse_native(url: &str) -> Option<String> {
    let wf = crate::regex!(
        r"(?i)^https?://hooks\.slack\.com/(?P<wf_type>workflows|triggers)/(?P<path>[A-Z0-9][A-Z0-9/_-]+)/?(?P<params>\?.+)?\n?\z"
    );
    if let Some(c) = wf.captures(url) {
        let mode = if c["wf_type"].eq_ignore_ascii_case("triggers") { "trigger" } else { "workflow" };
        let params = c.name("params").map_or("", |m| m.as_str());
        let sep = if params.is_empty() { "?" } else { "&" };
        return Some(format!("slack://{}/{params}{sep}mode={mode}", c["path"].trim_matches('/')));
    }
    let hook = crate::regex!(
        r"(?i)^https?://(?P<host>hooks\.slack(?P<gov>-gov)?\.com)/services/(?P<a>[A-Z0-9]+)/(?P<b>[A-Z0-9]+)/(?P<c>[A-Z0-9]+)/?(?P<params>\?.+)?\n?\z"
    );
    let c = hook.captures(url)?;
    let mut params = c.name("params").map_or("", |m| m.as_str()).to_string();
    if c.name("gov").is_some() {
        let sep = if params.is_empty() { "?" } else { "&" };
        params = format!("{params}{sep}mode=gov-hook");
    }
    Some(format!("slack://{}/{}/{}/{params}", &c["a"], &c["b"], &c["c"]))
}

/// Replace every case-insensitive occurrence of `needle` with the literal `repl`.
fn sub_literal_ci(body: &str, needle: &str, repl: &str) -> Option<String> {
    let re = regex::Regex::new(&format!("(?i){}", regex::escape(needle))).ok()?;
    Some(re.replace_all(body, regex::NoExpand(repl)).into_owned())
}

/// `_re_formatting_rules.sub(...)`; `None` on the unmapped `"\r*\n"` (KeyError).
fn escape_formatting(s: &str) -> Option<String> {
    if s.contains("\r*\n") {
        return None;
    }
    Some(s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;"))
}

/// Slack-ify `<!channel>`, `<@user>` and `<url|label>` references in a passthrough Markdown body.
fn slack_links(body: &str) -> Option<String> {
    let mut body = escape_formatting(body)?;
    let channel = crate::regex!(
        r"(?i)(?P<match>(?:<|&lt;)?[ \t]*!(?P<channel>[^| \n]+)(?:[ \t]*\|[ \t]*(?:(?P<val>[^\n]+?)[ \t]*)?(?:>|&gt;)|(?:>|&gt;)))"
    );
    let user = crate::regex!(
        r"(?i)(?P<match>(?:<|&lt;)?[ \t]*@(?P<userid>[^| \n]+)(?:[ \t]*\|[ \t]*(?:(?P<val>[^\n]+?)[ \t]*)?(?:>|&gt;)|(?:>|&gt;)))"
    );
    let url = crate::regex!(
        r"(?i)(?P<match>(?:<|&lt;)?[ \t]*(?P<url>(?:https?|mailto)://[^| \n]+)(?:[ \t]*\|[ \t]*(?:(?P<val>[^\n]+?)[ \t]*)?(?:>|&gt;)|(?:>|&gt;)))"
    );
    let strip = |s: &str| s.trim().to_string();
    for (re, kind) in [(channel, 0), (user, 1), (url, 2)] {
        let found: Vec<(String, String, String)> = re
            .captures_iter(&body)
            .map(|c| {
                (c[1].to_string(), c[2].to_string(), c.name("val").map_or(String::new(), |m| m.as_str().to_string()))
            })
            .collect();
        for (m, target, val) in found {
            let desc = strip(&val);
            let repl = match kind {
                0 => {
                    let t = strip(&target);
                    if desc.is_empty() { format!("<!{t}>") } else { format!("<!{t}|{desc}>") }
                }
                1 => {
                    let t = strip(&target);
                    if desc.is_empty() { format!("<@{t}>") } else { format!("<@{t}|{desc}>") }
                }
                _ => {
                    let t = target.replace("&amp;", "&");
                    if desc.is_empty() { format!("<{t}>") } else { format!("<{t}|{desc}>") }
                }
            };
            body = sub_literal_ci(&body, &m, &repl)?;
        }
    }
    Some(body)
}

/// Outcome of one Slack API call.
enum Sent {
    Ok(Value),
    Failed(Error),
    /// Unexpected response shape: abort the whole notification.
    Unexpected,
}

fn check(mode: Mode, res: Result<Response>) -> Sent {
    let r = match res {
        Ok(r) => r,
        Err(e) => return Sent::Failed(e),
    };
    let response = r.json().unwrap_or_else(|| json!({"ok": false}));
    let status_okay = match mode {
        Mode::Bot => {
            let a = if json_has_value(&response) {
                match response.as_object() {
                    Some(o) => o.get("ok").is_some_and(json_has_value),
                    None => return Sent::Unexpected,
                }
            } else {
                false
            };
            a || r.body.windows(2).any(|w| w == b"OK")
        }
        Mode::Workflow | Mode::Trigger => r.status == 200,
        Mode::Webhook | Mode::WebhookGov => r.body == b"ok",
    };
    if r.status != 200 || !status_okay {
        return Sent::Failed(r.http_error());
    }
    Sent::Ok(response)
}

/// Per-send shared state.
#[derive(Debug, Default)]
struct Run {
    aborted: AtomicBool,
    /// `(message key, channel id)` of channels that accepted the message (for the attachment phase).
    channel_ids: Mutex<Vec<(String, Value)>>,
    /// Shared by the retry attempts of this notification.
    memo: Memo,
}

fn message_key(key: &str) -> String {
    format!("message:{key}")
}

fn channel_key(key: &str) -> String {
    format!("channel:{key}")
}

fn attachment_key(no: usize, key: &str) -> String {
    format!("attachment:{no}:{key}")
}

impl Slack {
    fn request(&self, method: Method, url: &str, ua: &str, json_body: Option<&Value>) -> Request {
        let mut req = Request::new(method, url).header("User-Agent", ua).header("Accept", "application/json");
        if let Some(b) = json_body {
            req = req.header("Content-Type", "application/json; charset=utf-8").json(b);
        }
        if let Some(t) = &self.access_token
            && self.mode == Mode::Bot
        {
            req = req.header("Authorization", format!("Bearer {}", t.expose()));
        }
        req
    }

    fn gen_template(&self, src: &TemplateSrc, msg: &Prepared<'_>, ctx: &Context<'_>) -> Option<Value> {
        let text = read_template(ctx, src, MAX_TEMPLATE_SIZE)?;
        let image = if self.include_image { ctx.asset.image_url(msg.kind, ImageSize::Xy72) } else { None };
        let mut tokens = self.tokens.clone();
        let color = ctx.asset.color(msg.kind).to_string();
        for (k, v) in [
            ("app_body", msg.body.to_string()),
            ("app_title", msg.title.to_string()),
            ("app_type", msg.kind.as_str().to_string()),
            ("app_id", ctx.app_id().to_string()),
            ("app_desc", ctx.app_desc().to_string()),
            ("app_color", color.clone()),
            ("app_color_hex", color),
            ("app_image_url", image.unwrap_or_default()),
            ("app_url", ctx.app_url().to_string()),
        ] {
            tokens.retain(|(key, _)| key != k);
            tokens.push((k.to_string(), v));
        }
        let content: Value = serde_json::from_str(&apply_template_json(&text, &tokens)?).ok()?;
        let blocks = content.get("blocks").and_then(Value::as_array).filter(|b| !b.is_empty())?;
        if !blocks.iter().all(|b| b.get("type").is_some_and(Value::is_string)) {
            return None;
        }
        content.is_object().then_some(content)
    }

    fn payload(&self, msg: &Prepared<'_>, body: &str, ctx: &Context<'_>) -> std::result::Result<Value, Error> {
        let unsupported = || Error::Message("unsupported formatting sequence in message".into());
        let image = if self.include_image { ctx.asset.image_url(msg.kind, ImageSize::Xy72) } else { None };
        let color = ctx.asset.color(msg.kind);
        if self.use_blocks {
            if let Some(src) = &self.template {
                let content = self
                    .gen_template(src, msg, ctx)
                    .ok_or_else(|| Error::Message("the Slack template could not be applied".into()))?;
                return Ok(json!({"attachments": [content]}));
            }
            let fmt = if msg.format == NotifyFormat::Markdown { "mrkdwn" } else { "plain_text" };
            let mut blocks = vec![json!({"type": "section", "text": {"type": fmt, "text": body}})];
            if !msg.title.is_empty() {
                blocks.insert(
                    0,
                    json!({"type": "header", "text": {"type": "plain_text", "text": html_escape_noquote(msg.title), "emoji": true}}),
                );
            }
            let mut payload = json!({});
            if self.include_footer {
                let mut elements = vec![json!({"type": fmt, "text": ctx.app_id()})];
                if let Some(img) = &image {
                    payload["icon_url"] = json!(img);
                    elements.insert(0, json!({"type": "image", "image_url": img, "alt_text": msg.kind.as_str()}));
                }
                blocks.push(json!({"type": "context", "elements": elements}));
            }
            payload["attachments"] = json!([{"blocks": blocks, "color": color}]);
            return Ok(payload);
        }
        let body = if msg.format == NotifyFormat::Markdown && msg.passthrough {
            slack_links(body).ok_or_else(unsupported)?
        } else {
            body.to_string()
        };
        let title = escape_formatting(msg.title).ok_or_else(unsupported)?;
        let mut attachment = json!({"title": title, "text": body, "color": color});
        let mut payload = json!({"mrkdwn": msg.format == NotifyFormat::Markdown});
        if let Some(img) = &image {
            payload["icon_url"] = json!(img);
        }
        if self.include_footer {
            if let Some(img) = &image {
                attachment["footer_icon"] = json!(img);
            }
            attachment["footer"] = json!(ctx.app_id());
            if self.include_timestamp {
                attachment["ts"] = json!(crate::time::unix_time_ms() as f64 / 1000.0);
            }
        }
        payload["attachments"] = json!([attachment]);
        Ok(payload)
    }

    /// Resolve an e-mail to a user id (`lookup_userid`), then continue.
    fn lookup(&self, email: String, ua: String, run: Arc<Run>, k: impl FnOnce(Value) -> Plan + Send + 'static) -> Plan {
        if self.mode != Mode::Bot {
            return Plan::Fail(Error::Message("e-mails can only be resolved in bot mode".into()));
        }
        let cache = self.lookup_cache.clone();
        let bearer = format!("Bearer {}", self.access_token.as_ref().map_or("", Secret::expose));
        Plan::defer(move || {
            if run.aborted.load(Ordering::SeqCst) {
                return Plan::Done;
            }
            if let Some(v) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(&email).cloned() {
                return k(v);
            }
            let req = Request::get("https://slack.com/api/users.lookupByEmail")
                .header("User-Agent", &ua)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", bearer)
                .query(&[("email", email.as_str())]);
            Plan::http(req, move |res| {
                let r = match res {
                    Ok(r) => r,
                    Err(e) => return Plan::Fail(e),
                };
                let response = r.json().unwrap_or_else(|| json!({"ok": false}));
                let ok = if json_has_value(&response) {
                    match response.as_object() {
                        Some(o) => o.get("ok").is_some_and(json_has_value),
                        None => {
                            run.aborted.store(true, Ordering::SeqCst);
                            return Plan::Fail(Error::service("unexpected Slack lookup response"));
                        }
                    }
                } else {
                    false
                };
                if r.status != 200 || !ok {
                    return Plan::Fail(r.http_error());
                }
                let Some(id) = response.get("user").and_then(|u| u.as_object()).and_then(|u| u.get("id")).cloned()
                else {
                    run.aborted.store(true, Ordering::SeqCst);
                    return Plan::Fail(Error::service("unexpected Slack lookup response"));
                };
                cache.lock().unwrap_or_else(|e| e.into_inner()).insert(email, id.clone());
                k(id)
            })
            .context("user lookup")
        })
    }

    fn post_message(&self, payload: Value, ua: &str, run: Arc<Run>, track: bool, key: String) -> Plan {
        let req = self.request(Method::Post, &self.url, ua, Some(&payload));
        let mode = self.mode;
        let plan = Plan::defer(move || {
            if run.aborted.load(Ordering::SeqCst) {
                return Plan::Done;
            }
            Plan::http(req, move |res| match check(mode, res) {
                Sent::Unexpected => {
                    run.aborted.store(true, Ordering::SeqCst);
                    Plan::Fail(Error::service("unexpected Slack response"))
                }
                Sent::Failed(e) => Plan::Fail(e),
                Sent::Ok(resp) if !json_has_value(&resp) => Plan::Fail(Error::service("empty Slack response")),
                Sent::Ok(resp) => {
                    let channel_id = resp.get("channel").cloned().filter(json_has_value);
                    if let Some(id) = &channel_id {
                        run.memo.remember(&channel_key(&key), id.clone());
                    }
                    run.memo.mark_delivered(&message_key(&key));
                    match channel_id {
                        Some(id) => {
                            run.channel_ids.lock().unwrap_or_else(|e| e.into_inner()).push((key, id));
                            Plan::Done
                        }
                        None if track => Plan::Fail(Error::service("Slack did not identify the attachment channel")),
                        None => Plan::Done,
                    }
                }
            })
        });
        // A lone post needs no step name; with uploads it is one of several.
        if track { plan.context("post") } else { plan }
    }

    fn upload_attachments(&self, msg: &Prepared<'_>, ua: &str, run: Arc<Run>) -> Plan {
        let mode = self.mode;
        let steps: Vec<Plan> = msg
            .attachments
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let filename = if a.name.is_empty() { format!("file{:03}.dat", i + 1) } else { a.name.clone() };
                let get = self
                    .request(Method::Get, "https://slack.com/api/files.getUploadURLExternal", ua, Some(&json!({})))
                    .query(&[("filename", filename.as_str()), ("length", a.data.len().to_string().as_str())]);
                let upload_tpl = self.request(Method::Post, "", ua, None);
                let complete_tpl = self.request(
                    Method::Post,
                    "https://slack.com/api/files.completeUploadExternal",
                    ua,
                    Some(&json!({})),
                );
                let (name, data) = (a.name.clone(), a.data.clone());
                let run = run.clone();
                let no = i + 1;
                Plan::defer(move || {
                    let pending: Vec<(String, Value)> = run
                        .channel_ids
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .iter()
                        .filter(|(k, _)| !run.memo.is_delivered(&attachment_key(no, k)))
                        .cloned()
                        .collect();
                    if pending.is_empty() {
                        return Plan::Done;
                    }
                    Plan::http(get, move |res| {
                        let resp = match check(mode, res) {
                            Sent::Ok(r) => r,
                            Sent::Failed(e) => return Plan::Fail(e),
                            Sent::Unexpected => return Plan::Fail(Error::service("unexpected Slack response")),
                        };
                        let file_id = resp.get("file_id").cloned().filter(json_has_value);
                        let upload_url = resp.get("upload_url").cloned().filter(json_has_value);
                        let (Some(file_id), Some(upload_url)) = (file_id, upload_url) else {
                            return Plan::Fail(Error::service("Slack did not return an upload URL"));
                        };
                        let mut upload = upload_tpl;
                        upload.url = json_text(&upload_url);
                        let upload = upload.multipart(Multipart::new().file("file", name.clone(), "", data));
                        Plan::http(upload, move |res| {
                            match check(mode, res) {
                                Sent::Ok(r) if json_has_value(&r) => {}
                                Sent::Ok(_) => return Plan::Fail(Error::service("empty Slack response")),
                                Sent::Failed(e) => return Plan::Fail(e),
                                Sent::Unexpected => return Plan::Fail(Error::service("unexpected Slack response")),
                            }
                            Plan::chain(pending.into_iter().map(|(key, cid)| {
                                let payload = json!({"files": [{"id": file_id, "title": name}], "channel_id": cid});
                                let req = complete_tpl.clone().json(&payload);
                                let run = run.clone();
                                Plan::http(req, move |res| match check(mode, res) {
                                    Sent::Ok(r) if r.get("files").is_some_and(json_has_value) => {
                                        run.memo.mark_delivered(&attachment_key(no, &key));
                                        Plan::Done
                                    }
                                    Sent::Ok(_) => Plan::Fail(Error::service("Slack did not complete the upload")),
                                    Sent::Failed(e) => Plan::Fail(e),
                                    Sent::Unexpected => Plan::Fail(Error::service("unexpected Slack response")),
                                })
                                .context("upload complete")
                            }))
                        })
                        .context("upload")
                    })
                    .context("upload url")
                })
            })
            .collect();
        Plan::defer(move || {
            if run.aborted.load(Ordering::SeqCst)
                || run.channel_ids.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
            {
                return Plan::Done;
            }
            Plan::chain(steps)
        })
    }
}

/// Markdown as Slack `mrkdwn`.
pub fn commonmark_to_slack(body: &str) -> String {
    super::_chat_markup::render(body, &super::_chat_markup::ANCHOR)
}

impl Notify for Slack {
    /// Markdown becomes `mrkdwn`; plain text escapes `&`, `<` and `>`.
    fn convert(&self, body: &str, format: NotifyFormat) -> Option<String> {
        match format {
            NotifyFormat::Text => Some(html_escape_noquote(body)),
            NotifyFormat::Markdown => Some(commonmark_to_slack(body)),
            NotifyFormat::Html => None,
        }
    }

    fn files(&self, _: &Context<'_>) -> Vec<FileOp> {
        template_files(self.template.as_ref())
    }

    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let ua = ctx.app_id().to_string();
        let body = msg.body.to_string();

        if self.mode.is_workflow() {
            let payload = match &self.template {
                Some(src) => match self.gen_template(src, msg, ctx) {
                    Some(p) => p,
                    None => return Plan::Fail(Error::Message("the Slack template could not be applied".into())),
                },
                None => {
                    json!({"text": if msg.title.is_empty() { body.clone() } else { format!("{}: {body}", msg.title) }})
                }
            };
            let req = self.request(Method::Post, &self.url, &ua, Some(&payload));
            let mode = self.mode;
            return Plan::http(req, move |res| match check(mode, res) {
                Sent::Ok(_) => Plan::Done,
                Sent::Failed(e) => Plan::Fail(e),
                Sent::Unexpected => Plan::Fail(Error::service("unexpected Slack response")),
            });
        }

        let mut payload = match self.payload(msg, &body, ctx) {
            Ok(p) => p,
            Err(e) => return Plan::Fail(e),
        };
        if let Some(u) = &self.user {
            payload["username"] = json!(u);
        }

        let track = !msg.attachments.is_empty() && self.mode == Mode::Bot;
        let run = Arc::new(Run { memo: ctx.memo.clone(), ..Run::default() });
        let channel_re = crate::regex!(r"(?i)^(?P<channel>[+#@]?[A-Z0-9_-]{1,32})(:(?P<thread_ts>[0-9.]+))?$");
        let mut plans = Vec::new();
        let mut thread_ts: Option<String> = None;
        for channel in &self.channels {
            // A retry skips channels that took the message; their channel ids still get the pending attachments.
            let key = channel.clone().unwrap_or_default();
            if ctx.memo.is_delivered(&message_key(&key)) {
                let plan = match ctx.memo.recall(&channel_key(&key)) {
                    Some(id) => {
                        run.channel_ids.lock().unwrap_or_else(|e| e.into_inner()).push((key.clone(), id));
                        Plan::Done
                    }
                    None if track => Plan::Fail(Error::service("Slack did not identify the attachment channel")),
                    None => Plan::Done,
                };
                plans.push(match channel {
                    Some(c) => plan.target(c.clone()),
                    None => plan,
                });
                continue;
            }
            let Some(channel) = channel else {
                plans.push(self.post_message(payload.clone(), &ua, run.clone(), track, key));
                continue;
            };
            if let Some(email) = is_email(channel) {
                let mut p = payload.clone();
                if let Some(ts) = &thread_ts {
                    p["thread_ts"] = json!(ts);
                }
                let (this_ua, this_run) = (ua.clone(), run.clone());
                let poster = PostCtx::from(self);
                let plan = self.lookup(email.full_email, ua.clone(), run.clone(), move |id| {
                    if !json_has_value(&id) {
                        return Plan::Fail(Error::service("Slack user lookup returned no id"));
                    }
                    p["channel"] = id;
                    let post = poster.post(p, &this_ua, this_run, track, key);
                    // With attachments, `post_message` already names the step.
                    if track { post } else { post.context("post") }
                });
                plans.push(plan.target(channel.clone()));
                continue;
            }
            let Some(c) = channel_re.captures(channel) else {
                plans.push(Plan::Fail(Error::Message("invalid Slack target".into())).target(channel.clone()));
                continue;
            };
            thread_ts = c.name("thread_ts").map(|m| m.as_str().to_string());
            let name = &c["channel"];
            let target = if let Some(id) = name.strip_prefix('+') {
                id.to_string()
            } else if name.starts_with('@') || name.starts_with('#') {
                name.to_string()
            } else {
                format!("#{name}")
            };
            let mut p = payload.clone();
            p["channel"] = json!(target);
            if let Some(ts) = &thread_ts {
                p["thread_ts"] = json!(ts);
            }
            plans.push(self.post_message(p, &ua, run.clone(), track, key).target(channel.clone()));
        }
        if track {
            plans.push(self.upload_attachments(msg, &ua, run));
        }
        if plans.len() == 1 { plans.pop().unwrap_or(Plan::Done) } else { Plan::all(plans) }
    }

}

/// What `post_message` needs, detached from `&Slack` for continuations.
struct PostCtx {
    mode: Mode,
    url: String,
    access_token: Option<Secret>,
}

impl PostCtx {
    fn from(s: &Slack) -> Self {
        PostCtx { mode: s.mode, url: s.url.clone(), access_token: s.access_token.clone() }
    }

    fn post(self, payload: Value, ua: &str, run: Arc<Run>, track: bool, key: String) -> Plan {
        let slack = Slack {
            mode: self.mode,
            url: self.url,
            access_token: self.access_token,
            user: None,
            channels: Vec::new(),
            include_image: false,
            include_footer: false,
            include_timestamp: false,
            use_blocks: false,
            template: None,
            tokens: Vec::new(),
            lookup_cache: Arc::default(),
        };
        slack.post_message(payload, ua, run, track, key)
    }
}
