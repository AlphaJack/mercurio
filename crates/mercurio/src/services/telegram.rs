//! Telegram (`tgram://`): messages through the Telegram Bot API.
//!
//! Without a chat id the bot owner is detected with `getUpdates` once and kept in the persistent store (`bot_owner`).
//!
//! # Differences with Apprise
//!
//! - `?image=yes` posts the notify-type image by URL instead of uploading Apprise's bundled PNG. *intentional*
//! - Rich Message templates must be local files (`/path` or `file://`). *todo*
//! - HTML that Apprise's parser rejects is sent unreduced. *intentional*

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::env::Env;
use crate::asset::ImageSize;
use crate::convert::html;
use crate::convert::markup::{Markup, same};
use crate::error::Error;
use crate::http::{Multipart, Request, Response};
use crate::message::{Attachment, NotifyType};
use crate::parse::{parse_bool, parse_list, validate_regex_fmt};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef, UrlIdentifier};
use crate::url::{ParsedUrl, parse_url_unverified, unquote};
use super::_chat::apply_template_json;
use crate::util::{json_text, json_has_value, parse_int};
use crate::{FileOp, NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "telegram",
    name: "Telegram",
    schemes: &["tgram"],
    service_url: "https://telegram.org/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 4096, body_max_line_count: 0 },
    formats: &[NotifyFormat::Html, NotifyFormat::Markdown],
    attachments: true,
    templates: &[
        "{schema}://{bot_token}",
        "{schema}://{bot_token}/{targets}",
    ],
    tokens: &[
        Param::new("bot_token", "Bot Token").required().secret().pattern("^(bot)?(?P<key>[0-9]+:[a-z0-9_-]+)$"),
        Param::new("target_user", "Target Chat ID").pattern("^((-?[0-9]{1,32})|([a-z_-][a-z0-9_-]+))$"),
        Param::new("targets", "Targets").list("/").group(&["target_user"]),
    ],
    params: &[
        Param::new("album", "Group Photo/Video Attachments").bool(false),
        Param::new("content", "Content Placement").choice(&["before", "after"]).default("before"),
        Param::new("detect", "Detect Bot Owner").bool(true),
        Param::new("image", "Include Image").bool(false),
        Param::new("mdv", "Markdown Version").choice(&["v1", "v2"]).default("v1"),
        Param::new("preview", "Web Page Preview").bool(false),
        Param::new("silent", "Silent Notification").bool(false),
        Param::new("template", "Rich Message Template Path").secret(),
        Param::sets("to", &["targets"]),
        Param::new("topic", "Topic Thread ID").int().aliases(&["thread"]),
        Param::new("tokens", "Template Tokens").prefix(":"),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.telegram.org/bot";
const CAPTION_MAXLEN: usize = 1024;
const PHOTO_MAX_BYTES: usize = 10_000_000;
const FILE_MAX_BYTES: usize = 50_000_000;
const MEDIA_GROUP_MIN: usize = 2;
const MEDIA_GROUP_MAX: usize = 10;
const TEMPLATE_MAX_BYTES: u64 = 35_000;

#[derive(Debug, Clone, PartialEq, Eq)]
enum ChatId {
    Int(i64),
    /// `@name` or an id detected from `getUpdates` (stored as text).
    Str(String),
}

impl ChatId {
    fn text(&self) -> String {
        match self {
            ChatId::Int(i) => i.to_string(),
            ChatId::Str(s) => s.clone(),
        }
    }
    fn json(&self) -> Value {
        match self {
            ChatId::Int(i) => json!(i),
            ChatId::Str(s) => json!(s),
        }
    }
}

#[derive(Debug, Clone)]
struct Chat {
    id: ChatId,
    topic: Option<i64>,
}

impl Chat {
    /// The topic, unless it is 0 (the general thread).
    fn thread(&self) -> Option<i64> {
        self.topic.filter(|t| *t != 0)
    }
    fn label(&self) -> String {
        match self.thread() {
            Some(t) => format!("{}:{t}", self.id.text()),
            None => self.id.text(),
        }
    }
}

#[derive(Debug, Clone)]
struct Telegram {
    token: Secret,
    targets: Vec<Chat>,
    detect_owner: bool,
    include_image: bool,
    silent: bool,
    preview: bool,
    album: bool,
    topic: Option<i64>,
    content_before: bool,
    markdown_ver: &'static str,
    template: Option<String>,
    tokens: Vec<(String, String)>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    // Rewrite `tgram://[bot][user@]123:abc/...` into `tgram://123/abc/...`.
    let re = crate::regex!(
        r"(?i)^(?P<protocol>tgram://)(?:bot)?(?P<prefix>[a-z0-9_-]+(?::[a-z0-9_-]+)?@)?(?P<a>[0-9]+)(?::|%3A)+(?P<rest>.*)\n?$"
    );
    let caps = re.captures(&u.original).ok_or_else(|| SERVICE.err("unparseable Telegram URL"))?;
    let rebuilt = format!(
        "{}{}{}/{}",
        &caps["protocol"],
        caps.name("prefix").map(|m| m.as_str()).unwrap_or(""),
        &caps["a"],
        &caps["rest"]
    );
    let r = parse_url_unverified(&rebuilt).ok_or_else(|| SERVICE.err("unparseable Telegram URL"))?;
    let token_a = r.host();
    let mut entries = r.path_segments();
    if entries.is_empty() {
        return Err(SERVICE.err("the Telegram bot token is incomplete"));
    }
    let token_b = entries.remove(0);
    let mut targets_raw = entries;
    if let Some(to) = r.param_nonempty("to") {
        targets_raw.extend(parse_list([to]));
    }
    let raw_token = format!("{token_a}:{token_b}");
    let token = validate_regex_fmt(&raw_token, r"^(bot)?(?P<key>[0-9]+:[a-z0-9_-]+)$", "i", "{key}")
        .ok_or_else(|| SERVICE.err("the Telegram Bot Token specified is invalid"))?;

    let markdown_ver = {
        let m = SERVICE.raw(&r, "mdv").filter(|m| !m.is_empty()).unwrap_or(SERVICE.default_of("mdv")).to_lowercase();
        [("v1", "MARKDOWN"), ("1", "MARKDOWN"), ("v2", "MarkdownV2"), ("2", "MarkdownV2"), ("default", "MARKDOWN")]
            .iter()
            .find(|(k, _)| m.starts_with(k))
            .map(|(_, v)| *v)
            .unwrap_or("MARKDOWN")
    };

    let content = SERVICE.raw(&r, "content").filter(|c| !c.is_empty()).unwrap_or(SERVICE.default_of("content"));
    let content_before = match content.to_lowercase().as_str() {
        "before" => true,
        "after" => false,
        _ => return Err(SERVICE.err("the content placement specified is invalid")),
    };

    let topic_raw = r.param_nonempty("topic").or_else(|| r.param_nonempty("thread"));
    let topic = match topic_raw {
        None => None,
        Some(t) => Some(parse_int(t).ok_or_else(|| SERVICE.err("the Telegram Topic ID specified is invalid"))?),
    };

    let mut detect_owner = match SERVICE.raw(&r, "detect") {
        Some(v) => parse_bool(v, false),
        None => targets_raw.is_empty(),
    };

    let chat_re = crate::regex!(
        r"(?i)^(?:(?P<idno>-?[0-9]{1,32})|(?:@|%40)?(?P<name>[a-z_-][a-z0-9_-]+))(?:(?::|%3A)(?P<topic>[0-9]+))?$"
    );
    let mut targets = Vec::new();
    for t in parse_list(&targets_raw) {
        let Some(c) = chat_re.captures(&t) else {
            log::warn!("Telegram: dropped invalid chat/group");
            detect_owner = false;
            continue;
        };
        let chat_topic = match c.name("topic") {
            Some(m) => m.as_str().parse().ok().map(Some),
            None => Some(topic),
        };
        let id = match c.name("name") {
            Some(n) => Some(ChatId::Str(format!("@{}", n.as_str()))),
            None => c["idno"].parse().ok().map(ChatId::Int),
        };
        let (Some(id), Some(topic)) = (id, chat_topic) else {
            log::warn!("Telegram: dropped chat/group with an out-of-range id");
            detect_owner = false;
            continue;
        };
        targets.push(Chat { id, topic });
    }

    let template = match r.param_nonempty("template") {
        None => None,
        Some(t) => Some(template_path(&unquote(t))?),
    };

    Ok(Box::new(Telegram {
        token: Secret::new(token),
        targets,
        detect_owner,
        include_image: SERVICE.flag(&r, "image"),
        silent: SERVICE.flag(&r, "silent"),
        preview: SERVICE.flag(&r, "preview"),
        album: SERVICE.flag(&r, "album"),
        topic,
        content_before,
        markdown_ver,
        template,
        tokens: r.query_colon.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
    }))
}

/// Local path of a Rich Message template (`/path` or `file://path`).
fn template_path(t: &str) -> Result<String> {
    if let Some(rest) = t.strip_prefix("file://") {
        return Ok(unquote(rest.split('?').next().unwrap_or("")));
    }
    if crate::regex!(r"^[a-zA-Z0-9]+://").is_match(t) {
        return Err(SERVICE.err("only local Rich Message templates are supported"));
    }
    Ok(t.to_string())
}

/// Telegram endpoint and field for an attachment's MIME type.
fn mime_lookup(mime: &str) -> (&'static str, &'static str) {
    let m = mime.to_ascii_lowercase();
    if m.starts_with("image/gif") || m.starts_with("video/h264") {
        ("sendAnimation", "animation")
    } else if m.starts_with("image/") {
        ("sendPhoto", "photo")
    } else if m.starts_with("video/mp4") {
        ("sendVideo", "video")
    } else if m.starts_with("application/ogg") || m.starts_with("audio/ogg") {
        ("sendVoice", "voice")
    } else if m.starts_with("audio/mpeg") || m.starts_with("audio/mp4a-latm") {
        ("sendAudio", "audio")
    } else {
        ("sendDocument", "document")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Photo,
    Video,
    Single,
}

fn album_kind(a: &Attachment) -> Kind {
    let m = a.mime.to_lowercase();
    if m.starts_with("image/") && m != "image/gif" && a.data.len() <= PHOTO_MAX_BYTES {
        Kind::Photo
    } else if m == "video/mp4" && a.data.len() <= FILE_MAX_BYTES {
        Kind::Video
    } else {
        Kind::Single
    }
}

type Fields = Vec<(String, Value)>;

/// Everything a delivery needs, owned so continuations can hold it.
#[derive(Debug)]
struct Job {
    cfg: Telegram,
    app_id: String,
    env: Arc<dyn Env>,
    text: String,
    parse_mode: &'static str,
    title: String,
    body: String,
    kind: NotifyType,
    attachments: Vec<Attachment>,
    image_url: Option<String>,
    color: String,
    app_desc: String,
    app_url: String,
    first_piece: bool,
    /// The Rich Message template, or why it could not be loaded.
    template: std::result::Result<String, &'static str>,
}

fn status_ok(res: &Result<Response>) -> bool {
    matches!(res, Ok(r) if r.status == 200)
}

fn http_err(res: Result<Response>) -> Error {
    match res {
        Ok(r) => http_error(&r),
        Err(e) => e,
    }
}

/// [`Response::http_error`], with `parameters.retry_after` (seconds) as the wait when there is no `Retry-After` header.
fn http_error(r: &Response) -> Error {
    let hint = r.json().and_then(|v| v["parameters"]["retry_after"].as_u64()).filter(|s| *s > 0);
    r.rate_limited_or_http(hint.map(Duration::from_secs))
}

/// Send `req`; anything but 200 fails through [`http_error`].
fn send_ok(req: Request) -> Plan {
    Plan::http(req, |res| if status_ok(&res) { Plan::Done } else { Plan::Fail(http_err(res)) })
}

impl Job {
    fn url(&self, function: &str) -> String {
        format!("{NOTIFY_URL}{}/{function}", self.cfg.token.expose())
    }

    /// The request for one attachment: `None` when it is refused before any I/O.
    fn media_request(
        &self,
        chat: &Chat,
        thread: Option<i64>,
        mut payload: Fields,
        att_no: usize,
        document: bool,
    ) -> Option<Request> {
        let att = &self.attachments[att_no];
        let size = att.data.len();
        if size > FILE_MAX_BYTES {
            log::warn!("Telegram attachment is larger than the 50 MB upload limit");
            return None;
        }
        let (mut function, mut key) = mime_lookup(&att.mime);
        if document || (function == "sendPhoto" && size > PHOTO_MAX_BYTES) {
            (function, key) = ("sendDocument", "document");
        }
        payload.retain(|(k, _)| k != "chat_id");
        payload.push(("chat_id".into(), chat.id.json()));
        if let Some(t) = thread {
            payload.retain(|(k, _)| k != "message_thread_id");
            payload.push(("message_thread_id".into(), json!(t)));
        }
        let mut form = Multipart::with_env(self.env.as_ref());
        for (k, v) in &payload {
            form = form.text(k.clone(), json_text(v));
        }
        let name = if att.name.is_empty() { format!("file{:03}.dat", att_no + 1) } else { att.name.clone() };
        form = form.file(key, name, "", att.data.clone());
        Some(Request::post(self.url(function)).header("User-Agent", &self.app_id).multipart(form))
    }

    fn send_media(&self, chat: &Chat, thread: Option<i64>, payload: Fields, att_no: usize, document: bool) -> Plan {
        match self.media_request(chat, thread, payload, att_no, document) {
            Some(req) => send_ok(req),
            None => Plan::Fail(Error::Message("Telegram attachment is too large".into())),
        }
        .context("attachment")
    }

    fn caption(&self) -> Fields {
        vec![
            ("caption".into(), json!(self.text)),
            ("show_caption_above_media".into(), json!(self.cfg.content_before)),
            ("parse_mode".into(), json!(self.parse_mode)),
        ]
    }

    /// Send the attachments. `caption_thread` is the topic left on the shared caption by earlier targets.
    fn attachments_plan(self: &Arc<Self>, chat: &Chat, caption: Option<Fields>, caption_thread: Option<i64>) -> Plan {
        if self.cfg.album {
            return self.clone().album_plan(chat.clone(), 0, caption.unwrap_or_default());
        }
        let mut plans = Vec::new();
        for no in 0..self.attachments.len() {
            let att = &self.attachments[no];
            let title = if att.name.is_empty() { format!("file{:03}.dat", no + 1) } else { att.name.clone() };
            let (mut payload, thread) = match (&caption, no) {
                (Some(c), 0) => (c.clone(), chat.thread().or(caption_thread)),
                _ => (Vec::new(), chat.thread()),
            };
            payload.retain(|(k, _)| k != "title");
            payload.push(("title".into(), json!(title)));
            plans.push(self.send_media(chat, thread, payload, no, false));
        }
        Plan::chain(plans)
    }

    /// `_send_album_attachments` from attachment `no` on.
    fn album_plan(self: Arc<Self>, chat: Chat, no: usize, caption: Fields) -> Plan {
        let n = self.attachments.len();
        if no >= n {
            return Plan::Done;
        }
        let kinds: Vec<Kind> = self.attachments.iter().map(album_kind).collect();
        let mut end = no;
        let mut total = 0;
        while end < n
            && kinds[end] != Kind::Single
            && end - no < MEDIA_GROUP_MAX
            && total + self.attachments[end].data.len() <= FILE_MAX_BYTES
        {
            total += self.attachments[end].data.len();
            end += 1;
        }
        if end - no < MEDIA_GROUP_MIN {
            let end = end.max(no + 1);
            return self.retry_items(chat, no, end, caption);
        }
        let req = self.media_group_request(&chat, no, end, &kinds, &caption);
        let job = self.clone();
        Plan::http(req, move |res| match res {
            Ok(r) if r.status == 200 => job.album_plan(chat, end, Vec::new()),
            Ok(r) if r.status == 400 => job.retry_items(chat, no, end, caption),
            other => Plan::Fail(http_err(other)),
        })
        .context("attachment")
    }

    /// Send items `no..end` one at a time, then continue the album loop.
    fn retry_items(self: Arc<Self>, chat: Chat, no: usize, end: usize, caption: Fields) -> Plan {
        let mut plans = Vec::new();
        for idx in no..end {
            let payload = if idx == no { caption.clone() } else { Vec::new() };
            let kind = album_kind(&self.attachments[idx]);
            let first = self.media_request(&chat, chat.thread(), payload.clone(), idx, false);
            let job = self.clone();
            let c = chat.clone();
            plans.push(match first {
                None => Plan::Fail(Error::Message("Telegram attachment is too large".into())),
                Some(req) => Plan::http(req, move |res| {
                    if status_ok(&res) {
                        Plan::Done
                    } else if kind == Kind::Single {
                        Plan::Fail(http_err(res))
                    } else {
                        job.send_media(&c, c.thread(), payload, idx, true)
                    }
                }),
            }
            .context("attachment"));
        }
        let job = self.clone();
        plans.push(Plan::defer(move || job.album_plan(chat, end, Vec::new())));
        Plan::chain(plans)
    }

    fn media_group_request(&self, chat: &Chat, no: usize, end: usize, kinds: &[Kind], caption: &Fields) -> Request {
        let mut form = Multipart::with_env(self.env.as_ref()).text("chat_id", chat.id.text());
        form = form.text("disable_notification", self.cfg.silent.to_string());
        if let Some(t) = chat.thread() {
            form = form.text("message_thread_id", t.to_string());
        }
        let mut media = Vec::new();
        let mut files = Vec::new();
        for (i, idx) in (no..end).enumerate() {
            let att = &self.attachments[idx];
            let field = format!("file{i}");
            let mut item = Map::new();
            item.insert("type".into(), json!(if kinds[idx] == Kind::Video { "video" } else { "photo" }));
            item.insert("media".into(), json!(format!("attach://{field}")));
            if i == 0 {
                for (k, v) in caption {
                    item.insert(k.clone(), v.clone());
                }
            }
            media.push(Value::Object(item));
            let name = if att.name.is_empty() { format!("file{i:03}.dat") } else { att.name.clone() };
            files.push((field, name, att.mime.clone(), att.data.clone()));
        }
        form = form.text("media", Value::Array(media).to_string());
        for (field, name, mime, data) in files {
            form = form.file(field, name, mime, data);
        }
        Request::post(self.url("sendMediaGroup")).header("User-Agent", &self.app_id).multipart(form)
    }

    /// Image of the notify type, sent by URL; its outcome is ignored.
    fn image_plan(&self, chat: &Chat) -> Option<Plan> {
        if !self.cfg.include_image || !self.first_piece {
            return None;
        }
        let url = self.image_url.clone()?;
        let mut payload = json!({"chat_id": chat.id.json(), "photo": url});
        if let Some(t) = chat.thread() {
            payload["message_thread_id"] = json!(t);
        }
        let req = Request::post(self.url("SendPhoto"))
            .header("User-Agent", &self.app_id)
            .body(payload.to_string().into_bytes(), Some("application/json"));
        Some(Plan::http(req, |_| Plan::Done))
    }

    fn run(self: Arc<Self>, targets: Vec<Chat>) -> Plan {
        if targets.is_empty() {
            return Plan::Fail(Error::Message("there were no Telegram chat ids to notify".into()));
        }
        if self.cfg.template.is_some() {
            return self.rich(targets);
        }
        let has_attach = !self.attachments.is_empty();
        let has_body = !self.text.is_empty();
        let caption = (has_attach && has_body && self.text.chars().count() < CAPTION_MAXLEN).then(|| self.caption());
        let after = !has_body || caption.is_some() || !self.cfg.content_before;

        let mut leaked: Option<i64> = None;
        let mut plans = Vec::new();
        for chat in targets {
            let mut steps = Vec::new();
            if let Some(p) = self.image_plan(&chat) {
                steps.push(p);
            }
            let mut done = false;
            if has_attach && after {
                let carried = leaked;
                if caption.is_some() && !self.cfg.album {
                    leaked = chat.thread().or(leaked);
                }
                steps.push(self.attachments_plan(&chat, caption.clone(), carried));
                done = !has_body || caption.is_some();
            } else if caption.is_some() {
                done = true;
            }
            if !done {
                let mut payload = json!({
                    "disable_notification": self.cfg.silent,
                    "disable_web_page_preview": !self.cfg.preview,
                    "parse_mode": self.parse_mode,
                    "text": self.text,
                    "chat_id": chat.id.json(),
                });
                if let Some(t) = chat.thread() {
                    payload["message_thread_id"] = json!(t);
                }
                let req = Request::post(self.url("sendMessage"))
                    .header("User-Agent", &self.app_id)
                    .header("Content-Type", "application/json")
                    .body(payload.to_string().into_bytes(), None);
                let send = send_ok(req);
                steps.push(if has_attach { send.context("send") } else { send });
                if has_attach && !after {
                    steps.push(self.attachments_plan(&chat, None, None));
                }
            }
            let label = chat.label();
            plans.push(Plan::chain(steps).target(label));
        }
        Plan::all(plans)
    }

    /// `_gen_rich_payload`: load, fill and validate the template.
    fn rich_payload(&self) -> Result<Value> {
        let fail = |why: &str| Error::Service(format!("Telegram Rich Message template {why}"));
        let text = self.template.as_deref().map_err(|why| fail(why))?;

        let mut tokens: Vec<(String, String)> = self.cfg.tokens.clone();
        let image = if self.cfg.include_image { self.image_url.clone().unwrap_or_default() } else { String::new() };
        for (k, v) in [
            ("app_body", self.body.clone()),
            ("app_title", self.title.clone()),
            ("app_type", self.kind.as_str().to_string()),
            ("app_id", self.app_id.clone()),
            ("app_desc", self.app_desc.clone()),
            ("app_color", self.color.clone()),
            ("app_color_hex", self.color.clone()),
            ("app_image_url", image),
            ("app_url", self.app_url.clone()),
        ] {
            match tokens.iter_mut().find(|(tk, _)| tk == k) {
                Some(slot) => slot.1 = v,
                None => tokens.push((k.to_string(), v)),
            }
        }
        tokens.retain(|(k, _)| k != "app_mode");
        let content = apply_template_json(text, &tokens).ok_or_else(|| fail("references an unknown token"))?;
        let content: Value = serde_json::from_str(&content).map_err(|_| fail("contains invalid JSON"))?;
        let Some(obj) = content.as_object() else {
            return Err(fail("must be a JSON object"));
        };
        let blocks = obj.get("blocks").and_then(Value::as_array).filter(|b| !b.is_empty());
        let Some(blocks) = blocks else {
            return Err(fail("must contain a non-empty 'blocks' list"));
        };
        if !blocks.iter().all(|b| b.get("type").is_some_and(Value::is_string)) {
            return Err(fail("contains a block missing a 'type' string"));
        }
        Ok(content)
    }

    fn rich(self: Arc<Self>, targets: Vec<Chat>) -> Plan {
        Plan::defer(move || {
            let rich = match self.rich_payload() {
                Ok(v) => v,
                Err(e) => return Plan::Fail(e),
            };
            let plans = targets.into_iter().map(|chat| {
                let mut payload = json!({"chat_id": chat.id.json(), "rich_message": rich});
                if let Some(t) = chat.thread() {
                    payload["message_thread_id"] = json!(t);
                }
                if !self.cfg.preview {
                    payload["link_preview_options"] = json!({"is_disabled": true});
                }
                let req = Request::post(self.url("sendRichMessage"))
                    .header("User-Agent", &self.app_id)
                    .header("Content-Type", "application/json")
                    .body(payload.to_string().into_bytes(), None);
                let send = send_ok(req);
                let mut steps = vec![];
                if self.attachments.is_empty() {
                    steps.push(send);
                } else {
                    steps.push(send.context("send"));
                    steps.push(self.attachments_plan(&chat, None, None));
                }
                Plan::chain(steps).target(chat.label())
            });
            Plan::all(plans.collect::<Vec<_>>())
        })
    }
}

/// Bot owner id from a `getUpdates` response.
fn detect_owner(res: Result<Response>) -> std::result::Result<Value, Error> {
    let r = res?;
    if r.status != 200 {
        return Err(http_error(&r));
    }
    let fail = || Error::Service("failed to detect a Telegram user; send your bot a message first".into());
    let v = r.json().ok_or_else(fail)?;
    let obj = v.as_object().ok_or_else(fail)?;
    if !obj.get("ok").is_some_and(json_has_value) {
        return Err(fail());
    }
    let results = obj.get("result").and_then(Value::as_array).cloned().unwrap_or_default();
    for entry in results {
        if let Some(from) = entry.get("message").and_then(|m| m.get("from")) {
            let id = from.get("id").cloned().unwrap_or(json!(0));
            if !json_has_value(&id) {
                return Err(fail());
            }
            return Ok(id);
        }
    }
    Err(fail())
}

/// The tags Telegram accepts in HTML messages; headings become bold.
const TELEGRAM_HTML: html::Filter = html::Filter {
    tags: &[
        ("b", "b"),
        ("strong", "b"),
        ("i", "i"),
        ("em", "i"),
        ("u", "u"),
        ("ins", "u"),
        ("s", "s"),
        ("strike", "s"),
        ("del", "s"),
        ("tg-spoiler", "tg-spoiler"),
        ("tg-emoji", "tg-emoji"),
        ("a", "a"),
        ("code", "code"),
        ("pre", "pre"),
        ("blockquote", "blockquote"),
        ("h1", "b"),
        ("h2", "b"),
        ("h3", "b"),
        ("h4", "b"),
        ("h5", "b"),
        ("h6", "b"),
    ],
    attrs: &[("a", "href"), ("tg-emoji", "emoji-id")],
    // Telegram has no `<br>`.
    line_break: "\r\n",
    // Telegram renders a raw line break as a line break, so keep them.
    keep_newlines: true,
};

/// HTML reduced to the tags Telegram accepts; no-break and em spaces become plain spaces (Telegram has no entities for them).
pub fn html_to_telegram(body: &str) -> String {
    html::filter(body, &TELEGRAM_HTML).replace('\u{a0}', " ").replace('\u{2003}', "   ")
}

/// Legacy Telegram Markdown: `*bold*`, `_italic_`, code and `[text](url)`; it has no strike-through and escapes only `` ` * _ [ ``.
const TELEGRAM_V1: Markup = Markup {
    bold: ("*", "*"),
    italic: ("_", "_"),
    strike: ("", ""),
    code: ("`", "`"),
    code_block: ("```\n", "```"),
    heading_prefix: false,
    list_indent: "  ",
    link: crate::convert::markup::markdown_link,
    escape: |s| escape_chars(s, "`*_["),
    escape_code: same,
};

/// Telegram MarkdownV2: every reserved character outside markup is escaped.
const TELEGRAM_V2: Markup = Markup {
    bold: ("*", "*"),
    italic: ("_", "_"),
    strike: ("~", "~"),
    code: ("`", "`"),
    code_block: ("```\n", "```"),
    heading_prefix: false,
    list_indent: "  ",
    link: |text, url| format!("[{text}]({})", escape_chars(url, ")\\")),
    escape: |s| escape_chars(s, "_*[]()~`>#+-=|{}.!\\"),
    escape_code: |s| escape_chars(s, "`\\"),
};

fn escape_chars(s: &str, reserved: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if reserved.contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Markdown as Telegram Markdown (MarkdownV2 when `strict`).
pub fn commonmark_to_telegram(body: &str, strict: bool) -> String {
    crate::convert::markup::render(body, if strict { &TELEGRAM_V2 } else { &TELEGRAM_V1 })
}

impl Notify for Telegram {
    /// HTML is reduced to the tags Telegram accepts; CommonMark becomes the configured Telegram Markdown.
    fn convert(&self, body: &str, format: NotifyFormat) -> Option<String> {
        match format {
            NotifyFormat::Html => Some(html_to_telegram(body)),
            NotifyFormat::Markdown => Some(commonmark_to_telegram(body, self.markdown_ver == "MarkdownV2")),
            NotifyFormat::Text => None,
        }
    }

    fn files(&self, _: &Context<'_>) -> Vec<FileOp> {
        self.template.iter().flat_map(FileOp::local_file).collect()
    }

    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        // Rich Message templates take the caller's title and body, once.
        let (title, body) = match &self.template {
            Some(_) if msg.index > 0 => return Plan::Done,
            Some(_) => (msg.message.title.as_str(), msg.message.body.as_str()),
            None => (msg.title, msg.body),
        };
        // With `content=before`, attachments follow the last piece.
        let attachments = match (self.template.is_some(), self.content_before) {
            (true, _) => &msg.message.attachments[..],
            (false, true) if msg.index + 1 == msg.total => &msg.message.attachments[..],
            (false, true) => &[],
            (false, false) => msg.attachments,
        };
        let (text, parse_mode) = if msg.format == NotifyFormat::Markdown {
            (body.to_string(), self.markdown_ver)
        } else if msg.passthrough {
            // Undeclared input may be plain text or HTML: keep its line breaks, then reduce any tags to the ones Telegram accepts.
            let breaks = crate::regex!(r"(?i)(?:<br\s*/?>)?\r?\n").replace_all(body, "<br>");
            (html_to_telegram(&breaks), "HTML")
        } else {
            (body.to_string(), "HTML")
        };
        let job = Arc::new(Job {
            cfg: self.clone(),
            app_id: ctx.app_id().to_string(),
            env: ctx.env().clone(),
            text,
            parse_mode,
            title: title.to_string(),
            body: body.to_string(),
            kind: msg.kind,
            attachments: attachments.to_vec(),
            image_url: ctx.asset.image_url(msg.kind, ImageSize::Xy256),
            color: ctx.asset.color(msg.kind).to_string(),
            app_desc: ctx.app_desc().to_string(),
            app_url: ctx.app_url().to_string(),
            first_piece: msg.index == 0,
            template: match &self.template {
                Some(path) => ctx
                    .local_file(path, TEMPLATE_MAX_BYTES)
                    .and_then(|b| String::from_utf8(b.to_vec()).map_err(|_| "could not be read")),
                None => Err("could not be accessed"),
            },
        });
        if self.targets.is_empty() && self.detect_owner {
            let topic = job.cfg.topic;
            if let Some(id) = ctx.store.get("bot_owner").filter(json_has_value) {
                return job.run(vec![Chat { id: ChatId::Str(json_text(&id)), topic }]);
            }
            let store = ctx.store();
            let req = ctx.post(job.url("getUpdates")).header("Content-Type", "application/json");
            return Plan::http(req, move |res| match detect_owner(res) {
                Ok(id) => {
                    store.set("bot_owner", id.clone(), None);
                    job.run(vec![Chat { id: ChatId::Str(json_text(&id)), topic }])
                }
                Err(e) => Plan::Fail(e),
            })
            .context("owner lookup");
        }
        job.clone().run(self.targets.clone())
    }

    fn url_identifier(&self) -> UrlIdentifier {
        UrlIdentifier::parts(["tgram", self.token.expose()])
    }
}

#[cfg(test)]
#[expect(clippy::disallowed_methods, reason = "tests set up real files")]
mod tests {
    use super::*;
    use crate::testing::FakeTransport;
    use crate::{Asset, Message};

    #[test]
    fn rich_template_from_file() {
        #[expect(clippy::disallowed_methods, reason = "temporary directories need names unique across runs")]
        let unique = crate::env::system().random_hex(6);
        let dir = std::env::temp_dir().join(format!("mercurio-tgram-{unique}"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.json");
        std::fs::write(&path, r#"{"blocks":[{"type":"text","text":"{{app_title}}: {{ app_body }} {{name}}"}]}"#)
            .unwrap();
        let url = format!("tgram://123456789:abcdefg/12345?template={}&:name=x%C3%A9", path.display());
        let target = crate::parse(&url).unwrap();
        let fake = FakeTransport::new();
        let d = target.send(&Message::new("b\"ody").title("T"), &fake, &Asset::default());
        assert!(d.is_success(), "{d:?}");
        let reqs = fake.requests();
        assert_eq!(reqs.len(), 1);
        assert!(reqs[0].url.ends_with("/sendRichMessage"));
        let v: Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(v["chat_id"], json!(12345));
        assert_eq!(v["rich_message"]["blocks"][0]["text"], json!("T: b\"ody xé"));
        assert_eq!(v["link_preview_options"]["is_disabled"], json!(true));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn retry_waits_for_parameters_retry_after() {
        let target = crate::parse("tgram://123456789:abcdefg/12345?retry=1").unwrap();
        let fake = FakeTransport::new();
        let limited = r#"{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 7","parameters":{"retry_after":7}}"#;
        fake.respond(429, limited);
        fake.respond(200, r#"{"ok":true}"#);
        let attempts = target.deliver(&Message::new("b"), &fake, &Asset::default());
        assert_eq!(attempts.len(), 2);
        assert!(attempts[1].delivery.is_success(), "{attempts:?}");
        assert!(fake.sleeps().contains(&Duration::from_secs(7)), "{:?}", fake.sleeps());

        // Without the hint a 429 stays a plain HTTP error.
        let plain = FakeTransport::new();
        plain.respond(429, r#"{"ok":false,"error_code":429}"#);
        let once = crate::parse("tgram://123456789:abcdefg/12345").unwrap();
        let d = once.send(&Message::new("b"), &plain, &Asset::default());
        let err = d.outcomes[0].result.as_ref().unwrap_err();
        assert!(matches!(err.root(), Error::Http { status: 429, .. }), "{err:?}");
    }

    #[test]
    fn html_keeps_line_breaks_in_text() {
        // Single line breaks inside a paragraph survive.
        assert_eq!(html_to_telegram("<p>one\ntwo  \n\n  three</p>"), "one\r\ntwo\r\nthree");
        assert_eq!(html_to_telegram("a <b>b</b>\nc"), "a <b>b</b>\r\nc");
        assert_eq!(html_to_telegram("x  y"), "x y");
    }

    #[test]
    fn out_of_range_chat_id_is_dropped() {
        let target = crate::parse("tgram://123456789:abcdefg/-12345678901234567890123").unwrap();
        let fake = FakeTransport::new();
        let d = target.send(&Message::new("b"), &fake, &Asset::default());
        assert!(!d.is_success());
        assert!(fake.requests().is_empty());
    }
}
