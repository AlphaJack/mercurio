//! Fluxer (`fluxer://`, `fluxers://`): messages to a Fluxer channel through a webhook.
//!
//! Cloud: `fluxer://[botname@]{webhook_id}/{webhook_token}`. Self-hosted: `fluxers://[botname@]{host}[:port][/path]/{webhook_id}/{webhook_token}` (`/api/` is the default path, `?path=/` selects the host root).

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::asset::ImageSize;
use crate::http::{Multipart, Request};
use crate::message::Attachment;
use crate::parse::{is_hostname, is_ipaddr, parse_list, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::util::parse_int;
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "fluxer",
    name: "Fluxer",
    schemes: &["fluxer", "fluxers"],
    service_url: "https://fluxer.app/",
    parse,
    parse_native: Some(parse_native),
    // Title and body share one 2000-character field.
    limits: Limits { title_maxlen: 250, body_maxlen: 1750, body_max_line_count: 0 },
    formats: &[NotifyFormat::Text],
    attachments: true,
    templates: &[
        "{schema}://{webhook_id}/{webhook_token}",
        "{schema}://{host}/{webhook_id}/{webhook_token}",
        "{schema}://{host}:{port}/{webhook_id}/{webhook_token}",
        "{schema}://{host}{path}{webhook_id}/{webhook_token}",
        "{schema}://{host}:{port}{path}{webhook_id}/{webhook_token}",
        "{schema}://{botname}@{webhook_id}/{webhook_token}",
        "{schema}://{botname}@{host}:{port}/{webhook_id}/{webhook_token}",
        "{schema}://{botname}@{host}:{port}{path}{webhook_id}/{webhook_token}",
    ],
    tokens: &[
        Param::new("botname", "Bot Name"),
        Param::new("host", "Hostname"),
        Param::new("path", "Path").default("/api/"),
        Param::new("port", "Port").port(),
        Param::new("webhook_id", "Webhook ID").required().secret().pattern("^[0-9]{10,}$"),
        Param::new("webhook_token", "Webhook Token").required().secret().pattern(r"^[A-Za-z0-9_\-]{16,}$"),
    ],
    params: &[
        Param::new("avatar", "Avatar Image").bool(true),
        Param::new("avatar_url", "Avatar URL"),
        Param::new("fields", "Use Fields").bool(true),
        Param::new("flags", "Discord Flags").int().min(0),
        Param::new("footer", "Display Footer").bool(false),
        Param::new("footer_logo", "Footer Logo").bool(true),
        Param::new("href", "URL").aliases(&["url"]),
        Param::new("image", "Include Image").bool(false),
        Param::new("mode", "Mode").choice(&["cloud", "private"]).default("cloud").inferred(),
        Param::sets("name", &["botname"]),
        Param::sets("path", &["path"]),
        Param::new("ping", "Ping Users/Roles").list(", "),
        Param::new("thread", "Thread ID"),
        Param::new("thread_name", "Thread Name"),
        Param::new("tts", "Text To Speech").bool(false),
    ],
    ..ServiceDef::DEFAULTS
};

const CLOUD_NOTIFY_HOST: &str = "https://api.fluxer.app";
const DEFAULT_PRIVATE_PATH: &str = "/api/";
const MAX_FIELDS: usize = 10;
const FIELD_NAME_MAXLEN: usize = 256;
const FIELD_VALUE_MAXLEN: usize = 1024;
const DEFAULT_DELAY_SEC: f64 = 1.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Cloud,
    Private,
}

#[derive(Debug)]
struct Fluxer {
    /// `{prefix}/webhooks/{id}/{token}`.
    notify_url: Secret,
    user: Option<String>,
    tts: bool,
    avatar: bool,
    footer: bool,
    footer_logo: bool,
    include_image: bool,
    fields: bool,
    avatar_url: Option<String>,
    href: Option<String>,
    thread_id: Option<String>,
    thread_name: Option<String>,
    ping: Vec<String>,
    /// `?href=`, `?url=` and `?thread=` force Markdown.
    force_markdown: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut tokens = vec![u.host()];
    tokens.extend(u.path_segments());

    let mode = match u.param_nonempty("mode") {
        Some(m) => unquote(&m.trim().to_lowercase()).trim().to_lowercase(),
        None => {
            let host_ok = is_hostname(&u.host, true, true, true).is_some() || is_ipaddr(&u.host, true, true).is_some();
            if host_ok && tokens.len() > 2 { "private".into() } else { "cloud".into() }
        }
    };
    let tts = SERVICE.flag(u, "tts");
    let footer = SERVICE.flag(u, "footer");
    let footer_logo = SERVICE.flag_strict(u, "footer_logo");
    let fields = SERVICE.flag_strict(u, "fields");
    let include_image = SERVICE.flag(u, "image");
    let mut user = u.user();
    if let Some(b) = u.param("botname") {
        user = Some(unquote(b));
    } else if let Some(n) = u.param("name") {
        user = Some(unquote(n));
    }
    let flags = SERVICE.raw(u, "flags").map(unquote);
    let avatar_url = SERVICE.raw(u, "avatar_url").map(unquote);
    let mut force_markdown = false;
    let mut href = None;
    if let Some(h) = SERVICE.raw(u, "href") {
        href = Some(unquote(h));
        force_markdown = true;
    }
    let avatar = SERVICE.flag_strict(u, "avatar");
    let thread_id = SERVICE.raw(u, "thread").map(unquote);
    if thread_id.is_some() {
        force_markdown = true;
    }
    let thread_name = SERVICE.raw(u, "thread_name").map(unquote);
    let ping = SERVICE.raw(u, "ping").map(|p| parse_list([unquote(p)])).unwrap_or_default();

    let webhook_token = tokens.pop().unwrap_or_default();
    let webhook_id = tokens.pop().unwrap_or_default();
    let mut fullpath = if tokens.len() <= 1 { None } else { Some(format!("/{}/", tokens[1..].join("/"))) };
    if let Some(p) = u.param_nonempty("path") {
        fullpath = Some(unquote(p));
    }

    let webhook_id = validate_regex(&webhook_id, r"^[0-9]{10,}$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Fluxer Webhook ID was specified"))?;
    let webhook_token = validate_regex(&webhook_token, r"^[A-Za-z0-9_\-]{16,}$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Fluxer Webhook Token was specified"))?;
    let mut mode = match mode.as_str() {
        "cloud" => Mode::Cloud,
        "private" => Mode::Private,
        _ => return Err(SERVICE.err(format!("an invalid Fluxer Mode ({mode}) was specified"))),
    };
    let host = u.host();
    if host.is_empty() && mode == Mode::Private {
        return Err(SERVICE.err("an invalid Fluxer Hostname was provided"));
    }
    if mode == Mode::Private && crate::regex!(r"(?i)fluxer\.app").is_match(&host) {
        crate::warning!("Fluxer mode changed to cloud mode because fluxer.app found in the host");
        mode = Mode::Cloud;
    }
    let mut path = fullpath.map(|p| p.trim().to_string()).unwrap_or_default();
    if mode != Mode::Private {
        path = "/".into();
    } else if path.is_empty() {
        path = DEFAULT_PRIVATE_PATH.into();
    }
    let mut fullpath = format!("/{}", path.trim_matches('/'));
    if !fullpath.ends_with('/') {
        fullpath.push('/');
    }
    if let Some(f) = flags.as_deref().filter(|f| !f.is_empty()) {
        match parse_int(f) {
            Some(n) if n >= 0 => {}
            _ => return Err(SERVICE.err("an invalid Fluxer flags setting was specified")),
        }
    }

    let prefix = match mode {
        Mode::Cloud => CLOUD_NOTIFY_HOST.to_string(),
        Mode::Private => {
            let mut p = format!("{}://{}", u.http_scheme(), host);
            if let Some(port) = u.port {
                p.push_str(&format!(":{port}"));
            }
            p.push_str(fullpath.trim_end_matches('/'));
            p
        }
    };
    let notify_url = format!("{prefix}/webhooks/{webhook_id}/{webhook_token}");

    Ok(Box::new(Fluxer {
        notify_url: Secret::new(notify_url),
        user: user.filter(|s| !s.is_empty()),
        tts,
        avatar,
        footer,
        footer_logo,
        include_image,
        fields,
        avatar_url: avatar_url.filter(|s| !s.is_empty()),
        href: href.filter(|s| !s.is_empty()),
        thread_id: thread_id.filter(|s| !s.is_empty()),
        thread_name: thread_name.filter(|s| !s.is_empty()),
        ping,
        force_markdown,
    }))
}

fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(
        r"(?i)^https?://(?:api\.)?fluxer\.app/(?:(?:v[0-9]+/)?webhooks)/(?P<id>[0-9]+)/(?P<token>[A-Z0-9_-]+)/?(?P<params>\?.+)?$"
    );
    let c = re.captures(url)?;
    Some(format!("fluxers://{}/{}/{}", &c["id"], &c["token"], c.name("params").map(|m| m.as_str()).unwrap_or("")))
}

/// Mention payload: `allow_mentions` plus a `👉 ...` content line.
fn ping_payload(args: &[&str]) -> Map<String, Value> {
    let re = crate::regex!(r"(?i)\s*(?:<?@(?P<role>&?)(?P<id>[0-9]+)>?|@(?P<value>[a-z0-9]+))");
    let (mut roles, mut users, mut parse) = (Vec::<String>::new(), Vec::<String>::new(), Vec::<String>::new());
    let add = |v: &mut Vec<String>, s: &str| {
        if !v.iter().any(|x| x == s) {
            v.push(s.to_string());
        }
    };
    for arg in args {
        for c in re.captures_iter(arg) {
            if let Some(v) = c.name("value") {
                add(&mut parse, v.as_str());
            } else if c.name("role").is_some_and(|r| !r.as_str().is_empty()) {
                add(&mut roles, &c["id"]);
            } else if let Some(id) = c.name("id") {
                add(&mut users, id.as_str());
            }
        }
    }
    let mut out = Map::new();
    if roles.is_empty() && users.is_empty() && parse.is_empty() {
        return out;
    }
    let mentions: Vec<String> = parse
        .iter()
        .map(|v| format!("@{v}"))
        .chain(roles.iter().map(|v| format!("<@&{v}>")))
        .chain(users.iter().map(|v| format!("<@{v}>")))
        .collect();
    out.insert("allow_mentions".into(), json!({"parse": parse, "users": users, "roles": roles}));
    out.insert("content".into(), json!(format!("👉 {}", mentions.join(" "))));
    out
}

/// Intro text plus embed fields from `#` sections.
fn extract_markdown_sections(body: &str) -> (String, Vec<Value>) {
    let (description, sections) = crate::convert::markup::sections(body, FIELD_NAME_MAXLEN, FIELD_VALUE_MAXLEN - 10);
    let fields = sections
        .into_iter()
        .map(|(name, value)| {
            let value =
                if value.is_empty() { "```\n```".to_string() } else { format!("```md\n{}\n```", value.trim_end()) };
            json!({"name": name, "value": value})
        })
        .collect();
    (description, fields)
}

/// One `_send` call: JSON or multipart, with one retry after a 429.
fn send(base: Arc<Request>, body: Arc<SendBody>, retries: u32) -> Plan {
    let req = body.apply((*base).clone());
    Plan::http(req, move |res| match res {
        Err(e) => Plan::Fail(e),
        Ok(r) if r.status == 429 => {
            let delay = r
                .header("Retry-After")
                .and_then(|v| v.trim().parse::<f64>().ok())
                .filter(|d| d.is_finite())
                .unwrap_or(DEFAULT_DELAY_SEC)
                .clamp(DEFAULT_DELAY_SEC, 3600.0);
            if retries > 0 {
                Plan::chain([Plan::Sleep(Duration::from_secs_f64(delay)), send(base, body, retries - 1)])
            } else {
                Plan::Fail(r.http_error())
            }
        }
        Ok(r) if r.status == 200 || r.status == 204 => Plan::Done,
        Ok(r) => Plan::Fail(r.http_error()),
    })
}

enum SendBody {
    Json(Vec<u8>),
    File { payload_json: String, attachment: Attachment, boundary: String },
}

impl SendBody {
    fn apply(&self, req: Request) -> Request {
        match self {
            SendBody::Json(b) => req.header("Content-Type", "application/json; charset=utf-8").body(b.clone(), None),
            SendBody::File { payload_json, attachment, boundary } => {
                req.multipart(Multipart::with_boundary(boundary.clone()).text("payload_json", payload_json.clone()).file(
                    "files[0]",
                    attachment.name.clone(),
                    attachment.mime.clone(),
                    attachment.data.clone(),
                ))
            }
        }
    }
}

impl Notify for Fluxer {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let format = if self.force_markdown { NotifyFormat::Markdown } else { msg.format };
        let mut payload = Map::new();
        payload.insert("tts".into(), json!(self.tts));
        payload.insert("wait".into(), json!(!self.tts));

        let image_url = ctx.asset.image_url(msg.kind, ImageSize::Xy256);
        if self.avatar && (image_url.is_some() || self.avatar_url.is_some()) {
            payload.insert("avatar_url".into(), json!(self.avatar_url.clone().or(image_url.clone())));
        }
        if let Some(u) = &self.user {
            payload.insert("username".into(), json!(u));
        }
        if let Some(t) = &self.thread_name {
            payload.insert("thread_name".into(), json!(t));
        }
        let joined = self.ping.join(" ");
        if format == NotifyFormat::Markdown {
            if self.ping.is_empty() {
                payload.extend(ping_payload(&[msg.body]));
            } else {
                payload.extend(ping_payload(&[msg.body, &joined]));
            }
        } else if !self.ping.is_empty() {
            payload.extend(ping_payload(&[&joined]));
        }

        let mut url = self.notify_url.expose().to_string();
        if let Some(t) = &self.thread_id {
            url = Request::get(url).query(&[("thread_id", t.as_str())]).url;
        }
        let base = Arc::new(ctx.post(url));
        let json_send = |p: &Map<String, Value>| {
            send(base.clone(), Arc::new(SendBody::Json(serde_json::to_vec(p).unwrap_or_default())), 1)
        };

        let mut plans = Vec::new();
        if !msg.body.is_empty() {
            let mut rest: Vec<Value> = Vec::new();
            if format == NotifyFormat::Markdown {
                let mut embed = Map::new();
                embed.insert("author".into(), json!({"name": ctx.app_id(), "url": ctx.app_url()}));
                embed.insert("description".into(), json!(msg.body));
                embed.insert("color".into(), json!(ctx.asset.color_int(msg.kind)));
                if !msg.title.is_empty() {
                    embed.insert("title".into(), json!(msg.title));
                }
                if let Some(h) = &self.href {
                    embed.insert("url".into(), json!(h));
                }
                if self.footer {
                    let mut footer = Map::new();
                    footer.insert("text".into(), json!(ctx.app_desc()));
                    if self.footer_logo
                        && let Some(logo) = ctx.asset.logo_url()
                    {
                        footer.insert("icon_url".into(), json!(logo));
                    }
                    embed.insert("footer".into(), Value::Object(footer));
                }
                if self.include_image
                    && let Some(i) = &image_url
                {
                    embed.insert("thumbnail".into(), json!({"url": i, "height": 256, "width": 256}));
                }
                if self.fields {
                    let (description, fields) = extract_markdown_sections(msg.body);
                    embed.insert("description".into(), json!(description));
                    if !fields.is_empty() {
                        let split = fields.len().min(MAX_FIELDS);
                        embed.insert("fields".into(), Value::Array(fields[..split].to_vec()));
                        rest = fields[split..].to_vec();
                    }
                }
                payload.insert("embeds".into(), json!([Value::Object(embed)]));
            } else {
                let mut content =
                    if msg.title.is_empty() { msg.body.to_string() } else { format!("{}\r\n{}", msg.title, msg.body) };
                if let Some(Value::String(c)) = payload.get("content") {
                    content.push_str(c);
                }
                payload.insert("content".into(), json!(content));
            }
            plans.push(json_send(&payload));

            if !rest.is_empty() {
                payload["embeds"][0]["description"] = json!("");
                for chunk in rest.chunks(MAX_FIELDS) {
                    payload["embeds"][0]["fields"] = Value::Array(chunk.to_vec());
                    plans.push(json_send(&payload));
                }
            }
        }

        if !msg.attachments.is_empty() {
            payload.insert("tts".into(), json!(false));
            payload.insert("wait".into(), json!(false));
            payload.remove("embeds");
            payload.remove("allow_mentions");
            for a in msg.attachments {
                payload.insert("content".into(), json!(a.name));
                payload.insert("attachments".into(), json!([{"id": 0, "filename": a.name}]));
                let body =
                    SendBody::File {
                    payload_json: Value::Object(payload.clone()).to_string(),
                    attachment: a.clone(),
                    boundary: ctx.env().random_hex(16),
                };
                plans.push(send(base.clone(), Arc::new(body), 1));
            }
        }
        Plan::chain(plans)
    }
}
