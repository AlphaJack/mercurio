//! Matrix (`matrix://`, `matrixs://`): messages to Matrix rooms and users.
//!
//! Modes:
//! - Server (default): log in with `user:password` (falling back to registration) or use a raw access token (`matrixs://token@host/...`), then join rooms (`!id`, `#alias`, auto-created when missing), open direct-message rooms for `@user` targets, upload attachments to the media repository and send `m.text`/`m.notice` events (API v3 or `?v=2`). Homeserver discovery (`.well-known`) runs for `matrixs://`.
//! - Webhooks (`?mode=matrix|slack|t2bot|hookshot`, t2bot also as `matrix://{64-char-token}` or the native t2bot URL).
//! - End-to-end encryption (cargo feature `service-matrix-e2ee`; `?e2ee=no` disables it): device keys are uploaded, encrypted rooms get Megolm events, room keys are shared over Olm, attachments are AES-CTR encrypted. `?autoverify=yes` answers one same-user SAS verification.
//!
//! Persistent state (session, transaction counter, room cache, discovery, E2EE identity and Megolm sessions) lives in the target's [`crate::Store`]. In memory mode the session lasts as long as the target and [`Target::close`](crate::Target::close) logs out; with a storage path it survives between runs and is never logged out. `?keystore=DIR` keeps this URL's state under `DIR` (flush mode) whatever the asset's storage settings are.
//!
//! Divergences (listed under Differences):
//! - Non-string ids in server answers (room ids, tokens) are treated as missing instead of raising.
//!
//! # Differences
//!
//! - Non-string ids in server answers (room ids, tokens) are treated as missing instead of raising. *intentional*
//! - **Raw-token transaction ids.** Apprise reuses one UUID for every event of a send, so homeservers drop the later ones as duplicates -> mercurio uses a fresh UUID per event. *intentional*
//! - `retry_after_ms` is not fed into the retry loop (see Retries). *todo*
//! - **Encryption state.** Apprise treats a `200` with an empty `m.room.encryption` state as unencrypted -> mercurio treats the room as encrypted. *intentional*
//! - **Failed state lookup or E2EE setup.** Apprise falls back to plaintext -> mercurio fails the room. *intentional*
//! - **Room keys.** Apprise shares the Megolm key once per session -> mercurio re-shares it with new devices and rotates it when a member leaves. *intentional*
//! - **Device verification.** Cross-signing is not checked; devices are trusted on first use. *todo*
//! - **Stored state.** The pickled Olm/Megolm state in the store is plain, not encrypted at rest. *todo*

mod server;
pub mod sizing;

#[cfg(feature = "service-matrix-e2ee")]
pub mod e2ee;
#[cfg(feature = "service-matrix-e2ee")]
mod e2ee_flow;
#[cfg(feature = "service-matrix-e2ee")]
mod sas;

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde_json::{Value, json};

use crate::asset::ImageSize;
use crate::error::Error;
use crate::http::Request;
use crate::message::{Attachment, NotifyType};
use crate::parse::{is_hostname, parse_bool, parse_list, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef, UrlIdentifier};
use crate::store::{PersistentStore, StoreRef};
use crate::url::{ParsedUrl, unquote};
use crate::util::escape_html;
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "matrix",
    name: "Matrix",
    schemes: &["matrix", "matrixs"],
    service_url: "https://matrix.org/",
    parse,
    parse_native: Some(parse_native),
    limits: Limits { title_maxlen: 250, body_maxlen: BODY_MAXLEN_DEFAULT, body_max_line_count: 0 },
    formats: &[NotifyFormat::Text, NotifyFormat::Html, NotifyFormat::Markdown],
    attachments: true,
    throttle: Duration::from_millis(500),
    templates: &[
        "{schema}://{token}",
        "{schema}://{user}@{token}",
        "{schema}://{user}:{password}@{host}/{targets}",
        "{schema}://{user}:{password}@{host}:{port}/{targets}",
        "{schema}://{token}@{host}/{targets}",
        "{schema}://{token}@{host}:{port}/{targets}",
        "{schema}://{user}:{token}@{host}/{targets}",
        "{schema}://{user}:{token}@{host}:{port}/{targets}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("password", "Password").secret(),
        Param::new("port", "Port").port(),
        Param::new("target_room_alias", "Target Room Alias").prefix("#"),
        Param::new("target_room_id", "Target Room ID").prefix("!"),
        Param::new("target_user", "Target User").prefix("@"),
        Param::new("targets", "Targets").list("/").group(&["target_room_alias", "target_room_id", "target_user"]),
        Param::new("token", "Access Token").required().secret(),
        Param::new("user", "Username"),
    ],
    params: &[
        Param::new("autoverify", "Automatic Device Verification").bool(false),
        Param::new("discovery", "Server Discovery").bool(true),
        Param::new("e2ee", "End-to-End Encryption").bool(true),
        Param::new("hsreq", "Force Home Server on Room IDs").bool(true),
        Param::new("image", "Include Image").bool(false),
        Param::new("mode", "Webhook Mode").choice(&["off", "matrix", "slack", "t2bot", "hookshot"]).default("off").inferred(),
        Param::new("msgtype", "Message Type").choice(&["text", "notice"]).default("text"),
        Param::new("path", "Webhook Path").default("/webhook"),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
        Param::new("version", "Matrix API Version").choice(&["2", "3"]).default("3").aliases(&["v"]),
        Param::new("keystore", "Key store directory").note("keeps this URL's state under the directory"),
    ],
};

const BODY_MAXLEN_DEFAULT: usize = 65000;
const T2BOT_URL: &str = "https://webhooks.t2bot.io/api/v1/matrix/hook";
const V1_WEBHOOK_PATH: &str = "/api/v1/matrix/hook";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Off,
    Matrix,
    Slack,
    T2bot,
    Hookshot,
    /// `?mode=` (empty): accepted when parsing, fails at send time.
    Empty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Version {
    V2,
    V3,
}

#[derive(Debug)]
pub(crate) struct Config {
    pub secure: bool,
    /// Unquoted host.
    pub host: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub password: Option<Secret>,
    pub rooms: Vec<String>,
    pub users: Vec<String>,
    pub mode: Mode,
    pub version: Version,
    pub msgtype: String,
    pub include_image: bool,
    pub discovery: bool,
    pub hsreq: bool,
    pub webhook_path: String,
    pub e2ee: bool,
    #[cfg_attr(not(feature = "service-matrix-e2ee"), expect(dead_code, reason = "used by end-to-end encryption only"))]
    pub autoverify: bool,
    /// t2bot webhook id.
    pub t2bot_token: Option<Secret>,
    /// `?keystore=` directory (this URL's own persistent store).
    pub keystore: Option<PathBuf>,
}

const TITLE_MAXLEN: usize = 250;

/// Message data shared by every step of a send.
#[derive(Debug)]
pub(crate) struct Msg {
    pub title: String,
    /// Body after dialect conversion (Markdown rendered for non-passthrough).
    pub body: String,
    pub kind: NotifyType,
    pub format: NotifyFormat,
    pub passthrough: bool,
    pub attachments: Vec<Attachment>,
    pub image_url: Option<String>,
    pub app_id: String,
    pub app_desc: String,
    pub color: String,
}

#[derive(Debug)]
struct Matrix {
    cfg: Arc<Config>,
    /// The `?keystore=` store, opened on first use.
    keystore: OnceLock<StoreRef>,
}

fn opt(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.is_empty())
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    if u.host.is_empty() {
        return Err(SERVICE.err("no host was specified"));
    }
    let mut targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }
    let include_image = SERVICE.flag(u, "image");
    let discovery = SERVICE.flag_strict(u, "discovery");
    let hsreq = SERVICE.flag_strict(u, "hsreq");
    let webhook_path = SERVICE.raw(u, "path").map(unquote);
    let e2ee = SERVICE.raw(u, "e2ee").map(|v| parse_bool(v, false));
    let autoverify = SERVICE.flag(u, "autoverify");
    let mut mode = SERVICE.raw(u, "mode").map(str::to_string);
    let mut user = opt(u.user());
    let mut password = opt(u.password());
    if mode.is_none() && password.is_none() && targets.is_empty() {
        mode = Some("t2bot".into());
    }
    if mode.as_deref().is_some_and(|m| m.eq_ignore_ascii_case("t2bot")) {
        password = opt(Some(u.host()));
    }
    let msgtype = SERVICE.text(u, "msgtype");
    if let Some(t) = u.param_nonempty("token") {
        password = Some(unquote(t));
    } else if password.is_none() && user.is_some() {
        password = user.take();
    }
    let version = u.param_nonempty("version").or_else(|| u.param_nonempty("v")).map(unquote);

    let mut rooms = Vec::new();
    let mut users = Vec::new();
    for t in parse_list(&targets) {
        if server::match_user(&t).is_some() {
            users.push(t);
        } else {
            rooms.push(t);
        }
    }
    let webhook_path = match webhook_path.as_deref().map(str::trim) {
        Some(p) if !p.is_empty() => {
            let p = if p.starts_with('/') { p.to_string() } else { format!("/{p}") };
            let p = p.trim_end_matches('/').to_string();
            if p.is_empty() { "/".to_string() } else { p }
        }
        _ => SERVICE.default_of("path").to_string(),
    };
    let e2ee = e2ee.unwrap_or(true);
    let mode = match mode.map(|m| m.to_lowercase()).as_deref() {
        None | Some("off") => Mode::Off,
        Some("matrix") => Mode::Matrix,
        Some("slack") => Mode::Slack,
        Some("t2bot") => Mode::T2bot,
        Some("hookshot") => Mode::Hookshot,
        Some("") => Mode::Empty,
        Some(_) => return Err(SERVICE.err("the mode specified is invalid")),
    };
    let version = match version.as_deref() {
        None | Some("3") => Version::V3,
        Some("2") => Version::V2,
        Some(_) => return Err(SERVICE.err("the version specified is invalid")),
    };
    let msgtype = msgtype.unwrap_or_else(|| SERVICE.default_of("msgtype").into()).to_lowercase();
    if !msgtype.is_empty() && msgtype != "text" && msgtype != "notice" {
        return Err(SERVICE.err("the msgtype specified is invalid"));
    }
    let host = u.host();
    let mut t2bot_token = None;
    if mode == Mode::T2bot {
        match validate_regex(password.as_deref().unwrap_or(""), r"^[a-z0-9]{64}$", "i", true) {
            Some(t) => t2bot_token = Some(Secret::new(t)),
            None => return Err(SERVICE.err("an invalid T2Bot/Matrix Webhook ID was specified")),
        }
    } else if is_hostname(&host, true, true, true).is_none() {
        return Err(SERVICE.err("an invalid Matrix hostname was specified"));
    } else if u.port_raw.is_some() || u.port == Some(0) {
        return Err(SERVICE.err("an invalid Matrix port was specified"));
    }
    let discovery = discovery && mode == Mode::Off;
    let keystore = u.param_nonempty("keystore").map(PathBuf::from);
    Ok(Box::new(Matrix {
        cfg: Arc::new(Config {
            secure: u.secure,
            host,
            port: u.port,
            user,
            password: password.map(Secret::new),
            rooms,
            users,
            mode,
            version,
            msgtype,
            include_image,
            discovery,
            hsreq,
            webhook_path,
            e2ee,
            autoverify,
            t2bot_token,
            keystore,
        }),
        keystore: OnceLock::new(),
    }))
}

/// `https://webhooks.t2bot.io/api/v1/matrix/hook/TOKEN[/][?params]`.
fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(
        r"(?i)^https?://webhooks\.t2bot\.io/api/v[0-9]+/matrix/hook/(?P<webhook_token>[A-Z0-9_-]+)/?(?P<params>\?.+)?$"
    );
    let c = re.captures(url)?;
    let token = &c["webhook_token"];
    Some(match c.name("params") {
        Some(p) => format!("matrixs://{token}/{}&mode=t2bot", p.as_str()),
        None => format!("matrixs://{token}/?mode=t2bot"),
    })
}

impl Config {
    fn e2ee_capable(&self) -> bool {
        cfg!(feature = "service-matrix-e2ee") && self.e2ee && self.secure
    }

    /// Store namespace: the URL identity (scheme, mode, host, port, path, credentials), hashed.
    fn namespace(&self) -> String {
        let id = format!(
            "{}|{:?}|{}|{}|{}|{}|{}",
            if self.secure { "matrixs" } else { "matrix" },
            self.mode,
            self.host,
            self.port.unwrap_or(if self.secure { 443 } else { 80 }),
            self.webhook_path,
            self.user.as_deref().unwrap_or(""),
            self.password.as_ref().map(|p| p.expose()).unwrap_or(""),
        );
        crate::crypto::hex(&crate::crypto::sha256(id.as_bytes())).get(..16).unwrap_or_default().to_string()
    }

    fn mode_str(&self) -> &'static str {
        match self.mode {
            Mode::Off => "off",
            Mode::Matrix => "matrix",
            Mode::Slack => "slack",
            Mode::T2bot => "t2bot",
            Mode::Hookshot => "hookshot",
            Mode::Empty => "",
        }
    }
}

fn html_body(msg: &Msg) -> String {
    if msg.passthrough && msg.format == NotifyFormat::Markdown {
        crate::convert::markdown_to_html_plain(&msg.body)
    } else {
        msg.body.clone()
    }
}

fn plain_fallback(msg: &Msg) -> String {
    if msg.passthrough || !matches!(msg.format, NotifyFormat::Html | NotifyFormat::Markdown) {
        msg.body.clone()
    } else {
        crate::convert::html_to_text(&msg.body)
    }
}

fn rich(msg: &Msg) -> bool {
    matches!(msg.format, NotifyFormat::Html | NotifyFormat::Markdown)
}

/// The `m.room.message` content (also the plaintext of encrypted events).
pub(crate) fn message_content(cfg: &Config, msg: &Msg) -> Value {
    let title = if msg.title.is_empty() { String::new() } else { format!("# {}\r\n", msg.title) };
    let mut payload = json!({
        "msgtype": format!("m.{}", cfg.msgtype),
        "body": format!("{title}{}", plain_fallback(msg)),
    });
    if rich(msg) {
        let mut title_html = String::new();
        if !msg.title.is_empty() {
            title_html = format!("<h1>{}</h1>", escape_html(&msg.title, false, false));
            if msg.format != NotifyFormat::Markdown {
                title_html.push_str("<br/>");
            }
        }
        payload["format"] = json!("org.matrix.custom.html");
        payload["formatted_body"] = json!(format!("{title_html}{}", html_body(msg)));
    }
    payload
}

impl Matrix {
    fn webhook_url(&self) -> String {
        let cfg = &self.cfg;
        let token =
            cfg.password.as_ref().map(|p| p.expose().to_string()).or_else(|| cfg.user.clone()).unwrap_or_default();
        let base = || {
            let port = cfg.port.map(|p| format!(":{p}")).unwrap_or_default();
            format!("{}://{}{}", if cfg.secure { "https" } else { "http" }, cfg.host, port)
        };
        match cfg.mode {
            Mode::T2bot => format!("{T2BOT_URL}/{}", cfg.t2bot_token.as_ref().map(|t| t.expose()).unwrap_or("")),
            Mode::Hookshot => format!("{}{}/{token}", base(), cfg.webhook_path.trim_end_matches('/')),
            Mode::Off | Mode::Matrix | Mode::Slack | Mode::Empty => format!("{}{V1_WEBHOOK_PATH}/{token}", base()),
        }
    }

    fn display_name(&self, msg: &Msg) -> String {
        self.cfg.user.clone().unwrap_or_else(|| msg.app_id.clone())
    }

    fn rich_html(msg: &Msg) -> String {
        let mut title = String::new();
        if !msg.title.is_empty() {
            title = format!("<h1>{}</h1>", escape_html(&msg.title, false, true));
            if msg.format != NotifyFormat::Markdown {
                title.push_str("<br/>");
            }
        }
        format!("{title}{}", html_body(msg))
    }

    fn matrix_payload(&self, msg: &Msg) -> Value {
        let text = if rich(msg) {
            Self::rich_html(msg)
        } else if msg.title.is_empty() {
            msg.body.clone()
        } else {
            format!("{}\r\n{}", msg.title, msg.body)
        };
        json!({
            "displayName": self.display_name(msg),
            "format": if msg.format == NotifyFormat::Text { "plain" } else { "html" },
            "text": text,
        })
    }

    fn webhook_payload(&self, msg: &Msg) -> Result<Value> {
        Ok(match self.cfg.mode {
            Mode::Slack => {
                let fix = |s: &str| -> Result<String> {
                    if s.contains("\r*\n") {
                        return Err(Error::Service("Matrix Slack formatting failed".into()));
                    }
                    Ok(s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;"))
                };
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0);
                json!({
                    "username": self.display_name(msg),
                    "mrkdwn": msg.format == NotifyFormat::Markdown,
                    "attachments": [{
                        "title": fix(&msg.title)?,
                        "text": fix(&msg.body)?,
                        "color": msg.color,
                        "ts": ts,
                        "footer": msg.app_id,
                    }],
                })
            }
            Mode::Matrix => self.matrix_payload(msg),
            Mode::T2bot => {
                let mut p = self.matrix_payload(msg);
                if let Some(img) = &msg.image_url {
                    p["avatarUrl"] = json!(img);
                }
                p
            }
            Mode::Hookshot => {
                let mut p = json!({"username": self.display_name(msg), "text": ""});
                if rich(msg) {
                    let plain = plain_fallback(msg);
                    p["text"] = json!(if msg.title.is_empty() { plain } else { format!("{}\r\n{plain}", msg.title) });
                    p["html"] = json!(Self::rich_html(msg));
                } else {
                    let text =
                        if msg.title.is_empty() { msg.body.clone() } else { format!("{}\r\n{}", msg.title, msg.body) };
                    p["html"] = json!(escape_html(&text, true, false));
                    p["text"] = json!(text);
                }
                p
            }
            Mode::Off | Mode::Empty => return Err(Error::Service("Matrix webhook mode is not set".into())),
        })
    }

    fn webhook_plan(&self, msg: &Msg) -> Plan {
        let url = self.webhook_url();
        let payload = match self.webhook_payload(msg) {
            Ok(p) => p,
            Err(e) => return Plan::Fail(e),
        };
        let req = Request::post(url)
            .header("User-Agent", msg.app_id.clone())
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(&payload).unwrap_or_default(), None);
        Plan::send_expect(req, &[200, 202])
    }
}

impl Matrix {
    /// The target's store or the `?keystore=` one.
    fn store(&self, ctx: &Context<'_>) -> StoreRef {
        match &self.cfg.keystore {
            None => ctx.store(),
            Some(dir) => self
                .keystore
                .get_or_init(|| PersistentStore::new(Some(dir), &self.cfg.namespace()).shared())
                .clone(),
        }
    }
}

impl Notify for Matrix {
    fn stores(&self, ctx: &Context<'_>) -> Vec<StoreRef> {
        self.cfg.keystore.iter().map(|_| self.store(ctx)).collect()
    }

    /// CommonMark is rendered as HTML (no extensions); Slack webhooks get HTML as plain text instead.
    fn convert(&self, body: &str, format: NotifyFormat) -> Option<String> {
        match (self.cfg.mode == Mode::Slack, format) {
            (true, NotifyFormat::Html) => Some(crate::convert::html_to_text(body)),
            (false, NotifyFormat::Markdown) => Some(crate::convert::markdown_to_html_plain(body)),
            _ => None,
        }
    }


    fn plan(&self, m: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let cfg = &self.cfg;
        let msg = Msg {
            title: m.title.to_string(),
            body: m.body.to_string(),
            kind: m.kind,
            format: m.format,
            passthrough: m.passthrough,
            attachments: m.attachments.to_vec(),
            image_url: if cfg.include_image { ctx.asset.image_url(m.kind, ImageSize::Xy32) } else { None },
            app_id: ctx.app_id().to_string(),
            app_desc: ctx.app_desc().to_string(),
            color: ctx.asset.color(m.kind).to_string(),
        };
        if cfg.mode != Mode::Off {
            return self.webhook_plan(&msg);
        }
        server::plan(cfg.clone(), msg, self.store(ctx), ctx.memo.clone())
    }

    fn close(&self, ctx: &Context<'_>) -> Option<Plan> {
        if self.cfg.mode != Mode::Off {
            return None;
        }
        let msg = Msg {
            title: String::new(),
            body: String::new(),
            kind: NotifyType::Info,
            format: NotifyFormat::Text,
            passthrough: true,
            attachments: Vec::new(),
            image_url: None,
            app_id: ctx.app_id().to_string(),
            app_desc: ctx.app_desc().to_string(),
            color: String::new(),
        };
        server::close(self.cfg.clone(), msg, self.store(ctx))
    }

    fn url_identifier(&self) -> UrlIdentifier {
        let c = &self.cfg;
        let t2bot = c.mode == Mode::T2bot;
        let token = c.t2bot_token.as_ref().map(|t| t.expose().to_string());
        let password = c.password.as_ref().map(|p| p.expose().to_string());
        UrlIdentifier::Parts(vec![
            if c.secure { "matrixs" } else { "matrix" }.to_string(),
            c.mode_str().to_string(),
            if t2bot { token.as_deref().unwrap_or_default().to_string() } else { c.host.clone() },
            c.port.unwrap_or(if c.secure { 443 } else { 80 }).to_string(),
            if c.mode == Mode::Hookshot { c.webhook_path.clone() } else { String::new() },
            c.user.as_deref().filter(|_| !t2bot).unwrap_or_default().to_string(),
            password.as_deref().filter(|_| !t2bot).unwrap_or_default().to_string(),
        ])
    }

    /// Direct sends size the body limit from the content; other modes use fixed limits.
    fn limits(&self, title: &str, body: &str, format: NotifyFormat, ctx: &Context<'_>) -> Option<Limits> {
        let cfg = &self.cfg;
        if cfg.mode != Mode::Off {
            return Some(Limits { title_maxlen: TITLE_MAXLEN, body_maxlen: BODY_MAXLEN_DEFAULT, body_max_line_count: 0 });
        }
        let title: String = title.trim().chars().take(TITLE_MAXLEN).collect();
        let body = body.trim_end();
        let device_id = self.store(ctx).get("device_id").and_then(|v| v.as_str().map(str::to_string));
        let rich = matches!(format, NotifyFormat::Html | NotifyFormat::Markdown);
        let body_maxlen = sizing::body_char_limit(body, &title, rich, cfg.e2ee_capable(), device_id.as_deref());
        Some(Limits { title_maxlen: TITLE_MAXLEN, body_maxlen, body_max_line_count: 0 })
    }

}

#[cfg(test)]
mod tests;
