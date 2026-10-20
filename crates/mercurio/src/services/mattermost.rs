//! Mattermost (`mmost://`, `mmosts://`): posts to Mattermost channels.
//!
//! Channel-name lookups (bot mode) are cached in the persistent store for 20 days (`c:<name>`).


use serde_json::{Value, json};

use crate::asset::ImageSize;
use crate::http::{Multipart, Request};
use crate::parse::{parse_list, validate_nonblank};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef, UrlIdentifier};
use crate::url::{ParsedUrl, quote, unquote};
use crate::{Error, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "mattermost",
    name: "Mattermost",
    schemes: &["mmost", "mmosts"],
    service_url: "https://mattermost.com/",
    parse,
    parse_native: Some(parse_native),
    limits: Limits { title_maxlen: 0, body_maxlen: 4000, body_max_line_count: 0 },
    attachments: true,
    templates: &[
        "{schema}://{host}/{token}",
        "{schema}://{host}:{port}/{token}",
        "{schema}://{host}/{fullpath}/{token}",
        "{schema}://{host}:{port}/{fullpath}/{token}",
        "{schema}://{user}@{host}/{token}",
        "{schema}://{user}@{host}:{port}/{token}",
        "{schema}://{user}@{host}/{fullpath}/{token}",
        "{schema}://{user}@{host}:{port}/{fullpath}/{token}",
    ],
    tokens: &[
        Param::new("fullpath", "Path"),
        Param::new("host", "Hostname").required(),
        Param::new("port", "Port").port(),
        Param::new("target_channel", "Target Channel").prefix("#"),
        Param::new("target_channel_id", "Target Channel ID"),
        Param::new("targets", "Targets").list("/").group(&["target_channel", "target_channel_id"]),
        Param::new("token", "Token").required().secret(),
        Param::new("user", "User"),
    ],
    params: &[
        Param::sets("botname", &["user"]),
        Param::sets("channel", &["targets"]),
        Param::sets("channels", &["targets"]),
        Param::new("icon_url", "Icon URL"),
        Param::new("image", "Include Image").bool(true),
        Param::new("mode", "Mode").choice(&["webhook", "bot"]).default("webhook").inferred(),
        Param::sets("team", &["user"]),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Webhook,
    Bot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// Channel name (`#name`).
    Name(String),
    /// Channel id (`+id`, bot mode only).
    Id(String),
}

#[derive(Debug)]
struct Mattermost {
    base: String,
    token: Secret,
    user: Option<String>,
    mode: Mode,
    targets: Vec<Target>,
    include_image: bool,
    icon_url: Option<String>,
    /// Parts of the URL identity (namespace of the persistent store).
    id: Vec<String>,
}

/// Channel lookups are kept 20 days.
const CHANNEL_CACHE: std::time::Duration = std::time::Duration::from_secs(60 * 60 * 24 * 20);

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let mut tokens = u.path_segments();
    let token = tokens.pop();
    let fullpath = if tokens.is_empty() { String::new() } else { format!("/{}", tokens.join("/")) };
    let mut raw = Vec::new();
    for key in ["to", "channel", "channels"] {
        if let Some(v) = u.param_nonempty(key) {
            raw.extend(parse_list([v]));
        }
    }
    let mut mode = SERVICE.text(u, "mode");
    let mut user = u.user();
    if let Some(team) = u.param_nonempty("team") {
        user = Some(unquote(team));
        if mode.is_none() {
            mode = Some("bot".into());
        }
    } else if let Some(b) = u.param_nonempty("botname") {
        user = Some(unquote(b));
    }
    let icon_url = SERVICE.raw(u, "icon_url").map(unquote);

    let mode = match mode.as_deref().map(str::trim).filter(|m| !m.is_empty()) {
        None => Mode::Webhook,
        Some(m) => {
            let m = m.to_lowercase();
            if "webhook".starts_with(&m) {
                Mode::Webhook
            } else if "bot".starts_with(&m) {
                Mode::Bot
            } else {
                return Err(SERVICE.err("the Mattermost mode specified is invalid"));
            }
        }
    };
    let token = token
        .as_deref()
        .and_then(validate_nonblank)
        .ok_or_else(|| SERVICE.err("an invalid Mattermost Token was specified"))?;

    let user = user.filter(|u| !u.is_empty());
    let chan_re = crate::regex!(r"^(#|%23)(?P<name>[A-Za-z0-9_-]+)$");
    let id_re = crate::regex!(r"^(\+|%2B)?(?P<name>[A-Za-z0-9_-]+)$");
    let mut targets = Vec::new();
    for t in parse_list(raw) {
        if let Some(c) = chan_re.captures(&t) {
            if mode == Mode::Bot && user.is_none() {
                continue;
            }
            targets.push(Target::Name(c["name"].to_string()));
        } else if let Some(c) = id_re.captures(&t) {
            targets.push(match mode {
                Mode::Webhook => Target::Name(c["name"].to_string()),
                Mode::Bot => Target::Id(c["name"].to_string()),
            });
        }
    }

    let mut base = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = u.port {
        base.push_str(&format!(":{p}"));
    }
    base.push_str(fullpath.trim().trim_end_matches('/'));
    let id = vec![
        if u.secure { "mmosts" } else { "mmost" }.to_string(),
        if mode == Mode::Bot { "bot" } else { "webhook" }.to_string(),
        token.clone(),
        u.host(),
        u.port.map(|p| p.to_string()).as_deref().unwrap_or_default().to_string(),
        fullpath.trim().to_string(),
        user.as_deref().filter(|_| mode == Mode::Bot).unwrap_or_default().to_string(),
    ];
    Ok(Box::new(Mattermost {
        base,
        token: Secret::new(token),
        user,
        mode,
        targets,
        include_image: SERVICE.flag_strict(u, "image"),
        icon_url,
        id,
    }))
}

fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(
        r"(?i)^http(?P<secure>s?)://(?P<host>mattermost\.[A-Z0-9_.-]+)(:(?P<port>[1-9][0-9]{0,5}))?/hooks/(?P<token>[A-Z0-9_-]+)/?(?P<params>\?.+)?\n?\z"
    );
    let c = re.captures(url)?;
    let scheme = if c["secure"].is_empty() { "mmost" } else { "mmosts" };
    let port = c.name("port").map_or(String::new(), |p| format!(":{}", p.as_str()));
    Some(format!("{scheme}://{}{port}/{}/{}", &c["host"], &c["token"], c.name("params").map_or("", |m| m.as_str())))
}

/// Upload every attachment for one channel, then post the message.
fn bot_post(
    base: String,
    bearer: String,
    ua: String,
    channel_id: String,
    body: String,
    files: Vec<(String, Vec<u8>, String, String)>,
    file_ids: Vec<Value>,
) -> Plan {
    if file_ids.len() < files.len() {
        let (fname, data, mime, boundary) = files[file_ids.len()].clone();
        let form = Multipart::with_boundary(boundary).text("channel_id", channel_id.as_str()).file("files", fname, mime, data);
        let req = Request::post(format!("{base}/api/v4/files"))
            .header("User-Agent", &ua)
            .header("Authorization", &bearer)
            .multipart(form);
        return Plan::http(req, move |res| {
            let r = match res {
                Ok(r) => r,
                Err(e) => return Plan::Fail(e),
            };
            if r.status != 200 && r.status != 201 {
                return Plan::Fail(r.http_error());
            }
            let id = r
                .json()
                .and_then(|d| match d.get("file_infos") {
                    None => Some(json!("")),
                    Some(f) => f.get(0).map(|i| i.get("id").cloned().unwrap_or(json!(""))),
                })
                .filter(crate::util::json_has_value);
            match id {
                Some(id) => {
                    let mut file_ids = file_ids;
                    file_ids.push(id);
                    bot_post(base, bearer, ua, channel_id, body, files, file_ids)
                }
                None => Plan::Fail(Error::service("Mattermost file upload returned no file ID")),
            }
        })
        .context("upload");
    }
    let mut payload = json!({"channel_id": channel_id, "message": body});
    if !file_ids.is_empty() {
        payload["file_ids"] = Value::Array(file_ids);
    }
    let req = Request::post(format!("{base}/api/v4/posts"))
        .header("User-Agent", &ua)
        .header("Authorization", &bearer)
        .json(&payload);
    let post = Plan::send_expect(req, &[201, 200]);
    if files.is_empty() { post } else { post.context("post") }
}

impl Notify for Mattermost {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let ua = ctx.app_id().to_string();
        match self.mode {
            Mode::Webhook => {
                if msg.body.is_empty() {
                    return Plan::Fail(Error::Message("Mattermost webhooks do not support attachments".into()));
                }
                let url = format!("{}/hooks/{}", self.base, self.token.expose());
                let image = match self.icon_url.as_deref().filter(|i| !i.is_empty()) {
                    Some(i) => Some(i.to_string()),
                    None if self.include_image => ctx.asset.image_url(msg.kind, ImageSize::Xy72),
                    None => None,
                };
                let post = |channel: Option<&str>| {
                    let mut payload = json!({"text": msg.body});
                    if let Some(i) = &image {
                        payload["icon_url"] = json!(i);
                    }
                    payload["username"] = json!(self.user.as_deref().unwrap_or(&ua));
                    if let Some(c) = channel.filter(|c| !c.is_empty()) {
                        payload["channel"] = json!(c);
                    }
                    let req = Request::post(&url).header("User-Agent", &ua).json(&payload);
                    Plan::send_expect(req, &[200])
                };
                if self.targets.is_empty() {
                    return post(None);
                }
                Plan::all(self.targets.iter().map(|t| {
                    let (Target::Name(n) | Target::Id(n)) = t;
                    post(Some(n)).target(format!("#{n}"))
                }))
            }
            Mode::Bot => {
                if self.targets.is_empty() {
                    return Plan::Fail(Error::Message("Mattermost BOT mode has no valid channels to notify".into()));
                }
                let bearer = format!("Bearer {}", self.token.expose());
                // (name, data, MIME type, multipart boundary of its upload)
                let files: Vec<(String, Vec<u8>, String, String)> = msg
                    .attachments
                    .iter()
                    .enumerate()
                    .map(|(i, a)| {
                        let name = if a.name.is_empty() { format!("file{:03}.dat", i + 1) } else { a.name.clone() };
                        (name, a.data.clone(), a.mime.clone(), ctx.env().random_hex(16))
                    })
                    .collect();
                let body = msg.body.to_string();
                Plan::all(self.targets.iter().map(|t| {
                    match t {
                        Target::Id(id) => bot_post(
                            self.base.clone(),
                            bearer.clone(),
                            ua.clone(),
                            id.clone(),
                            body.clone(),
                            files.clone(),
                            Vec::new(),
                        )
                        .target(format!("+{id}")),
                        Target::Name(name) => {
                            let key = format!("c:{name}");
                            let label = format!("#{name}");
                            let (base, bearer, ua, body, files) =
                                (self.base.clone(), bearer.clone(), ua.clone(), body.clone(), files.clone());
                            let store = ctx.store();
                            let url = format!(
                                "{}/api/v4/teams/name/{}/channels/name/{}",
                                self.base,
                                quote(self.user.as_deref().unwrap_or(""), ""),
                                quote(name, "")
                            );
                            let req = Request::get(url)
                                .header("User-Agent", &ua)
                                .header("Accept", "application/json")
                                .header("Authorization", &bearer);
                            Plan::defer(move || {
                                if let Some(id) = store.get_str(&key).filter(|id| !id.is_empty()) {
                                    return bot_post(base, bearer, ua, id, body, files, Vec::new());
                                }
                                Plan::http(req, move |res| {
                                    let r = match res {
                                        Ok(r) => r,
                                        Err(e) => return Plan::Fail(e),
                                    };
                                    if r.status != 200 {
                                        return Plan::Fail(r.http_error());
                                    }
                                    let Some(data) = std::str::from_utf8(&r.body)
                                        .ok()
                                        .and_then(|s| serde_json::from_str::<Value>(s).ok())
                                    else {
                                        return Plan::Fail(Error::service(
                                            "Mattermost channel lookup response was not JSON",
                                        ));
                                    };
                                    let Some(obj) = data.as_object() else {
                                        return Plan::Fail(Error::service(
                                            "unexpected Mattermost channel lookup response",
                                        ));
                                    };
                                    match obj.get("id").and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
                                        Some(id) => {
                                            store.set(&key, Value::String(id.to_string()), Some(CHANNEL_CACHE));
                                            bot_post(base, bearer, ua, id.to_string(), body, files, Vec::new())
                                        }
                                        None => Plan::Fail(Error::service("Mattermost channel not found")),
                                    }
                                })
                                .context("channel lookup")
                            })
                            .target(label)
                        }
                    }
                }))
            }
        }
    }

    fn url_identifier(&self) -> UrlIdentifier {
        UrlIdentifier::Parts(self.id.clone())
    }
}
