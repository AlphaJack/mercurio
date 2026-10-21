//! ntfy (`ntfy://`, `ntfys://`, `https://ntfy.sh/topic`): publishes to ntfy topics.

use serde_json::{Map, Value, json};

use crate::env::Env;
use crate::asset::ImageSize;
use crate::error::Error;
use crate::http::Request;
use crate::parse::{is_hostname, is_ipaddr, parse_list, parse_list_unquoted, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, quote, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "ntfy",
    name: "ntfy",
    schemes: &["ntfy", "ntfys"],
    service_url: "https://ntfy.sh/",
    parse,
    parse_native: Some(parse_native),
    // Title and body share one 7800-character field.
    limits: Limits { title_maxlen: 200, body_maxlen: 7600, body_max_line_count: 0 },
    attachments: true,
    templates: &[
        "{schema}://{topic}",
        "{schema}://{host}/{targets}",
        "{schema}://{host}:{port}/{targets}",
        "{schema}://{user}@{host}/{targets}",
        "{schema}://{user}@{host}:{port}/{targets}",
        "{schema}://{user}:{password}@{host}/{targets}",
        "{schema}://{user}:{password}@{host}:{port}/{targets}",
        "{schema}://{token}@{host}/{targets}",
        "{schema}://{token}@{host}:{port}/{targets}",
    ],
    tokens: &[
        Param::new("host", "Hostname"),
        Param::new("password", "Password").secret(),
        Param::new("port", "Port").port(),
        Param::new("targets", "Targets").list("/").required().group(&["topic"]),
        Param::new("token", "Token").secret(),
        Param::new("topic", "Topic").pattern("^[a-z0-9_-]{1,64}$"),
        Param::new("user", "Username"),
    ],
    params: &[
        Param::new("actions", "Actions"),
        Param::new("attach", "Attach"),
        Param::new("auth", "Authentication Type").choice(&["basic", "token"]).default("basic").inferred(),
        Param::new("avatar_url", "Avatar URL"),
        Param::new("click", "Click"),
        Param::new("delay", "Delay"),
        Param::new("email", "Email"),
        Param::new("filename", "Attach Filename"),
        Param::new("image", "Include Image").bool(true),
        Param::new("mode", "Mode").choice(&["cloud", "private"]).default("private").inferred(),
        Param::new("priority", "Priority").choice(&["max", "high", "default", "low", "min"]).default("default"),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
        Param::new("xtags", "Tags").aliases(&["tags"]),
    ],
    ..ServiceDef::DEFAULTS
};

const CLOUD_URL: &str = "https://ntfy.sh";
/// JSON payloads larger than this are sent as an attachment instead.
const JSON_SIZE_LIMIT: usize = 8000;
const PRIORITY_DEFAULT: &str = "default";

/// Prefix -> priority, in match order.
const PRIORITY_MAP: &[(&str, &str)] = &[
    ("l", "low"),
    ("mo", "low"),
    ("n", "default"),
    ("h", "high"),
    ("e", "max"),
    ("mi", "min"),
    ("ma", "max"),
    ("d", "default"),
    ("1", "min"),
    ("2", "low"),
    ("3", "default"),
    ("4", "high"),
    ("5", "max"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Cloud,
    Private,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Auth {
    Basic,
    Token,
}

#[derive(Debug)]
struct Ntfy {
    mode: Mode,
    auth: Auth,
    /// `{scheme}://{host}[:port]` for private mode.
    base: String,
    user: Option<String>,
    password: Option<Secret>,
    token: Option<Secret>,
    topics: Vec<String>,
    attach: Option<String>,
    filename: Option<String>,
    click: Option<String>,
    delay: Option<String>,
    email: Option<String>,
    priority: &'static str,
    tags: Vec<String>,
    actions: Option<String>,
    include_image: bool,
    avatar_url: Option<String>,
}

fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or("")
}

fn param_unquoted(u: &ParsedUrl, key: &str) -> Option<String> {
    u.param_nonempty(key).map(unquote)
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let priority_raw = param_unquoted(u, "priority");

    let mut attach = None;
    let mut filename = None;
    if let Some(a) = param_unquoted(u, "attach") {
        if let Some(r) = crate::url::parse_url(&a) {
            let b = basename(r.fullpath.as_deref().unwrap_or(""));
            filename = if b.is_empty() { None } else { Some(b.to_string()) };
        }
        if let Some(f) = param_unquoted(u, "filename") {
            filename = Some(basename(&f).to_string());
        }
        attach = Some(a);
    }
    let click_raw = param_unquoted(u, "click");
    let delay = param_unquoted(u, "delay");
    let email = param_unquoted(u, "email");
    let raw_xtags = u.param_nonempty("xtags").or_else(|| u.param_nonempty("tags")).unwrap_or("");
    let xtags = if raw_xtags.is_empty() { Vec::new() } else { parse_list([unquote(raw_xtags)]) };
    let actions = param_unquoted(u, "actions");
    let include_image = SERVICE.flag(u, "image");
    let avatar_url = u.param("avatar_url").map(unquote);

    let mut targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list_unquoted([to]));
    }

    let mut auth: Option<String> = None;
    let mut token: Option<String> = None;
    if let Some(t) = u.param_nonempty("token") {
        auth = Some("token".into());
        token = Some(unquote(t));
    }
    if let Some(a) = u.param_nonempty("auth") {
        auth = Some(unquote(&a.trim().to_lowercase()));
    }
    let raw_user = u.user.as_deref().filter(|s| !s.is_empty());
    let raw_pass = u.password.as_deref().filter(|s| !s.is_empty());
    if auth.is_none()
        && let (Some(user), None) = (raw_user, raw_pass)
    {
        let tk = crate::regex!(r"(?i)^tk_[^ \t]+");
        auth = Some(if tk.is_match(user) { "token" } else { "basic" }.into());
    }
    if auth.as_deref() == Some("token") && token.as_deref().is_none_or(str::is_empty) {
        match (raw_user, raw_pass) {
            (Some(user), None) => token = Some(unquote(user)),
            (_, Some(pw)) => token = Some(unquote(pw)),
            _ => {}
        }
    }

    let host_raw = u.host.as_str();
    let mode_s = match u.param_nonempty("mode") {
        Some(m) => unquote(&m.trim().to_lowercase()),
        None => {
            let valid = is_hostname(host_raw, true, true, true).is_some() || is_ipaddr(host_raw, true, true).is_some();
            if valid && !targets.is_empty() { "private".into() } else { "cloud".into() }
        }
    };
    if mode_s == "cloud" && !crate::regex!(r"(?i)ntfy\.sh").is_match(host_raw) {
        targets.insert(0, host_raw.to_string());
    } else if mode_s == "private" && is_hostname(host_raw, true, true, true).is_none() {
        return Err(SERVICE.err("an invalid ntfy hostname was specified"));
    }

    let mode = match mode_s.trim().to_lowercase().as_str() {
        "cloud" => Mode::Cloud,
        "private" => Mode::Private,
        _ => return Err(SERVICE.err("an invalid ntfy mode was specified")),
    };
    let auth = match auth.as_deref().map(|a| a.trim().to_lowercase()) {
        None => Auth::Basic,
        Some(a) if a == "basic" => Auth::Basic,
        Some(a) if a == "token" => Auth::Token,
        Some(_) => return Err(SERVICE.err("an invalid ntfy authentication type was specified")),
    };
    let click = click_raw.map(|c| if c.is_ascii() { c } else { quote(&c, ":/?&=[]") });
    let priority = match priority_raw {
        None => PRIORITY_DEFAULT,
        Some(p) => {
            let p = p.to_lowercase();
            PRIORITY_MAP.iter().find(|(k, _)| p.starts_with(k)).map(|(_, v)| *v).unwrap_or(PRIORITY_DEFAULT)
        }
    };
    let tags = parse_list(&xtags);
    let topics: Vec<String> =
        parse_list(&targets).into_iter().filter_map(|t| validate_regex(&t, r"^[a-z0-9_-]{1,64}$", "i", true)).collect();

    let mut base = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(port) = u.port {
        base.push_str(&format!(":{port}"));
    }

    Ok(Box::new(Ntfy {
        mode,
        auth,
        base,
        user: u.user().filter(|s| !s.is_empty()),
        password: u.password().map(Secret::new),
        token: token.filter(|t| !t.is_empty()).map(Secret::new),
        topics,
        attach,
        filename,
        click,
        delay,
        email,
        priority,
        tags,
        actions,
        include_image,
        avatar_url,
    }))
}

/// `https://ntfy.sh/topic?params` -> `ntfys://topic?params&mode=cloud`.
fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(r"(?i)^(?:http|ntfy)s?://ntfy\.sh(?P<topics>/[^?]+)?(?P<params>\?.+)?\n?$");
    let c = re.captures(url)?;
    let topics = c.name("topics").map(|m| m.as_str()).unwrap_or("");
    let params = match c.name("params") {
        Some(p) => format!("{}&mode=cloud", p.as_str()),
        None => "?mode=cloud".into(),
    };
    Some(format!("ntfys://{topics}{params}"))
}

/// One upload: (filename, data).
struct Upload {
    name: String,
    data: bytes::Bytes,
}

/// Per-message values shared by every request.
struct Common<'a> {
    image_url: Option<&'a str>,
    format: NotifyFormat,
    app_id: &'a str,
    env: &'a dyn Env,
}

impl Ntfy {
    /// Publish to one topic; `None` attach sends JSON.
    fn send_one(&self, topic: &str, body: &str, title: &str, upload: Option<Upload>, common: &Common<'_>) -> Plan {
        let mut headers: Vec<(&str, String)> = vec![("User-Agent", common.app_id.to_string())];
        let mut basic: Option<(&str, Option<&str>)> = None;
        let mut url = match self.mode {
            Mode::Cloud => CLOUD_URL.to_string(),
            Mode::Private => {
                match self.auth {
                    Auth::Basic => {
                        if let Some(user) = &self.user {
                            basic = Some((user, self.password.as_ref().map(Secret::expose)));
                        }
                    }
                    Auth::Token => match &self.token {
                        None => return Plan::Fail(SERVICE.err("no ntfy token was specified")),
                        Some(t) => headers.push(("Authorization", format!("Bearer {}", t.expose()))),
                    },
                }
                self.base.clone()
            }
        };

        let mut payload = Map::new();
        let mut params: Vec<(&str, String)> = Vec::new();
        let is_upload = upload.is_some();
        if !is_upload {
            headers.push(("Content-Type", "application/json".into()));
            payload.insert("topic".into(), json!(topic));
            if let Some(a) = &self.attach {
                payload.insert("attach".into(), json!(a));
                if let Some(f) = &self.filename {
                    payload.insert("filename".into(), json!(f));
                }
            }
            if !title.is_empty() {
                payload.insert("title".into(), json!(title));
            }
            if !body.is_empty() {
                payload.insert("message".into(), json!(crate::http::TEXT));
            }
        } else {
            url.push('/');
            url.push_str(topic);
            params.push(("filename", upload.as_ref().map(|u| u.name.clone()).unwrap_or_default()));
            if !title.is_empty() {
                params.push(("title", title.to_string()));
            }
            if !body.is_empty() {
                params.push(("message", body.to_string()));
            }
        }
        if let Some(i) = common.image_url {
            headers.push(("X-Icon", i.to_string()));
        }
        if common.format == NotifyFormat::Markdown {
            headers.push(("X-Markdown", "yes".into()));
        }
        if self.priority != PRIORITY_DEFAULT {
            headers.push(("X-Priority", self.priority.into()));
        }
        if let Some(d) = &self.delay {
            headers.push(("X-Delay", d.clone()));
        }
        if let Some(c) = &self.click {
            headers.push(("X-Click", quote(c, ":/?@&=#")));
        }
        if let Some(e) = &self.email {
            headers.push(("X-Email", e.clone()));
        }
        if !self.tags.is_empty() {
            headers.push(("X-Tags", self.tags.join(",")));
        }
        if let Some(a) = self.actions.as_ref().filter(|a| !a.is_empty()) {
            headers.push(("X-Actions", a.clone()));
        }

        let data: bytes::Bytes = match upload {
            Some(up) => up.data,
            None => {
                if crate::http::json_text_len(&Value::Object(payload.clone()), body) > JSON_SIZE_LIMIT {
                    // Send the message as an attachment instead.
                    let content =
                        format!("{}{}", if title.is_empty() { String::new() } else { format!("{title}\n") }, body);
                    let name = format!("{}.txt", common.env.uuid4());
                    let up = Upload { name, data: bytes::Bytes::from(content.into_bytes()) };
                    return self.send_one(topic, "", "", Some(up), common);
                }
                bytes::Bytes::from(crate::http::json_with_text(&Value::Object(payload), body))
            }
        };

        let mut req = Request::post(url).query(&params).body(data, None);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        if let Some((user, pw)) = basic {
            req = req.basic_auth(user, pw);
        }
        Plan::http(req, |res| match res {
            Ok(r) if r.status == 200 => Plan::Done,
            Ok(r) => {
                let mut status = r.status;
                let mut reason = r.snippet();
                if let Some(Value::Object(j)) = r.json() {
                    if let Some(e) = j.get("error").and_then(Value::as_str) {
                        reason = e.to_string();
                    }
                    if let Some(c) = j.get("code").and_then(|c| c.as_u64().or_else(|| c.as_str()?.parse().ok())) {
                        status = u16::try_from(c).unwrap_or(status);
                    }
                }
                Plan::Fail(if status == r.status { r.http_error_with(reason) } else { Error::Http { status, reason } })
            }
            Err(e) => Plan::Fail(e),
        })
    }
}

impl Notify for Ntfy {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.topics.is_empty() {
            return Plan::Fail(SERVICE.err("there are no ntfy topics to notify"));
        }
        let image = ctx.asset.image_url(msg.kind, ImageSize::Xy256);
        let avatar = self.avatar_url.as_deref().filter(|a| !a.is_empty());
        let image_url: Option<String> = if self.include_image && (image.is_some() || avatar.is_some()) {
            avatar.map(str::to_string).or(image)
        } else {
            None
        };
        let common =
            Common { image_url: image_url.as_deref(), format: msg.format, app_id: ctx.app_id(), env: ctx.env().as_ref() };

        let topics = self.topics.iter();
        if !msg.attachments.is_empty() {
            Plan::chain(topics.map(|topic| {
                Plan::chain(msg.attachments.iter().enumerate().map(|(no, a)| {
                    let (body, title) = if no == 0 { (msg.body, msg.title) } else { ("", "") };
                    let up = Upload { name: a.name.clone(), data: a.data.clone() };
                    self.send_one(topic, body, title, Some(up), &common)
                }))
                .target(topic.clone())
            }))
        } else {
            Plan::all(
                topics.map(|topic| self.send_one(topic, msg.body, msg.title, None, &common).target(topic.clone())),
            )
        }
    }

}
