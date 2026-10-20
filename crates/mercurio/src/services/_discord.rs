//! Helpers shared by services (Discord engine used by `discord`; mention detection used by `notifiarr`).

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::asset::ImageSize;
use crate::error::Error;
use crate::http::{Multipart, Request, Response};
use crate::message::{Attachment, NotifyFormat};
use crate::parse::{parse_list, validate_nonblank};
use crate::service::{Context, Notify, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::util::parse_int;
use crate::{FileOp, Plan, Prepared, Result};

/// One `USER_ROLE_DETECTION_RE` match: `(is_role, id, value)`.
pub type Mention = (bool, String, String);

/// `USER_ROLE_DETECTION_RE.findall(text)`.
pub fn find_mentions(text: &str) -> Vec<Mention> {
    let re = crate::regex!(r"(?i)\s*(?:<?@(&?)([0-9]+)>?|@([a-z0-9]+))");
    re.captures_iter(text)
        .map(|c| {
            (
                c.get(1).is_some_and(|m| !m.as_str().is_empty()),
                c.get(2).map(|m| m.as_str().to_string()).unwrap_or_default(),
                c.get(3).map(|m| m.as_str().to_string()).unwrap_or_default(),
            )
        })
        .collect()
}

fn push_unique(v: &mut Vec<String>, s: &str) {
    if !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}

/// Discord `ping_payload(*args)`: `allow_mentions` + `content`.
fn ping_payload(args: &[&str]) -> Map<String, Value> {
    let mut parse = Vec::new();
    let mut users = Vec::new();
    let mut roles = Vec::new();
    for arg in args {
        for (is_role, no, value) in find_mentions(arg) {
            if !value.is_empty() {
                push_unique(&mut parse, &value);
            } else if is_role {
                push_unique(&mut roles, &no);
            } else {
                push_unique(&mut users, &no);
            }
        }
    }
    let mut out = Map::new();
    if parse.is_empty() && users.is_empty() && roles.is_empty() {
        return out;
    }
    let tokens: Vec<String> = parse
        .iter()
        .map(|v| format!("@{v}"))
        .chain(roles.iter().map(|v| format!("<@&{v}>")))
        .chain(users.iter().map(|v| format!("<@{v}>")))
        .collect();
    out.insert("allow_mentions".into(), json!({"parse": parse, "users": users, "roles": roles}));
    out.insert("content".into(), json!(format!("👉 {}", tokens.join(" "))));
    out
}


const DISCORD_MAX_FIELDS: usize = 10;
const DISCORD_FIELD_NAME_MAXLEN: usize = 256;
const DISCORD_FIELD_VALUE_MAXLEN: usize = 1024;
const DISCORD_MAX_TEMPLATE_SIZE: u64 = 35000;
const DISCORD_MAX_ATTACHMENTS: usize = 10;
const DISCORD_MAX_ATTACH_BYTES: usize = 25 * 1024 * 1024;
/// `clock_skew` added to rate-limit waits.
const CLOCK_SKEW_SECS: f64 = 10.0;

#[derive(Debug, Clone)]
enum Template {
    /// Local file path.
    File(String),
    /// Remote template (`http(s)://`): not supported by mercurio.
    Remote,
}

#[derive(Debug)]
pub struct Discord {
    name: &'static str,
    notify_url: &'static str,
    webhook_id: Secret,
    webhook_token: Secret,
    user: Option<String>,
    tts: bool,
    avatar: bool,
    footer: bool,
    footer_logo: bool,
    include_image: bool,
    fields: bool,
    avatar_url: Option<String>,
    href: Option<String>,
    thread: Option<String>,
    flags: Option<i64>,
    ping: Vec<String>,
    template: Option<Template>,
    tokens: Vec<(String, String)>,
    batch: bool,
    use_embeds: bool,
    /// `?emojis=no` on `discord://`: every `:name:` is sent escaped.
    escape_emojis: bool,
}

/// Escape the colon that opens each `:name:` so Discord shows it as text (`2001:db8:100::1` would otherwise show an emoji for `:100:`). Escaped characters, code spans, `<...>` tokens and web links are left alone.
pub fn escape_emojis(text: &str) -> String {
    let c: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len() + 8);
    let mut i = 0;
    let name_char = |ch: char| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '+' | '-');
    while i < c.len() {
        let skip = match c[i] {
            '\\' if i + 1 < c.len() => Some(i + 2),
            '`' => {
                // A run of n backticks closes on n backticks (fewer when that fails).
                let run = c[i..].iter().take_while(|&&ch| ch == '`').count();
                (1..=run).rev().find_map(|n| {
                    let ticks = |j: usize| j + n <= c.len() && c[j..j + n].iter().all(|&ch| ch == '`');
                    (i + n + 1..c.len()).find(|&j| ticks(j)).map(|j| j + n)
                })
            }
            '<' => c[i + 1..]
                .iter()
                .position(|&ch| ch == '<' || ch == '>' || ch.is_whitespace())
                .filter(|&k| c[i + 1 + k] == '>')
                .map(|k| i + k + 2),
            'h' | 'H' => {
                let rest: String = c[i..c.len().min(i + 8)].iter().collect::<String>().to_ascii_lowercase();
                let scheme = if rest.starts_with("https://") {
                    8
                } else if rest.starts_with("http://") {
                    7
                } else {
                    0
                };
                let tail = c[i + scheme..].iter().take_while(|ch| !ch.is_whitespace()).count();
                (scheme > 0 && tail > 0).then(|| i + scheme + tail)
            }
            _ => None,
        };
        if let Some(end) = skip {
            out.extend(&c[i..end]);
            i = end;
            continue;
        }
        if c[i] == ':' {
            let name = c[i + 1..].iter().take_while(|&&ch| name_char(ch)).count();
            if name > 0 && c.get(i + 1 + name) == Some(&':') {
                out.push_str("\\:");
                i += 1;
                continue;
            }
        }
        out.push(c[i]);
        i += 1;
    }
    out
}

pub fn discord_parse(def: &'static ServiceDef, notify_url: &'static str, u: &ParsedUrl) -> Result<Discord> {
    let webhook_id = validate_nonblank(&u.host())
        .ok_or_else(|| def.err(format!("an invalid {} Webhook ID was specified", def.name)))?;
    let webhook_token = u.path_segments()
        .into_iter()
        .next()
        .and_then(|t| validate_nonblank(&t))
        .ok_or_else(|| def.err(format!("an invalid {} Webhook Token was specified", def.name)))?;

    let mut user = u.user();
    if let Some(b) = u.param("botname") {
        user = Some(unquote(&unquote(b)));
    }

    let flags = match def.raw(u, "flags").map(unquote) {
        Some(f) if !f.is_empty() => match parse_int(&f) {
            Some(n) if n >= 0 => Some(n),
            _ => return Err(def.err("an invalid flags setting was specified")),
        },
        _ => None,
    };

    let mut use_embeds = u.format == Some(NotifyFormat::Markdown);
    let href = if let Some(h) = u.param("href") {
        Some(unquote(h))
    } else if let Some(h) = u.param("url") {
        use_embeds = true;
        Some(unquote(h))
    } else {
        None
    };
    let thread = def.raw(u, "thread").map(|t| {
        use_embeds = true;
        unquote(t)
    });

    let template = match def.text(u, "template") {
        None => None,
        Some(t) => Some(parse_template(def, &t)?),
    };

    Ok(Discord {
        name: def.name,
        notify_url,
        webhook_id: Secret::new(webhook_id),
        webhook_token: Secret::new(webhook_token),
        user: user.filter(|s| !s.is_empty()),
        tts: def.flag_strict(u, "tts"),
        avatar: def.flag_strict(u, "avatar"),
        footer: def.flag_strict(u, "footer"),
        footer_logo: def.flag_strict(u, "footer_logo"),
        include_image: def.flag_strict(u, "image"),
        fields: def.flag_strict(u, "fields"),
        avatar_url: def.text(u, "avatar_url"),
        href: href.filter(|s| !s.is_empty()),
        thread: thread.filter(|s| !s.is_empty()),
        flags: flags.filter(|f| *f != 0),
        ping: def.raw(u, "ping").map(|p| parse_list([unquote(p)])).unwrap_or_default(),
        template,
        tokens: u.query_colon.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        batch: def.flag_strict(u, "batch"),
        use_embeds,
        escape_emojis: def.id == "discord" && !def.flag_strict(u, "emojis"),
    })
}

fn parse_template(def: &'static ServiceDef, t: &str) -> Result<Template> {
    match crate::url::scheme_of(t) {
        None => Ok(Template::File(t.to_string())),
        Some(s) if s == "file" => {
            let rest = t.split_once("://").map(|(_, r)| r).unwrap_or("");
            let path = rest.split('?').next().unwrap_or("");
            Ok(Template::File(unquote(path)))
        }
        Some(s) if s == "http" || s == "https" => Ok(Template::Remote),
        Some(_) => Err(def.err("the template specified could not be loaded")),
    }
}

/// `apply_template(content, app_mode=JSON, **tokens)`.
fn apply_template(content: &str, tokens: &[(String, String)]) -> std::result::Result<String, String> {
    if tokens.is_empty() {
        return Ok(content.to_string());
    }
    let alts: Vec<String> = tokens.iter().map(|(k, _)| regex::escape(k)).collect();
    let pattern = format!(r"(?i)\{{\{{\s*({})\s*\}}\}}", alts.join("|"));
    let re = regex::Regex::new(&pattern).map_err(|e| e.to_string())?;
    let mut missing = None;
    let out = re.replace_all(content, |c: &regex::Captures| {
        let m = c.get(0).map_or("", |m| m.as_str());
        let key = m.get(2..m.len().saturating_sub(2)).unwrap_or("").trim();
        match tokens.iter().find(|(k, _)| k == key) {
            Some((_, v)) => {
                let s = serde_json::to_string(v).unwrap_or_default();
                s.get(1..s.len().saturating_sub(1)).unwrap_or("").to_string()
            }
            None => {
                missing = Some(key.to_string());
                String::new()
            }
        }
    });
    match missing {
        Some(k) => Err(format!("template token {k:?} is not defined")),
        None => Ok(out.into_owned()),
    }
}

/// Shared, immutable request data for a delivery sequence.
struct Endpoint {
    url: String,
    user_agent: String,
    params: Option<String>,
}

enum Step {
    Json(Value),
    Files(Value, Vec<Attachment>),
}

#[derive(Clone, Copy)]
struct RateLimit {
    remaining: f64,
    /// Unix seconds.
    reset: f64,
}

fn now_secs() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn build_request(ep: &Endpoint, step: &Step) -> Request {
    let mut req = Request::post(ep.url.clone()).header("User-Agent", ep.user_agent.clone());
    if let Some(t) = &ep.params {
        req = req.query(&[("thread_id", t.as_str())]);
    }
    match step {
        Step::Json(p) => req
            .header("Content-Type", "application/json; charset=utf-8")
            .body(serde_json::to_vec(p).unwrap_or_default(), None),
        Step::Files(p, files) => {
            let mut form = Multipart::new().text("payload_json", serde_json::to_string(p).unwrap_or_default());
            for (i, a) in files.iter().enumerate() {
                form = form.file(format!("files[{i}]"), a.name.clone(), a.mime.clone(), a.data.clone());
            }
            req.multipart(form)
        }
    }
}

fn update_ratelimit(rl: &mut RateLimit, r: &Response) {
    let rem = r.header("X-RateLimit-Remaining").and_then(|v| v.trim().parse::<f64>().ok());
    let reset = r.header("X-RateLimit-Reset").and_then(parse_int);
    if let (Some(rem), Some(reset)) = (rem, reset) {
        rl.remaining = rem;
        rl.reset = reset as f64;
    }
}

/// Send `steps` in order; stop at the first failure (the whole send fails).
fn run_steps(ep: Arc<Endpoint>, mut steps: VecDeque<Step>, rl: RateLimit, retries: u32) -> Plan {
    let Some(step) = steps.pop_front() else { return Plan::Done };
    let mut pre = Vec::new();
    if rl.remaining <= 0.0 {
        let now = now_secs();
        if now < rl.reset {
            pre.push(Plan::Sleep(Duration::from_secs_f64(rl.reset - now + CLOCK_SKEW_SECS)));
        }
    }
    let req = build_request(&ep, &step);
    let next = Plan::http(req, move |res| {
        let r = match res {
            Ok(r) => r,
            Err(e) => return Plan::Fail(e),
        };
        let mut rl = rl;
        update_ratelimit(&mut rl, &r);
        if r.status == 200 || r.status == 204 {
            return run_steps(ep, steps, rl, 1);
        }
        if r.status == 429 && retries > 0 {
            steps.push_front(step);
            return run_steps(ep, steps, rl, retries - 1);
        }
        // Without `Retry-After`, Discord's bucket reset is the wait.
        if r.status == 429 && r.retry_after().is_none() && rl.reset > now_secs() {
            let retry_after = Duration::from_secs_f64(rl.reset - now_secs() + CLOCK_SKEW_SECS);
            return Plan::Fail(r.rate_limited_or_http(Some(retry_after)));
        }
        Plan::Fail(r.http_error())
    });
    pre.push(next);
    Plan::chain(pre)
}

impl Discord {
    fn load_template(
        &self,
        template: &Template,
        msg: &Prepared<'_>,
        ctx: &Context<'_>,
    ) -> std::result::Result<Map<String, Value>, Error> {
        let path = match template {
            Template::File(p) => p,
            Template::Remote => {
                return Err(Error::Unsupported(format!("{}: remote templates are not supported", self.name)));
            }
        };
        let fail = |why: &str| Error::Service(format!("{} template {why}", self.name));
        let raw = ctx.local_file(path, DISCORD_MAX_TEMPLATE_SIZE).map_err(fail)?;
        if raw.is_empty() {
            return Err(fail("could not be accessed"));
        }
        let raw = std::str::from_utf8(raw).map_err(|_| fail("could not be read"))?;

        let image_url = ctx.asset.image_url(msg.kind, ImageSize::Xy256).unwrap_or_default();
        let mut tokens: Vec<(String, String)> = self.tokens.clone();
        let mut set = |k: &str, v: String| {
            if let Some(slot) = tokens.iter_mut().find(|(key, _)| key == k) {
                slot.1 = v;
            } else {
                tokens.push((k.to_string(), v));
            }
        };
        set("app_body", msg.body.to_string());
        set("app_title", msg.title.to_string());
        set("app_type", msg.kind.as_str().to_string());
        set("app_id", ctx.app_id().to_string());
        set("app_desc", ctx.app_desc().to_string());
        set("app_color", ctx.asset.color(msg.kind).to_string());
        set("app_color_hex", ctx.asset.color(msg.kind).to_string());
        set("app_color_int", ctx.asset.color_int(msg.kind).to_string());
        set("app_image_url", image_url);
        set("app_url", ctx.app_url().to_string());

        let content = apply_template(raw, &tokens).map_err(|e| fail(&e))?;
        let value: Value = serde_json::from_str(&content).map_err(|_| fail("contains invalid JSON"))?;
        let Value::Object(obj) = value else { return Err(fail("must be a JSON object")) };
        let has_content = obj.get("content").and_then(Value::as_str).is_some_and(|s| !s.is_empty());
        let embeds = obj.get("embeds").and_then(Value::as_array).filter(|a| !a.is_empty());
        if !has_content && embeds.is_none() {
            return Err(fail("must contain a non-empty 'content' string or a non-empty 'embeds' list"));
        }
        if embeds.is_some_and(|e| !e.iter().all(Value::is_object)) {
            return Err(fail("contains an embed entry that is not a JSON object"));
        }
        Ok(obj)
    }
}

impl Notify for Discord {
    fn convert(&self, body: &str, _format: NotifyFormat) -> Option<String> {
        self.escape_emojis.then(|| escape_emojis(body))
    }

    fn files(&self, _: &Context<'_>) -> Vec<FileOp> {
        match &self.template {
            Some(Template::File(path)) => FileOp::local_file(path).into(),
            _ => Vec::new(),
        }
    }

    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        // The title skips `convert`, so it is escaped here.
        let title;
        let escaped;
        let msg = if self.escape_emojis && !msg.passthrough && !msg.title.is_empty() {
            title = escape_emojis(msg.title);
            escaped = Prepared { title: &title, ..*msg };
            &escaped
        } else {
            msg
        };
        let mut payload = Map::new();
        payload.insert("tts".into(), json!(self.tts));
        payload.insert("wait".into(), json!(!self.tts));
        if let Some(f) = self.flags {
            payload.insert("flags".into(), json!(f));
        }
        let image_url = ctx.asset.image_url(msg.kind, ImageSize::Xy256);
        if self.avatar
            && let Some(a) = self.avatar_url.clone().or_else(|| image_url.clone())
        {
            payload.insert("avatar_url".into(), json!(a));
        }
        if let Some(u) = &self.user {
            payload.insert("username".into(), json!(u));
        }

        if self.template.is_none() {
            let pings = self.ping.join(" ");
            let extra = if self.use_embeds {
                if self.ping.is_empty() { ping_payload(&[msg.body]) } else { ping_payload(&[msg.body, &pings]) }
            } else if !self.ping.is_empty() {
                ping_payload(&[&pings])
            } else {
                Map::new()
            };
            payload.extend(extra);
        }

        let mut steps = VecDeque::new();
        if let Some(template) = &self.template {
            match self.load_template(template, msg, ctx) {
                Ok(t) => payload.extend(t),
                Err(e) => return Plan::Fail(e),
            }
            steps.push_back(Step::Json(Value::Object(payload.clone())));
        } else if !msg.body.is_empty() {
            let mut fields: Vec<Value> = Vec::new();
            if self.use_embeds {
                let mut embed = Map::new();
                embed.insert("author".into(), json!({"name": ctx.app_id(), "url": ctx.app_url()}));
                embed.insert("title".into(), json!(msg.title));
                embed.insert("description".into(), json!(msg.body));
                embed.insert("color".into(), json!(ctx.asset.color_int(msg.kind)));
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
                    && let Some(img) = &image_url
                {
                    embed.insert("thumbnail".into(), json!({"url": img, "height": 256, "width": 256}));
                }
                if self.fields {
                    let (description, sections) = crate::convert::markup::sections(
                        msg.body,
                        DISCORD_FIELD_NAME_MAXLEN,
                        DISCORD_FIELD_VALUE_MAXLEN - 10,
                    );
                    fields = sections
                        .into_iter()
                        .map(|(name, value)| {
                            let value = if value.is_empty() {
                                "```\n```".to_string()
                            } else {
                                format!("```md\n{}\n```", value.trim_end())
                            };
                            json!({"name": name, "value": value})
                        })
                        .collect();
                    embed.insert("description".into(), json!(description));
                    if !fields.is_empty() {
                        let rest = fields.split_off(fields.len().min(DISCORD_MAX_FIELDS));
                        embed.insert("fields".into(), Value::Array(std::mem::replace(&mut fields, rest)));
                    }
                }
                payload.insert("embeds".into(), json!([embed]));
            } else {
                let mut content =
                    if msg.title.is_empty() { msg.body.to_string() } else { format!("{}\r\n{}", msg.title, msg.body) };
                if let Some(Value::String(c)) = payload.get("content") {
                    content.push_str(c);
                }
                payload.insert("content".into(), json!(content));
            }
            steps.push_back(Step::Json(Value::Object(payload.clone())));

            if !fields.is_empty() {
                payload["embeds"][0]["description"] = json!("");
                for chunk in fields.chunks(DISCORD_MAX_FIELDS) {
                    payload["embeds"][0]["fields"] = Value::Array(chunk.to_vec());
                    steps.push_back(Step::Json(Value::Object(payload.clone())));
                }
            }
        }

        if !msg.attachments.is_empty() {
            payload.insert("tts".into(), json!(false));
            payload.insert("wait".into(), json!(true));
            payload.remove("embeds");
            payload.remove("content");
            payload.remove("allow_mentions");
            let max_per = if self.batch { DISCORD_MAX_ATTACHMENTS } else { 1 };
            let mut batches: Vec<Vec<Attachment>> = Vec::new();
            let mut current: Vec<Attachment> = Vec::new();
            let mut size = 0usize;
            for a in msg.attachments {
                let len = if self.batch { a.data.len() } else { 0 };
                if !current.is_empty()
                    && (current.len() >= max_per || (self.batch && size + len > DISCORD_MAX_ATTACH_BYTES))
                {
                    batches.push(std::mem::take(&mut current));
                    size = 0;
                }
                current.push(a.clone());
                size += len;
            }
            batches.push(current);
            let p = Value::Object(payload);
            for b in batches {
                steps.push_back(Step::Files(p.clone(), b));
            }
        }

        let ep = Arc::new(Endpoint {
            url: format!("{}/{}/{}", self.notify_url, self.webhook_id.expose(), self.webhook_token.expose()),
            user_agent: ctx.app_id().to_string(),
            params: self.thread.clone(),
        });
        run_steps(ep, steps, RateLimit { remaining: 1.0, reset: 0.0 }, 1)
    }
}

/// `parse_native_url` for Discord-style webhook URLs: `{scheme}://{id}/{token}/{params}`.
pub fn native_webhook(url: &str, re: &regex::Regex, scheme: &str) -> Option<String> {
    let c = re.captures(url)?;
    Some(format!(
        "{scheme}://{}/{}/{}",
        &c["webhook_id"],
        &c["webhook_token"],
        c.name("params").map(|m| m.as_str()).unwrap_or("")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emoji_escape_cases() {
        // Text with colons that must not turn into emoji shortcodes.
        for (text, expected) in [
            ("2001:db8:100::1", "2001\\:db8\\:100::1"),
            ("00:ab:cd:ef:12:34", "00\\:ab\\:cd\\:ef\\:12:34"),
            ("12:30:45", "12\\:30:45"),
            (":smile:", "\\:smile:"),
            (":smile::smile:", "\\:smile:\\:smile:"),
            (":a:b:", "\\:a\\:b:"),
            ("ok:smile:ok", "ok\\:smile:ok"),
            (":+1: :-1:", "\\:+1: \\:-1:"),
            ("**:fire:**", "**\\:fire:**"),
            ("_:fire:_", "_\\:fire:_"),
            ("# Title :fire:", "# Title \\:fire:"),
            ("> quote :fire:", "> quote \\:fire:"),
            ("- item :fire:", "- item \\:fire:"),
            ("`2001:db8:100::1`", "`2001:db8:100::1`"),
            ("``a:b:c``", "``a:b:c``"),
            ("x `:a:` :b: `:c:`", "x `:a:` \\:b: `:c:`"),
            ("```\n:smile:\n```", "```\n:smile:\n```"),
            ("```py\nx = {'a:b:': 1}\n```\n:c:", "```py\nx = {'a:b:': 1}\n```\n\\:c:"),
            ("`:smile:", "`\\:smile:"),
            ("<:party:123>", "<:party:123>"),
            ("<a:wave:456>", "<a:wave:456>"),
            ("<t:1700000000:R>", "<t:1700000000:R>"),
            ("<@123> <@&456> <#789> </cmd:9>", "<@123> <@&456> <#789> </cmd:9>"),
            ("a < b :c: > d", "a < b \\:c: > d"),
            ("https://[fe80::1:2]/x:y:", "https://[fe80::1:2]/x:y:"),
            ("HTTP://a.ca/:b:", "HTTP://a.ca/:b:"),
            ("http://host:8080/", "http://host:8080/"),
            ("<https://a.ca/:b:>", "<https://a.ca/:b:>"),
            ("[link](https://a.ca/:b:) :c:", "[link](https://a.ca/:b:) \\:c:"),
            ("\\:smile:", "\\:smile:"),
            ("\\\\:smile:", "\\\\\\:smile:"),
            ("time: 5", "time: 5"),
            ("a::b", "a::b"),
            (":AB:", ":AB:"),
            (":", ":"),
            ("", ""),
        ] {
            assert_eq!(escape_emojis(text), expected, "{text:?}");
        }
    }

    #[test]
    fn emoji_escape_is_linear() {
        for (prefix, piece, count) in [
            ("", "`x", 100_000),
            ("", "``x", 70_000),
            ("``", "x", 200_000),
            ("", "<a:b:", 40_000),
            ("http://", ":a", 100_000),
            ("", "a:", 100_000),
            ("", ":", 200_000),
            ("", "\\", 200_000),
            ("", "`a:b\\:<", 30_000),
        ] {
            let text = format!("{prefix}{}", piece.repeat(count));
            let start = std::time::Instant::now();
            escape_emojis(&text);
            assert!(start.elapsed() < std::time::Duration::from_secs(2), "{piece:?}");
        }
    }

    #[test]
    fn mentions() {
        let m = find_mentions("hi <@123> <@&456> @here");
        assert_eq!(m.len(), 3);
        assert!(m[1].0);
        assert_eq!(m[2].2, "here");
    }

    #[test]
    fn template_tokens() {
        let t = vec![("app_body".to_string(), "a\"b".to_string())];
        assert_eq!(apply_template("{\"c\": \"{{ app_body }}\"}", &t).unwrap(), "{\"c\": \"a\\\"b\"}");
    }
}
