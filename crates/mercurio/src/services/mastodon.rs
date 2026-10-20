//! Mastodon (`mastodon://`, `toot://`, `mastodons://`, `toots://`): posts statuses to a Mastodon instance.
//!
//! # Differences with Apprise
//!
//! - The rate-limit reset is read from `X-RateLimit-Reset` (an RFC 3339 time); Apprise reads `X-RateLimit-Limit`, a request count, so its back-off never waits. The budget is kept for the life of the URL, as in Apprise. *intentional*
//! - The account lookup of direct mode is kept for the life of the URL whatever `?cache=` says, as in Apprise (whose `_whoami()` call ignores it). *intentional*
//! - In direct mode prepended targets keep their configured (sorted) order; Apprise iterates an unordered set. *intentional*

use std::sync::Arc;

use super::_ratelimit::{RateLimit, Reset};

use serde_json::{Map, Value, json};

use crate::env::Env;
use crate::http::{Method, Multipart, Request, Response};
use crate::parse::parse_list;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::util::json_has_value;
use crate::{Error, NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "mastodon",
    name: "Mastodon",
    schemes: &["mastodon", "toot", "mastodons", "toots"],
    service_url: "https://joinmastodon.org",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: BODY_MAXLEN, body_max_line_count: 0 },
    formats: &[NotifyFormat::Text],
    attachments: true,
    templates: &[
        "{schema}://{token}@{host}",
        "{schema}://{token}@{host}:{port}",
        "{schema}://{token}@{host}/{targets}",
        "{schema}://{token}@{host}:{port}/{targets}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("port", "Port").port(),
        Param::new("target_user", "Target User").prefix("@"),
        Param::new("targets", "Targets").list("/").group(&["target_user"]),
        Param::new("token", "Access Token").required(),
    ],
    params: &[
        Param::new("batch", "Batch Mode").bool(true),
        Param::new("key", "Idempotency-Key"),
        Param::new("language", "Language Code"),
        Param::new("ping", "Ping Users/Tags").list(", "),
        Param::new("sensitive", "Sensitive Attachments").bool(false),
        Param::new("spoiler", "Spoiler Text"),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
        Param::new("visibility", "Visibility").choice(&["default", "direct", "private", "unlisted", "public"]).default("default").inferred(),
    ],
    ..ServiceDef::DEFAULTS
};

const BODY_MAXLEN: usize = 500;
const BATCH_SIZE: usize = 4;
const VISIBILITIES: &[&str] = &["default", "direct", "private", "unlisted", "public"];

#[derive(Debug)]
struct Config {
    api_url: String,
    token: Secret,
    visibility: &'static str,
    batch: bool,
    sensitive: bool,
    spoiler: Option<String>,
    key: Option<String>,
    language: Option<String>,
    targets: Vec<String>,
    hashtags: Vec<String>,
    ping: Vec<String>,
    /// The request budget, shared by every send of this URL.
    rate: Arc<RateLimit>,
    /// `@user` of the authenticated account once looked up, kept for the life of the URL (Apprise's `_whoami_cache`).
    whoami: std::sync::Mutex<Option<String>>,
}

#[derive(Debug)]
struct Mastodon(Arc<Config>);

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn is_user_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn is_host_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
}

/// `IS_USER`: `^\s*@?(?P<user>[A-Z0-9_]+(?:@[A-Z0-9_.-]+)?)$` (re.I).
fn is_user(s: &str) -> Option<String> {
    let re = crate::regex!(r"(?i)^\s*@?([A-Z0-9_]+(?:@[A-Z0-9_.-]+)?)\n?$");
    re.captures(s).map(|c| c[1].to_string())
}

/// `HASHTAG_VALUE_RE` plus the "not all digits" rule.
fn valid_hashtag(token: &str) -> bool {
    let value = token.strip_prefix('#').unwrap_or(token);
    let mut chars = value.chars();
    match chars.next() {
        Some(c) if is_word(c) && c != '_' => {}
        _ => return false,
    }
    if !chars.all(is_word) {
        return false;
    }
    let digits: String = value.chars().filter(|c| *c != '_').collect();
    digits.is_empty() || !digits.chars().all(|c| c.is_numeric())
}

fn normalize_ping_token(token: &str) -> Option<String> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    if token.starts_with('@')
        && let Some(user) = is_user(token)
    {
        return Some(format!("@{user}"));
    }
    if token.starts_with('#') {
        return valid_hashtag(token).then(|| token.to_string());
    }
    None
}

fn casefold(s: &str) -> String {
    s.to_lowercase()
}

fn lookahead_ok(chars: &[char], p: usize) -> bool {
    p == chars.len() || chars[p].is_whitespace() || ",.&()[]<>".contains(chars[p])
}

/// `MENTION_DETECTION_RE.findall`: `(?<![\w@])(@[A-Z0-9_]+(?:@[A-Z0-9_.-]+)?)(?=$|[\s,.&()\[\]<>]+)`.
fn find_mentions(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        if chars[i] != '@' || (i > 0 && (is_word(chars[i - 1]) || chars[i - 1] == '@')) {
            i += 1;
            continue;
        }
        let mut u = i + 1;
        while u < n && is_user_char(chars[u]) {
            u += 1;
        }
        if u == i + 1 {
            i += 1;
            continue;
        }
        let mut end = None;
        // Greedy user part; with or without the optional @host suffix.
        for ue in (i + 2..=u).rev() {
            if ue < n && chars[ue] == '@' {
                let mut h = ue + 1;
                while h < n && is_host_char(chars[h]) {
                    h += 1;
                }
                if let Some(he) = (ue + 2..=h).rev().find(|he| lookahead_ok(&chars, *he)) {
                    end = Some(he);
                    break;
                }
            }
            if lookahead_ok(&chars, ue) {
                end = Some(ue);
                break;
            }
        }
        match end {
            Some(e) => {
                out.push(chars[i..e].iter().collect());
                i = e;
            }
            None => i += 1,
        }
    }
    out
}

/// `HASHTAG_DETECTION_RE.findall`: `(?<![#%\w])(#[^\W_][\w]*)(?![#%\w])`.
fn find_hashtags(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        let prev_ok = i == 0 || !(is_word(chars[i - 1]) || matches!(chars[i - 1], '#' | '%'));
        if chars[i] != '#' || !prev_ok || i + 1 >= n || !is_word(chars[i + 1]) || chars[i + 1] == '_' {
            i += 1;
            continue;
        }
        let mut e = i + 2;
        while e < n && is_word(chars[e]) {
            e += 1;
        }
        if e < n && matches!(chars[e], '#' | '%') {
            i += 1;
            continue;
        }
        out.push(chars[i..e].iter().collect());
        i = e;
    }
    out
}

fn ping_tokens_scan(text: &str, seen: &mut Vec<String>) -> Vec<String> {
    let mut results = Vec::new();
    let mut add = |t: String, seen: &mut Vec<String>| {
        let k = casefold(&t);
        if !seen.contains(&k) {
            seen.push(k);
            results.push(t);
        }
    };
    for t in find_mentions(text) {
        add(t, seen);
    }
    for t in find_hashtags(text) {
        if valid_hashtag(&t) {
            add(t, seen);
        }
    }
    results
}

fn ping_tokens_normalized(text: &str, seen: &mut Vec<String>) -> Vec<String> {
    let mut results = Vec::new();
    for token in parse_list([text]) {
        if let Some(n) = normalize_ping_token(&token) {
            let k = casefold(&n);
            if !seen.contains(&k) {
                seen.push(k);
                results.push(n);
            }
        }
    }
    results
}

fn ping_payload(tokens: &[String]) -> String {
    if tokens.is_empty() { String::new() } else { format!(" {}", tokens.join(" ")) }
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let token = if let Some(t) = SERVICE.text(u, "token") {
        Some(t)
    } else if u.password.as_deref().is_none_or(str::is_empty) && u.user.as_deref().is_some_and(|s| !s.is_empty()) {
        u.user.as_deref().map(unquote)
    } else {
        None
    };
    let token = token
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| SERVICE.err("an invalid Mastodon Access Token was specified"))?;

    let mut raw_targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        raw_targets.extend(parse_list([to]));
    }

    let visibility = match SERVICE.text(u, "visibility") {
        Some(v) => Some(v),
        None if u.scheme.starts_with("toot") => Some("public".to_string()),
        None => None,
    };
    let visibility = match visibility.filter(|v| !v.is_empty()) {
        None => "default",
        Some(v) => {
            let vis = v.trim().to_lowercase();
            VISIBILITIES
                .iter()
                .copied()
                .find(|x| x.starts_with(&vis))
                .ok_or_else(|| SERVICE.err("the Mastodon visibility specified is invalid"))?
        }
    };

    let mut api_url = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = u.port {
        api_url.push_str(&format!(":{p}"));
    }

    let mut targets = Vec::new();
    let mut hashtags: Vec<String> = Vec::new();
    let mut tag_seen = Vec::new();
    let mut has_error = false;
    for target in parse_list(raw_targets) {
        if let Some(user) = is_user(&target) {
            targets.push(format!("@{user}"));
            continue;
        }
        match normalize_ping_token(&target) {
            Some(n) if n.starts_with('#') => {
                let k = casefold(&n);
                if !tag_seen.contains(&k) {
                    tag_seen.push(k);
                    hashtags.push(n);
                }
            }
            _ => has_error = true,
        }
    }
    if has_error && targets.is_empty() && hashtags.is_empty() {
        return Err(SERVICE.err("no Mastodon targets to notify"));
    }

    let mut ping = Vec::new();
    let mut ping_seen = Vec::new();
    if let Some(p) = SERVICE.raw(u, "ping") {
        for t in parse_list([unquote(p)]) {
            if let Some(n) = normalize_ping_token(&t) {
                let k = casefold(&n);
                if !ping_seen.contains(&k) {
                    ping_seen.push(k);
                    ping.push(n);
                }
            }
        }
    }

    Ok(Box::new(Mastodon(Arc::new(Config {
        api_url,
        token: Secret::new(token),
        visibility,
        batch: SERVICE.flag(u, "batch"),
        sensitive: SERVICE.flag(u, "sensitive"),
        spoiler: SERVICE.text(u, "spoiler"),
        key: SERVICE.text(u, "key"),
        language: SERVICE.text(u, "language"),
        targets,
        hashtags,
        ping,
        rate: RateLimit::new(Reset::Rfc3339, std::time::Duration::from_millis(500)),
        whoami: std::sync::Mutex::new(None),
    }))))
}

impl Config {
    fn configured_tokens(&self) -> String {
        let mut all = self.targets.clone();
        all.extend(self.hashtags.iter().cloned());
        all.extend(self.ping.iter().cloned());
        all.join(" ")
    }

    fn request(&self, method: Method, path: &str, ctx_ua: &str) -> Request {
        Request::new(method, format!("{}{}", self.api_url, path))
            .header("User-Agent", ctx_ua)
            .header("Authorization", format!("Bearer {}", self.token.expose()))
    }
}

/// The statuses Mastodon succeeds with.
const OK: &[u16] = &[200, 201, 202];

/// Success: 200, 201 or 202; body parsed as JSON (or `{}`).
fn outcome(res: Result<Response>) -> std::result::Result<Value, (Error, Value)> {
    match res {
        Err(e) => Err((e, json!({}))),
        Ok(r) => {
            let content = r.json().unwrap_or_else(|| json!({}));
            if matches!(r.status, 200..=202) { Ok(content) } else { Err((r.http_error(), content)) }
        }
    }
}

/// Markdown as plain text: markup dropped, links as `text (url)`.
fn dialect_convert(body: &str) -> String {
    crate::convert::markup::render(body, &crate::convert::markup::Markup::PLAIN)
}

struct Upload {
    name: String,
    mime: String,
    data: Vec<u8>,
}

struct Job {
    cfg: Arc<Config>,
    ua: String,
    env: Arc<dyn Env>,
    body: String,
    format: NotifyFormat,
    uploads: Vec<Upload>,
}

impl Notify for Mastodon {
    fn convert(&self, body: &str, format: NotifyFormat) -> Option<String> {
        (format == NotifyFormat::Markdown).then(|| dialect_convert(body))
    }

    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let body = msg.body.to_string();
        let uploads = msg
            .attachments
            .iter()
            .filter(|a| {
                let m = a.mime.to_ascii_lowercase();
                m.starts_with("image/") || m.starts_with("video/") || m.starts_with("audio/")
            })
            .map(|a| Upload { name: a.name.clone(), mime: a.mime.clone(), data: a.data.to_vec() })
            .collect();
        let job = Job { cfg: self.0.clone(), ua: ctx.app_id().to_string(), env: ctx.env().clone(), body, format: msg.format, uploads };

        if self.0.visibility == "direct" && self.0.targets.is_empty() {
            if let Some(me) = self.0.whoami.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone() {
                return job.start(Some(me));
            }
            let req = self
                .0
                .request(Method::Get, "/api/v1/accounts/verify_credentials", &job.ua)
                .header("Content-Type", "application/json")
                .body(b"null".to_vec(), None);
            let env = job.env.clone();
            return self.0.rate.send(req, OK, &env, move |res| match outcome(res) {
                Err((e, _)) => Plan::Fail(e),
                Ok(v) => match v.get("username").zip(v.get("id")) {
                    Some((Value::String(user), _)) => {
                        let me = format!("@{user}");
                        *job.cfg.whoami.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(me.clone());
                        job.start(Some(me))
                    }
                    _ => Plan::Fail(Error::service("could not look up the Mastodon account")),
                },
            })
            .context("account lookup");
        }
        job.start(None)
    }

    fn limits(&self, _title: &str, _body: &str, _format: NotifyFormat, _ctx: &Context<'_>) -> Option<Limits> {
        let mut seen = Vec::new();
        let tokens = ping_tokens_normalized(&self.0.configured_tokens(), &mut seen);
        let used = ping_payload(&tokens).chars().count();
        Some(Limits { title_maxlen: 0, body_maxlen: BODY_MAXLEN.saturating_sub(used), body_max_line_count: 0 })
    }

}

impl Job {
    /// `myself`: the authenticated account when direct mode looked it up.
    fn start(mut self, myself: Option<String>) -> Plan {
        let mut prefix: Vec<String> = Vec::new();
        if self.cfg.visibility == "direct" {
            let users: Vec<String> = find_mentions(&self.body);
            prefix = self.cfg.targets.iter().filter(|t| !users.contains(t)).cloned().collect();
            prefix.dedup();
            if let Some(me) = myself
                && !users.contains(&me)
                && !prefix.contains(&me)
            {
                prefix.push(me);
            }
        }
        let uploads = std::mem::take(&mut self.uploads);
        self.upload(prefix, uploads.into_iter(), Vec::new())
    }

    fn upload(self, prefix: Vec<String>, mut rest: std::vec::IntoIter<Upload>, mut done: Vec<(Value, String)>) -> Plan {
        let Some(att) = rest.next() else {
            return self.statuses(prefix, done);
        };
        let form = Multipart::with_env(self.env.as_ref()).text("description", att.name.clone()).file(
            "file",
            att.name.clone(),
            "application/octet-stream",
            att.data,
        );
        let req = self.cfg.request(Method::Post, "/api/v1/media", &self.ua).multipart(form);
        let rate = self.cfg.rate.clone();
        let env = self.env.clone();
        rate.send(req, OK, &env, move |res| match outcome(res) {
            Err((e, _)) => Plan::Fail(e),
            Ok(v) => {
                if let Some(id) = v.as_object().and_then(|o| o.get("id")).filter(|id| json_has_value(id)) {
                    done.push((id.clone(), att.mime));
                }
                self.upload(prefix, rest, done)
            }
        })
        .context("upload")
    }

    fn statuses(self, prefix: Vec<String>, attachments: Vec<(Value, String)>) -> Plan {
        let cfg = &self.cfg;
        let mut seen: Vec<String> = prefix.iter().map(|t| casefold(t)).collect();
        let mut tokens = Vec::new();
        if self.format == NotifyFormat::Text {
            let _ = ping_tokens_scan(&self.body, &mut seen);
        }
        let has_config = !(cfg.targets.is_empty() && cfg.hashtags.is_empty() && cfg.ping.is_empty());
        if self.format == NotifyFormat::Markdown {
            tokens.extend(ping_tokens_scan(&self.body, &mut seen));
        }
        if has_config {
            tokens.extend(ping_tokens_normalized(&cfg.configured_tokens(), &mut seen));
        }
        let mut status =
            if prefix.is_empty() { self.body.clone() } else { format!("{} {}", prefix.join(" "), self.body) };
        status.push_str(&ping_payload(&tokens));

        let mut payload = Map::new();
        payload.insert("status".into(), json!(status));
        payload.insert("sensitive".into(), json!(cfg.sensitive));
        if cfg.visibility != "default" {
            payload.insert("visibility".into(), json!(cfg.visibility));
        }
        if let Some(s) = &cfg.spoiler {
            payload.insert("spoiler_text".into(), json!(s));
        }
        if let Some(k) = &cfg.key {
            payload.insert("Idempotency-Key".into(), json!(k));
        }
        if let Some(l) = &cfg.language {
            payload.insert("language".into(), json!(l));
        }

        let mut payloads = Vec::new();
        let uploaded = !attachments.is_empty();
        if attachments.is_empty() {
            payloads.push(payload);
        } else {
            let batch_size = if cfg.batch { BATCH_SIZE } else { 1 };
            let jpg_png = crate::regex!(r"(?i)^image/(png|jpe?g)");
            let mut batches: Vec<Vec<Value>> = Vec::new();
            let mut batch = Vec::new();
            for (id, mime) in attachments {
                batch.push(id);
                if !jpg_png.is_match(&mime) || batch.len() >= batch_size {
                    batches.push(std::mem::take(&mut batch));
                }
            }
            if !batch.is_empty() {
                batches.push(batch);
            }
            let total = batches.len();
            for (no, ids) in batches.into_iter().enumerate() {
                let mut p = payload.clone();
                p.insert("media_ids".into(), Value::Array(ids));
                if no > 0 || self.body.is_empty() {
                    p.insert("status".into(), json!(format!("{:02}/{:02}", no + 1, total)));
                    p.insert("sensitive".into(), json!(false));
                    if let Some(k) = &cfg.key {
                        p.insert("Idempotency-Key".into(), json!(format!("{k}-part{no:02}")));
                    }
                }
                payloads.push(p);
            }
        }

        Plan::all(payloads.into_iter().map(|p| {
            let req = cfg
                .request(Method::Post, "/api/v1/statuses", &self.ua)
                .header("Content-Type", "application/json")
                .body(serde_json::to_vec(&Value::Object(p)).unwrap_or_default(), None);
            let post = cfg.rate.send(req, OK, &self.env, |res| match outcome(res) {
                Ok(_) => Plan::Done,
                Err((e, _)) => Plan::Fail(e),
            });
            if uploaded { post.context("post") } else { post }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mentions() {
        assert_eq!(find_mentions("hi @abc, and @x@host.com. email@miss"), vec!["@abc", "@x@host.com."]);
        assert_eq!(find_mentions("@a@b.c!"), vec!["@a@b"]);
        assert_eq!(find_hashtags("#déjà_vu ##bad #bad% #123 #ok."), vec!["#déjà_vu", "#123", "#ok"]);
        assert!(!valid_hashtag("#123"));
        assert_eq!(dialect_convert("## Title ##\r\nbody"), "Title\n\nbody");
        assert_eq!(dialect_convert("**b** [l](https://x)"), "b l (https://x)");
        assert_eq!(dialect_convert("a\\_b"), "a_b");
    }

    #[test]
    fn rate_limit_is_kept_between_sends() {
        let reset = crate::time::iso8601_utc(super::super::_ratelimit::NOW + 60);
        let spent = Response::new(200, b"{}".to_vec())
            .with_header("X-RateLimit-Remaining", "0")
            .with_header("X-RateLimit-Reset", reset);
        let wait = super::super::_ratelimit::second_send_waits("mastodon://token@hostname", vec![spent], Response::new(200, b"{}".to_vec()));
        assert!(wait > std::time::Duration::from_secs(55) && wait <= std::time::Duration::from_secs(61), "{wait:?}");
    }


    #[test]
    fn direct_mode_looks_the_account_up_once() {
        let t = crate::parse("mastodon://token@hostname?visibility=direct").unwrap();
        let fake = crate::testing::FakeTransport::new();
        fake.on_url("verify_credentials", Response::new(200, br#"{"username": "me", "id": "1"}"#.to_vec()));
        fake.default_response(Response::new(200, b"{}".to_vec()));
        let asset = crate::Asset::default();
        for text in ["one", "two"] {
            assert!(t.send(&crate::Message::new(text), &fake, &asset).is_success());
        }
        let lookups = fake.requests().iter().filter(|r| r.url.contains("verify_credentials")).count();
        assert_eq!(lookups, 1);
        let posts: Vec<_> = fake.requests().into_iter().filter(|r| r.url.ends_with("/statuses")).collect();
        assert_eq!(posts.len(), 2);
        assert!(String::from_utf8_lossy(&posts[1].body).contains("@me"), "the cached account is still mentioned");
    }

}
