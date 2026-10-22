//! `/notify`: stateless and stored sends, plain or as a live stream.

use std::time::Duration;

use mercurio::redact_url;
use mercurio::{AsyncMercurio, Message, NotifyFormat, NotifyType, TagFilter};
use serde_json::Value;

use super::super::auth::Role;
use super::super::http::{Reply, Req, parse_bool};
use super::super::payload::{self, Content};
use super::super::{DENIED, INVALID_KEY_HEADER, Server, filters, notify, store, valid_key};

/// Lowest level of the lines sent to `APPRISE_WEBHOOK_URL`: INFO, so the library's DEBUG lines stay out.
const WEBHOOK_LEVEL: u8 = 20;

impl Server {
    pub(crate) async fn notify_route(&self, req: &Req, key: &str) -> Reply {
        if let Some(r) = self.stateful_disabled(req) {
            return r;
        }
        let key = match req.x_header("Config-ID") {
            Some(h) if valid_key(h) => h.to_string(),
            Some(_) => return Reply::error(req, 400, INVALID_KEY_HEADER),
            None => key.to_string(),
        };
        let content = match payload::load_notify(req, false, Some(&key), self.s.mapping_depth) {
            Ok(c) => c,
            Err(r) => return r,
        };
        self.notify_stored(req, &key, content).await
    }

    async fn notify_stored(&self, req: &Req, key: &str, mut content: Content) -> Reply {
        req.note(|ev| ev.key = Some(key.to_string()));
        if !self.key_ok(req, key, true).await {
            return self.key_denied(req, key);
        }
        // Public and locked callers may only send to a tag they know.
        let tag_only = req.role.get() != Role::Admin && self.configuration_is_locked(Some(key)).await;
        let tag = payload::notify_tag(req, &content);
        if tag_only && !tag.as_ref().is_ok_and(|t| payload::tag_is_specific(t.as_ref())) {
            return Reply::error(req, 400, "A specific tag other than 'all' is required for this configuration");
        }
        let Ok(tag) = tag else {
            return Reply::error(req, 400, "Unsupported characters found in tag definition");
        };
        let attachments = match self.attachments(req, &mut content).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        query_overrides(req, &mut content);
        let message = match self.message(req, &mut content, attachments) {
            Ok(m) => m,
            Err(r) => return r,
        };
        let (config, format) = match self.store.get(key).await {
            Ok(Some(c)) => c,
            Ok(None) => return Reply::error(req, 404, "There was no configuration found"),
            Err(()) => return Reply::error(req, 500, "An error occurred accessing configuration"),
        };
        let recursion = match self.recursion(req) {
            Ok(n) => n,
            Err(r) => return r,
        };
        let asset = self.request_asset(req, true, recursion);
        let mut m = AsyncMercurio::with_transport(self.transport.clone())
            .config_options(self.config_options())
            .asset(asset.clone());
        match self.load(&config, Some(format)).await {
            Ok(cfg) => {
                m.add_loaded(cfg);
            }
            Err(e) => req.note(|ev| ev.detail.push(format!("the configuration could not be loaded: {e}"))),
        }
        // Without a tag only untagged entries are notified.
        let filter = tag.as_ref().map(payload::tag_filter).unwrap_or_else(TagFilter::untagged);
        let vars = content.template.take().unwrap_or_default();
        let job = notify::Job { notifier: m, message, filter, vars, key: Some(key.to_string()) };
        self.deliver(req, job).await
    }

    pub(crate) async fn notify_stateless(&self, req: &Req) -> Reply {
        let key = match req.x_header("Config-ID") {
            Some(h) if valid_key(h) => Some(h.to_string()),
            Some(_) => return Reply::error(req, 400, INVALID_KEY_HEADER),
            None => None,
        };
        let mut content = match payload::load_notify(req, true, None, self.s.mapping_depth) {
            Ok(c) => c,
            Err(r) => return r,
        };
        let has_urls = content.fields.get("urls").is_some_and(|v| match v {
            Value::String(s) => !s.is_empty(),
            Value::Array(a) => !a.is_empty(),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_) => false,
        });
        if let Some(key) = key.as_deref().filter(|_| !has_urls) {
            if let Some(r) = self.stateful_disabled(req) {
                return r;
            }
            return self.notify_stored(req, key, content).await;
        }
        if !self.s.stateless_enabled {
            return Reply::error(req, 403, DENIED);
        }
        if self.s.auth.required && req.role.get() != Role::Admin {
            let scope = key.as_deref().unwrap_or("stateless");
            if key.is_none() || !self.key_ok(req, scope, false).await {
                return self.key_denied(req, scope);
            }
            if self.key_state(scope).await.access != store::ACCESS_USER {
                return Reply::error(req, 403, "This configuration does not permit stateless notifications");
            }
        }
        let urls: Vec<String> = match content.fields.get("urls") {
            Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
            Some(Value::Array(a)) if !a.is_empty() => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
            _ => self.s.stateless_urls.iter().cloned().collect(),
        };
        let Ok(tag) = payload::notify_tag(req, &content) else {
            return Reply::error(req, 400, "Unsupported characters found in tag definition");
        };
        query_overrides(req, &mut content);
        let attachments = match self.attachments(req, &mut content).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        let message = match self.message(req, &mut content, attachments) {
            Ok(m) => m,
            Err(r) => return r,
        };
        let recursion = match self.recursion(req) {
            Ok(n) => n,
            Err(r) => return r,
        };
        let asset = self.request_asset(req, self.s.stateless_storage, recursion);
        let mut m = AsyncMercurio::with_transport(self.transport.clone()).asset(asset.clone());
        for u in mercurio::__private::parse_urls(urls.iter().map(String::as_str), true) {
            match mercurio::parse(&u) {
                Ok(t) if self.s.services.enabled(t.service().id) => {
                    m.push(t);
                }
                Ok(t) => req.note(|ev| {
                    ev.detail.push(format!("skipped {}: the {} service is disabled", redact_url(&u), t.service().name));
                }),
                Err(e) => req.note(|ev| ev.detail.push(format!("skipped {}: {e}", redact_url(&u)))),
            }
        }
        if m.is_empty() {
            return Reply::error(req, 400, "There was no valid URLs provided to notify");
        }
        let filter = tag.as_ref().map(payload::tag_filter).unwrap_or_else(TagFilter::all);
        let vars = content.template.take().unwrap_or_default();
        let job = notify::Job { notifier: m, message, filter, vars, key: None };
        self.deliver(req, job).await
    }

    /// The asset for a send, carrying the caller's `X-Apprise-ID` and recursion count.
    fn request_asset(&self, req: &Req, persistent: bool, recursion: u32) -> mercurio::Asset {
        let uid = req.x_header("ID").map(str::trim).filter(|u| !u.is_empty()).map(str::to_string);
        mercurio::Asset { uid, recursion, ..self.asset(persistent) }
    }

    /// The requested log detail; stored configurations limit it to `INFO` unless the caller is the administrator or has `user` access.
    async fn log_level(&self, req: &Req, key: Option<&str>) -> u8 {
        let level = req.x_header("Log-Level").and_then(notify::level_value).unwrap_or(self.s.log_level);
        let Some(key) = key else { return level };
        if level >= 20 || !self.s.auth.required {
            return level;
        }
        match req.role.get() {
            Role::Admin | Role::Open => level,
            Role::User if self.key_state(key).await.access == store::ACCESS_USER => level,
            Role::User | Role::Anonymous => 20,
        }
    }

    async fn deliver(&self, req: &Req, job: notify::Job) -> Reply {
        let level = self.log_level(req, job.key.as_deref()).await;
        let wants_stream = req.header("accept").is_some_and(|a| {
            a.split(',').any(|m| m.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("text/event-stream"))
        }) || parse_bool(req.query("stream"), false);
        if wants_stream {
            let Some(slot) = self.streams.try_admit() else {
                let msg = "The server is temporarily unable to start a new live notification stream";
                return Reply::error(req, 503, msg).header("Retry-After", "15");
            };
            let (metrics, webhook, transport, remote) =
                (self.metrics.clone(), self.s.webhook.clone(), self.transport.clone(), req.remote.clone());
            let done: notify::OnDone = Box::new(move |report, logs| {
                Box::pin(async move {
                    metrics.notified(report.status().as_str());
                    if let Some(url) = webhook {
                        let logs = notify::filter_level(logs, WEBHOOK_LEVEL);
                        filters::send_webhook(transport.as_ref(), &url, &remote, report.is_success(), &logs).await;
                    }
                })
            });
            req.note(|ev| ev.stream = true);
            return notify::stream(job, level, slot, Duration::from_secs(15), done);
        }
        let (reply, report, logs) = notify::deliver(req, &job, level).await;
        self.metrics.notified(report.status().as_str());
        if let Some(url) = &self.s.webhook {
            let logs = notify::filter_level(logs, WEBHOOK_LEVEL);
            filters::send_webhook(self.transport.as_ref(), url, &req.remote, report.is_success(), &logs).await;
        }
        reply
    }

    async fn attachments(&self, req: &Req, content: &mut Content) -> Result<Vec<mercurio::Attachment>, Reply> {
        let allowed = |u: &str| self.s.attach_urls.allowed(u);
        let rules = payload::AttachRules { size: self.s.attach_size, max: self.s.max_attachments, allowed: &allowed };
        payload::attachments(content, &rules, self.transport.as_ref()).await.map_err(|e| {
            req.note(|ev| ev.detail.push(format!("bad attachment: {e}")));
            Reply::error(req, 400, "Bad Attachment")
        })
    }

    /// Body, title, type and format checks; the message to send.
    fn message(&self, req: &Req, c: &mut Content, attachments: Vec<mercurio::Attachment>) -> Result<Message, Reply> {
        // Moved out, not copied: the body can be megabytes.
        let body = match c.fields.remove("body") {
            Some(Value::String(s)) => s,
            _ => String::new(),
        };
        let kind = c.str("type").unwrap_or("info");
        if (body.is_empty() && attachments.is_empty()) || !["info", "success", "warning", "failure"].contains(&kind) {
            return Err(Reply::error(req, 400, "Payload lacks minimum requirements"));
        }
        let format = if c.fields.contains_key("format") {
            match c.fields.get("format").and_then(Value::as_str).map(str::trim).filter(|f| !f.is_empty()) {
                None => None,
                Some(f) => match ["text", "markdown", "html"].contains(&f).then(|| NotifyFormat::parse(f)).flatten() {
                    Some(f) => Some(f),
                    None => return Err(Reply::error(req, 400, "An invalid body input format was specified")),
                },
            }
        } else {
            self.s.default_format
        };
        let mut msg = Message::new(body).title(c.str("title").unwrap_or_default());
        msg.kind = NotifyType::parse(kind).unwrap_or_default();
        msg.format = format;
        msg.attachments = attachments;
        Ok(msg)
    }

    /// The `Recursion-Count` header against `APPRISE_RECURSION_MAX`.
    fn recursion(&self, req: &Req) -> Result<u32, Reply> {
        let Some(raw) = req.x_header("Recursion-Count") else { return Ok(0) };
        match raw.parse::<i64>() {
            Ok(n) if n >= 0 && n <= i64::from(self.s.recursion_max) => Ok(n as u32),
            Ok(n) if n >= 0 => Err(Reply::error(req, 406, "The recursion limit has been reached")),
            _ => Err(Reply::error(req, 400, "An invalid recursion value was specified")),
        }
    }
}

/// `?format=`, `?type=` and `?title=` fill fields the payload left empty.
fn query_overrides(req: &Req, c: &mut Content) {
    for name in ["format", "type", "title"] {
        if c.str(name).is_none()
            && let Some(v) = req.query(name)
        {
            c.fields.insert(name.into(), Value::String(v.to_string()));
        }
    }
}
