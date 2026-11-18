//! `/notify`: stateless and stored sends, plain or as a live stream.

use std::time::Duration;

use mercurio::redact_url;
use mercurio::{AsyncMercurio, Message, NotifyFormat, NotifyType, TagFilter};
use serde_json::Value;

use super::super::api::{self, types};
use super::super::auth::Role;
use super::super::call::{Call, Fault, parse_bool};
use super::super::notify::{self, Delivered};
use super::super::payload::{self, Content, NotifyBody, NotifyInput};
use super::super::{DENIED, Server, filters, store};

/// Lowest level of the lines sent to `APPRISE_WEBHOOK_URL`: INFO, so the library's DEBUG lines stay out.
const WEBHOOK_LEVEL: u8 = 20;

/// The answer to a send: its logs once done, or a live stream of them.
pub(crate) enum Sent {
    Done(Delivered),
    Stream(api::Items<types::StreamEvent>),
}

/// The `X-Apprise-*` values of a send that are not part of its payload.
#[derive(Default)]
pub(crate) struct SendHeaders {
    pub config_id: Option<String>,
    pub log_level: Option<String>,
    /// `X-Apprise-Recursion-Count`: the spec has checked that it is a whole number from 0.
    pub recursion: Option<i64>,
    pub apprise_id: Option<String>,
}

impl Server {
    /// `POST /notify/{key}`: send through the stored configuration.
    pub(crate) async fn notify(
        &self,
        call: &Call<'_>,
        key: &str,
        h: SendHeaders,
        input: NotifyInput,
    ) -> Result<Sent, Fault> {
        self.require_stateful(call)?;
        let key = h.config_id.as_deref().unwrap_or(key).to_owned();
        self.check_size(call, &input)?;
        let (content, input) =
            payload::load_notify(input, false, Some(&key), self.s.mapping_depth).map_err(|f| call.fail(f))?;
        self.notify_stored(call, &key, &h, content, input).await
    }

    /// `POST /notify`: send to the URLs in the request, or through the stored configuration `X-Apprise-Config-ID`
    /// names when there are none.
    pub(crate) async fn notify_stateless(
        &self,
        call: &Call<'_>,
        h: SendHeaders,
        input: NotifyInput,
    ) -> Result<Sent, Fault> {
        let key = h.config_id.clone();
        self.check_size(call, &input)?;
        let (mut content, input) =
            payload::load_notify(input, true, None, self.s.mapping_depth).map_err(|f| call.fail(f))?;
        let has_urls = content.fields.get("urls").is_some_and(|v| match v {
            Value::String(s) => !s.is_empty(),
            Value::Array(a) => !a.is_empty(),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_) => false,
        });
        if let Some(key) = key.as_deref().filter(|_| !has_urls) {
            self.require_stateful(call)?;
            return self.notify_stored(call, key, &h, content, input).await;
        }
        if !self.s.stateless_enabled {
            return Err(call.fail(Fault::new(403, DENIED)));
        }
        if self.s.auth.required && call.caller.role.get() != Role::Admin {
            let scope = key.as_deref().unwrap_or("stateless");
            if key.is_none() || !self.key_ok(call, scope, false).await {
                return Err(self.key_denied(call, scope));
            }
            if self.key_state(scope).await.access != store::ACCESS_USER {
                return Err(call.fail(Fault::new(403, "This configuration does not permit stateless notifications")));
            }
        }
        let urls: Vec<String> = match content.fields.get("urls") {
            Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
            Some(Value::Array(a)) if !a.is_empty() => payload::strings(a),
            _ => self.s.stateless_urls.iter().cloned().collect(),
        };
        let Ok(tag) = payload::notify_tag(&input, &content) else {
            return Err(call.fail(Fault::new(400, "Unsupported characters found in tag definition")));
        };
        query_overrides(&input, &mut content);
        let attachments = self.attachments(call, &mut content).await?;
        let message = self.message(call, &mut content, attachments)?;
        let recursion = self.recursion(call, &h)?;
        let asset = self.request_asset(call, &h, self.s.stateless_storage, recursion);
        let mut m = AsyncMercurio::with_transport(self.transport.clone()).asset(asset);
        let mut skipped = Vec::new();
        for u in mercurio::__private::parse_urls(urls.iter().map(String::as_str), true) {
            match mercurio::parse(&u) {
                Ok(t) if self.s.services.enabled(t.service().id) => {
                    m.push(t);
                }
                Ok(t) => {
                    skipped.push(format!("skipped {}: the {} service is disabled", redact_url(&u), t.service().name))
                }
                Err(e) => skipped.push(format!("skipped {}: {e}", redact_url(&u))),
            }
        }
        if !skipped.is_empty() {
            call.note("detail", skipped.join("; "));
        }
        if m.is_empty() {
            return Err(call.fail(Fault::new(400, "There was no valid URLs provided to notify")));
        }
        let filter = tag.as_ref().map(payload::tag_filter).unwrap_or_else(TagFilter::all);
        let vars = content.template.take().unwrap_or_default();
        let job = notify::Job { notifier: m, message, filter, vars, key: None };
        self.deliver(call, &h, &input, job).await
    }

    /// apprise-api's `APPRISE_UPLOAD_MAX_MEMORY_SIZE`: a JSON, form or text body above it is `431`; files do not
    /// count.
    fn check_size(&self, call: &Call<'_>, input: &NotifyInput) -> Result<(), Fault> {
        let counted = !matches!(input.body, Some(NotifyBody::Multipart { .. }) | None);
        if counted && call.body_len > self.s.upload_max {
            return Err(call.fail(Fault::new(431, "JSON Payload provided is too large")));
        }
        Ok(())
    }

    async fn notify_stored(
        &self,
        call: &Call<'_>,
        key: &str,
        h: &SendHeaders,
        mut content: Content,
        input: NotifyInput,
    ) -> Result<Sent, Fault> {
        self.require_key(call, key, true).await?;
        // Public and locked callers may only send to a tag they know.
        let tag_only = call.caller.role.get() != Role::Admin && self.configuration_is_locked(Some(key)).await;
        let tag = payload::notify_tag(&input, &content);
        if tag_only && !tag.as_ref().is_ok_and(|t| payload::tag_is_specific(t.as_ref())) {
            let msg = "A specific tag other than 'all' is required for this configuration";
            return Err(call.fail(Fault::new(400, msg)));
        }
        let Ok(tag) = tag else {
            return Err(call.fail(Fault::new(400, "Unsupported characters found in tag definition")));
        };
        let attachments = self.attachments(call, &mut content).await?;
        query_overrides(&input, &mut content);
        let message = self.message(call, &mut content, attachments)?;
        let (config, format) = match self.store.get(key).await {
            Ok(Some(c)) => c,
            Ok(None) => return Err(call.fail(Fault::new(404, "There was no configuration found"))),
            Err(()) => return Err(call.fail(Fault::new(500, "An error occurred accessing configuration"))),
        };
        let recursion = self.recursion(call, h)?;
        let asset = self.request_asset(call, h, true, recursion);
        let mut m =
            AsyncMercurio::with_transport(self.transport.clone()).config_options(self.config_options()).asset(asset);
        match self.load(&config, Some(format)).await {
            Ok(cfg) => {
                m.add_loaded(cfg);
            }
            Err(e) => call.note("detail", format!("the configuration could not be loaded: {e}")),
        }
        // Without a tag only untagged entries are notified.
        let filter = tag.as_ref().map(payload::tag_filter).unwrap_or_else(TagFilter::untagged);
        let vars = content.template.take().unwrap_or_default();
        let job = notify::Job { notifier: m, message, filter, vars, key: Some(key.to_owned()) };
        self.deliver(call, h, &input, job).await
    }

    /// The asset for a send, carrying the caller's `X-Apprise-ID` and recursion count.
    fn request_asset(&self, call: &Call<'_>, h: &SendHeaders, persistent: bool, recursion: u32) -> mercurio::Asset {
        let uid = h.apprise_id.as_deref().map(str::trim).filter(|u| !u.is_empty()).map(str::to_owned);
        call.note("apprise_id", &uid);
        mercurio::Asset { uid, recursion, ..self.asset(persistent) }
    }

    /// The requested log detail; stored configurations limit it to `INFO` unless the caller is the administrator or
    /// has `user` access.
    async fn log_level(&self, call: &Call<'_>, h: &SendHeaders, key: Option<&str>) -> u8 {
        let level = h.log_level.as_deref().and_then(notify::level_value).unwrap_or(self.s.log_level);
        let Some(key) = key else { return level };
        if level >= 20 || !self.s.auth.required {
            return level;
        }
        match call.caller.role.get() {
            Role::Admin | Role::Open => level,
            Role::User if self.key_state(key).await.access == store::ACCESS_USER => level,
            Role::User | Role::Anonymous => 20,
        }
    }

    async fn deliver(
        &self,
        call: &Call<'_>,
        h: &SendHeaders,
        input: &NotifyInput,
        job: notify::Job,
    ) -> Result<Sent, Fault> {
        let level = self.log_level(call, h, job.key.as_deref()).await;
        if call.event_stream || parse_bool(input.query("stream"), false) {
            let Ok(slot) = self.streams.clone().try_acquire_owned() else {
                let msg = "The server is temporarily unable to start a new live notification stream";
                return Err(call.fail(Fault::new(503, msg).retry_after(15)));
            };
            let (metrics, webhook, transport, remote) =
                (self.metrics.clone(), self.s.webhook.clone(), self.transport.clone(), call.remote_ip());
            let done: notify::OnDone = Box::new(move |report, logs| {
                Box::pin(async move {
                    metrics.notified(report.status().as_str());
                    if let Some(url) = webhook {
                        let logs = notify::filter_level(logs, WEBHOOK_LEVEL);
                        filters::send_webhook(transport.as_ref(), &url, &remote, report.is_success(), &logs).await;
                    }
                })
            });
            call.note("stream", true);
            return Ok(Sent::Stream(notify::stream(job, level, slot, Duration::from_secs(15), done)));
        }
        let (delivered, report, logs) = notify::deliver(call, &job, level).await;
        self.metrics.notified(report.status().as_str());
        if let Some(url) = &self.s.webhook {
            let logs = notify::filter_level(logs, WEBHOOK_LEVEL);
            filters::send_webhook(self.transport.as_ref(), url, &call.remote_ip(), report.is_success(), &logs).await;
        }
        Ok(Sent::Done(delivered))
    }

    async fn attachments(&self, call: &Call<'_>, content: &mut Content) -> Result<Vec<mercurio::Attachment>, Fault> {
        let allowed = |u: &str| self.s.attach_urls.allowed(u);
        let rules = payload::AttachRules { size: self.s.attach_size, max: self.s.max_attachments, allowed: &allowed };
        payload::attachments(content, &rules, self.transport.as_ref()).await.map_err(|e| {
            call.note("detail", format!("bad attachment: {e}"));
            call.fail(Fault::new(400, "Bad Attachment"))
        })
    }

    /// Body, title, type and format checks; the message to send.
    fn message(
        &self,
        call: &Call<'_>,
        c: &mut Content,
        attachments: Vec<mercurio::Attachment>,
    ) -> Result<Message, Fault> {
        // Moved out, not copied: the body can be megabytes.
        let body = match c.fields.remove("body") {
            Some(Value::String(s)) => s,
            _ => String::new(),
        };
        let kind = c.str("type").unwrap_or("info");
        if (body.is_empty() && attachments.is_empty()) || !["info", "success", "warning", "failure"].contains(&kind) {
            return Err(call.fail(Fault::new(400, "Payload lacks minimum requirements")));
        }
        let format = if c.fields.contains_key("format") {
            match c.fields.get("format").and_then(Value::as_str).map(str::trim).filter(|f| !f.is_empty()) {
                None => None,
                Some(f) => match ["text", "markdown", "html"].contains(&f).then(|| NotifyFormat::parse(f)).flatten() {
                    Some(f) => Some(f),
                    None => return Err(call.fail(Fault::new(400, "An invalid body input format was specified"))),
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
    fn recursion(&self, call: &Call<'_>, h: &SendHeaders) -> Result<u32, Fault> {
        let Some(n) = h.recursion else { return Ok(0) };
        call.note("recursion", n);
        match u32::try_from(n) {
            Ok(n) if n <= self.s.recursion_max => Ok(n),
            _ => Err(call.fail(Fault::new(406, "The recursion limit has been reached"))),
        }
    }
}

/// `?format=`, `?type=` and `?title=` fill fields the payload left empty.
fn query_overrides(input: &NotifyInput, c: &mut Content) {
    for name in ["format", "type", "title"] {
        if c.str(name).is_none()
            && let Some(v) = input.query(name)
        {
            c.fields.insert(name.into(), Value::String(v.to_owned()));
        }
    }
}
