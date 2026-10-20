//! Stored configurations: `/add`, `/get` (`/cfg/{key}`), `/del`, `/move`, `/json/urls` and the `/cfg` key list.

use std::time::SystemTime;

use mercurio::TagFilter;
use mercurio::config::{Config, ConfigFormat, ConfigService};
use mercurio::plan::redact_url;
use serde_json::{Map, Value, json};

use super::super::auth::Role;
use super::super::http::{self, Reply, Req, parse_bool};
use super::super::store::{Cleared, Mode, Moved};
use super::super::{DENIED, Server, payload, resolve_key, valid_key};

impl Server {
    pub(crate) async fn list(&self, req: &Req) -> Reply {
        let allowed = if self.s.auth.required { req.role.get() == Role::Admin } else { !self.s.config_lock };
        if !self.s.admin_list || self.store.mode != Mode::Simple || !allowed {
            return Reply::error(req, 403, DENIED);
        }
        let keys = self.store.keys().await;
        if !req.wants_json() {
            return Reply::text(200, &keys.join("\n"));
        }
        if !self.s.auth.required {
            return Reply::json(200, &json!(keys));
        }
        let mut entries = Vec::new();
        for k in &keys {
            let st = self.key_state(k).await;
            entries.push(json!({"key": k, "user": st.username, "access": st.access}));
        }
        Reply::json(200, &Value::Array(entries))
    }

    pub(crate) async fn get_config(&self, req: &Req, key: Option<&str>) -> Reply {
        if let Some(r) = self.stateful_disabled(req) {
            return r;
        }
        let key = match resolve_key(req, key) {
            Ok(k) => k,
            Err(r) => return r,
        };
        if !self.key_ok(req, &key, false).await {
            return self.key_denied(req, &key);
        }
        if !self.config_lock_allows(req, Some(&key)).await {
            return Reply::error(req, 403, DENIED);
        }
        match self.store.get(&key).await {
            Err(()) => Reply::error(req, 500, "An error occurred accessing configuration"),
            Ok(None) => Reply::empty(204),
            Ok(Some((config, format))) if req.wants_json() => {
                Reply::json(200, &json!({"format": format.as_str(), "config": config}))
            }
            Ok(Some((config, ConfigFormat::Yaml))) => Reply::new(200, "text/yaml; charset=utf-8", config.into_bytes()),
            Ok(Some((config, _))) => Reply::new(200, "text/plain; charset=utf-8", config.into_bytes()),
        }
    }

    pub(crate) async fn add(&self, req: &Req, key: Option<&str>) -> Reply {
        if let Some(r) = self.stateful_disabled(req) {
            return r;
        }
        let key = match resolve_key(req, key) {
            Ok(k) => k,
            Err(r) => return r,
        };
        if !self.key_ok(req, &key, false).await {
            return self.key_denied(req, &key);
        }
        if !self.config_lock_allows(req, Some(&key)).await {
            return Reply::error(req, 403, DENIED);
        }
        let fields: Map<String, Value> = if req.json_payload() {
            let m = match payload::json_object(req) {
                Ok(m) => m,
                Err(r) => return r,
            };
            let str_list = |v: &Value| v.is_string() || v.as_array().is_some_and(|a| a.iter().all(Value::is_string));
            if m.get("urls").is_some_and(|v| !str_list(v)) {
                return Reply::field_error(req, 400, "The urls field must be a string or list of strings", "urls");
            }
            for f in ["config", "format"] {
                if m.get(f).is_some_and(|v| !v.is_string()) {
                    return Reply::field_error(req, 400, &format!("The {f} field must be a string"), f);
                }
            }
            m
        } else {
            let (mut m, _, _) = payload::form_fields(req);
            if m.get("urls").and_then(Value::as_str).is_some_and(str::is_empty) {
                m.remove("urls");
            }
            m
        };
        if fields.contains_key("urls") {
            let raw: Vec<String> = match fields.get("urls") {
                Some(Value::String(s)) => vec![s.clone()],
                Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
                _ => Vec::new(),
            };
            let urls: Vec<String> = mercurio::parse::parse_urls(raw.iter().map(String::as_str), true)
                .into_iter()
                .filter(|u| mercurio::parse(u).is_ok_and(|t| self.s.services.enabled(t.service().id)))
                .collect();
            if urls.is_empty() {
                return Reply::error(req, 400, "No valid URLs defined");
            }
            if !self.store.put(&key, &urls.join("\r\n"), ConfigFormat::Text).await {
                return Reply::error(req, 500, "The configuration could not be saved");
            }
        } else if let Some(config) = fields.get("config").and_then(Value::as_str) {
            if config.len() > self.s.config_max_len {
                return Reply::error(req, 400, "The configuration payload is too large");
            }
            let fmt = fields.get("format").and_then(Value::as_str).unwrap_or("").trim().to_lowercase();
            let format = match fmt.as_str() {
                "" | "auto" => None,
                f => match ConfigFormat::parse(f) {
                    Some(f) => Some(f),
                    None => return Reply::error(req, 400, "Invalid configuration format specified"),
                },
            };
            let mut stored = format.unwrap_or(ConfigFormat::Text);
            if !config.trim().is_empty() {
                let Some(detected) = format.or_else(|| mercurio::config::detect_format(config)) else {
                    return Reply::error(req, 400, "The configuration format could not be auto-detected");
                };
                stored = detected;
                let Ok(cfg) = self.load(config, Some(detected)).await else {
                    return Reply::error(req, 400, "The configuration could not be parsed");
                };
                if cfg.services.is_empty() && detected == ConfigFormat::Yaml && yaml_refused(config) {
                    return Reply::error(req, 400, "The configuration could not be parsed");
                }
            }
            if !self.store.put(&key, config, stored).await {
                return Reply::error(req, 500, "An error occurred saving configuration");
            }
        } else if fields.is_empty() {
            return Reply::error(req, 400, "Invalid payload structure provided");
        } else {
            return Reply::error(req, 400, "No configuration provided");
        }
        let mut reply = Reply::ok(req, "Successfully saved configuration");
        if let Some((created, modified)) = self.store.file_times(&key).await {
            reply = reply
                .header("X-Apprise-Config-Created", &iso_seconds(created))
                .header("X-Apprise-Config-MTime", &iso_seconds(modified));
        }
        reply.header("X-Apprise-Timezone", "Etc/UTC")
    }

    pub(crate) async fn del(&self, req: &Req, key: Option<&str>) -> Reply {
        if let Some(r) = self.stateful_disabled(req) {
            return r;
        }
        let key = match resolve_key(req, key) {
            Ok(k) => k,
            Err(r) => return r,
        };
        if !self.key_ok(req, &key, false).await {
            return self.key_denied(req, &key);
        }
        if !self.config_lock_allows(req, Some(&key)).await {
            return Reply::error(req, 403, DENIED);
        }
        let shared = req.role.get() == Role::User;
        let result = self.store.clear(&key).await;
        if result == Cleared::Failed {
            return Reply::error(req, 500, "The configuration could not be removed");
        }
        if shared {
            // A configuration user keeps their login to save a replacement.
            self.store.touch_auth(&key).await;
        } else if self.store.clear_auth(&key).await == Cleared::Failed {
            let msg = "The configuration was removed, but its authentication could not be removed";
            return Reply::error(req, 500, msg);
        }
        match result {
            Cleared::Nothing | Cleared::Failed => Reply::empty(204),
            Cleared::Removed => Reply::ok(req, "Successfully removed configuration"),
        }
    }

    pub(crate) async fn move_config(&self, req: &Req, key: Option<&str>) -> Reply {
        if let Some(r) = self.stateful_disabled(req) {
            return r;
        }
        let key = match resolve_key(req, key) {
            Ok(k) => k,
            Err(r) => return r,
        };
        if !self.key_ok(req, &key, false).await {
            return self.key_denied(req, &key);
        }
        if !self.config_lock_allows(req, None).await {
            return Reply::error(req, 403, DENIED);
        }
        let (from, to) = if req.json_payload() {
            let m = match payload::json_object(req) {
                Ok(m) => m,
                Err(r) => return r,
            };
            match m.get("to").and_then(Value::as_str) {
                Some(to) if valid_key(to) && to != key => (key.clone(), to.to_string()),
                _ => {
                    let msg = "A valid destination (to), different from the source, is required";
                    return Reply::field_error(req, 400, msg, "to");
                }
            }
        } else {
            let (m, _, _) = payload::form_fields(req);
            let field = |f: &str| m.get(f).and_then(Value::as_str).map(str::trim).unwrap_or("").to_string();
            let (from, to) = (field("from"), field("to"));
            for (name, v) in [("from", &from), ("to", &to)] {
                if v.is_empty() {
                    return Reply::field_error(req, 400, "This field is required.", name);
                }
                if !valid_key(v) {
                    return Reply::field_error(req, 400, "Enter a valid value.", name);
                }
            }
            if from == to {
                return Reply::error(req, 400, "The destination configuration ID must differ from the source");
            }
            (from, to)
        };
        if from != key && !self.key_ok(req, &from, false).await {
            return self.key_denied(req, &from);
        }
        if !self.s.config_lock && !self.store.writable().await {
            return Reply::error(req, 424, "The configuration store is not currently writable");
        }
        match self.store.move_key(&from, &to).await {
            Moved::NotFound => Reply::error(req, 404, "There was no configuration to move"),
            Moved::Conflict => Reply::field_error(req, 409, "A configuration already exists at the destination", "to"),
            Moved::Failed => Reply::error(req, 500, "The configuration could not be moved"),
            Moved::Done => Reply::ok(req, "Successfully moved configuration"),
        }
    }

    pub(crate) async fn json_urls(&self, req: &Req, key: Option<&str>) -> Reply {
        if let Some(r) = self.stateful_disabled(req) {
            return r;
        }
        let key = match resolve_key(req, key) {
            Ok(k) => k,
            Err(r) => return r,
        };
        if !self.key_ok(req, &key, false).await {
            return self.key_denied(req, &key);
        }
        if !self.config_lock_allows(req, Some(&key)).await {
            return Reply::error(req, 403, DENIED);
        }
        let privacy = parse_bool(req.query("privacy"), false);
        let show_defaults = self.s.allow_templates && !privacy && !self.s.config_lock;
        let (content, format) = match self.store.get(&key).await {
            Err(()) => {
                return Reply::json(500, &json!({"tags": [], "urls": [], "error": "There was no configuration found"}));
            }
            Ok(None) => return Reply::empty(204),
            Ok(Some(c)) => c,
        };
        let cfg = Config::from_text_async(&content, Some(format), self.transport.as_ref(), &self.config_options())
            .await
            .unwrap_or_default();
        let defaults = if show_defaults { template_defaults(&content, format) } else { Default::default() };
        let filter = TagFilter::parse(req.query("tag").filter(|t| !t.trim().is_empty()).unwrap_or("all"));
        let mut all_tags = std::collections::BTreeSet::new();
        let mut urls = Vec::new();
        for s in cfg.services.iter().filter(|s| filter.matches(s.tags())) {
            let (url, def, id, template_names) = match s {
                ConfigService::Ready(t) => {
                    (t.url().to_string(), t.service(), t.url_id(&mercurio::Asset::default()), Vec::new())
                }
                ConfigService::Pending(p) => (p.url(), p.service(), None, p.template_names().to_vec()),
            };
            let (name, service_id) = (def.name, def.id);
            let mut names: Vec<String> = s.tags().iter().map(|t| t.name.clone()).collect();
            names.sort();
            names.dedup();
            all_tags.extend(names.iter().cloned());
            let mut tags: Vec<&mercurio::Tag> = s.tags().iter().collect();
            tags.sort_by(|a, b| (&a.name, a.priority).cmp(&(&b.name, b.priority)));
            let details: Vec<Value> = tags
                .iter()
                .map(|t| {
                    let token =
                        if t.has_priority || t.priority > 0 { format!("{}:{}", t.priority, t.name) } else { t.name.clone() };
                    json!({"name": t.name, "priority": t.priority, "token": token, "exact": format!("{}:{}", t.priority, t.name)})
                })
                .collect();
            let query = url_query(&url);
            let retry: u64 = query.iter().find(|(k, _)| k == "retry").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
            let optional = query.iter().any(|(k, v)| k == "optional" && parse_bool(Some(v), false));
            let template: Map<String, Value> = if self.s.allow_templates {
                template_names
                    .iter()
                    .map(|n| (n.clone(), defaults.get(n).map(|d| Value::String(d.clone())).unwrap_or(Value::Null)))
                    .collect()
            } else {
                Map::new()
            };
            urls.push(json!({
                "id": id,
                "service_name": name,
                "enabled": self.s.services.enabled(service_id),
                "url": if privacy { redact_url(&url) } else { url.clone() },
                "retry": retry,
                "optional": optional,
                "tags": names,
                "tag_details": details,
                "template": template,
            }));
        }
        Reply::json(200, &json!({"tags": all_tags, "urls": urls}))
    }
}

/// A YAML document that would be discarded as a whole (syntax error, not a mapping or a broken `template:` section).
fn yaml_refused(content: &str) -> bool {
    use mercurio::config::yaml::{Yaml, parse};
    match parse(content) {
        Err(_) => true,
        Ok(Yaml::Null) => false,
        Ok(doc) => {
            doc.as_map().is_none()
                || doc.get("template").is_some_and(|t| mercurio::config::template::TemplateSchema::parse(t).is_err())
        }
    }
}
/// Template defaults declared in a YAML configuration.
fn template_defaults(content: &str, format: ConfigFormat) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    if format != ConfigFormat::Yaml {
        return out;
    }
    let Ok(doc) = mercurio::config::yaml::parse(content) else { return out };
    if let Some(Ok(schema)) = doc.get("template").map(mercurio::config::template::TemplateSchema::parse) {
        for (name, default) in schema.variables {
            if let Some(d) = default {
                out.insert(name, d);
            }
        }
    }
    out
}
fn url_query(url: &str) -> Vec<(String, String)> {
    url.split_once('?').map(|(_, q)| http::form_pairs(q)).unwrap_or_default()
}
/// `YYYY-MM-DDTHH:MM:SS` (UTC).
fn iso_seconds(t: SystemTime) -> String {
    let secs = t.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (y, mo, d, h, mi, s) = mercurio::crypto::utc_parts(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}")
}
