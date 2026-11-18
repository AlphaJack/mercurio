//! Stored configurations: `/add`, `/get` (`/cfg/{key}`), `/del`, `/move`, `/json/urls` and the `/cfg` key list.

use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

use mercurio::TagFilter;
use mercurio::redact_url;
use mercurio::{Config, ConfigFormat, config::ConfigService};

use super::super::api::operations::responses;
use super::super::api::types;
use super::super::auth::Role;
use super::super::call::{Call, Fault, parse_bool};
use super::super::key::valid_key;
use super::super::store::{Cleared, Mode, Moved};
use super::super::text::{form_pairs, non_blank, trimmed};
use super::super::{DENIED, Server};
use super::key::resolve_key;

/// The Config IDs, one per line, or as JSON (with their logins when authentication is on).
pub(crate) enum Listing {
    Text(String),
    Json(types::ConfigList),
}

/// A stored configuration, in the format the client reads.
pub(crate) enum Stored {
    Text(String),
    Yaml(String),
    Json(types::StoredConfig),
}

/// A saved configuration: the answer and the file's times.
pub(crate) struct Saved {
    pub body: responses::Changed,
    pub created: Option<String>,
    pub modified: Option<String>,
}

/// `/json/urls`: the URLs, nothing stored, or a configuration that could not be read.
pub(crate) enum Urls {
    Found(types::JsonUrls),
    Empty,
    Unreadable(types::JsonUrls),
}

/// The configuration a `/add` request carries, whatever its media type.
pub(crate) struct NewConfig {
    pub urls: Option<types::Strings>,
    pub config: Option<String>,
    pub format: Option<String>,
}

/// A `/move` request: the destination, and with a form the source too.
pub(crate) enum MoveTo {
    Json(Option<String>),
    Form { from: Option<String>, to: Option<String> },
}

/// A success message as text, or `{"error": null}` for JSON clients.
pub(super) fn done(call: &Call<'_>, message: &str) -> responses::Changed {
    if call.json {
        responses::Changed::Json(types::Changed { error: () })
    } else {
        responses::Changed::Plain(message.to_owned())
    }
}

impl Server {
    pub(crate) async fn list(&self, call: &Call<'_>) -> Result<Listing, Fault> {
        let allowed = if self.s.auth.required { call.caller.role.get() == Role::Admin } else { !self.s.config_lock };
        if !self.s.admin_list || self.store.mode != Mode::Simple || !allowed {
            return Err(call.fail(Fault::new(403, DENIED)));
        }
        let keys = self.store.keys().await;
        if !call.json {
            return Ok(Listing::Text(keys.join("\n")));
        }
        if !self.s.auth.required {
            return Ok(Listing::Json(types::ConfigList::StringArray(keys)));
        }
        let mut entries = Vec::new();
        for k in keys {
            let st = self.key_state(&k).await;
            entries.push(types::ConfigEntry { key: k, user: st.username, access: st.access });
        }
        Ok(Listing::Json(types::ConfigList::ConfigEntryArray(entries)))
    }

    /// The key a configuration request names, once its caller may use it and see its content.
    async fn config_key(&self, call: &Call<'_>, header: Option<&str>, path: Option<&str>) -> Result<String, Fault> {
        self.require_stateful(call)?;
        let key = resolve_key(call, header, path)?;
        self.require_key(call, &key, false).await?;
        if !self.config_lock_allows(call, Some(&key)).await {
            return Err(call.fail(Fault::new(403, DENIED)));
        }
        Ok(key)
    }

    /// `None`: nothing is stored under the key (`204`).
    pub(crate) async fn get_config(
        &self,
        call: &Call<'_>,
        header: Option<&str>,
        path: Option<&str>,
    ) -> Result<Option<Stored>, Fault> {
        let key = self.config_key(call, header, path).await?;
        match self.store.get(&key).await {
            Err(()) => Err(call.fail(Fault::new(500, "An error occurred accessing configuration"))),
            Ok(None) => Ok(None),
            Ok(Some((config, format))) if call.json => {
                let format = match format {
                    ConfigFormat::Yaml => types::StoredConfigFormat::Yaml,
                    ConfigFormat::Text => types::StoredConfigFormat::Text,
                };
                Ok(Some(Stored::Json(types::StoredConfig { format, config })))
            }
            Ok(Some((config, ConfigFormat::Yaml))) => Ok(Some(Stored::Yaml(config))),
            Ok(Some((config, ConfigFormat::Text))) => Ok(Some(Stored::Text(config))),
        }
    }

    pub(crate) async fn add(
        &self,
        call: &Call<'_>,
        header: Option<&str>,
        path: Option<&str>,
        new: Option<NewConfig>,
    ) -> Result<Saved, Fault> {
        let key = self.config_key(call, header, path).await?;
        let Some(new) = new.filter(|n| n.urls.is_some() || n.config.is_some() || n.format.is_some()) else {
            return Err(call.fail(Fault::new(400, "Invalid payload structure provided")));
        };
        let urls = match new.urls {
            Some(types::Strings::String(s)) if s.is_empty() => None,
            Some(types::Strings::String(s)) => Some(vec![s]),
            Some(types::Strings::Array(a)) => Some(a),
            // The spec's check answers any other value before the handler (`violation_fault`).
            Some(types::Strings::Other(_)) | None => None,
        };
        if let Some(raw) = urls {
            let urls: Vec<String> = mercurio::__private::parse_urls(raw.iter().map(String::as_str), true)
                .into_iter()
                .filter(|u| mercurio::parse(u).is_ok_and(|t| self.s.services.enabled(t.service().id)))
                .collect();
            if urls.is_empty() {
                return Err(call.fail(Fault::new(400, "No valid URLs defined")));
            }
            if !self.store.put(&key, &urls.join("\r\n"), ConfigFormat::Text).await {
                return Err(call.fail(Fault::new(500, "The configuration could not be saved")));
            }
        } else if let Some(config) = new.config {
            self.save_config(call, &key, &config, new.format.as_deref()).await?;
        } else {
            return Err(call.fail(Fault::new(400, "No configuration provided")));
        }
        let times = self.store.file_times(&key).await;
        Ok(Saved {
            body: done(call, "Successfully saved configuration"),
            created: times.map(|(created, _)| iso_seconds(created)),
            modified: times.map(|(_, modified)| iso_seconds(modified)),
        })
    }

    /// Checks and stores configuration text in `format` (`text`, `yaml`, or empty / `auto` to detect it).
    async fn save_config(&self, call: &Call<'_>, key: &str, config: &str, format: Option<&str>) -> Result<(), Fault> {
        if config.len() > self.s.config_max_len {
            return Err(call.fail(Fault::new(400, "The configuration payload is too large")));
        }
        let fmt = format.unwrap_or("").trim().to_lowercase();
        let format = match fmt.as_str() {
            "" | "auto" => None,
            f => match ConfigFormat::parse(f) {
                Some(f) => Some(f),
                None => return Err(call.fail(Fault::new(400, "Invalid configuration format specified"))),
            },
        };
        let mut stored = format.unwrap_or(ConfigFormat::Text);
        if !config.trim().is_empty() {
            let Some(detected) = format.or_else(|| mercurio::__private::detect_format(config)) else {
                return Err(call.fail(Fault::new(400, "The configuration format could not be auto-detected")));
            };
            stored = detected;
            let unparsed = || call.fail(Fault::new(400, "The configuration could not be parsed"));
            let cfg = self.load(config, Some(detected)).await.map_err(|_why| unparsed())?;
            if cfg.services.is_empty() && detected == ConfigFormat::Yaml && yaml_refused(config) {
                return Err(unparsed());
            }
        }
        if self.store.put(key, config, stored).await {
            Ok(())
        } else {
            Err(call.fail(Fault::new(500, "An error occurred saving configuration")))
        }
    }

    /// `None`: nothing was stored under the key (`204`).
    pub(crate) async fn del(
        &self,
        call: &Call<'_>,
        header: Option<&str>,
        path: Option<&str>,
    ) -> Result<Option<responses::Changed>, Fault> {
        let key = self.config_key(call, header, path).await?;
        let shared = call.caller.role.get() == Role::User;
        let result = self.store.clear(&key).await;
        if result == Cleared::Failed {
            return Err(call.fail(Fault::new(500, "The configuration could not be removed")));
        }
        if shared {
            // A configuration user keeps their login to save a replacement.
            self.store.touch_auth(&key).await;
        } else if self.store.clear_auth(&key).await == Cleared::Failed {
            let msg = "The configuration was removed, but its authentication could not be removed";
            return Err(call.fail(Fault::new(500, msg)));
        }
        Ok((result == Cleared::Removed).then(|| done(call, "Successfully removed configuration")))
    }

    pub(crate) async fn move_config(
        &self,
        call: &Call<'_>,
        header: Option<&str>,
        path: Option<&str>,
        to: MoveTo,
    ) -> Result<responses::Changed, Fault> {
        self.require_stateful(call)?;
        let key = resolve_key(call, header, path)?;
        self.require_key(call, &key, false).await?;
        if !self.config_lock_allows(call, None).await {
            return Err(call.fail(Fault::new(403, DENIED)));
        }
        let (from, to) = match to {
            MoveTo::Json(to) => match to {
                Some(to) if valid_key(&to) && to != key => (key.clone(), to),
                _ => {
                    let msg = "A valid destination (to), different from the source, is required";
                    return Err(call.fail(Fault::new(400, msg).field("to")));
                }
            },
            MoveTo::Form { from, to } => {
                let (from, to) = (trimmed(from), trimmed(to));
                for (name, v) in [("from", &from), ("to", &to)] {
                    if v.is_empty() {
                        return Err(call.fail(Fault::new(400, "This field is required.").field(name)));
                    }
                    if !valid_key(v) {
                        return Err(call.fail(Fault::new(400, "Enter a valid value.").field(name)));
                    }
                }
                if from == to {
                    let msg = "The destination configuration ID must differ from the source";
                    return Err(call.fail(Fault::new(400, msg)));
                }
                (from, to)
            }
        };
        if from != key {
            self.require_key(call, &from, false).await?;
        }
        if !self.s.config_lock && !self.store.writable().await {
            return Err(call.fail(Fault::new(424, "The configuration store is not currently writable")));
        }
        match self.store.move_key(&from, &to).await {
            Moved::NotFound => Err(call.fail(Fault::new(404, "There was no configuration to move"))),
            Moved::Conflict => {
                Err(call.fail(Fault::new(409, "A configuration already exists at the destination").field("to")))
            }
            Moved::Failed => Err(call.fail(Fault::new(500, "The configuration could not be moved"))),
            Moved::Done => Ok(done(call, "Successfully moved configuration")),
        }
    }

    pub(crate) async fn json_urls(
        &self,
        call: &Call<'_>,
        header: Option<&str>,
        path: Option<&str>,
        privacy: Option<&str>,
        tag: Option<&str>,
    ) -> Result<Urls, Fault> {
        let key = self.config_key(call, header, path).await?;
        let privacy = parse_bool(privacy, false);
        let show_defaults = self.s.allow_templates && !privacy && !self.s.config_lock;
        let (content, format) = match self.store.get(&key).await {
            Err(()) => {
                let error = Some("There was no configuration found".to_owned());
                return Ok(Urls::Unreadable(types::JsonUrls { error, tags: vec![], urls: vec![] }));
            }
            Ok(None) => return Ok(Urls::Empty),
            Ok(Some(c)) => c,
        };
        let cfg = Config::from_text_async(&content, Some(format), self.transport.as_ref(), &self.config_options())
            .await
            .unwrap_or_default();
        let defaults = if show_defaults { template_defaults(&content, format) } else { BTreeMap::new() };
        let filter = TagFilter::parse(tag.filter(non_blank).unwrap_or("all"));
        let mut all_tags = BTreeSet::new();
        let mut urls = Vec::new();
        for s in cfg.services.iter().filter(|s| filter.matches(s.tags())) {
            let (url, def, id, template_names) = match s {
                ConfigService::Ready(t) => (t.url().to_owned(), t.service(), t.url_id(&self.asset(false)), Vec::new()),
                ConfigService::Pending(p) => (p.url(), p.service(), None, p.template_names().to_vec()),
            };
            let mut names: Vec<String> = s.tags().iter().map(|t| t.name.clone()).collect();
            names.sort();
            names.dedup();
            all_tags.extend(names.iter().cloned());
            let mut tags: Vec<&mercurio::Tag> = s.tags().iter().collect();
            tags.sort_by(|a, b| (&a.name, a.priority).cmp(&(&b.name, b.priority)));
            let tag_details = tags
                .iter()
                .map(|t| types::JsonUrlsUrlsItemTagDetailsItem {
                    name: t.name.clone(),
                    priority: i64::try_from(t.priority).unwrap_or(i64::MAX),
                    token: if t.has_priority || t.priority > 0 {
                        format!("{}:{}", t.priority, t.name)
                    } else {
                        t.name.clone()
                    },
                    exact: format!("{}:{}", t.priority, t.name),
                })
                .collect();
            let query = url_query(&url);
            let retry = query.iter().find(|(k, _)| k == "retry").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
            let optional = query.iter().any(|(k, v)| k == "optional" && parse_bool(Some(v), false));
            let template = if self.s.allow_templates {
                template_names.iter().map(|n| (n.clone(), defaults.get(n).cloned())).collect()
            } else {
                BTreeMap::new()
            };
            urls.push(types::JsonUrlsUrlsItem {
                id,
                service_name: def.name.to_owned(),
                enabled: self.s.services.enabled(def.id),
                url: if privacy { redact_url(&url) } else { url },
                retry,
                optional,
                tags: names,
                tag_details,
                template,
            });
        }
        Ok(Urls::Found(types::JsonUrls { error: None, tags: all_tags.into_iter().collect(), urls }))
    }
}

/// A YAML document that would be discarded as a whole (syntax error, not a mapping or a broken `template:` section).
fn yaml_refused(content: &str) -> bool {
    use mercurio::__private::yaml::{Yaml, parse};
    match parse(content) {
        Err(_) => true,
        Ok(Yaml::Null) => false,
        Ok(doc) => {
            doc.as_map().is_none()
                || doc.get("template").is_some_and(|t| mercurio::__private::TemplateSchema::parse(t).is_err())
        }
    }
}

/// Template defaults declared in a YAML configuration.
fn template_defaults(content: &str, format: ConfigFormat) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if format != ConfigFormat::Yaml {
        return out;
    }
    let Ok(doc) = mercurio::__private::yaml::parse(content) else { return out };
    if let Some(Ok(schema)) = doc.get("template").map(mercurio::__private::TemplateSchema::parse) {
        for (name, default) in schema.variables {
            if let Some(d) = default {
                out.insert(name, d);
            }
        }
    }
    out
}

fn url_query(url: &str) -> Vec<(String, String)> {
    url.split_once('?').map(|(_, q)| form_pairs(q)).unwrap_or_default()
}

/// `YYYY-MM-DDTHH:MM:SS` (UTC).
fn iso_seconds(t: SystemTime) -> String {
    let secs = t.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (y, mo, d, h, mi, s) = mercurio::__private::utc_parts(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}")
}
