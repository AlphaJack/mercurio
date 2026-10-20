//! `/status`, `/details` and `/metrics`.

use serde_json::{Value, json};

use super::super::http::{Reply, Req, parse_bool};
use super::super::{INVALID_KEY_HEADER, Server, details, store, valid_key};

impl Server {
    pub(crate) async fn status(&self, req: &Req, key: Option<&str>) -> Reply {
        let key = match (req.x_header("Config-ID"), key) {
            (Some(h), _) if !valid_key(h) => return Reply::error(req, 400, INVALID_KEY_HEADER),
            (Some(h), _) => Some(h.to_string()),
            (None, k) => k.map(str::to_string),
        };
        if let Some(k) = key.as_deref()
            && !self.key_ok(req, k, false).await
        {
            return self.key_denied(req, k);
        }
        let stateful = self.store.enabled();
        let mut details = Vec::new();
        let mut can_write_config = false;
        if stateful && !self.s.config_lock {
            can_write_config = self.store.writable().await;
            if !can_write_config {
                details.push("CONFIG_PERMISSION_ISSUE");
            }
        }
        let mut persistent = false;
        if let Some(dir) = &self.s.storage {
            persistent = store::writable(dir).await;
            if !persistent {
                details.push("STORE_PERMISSION_ISSUE");
            }
        }
        if details.is_empty() {
            details.push("OK");
        }
        let status = if details.contains(&"OK") { 200 } else { 417 };
        if !req.wants_json() {
            return Reply::text(status, &details.join(","));
        }
        Reply::json(
            status,
            &json!({
                "config_lock": !self.config_lock_allows(req, key.as_deref()).await,
                "attach_lock": self.s.attach_size == 0,
                "stateful_enabled": stateful,
                "stateless_enabled": self.s.stateless_enabled,
                "degraded": !stateful && !self.s.stateless_enabled,
                "max_attachments": self.s.max_attachments,
                "attach_size": self.s.attach_size,
                "status": {
                    "persistent_storage": persistent,
                    "can_write_config": can_write_config,
                    "can_write_attach": self.s.attach_size > 0,
                    "details": details,
                },
                "privilege": req.role.get().label(),
            }),
        )
    }

    pub(crate) async fn details(&self, req: &Req) -> Reply {
        if let Some(h) = req.x_header("Config-ID") {
            if !valid_key(h) {
                return Reply::error(req, 400, INVALID_KEY_HEADER);
            }
            if !self.key_ok(req, h, false).await {
                return self.key_denied(req, h);
            }
        }
        let show_all = parse_bool(req.query("all"), false);
        let mut schemas: Vec<Value> = mercurio::services()
            .iter()
            .filter(|d| show_all || self.s.services.enabled(d.id))
            .map(|d| details::schema(d, show_all.then(|| self.s.services.enabled(d.id))))
            .collect();
        schemas.sort_by_key(|s| s["service_name"].as_str().unwrap_or("").to_uppercase());
        let asset = details::asset(&self.asset(false));
        Reply::json(200, &json!({"version": env!("CARGO_PKG_VERSION"), "schemas": schemas, "asset": asset}))
    }

    pub(crate) fn metrics_page(&self) -> Reply {
        Reply::new(200, "text/plain; version=0.0.4; charset=utf-8", self.metrics.render().into_bytes())
    }
}
