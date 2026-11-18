//! `/status`, `/details` and `/metrics`.

use serde_json::Value;

use super::super::api::operations::{self as ops, responses};
use super::super::api::types;
use super::super::call::{Call, Fault, parse_bool};
use super::super::key::MISSING_KEY;
use super::super::{Server, details, store};

/// The health of the server: whether it can write configurations and persistent storage.
pub(crate) struct Health {
    pub ok: bool,
    pub body: responses::Health,
}

impl Server {
    /// `GET /status[/{key}]`: `OK`, or the problems found; JSON clients get the details.
    pub(crate) async fn status(
        &self,
        call: &Call<'_>,
        header: Option<&str>,
        key: Option<&str>,
    ) -> Result<Health, Fault> {
        if let Some(k) = header.or(key) {
            self.require_key(call, k, false).await?;
        }
        let stateful = self.store.enabled();
        let mut problems = Vec::new();
        let mut can_write_config = false;
        if stateful && !self.s.config_lock {
            can_write_config = self.store.writable().await;
            if !can_write_config {
                problems.push(types::HealthStatusDetailsItem::ConfigPermissionIssue);
            }
        }
        let mut persistent = false;
        if let Some(dir) = &self.s.storage {
            persistent = store::writable(dir).await;
            if !persistent {
                problems.push(types::HealthStatusDetailsItem::StorePermissionIssue);
            }
        }
        let ok = problems.is_empty();
        let details = if ok { vec![types::HealthStatusDetailsItem::Ok] } else { problems };
        if !call.json {
            let text: Vec<String> = details.iter().map(ToString::to_string).collect();
            return Ok(Health { ok, body: responses::Health::Plain(text.join(",")) });
        }
        let privilege = match call.caller.role.get().label() {
            "user" => types::HealthPrivilege::User,
            _ => types::HealthPrivilege::Admin,
        };
        let health = types::Health {
            config_lock: !self.config_lock_allows(call, key).await,
            attach_lock: self.s.attach_size == 0,
            stateful_enabled: stateful,
            stateless_enabled: self.s.stateless_enabled,
            degraded: !stateful && !self.s.stateless_enabled,
            max_attachments: i64::try_from(self.s.max_attachments).unwrap_or(i64::MAX),
            attach_size: i64::try_from(self.s.attach_size).unwrap_or(i64::MAX),
            privilege,
            status: types::HealthStatus {
                persistent_storage: persistent,
                can_write_config,
                can_write_attach: self.s.attach_size > 0,
                details,
            },
        };
        Ok(Health { ok, body: responses::Health::Json(health) })
    }

    /// `GET /details`: the supported services and their URL templates; `?all=yes` includes disabled ones.
    pub(crate) async fn details(
        &self,
        call: &Call<'_>,
        header: Option<&str>,
        all: Option<&str>,
    ) -> Result<types::Details, Fault> {
        if let Some(k) = header {
            self.require_key(call, k, false).await?;
        }
        let show_all = parse_bool(all, false);
        // The answer depends on the settings only: built once per `all`, it is about 0.5 MB of JSON.
        Ok(self.details_cache[usize::from(show_all)].get_or_init(|| self.details_json(show_all)).clone())
    }

    fn details_json(&self, show_all: bool) -> types::Details {
        let mut schemas: Vec<Value> = mercurio::services()
            .iter()
            .filter(|d| show_all || self.s.services.enabled(d.id))
            .map(|d| details::schema(d, show_all.then(|| self.s.services.enabled(d.id))))
            .collect();
        schemas.sort_by_key(|s| s["service_name"].as_str().unwrap_or("").to_uppercase());
        let as_map = |v: Value| match v {
            Value::Object(m) => m.into_iter().collect(),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Array(_) => Default::default(),
        };
        types::Details {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            schemas: schemas.into_iter().map(as_map).collect(),
            asset: as_map(details::asset(&self.asset(false))),
        }
    }

    /// `GET /metrics`: the counters in the Prometheus text format.
    pub(crate) fn metrics_page(&self) -> String {
        self.metrics.render()
    }

    /// `/status/@`, `/cfg/@`, `/auth/@`: the current Config ID, which an API call never has.
    pub(crate) fn current_key(call: &Call<'_>) -> Fault {
        call.fail(Fault::new(400, MISSING_KEY))
    }
}

/// `200` with the health when it is good, `417` with it otherwise.
macro_rules! health_response {
    ($($op:ident),*) => {$(
        impl ops::$op::Response {
            pub(crate) fn health(h: Health) -> Self {
                if h.ok { Self::Ok(h.body) } else { Self::ExpectationFailed(h.body) }
            }
        }
    )*};
}
health_response!(status, status_key);
