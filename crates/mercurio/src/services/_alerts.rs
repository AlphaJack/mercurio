//! Alert lifecycle of Jira Service Management Operations alerts (`jira://`, `opsgenie://`): `new` alerts remember their `requestId`s in the persistent store (60 days, keyed by a hash of entity, alias or title); `close`, `acknowledge`, `note` and `delete` act on the remembered ids.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use crate::http::{Method, Request, Response};
use crate::service::Context;
use crate::util::{json_text, json_has_value};
use crate::{Error, Plan, Result};

/// Request ids are kept for 60 days.
const ID_EXPIRY: Duration = Duration::from_secs(60 * 60 * 24 * 60);

/// One alert delivery.
pub(crate) struct AlertJob {
    /// Service name for error messages.
    pub name: &'static str,
    pub url: &'static str,
    pub headers: Vec<(&'static str, String)>,
    /// Effective action: `new`, `close`, `acknowledge`, `note` or `delete`.
    pub action: &'static str,
    /// `entity`, else `alias`, else the title, else the app id.
    pub key_source: String,
    /// Payload of a new alert (without `responders`).
    pub payload: Value,
    /// `(batch start index, responders)`; one `(0, None)` entry without targets.
    pub batches: Vec<(usize, Option<Value>)>,
    /// Payload for the other actions (`{"source", "note", "user"?}`).
    pub note: Value,
    /// The message text: the payloads hold [`crate::http::TEXT`] where it goes, so it exists once here.
    pub text: String,
    /// Message piece index (delivery tracking is per piece).
    pub piece: usize,
}

/// Store key: first 10 hex characters of SHA-1 of the key source.
fn store_key(source: &str) -> String {
    let mut h = crate::crypto::hex(&crate::crypto::sha1(source.as_bytes()));
    h.truncate(10);
    h
}

/// Success on 200/202; returns the `requestId` if any.
fn fetch(name: &'static str, res: Result<Response>) -> std::result::Result<Value, Error> {
    let r = res?;
    let content = r.json().unwrap_or_else(|| json!({}));
    let Some(obj) = content.as_object() else {
        return Err(Error::Service(format!("unexpected {name} response")));
    };
    if r.status != 200 && r.status != 202 {
        return Err(r.http_error());
    }
    Ok(obj.get("requestId").cloned().unwrap_or(Value::Null))
}

impl AlertJob {
    fn request(&self, method: Method, url: String, body: &Value) -> Request {
        let mut req = Request::new(method, url);
        for (k, v) in &self.headers {
            req = req.header(*k, v.as_str());
        }
        req.body(crate::http::json_with_text(body, &self.text), None)
    }

    pub(crate) fn plan(self, ctx: &Context<'_>) -> Plan {
        let store = ctx.store();
        let memo = ctx.memo.clone();
        let key = store_key(&self.key_source);
        let stored: Vec<Value> = store.get(&key).and_then(|v| v.as_array().cloned()).unwrap_or_default();
        let slot = |index: usize| format!("{}:{}:{index}", self.name, self.piece);

        if self.action == "new" {
            // Start a new id list unless an earlier attempt completed a batch.
            let resumed = self.batches.iter().any(|(i, _)| memo.is_delivered(&slot(*i)));
            let ids = Arc::new(Mutex::new(if resumed { stored } else { Vec::new() }));
            let mut plans = Vec::new();
            for (index, responders) in &self.batches {
                let tag = slot(*index);
                if memo.is_delivered(&tag) {
                    continue;
                }
                let mut payload = self.payload.clone();
                if let Some(r) = responders {
                    payload["responders"] = r.clone();
                }
                let req = self.request(Method::Post, self.url.to_owned(), &payload);
                let (ids, memo, name) = (ids.clone(), memo.clone(), self.name);
                plans.push(Plan::http(req, move |res| match fetch(name, res) {
                    Ok(id) if json_has_value(&id) => {
                        ids.lock().unwrap_or_else(|p| p.into_inner()).push(id);
                        memo.mark_delivered(&tag);
                        Plan::Done
                    }
                    Ok(_) => Plan::Fail(Error::Service(format!("{name} returned no requestId"))),
                    Err(e) => Plan::Fail(e),
                }));
            }
            plans.push(Plan::defer(move || {
                let ids = ids.lock().unwrap_or_else(|p| p.into_inner()).clone();
                store.set(&key, Value::Array(ids), Some(ID_EXPIRY));
                Plan::Done
            }));
            return Plan::all(plans);
        }

        if stored.is_empty() {
            log::info!("No {} notification sent due to (nothing to {}) condition", self.name, self.action);
            return Plan::Done;
        }
        let failed = Arc::new(AtomicBool::new(false));
        let mut plans: Vec<Plan> = stored
            .iter()
            .map(|id| {
                let id = json_text(id);
                let (method, url) = match self.action {
                    "delete" => (Method::Delete, format!("{}/{id}", self.url)),
                    "acknowledge" => (Method::Post, format!("{}/{id}/acknowledge", self.url)),
                    "close" => (Method::Post, format!("{}/{id}/close", self.url)),
                    _ => (Method::Post, format!("{}/{id}/notes", self.url)),
                };
                let req = self.request(method, url, &self.note).query(&[("identifierType", "id")]);
                let (failed, name) = (failed.clone(), self.name);
                Plan::http(req, move |res| match fetch(name, res) {
                    Ok(_) => Plan::Done,
                    Err(e) => {
                        failed.store(true, Ordering::SeqCst);
                        Plan::Fail(e)
                    }
                })
            })
            .collect();
        if self.action == "delete" {
            plans.push(Plan::defer(move || {
                if !failed.load(Ordering::SeqCst) {
                    store.clear(&[&key]);
                }
                Plan::Done
            }));
        }
        Plan::all(plans)
    }
}
