//! `/auth`: read, set or remove a key's login.

use serde_json::{Value, json};

use super::super::auth::{KeyState, Role};
use super::super::http::{Reply, Req};
use super::super::store::{self, Cleared};
use super::super::{Server, codec, payload, resolve_key};

impl Server {
    pub(crate) async fn auth_view(&self, req: &Req, key: Option<&str>) -> Reply {
        if let Some(r) = self.stateful_disabled(req) {
            return r;
        }
        if req.method == "POST" && req.content_type() != "application/json" {
            return Reply::error(req, 400, "Content-Type must be application/json");
        }
        if !self.s.auth.required {
            return Reply::error(req, 403, "Authentication mode is disabled (set APPRISE_AUTH_REQUIRED to enable it)");
        }
        let key = match resolve_key(req, key) {
            Ok(k) => k,
            Err(r) => return r,
        };
        let state = self.key_state(&key).await;
        match req.method.as_str() {
            "POST" => {
                let allowed = if state.configured() {
                    self.key_ok(req, &key, false).await
                } else {
                    req.role.get() == Role::Admin
                };
                if !allowed {
                    return self.key_denied(req, &key);
                }
                self.auth_set(req, &key, &state).await
            }
            "DELETE" => {
                if !self.key_ok(req, &key, false).await {
                    return self.key_denied(req, &key);
                }
                if req.role.get() != Role::Admin {
                    let msg = "Global administrator credentials are required to remove authentication";
                    return Reply::error(req, 403, msg);
                }
                match self.store.clear_auth(&key).await {
                    Cleared::Failed => Reply::error(req, 500, "The authentication could not be removed"),
                    Cleared::Removed | Cleared::Nothing if req.wants_json() => {
                        Reply::json(200, &json!({"error": null, "auth_state": "admin"}))
                    }
                    Cleared::Removed | Cleared::Nothing => Reply::text(200, "Successfully removed authentication"),
                }
            }
            _ => {
                if !self.key_ok(req, &key, false).await {
                    return self.key_denied(req, &key);
                }
                let username =
                    if state.assigned() { state.username.clone().unwrap_or_default() } else { String::new() };
                let access = state.saved_access.clone().unwrap_or(state.access.clone());
                Reply::json(200, &json!({"mode": state.mode, "access": access, "username": username}))
            }
        }
    }

    /// `POST /auth/{key}`: set credentials and access.
    async fn auth_set(&self, req: &Req, key: &str, state: &KeyState) -> Reply {
        let content = match payload::json_object(req) {
            Ok(m) => m,
            Err(r) => return r,
        };
        let shared = req.role.get() == Role::User;
        let current_user = state.username.clone().unwrap_or_default();
        let current_access = state.saved_access.clone().unwrap_or(state.access.clone());
        if shared && content.contains_key("access") {
            return Reply::field_error(req, 403, "Only an administrator may set configuration access", "access");
        }
        let field = |k: &str, default: Option<Value>| content.get(k).cloned().or(default);
        let default_user = Value::String(if shared { String::new() } else { current_user.clone() });
        let username = match field("username", Some(default_user)) {
            Some(Value::Null) => Some(String::new()),
            Some(Value::String(s)) => Some(s),
            _ => None,
        };
        let access = field("access", Some(Value::String(current_access.clone())));
        let password = field("password", if shared { None } else { Some(Value::String(String::new())) });
        let confirm = content.get("password_confirm");
        let (Some(username), Some(Value::String(access)), Some(Value::String(password))) = (username, access, password)
        else {
            return Reply::error(req, 400, "Valid username and password fields are required");
        };
        if shared && confirm.is_some_and(|c| !c.is_string()) {
            return Reply::error(req, 400, "Valid username and password fields are required");
        }
        let username = username.trim().to_string();
        if shared && username != current_user {
            return Reply::field_error(req, 403, "The username cannot be changed by a configuration user", "username");
        }
        let access = if access.is_empty() { current_access.clone() } else { access };
        if username.contains(':') {
            return Reply::field_error(req, 400, "Username cannot contain ':'", "username");
        }
        for (name, v) in [("username", &username), ("password", &password)] {
            if v.chars().count() > 255 {
                return Reply::field_error(req, 400, "Ensure this value has at most 255 characters.", name);
            }
        }
        if !store::ACCESS_CHOICES.contains(&access.as_str()) {
            let msg = format!("Select a valid choice. {access} is not one of the available choices.");
            return Reply::field_error(req, 400, &msg, "access");
        }
        let open = access == store::ACCESS_PUBLIC || access == store::ACCESS_DISABLED;
        if shared {
            if password.is_empty() {
                return Reply::field_error(req, 400, "A new password is required", "password");
            }
            if confirm.and_then(Value::as_str).is_some_and(|c| c != password) {
                return Reply::field_error(req, 400, "The passwords do not match", "password_confirm");
            }
            if state.digest.as_deref().is_some_and(|d| codec::password_check(&format!("{username}:{password}"), d)) {
                let msg = "The new password must differ from the current password";
                return Reply::field_error(req, 400, msg, "password");
            }
        } else if password.is_empty() {
            if !state.assigned() && !open {
                return Reply::field_error(req, 400, "A password is required for this access mode", "password");
            } else if username != current_user {
                return Reply::field_error(req, 400, "Set a password when changing the username", "username");
            }
        }
        let saved = if !password.is_empty() {
            let digest = codec::password_hash(&format!("{username}:{password}"));
            let rec = store::AuthRecord { access: access.clone(), username: Some(username), digest: Some(digest) };
            self.store.write_auth(key, &rec).await
        } else {
            match self.store.auth(key).await {
                Ok(None) if open => {
                    let rec = store::AuthRecord { access: access.clone(), username: None, digest: None };
                    self.store.write_auth(key, &rec).await
                }
                Ok(Some(rec)) if rec.digest.is_some() || open => {
                    self.store.write_auth(key, &store::AuthRecord { access: access.clone(), ..rec }).await
                }
                _ => false,
            }
        };
        if !saved {
            return Reply::error(req, 500, "The authentication could not be saved");
        }
        let effective =
            if self.s.config_lock && access == store::ACCESS_USER { store::ACCESS_LOCKED } else { access.as_str() };
        if req.wants_json() {
            Reply::json(200, &json!({"error": null, "auth_state": effective}))
        } else {
            Reply::text(200, "Successfully set authentication")
        }
    }
}
