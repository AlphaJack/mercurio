//! `/auth`: read, set or remove a key's login.

use super::super::api::types;
use super::super::auth::{KeyState, Role};
use super::super::call::{Call, Fault};
use super::super::store::{self, Cleared};
use super::super::{Server, codec};
use super::key::resolve_key;

/// The answer to a change of login: text, or `{"error": null, "auth_state": ...}` for JSON clients.
pub(crate) enum AuthChanged {
    Text(String),
    Json(types::AuthChange),
}

fn changed(call: &Call<'_>, message: &str, state: &str) -> AuthChanged {
    if call.json {
        AuthChanged::Json(types::AuthChange { error: (), auth_state: state.to_owned() })
    } else {
        AuthChanged::Text(message.to_owned())
    }
}

impl Server {
    /// The key an `/auth` request names and its login, when storage and authentication are on.
    async fn auth_key(
        &self,
        call: &Call<'_>,
        header: Option<&str>,
        path: Option<&str>,
    ) -> Result<(String, KeyState), Fault> {
        self.require_stateful(call)?;
        if !self.s.auth.required {
            let msg = "Authentication mode is disabled (set APPRISE_AUTH_REQUIRED to enable it)";
            return Err(call.fail(Fault::new(403, msg)));
        }
        let key = resolve_key(call, header, path)?;
        let state = self.key_state(&key).await;
        Ok((key, state))
    }

    /// `GET /auth/{key}`: the key's access mode and username.
    pub(crate) async fn get_auth(
        &self,
        call: &Call<'_>,
        header: Option<&str>,
        path: Option<&str>,
    ) -> Result<types::AuthState, Fault> {
        let (key, state) = self.auth_key(call, header, path).await?;
        self.require_key(call, &key, false).await?;
        let username = if state.assigned() { state.username.clone().unwrap_or_default() } else { String::new() };
        let access = state.saved_access.clone().unwrap_or(state.access.clone());
        Ok(types::AuthState { mode: state.mode.to_owned(), access, username })
    }

    /// `DELETE /auth/{key}`: remove the key's login (administrator only).
    pub(crate) async fn delete_auth(
        &self,
        call: &Call<'_>,
        header: Option<&str>,
        path: Option<&str>,
    ) -> Result<AuthChanged, Fault> {
        let (key, _) = self.auth_key(call, header, path).await?;
        self.require_key(call, &key, false).await?;
        if call.caller.role.get() != Role::Admin {
            let msg = "Global administrator credentials are required to remove authentication";
            return Err(call.fail(Fault::new(403, msg)));
        }
        match self.store.clear_auth(&key).await {
            Cleared::Failed => Err(call.fail(Fault::new(500, "The authentication could not be removed"))),
            Cleared::Removed | Cleared::Nothing => Ok(changed(call, "Successfully removed authentication", "admin")),
        }
    }

    /// `POST /auth/{key}`: set the key's login and access mode.
    pub(crate) async fn set_auth(
        &self,
        call: &Call<'_>,
        header: Option<&str>,
        path: Option<&str>,
        body: Option<types::SetAuth>,
    ) -> Result<AuthChanged, Fault> {
        self.require_stateful(call)?;
        if call.content_type != "application/json" {
            return Err(call.fail(Fault::new(400, "Content-Type must be application/json")));
        }
        let (key, state) = self.auth_key(call, header, path).await?;
        let allowed = if state.configured() {
            self.key_ok(call, &key, false).await
        } else {
            call.caller.role.get() == Role::Admin
        };
        if !allowed {
            return Err(self.key_denied(call, &key));
        }
        let Some(body) = body else {
            return Err(call.fail(Fault::new(400, "Invalid JSON Payload provided")));
        };
        let shared = call.caller.role.get() == Role::User;
        let current_user = state.username.clone().unwrap_or_default();
        let current_access = state.saved_access.clone().unwrap_or(state.access.clone());
        if shared && body.access.is_some() {
            let f = Fault::new(403, "Only an administrator may set configuration access").field("access");
            return Err(call.fail(f));
        }
        let username = match body.username {
            super::super::api::Nullable::Value(u) => u,
            super::super::api::Nullable::Null => String::new(),
            super::super::api::Nullable::Absent if shared => String::new(),
            super::super::api::Nullable::Absent => current_user.clone(),
        };
        let Some(password) = body.password.or_else(|| (!shared).then(String::new)) else {
            return Err(call.fail(Fault::new(400, "Valid username and password fields are required")));
        };
        let username = username.trim().to_owned();
        if shared && username != current_user {
            let f = Fault::new(403, "The username cannot be changed by a configuration user").field("username");
            return Err(call.fail(f));
        }
        let access = match body.access {
            None | Some(types::SetAuthAccess::Empty) => current_access.clone(),
            Some(a) => a.to_string(),
        };
        if username.contains(':') {
            return Err(call.fail(Fault::new(400, "Username cannot contain ':'").field("username")));
        }
        for (name, v) in [("username", &username), ("password", &password)] {
            if v.chars().count() > 255 {
                return Err(call.fail(Fault::new(400, "Ensure this value has at most 255 characters.").field(name)));
            }
        }
        if !store::ACCESS_CHOICES.contains(&access.as_str()) {
            let msg = format!("Select a valid choice. {access} is not one of the available choices.");
            return Err(call.fail(Fault::new(400, msg).field("access")));
        }
        let open = access == store::ACCESS_PUBLIC || access == store::ACCESS_DISABLED;
        if shared {
            if password.is_empty() {
                return Err(call.fail(Fault::new(400, "A new password is required").field("password")));
            }
            if body.password_confirm.as_deref().is_some_and(|c| c != password) {
                return Err(call.fail(Fault::new(400, "The passwords do not match").field("password_confirm")));
            }
            if state.digest.as_deref().is_some_and(|d| codec::password_check(&format!("{username}:{password}"), d)) {
                let f = Fault::new(400, "The new password must differ from the current password").field("password");
                return Err(call.fail(f));
            }
        } else if password.is_empty() {
            if !state.assigned() && !open {
                let f = Fault::new(400, "A password is required for this access mode").field("password");
                return Err(call.fail(f));
            } else if username != current_user {
                let f = Fault::new(400, "Set a password when changing the username").field("username");
                return Err(call.fail(f));
            }
        }
        let saved = if !password.is_empty() {
            let digest = codec::password_hash(&format!("{username}:{password}"));
            let rec = store::AuthRecord { access: access.clone(), username: Some(username), digest: Some(digest) };
            self.store.write_auth(&key, &rec).await
        } else {
            match self.store.auth(&key).await {
                Ok(None) if open => {
                    let rec = store::AuthRecord { access: access.clone(), username: None, digest: None };
                    self.store.write_auth(&key, &rec).await
                }
                Ok(Some(rec)) if rec.digest.is_some() || open => {
                    self.store.write_auth(&key, &store::AuthRecord { access: access.clone(), ..rec }).await
                }
                Ok(Some(_) | None) | Err(_) => false,
            }
        };
        if !saved {
            return Err(call.fail(Fault::new(500, "The authentication could not be saved")));
        }
        let effective =
            if self.s.config_lock && access == store::ACCESS_USER { store::ACCESS_LOCKED } else { access.as_str() };
        Ok(changed(call, "Successfully set authentication", effective))
    }
}
