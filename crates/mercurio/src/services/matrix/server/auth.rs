//! Who the session is: homeserver discovery (`.well-known`), login, registration, `whoami`, the cached identity, and logout.

use super::*;

impl Session {
    pub(super) fn cache_discovery(&self, base: &str, identity: &str) {
        self.store.set(DISCOVERY_BASE_KEY, json!(base), Some(DISCOVERY_CACHE));
        self.store.set(DISCOVERY_IDENTITY_KEY, json!(identity), Some(DISCOVERY_CACHE + Duration::from_secs(2)));
    }

    pub(super) fn discovery_failed(self, why: &str, k: K<bool>) -> Plan {
        crate::warning!("Matrix Well-Known {why}");
        self.store.clear(&[DISCOVERY_BASE_KEY, DISCOVERY_IDENTITY_KEY]);
        k(self, false)
    }

    /// Homeserver discovery (`.well-known`); `k(false)` when it failed.
    pub(super) fn discover(self, k: K<bool>) -> Plan {
        let url = format!("{}/.well-known/matrix/client", self.host_base());
        let probe = |u: String| Fetch::get_url(u).bounded(MAX_RESPONSE_BYTES).no_auth();
        self.fetch(probe(url), move |s, r| {
            if r.status == 404 {
                s.cache_discovery("", "");
                return k(s, true);
            }
            if r.status != 200 {
                return s.discovery_failed("Base URI Discovery Failed", k);
            }
            if !has_value(&r.json) {
                s.cache_discovery("", "");
                return k(s, true);
            }
            let base = r
                .json
                .get("m.homeserver")
                .and_then(|h| h.get("base_url"))
                .and_then(Value::as_str)
                .map(|b| b.trim_end_matches('/').to_owned())
                .filter(|b| is_secure_http_url(b) && !b.contains('?'));
            let Some(base) = base else {
                return s.discovery_failed("Base URI Discovery Failed (m.homeserver)", k);
            };
            let response = r.json;
            s.fetch(probe(format!("{base}/_matrix/client/versions")), move |s, r| {
                if r.status != 200 {
                    return s.discovery_failed("Base URI Discovery Verification Failed", k);
                }
                let Some(id) = response.as_object().and_then(|o| o.get("m.identity_server")) else {
                    s.cache_discovery(&base, "");
                    return k(s, true);
                };
                let identity = id
                    .get("base_url")
                    .and_then(Value::as_str)
                    .map(|b| b.trim_end_matches('/').to_owned())
                    .filter(|b| is_secure_http_url(b) && !b.contains('?'));
                let Some(identity) = identity else {
                    return s.discovery_failed("Identity URI Discovery Failed", k);
                };
                s.fetch(probe(format!("{identity}/_matrix/identity/v2")), move |s, r| {
                    if r.status != 200 {
                        return s.discovery_failed("Identity URI Discovery Failed", k);
                    }
                    s.cache_discovery(&base, &identity);
                    k(s, true)
                })
            })
        })
    }

    pub(super) fn set_identity(&mut self, resp: &Value) {
        self.access_token = get_str(resp, "access_token");
        self.user_id = get_str(resp, "user_id");
        self.device_id = get_str(resp, "device_id");
        match get_str(resp, "home_server").filter(|h| !h.is_empty()) {
            Some(hs) => self.home_server = Some(hs),
            None => {
                if !non_empty(self.home_server.as_deref())
                    && let Some(u) = &self.user_id
                    && let Some(hs) = hs_of(u)
                {
                    self.home_server = Some(hs);
                }
            }
        }
    }

    pub(super) fn store_identity(&self) {
        self.store.set("access_token", json!(self.access_token), CACHE_EXPIRY);
        if non_empty(self.home_server.as_deref()) {
            self.store.set("home_server", json!(self.home_server), CACHE_EXPIRY);
        }
        self.store.set("user_id", json!(self.user_id), CACHE_EXPIRY);
        if non_empty(self.device_id.as_deref()) {
            self.store.set("device_id", json!(self.device_id), CACHE_EXPIRY);
        }
    }

    pub(super) fn login(self, k: K<bool>) -> Plan {
        if non_empty(self.access_token.as_deref()) {
            return k(self, true);
        }
        let (Some(user), Some(password)) = (self.cfg.user.clone(), self.password().map(str::to_owned)) else {
            crate::warning!("Failed to login to Matrix server: token or user/pass combo is missing.");
            return k(self, false);
        };
        let mut payload = if self.cfg.version == Version::V3 {
            json!({"type": "m.login.password", "identifier": {"type": "m.id.user", "user": user}, "password": password})
        } else {
            json!({"type": "m.login.password", "user": user, "password": password})
        };
        match &self.device_id {
            Some(d) if !d.is_empty() => payload["device_id"] = json!(d),
            _ => payload["initial_device_display_name"] = json!(self.msg.app_id),
        }
        let f = Fetch::post("/login", payload).credentials().bounded(MAX_RESPONSE_BYTES);
        self.fetch(f, move |mut s, r| {
            let Some(resp) = r.object().map(|m| Value::Object(m.clone())) else { return k(s, false) };
            s.set_identity(&resp);
            if !non_empty(s.access_token.as_deref()) {
                return k(s, false);
            }
            s.store_identity();
            k(s, true)
        })
    }

    pub(super) fn register(self, k: K<bool>) -> Plan {
        let mut payload = json!({"kind": "user", "auth": {"type": "m.login.dummy"}});
        if let Some(u) = &self.cfg.user {
            payload["username"] = json!(u);
        }
        if let Some(p) = self.password() {
            payload["password"] = json!(p);
        }
        match &self.device_id {
            Some(d) if !d.is_empty() => payload["device_id"] = json!(d),
            _ => payload["initial_device_display_name"] = json!(self.msg.app_id),
        }
        let f = Fetch::post("/register", payload).param("kind", "user");
        self.fetch(f, move |mut s, r| {
            let Some(resp) = r.object().map(|m| Value::Object(m.clone())) else { return k(s, false) };
            s.set_identity(&resp);
            s.store_identity();
            let ok = s.access_token.is_some();
            k(s, ok)
        })
    }

    pub(super) fn whoami(self, k: K<()>) -> Plan {
        self.fetch(Fetch::get("/account/whoami"), move |mut s, r| {
            let Some(resp) = r.object().map(|m| Value::Object(m.clone())) else { return k(s, ()) };
            if let Some(u) = get_str(&resp, "user_id").filter(|u| !u.is_empty()) {
                s.user_id = Some(u);
            }
            if let Some(d) = get_str(&resp, "device_id").filter(|d| !d.is_empty()) {
                s.device_id = Some(d);
            }
            if !non_empty(s.home_server.as_deref())
                && let Some(u) = &s.user_id
                && let Some(hs) = hs_of(u)
            {
                s.home_server = Some(hs);
            }
            if non_empty(s.user_id.as_deref()) {
                s.store.set("user_id", json!(s.user_id), CACHE_EXPIRY);
            }
            if non_empty(s.device_id.as_deref()) {
                s.store.set("device_id", json!(s.device_id), CACHE_EXPIRY);
            }
            if non_empty(s.home_server.as_deref()) {
                s.store.set("home_server", json!(s.home_server), CACHE_EXPIRY);
            }
            k(s, ())
        })
    }

    /// Log out of a session kept in a memory store (persistent stores keep it for the next run). `None` when there is nothing to do.
    pub(crate) fn logout(self) -> Option<Plan> {
        let token_is_password =
            self.access_token.is_some() && self.access_token.as_deref() == self.password() && self.cfg.user.is_none();
        if self.cfg.mode == Mode::T2bot
            || self.store.path().is_some()
            || token_is_password
            || !non_empty(self.access_token.as_deref())
        {
            return None;
        }
        Some(self.fetch(Fetch::post("/logout", json!({})), |s, _| {
            s.store.clear(&[
                "access_token",
                "home_server",
                "user_id",
                "transaction_id",
                "device_id",
                "e2ee_keys_uploaded",
            ]);
            Plan::Done
        }))
    }
}
