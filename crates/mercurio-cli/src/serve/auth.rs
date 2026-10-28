//! Basic Auth: an optional administrator login plus per-key logins with an access mode (`user`, `locked`, `public`, `disabled`).

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::codec;
use super::store::{ACCESS_DISABLED, ACCESS_LOCKED, ACCESS_PUBLIC, ACCESS_USER, AuthRecord, ConfigStore};

/// Who is calling, as far as this request has proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum Role {
    /// Authentication is switched off.
    #[default]
    Open,
    /// The administrator login.
    Admin,
    /// A per-key login (for the key checked last).
    User,
    /// Nothing proven yet.
    Anonymous,
}

impl Role {
    pub(super) fn label(self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Open | Role::Admin | Role::Anonymous => "admin",
        }
    }
}

pub(super) struct AuthSettings {
    pub required: bool,
    /// `(username, password)` of the administrator, when enabled.
    pub admin: Option<(String, String)>,
    pub realm: String,
}

/// How one key is protected (`ConfigAuthState`).
#[derive(Debug, Clone)]
pub(super) struct KeyState {
    /// `disabled` (authentication off), `global` (no login) or `assigned`.
    pub mode: &'static str,
    pub username: Option<String>,
    pub digest: Option<String>,
    /// Effective access (the global lock turns `user` into `locked`).
    pub access: String,
    pub saved_access: Option<String>,
}

impl KeyState {
    pub(super) fn assigned(&self) -> bool {
        self.digest.is_some()
    }
    pub(super) fn configured(&self) -> bool {
        self.mode == "assigned"
    }
    pub(super) fn config_locked(&self) -> bool {
        [ACCESS_LOCKED, ACCESS_PUBLIC, ACCESS_DISABLED].contains(&self.access.as_str())
    }
    pub(super) fn public(&self) -> bool {
        self.access == ACCESS_PUBLIC
    }
    pub(super) fn disabled(&self) -> bool {
        self.access == ACCESS_DISABLED
    }
}

/// Remembers successful password checks for five minutes (hashing is slow by design); never the credentials themselves.
pub(super) struct Verifier {
    secret: [u8; 32],
    ok: Mutex<BTreeMap<Vec<u8>, Instant>>,
}

const CACHE_TTL: Duration = Duration::from_secs(300);
const CACHE_MAX: usize = 4096;

impl Default for Verifier {
    fn default() -> Self {
        let mut secret = [0u8; 32];
        mercurio::__private::random_bytes(&mut secret);
        Verifier { secret, ok: Mutex::new(BTreeMap::new()) }
    }
}

impl Verifier {
    pub(super) fn verify(&self, key: &str, user: &str, pass: &str, rec_user: Option<&str>, digest: &str) -> bool {
        let mut material = Vec::new();
        for v in [key, user, pass, digest] {
            material.extend_from_slice(&(v.len() as u64).to_be_bytes());
            material.extend_from_slice(v.as_bytes());
        }
        let fp = mercurio::__private::hmac_sha256(&self.secret, &material);
        let user_ok = rec_user.is_none_or(|u| u == user);
        if let Ok(mut cache) = self.ok.lock() {
            if cache.get(&fp).is_some_and(|t| t.elapsed() < CACHE_TTL) {
                return user_ok;
            }
            cache.retain(|_, t| t.elapsed() < CACHE_TTL);
        }
        let ok = codec::password_check(&format!("{user}:{pass}"), digest) && user_ok;
        if ok
            && let Ok(mut cache) = self.ok.lock()
            && cache.len() < CACHE_MAX
        {
            cache.insert(fp, Instant::now());
        }
        ok
    }
}

impl AuthSettings {
    /// The key's state; an unreadable login stays locked.
    pub(super) async fn key_state(&self, store: &ConfigStore, key: &str, config_lock: bool) -> KeyState {
        let effective = |a: &str| if config_lock && a == ACCESS_USER { ACCESS_LOCKED.to_owned() } else { a.to_owned() };
        if !self.required {
            return KeyState {
                mode: "disabled",
                username: None,
                digest: None,
                access: effective(ACCESS_USER),
                saved_access: None,
            };
        }
        match store.auth(key).await {
            Err(()) => KeyState {
                mode: "assigned",
                username: None,
                digest: None,
                access: ACCESS_LOCKED.into(),
                saved_access: None,
            },
            Ok(None) => KeyState {
                mode: "global",
                username: None,
                digest: None,
                access: effective(ACCESS_USER),
                saved_access: None,
            },
            Ok(Some(AuthRecord { access, username, digest })) => {
                KeyState { mode: "assigned", username, digest, access: effective(&access), saved_access: Some(access) }
            }
        }
    }

    pub(super) fn is_admin(&self, creds: Option<&(String, String)>) -> bool {
        match (&self.admin, creds) {
            (Some((u, p)), Some((cu, cp))) => {
                let a = format!("{u}:{p}");
                let b = format!("{cu}:{cp}");
                a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
            }
            _ => false,
        }
    }
}
