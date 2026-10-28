//! Opt-in (`?autoverify=yes`) same-user SAS verification.
//!
//! The service polls `/sync` for up to 120 seconds for an `m.key.verification.request` from another device of the same user, answers it (`ready`, `accept`, `key`, `mac`, `done`) and remembers the verified identity in the key store. The SAS code is logged at `info` level; compare it with the other device before approving there. Reference: <https://spec.matrix.org/v1.19/client-server-api/#key-verification-framework>.

use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use super::{XKey, b64dec, b64enc, canonical_json, hkdf_sha256, hmac_sha256, sha256, verify_device_keys};
use super::flow::binding_key;
use super::super::server::{CACHE_EXPIRY, Fetch, K, Session, has_value};
use crate::Plan;
use crate::env::Env;

pub(crate) const EVENT_REQUEST: &str = "m.key.verification.request";
pub(crate) const EVENT_READY: &str = "m.key.verification.ready";
pub(crate) const EVENT_START: &str = "m.key.verification.start";
pub(crate) const EVENT_ACCEPT: &str = "m.key.verification.accept";
pub(crate) const EVENT_CANCEL: &str = "m.key.verification.cancel";
pub(crate) const EVENT_KEY: &str = "m.key.verification.key";
pub(crate) const EVENT_MAC: &str = "m.key.verification.mac";
pub(crate) const EVENT_DONE: &str = "m.key.verification.done";

const METHOD: &str = "m.sas.v1";
const KEY_AGREEMENT: &str = "curve25519-hkdf-sha256";
const HASH: &str = "sha256";
const MAC: &str = "hkdf-hmac-sha256.v2";
const MAX_MAC_KEYS: usize = 10;
const MAX_FIELD_LEN: usize = 512;
const REQUEST_MAX_PAST_MS: i64 = 10 * 60 * 1000;
const REQUEST_MAX_FUTURE_MS: i64 = 5 * 60 * 1000;
const MAX_ID_LEN: usize = 512;
const MAX_DEVICE_KEYS: usize = 8;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(120);
const RETRY_COOLDOWN: Duration = Duration::from_secs(60 * 15);
const REFRESH_INTERVAL: f64 = 60.0 * 60.0 * 24.0;
/// Half the default 4 s read timeout.
const POLL_MS: u64 = 2000;

fn sync_filter() -> String {
    // The /sync filter, serialised with ", " and ": " separators.
    r#"{"presence": {"types": []}, "account_data": {"types": []}, "room": {"rooms": []}}"#.to_owned()
}

fn valid_id(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty() && s.chars().count() <= MAX_ID_LEN).map(str::to_owned)
}

/// `x` is listed in `value`: an array item, a substring or an object key.
fn advertises(value: Option<&Value>, x: &str) -> bool {
    match value {
        Some(Value::Array(a)) => a.iter().any(|v| v.as_str() == Some(x)),
        Some(Value::String(s)) => s.contains(x),
        Some(Value::Object(m)) => m.contains_key(x),
        _ => false,
    }
}

fn bounded_str(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty() && s.chars().count() <= MAX_FIELD_LEN)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SasState {
    Started,
    Accepted,
    KeyReceived,
    MacSent,
    Verified,
}

/// Responder side of one SAS verification.
#[derive(Debug)]
pub(crate) struct Sas {
    own_user: String,
    own_device: String,
    peer_user: String,
    peer_device: String,
    start: Value,
    pub transaction_id: String,
    sas_methods: Vec<String>,
    key: XKey,
    pub public_key: String,
    shared: Option<[u8; 32]>,
    peer_public: Option<String>,
    pub state: SasState,
}

impl Drop for Sas {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.as_mut() {
            zeroize::Zeroize::zeroize(shared);
        }
    }
}

pub(crate) type SasResult<T> = Result<T, &'static str>;

/// Three 13-bit numbers (1000..=9191) from 5 SAS bytes.
pub(crate) fn decimal_from_bytes(b: &[u8; 5]) -> (u16, u16, u16) {
    let mut v: u64 = 0;
    for x in b {
        v = (v << 8) | u64::from(*x);
    }
    let v = v >> 1;
    (((v >> 26) & 0x1fff) as u16 + 1000, ((v >> 13) & 0x1fff) as u16 + 1000, (v & 0x1fff) as u16 + 1000)
}

impl Sas {
    pub(crate) fn new(
        own_user: &str,
        own_device: &str,
        peer_user: &str,
        peer_device: &str,
        start: &Value,
        env: &dyn Env,
    ) -> SasResult<Self> {
        Self::with_key(own_user, own_device, peer_user, peer_device, start, XKey::generate(env))
    }

    pub(crate) fn with_key(
        own_user: &str,
        own_device: &str,
        peer_user: &str,
        peer_device: &str,
        start: &Value,
        key: XKey,
    ) -> SasResult<Self> {
        let obj = start.as_object().ok_or("SAS start content must be an object")?;
        let txn = obj.get("transaction_id").and_then(Value::as_str).filter(|t| !t.is_empty());
        let (Some(txn), false) = (txn, peer_device.is_empty()) else {
            return Err("Missing SAS transaction or peer device ID");
        };
        if obj.get("from_device").and_then(Value::as_str) != Some(peer_device) {
            return Err("SAS start device does not match request device");
        }
        if obj.get("method").and_then(Value::as_str) != Some(METHOD) {
            return Err("Unsupported SAS verification method");
        }
        if !advertises(obj.get("key_agreement_protocols"), KEY_AGREEMENT) {
            return Err("Unsupported SAS key agreement");
        }
        if !advertises(obj.get("hashes"), HASH) {
            return Err("Unsupported SAS hash");
        }
        if !advertises(obj.get("message_authentication_codes"), MAC) {
            return Err("Unsupported SAS MAC");
        }
        let sas_methods: Vec<String> = ["decimal"]
            .iter()
            .filter(|m| advertises(obj.get("short_authentication_string"), m))
            .map(|m| m.to_string())
            .collect();
        if sas_methods.is_empty() {
            return Err("SAS start does not offer decimal verification");
        }
        let public_key = b64enc(&key.public());
        Ok(Sas {
            own_user: own_user.into(),
            own_device: own_device.into(),
            peer_user: peer_user.into(),
            peer_device: peer_device.into(),
            start: start.clone(),
            transaction_id: txn.to_owned(),
            sas_methods,
            key,
            public_key,
            shared: None,
            peer_public: None,
            state: SasState::Started,
        })
    }

    /// `m.key.verification.accept` content.
    pub(crate) fn accept_content(&mut self) -> SasResult<Value> {
        if self.state != SasState::Started {
            return Err("SAS verification start was already accepted");
        }
        let mut data = self.public_key.as_bytes().to_vec();
        data.extend_from_slice(canonical_json(&self.start).as_bytes());
        let commitment = b64enc(&sha256(&data));
        self.state = SasState::Accepted;
        Ok(json!({
            "transaction_id": self.transaction_id,
            "key_agreement_protocol": KEY_AGREEMENT,
            "hash": HASH,
            "message_authentication_code": MAC,
            "short_authentication_string": self.sas_methods,
            "commitment": commitment,
        }))
    }

    pub(crate) fn receive_key(&mut self, peer_public: &Value) -> SasResult<()> {
        if self.state != SasState::Accepted {
            return Err("Unexpected SAS key event");
        }
        let Some(pk) = bounded_str(Some(peer_public)) else { return Err("SAS peer key is missing or malformed") };
        let raw = b64dec(pk).ok().ok_or("SAS peer key is not base64")?;
        let shared = self.key.exchange(&raw).map_err(|e| e.0)?;
        self.shared = Some(shared);
        self.peer_public = Some(pk.to_owned());
        self.state = SasState::KeyReceived;
        Ok(())
    }

    pub(crate) fn key_content(&self) -> SasResult<Value> {
        if self.state != SasState::KeyReceived {
            return Err("SAS peer key has not been received");
        }
        Ok(json!({"transaction_id": self.transaction_id, "key": self.public_key}))
    }

    fn sas_info(&self) -> SasResult<String> {
        let peer = self.peer_public.as_ref().ok_or("SAS shared secret has not been established")?;
        Ok(format!(
            "MATRIX_KEY_VERIFICATION_SAS|{}|{}|{}|{}|{}|{}|{}",
            self.peer_user,
            self.peer_device,
            peer,
            self.own_user,
            self.own_device,
            self.public_key,
            self.transaction_id
        ))
    }

    /// The decimal short authentication string.
    pub(crate) fn decimal_sas(&self) -> SasResult<(u16, u16, u16)> {
        let shared = self.shared.as_ref().ok_or("SAS shared secret has not been established")?;
        let info = self.sas_info()?;
        let bytes = hkdf_sha256(shared, 5, None, info.as_bytes());
        let b: [u8; 5] = bytes.as_slice().try_into().ok().ok_or("hkdf length")?;
        Ok(decimal_from_bytes(&b))
    }

    fn calculate_mac(
        &self,
        value: &str,
        key_id: &str,
        sender: (&str, &str),
        receiver: (&str, &str),
    ) -> SasResult<String> {
        let shared = self.shared.as_ref().ok_or("SAS shared secret has not been established")?;
        let info = format!(
            "MATRIX_KEY_VERIFICATION_MAC{}{}{}{}{}{}",
            sender.0, sender.1, receiver.0, receiver.1, self.transaction_id, key_id
        );
        let mac_key = hkdf_sha256(shared, 32, None, info.as_bytes());
        Ok(b64enc(&hmac_sha256(&mac_key, value.as_bytes())))
    }

    /// MAC proving possession of our device signing key.
    pub(crate) fn mac_content(&mut self, own_signing_key: &str) -> SasResult<Value> {
        if self.state != SasState::KeyReceived {
            return Err("SAS peer key has not been received");
        }
        let key_id = format!("ed25519:{}", self.own_device);
        let own = (self.own_user.clone(), self.own_device.clone());
        let peer = (self.peer_user.clone(), self.peer_device.clone());
        let mac = self.calculate_mac(own_signing_key, &key_id, (&own.0, &own.1), (&peer.0, &peer.1))?;
        let keys = self.calculate_mac(&key_id, "KEY_IDS", (&own.0, &own.1), (&peer.0, &peer.1))?;
        self.state = SasState::MacSent;
        Ok(json!({"transaction_id": self.transaction_id, "mac": {key_id: mac}, "keys": keys}))
    }

    /// Validate the initiator's MACs against the queried keys.
    pub(crate) fn verify_peer_mac(&mut self, content: &Value, peer_keys: &Map<String, Value>) -> SasResult<()> {
        if self.state != SasState::MacSent {
            return Err("Unexpected SAS MAC event");
        }
        if content.get("transaction_id").and_then(Value::as_str) != Some(self.transaction_id.as_str()) {
            return Err("SAS MAC transaction does not match");
        }
        let macs = content
            .get("mac")
            .and_then(Value::as_object)
            .filter(|m| !m.is_empty())
            .ok_or("SAS MAC event contains no keys")?;
        if macs.len() > MAX_MAC_KEYS {
            return Err("SAS MAC event carries too many keys");
        }
        for (k, v) in macs {
            if k.is_empty() || k.chars().count() > MAX_FIELD_LEN || bounded_str(Some(v)).is_none() {
                return Err("SAS MAC event carries a malformed entry");
            }
        }
        if !macs.contains_key(&format!("ed25519:{}", self.peer_device)) {
            return Err("SAS MAC omits the peer device key");
        }
        let keys_mac = bounded_str(content.get("keys")).ok_or("SAS MAC event carries a malformed key list MAC")?;
        let mut ids: Vec<&String> = macs.keys().collect();
        ids.sort();
        let ids = ids.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",");
        let own = (self.own_user.clone(), self.own_device.clone());
        let peer = (self.peer_user.clone(), self.peer_device.clone());
        let expected = self.calculate_mac(&ids, "KEY_IDS", (&peer.0, &peer.1), (&own.0, &own.1))?;
        if !ct_eq(keys_mac, &expected) {
            return Err("SAS key list MAC does not match");
        }
        for (key_id, received) in macs {
            let pk = bounded_str(peer_keys.get(key_id)).ok_or("SAS MAC references an unknown key")?;
            let expected = self.calculate_mac(pk, key_id, (&peer.0, &peer.1), (&own.0, &own.1))?;
            if !ct_eq(received.as_str().unwrap_or(""), &expected) {
                return Err("SAS device key MAC does not match");
            }
        }
        self.state = SasState::Verified;
        Ok(())
    }
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn store_verified_binding(s: &Session) -> bool {
    match s.store.get("e2ee_device_binding").filter(has_value) {
        Some(b) => s.store.set("e2ee_verified_binding", b, CACHE_EXPIRY),
        None => false,
    }
}

/// Extend trust for the verified identity.
pub(in super::super) fn refresh_verified_state(s: &Session) -> bool {
    let Some(binding) = s.store.get("e2ee_device_binding").filter(has_value) else { return false };
    if s.store.get("e2ee_verified_binding").as_ref() != Some(&binding)
        || s.user_id.as_deref().is_none_or(str::is_empty)
        || s.device_id.as_deref().is_none_or(str::is_empty)
    {
        return false;
    }
    let Some(acct) = &s.e2ee.account else { return false };
    if binding.as_str() != Some(binding_key(s).as_str()) {
        return false;
    }
    let last =
        s.store.get("e2ee_autoverify_refreshed_at").and_then(|v| v.as_f64()).filter(|f| f.is_finite()).unwrap_or(0.0);
    if s.env.unix_time_f64() - last < REFRESH_INTERVAL {
        return true;
    }
    let ok = s.store.set("device_id", json!(s.device_id), CACHE_EXPIRY)
        && super::vault::set(s, "e2ee_account", acct.to_value())
        && s.store.set("e2ee_device_binding", binding.clone(), CACHE_EXPIRY)
        && s.store.set("e2ee_verified_binding", binding, CACHE_EXPIRY);
    if ok {
        s.store.set("e2ee_autoverify_refreshed_at", json!(s.env.unix_time_f64()), CACHE_EXPIRY);
    }
    ok
}

/// Complete one same-user SAS verification.
pub(in super::super) fn auto_verify(s: Session, k: K<bool>) -> Plan {
    let binding = s.store.get("e2ee_device_binding");
    if binding.as_ref().is_some_and(has_value) && s.store.get("e2ee_verified_binding") == binding {
        return k(s, true);
    }
    if s.user_id.as_deref().is_none_or(str::is_empty)
        || s.device_id.as_deref().is_none_or(str::is_empty)
        || s.e2ee.account.is_none()
    {
        return k(s, false);
    }
    if s.store.get("e2ee_autoverify_cooldown") == binding {
        return k(s, false);
    }
    log::info!("Matrix E2EE: waiting up to {} seconds for a same-user SAS verification request.", TIMEOUT.as_secs());
    let v = Verifier { deadline: Instant::now() + TIMEOUT, active: None };
    poll(
        s,
        v,
        None,
        Box::new(move |s, ok| {
            if !ok {
                s.store.set("e2ee_autoverify_cooldown", binding.unwrap_or(Value::Null), Some(RETRY_COOLDOWN));
            }
            k(s, ok)
        }),
    )
}

struct Active {
    transaction_id: String,
    user_id: String,
    device_id: String,
    peer_keys: Map<String, Value>,
    sas: Option<Sas>,
    peer_done: bool,
}

struct Verifier {
    deadline: Instant,
    active: Option<Active>,
}

/// Continuation receiving the verifier and a final outcome (`None`: keep polling).
type VK = Box<dyn FnOnce(Session, Verifier, Option<bool>) -> Plan + Send>;
/// Continuation receiving a request outcome.
type VB = Box<dyn FnOnce(Session, Verifier, bool) -> Plan + Send>;
/// Continuation receiving the peer's keys.
type VKeys = Box<dyn FnOnce(Session, Verifier, Option<Map<String, Value>>) -> Plan + Send>;

impl Verifier {
    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now()).min(TIMEOUT)
    }
}

fn bounded(v: &Verifier, f: Fetch, bound: Option<Duration>, best_effort: bool) -> Option<Fetch> {
    let remaining = v.remaining();
    if remaining.is_zero() && !best_effort {
        return None;
    }
    let bound = bound.unwrap_or(Duration::from_millis(POLL_MS));
    let t = bound.min(remaining) + Duration::from_secs(2);
    Some(f.timeout(t).retry_budget(remaining).bounded(MAX_RESPONSE_BYTES))
}

fn poll(s: Session, v: Verifier, since: Option<String>, k: K<bool>) -> Plan {
    if Instant::now() >= v.deadline {
        return fail(
            s,
            v,
            "m.timeout",
            "SAS verification timed out",
            Box::new(move |s, _, r| k(s, r.unwrap_or(false))),
        );
    }
    let remaining_ms = v.deadline.saturating_duration_since(Instant::now()).as_millis() as u64;
    let poll_ms = POLL_MS.min(remaining_ms);
    let mut f = Fetch::get("/sync")
        .param("timeout", poll_ms.to_string())
        .param("filter", sync_filter())
        .param("set_presence", "offline");
    if let Some(since) = &since {
        f = f.param("since", since.clone());
    }
    let Some(f) = bounded(&v, f, Some(Duration::from_millis(poll_ms)), false) else { return k(s, false) };
    s.fetch(f, move |s, r| {
        let Some(resp) = r.object() else { return k(s, false) };
        let Some(next) = resp.get("next_batch").and_then(Value::as_str).filter(|n| !n.is_empty()).map(str::to_owned)
        else {
            return k(s, false);
        };
        let events: Vec<Value> = resp
            .get("to_device")
            .and_then(Value::as_object)
            .and_then(|t| t.get("events"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        handle_events(
            s,
            v,
            events.into_iter(),
            Box::new(move |s, v, result| match result {
                Some(r) => k(s, r),
                None => poll(s, v, Some(next), k),
            }),
        )
    })
}

fn handle_events(s: Session, v: Verifier, mut events: std::vec::IntoIter<Value>, k: VK) -> Plan {
    let Some(event) = events.next() else { return k(s, v, None) };
    handle_event(
        s,
        v,
        event,
        Box::new(move |s, v, result| {
            if result.is_some() {
                return k(s, v, result);
            }
            if Instant::now() >= v.deadline {
                return k(s, v, None);
            }
            handle_events(s, v, events, k)
        }),
    )
}

fn handle_event(s: Session, mut v: Verifier, event: Value, k: VK) -> Plan {
    let Some(ev) = event.as_object() else { return k(s, v, None) };
    let etype = ev.get("type").and_then(Value::as_str).unwrap_or("").to_owned();
    let sender = ev.get("sender").and_then(Value::as_str).map(str::to_owned);
    let content = ev.get("content").cloned().unwrap_or_else(|| json!({}));
    if sender.is_none() || sender != s.user_id || !content.is_object() {
        return k(s, v, None);
    }
    let sender = sender.unwrap_or_default();
    if etype == EVENT_REQUEST {
        return handle_request(s, v, sender, content, k);
    }
    let txn = content.get("transaction_id").and_then(Value::as_str).map(str::to_owned);
    let Some(active) = v.active.as_ref() else { return k(s, v, None) };
    if txn.as_deref() != Some(active.transaction_id.as_str()) || sender != active.user_id {
        return k(s, v, None);
    }
    if etype == EVENT_CANCEL {
        crate::warning!(
            "Matrix E2EE SAS verification was cancelled: {}",
            content.get("reason").and_then(Value::as_str).filter(|r| !r.is_empty()).unwrap_or("unspecified reason")
        );
        return k(s, v, Some(false));
    }
    if etype == EVENT_START {
        return handle_start(s, v, sender, content, k);
    }
    if v.active.as_ref().is_some_and(|a| a.sas.is_none()) {
        return fail(s, v, "m.unexpected_message", "SAS verification has not started", k);
    }
    match etype.as_str() {
        EVENT_KEY => handle_key(s, v, sender, content, k),
        EVENT_MAC => {
            // `handle_event` returned early unless both are set.
            let Some(active) = v.active.as_mut() else { return k(s, v, None) };
            let peer_keys = active.peer_keys.clone();
            let Some(sas) = active.sas.as_mut() else { return k(s, v, None) };
            if sas.verify_peer_mac(&content, &peer_keys).is_err() {
                return fail(s, v, "m.key_mismatch", "SAS device key MAC did not match", k);
            }
            let (user, device, txn) = (active.user_id.clone(), active.device_id.clone(), active.transaction_id.clone());
            send_event(
                s,
                v,
                EVENT_DONE,
                &user,
                &device,
                json!({"transaction_id": txn}),
                false,
                Box::new(move |s, v, ok| {
                    if !ok {
                        return k(s, v, Some(false));
                    }
                    if v.active.as_ref().is_some_and(|a| a.peer_done) {
                        let r = store_verified_binding(&s);
                        return k(s, v, Some(r));
                    }
                    k(s, v, None)
                }),
            )
        }
        EVENT_DONE => {
            let Some(active) = v.active.as_mut() else { return k(s, v, None) };
            active.peer_done = true;
            if active.sas.as_ref().is_some_and(|x| x.state == SasState::Verified) {
                let r = store_verified_binding(&s);
                return k(s, v, Some(r));
            }
            k(s, v, None)
        }
        _ => k(s, v, None),
    }
}

fn handle_request(s: Session, v: Verifier, sender: String, content: Value, k: VK) -> Plan {
    let now = s.env.unix_time_ms() as i64;
    let ts = content
        .get("timestamp")
        .and_then(|t| if t.is_boolean() { Some(i64::from(t.as_bool() == Some(true))) } else { t.as_i64() });
    let txn = valid_id(content.get("transaction_id"));
    let from_device = valid_id(content.get("from_device"));
    let methods_ok =
        content.get("methods").and_then(Value::as_array).is_some_and(|m| m.iter().any(|x| x.as_str() == Some(METHOD)));
    let (Some(ts), Some(txn), Some(from_device), true) = (ts, txn, from_device, methods_ok) else {
        return k(s, v, None);
    };
    if ts < now - REQUEST_MAX_PAST_MS || ts > now + REQUEST_MAX_FUTURE_MS {
        return k(s, v, None);
    }
    if let Some(active) = &v.active {
        let same_device = sender == active.user_id && from_device == active.device_id;
        if same_device && txn == active.transaction_id {
            return k(s, v, None);
        }
        let reject = move |s: Session, v: Verifier| {
            send_event(
                s,
                v,
                EVENT_CANCEL,
                &sender,
                &from_device,
                json!({"transaction_id": txn, "code": "m.unexpected_message", "reason": "Another verification is already active"}),
                false,
                Box::new(move |s, v, _| k(s, v, None)),
            )
        };
        if same_device {
            return cancel(
                s,
                v,
                "m.unexpected_message",
                "A newer verification request superseded this one",
                Box::new(move |s, mut v, _| {
                    v.active = None;
                    reject(s, v)
                }),
            );
        }
        return reject(s, v);
    }
    peer_keys(
        s,
        v,
        sender.clone(),
        from_device.clone(),
        Box::new(move |s, mut v, keys| {
            let Some(keys) = keys.filter(|k| !k.is_empty()) else { return k(s, v, Some(false)) };
            v.active = Some(Active {
                transaction_id: txn.clone(),
                user_id: sender.clone(),
                device_id: from_device.clone(),
                peer_keys: keys,
                sas: None,
                peer_done: false,
            });
            let own_device = s.device_id.clone().unwrap_or_default();
            send_event(
                s,
                v,
                EVENT_READY,
                &sender,
                &from_device,
                json!({"transaction_id": txn, "from_device": own_device, "methods": [METHOD]}),
                false,
                Box::new(move |s, v, ok| k(s, v, if ok { None } else { Some(false) })),
            )
        }),
    )
}

fn handle_start(s: Session, mut v: Verifier, sender: String, content: Value, k: VK) -> Plan {
    let Some(active) = v.active.as_mut() else { return k(s, v, None) };
    if active.sas.is_some() {
        return fail(s, v, "m.unexpected_message", "SAS verification was already started", k);
    }
    let own_user = s.user_id.clone().unwrap_or_default();
    let own_device = s.device_id.clone().unwrap_or_default();
    let made = Sas::new(&own_user, &own_device, &sender, &active.device_id, &content, s.env.as_ref())
        .and_then(|mut sas| sas.accept_content().map(|a| (sas, a)));
    let Ok((sas, accept)) = made else {
        return fail(s, v, "m.unknown_method", "Unsupported SAS verification parameters", k);
    };
    active.sas = Some(sas);
    let device = active.device_id.clone();
    send_event(
        s,
        v,
        EVENT_ACCEPT,
        &sender,
        &device,
        accept,
        false,
        Box::new(move |s, v, ok| k(s, v, if ok { None } else { Some(false) })),
    )
}

fn handle_key(s: Session, mut v: Verifier, sender: String, content: Value, k: VK) -> Plan {
    let signing = s.e2ee.account.as_ref().map(|a| a.signing_key()).unwrap_or_default();
    // `handle_event` only calls this with an active, started verification.
    let Some(active) = v.active.as_mut() else { return k(s, v, None) };
    let Some(sas) = active.sas.as_mut() else { return k(s, v, None) };
    let key = content.get("key").filter(|x| has_value(x)).cloned().unwrap_or_else(|| json!(""));
    let steps = sas.receive_key(&key).and_then(|()| {
        let code = sas.decimal_sas()?;
        let key_content = sas.key_content()?;
        let mac_content = sas.mac_content(&signing)?;
        Ok((code, key_content, mac_content))
    });
    let Ok((code, key_content, mac_content)) = steps else {
        return fail(s, v, "m.invalid_message", "Invalid SAS public key", k);
    };
    log::info!("Matrix E2EE SAS code (compare against your other device): {}-{}-{}", code.0, code.1, code.2);
    let device = active.device_id.clone();
    let device2 = device.clone();
    let sender2 = sender.clone();
    send_event(
        s,
        v,
        EVENT_KEY,
        &sender,
        &device,
        key_content,
        false,
        Box::new(move |s, v, ok| {
            if !ok {
                return k(s, v, Some(false));
            }
            send_event(
                s,
                v,
                EVENT_MAC,
                &sender2,
                &device2,
                mac_content,
                false,
                Box::new(move |s, v, ok| k(s, v, if ok { None } else { Some(false) })),
            )
        }),
    )
}

/// One unencrypted to-device event.
#[expect(clippy::too_many_arguments, reason = "one parameter per event field")]
fn send_event(
    s: Session,
    v: Verifier,
    event_type: &str,
    user_id: &str,
    device_id: &str,
    content: Value,
    best_effort: bool,
    k: VB,
) -> Plan {
    let path = format!("/sendToDevice/{event_type}/{}", s.env.uuid4().replace('-', ""));
    let f = Fetch::put(path, json!({"messages": {user_id: {device_id: content}}}));
    let Some(f) = bounded(&v, f, None, best_effort) else { return k(s, v, false) };
    s.fetch(f, move |s, r| k(s, v, r.ok))
}

/// Best-effort cancellation of the active transaction.
fn cancel(s: Session, v: Verifier, code: &str, reason: &str, k: VB) -> Plan {
    let Some(active) = &v.active else { return k(s, v, false) };
    let (user, device, txn) = (active.user_id.clone(), active.device_id.clone(), active.transaction_id.clone());
    send_event(
        s,
        v,
        EVENT_CANCEL,
        &user,
        &device,
        json!({"transaction_id": txn, "code": code, "reason": reason}),
        true,
        k,
    )
}

/// Cancel (if active) and report failure.
fn fail(s: Session, v: Verifier, code: &str, reason: &str, k: VK) -> Plan {
    cancel(s, v, code, reason, Box::new(move |s, v, _| k(s, v, Some(false))))
}

/// Validated device keys plus advertised master keys.
fn peer_keys(s: Session, v: Verifier, user_id: String, device_id: String, k: VKeys) -> Plan {
    let f = Fetch::post("/keys/query", json!({"device_keys": {user_id.clone(): [device_id]}}));
    let Some(f) = bounded(&v, f, None, false) else { return k(s, v, None) };
    s.fetch(f, move |s, r| {
        let Some(resp) = r.object() else { return k(s, v, None) };
        let device = resp.get("device_keys").and_then(|d| d.get(&user_id)).and_then(|u| u.get(&device_id));
        let Some(device) = device.filter(|d| verify_device_keys(d, &user_id, &device_id)) else { return k(s, v, None) };
        let mut keys = device
            .get("keys")
            .and_then(Value::as_object)
            .filter(|m| m.len() <= MAX_DEVICE_KEYS)
            .cloned()
            .unwrap_or_default();
        if let Some(master) = resp
            .get("master_keys")
            .and_then(|m| m.get(&user_id))
            .and_then(|m| m.get("keys"))
            .and_then(Value::as_object)
            .filter(|m| m.len() <= MAX_DEVICE_KEYS)
        {
            keys.extend(master.clone());
        }
        k(s, v, Some(keys))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(peer_device: &str) -> Value {
        json!({
            "from_device": peer_device,
            "transaction_id": "sas-transaction",
            "method": "m.sas.v1",
            "key_agreement_protocols": ["curve25519-hkdf-sha256"],
            "hashes": ["sha256"],
            "message_authentication_codes": ["hkdf-hmac-sha256.v2"],
            "short_authentication_string": ["decimal", "emoji"],
        })
    }

    /// The responder interoperates with an initiator built from the spec.
    #[test]
    fn responder_roundtrip() {
        let (user, own_dev, peer_dev, txn) = ("@u:h", "MERCURIO", "ELEMENT", "sas-transaction");
        let st = start(peer_dev);
        let mut sas = Sas::new(user, own_dev, user, peer_dev, &st, crate::testing::test_env()).unwrap();
        let accept = sas.accept_content().unwrap();
        let mut data = sas.public_key.as_bytes().to_vec();
        data.extend_from_slice(canonical_json(&st).as_bytes());
        assert_eq!(accept["commitment"], b64enc(&sha256(&data)));
        assert_eq!(accept["short_authentication_string"], json!(["decimal"]));
        assert!(sas.accept_content().is_err(), "accept twice");

        let peer = XKey::generate(crate::testing::test_env());
        sas.receive_key(&json!(b64enc(&peer.public()))).unwrap();
        assert_eq!(sas.key_content().unwrap()["key"], sas.public_key);
        let shared = peer.exchange(&b64dec(&sas.public_key).unwrap()).unwrap();

        // Both sides derive the same decimal code.
        let info = format!(
            "MATRIX_KEY_VERIFICATION_SAS|{user}|{peer_dev}|{}|{user}|{own_dev}|{}|{txn}",
            b64enc(&peer.public()),
            sas.public_key
        );
        let b: [u8; 5] = hkdf_sha256(&shared, 5, None, info.as_bytes()).as_slice().try_into().unwrap();
        assert_eq!(sas.decimal_sas().unwrap(), decimal_from_bytes(&b));

        let peer_mac = |value: &str, key_id: &str| {
            let info = format!("MATRIX_KEY_VERIFICATION_MAC{user}{peer_dev}{user}{own_dev}{txn}{key_id}");
            b64enc(&hmac_sha256(&hkdf_sha256(&shared, 32, None, info.as_bytes()), value.as_bytes()))
        };
        let own = super::super::OlmAccount::new(crate::testing::test_env());
        let mac = sas.mac_content(&own.signing_key()).unwrap();
        assert!(mac["mac"].get("ed25519:MERCURIO").is_some());
        // Our MAC verifies with the peer-side derivation (sender = us).
        let info = format!("MATRIX_KEY_VERIFICATION_MAC{user}{own_dev}{user}{peer_dev}{txn}ed25519:MERCURIO");
        let expect =
            b64enc(&hmac_sha256(&hkdf_sha256(&shared, 32, None, info.as_bytes()), own.signing_key().as_bytes()));
        assert_eq!(mac["mac"]["ed25519:MERCURIO"], expect);

        let peer_acct = super::super::OlmAccount::new(crate::testing::test_env());
        let kid = format!("ed25519:{peer_dev}");
        let content = json!({
            "transaction_id": txn,
            "mac": {kid.clone(): peer_mac(&peer_acct.signing_key(), &kid)},
            "keys": peer_mac(&kid, "KEY_IDS"),
        });
        let keys: Map<String, Value> = [(kid, json!(peer_acct.signing_key()))].into_iter().collect();
        let mut tampered = content.clone();
        tampered["keys"] = json!("invalid");
        assert_eq!(sas.verify_peer_mac(&tampered, &keys), Err("SAS key list MAC does not match"));
        sas.verify_peer_mac(&content, &keys).unwrap();
        assert_eq!(sas.state, SasState::Verified);
    }

    #[test]
    fn decimal_vectors() {
        assert_eq!(decimal_from_bytes(&[0xff; 5]), (9191, 9191, 9191));
        assert_eq!(decimal_from_bytes(&[0; 5]), (1000, 1000, 1000));
        let b = [0u8, 1, 0, 0, 0];
        let expected = (
            ((u16::from(b[0]) << 5) | (u16::from(b[1]) >> 3)) + 1000,
            (((u16::from(b[1]) & 7) << 10) | (u16::from(b[2]) << 2) | (u16::from(b[3]) >> 6)) + 1000,
            (((u16::from(b[3]) & 0x3f) << 7) | (u16::from(b[4]) >> 1)) + 1000,
        );
        assert_eq!(decimal_from_bytes(&b), expected);
    }

    #[test]
    fn start_validation() {
        let ok = start("ELEMENT");
        assert!(Sas::new("@u:h", "A", "@u:h", "ELEMENT", &ok, crate::testing::test_env()).is_ok());
        assert!(Sas::new("@u:h", "A", "@u:h", "", &ok, crate::testing::test_env()).is_err());
        assert!(Sas::new("@u:h", "A", "@u:h", "OTHER", &ok, crate::testing::test_env()).is_err());
        for (field, bad) in [
            ("method", json!("m.reciprocate.v1")),
            ("key_agreement_protocols", json!(["curve25519"])),
            ("hashes", json!(["sha512"])),
            ("message_authentication_codes", json!(["hkdf-hmac-sha256"])),
            ("short_authentication_string", json!(["emoji"])),
            ("transaction_id", json!("")),
        ] {
            let mut st = ok.clone();
            st[field] = bad;
            assert!(Sas::new("@u:h", "A", "@u:h", "ELEMENT", &st, crate::testing::test_env()).is_err(), "{field}");
        }
    }

    #[test]
    fn state_guards_and_limits() {
        let mut sas = Sas::new("@u:h", "A", "@u:h", "ELEMENT", &start("ELEMENT"), crate::testing::test_env()).unwrap();
        assert!(sas.receive_key(&json!("x")).is_err(), "key before accept");
        assert!(sas.key_content().is_err());
        assert!(sas.decimal_sas().is_err());
        assert!(sas.mac_content("k").is_err());
        sas.accept_content().unwrap();
        assert!(sas.receive_key(&json!("")).is_err());
        assert!(sas.receive_key(&json!("A".repeat(600))).is_err());
        assert!(sas.receive_key(&json!(b64enc(&[0u8; 32]))).is_err(), "low-order key");
        let peer = XKey::generate(crate::testing::test_env());
        sas.receive_key(&json!(b64enc(&peer.public()))).unwrap();
        sas.mac_content("k").unwrap();
        let too_many: Map<String, Value> = (0..11).map(|i| (format!("ed25519:{i}"), json!("m"))).collect();
        let c = json!({"transaction_id": "sas-transaction", "mac": too_many, "keys": "x"});
        assert_eq!(sas.verify_peer_mac(&c, &Map::new()), Err("SAS MAC event carries too many keys"));
        let c = json!({"transaction_id": "sas-transaction", "mac": {"ed25519:OTHER": "m"}, "keys": "x"});
        assert_eq!(sas.verify_peer_mac(&c, &Map::new()), Err("SAS MAC omits the peer device key"));
        let c = json!({"transaction_id": "other", "mac": {"ed25519:ELEMENT": "m"}, "keys": "x"});
        assert!(sas.verify_peer_mac(&c, &Map::new()).is_err());
        assert_eq!(
            sync_filter(),
            r#"{"presence": {"types": []}, "account_data": {"types": []}, "room": {"rooms": []}}"#
        );
    }
}
