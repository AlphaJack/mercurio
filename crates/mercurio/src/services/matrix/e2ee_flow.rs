//! E2EE delivery steps: key upload, encrypted-room detection, Megolm sessions, room members, room-key sharing, encrypted events and encrypted attachments.
//!
//! Device trust is trust on first use: a device gets room keys when its self-signature verifies and its keys match the ones pinned the first time it was seen ([`Pins`]).

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::{Map, Value, json};

use super::e2ee::{MEGOLM_ALGORITHM, MegolmSession, OLM_ALGORITHM, OlmAccount, verify_device_keys, verify_signed_otk};
use super::server::{CACHE_EXPIRY, Fetch, K, Session, has_value, quote_path};
use super::sizing::{MATRIX_EVENT_BYTE_LIMIT, MATRIX_EVENT_SAFETY_MARGIN};
use crate::Plan;
use crate::error::Error;
use crate::http::Request;

/// E2EE state of one send.
#[derive(Debug, Default)]
pub(super) struct E2ee {
    pub account: Option<OlmAccount>,
    /// Setup succeeded; encryption is still decided per room.
    pub capable: bool,
    /// Why setup failed: encrypted rooms fail with it (never plaintext).
    pub setup_error: Option<Error>,
}

/// How long a room's "not encrypted" answer is trusted: encryption can be enabled at any time, but never disabled, so "encrypted" is kept longer.
pub(super) const UNENCRYPTED_TTL: Option<Duration> = Some(Duration::from_secs(300));
/// Store value of a room known to have no `m.room.encryption` state.
const UNENCRYPTED: &str = "unencrypted";

/// How long the joined members and their device keys are reused before they are queried again: joins and leaves are noticed within this time.
pub(super) const MEMBERS_TTL: Option<Duration> = Some(Duration::from_secs(300));

/// Devices of the joined members: user -> device -> (curve25519, ed25519).
type Members = BTreeMap<String, BTreeMap<String, (String, String)>>;

/// User -> device -> curve25519 key.
type DeviceSet = BTreeMap<String, BTreeMap<String, String>>;

/// Who holds the key of a room's current outbound Megolm session.
#[derive(Debug, Default)]
struct Shared {
    /// Devices that received it.
    devices: DeviceSet,
    /// Devices that could not get it (no one-time key); retried on the next fresh member query.
    skipped: DeviceSet,
}

fn shared_key(room_id: &str) -> String {
    format!("e2ee_key_shared_{room_id}")
}

fn device_set(v: Option<&Value>) -> DeviceSet {
    v.and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default()
}

fn holds<'a>(set: &'a DeviceSet, user: &str, device: &str) -> Option<&'a String> {
    set.get(user).and_then(|d| d.get(device))
}

impl Shared {
    /// The record of `session_id`; `None` when there is none for it (an older store format or another session).
    fn load(s: &Session, room_id: &str, session_id: &str) -> Option<Self> {
        let v = s.store.get(&shared_key(room_id))?;
        if v.get("session_id").and_then(Value::as_str) != Some(session_id) {
            return None;
        }
        Some(Shared { devices: device_set(v.get("devices")), skipped: device_set(v.get("skipped")) })
    }

    fn save(&self, s: &Session, room_id: &str, session_id: &str) {
        let v = json!({"session_id": session_id, "devices": self.devices, "skipped": self.skipped});
        s.store.set(&shared_key(room_id), v, CACHE_EXPIRY);
    }

    /// A device that holds the key is gone or presents another key.
    fn someone_left(&self, current: &Members) -> bool {
        self.devices.iter().any(|(u, devs)| {
            devs.iter().any(|(d, ck)| current.get(u).and_then(|m| m.get(d)).map(|(c, _)| c) != Some(ck))
        })
    }
}

fn merge(into: &mut DeviceSet, from: DeviceSet) {
    for (u, devs) in from {
        into.entry(u).or_default().extend(devs);
    }
}

pub(super) fn restore(s: &mut Session) {
    if s.cfg.e2ee
        && let Some(v) = s.store.get("e2ee_account").filter(has_value)
    {
        s.e2ee.account = OlmAccount::from_value(&v).ok();
    }
}

pub(super) fn binding_key(s: &Session) -> String {
    match &s.e2ee.account {
        None => String::new(),
        Some(a) => format!(
            "{}|{}|{}|{}",
            s.user_id.as_deref().unwrap_or(""),
            s.device_id.as_deref().unwrap_or(""),
            a.identity_key(),
            a.signing_key()
        ),
    }
}

/// E2EE setup, plus the optional automatic verification.
pub(super) fn setup(mut s: Session, k: K<()>) -> Plan {
    if s.e2ee.account.is_none() {
        s.e2ee.account = s.store.get("e2ee_account").filter(has_value).and_then(|v| OlmAccount::from_value(&v).ok());
        if s.e2ee.account.is_none() {
            let acct = OlmAccount::new();
            s.store.set("e2ee_account", acct.to_value(), CACHE_EXPIRY);
            s.e2ee.account = Some(acct);
        }
    }
    if s.store.get("e2ee_device_binding") != Some(json!(binding_key(&s))) {
        s.store.clear(&["e2ee_keys_uploaded"]);
    }
    let after = move |mut s: Session, ok: bool| -> Plan {
        s.e2ee.capable = ok;
        if !ok {
            log::warn!("Matrix E2EE setup failed; encrypted rooms will not receive the message.");
            if s.e2ee.setup_error.is_none() {
                s.e2ee.setup_error = Some(Error::Service("Matrix E2EE setup failed".into()));
            }
            return k(s, ());
        }
        if s.cfg.autoverify {
            return super::sas::auto_verify(
                s,
                Box::new(move |s, verified| {
                    if !verified {
                        log::warn!(
                            "Matrix E2EE automatic device verification did not complete; continuing without \
                             confirming device trust."
                        );
                    }
                    k(s, ())
                }),
            );
        }
        k(s, ())
    };
    if !s.store.get("e2ee_keys_uploaded").is_some_and(|v| has_value(&v)) {
        return upload_keys(s, Box::new(after));
    }
    after(s, true)
}

/// Upload the device keys and a fallback key (no one-time keys).
fn upload_keys(mut s: Session, k: K<bool>) -> Plan {
    let (Some(user_id), Some(device_id)) =
        (s.user_id.clone().filter(|u| !u.is_empty()), s.device_id.clone().filter(|d| !d.is_empty()))
    else {
        log::warn!("Matrix E2EE: cannot upload keys without user_id and device_id; ensure login completes first.");
        return k(s, false);
    };
    let Some(acct) = s.e2ee.account.as_mut() else { return k(s, false) };
    let payload = json!({
        "device_keys": acct.device_keys_payload(&user_id, &device_id),
        "fallback_keys": acct.fallback_keys_payload(&user_id, &device_id),
    });
    s.fetch(Fetch::post("/keys/upload", payload), move |mut s, r| {
        if !r.ok {
            log::warn!("Matrix E2EE: device key upload failed.");
            s.e2ee.setup_error = Some(r.error("Matrix E2EE device key upload failed").context("key upload"));
            return k(s, false);
        }
        if let Some(a) = &s.e2ee.account {
            s.store.set("e2ee_account", a.to_value(), CACHE_EXPIRY);
        }
        s.store.set("e2ee_keys_uploaded", json!(true), CACHE_EXPIRY);
        s.store.set("e2ee_device_binding", json!(binding_key(&s)), CACHE_EXPIRY);
        k(s, true)
    })
}

/// `Ok` only for a definitive answer (200: the room has an `m.room.encryption` state event, even an empty/redacted one; 404 `M_NOT_FOUND`: it has none). Any other answer is an error and is never cached. It fails the room rather than downgrading to plaintext.
pub(super) fn room_encrypted(s: Session, room_id: String, k: K<Result<bool, Error>>) -> Plan {
    let cache_key = format!("e2ee_room_enc_{room_id}");
    match s.store.get(&cache_key) {
        Some(Value::Bool(true)) => return k(s, Ok(true)),
        Some(Value::String(v)) if v == UNENCRYPTED => return k(s, Ok(false)),
        _ => {}
    }
    let f = Fetch::get(format!("/rooms/{}/state/m.room.encryption", quote_path(&room_id))).ok_status(&[404]);
    s.fetch(f, move |s, r| {
        if r.ok {
            s.store.set(&cache_key, json!(true), CACHE_EXPIRY);
            return k(s, Ok(true));
        }
        let not_found = r.json.get("errcode").and_then(Value::as_str) == Some("M_NOT_FOUND");
        if r.transport.is_none() && r.status == 404 && not_found {
            s.store.set(&cache_key, json!(UNENCRYPTED), UNENCRYPTED_TTL);
            return k(s, Ok(false));
        }
        log::warn!(
            "Matrix E2EE: could not read the encryption state of room {room_id} (error={}); not sending to it.",
            r.status
        );
        let e = r.error("could not read the room's encryption state").context("encryption state");
        k(s, Err(e))
    })
}

/// The outbound session, rotated when due; `true` when it was just created (nobody holds its key yet).
fn get_megolm(s: &Session, room_id: &str) -> (MegolmSession, bool) {
    let key = format!("e2ee_megolm_{room_id}");
    if let Some(v) = s.store.get(&key).filter(has_value)
        && let Ok(sess) = MegolmSession::from_value(&v)
        && !sess.should_rotate()
    {
        return (sess, false);
    }
    (new_megolm(s, room_id), true)
}

fn new_megolm(s: &Session, room_id: &str) -> MegolmSession {
    let sess = MegolmSession::new();
    s.store.set(&format!("e2ee_megolm_{room_id}"), sess.to_value(), CACHE_EXPIRY);
    s.store.clear(&[&shared_key(room_id)]);
    sess
}

fn save_megolm(s: &Session, room_id: &str, sess: &MegolmSession) {
    s.store.set(&format!("e2ee_megolm_{room_id}"), sess.to_value(), CACHE_EXPIRY);
}

/// Encrypted delivery to one room: message, then attachments.
pub(super) fn deliver_encrypted(s: Session, label: String, room_id: String) -> Plan {
    send_to_room(
        s,
        room_id.clone(),
        Box::new(move |mut s, (session, failed)| {
            if let Some(step) = failed {
                s.fail_target_with(label, Error::Service("encrypted message not sent".into()).context(step));
                return s.next_room();
            }
            if s.msg.attachments.is_empty() {
                s.ok_target(label);
                return s.next_room();
            }
            // The same session as the message: its holders are known.
            let Some(session) = session else {
                s.fail_target_with(label, Error::Service("encrypted message not sent".into()).context("send"));
                return s.next_room();
            };
            send_attachments(s, label, room_id, session, 0, None)
        }),
    )
}

fn send_attachments(
    mut s: Session,
    label: String,
    room_id: String,
    session: MegolmSession,
    idx: usize,
    target_error: Option<&'static str>,
) -> Plan {
    if idx >= s.msg.attachments.len() {
        if let Some(step) = target_error {
            s.fail_target_with(label, Error::Service("encrypted attachment post failed".into()).context(step));
        } else {
            s.ok_target(label);
        }
        return s.next_room();
    }
    send_attachment(
        s,
        room_id.clone(),
        session,
        idx,
        Box::new(move |s, (session, failed)| {
            send_attachments(s, label, room_id, session, idx + 1, target_error.or(failed))
        }),
    )
}

/// The devices that should hold the room key: every verified device of the joined members except this one.
fn recipients(s: &Session, members: &Members) -> Members {
    let is_me = |u: &str, d: &str| Some(u) == s.user_id.as_deref() && Some(d) == s.device_id.as_deref();
    members
        .iter()
        .map(|(u, devs)| {
            let devs = devs
                .iter()
                .filter(|(d, (ck, _))| !ck.is_empty() && !is_me(u, d))
                .map(|(d, v)| (d.clone(), v.clone()))
                .collect();
            (u.clone(), devs)
        })
        .collect()
}

/// Share the room key with devices that lack it (rotating the session first when a holder left), then send. `k` gets the step that failed, or `None` once the message is sent.
fn send_to_room(s: Session, room_id: String, k: K<(Option<MegolmSession>, Option<&'static str>)>) -> Plan {
    let rid = room_id.clone();
    room_members(
        s,
        &rid,
        Box::new(move |s, members| {
            let (members, fresh) = match members {
                Ok(m) => m,
                Err(step) => {
                    log::warn!("Matrix E2EE: failed to query room members for {room_id}.");
                    return k(s, (None, Some(step)));
                }
            };
            let current = recipients(&s, &members);
            let (mut session, created) = get_megolm(&s, &room_id);
            let known = if created { Some(Shared::default()) } else { Shared::load(&s, &room_id, &session.session_id) };
            let mut shared = match known {
                Some(sh) if !sh.someone_left(&current) => sh,
                _ => {
                    log::info!(
                        "Matrix E2EE: a device left room {room_id} or changed keys; rotating the Megolm session."
                    );
                    session = new_megolm(&s, &room_id);
                    Shared::default()
                }
            };
            if fresh {
                shared.skipped.clear();
            }
            let pending: Members = current
                .into_iter()
                .map(|(u, devs)| {
                    let devs = devs
                        .into_iter()
                        .filter(|(d, (ck, _))| {
                            holds(&shared.devices, &u, d) != Some(ck) && holds(&shared.skipped, &u, d).is_none()
                        })
                        .collect();
                    (u, devs)
                })
                .collect();
            if pending.values().all(BTreeMap::is_empty) {
                shared.save(&s, &room_id, &session.session_id);
                return encrypt_and_send(s, room_id, session, k);
            }
            share_room_key(
                s,
                room_id.clone(),
                session,
                pending,
                Box::new(move |s, (session, outcome)| {
                    let (sent, skipped) = match outcome {
                        Ok(o) => o,
                        Err(step) => return k(s, (None, Some(step))),
                    };
                    merge(&mut shared.devices, sent);
                    merge(&mut shared.skipped, skipped);
                    shared.save(&s, &room_id, &session.session_id);
                    encrypt_and_send(s, room_id, session, k)
                }),
            )
        }),
    )
}

fn envelope(s: &Session, session: &MegolmSession, ciphertext: String) -> Value {
    json!({
        "algorithm": MEGOLM_ALGORITHM,
        "ciphertext": ciphertext,
        "sender_key": s.e2ee.account.as_ref().map(OlmAccount::identity_key).unwrap_or_default(),
        "session_id": session.session_id,
        "device_id": s.device_id.clone().unwrap_or_default(),
    })
}

fn encrypt_and_send(
    s: Session,
    room_id: String,
    mut session: MegolmSession,
    k: K<(Option<MegolmSession>, Option<&'static str>)>,
) -> Plan {
    let content = super::message_content(&s.cfg, &s.msg);
    let inner = json!({"type": "m.room.message", "content": content, "room_id": room_id});
    let ct = session.encrypt(&inner);
    save_megolm(&s, &room_id, &session);
    let payload = envelope(&s, &session, ct);
    let size = payload.to_string().len();
    let budget = MATRIX_EVENT_BYTE_LIMIT - MATRIX_EVENT_SAFETY_MARGIN;
    if size > budget {
        log::warn!(
            "Matrix E2EE: encrypted event for room {room_id} is {size} bytes, over the safe {budget}-byte budget; \
             message not sent."
        );
        return k(s, (Some(session), Some("send")));
    }
    let path = format!("/rooms/{}/send/m.room.encrypted/{}", quote_path(&room_id), s.txn);
    s.fetch(Fetch::put(path, payload), move |mut s, r| {
        s.bump_txn();
        k(s, (Some(session), (!r.ok).then_some("send")))
    })
}

/// Verified device keys of every joined member, reused for [`MEMBERS_TTL`]; `true` when just queried. `Err` names the failed step.
fn room_members(s: Session, room_id: &str, k: K<Result<(Members, bool), &'static str>>) -> Plan {
    let cache_key = format!("e2ee_members_{room_id}");
    if let Some(m) = s.store.get(&cache_key).and_then(|v| serde_json::from_value::<Members>(v).ok()) {
        return k(s, Ok((m, false)));
    }
    let path = format!("/rooms/{}/joined_members", quote_path(room_id));
    s.fetch(Fetch::get(path), move |s, r| {
        let Some(resp) = r.object() else { return k(s, Err("member lookup")) };
        let ids: Vec<String> =
            resp.get("joined").and_then(Value::as_object).map(|m| m.keys().cloned().collect()).unwrap_or_default();
        if ids.is_empty() {
            s.store.set(&cache_key, json!({}), MEMBERS_TTL);
            return k(s, Ok((Members::new(), true)));
        }
        let query: Map<String, Value> = ids.into_iter().map(|u| (u, json!([]))).collect();
        s.fetch(Fetch::post("/keys/query", json!({"device_keys": query})), move |s, r| {
            let Some(resp) = r.object() else { return k(s, Err("key query")) };
            let mut out = Members::new();
            if let Some(dk) = resp.get("device_keys").and_then(Value::as_object) {
                for (uid, devices) in dk {
                    let entry = out.entry(uid.clone()).or_default();
                    let Some(devices) = devices.as_object() else { continue };
                    let mut pins = Pins::load(&s, uid);
                    for (dev_id, info) in devices {
                        if !verify_device_keys(info, uid, dev_id) {
                            log::debug!(
                                "Matrix E2EE: device key signature invalid for {uid} / {dev_id}; device skipped."
                            );
                            continue;
                        }
                        let keys = info.get("keys");
                        let key = |alg: &str| {
                            keys.and_then(|k| k.get(format!("{alg}:{dev_id}")))
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string()
                        };
                        let (curve, ed) = (key("curve25519"), key("ed25519"));
                        let is_me = Some(uid.as_str()) == s.user_id.as_deref()
                            && Some(dev_id.as_str()) == s.device_id.as_deref();
                        if !is_me && !pins.check(uid, dev_id, &curve, &ed) {
                            continue;
                        }
                        entry.insert(dev_id.clone(), (curve, ed));
                    }
                    pins.save(&s, uid);
                }
            }
            s.store.set(&cache_key, json!(out), MEMBERS_TTL);
            k(s, Ok((out, true)))
        })
    })
}

/// Trust on first use: the keys each device of a user presented when first seen (`device -> {"curve25519", "ed25519"}`), kept without expiry.
struct Pins {
    devices: Map<String, Value>,
    changed: bool,
}

impl Pins {
    fn key(user: &str) -> String {
        format!("e2ee_pin_{user}")
    }

    fn load(s: &Session, user: &str) -> Self {
        let devices = match s.store.get(&Self::key(user)) {
            Some(Value::Object(m)) => m,
            _ => Map::new(),
        };
        Pins { devices, changed: false }
    }

    /// `true` when the device may get room keys: first seen (now pinned) or presenting its pinned keys.
    fn check(&mut self, user: &str, device: &str, curve: &str, ed: &str) -> bool {
        match self.devices.get(device) {
            Some(p)
                if p.get("curve25519").and_then(Value::as_str) == Some(curve)
                    && p.get("ed25519").and_then(Value::as_str) == Some(ed) =>
            {
                true
            }
            Some(_) => {
                log::warn!(
                    "Matrix E2EE: device {user} / {device} presents keys that differ from the ones first seen; \
                     not sharing room keys with it."
                );
                false
            }
            None => {
                self.devices.insert(device.to_string(), json!({"curve25519": curve, "ed25519": ed}));
                self.changed = true;
                true
            }
        }
    }

    fn save(&self, s: &Session, user: &str) {
        if self.changed {
            s.store.set(&Self::key(user), Value::Object(self.devices.clone()), None);
        }
    }
}

/// What a key share achieved: devices that got the key, devices that could not (no usable one-time key); `Err` names the request that failed.
type ShareOutcome = Result<(DeviceSet, DeviceSet), &'static str>;

/// Send the Megolm key to the `pending` devices over Olm.
fn share_room_key(
    s: Session,
    room_id: String,
    session: MegolmSession,
    pending: Members,
    k: K<(MegolmSession, ShareOutcome)>,
) -> Plan {
    let request: Map<String, Value> = pending
        .iter()
        .map(|(uid, devs)| {
            (uid.clone(), Value::Object(devs.keys().map(|d| (d.clone(), json!("signed_curve25519"))).collect()))
        })
        .collect();
    s.fetch(Fetch::post("/keys/claim", json!({"one_time_keys": request})), move |mut s, r| {
        if !r.ok {
            log::warn!("Matrix E2EE: failed to claim one-time keys.");
            return k(s, (session, Err("key claim")));
        }
        let (messages, sent, skipped) = build_key_shares(&s, &room_id, &session, &pending, &r.json);
        if sent.values().all(BTreeMap::is_empty) {
            return k(s, (session, Ok((sent, skipped))));
        }
        s.bump_txn();
        let path = format!("/sendToDevice/m.room.encrypted/{}", s.txn);
        s.fetch(Fetch::put(path, json!({"messages": messages})), move |s, r| {
            if !r.ok {
                log::warn!("Matrix E2EE: failed to deliver room key to devices in {room_id}.");
                return k(s, (session, Err("key share")));
            }
            k(s, (session, Ok((sent, skipped))))
        })
    })
}

/// The Olm-encrypted `m.room_key` to-device messages, the devices they go to and the devices left out (no usable one-time key).
fn build_key_shares(
    s: &Session,
    room_id: &str,
    session: &MegolmSession,
    members: &Members,
    claim: &Value,
) -> (Map<String, Value>, DeviceSet, DeviceSet) {
    let mut sent = DeviceSet::new();
    let mut skipped = DeviceSet::new();
    let Some(acct) = s.e2ee.account.as_ref() else { return (Map::new(), sent, skipped) };
    let otks = claim.get("one_time_keys").and_then(Value::as_object);
    let room_key = json!({
        "algorithm": MEGOLM_ALGORITHM,
        "room_id": room_id,
        "session_id": session.session_id,
        "session_key": session.session_key(),
    });
    let mut out = Map::new();
    let mut no_otk = 0usize;
    for (uid, devices) in members {
        let mut per_user = Map::new();
        for (dev_id, (their_ik, ed25519)) in devices {
            if Some(uid.as_str()) == s.user_id.as_deref() && Some(dev_id.as_str()) == s.device_id.as_deref() {
                continue;
            }
            if their_ik.is_empty() {
                continue;
            }
            let mut their_otk: Option<String> = None;
            if let Some(entry) = otks.and_then(|o| o.get(uid)).and_then(|u| u.get(dev_id)).and_then(Value::as_object) {
                for (kid, v) in entry {
                    if !kid.starts_with("signed_curve25519:") {
                        continue;
                    }
                    if v.is_object() && !ed25519.is_empty() && verify_signed_otk(v, uid, dev_id, ed25519) {
                        their_otk = v.get("key").and_then(Value::as_str).map(str::to_string);
                    } else if v.is_object() {
                        log::debug!("Matrix E2EE: OTK signature invalid for {uid} / {dev_id}; skipped.");
                    }
                    break;
                }
            }
            let Some(otk) = their_otk.filter(|o| !o.is_empty()) else {
                no_otk += 1;
                skipped.entry(uid.clone()).or_default().insert(dev_id.clone(), their_ik.clone());
                continue;
            };
            let mut olm = match acct.create_outbound_session(their_ik, &otk) {
                Ok(o) => o,
                Err(e) => {
                    log::debug!("Matrix E2EE: failed to build Olm session for {uid} / {dev_id}: {e}");
                    skipped.entry(uid.clone()).or_default().insert(dev_id.clone(), their_ik.clone());
                    continue;
                }
            };
            let inner = json!({
                "type": "m.room_key",
                "content": room_key,
                "sender": s.user_id,
                "recipient": uid,
                "recipient_keys": {"ed25519": ed25519},
                "keys": {"ed25519": acct.signing_key()},
            });
            let ct = olm.encrypt(inner.to_string().as_bytes());
            per_user.insert(
                dev_id.clone(),
                json!({"algorithm": OLM_ALGORITHM, "ciphertext": {their_ik.clone(): ct}, "sender_key": acct.identity_key()}),
            );
            sent.entry(uid.clone()).or_default().insert(dev_id.clone(), their_ik.clone());
        }
        out.insert(uid.clone(), Value::Object(per_user));
    }
    if no_otk > 0 {
        log::warn!(
            "Matrix E2EE: {no_otk} device(s) in {room_id} had no one-time key available; those device(s) will not \
             be able to decrypt this message."
        );
    }
    (out, sent, skipped)
}

/// Encrypt, upload, send the `m.room.encrypted` event.
fn send_attachment(
    s: Session,
    room_id: String,
    session: MegolmSession,
    idx: usize,
    k: K<(MegolmSession, Option<&'static str>)>,
) -> Plan {
    let att = s.msg.attachments[idx].clone();
    let (ciphertext, mut file_info) = super::e2ee::encrypt_attachment(&att.data);
    s.with_base(move |s, base| {
        let Ok(base) = base else { return k(s, (session, Some("upload"))) };
        let name = if att.name.is_empty() { "file".to_string() } else { att.name.clone() };
        let mut req = Request::post(format!("{base}{}/upload", s.media_prefix()))
            .header("User-Agent", s.msg.app_id.clone())
            .header("Content-Type", "application/octet-stream")
            .header("Accept", "application/json");
        if let Some(t) = &s.access_token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        let req = req.body(ciphertext, None).query(&[("filename", name.as_str())]);
        Plan::http(req, move |res| {
            let uri = match &res {
                Ok(r) if r.status == 200 => r.json().and_then(|v| v.get("content_uri").filter(|u| has_value(u)).cloned()),
                _ => None,
            };
            let Some(uri) = uri else {
                log::warn!("Matrix E2EE: media upload failed.");
                return k(s, (session, Some("upload")));
            };
            file_info["url"] = uri;
            let is_image = att.mime.to_ascii_lowercase().starts_with("image/");
            let mut content = json!({
                "msgtype": if is_image { "m.image" } else { "m.file" },
                "body": name,
                "file": file_info,
                "info": {"mimetype": att.mime, "size": att.data.len()},
            });
            if !is_image {
                content["filename"] = json!(name);
            }
            let mut session = session;
            let inner = json!({"type": "m.room.message", "content": content, "room_id": room_id});
            let ct = session.encrypt(&inner);
            save_megolm(&s, &room_id, &session);
            let payload = envelope(&s, &session, ct);
            let path = format!("/rooms/{}/send/m.room.encrypted/{}", quote_path(&room_id), s.txn);
            s.fetch(Fetch::put(path, payload), move |mut s, r| {
                s.bump_txn();
                k(s, (session, (!r.ok).then_some("send")))
            })
        })
    })
}
