//! E2EE secrets at rest: the Olm account and the Megolm sessions are sealed with AES-256-GCM before they reach the store, under a key derived (HKDF-SHA256) from the URL's own secret, its password or access token. The key is never stored, so a copy of the storage directory alone does not reveal them.
//!
//! The store key is the associated data, so a sealed value cannot be moved to another key. A value written before sealing existed is read as it is and sealed again. One that no longer opens (the password changed) is dropped, and the device starts over with new keys, as on a first run.

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;
use serde_json::{Value, json};

use super::server::{CACHE_EXPIRY, Session, has_value};
use crate::crypto::{b64, b64_decode};

/// Marks a sealed value in the store.
const SEALED: &str = "sealed";
const SALT: &[u8] = b"mercurio matrix e2ee state";

/// The sealing key, from the URL's password or access token; `None` without one.
fn key(s: &Session) -> Option<LessSafeKey> {
    let secret = s.password().filter(|p| !p.is_empty())?;
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, SALT).extract(secret.as_bytes());
    let okm = prk.expand(&[b"v1"], &AES_256_GCM).ok()?;
    Some(LessSafeKey::new(UnboundKey::from(okm)))
}

/// Seal `v` and store it under `name`; stored as it is when the URL has no secret.
pub(super) fn set(s: &Session, name: &str, v: Value) -> bool {
    let sealed = match key(s) {
        Some(k) => seal(s, &k, name, &v),
        None => Some(v),
    };
    sealed.is_some_and(|v| s.store.set(name, v, CACHE_EXPIRY))
}

fn seal(s: &Session, k: &LessSafeKey, name: &str, v: &Value) -> Option<Value> {
    let mut nonce = [0u8; 12];
    s.env.fill_random(&mut nonce);
    let mut data = serde_json::to_vec(v).ok()?;
    k.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(name.as_bytes()), &mut data).ok()?;
    Some(json!({ SEALED: 1, "n": b64(&nonce), "c": b64(&data) }))
}

/// The value stored under `name`, opened; `None` when absent or when it no longer opens.
pub(super) fn get(s: &Session, name: &str) -> Option<Value> {
    let v = s.store.get(name).filter(has_value)?;
    if v.get(SEALED).is_none() {
        // Written before sealing existed (or without a secret): sealed from now on.
        if key(s).is_some() {
            set(s, name, v.clone());
        }
        return Some(v);
    }
    let opened = key(s).and_then(|k| open(&k, name, &v));
    if opened.is_none() {
        log::warn!("Matrix E2EE: the stored {name} could not be decrypted (the URL's password or token changed?); starting over");
        s.store.clear(&[name]);
    }
    opened
}

fn open(k: &LessSafeKey, name: &str, v: &Value) -> Option<Value> {
    let nonce: [u8; 12] = b64_decode(v.get("n")?.as_str()?)?.try_into().ok()?;
    let mut data = b64_decode(v.get("c")?.as_str()?)?;
    let plain = k.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(name.as_bytes()), &mut data).ok()?;
    serde_json::from_slice(plain).ok()
}
