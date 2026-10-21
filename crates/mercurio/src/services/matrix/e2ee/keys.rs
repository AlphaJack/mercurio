//! Device keys: Ed25519 signature checks of `/keys/query` device objects, cross-signing keys and signed one-time keys.

use super::*;

/// Verify an Ed25519 signature.
pub fn verify_ed25519(public_b64: &str, msg: &[u8], sig_b64: &str) -> bool {
    let (Ok(pk), Ok(sig)) = (b64dec(public_b64), b64dec(sig_b64)) else { return false };
    if pk.len() != 32 {
        return false;
    }
    UnparsedPublicKey::new(&ED25519, pk).verify(msg, &sig).is_ok()
}

/// Verify the self-signature of a `/keys/query` device object.
pub fn verify_device_keys(dev: &Value, user_id: &str, device_id: &str) -> bool {
    let Some(obj) = dev.as_object() else { return false };
    if obj.get("user_id").and_then(Value::as_str) != Some(user_id)
        || obj.get("device_id").and_then(Value::as_str) != Some(device_id)
    {
        return false;
    }
    let sig_key = format!("ed25519:{device_id}");
    let Some(pk) = obj.get("keys").and_then(|k| k.get(&sig_key)).and_then(Value::as_str).filter(|s| !s.is_empty())
    else {
        return false;
    };
    let Some(sig) = obj
        .get("signatures")
        .and_then(|s| s.get(user_id))
        .and_then(|s| s.get(&sig_key))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        return false;
    };
    let signed: Map<String, Value> = obj
        .iter()
        .filter(|(k, _)| *k != "signatures" && *k != "unsigned")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    verify_ed25519(pk, canonical_json(&Value::Object(signed)).as_bytes(), sig)
}

/// Verify that the ed25519 key `public` of `user_id` (key id `ed25519:{public}`, as cross-signing keys are named) signed `obj`: its canonical JSON without `signatures` and `unsigned`.
pub fn verify_signed_by(obj: &Value, user_id: &str, public: &str) -> bool {
    let Some(map) = obj.as_object() else { return false };
    let Some(sig) = map
        .get("signatures")
        .and_then(|s| s.get(user_id))
        .and_then(|s| s.get(format!("ed25519:{public}")))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        return false;
    };
    let signed: Map<String, Value> = map
        .iter()
        .filter(|(k, _)| *k != "signatures" && *k != "unsigned")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    verify_ed25519(public, canonical_json(&Value::Object(signed)).as_bytes(), sig)
}

/// The ed25519 public key of a cross-signing key object (a `master_keys` or `self_signing_keys` entry): for `user_id`, with `usage`, holding exactly one key whose id is `ed25519:` and the key itself.
pub fn cross_signing_key(obj: &Value, user_id: &str, usage: &str) -> Option<String> {
    let map = obj.as_object()?;
    if map.get("user_id").and_then(Value::as_str) != Some(user_id)
        || !map.get("usage")?.as_array()?.iter().any(|u| u.as_str() == Some(usage))
    {
        return None;
    }
    let keys = map.get("keys")?.as_object()?;
    let [(id, public)] = keys.iter().collect::<Vec<_>>()[..] else { return None };
    let public = public.as_str()?;
    (id.strip_prefix("ed25519:") == Some(public)).then(|| public.to_string())
}

/// Verify a `signed_curve25519` one-time key object.
pub fn verify_signed_otk(otk: &Value, user_id: &str, device_id: &str, ed25519_pub: &str) -> bool {
    let Some(obj) = otk.as_object() else { return false };
    let Some(sig) = obj
        .get("signatures")
        .and_then(|s| s.get(user_id))
        .and_then(|s| s.get(format!("ed25519:{device_id}")))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    else {
        return false;
    };
    let signed: Map<String, Value> =
        obj.iter().filter(|(k, _)| *k != "signatures").map(|(k, v)| (k.clone(), v.clone())).collect();
    verify_ed25519(ed25519_pub, canonical_json(&Value::Object(signed)).as_bytes(), sig)
}
