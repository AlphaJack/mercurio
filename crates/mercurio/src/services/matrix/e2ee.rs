//! End-to-end encryption: the outbound halves of Olm and Megolm, device-key signing/verification and attachment encryption.
//!
//! Primitives: Ed25519, HMAC-SHA-256 and SHA-256 from `ring`; X25519 from `curve25519-dalek` (ring's X25519 keys are ephemeral-only and cannot be persisted); AES-256 (CBC with PKCS#7, CTR) from `aes`; HKDF-SHA-256 on top of ring's HMAC.
//!
//! Private keys, chain/ratchet keys, X25519 shared secrets and HKDF outputs are wiped when dropped (`zeroize`); ring's expanded Ed25519 key pair and the AES key schedule are not. The pickled state is sealed in the store (see `vault`).
//!
//! References: <https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md>, <https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/megolm.md>, <https://spec.matrix.org/v1.11/client-server-api/#end-to-end-encryption>.

use aes::Aes256;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use base64::Engine;
use curve25519_dalek::montgomery::MontgomeryPoint;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde_json::{Map, Value, json};
use zeroize::{Zeroize, Zeroizing};

use crate::env::Env;

/// Rotate the Megolm session after this many messages.
pub const MEGOLM_ROTATION_MSGS: u32 = 100;
/// Rotate the Megolm session after this many seconds (7 days).
pub const MEGOLM_ROTATION_AGE: f64 = 60.0 * 60.0 * 24.0 * 7.0;
/// Serialisation version of cached Megolm sessions.
pub const MATRIX_MEGOLM_STORE_VERSION: u64 = 1;

pub const OLM_ALGORITHM: &str = "m.olm.v1.curve25519-aes-sha2";
pub const MEGOLM_ALGORITHM: &str = "m.megolm.v1.aes-sha2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoError(pub &'static str);

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

pub type CResult<T> = std::result::Result<T, CryptoError>;

/// Matrix unpadded standard base64.
pub fn b64enc(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(data)
}

/// Decode base64, tolerating missing padding and URL-safe characters.
pub fn b64dec(s: &str) -> CResult<Vec<u8>> {
    let s: String = s
        .chars()
        .map(|c| {
            if c == '-' {
                '+'
            } else if c == '_' {
                '/'
            } else {
                c
            }
        })
        .collect();
    let s = s.trim_end_matches('=');
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(s)
        .or_else(|_| {
            base64::engine::GeneralPurpose::new(
                &base64::alphabet::STANDARD,
                base64::engine::GeneralPurposeConfig::new()
                    .with_decode_allow_trailing_bits(true)
                    .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireNone),
            )
            .decode(s)
        })
        .map_err(|_| CryptoError("invalid base64"))
}

fn b64url_nopad(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let tag = ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key), data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// HKDF-SHA-256 (RFC 5869); `None` salt is 32 zero bytes. Every intermediate and the output are wiped on drop.
pub fn hkdf_sha256(ikm: &[u8], len: usize, salt: Option<&[u8]>, info: &[u8]) -> Zeroizing<Vec<u8>> {
    let zero = [0u8; 32];
    let prk = Zeroizing::new(hmac_sha256(salt.unwrap_or(&zero), ikm));
    // Capacity for the last whole block: the buffers never reallocate (which would leave an unwiped copy behind).
    let mut out = Zeroizing::new(Vec::with_capacity(len + 32));
    let mut t = Zeroizing::new([0u8; 32]);
    let mut input = Zeroizing::new(Vec::with_capacity(32 + info.len() + 1));
    let mut i = 1u8;
    while out.len() < len {
        input.clear();
        if i > 1 {
            input.extend_from_slice(&t[..]);
        }
        input.extend_from_slice(info);
        input.push(i);
        *t = hmac_sha256(&prk[..], &input);
        out.extend_from_slice(&t[..]);
        i = i.wrapping_add(1);
    }
    out.truncate(len);
    out
}

fn aes(key: &[u8; 32]) -> Aes256 {
    Aes256::new(&Array::from(*key))
}

/// AES-256-CBC with PKCS#7 padding.
pub fn aes_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let cipher = aes(key);
    let pad = 16 - plaintext.len() % 16;
    let mut data = plaintext.to_vec();
    data.extend(std::iter::repeat_n(pad as u8, pad));
    let mut prev = *iv;
    // Padding makes `data` a whole number of blocks: the remainder is empty.
    let mut rest = data.as_mut_slice();
    while let Some((chunk, tail)) = rest.split_first_chunk_mut::<16>() {
        rest = tail;
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        let mut block = Array::from(*chunk);
        cipher.encrypt_block(&mut block);
        *chunk = block.into();
        prev = *chunk;
    }
    data
}

/// AES-256-CTR with a 128-bit big-endian counter (as `cryptography`'s `CTR`).
pub fn aes_ctr(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = aes(key);
    let mut counter = u128::from_be_bytes(*iv);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut block = Array::from(counter.to_be_bytes());
        cipher.encrypt_block(&mut block);
        out.extend(chunk.iter().zip(block.iter()).map(|(a, b)| a ^ b));
        counter = counter.wrapping_add(1);
    }
    out
}

pub fn random32(env: &dyn Env) -> [u8; 32] {
    let mut b = [0u8; 32];
    env.fill_random(&mut b);
    b
}

pub fn varint(mut n: u64) -> Vec<u8> {
    if n == 0 {
        return vec![0];
    }
    let mut out = Vec::new();
    while n != 0 {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
    }
    out
}

/// Protobuf length-delimited field.
pub fn pb_bytes(field: u64, data: &[u8]) -> Vec<u8> {
    let mut out = varint((field << 3) | 2);
    out.extend(varint(data.len() as u64));
    out.extend_from_slice(data);
    out
}

/// Protobuf varint field.
pub fn pb_varint(field: u64, value: u64) -> Vec<u8> {
    let mut out = varint(field << 3);
    out.extend(varint(value));
    out
}

/// Matrix canonical JSON: sorted keys, no whitespace, UTF-8.
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                write_canonical(&m[k.as_str()], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(x, out);
            }
            out.push(']');
        }
        other @ (Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)) => {
            out.push_str(&serde_json::to_string(other).unwrap_or_default());
        }
    }
}

/// Ed25519 signing key (kept as its 32-byte seed, wiped on drop).
pub struct SigningKey {
    seed: [u8; 32],
    // `Ed25519KeyPair` is not `Clone`; sharing it avoids re-deriving it.
    pair: std::sync::Arc<Ed25519KeyPair>,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey").field("public", &b64enc(self.public())).finish_non_exhaustive()
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl SigningKey {
    // Ring rejects only seeds whose length is not 32 bytes; `random32()` is `[u8; 32]`.
    #[expect(clippy::expect_used, reason = "ring rejects only seeds whose length is not 32 bytes")]
    pub fn generate(env: &dyn Env) -> Self {
        Self::from_seed(random32(env)).expect("valid seed")
    }

    pub fn from_seed(seed: [u8; 32]) -> CResult<Self> {
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| CryptoError("invalid ed25519 seed"))?;
        Ok(Self { seed, pair: std::sync::Arc::new(pair) })
    }

    pub fn from_b64(s: &str) -> CResult<Self> {
        let raw = Zeroizing::new(b64dec(s)?);
        let seed = Zeroizing::new(
            <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| CryptoError("ed25519 key must be 32 bytes"))?,
        );
        Self::from_seed(*seed)
    }

    pub fn seed_b64(&self) -> String {
        b64enc(&self.seed)
    }

    pub fn public(&self) -> &[u8] {
        self.pair.public_key().as_ref()
    }

    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        out.copy_from_slice(self.pair.sign(data).as_ref());
        out
    }

    pub fn sign_b64(&self, data: &[u8]) -> String {
        b64enc(&self.sign(data))
    }
}

/// X25519 private key (wiped on drop).
pub struct XKey([u8; 32]);

impl Drop for XKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for XKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("XKey").field(&b64enc(&self.public())).finish()
    }
}

impl XKey {
    pub fn generate(env: &dyn Env) -> Self {
        XKey(random32(env))
    }

    #[cfg(test)]
    pub fn from_bytes(b: [u8; 32]) -> Self {
        XKey(b)
    }

    pub fn from_b64(s: &str) -> CResult<Self> {
        let raw = Zeroizing::new(b64dec(s)?);
        Ok(XKey(<[u8; 32]>::try_from(raw.as_slice()).map_err(|_| CryptoError("x25519 key must be 32 bytes"))?))
    }

    pub fn to_b64(&self) -> String {
        b64enc(&self.0)
    }

    pub fn public(&self) -> [u8; 32] {
        MontgomeryPoint::mul_base_clamped(self.0).to_bytes()
    }

    /// X25519; rejects low-order points (all-zero shared secret) like `cryptography`.
    pub fn exchange(&self, their_public: &[u8]) -> CResult<[u8; 32]> {
        let p: [u8; 32] = their_public.try_into().map_err(|_| CryptoError("x25519 public key must be 32 bytes"))?;
        let shared = MontgomeryPoint(p).mul_clamped(self.0).to_bytes();
        if shared.iter().all(|b| *b == 0) {
            return Err(CryptoError("x25519 shared secret is zero"));
        }
        Ok(shared)
    }
}

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

/// Encrypt attachment bytes (Matrix `EncryptedFile` v2, AES-256-CTR).
pub fn encrypt_attachment(data: &[u8], env: &dyn Env) -> (Vec<u8>, Value) {
    let key = Zeroizing::new(random32(env));
    let mut iv = [0u8; 16];
    env.fill_random(&mut iv[..8]);
    encrypt_attachment_with(data, &key, &iv)
}

pub fn encrypt_attachment_with(data: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> (Vec<u8>, Value) {
    let ct = aes_ctr(key, iv, data);
    let digest = sha256(&ct);
    let info = json!({
        "v": "v2",
        "key": {
            "kty": "oct",
            "key_ops": ["encrypt", "decrypt"],
            "alg": "A256CTR",
            "k": b64url_nopad(key),
            "ext": true,
        },
        "iv": b64enc(iv),
        "hashes": {"sha256": b64enc(&digest)},
    });
    (ct, info)
}

/// Device-level Curve25519 identity key + Ed25519 signing key.
#[derive(Debug)]
pub struct OlmAccount {
    ik: XKey,
    sk: SigningKey,
    /// `{"id": ..., "sk": ...}` of the published fallback key.
    fallback_otk: Option<Value>,
}

impl Drop for OlmAccount {
    fn drop(&mut self) {
        if let Some(Value::Object(f)) = &mut self.fallback_otk
            && let Some(Value::String(sk)) = f.get_mut("sk")
        {
            sk.zeroize();
        }
    }
}

impl OlmAccount {
    pub fn new(env: &dyn Env) -> Self {
        Self { ik: XKey::generate(env), sk: SigningKey::generate(env), fallback_otk: None }
    }

    #[cfg(test)]
    pub fn from_keys(ik: XKey, sk: SigningKey) -> Self {
        Self { ik, sk, fallback_otk: None }
    }

    pub fn identity_key(&self) -> String {
        b64enc(&self.ik.public())
    }

    pub fn signing_key(&self) -> String {
        b64enc(self.sk.public())
    }

    pub fn sign(&self, data: &[u8]) -> String {
        self.sk.sign_b64(data)
    }

    #[cfg(test)]
    pub fn identity_private(&self) -> &XKey {
        &self.ik
    }

    pub fn to_value(&self) -> Value {
        json!({"ik": self.ik.to_b64(), "sk": self.sk.seed_b64(), "fallback_otk": self.fallback_otk})
    }

    pub fn from_value(v: &Value) -> CResult<Self> {
        let ik = v.get("ik").and_then(Value::as_str).ok_or(CryptoError("missing ik"))?;
        let sk = v.get("sk").and_then(Value::as_str).ok_or(CryptoError("missing sk"))?;
        let ik = XKey::from_b64(ik)?;
        let sk = SigningKey::from_b64(sk)?;
        let fallback_otk = v.get("fallback_otk").filter(|f| !f.is_null()).cloned();
        Ok(Self { ik, sk, fallback_otk })
    }

    /// Signed `device_keys` for `POST /keys/upload`.
    pub fn device_keys_payload(&self, user_id: &str, device_id: &str) -> Value {
        let mut dk = json!({
            "algorithms": [OLM_ALGORITHM, MEGOLM_ALGORITHM],
            "device_id": device_id,
            "keys": {
                format!("curve25519:{device_id}"): self.identity_key(),
                format!("ed25519:{device_id}"): self.signing_key(),
            },
            "user_id": user_id,
        });
        let sig = self.sign(canonical_json(&dk).as_bytes());
        dk["signatures"] = json!({user_id: {format!("ed25519:{device_id}"): sig}});
        dk
    }

    fn signed_curve25519_key(&self, user_id: &str, device_id: &str, key_b64: &str) -> Value {
        let mut p = json!({"key": key_b64});
        let sig = self.sign(canonical_json(&p).as_bytes());
        p["signatures"] = json!({user_id: {format!("ed25519:{device_id}"): sig}});
        p
    }

    /// Signed `fallback_keys` (creates the fallback key on first use).
    pub fn fallback_keys_payload(&mut self, user_id: &str, device_id: &str, env: &dyn Env) -> Value {
        let parsed = self.fallback_otk.as_ref().and_then(|f| {
            let id = f.get("id")?.as_str()?.to_string();
            let sk = XKey::from_b64(f.get("sk")?.as_str()?).ok()?;
            Some((id, sk))
        });
        let (id, sk) = match parsed {
            Some(p) => p,
            None => {
                let id = env.uuid4().replace('-', "").get(..10).unwrap_or_default().to_string();
                let sk = XKey::generate(env);
                self.fallback_otk = Some(json!({"id": id, "sk": sk.to_b64()}));
                (id, sk)
            }
        };
        json!({format!("signed_curve25519:{id}"): self.signed_curve25519_key(user_id, device_id, &b64enc(&sk.public()))})
    }

    /// Outbound Olm session (X3DH) to a device.
    pub fn create_outbound_session(&self, their_ik_b64: &str, their_otk_b64: &str, env: &dyn Env) -> CResult<OlmSession> {
        self.create_outbound_session_with(their_ik_b64, their_otk_b64, XKey::generate(env))
    }

    pub fn create_outbound_session_with(
        &self,
        their_ik_b64: &str,
        their_otk_b64: &str,
        eph: XKey,
    ) -> CResult<OlmSession> {
        let their_ik = b64dec(their_ik_b64)?;
        let their_otk = b64dec(their_otk_b64)?;
        if their_ik.len() != 32 || their_otk.len() != 32 {
            return Err(CryptoError("curve25519 keys must be 32 bytes"));
        }
        let dh1 = Zeroizing::new(self.ik.exchange(&their_otk)?);
        let dh2 = Zeroizing::new(eph.exchange(&their_ik)?);
        let dh3 = Zeroizing::new(eph.exchange(&their_otk)?);
        let mut ikm = Zeroizing::new(Vec::with_capacity(96));
        ikm.extend_from_slice(&dh1[..]);
        ikm.extend_from_slice(&dh2[..]);
        ikm.extend_from_slice(&dh3[..]);
        let keys = hkdf_sha256(&ikm, 64, None, b"OLM_ROOT");
        let mut chain = [0u8; 32];
        chain.copy_from_slice(&keys[32..]);
        Ok(OlmSession {
            our_ik_pub: self.ik.public(),
            eph_pub: eph.public(),
            their_otk_pub: their_otk,
            chain_key: chain,
            counter: 0,
        })
    }
}

/// Single-use outbound Olm session (pre-key messages only).
#[derive(Debug)]
pub struct OlmSession {
    our_ik_pub: [u8; 32],
    eph_pub: [u8; 32],
    their_otk_pub: Vec<u8>,
    chain_key: [u8; 32],
    counter: u64,
}

impl Drop for OlmSession {
    fn drop(&mut self) {
        self.chain_key.zeroize();
    }
}

impl OlmSession {
    /// Encrypt as an Olm pre-key (type 0) message: `{"type": 0, "body": ...}`.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Value {
        let msg_key = Zeroizing::new(hmac_sha256(&self.chain_key, b"\x01"));
        self.chain_key = hmac_sha256(&self.chain_key, b"\x02");
        let keys = hkdf_sha256(&msg_key[..], 80, Some(&[0u8; 32]), b"OLM_KEYS");
        let (aes_key, mac_key, iv) = split_keys(&keys);
        let ct = aes_cbc_encrypt(&aes_key, &iv, plaintext);
        let mut inner = vec![3u8];
        inner.extend(pb_bytes(1, &self.eph_pub));
        inner.extend(pb_varint(2, self.counter));
        inner.extend(pb_bytes(4, &ct));
        let mac = hmac_sha256(&mac_key[..], &inner);
        inner.extend_from_slice(&mac[..8]);
        let mut outer = vec![3u8];
        outer.extend(pb_bytes(1, &self.their_otk_pub));
        outer.extend(pb_bytes(2, &self.eph_pub));
        outer.extend(pb_bytes(3, &self.our_ik_pub));
        outer.extend(pb_bytes(4, &inner));
        self.counter += 1;
        json!({"type": 0, "body": b64enc(&outer)})
    }
}

/// AES key, MAC key (both wiped on drop) and IV from 80 HKDF bytes.
fn split_keys(keys: &[u8]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>, [u8; 16]) {
    let mut a = Zeroizing::new([0u8; 32]);
    let mut m = Zeroizing::new([0u8; 32]);
    let mut iv = [0u8; 16];
    a.copy_from_slice(&keys[..32]);
    m.copy_from_slice(&keys[32..64]);
    iv.copy_from_slice(&keys[64..80]);
    (a, m, iv)
}

/// Outbound Megolm session (ratchet wiped on drop).
#[derive(Debug)]
pub struct MegolmSession {
    ratchet: [[u8; 32]; 4],
    counter: u32,
    sk: SigningKey,
    pub session_id: String,
    pub created_at: f64,
}

impl Drop for MegolmSession {
    fn drop(&mut self) {
        self.ratchet.zeroize();
    }
}

impl MegolmSession {
    pub fn new(env: &dyn Env) -> Self {
        let ratchet = [random32(env), random32(env), random32(env), random32(env)];
        Self::from_parts(ratchet, 0, SigningKey::generate(env), env.unix_time_f64())
    }

    pub fn from_parts(ratchet: [[u8; 32]; 4], counter: u32, sk: SigningKey, created_at: f64) -> Self {
        let session_id = b64enc(sk.public());
        Self { ratchet, counter, sk, session_id, created_at }
    }

    #[cfg(test)]
    pub fn counter(&self) -> u32 {
        self.counter
    }

    fn advance(&mut self) {
        let r = &mut self.ratchet;
        let n1 = self.counter.wrapping_add(1);
        let h = if n1.is_multiple_of(1 << 24) {
            0
        } else if n1.is_multiple_of(1 << 16) {
            1
        } else if n1.is_multiple_of(1 << 8) {
            2
        } else {
            3
        };
        let orig = Zeroizing::new(r[h]);
        for i in (h..4).rev() {
            r[i] = hmac_sha256(&orig[..], &[i as u8]);
        }
        self.counter = n1;
    }

    fn message_keys(&self) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>, [u8; 16]) {
        let ratchet = Zeroizing::new(self.ratchet.concat());
        let keys = hkdf_sha256(&ratchet, 80, None, b"MEGOLM_KEYS");
        split_keys(&keys)
    }

    pub fn should_rotate(&self, env: &dyn Env) -> bool {
        self.counter >= MEGOLM_ROTATION_MSGS || env.unix_time_f64() - self.created_at >= MEGOLM_ROTATION_AGE
    }

    /// Encrypt bytes; returns the base64 Megolm message.
    pub fn encrypt_bytes(&mut self, plaintext: &[u8]) -> String {
        let (aes_key, mac_key, iv) = self.message_keys();
        let ct = aes_cbc_encrypt(&aes_key, &iv, plaintext);
        let mut body = vec![3u8];
        body.extend(pb_varint(1, self.counter as u64));
        body.extend(pb_bytes(2, &ct));
        let mac = hmac_sha256(&mac_key[..], &body);
        body.extend_from_slice(&mac[..8]);
        let sig = self.sk.sign(&body);
        body.extend_from_slice(&sig);
        self.advance();
        b64enc(&body)
    }

    /// Encrypt a JSON event (compact serialisation).
    pub fn encrypt(&mut self, event: &Value) -> String {
        self.encrypt_bytes(event.to_string().as_bytes())
    }

    /// Exportable session key (`m.room_key` `session_key`).
    pub fn session_key(&self) -> String {
        let mut payload = Zeroizing::new(Vec::with_capacity(229));
        payload.push(2u8);
        payload.extend_from_slice(&self.counter.to_be_bytes());
        for part in &self.ratchet {
            payload.extend_from_slice(part);
        }
        payload.extend_from_slice(self.sk.public());
        let sig = self.sk.sign(&payload);
        payload.extend_from_slice(&sig);
        b64enc(&payload)
    }

    pub fn to_value(&self) -> Value {
        json!({
            "version": MATRIX_MEGOLM_STORE_VERSION,
            "ratchet": self.ratchet.iter().map(|r| b64enc(r)).collect::<Vec<_>>(),
            "counter": self.counter,
            "sk": self.sk.seed_b64(),
            "session_id": self.session_id,
            "created_at": self.created_at,
        })
    }

    pub fn from_value(v: &Value, env: &dyn Env) -> CResult<Self> {
        if v.get("version").and_then(Value::as_u64) != Some(MATRIX_MEGOLM_STORE_VERSION) {
            return Err(CryptoError("incompatible Megolm session cache format"));
        }
        let parts = v.get("ratchet").and_then(Value::as_array).ok_or(CryptoError("missing ratchet"))?;
        if parts.len() != 4 {
            return Err(CryptoError("ratchet must have 4 parts"));
        }
        let mut ratchet = Zeroizing::new([[0u8; 32]; 4]);
        for (slot, p) in ratchet.iter_mut().zip(parts) {
            let raw = Zeroizing::new(b64dec(p.as_str().ok_or(CryptoError("ratchet part"))?)?);
            *slot = <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| CryptoError("ratchet part must be 32 bytes"))?;
        }
        let counter = v.get("counter").and_then(Value::as_u64).ok_or(CryptoError("missing counter"))?;
        let counter = u32::try_from(counter).map_err(|_| CryptoError("counter out of range"))?;
        let sk = SigningKey::from_b64(v.get("sk").and_then(Value::as_str).ok_or(CryptoError("missing sk"))?)?;
        let created_at = v.get("created_at").and_then(Value::as_f64).unwrap_or_else(|| env.unix_time_f64());
        Ok(Self::from_parts(*ratchet, counter, sk, created_at))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use crate::crypto::unhex as hex;

    fn arr32(v: &[u8]) -> [u8; 32] {
        v.try_into().unwrap()
    }

    #[test]
    fn hkdf_rfc5869_case1() {
        let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let okm = hkdf_sha256(&ikm, 42, Some(&salt), &info);
        assert_eq!(
            crate::crypto::hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
        // Case 3: no salt (zero-length salt == 32 zero bytes for SHA-256).
        let okm = hkdf_sha256(&hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), 42, None, b"");
        assert_eq!(
            crate::crypto::hex(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    /// The wiping HKDF (fixed buffers, no reallocation) matches a plain RFC 5869 expansion for every length and multi-block output.
    #[test]
    fn hkdf_matches_reference_for_all_lengths() {
        fn reference(ikm: &[u8], len: usize, info: &[u8]) -> Vec<u8> {
            let prk = hmac_sha256(&[0u8; 32], ikm);
            let (mut out, mut t) = (Vec::new(), Vec::new());
            for i in 1u8.. {
                if out.len() >= len {
                    break;
                }
                let mut input = t.clone();
                input.extend_from_slice(info);
                input.push(i);
                t = hmac_sha256(&prk, &input).to_vec();
                out.extend_from_slice(&t);
            }
            out.truncate(len);
            out
        }
        for len in 0..=200 {
            let got = hkdf_sha256(b"ikm", len, None, b"info");
            assert_eq!(got.as_slice(), reference(b"ikm", len, b"info").as_slice(), "len {len}");
            assert!(got.capacity() <= len + 32, "no reallocation");
        }
    }

    #[test]
    fn x25519_rfc7748() {
        let a = XKey::from_bytes(arr32(&hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")));
        let b = XKey::from_bytes(arr32(&hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")));
        assert_eq!(crate::crypto::hex(&a.public()), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(crate::crypto::hex(&b.public()), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = a.exchange(&b.public()).unwrap();
        assert_eq!(crate::crypto::hex(&shared), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(b.exchange(&a.public()).unwrap(), shared);
        assert!(a.exchange(&[0u8; 32]).is_err(), "low-order point");
        assert!(a.exchange(&[1u8; 5]).is_err());
    }

    #[test]
    fn ed25519_rfc8032_test1() {
        let sk = SigningKey::from_seed(arr32(&hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")))
            .unwrap();
        assert_eq!(crate::crypto::hex(sk.public()), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let sig = sk.sign(b"");
        assert_eq!(
            crate::crypto::hex(&sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert!(verify_ed25519(&b64enc(sk.public()), b"", &b64enc(&sig)));
        assert!(!verify_ed25519(&b64enc(sk.public()), b"x", &b64enc(&sig)));
        assert!(!verify_ed25519("bad", b"", "bad"));
    }

    /// Matrix spec appendix "Signing JSON" examples (key `ed25519:1`).
    #[test]
    fn matrix_spec_json_signing() {
        let seed = b64dec("YJDBA9Xnr2sVqXD9Vj7XVUnmFZcZrlw8Md7kMW+3XA1").unwrap();
        let sk = SigningKey::from_seed(arr32(&seed)).unwrap();
        assert_eq!(
            sk.sign_b64(canonical_json(&json!({})).as_bytes()),
            "K8280/U9SSy9IVtjBuVeLr+HpOB4BQFWbg+UZaADMtTdGYI7Geitb76LTrr5QV/7Xg4ahLwYGYZzuHGZKM5ZAQ"
        );
        assert_eq!(
            sk.sign_b64(canonical_json(&json!({"one": 1, "two": "Two"})).as_bytes()),
            "KqmLSbO39/Bzb0QIYE82zqLwsA+PDzYIpIRA2sRQ4sL53+sN6/fpNSoqE7BP7vBZhG6kYdD13EIMJpvhJI+6Bw"
        );
    }

    #[test]
    fn canonical_json_rules() {
        let v = json!({"b": 1, "a": {"d": [1, "x"], "c": null}, "é": "日本", "ctl": "\u{1}\n"});
        assert_eq!(canonical_json(&v), r#"{"a":{"c":null,"d":[1,"x"]},"b":1,"ctl":"\u0001\n","é":"日本"}"#);
    }

    #[test]
    fn aes_known_answers() {
        // NIST SP 800-38A F.2.5 (CBC-AES256.Encrypt), first block.
        let key = arr32(&hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"));
        let iv: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let pt = hex("6bc1bee22e409f96e93d7e117393172a");
        let ct = aes_cbc_encrypt(&key, &iv, &pt);
        assert_eq!(crate::crypto::hex(&ct[..16]), "f58c4c04d6e5f1ba779eabfb5f7bfbd6");
        assert_eq!(ct.len(), 32, "PKCS#7 adds a full block");
        // NIST SP 800-38A F.5.5 (CTR-AES256.Encrypt), first two blocks.
        let iv: [u8; 16] = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").try_into().unwrap();
        let pt = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        assert_eq!(
            crate::crypto::hex(&aes_ctr(&key, &iv, &pt)),
            "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
        );
    }

    #[test]
    fn varints() {
        assert_eq!(varint(0), vec![0]);
        assert_eq!(varint(300), vec![0xac, 0x02]);
        assert_eq!(pb_varint(1, 5), vec![0x08, 5]);
        assert_eq!(pb_bytes(4, b"ab"), vec![0x22, 2, b'a', b'b']);
    }

    // Receiver-side helpers (tests only)

    pub(crate) fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Vec<u8> {
        use aes::cipher::BlockCipherDecrypt;
        let cipher = Aes256::new_from_slice(key).expect("AES-256 key");
        let mut prev: Vec<u8> = iv.to_vec();
        let mut out = Vec::new();
        for chunk in ct.chunks(16) {
            let mut block = Array::try_from(chunk).expect("16-byte block");
            cipher.decrypt_block(&mut block);
            out.extend(block.iter().zip(prev.iter()).map(|(a, b)| a ^ b));
            prev = chunk.to_vec();
        }
        let pad = *out.last().unwrap() as usize;
        out.truncate(out.len() - pad);
        out
    }

    fn read_varint(d: &[u8], pos: &mut usize) -> u64 {
        let (mut v, mut shift) = (0u64, 0);
        loop {
            let b = d[*pos];
            *pos += 1;
            v |= u64::from(b & 0x7f) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                return v;
            }
        }
    }

    pub(crate) fn pb_fields(d: &[u8]) -> std::collections::BTreeMap<u64, (Vec<u8>, u64)> {
        let mut out = std::collections::BTreeMap::new();
        let mut pos = 0;
        while pos < d.len() {
            let tag = read_varint(d, &mut pos);
            match tag & 7 {
                2 => {
                    let len = read_varint(d, &mut pos) as usize;
                    out.insert(tag >> 3, (d[pos..pos + len].to_vec(), 0));
                    pos += len;
                }
                0 => {
                    let v = read_varint(d, &mut pos);
                    out.insert(tag >> 3, (Vec::new(), v));
                }
                w => panic!("wire type {w}"),
            }
        }
        out
    }

    /// Bob decrypts Alice's pre-key message (mirrors the upstream test).
    #[test]
    fn olm_roundtrip() {
        let alice = OlmAccount::new(crate::testing::test_env());
        let bob = OlmAccount::new(crate::testing::test_env());
        let bob_otk = XKey::generate(crate::testing::test_env());
        let mut session = alice.create_outbound_session(&bob.identity_key(), &b64enc(&bob_otk.public()), crate::testing::test_env()).unwrap();
        let msg = session.encrypt(b"hello from Alice");
        assert_eq!(msg["type"], 0);
        let raw = b64dec(msg["body"].as_str().unwrap()).unwrap();
        assert_eq!(raw[0], 3);
        let outer = pb_fields(&raw[1..]);
        assert_eq!(outer[&1].0, bob_otk.public());
        let base_key = outer[&2].0.clone();
        let alice_ik = outer[&3].0.clone();
        assert_eq!(b64enc(&alice_ik), alice.identity_key());
        let dh1 = bob_otk.exchange(&alice_ik).unwrap();
        let dh2 = bob.identity_private().exchange(&base_key).unwrap();
        let dh3 = bob_otk.exchange(&base_key).unwrap();
        let keys = hkdf_sha256(&[dh1, dh2, dh3].concat(), 64, None, b"OLM_ROOT");
        let msg_key = hmac_sha256(&keys[32..], b"\x01");
        let k = hkdf_sha256(&msg_key, 80, Some(&[0u8; 32]), b"OLM_KEYS");
        let inner_with_mac = &outer[&4].0;
        let (inner, mac) = inner_with_mac.split_at(inner_with_mac.len() - 8);
        assert_eq!(&hmac_sha256(&k[32..64], inner)[..8], mac);
        assert_eq!(inner[0], 3);
        let f = pb_fields(&inner[1..]);
        assert_eq!(f[&1].0, base_key, "ratchet key equals base key");
        assert_eq!(f[&2].1, 0, "chain index");
        assert_eq!(aes_cbc_decrypt(&k[..32], &k[64..80], &f[&4].0), b"hello from Alice");
        // Second message advances the chain.
        let m2 = session.encrypt(b"again");
        assert_ne!(m2["body"], msg["body"]);
    }

    /// Decrypt Megolm messages from the exported session key, as a receiving client would (signature, MAC, ratchet advance).
    #[test]
    fn megolm_roundtrip() {
        let mut s = MegolmSession::new(crate::testing::test_env());
        let key = b64dec(&s.session_key()).unwrap();
        assert_eq!(key.len(), 1 + 4 + 128 + 32 + 64);
        assert_eq!(key[0], 2);
        let signing_pub = &key[133..165];
        assert_eq!(b64enc(signing_pub), s.session_id);
        assert!(verify_ed25519(&s.session_id, &key[..165], &b64enc(&key[165..])));
        let mut ratchet = [[0u8; 32]; 4];
        for (i, r) in ratchet.iter_mut().enumerate() {
            r.copy_from_slice(&key[5 + 32 * i..5 + 32 * (i + 1)]);
        }
        let mut inbound = MegolmSession::from_parts(ratchet, 0, SigningKey::generate(crate::testing::test_env()), 0.0);
        for n in 0..300u32 {
            let text = format!("message {n}");
            let ct = b64dec(&s.encrypt_bytes(text.as_bytes())).unwrap();
            let (signed, sig) = ct.split_at(ct.len() - 64);
            assert!(verify_ed25519(&s.session_id, signed, &b64enc(sig)));
            let (body, mac) = signed.split_at(signed.len() - 8);
            let (aes_key, mac_key, iv) = inbound.message_keys();
            assert_eq!(&hmac_sha256(&mac_key[..], body)[..8], mac);
            let f = pb_fields(&body[1..]);
            assert_eq!(f[&1].1, u64::from(n));
            assert_eq!(aes_cbc_decrypt(&aes_key[..], &iv, &f[&2].0), text.as_bytes());
            inbound.advance();
        }
        assert_eq!(s.counter(), 300);
        assert!(s.should_rotate(crate::testing::test_env()));
        let restored = MegolmSession::from_value(&s.to_value(), crate::testing::test_env()).unwrap();
        assert_eq!(restored.session_key(), s.session_key());
        assert!(MegolmSession::from_value(&json!({"version": 0}), crate::testing::test_env()).is_err());
    }

    #[test]
    fn megolm_advance_matches_libolm_rules() {
        // R[h] for the highest changed part derives the lower ones from its original value.
        let mut s = MegolmSession::from_parts([[1; 32], [2; 32], [3; 32], [4; 32]], 255, SigningKey::generate(crate::testing::test_env()), 0.0);
        s.advance();
        assert_eq!(s.ratchet[2], hmac_sha256(&[3; 32], &[2]));
        assert_eq!(s.ratchet[3], hmac_sha256(&[3; 32], &[3]));
        assert_eq!(s.ratchet[1], [2; 32]);
        let mut s =
            MegolmSession::from_parts([[1; 32], [2; 32], [3; 32], [4; 32]], (1 << 24) - 1, SigningKey::generate(crate::testing::test_env()), 0.0);
        s.advance();
        assert_eq!(s.ratchet[0], hmac_sha256(&[1; 32], &[0]));
        assert_eq!(s.ratchet[3], hmac_sha256(&[1; 32], &[3]));
    }

    #[test]
    fn device_keys_sign_and_verify() {
        let mut acct = OlmAccount::new(crate::testing::test_env());
        let dk = acct.device_keys_payload("@a:hs", "DEV");
        assert!(verify_device_keys(&dk, "@a:hs", "DEV"));
        assert!(!verify_device_keys(&dk, "@b:hs", "DEV"), "user binding");
        assert!(!verify_device_keys(&dk, "@a:hs", "OTHER"), "device binding");
        let mut tampered = dk.clone();
        tampered["keys"]["curve25519:DEV"] = json!("AAAA");
        assert!(!verify_device_keys(&tampered, "@a:hs", "DEV"));
        let mut with_unsigned = dk.clone();
        with_unsigned["unsigned"] = json!({"device_display_name": "x"});
        assert!(verify_device_keys(&with_unsigned, "@a:hs", "DEV"));
        let fb = acct.fallback_keys_payload("@a:hs", "DEV", crate::testing::test_env());
        let (kid, otk) = fb.as_object().unwrap().iter().next().unwrap();
        assert!(kid.starts_with("signed_curve25519:") && kid.len() == 28);
        assert!(verify_signed_otk(otk, "@a:hs", "DEV", &acct.signing_key()));
        assert!(!verify_signed_otk(otk, "@a:hs", "DEV", &OlmAccount::new(crate::testing::test_env()).signing_key()));
        // The fallback key is stable once created and survives a round trip.
        let again = OlmAccount::from_value(&acct.to_value()).unwrap().fallback_keys_payload("@a:hs", "DEV", crate::testing::test_env());
        assert_eq!(again[kid]["key"], otk["key"]);
        assert!(OlmAccount::from_value(&json!({"ik": "x"})).is_err());
    }

    #[test]
    fn attachment_encryption() {
        let key = [7u8; 32];
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(&[9; 8]);
        let (ct, info) = encrypt_attachment_with(b"hello world", &key, &iv);
        assert_eq!(aes_ctr(&key, &iv, &ct), b"hello world");
        assert_eq!(info["v"], "v2");
        assert_eq!(info["key"]["alg"], "A256CTR");
        assert_eq!(info["key"]["k"], b64url_nopad(&key));
        assert_eq!(info["iv"], b64enc(&iv));
        assert_eq!(b64enc(&[0xfb; 16]), "+/v7+/v7+/v7+/v7+/v7+w");
        assert_eq!(info["hashes"]["sha256"], b64enc(&sha256(&ct)));
        let (_, rand_info) = encrypt_attachment(b"x", crate::testing::test_env());
        let iv = b64dec(rand_info["iv"].as_str().unwrap()).unwrap();
        assert_eq!(&iv[8..], &[0u8; 8]);
    }
}
