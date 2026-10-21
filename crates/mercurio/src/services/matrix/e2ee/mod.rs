//! End-to-end encryption: the outbound halves of Olm and Megolm, device-key signing/verification and attachment encryption.
//!
//! Primitives: Ed25519, HMAC-SHA-256 and SHA-256 from `ring`; X25519 from `curve25519-dalek` (ring's X25519 keys are ephemeral-only and cannot be persisted); AES-256 (CBC with PKCS#7, CTR) from `aes`; HKDF-SHA-256 on top of ring's HMAC.
//!
//! Private keys, chain/ratchet keys, X25519 shared secrets and HKDF outputs are wiped when dropped (`zeroize`); ring's expanded Ed25519 key pair and the AES key schedule are not. The pickled state is sealed in the store (see `vault`).
//!
//! References: <https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md>, <https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/megolm.md>, <https://spec.matrix.org/v1.11/client-server-api/#end-to-end-encryption>.

pub(super) mod flow;
pub(super) mod sas;
pub(super) mod vault;

mod attachment;
pub(super) mod keys;
mod megolm;
mod olm;
pub use attachment::encrypt_attachment;
pub use keys::{cross_signing_key, verify_device_keys, verify_signed_by, verify_signed_otk};
pub use megolm::MegolmSession;
pub use olm::OlmAccount;

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

#[cfg(test)]
pub(crate) mod tests {
    use super::attachment::encrypt_attachment_with;
    use super::keys::verify_ed25519;
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
