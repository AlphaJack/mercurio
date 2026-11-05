//! The cryptographic and encoding primitives the E2EE parts share.

use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use base64::Engine;
use serde_json::Value;
use zeroize::Zeroizing;
use crate::env::Env;
use super::*;

/// AES-256-CBC with PKCS#7 padding.
pub(crate) fn aes_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
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
pub(crate) fn aes_ctr(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
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

/// Decode base64, tolerating missing padding and URL-safe characters.
pub(crate) fn b64dec(s: &str) -> CResult<Vec<u8>> {
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
        .ok().ok_or(CryptoError("invalid base64"))
}

/// Matrix unpadded standard base64.
pub(crate) fn b64enc(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(data)
}

/// Matrix canonical JSON: sorted keys, no whitespace, UTF-8.
pub(crate) fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

/// HKDF-SHA-256 (RFC 5869); `None` salt is 32 zero bytes. Every intermediate and the output are wiped on drop.
pub(crate) fn hkdf_sha256(ikm: &[u8], len: usize, salt: Option<&[u8]>, info: &[u8]) -> Zeroizing<Vec<u8>> {
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

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let tag = ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key), data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Protobuf length-delimited field.
pub(crate) fn pb_bytes(field: u64, data: &[u8]) -> Vec<u8> {
    let mut out = varint((field << 3) | 2);
    out.extend(varint(data.len() as u64));
    out.extend_from_slice(data);
    out
}

/// Protobuf varint field.
pub(crate) fn pb_varint(field: u64, value: u64) -> Vec<u8> {
    let mut out = varint(field << 3);
    out.extend(varint(value));
    out
}

pub(crate) fn random32(env: &dyn Env) -> [u8; 32] {
    let mut b = [0u8; 32];
    env.fill_random(&mut b);
    b
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// AES key, MAC key (both wiped on drop) and IV from 80 HKDF bytes.
pub(super) fn split_keys(keys: &[u8]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>, [u8; 16]) {
    let mut a = Zeroizing::new([0u8; 32]);
    let mut m = Zeroizing::new([0u8; 32]);
    let mut iv = [0u8; 16];
    a.copy_from_slice(&keys[..32]);
    m.copy_from_slice(&keys[32..64]);
    iv.copy_from_slice(&keys[64..80]);
    (a, m, iv)
}

pub(super) fn aes(key: &[u8; 32]) -> Aes256 {
    Aes256::new(&Array::from(*key))
}

pub(crate) fn varint(mut n: u64) -> Vec<u8> {
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

pub(super) fn write_canonical(v: &Value, out: &mut String) {
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
