//! Hashing, MACs, randomness and encodings backed by `ring` (already linked for TLS), so services need no extra crates for common signatures.

use base64::Engine;
use ring::rand::SecureRandom;
use ring::{digest, hmac};

/// Fill `buf` from the system's secure random number generator.
///
/// # Panics
///
/// When the OS random source fails.
#[expect(
    clippy::expect_used,
    reason = "keys, nonces and IVs from an unfilled buffer would be predictable; no caller can recover from a missing OS RNG"
)]
pub fn random_bytes(buf: &mut [u8]) {
    ring::rand::SystemRandom::new().fill(buf).expect("system RNG available");
}

/// Random lowercase hex string of `n_bytes * 2` chars.
pub fn random_hex(n_bytes: usize) -> String {
    let mut b = vec![0u8; n_bytes];
    random_bytes(&mut b);
    hex(&b)
}

/// Random RFC 4122 version 4 UUID.
pub fn uuid4() -> String {
    let mut b = [0u8; 16];
    random_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b);
    let (a, rest) = h.split_at(8);
    let (b, rest) = rest.split_at(4);
    let (c, rest) = rest.split_at(4);
    let (d, e) = rest.split_at(4);
    format!("{a}-{b}-{c}-{d}-{e}")
}

/// Lower-case hex encoding.
pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex decoding; pairs that are not hex digits are skipped, as is an odd last digit.
pub fn unhex(s: &str) -> Vec<u8> {
    let (pairs, _) = s.as_bytes().as_chunks::<2>();
    pairs.iter().filter_map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok()).collect()
}

/// SHA-1 digest (legacy signatures only).
pub fn sha1(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data).as_ref().to_vec()
}
/// SHA-256 digest.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}
/// SHA-512 digest.
pub fn sha512(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA512, data).as_ref().to_vec()
}

/// HMAC-SHA1 of `data` with `key` (legacy signatures only).
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key), data).as_ref().to_vec()
}
/// HMAC-SHA256 of `data` with `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data).as_ref().to_vec()
}
/// HMAC-SHA512 of `data` with `key`.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, key), data).as_ref().to_vec()
}

/// Standard base64 with padding.
pub fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}
/// URL-safe base64 without padding.
pub fn b64_url_nopad(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}
/// Decode standard base64 (surrounding whitespace ignored); `None` if invalid.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s.trim()).ok()
}
/// Decode URL-safe base64, with or without padding; `None` if invalid.
pub fn b64_url_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests() {
        assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            hex(&hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog")),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn uuid() {
        let u = uuid4();
        assert!(crate::parse::is_uuid(&u), "{u}");
    }
}
