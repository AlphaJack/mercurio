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
/// SHA-384 digest.
pub fn sha384(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA384, data).as_ref().to_vec()
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
/// URL-safe base64 with padding.
pub fn b64_url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE.encode(data)
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

/// Unix time in seconds.
pub fn unix_time() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Unix time in milliseconds.
pub fn unix_time_ms() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

const SECS_PER_DAY: u64 = 86_400;
/// Days in a 400-year Gregorian cycle.
const DAYS_PER_ERA: i64 = 146_097;
/// Days from 0000-03-01 to 1970-01-01: the dates below count from March, so leap days end a year.
const EPOCH_FROM_MARCH: i64 = 719_468;

/// Unix seconds at midnight UTC of `year-month-day` (Howard Hinnant's `days_from_civil`).
pub fn unix_secs(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * DAYS_PER_ERA + doe - EPOCH_FROM_MARCH) * SECS_PER_DAY as i64
}

/// UTC timestamp parts `(year, month, day, hour, minute, second)` for `secs` (Howard Hinnant's `civil_from_days`).
pub fn utc_parts(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / SECS_PER_DAY) as i64;
    let rem = secs % SECS_PER_DAY;
    let z = days + EPOCH_FROM_MARCH;
    let era = z.div_euclid(DAYS_PER_ERA);
    let doe = z.rem_euclid(DAYS_PER_ERA);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, (rem / 3600) as u32, ((rem % 3600) / 60) as u32, (rem % 60) as u32)
}

/// RFC 3339 / ISO 8601 UTC timestamp, e.g. `2026-10-16T12:00:00Z`.
pub fn iso8601_utc(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = utc_parts(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// RFC 2822 date, e.g. `Fri, 16 Oct 2026 12:00:00 +0000`.
pub fn rfc2822_utc(secs: u64) -> String {
    let (y, mo, d, h, mi, s) = utc_parts(secs);
    let days = (secs / SECS_PER_DAY) as i64;
    let wd = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][days.rem_euclid(7) as usize];
    let mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][(mo - 1) as usize];
    format!("{wd}, {d:02} {mon} {y:04} {h:02}:{mi:02}:{s:02} +0000")
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
    fn dates() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(1_792_152_000), "2026-10-16T12:00:00Z");
        assert_eq!(iso8601_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc2822_utc(0), "Thu, 01 Jan 1970 00:00:00 +0000");
    }

    #[test]
    fn uuid() {
        let u = uuid4();
        assert!(crate::parse::is_uuid(&u), "{u}");
    }
}
