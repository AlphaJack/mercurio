//! OpenPGP for e-mail and Delta Chat (`?pgp=`), written in-house on `ring` (RFC 9580): what the parts share (ASCII armor, packets, MPIs, big-number reduction). Signing is in `sign`, encryption in `encrypt`, key generation and the Autocrypt header in `keys`, Web Key Directory lookups in `wkd`.

use crate::crypto;

mod encrypt;
mod keys;
mod sign;
pub mod wkd;
pub use encrypt::encrypt;
pub use keys::{autocrypt_header, generate};
pub use sign::sign;
use sign::{Key, Signer, signature_packet, subpacket};

/// Packet tags.
const TAG_SIGNATURE: u8 = 2;

const TAG_SECRET_KEY: u8 = 5;

/// Public-key algorithms: RSA (encrypt or sign), RSA sign-only, EdDSA in GnuPG's (legacy) encoding.
const ALGO_RSA: u8 = 1;

const ALGO_RSA_SIGN: u8 = 3;

const ALGO_EDDSA: u8 = 22;

/// ECDH (GnuPG's `cv25519` subkeys).
const ALGO_ECDH: u8 = 18;

/// The curve OID of Curve25519 in GnuPG's ECDH encoding.
const CV25519_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

/// The curve OID of Ed25519 in that encoding.
const ED25519_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];

/// Hash algorithm: SHA-256.
const HASH_SHA256: u8 = 8;

/// Signature type: binary document.
const SIG_BINARY: u8 = 0x00;

/// A readable algorithm name for a refused key.
fn algorithm_name(algo: u8) -> String {
    match algo {
        1..=3 => "RSA".into(),
        16 => "ElGamal".into(),
        17 => "DSA".into(),
        18 => "ECDH".into(),
        19 => "ECDSA".into(),
        22 => "EdDSA on a curve other than Ed25519".into(),
        27 => "Ed25519 in the RFC 9580 encoding".into(),
        28 => "X25519".into(),
        other => format!("algorithm {other}"),
    }
}

/// CRC-24 of RFC 9580 section 6.1.
fn crc24(data: &[u8]) -> u32 {
    let mut crc: u32 = 0x00b7_04ce;
    for &b in data {
        crc ^= u32::from(b) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4cfb;
            }
        }
    }
    crc & 0x00ff_ffff
}

/// The bytes inside an ASCII-armored block (its checksum checked when present); `None` when it is not armor.
fn dearmor(text: &str) -> Option<Vec<u8>> {
    let mut lines = text.lines().map(str::trim).skip_while(|l| !l.starts_with("-----BEGIN PGP "));
    lines.next()?;
    // Armor headers (`Version: ...`) end at the first blank line.
    let mut body = String::new();
    let mut checksum = None;
    let mut in_headers = true;
    for line in lines {
        if line.starts_with("-----END PGP ") {
            break;
        }
        if in_headers {
            if line.is_empty() {
                in_headers = false;
            } else if !line.contains(": ") {
                in_headers = false;
                body.push_str(line);
            }
            continue;
        }
        match line.strip_prefix('=') {
            Some(sum) if sum.len() == 4 => checksum = Some(sum.to_string()),
            _ => body.push_str(line),
        }
    }
    let data = crypto::b64_decode(&body)?;
    if let Some(sum) = checksum {
        let crc = crc24(&data).to_be_bytes();
        if crypto::b64_decode(&sum)? != crc[1..] {
            return None;
        }
    }
    Some(data)
}

/// The first packet: its tag and body (see [`next_packet`]).
fn first_packet(data: &[u8]) -> Option<(u8, &[u8])> {
    next_packet(data).map(|(tag, body, _)| (tag, body))
}

/// The packet at the start of `data`: its tag, its body and what follows it. Old and new packet formats; partial and indeterminate lengths are refused (keys never use them).
fn next_packet(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let head = *data.first()?;
    if head & 0x80 == 0 {
        return None;
    }
    let (tag, len, start): (u8, usize, usize) = if head & 0x40 != 0 {
        let tag = head & 0x3f;
        match *data.get(1)? {
            l @ 0..=191 => (tag, usize::from(l), 2),
            l @ 192..=223 => (tag, (usize::from(l) - 192) * 256 + usize::from(*data.get(2)?) + 192, 3),
            255 => (tag, usize::try_from(u32::from_be_bytes(data.get(2..6)?.try_into().ok()?)).ok()?, 6),
            224..=254 => return None,
        }
    } else {
        let tag = (head >> 2) & 0x0f;
        match head & 0x03 {
            0 => (tag, usize::from(*data.get(1)?), 2),
            1 => (tag, usize::from(u16::from_be_bytes(data.get(1..3)?.try_into().ok()?)), 3),
            2 => (tag, usize::try_from(u32::from_be_bytes(data.get(1..5)?.try_into().ok()?)).ok()?, 5),
            _ => return None,
        }
    };
    let end = start.checked_add(len)?;
    Some((tag, data.get(start..end)?, data.get(end..)?))
}

/// A multiprecision integer at the start of `b` (its value without leading zeros), and what follows it.
fn mpi(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let bits = usize::from(u16::from_be_bytes(b.get(..2)?.try_into().ok()?));
    let len = bits.div_ceil(8);
    Some((b.get(2..2 + len)?, b.get(2 + len..)?))
}

/// `value` as an MPI: its bit count, then its bytes without leading zeros.
fn put_mpi(out: &mut Vec<u8>, value: &[u8]) {
    let skip = value.iter().take_while(|b| **b == 0).count();
    let value = value.get(skip..).unwrap_or_default();
    let bits = value.first().map_or(0, |b| 8 - b.leading_zeros() as usize + 8 * (value.len() - 1));
    out.extend_from_slice(&u16::try_from(bits).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(value);
}

/// Big-endian magnitude to `count` little-endian 64-bit limbs.
fn limbs(be: &[u8], count: usize) -> Vec<u64> {
    let mut out = vec![0u64; count];
    for (i, b) in be.iter().rev().enumerate() {
        if let Some(limb) = out.get_mut(i / 8) {
            *limb |= u64::from(*b) << (8 * (i % 8));
        }
    }
    out
}

/// Little-endian limbs back to a big-endian magnitude of `len` bytes.
fn magnitude(limbs: &[u64], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for (i, b) in out.iter_mut().rev().enumerate() {
        *b = limbs.get(i / 8).map_or(0, |l| (l >> (8 * (i % 8))).to_le_bytes()[0]);
    }
    out
}

/// `a mod m` for big-endian magnitudes (`m` non-zero). Every bit of `a` takes the same steps, the subtraction kept or dropped by a mask, so the time does not depend on the secret values.
fn big_mod(a: &[u8], m: &[u8]) -> Vec<u8> {
    let n = m.len().div_ceil(8) + 1;
    let m = limbs(m, n);
    let mut r = vec![0u64; n];
    let mut t = vec![0u64; n];
    for byte in a {
        for bit in (0..8).rev() {
            // r = 2r + bit: r < m before, so r < 2m after, and one conditional subtraction keeps r < m.
            let mut carry = u64::from((byte >> bit) & 1);
            for limb in &mut r {
                let next = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = next;
            }
            let mut borrow = 0u64;
            for ((ti, ri), mi) in t.iter_mut().zip(&r).zip(&m) {
                let (d1, b1) = ri.overflowing_sub(*mi);
                let (d2, b2) = d1.overflowing_sub(borrow);
                *ti = d2;
                borrow = u64::from(b1 | b2);
            }
            // No borrow: r ≥ m, so r becomes t.
            let keep = borrow.wrapping_sub(1);
            for (ri, ti) in r.iter_mut().zip(&t) {
                *ri = (*ti & keep) | (*ri & !keep);
            }
        }
    }
    magnitude(&r, (n - 1) * 8)
}

/// `x − 1` for a big-endian magnitude greater than zero.
fn minus_one(x: &[u8]) -> Vec<u8> {
    let mut out = x.to_vec();
    for b in out.iter_mut().rev() {
        let (v, borrow) = b.overflowing_sub(1);
        *b = v;
        if !borrow {
            break;
        }
    }
    out
}

/// A new-format packet with the shortest length encoding.
fn packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0xc0 | tag];
    match body.len() {
        l @ 0..=191 => out.push(u8::try_from(l).unwrap_or(0)),
        l @ 192..=8383 => {
            let l = l - 192;
            out.extend_from_slice(&[u8::try_from(l / 256 + 192).unwrap_or(0), u8::try_from(l % 256).unwrap_or(0)]);
        }
        l => {
            out.push(255);
            out.extend_from_slice(&u32::try_from(l).unwrap_or(u32::MAX).to_be_bytes());
        }
    }
    out.extend_from_slice(body);
    out
}

/// ASCII armor with CRLF line endings: 64-character base64 lines and the CRC-24 checksum.
fn armor(kind: &str, data: &[u8]) -> String {
    let b64 = crypto::b64(data);
    let mut out = format!("-----BEGIN PGP {kind}-----\r\n\r\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push_str("\r\n");
    }
    let crc = crc24(data).to_be_bytes();
    out.push_str(&format!("={}\r\n-----END PGP {kind}-----\r\n", crypto::b64(crc.get(1..).unwrap_or_default())));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn big_mod_matches_integers() {
        let be = |v: u128| v.to_be_bytes().to_vec();
        let trim = |v: Vec<u8>| v.into_iter().skip_while(|b| *b == 0).collect::<Vec<_>>();
        for (a, m) in [(0u128, 7u128), (6, 7), (7, 7), (1 << 100, 1_000_003), (u128::MAX, u64::MAX as u128), (12_345_678_901_234_567_890, 97)] {
            assert_eq!(trim(big_mod(&be(a), &trim(be(m)))), trim(be(a % m)), "{a} mod {m}");
        }
        assert_eq!(minus_one(&[1, 0, 0]), [0, 0xff, 0xff]);
    }

    #[test]
    fn crc24_vector() {
        assert_eq!(crc24(b""), 0x00b7_04ce);
        assert_eq!(crc24(b"123456789"), 0x0021_cf02);
    }

    /// A scripted SMTP server on `fake`: the lines of every message it receives (dot-stuffing undone).
    pub(super) fn capture_smtp(fake: &crate::testing::FakeTransport) -> std::sync::Arc<std::sync::Mutex<Vec<String>>> {
        use std::sync::{Arc, Mutex};

        use crate::testing::ScriptedConn;

        let data = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = data.clone();
        let mut in_data = false;
        let conn = ScriptedConn::lines("220 hi\r\n", move |line| {
            if in_data {
                if line == "." {
                    in_data = false;
                    return Some("250 queued\r\n".into());
                }
                // SMTP dot-stuffing: a leading `..` stands for `.`.
                let line = line.strip_prefix('.').filter(|l| l.starts_with('.')).unwrap_or(line);
                seen.lock().unwrap().push(line.to_string());
                return None;
            }
            Some(
                match line.split(' ').next().unwrap_or("") {
                    "EHLO" => "250-x\r\n250 AUTH PLAIN\r\n",
                    "AUTH" => "235 ok\r\n",
                    "DATA" => {
                        in_data = true;
                        "354 go\r\n"
                    }
                    "QUIT" => "221 bye\r\n",
                    _ => "250 ok\r\n",
                }
                .into(),
            )
        });
        fake.push_conn(conn);
        data
    }
}
