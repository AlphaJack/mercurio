//! OpenPGP for e-mail and Delta Chat (`?pgp=`): detached signatures (RFC 3156) written in-house, with `ring` doing the cryptography.
//!
//! Only what signing needs is implemented (RFC 9580): ASCII armor, the v4 secret key packet of an Ed25519 key in GnuPG's EdDSA encoding (algorithm 22) or of an RSA key (algorithms 1 and 3, 2048 to 8192 bits), its fingerprint, and a v4 binary-document signature over SHA-256. Other keys are refused with their algorithm named.
//!
//! An RSA key is handed to `ring` as PKCS#1: OpenPGP keeps `u = p⁻¹ mod q`, so `p` and `q` trade places and `u` becomes PKCS#1's `q⁻¹ mod p` as it is; only `d mod (p − 1)` and `d mod (q − 1)` are computed, by a reduction that runs the same steps whatever the secret values.

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};

use crate::crypto;
use crate::env::Env;

/// Why a key could not sign.
#[derive(Debug, PartialEq, Eq)]
pub enum SignError {
    /// Not an OpenPGP secret key.
    Unreadable,
    /// Locked with a passphrase (Apprise does not support those either).
    Protected,
    /// Neither Ed25519 in GnuPG's encoding nor RSA of 2048 to 8192 bits (the algorithm is named).
    Algorithm(String),
    /// The key material is inconsistent (the secret does not match the public key).
    Failed,
}

impl SignError {
    /// The warning Apprise logs (or mercurio's, for the algorithm).
    pub fn warning(&self) -> String {
        match self {
            SignError::Unreadable => "PGP Private Key file could not be parsed".into(),
            SignError::Protected => {
                "PGP Private Key is passphrase-protected; Apprise does not support passphrase-protected keys".into()
            }
            SignError::Algorithm(alg) => format!(
                "PGP Private Key is {alg}; mercurio signs with Ed25519 keys (GnuPG's EdDSA encoding) and RSA keys of 2048 to \
                 8192 bits"
            ),
            SignError::Failed => "PGP signing failed; key may lack Sign capability".into(),
        }
    }
}

/// Packet tags.
const TAG_SIGNATURE: u8 = 2;
const TAG_SECRET_KEY: u8 = 5;
/// Public-key algorithms: RSA (encrypt or sign), RSA sign-only, EdDSA in GnuPG's (legacy) encoding.
const ALGO_RSA: u8 = 1;
const ALGO_RSA_SIGN: u8 = 3;
const ALGO_EDDSA: u8 = 22;
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

/// The first packet: its tag and body. Old and new packet formats; partial and indeterminate lengths are refused (keys never use them).
fn first_packet(data: &[u8]) -> Option<(u8, &[u8])> {
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
    Some((tag, data.get(start..start.checked_add(len)?)?))
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

/// An unlocked signing key.
enum Signer {
    Ed25519(Ed25519KeyPair),
    Rsa(RsaKeyPair),
}

/// An unlocked primary key: how it signs, its algorithm id and its v4 fingerprint.
struct Key {
    signer: Signer,
    algo: u8,
    fingerprint: [u8; 20],
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

/// A DER length.
fn der_len(out: &mut Vec<u8>, len: usize) {
    match (u8::try_from(len), u16::try_from(len)) {
        (Ok(l), _) if l < 0x80 => out.push(l),
        (Ok(l), _) => out.extend_from_slice(&[0x81, l]),
        (Err(_), Ok(l)) => {
            out.push(0x82);
            out.extend_from_slice(&l.to_be_bytes());
        }
        (Err(_), Err(_)) => {
            out.push(0x84);
            out.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes());
        }
    }
}

/// A DER INTEGER for a non-negative magnitude.
fn der_uint(out: &mut Vec<u8>, value: &[u8]) {
    let skip = value.iter().take_while(|b| **b == 0).count();
    let value = value.get(skip..).unwrap_or_default();
    let pad = value.first().is_none_or(|b| b & 0x80 != 0);
    out.push(0x02);
    der_len(out, value.len() + usize::from(pad));
    if pad {
        out.push(0);
    }
    out.extend_from_slice(value);
}

/// PKCS#1 `RSAPrivateKey` from OpenPGP's `n, e, d, p, q, u` (`u = p⁻¹ mod q`): `p` and `q` trade places, so `u` is PKCS#1's `q⁻¹ mod p`.
fn rsa_pkcs1(n: &[u8], e: &[u8], d: &[u8], p: &[u8], q: &[u8], u: &[u8]) -> Vec<u8> {
    let (p, q) = (q, p);
    let dp = zeroize::Zeroizing::new(big_mod(d, &minus_one(p)));
    let dq = zeroize::Zeroizing::new(big_mod(d, &minus_one(q)));
    let mut body = Vec::new();
    for v in [&[0u8][..], n, e, d, p, q, &dp, &dq, u] {
        der_uint(&mut body, v);
    }
    let mut der = vec![0x30];
    der_len(&mut der, body.len());
    der.extend_from_slice(&body);
    body.iter_mut().for_each(|b| *b = 0);
    der
}


/// Read the primary key of an armored (or binary) secret key.
fn secret_key(data: &[u8]) -> Result<Key, SignError> {
    let bytes = match std::str::from_utf8(data).ok().and_then(dearmor) {
        Some(b) => zeroize::Zeroizing::new(b),
        None => zeroize::Zeroizing::new(data.to_vec()),
    };
    let (tag, body) = first_packet(&bytes).ok_or(SignError::Unreadable)?;
    if tag != TAG_SECRET_KEY || body.first() != Some(&4) {
        return Err(SignError::Unreadable);
    }
    let algo = *body.get(5).ok_or(SignError::Unreadable)?;
    let params = body.get(6..).ok_or(SignError::Unreadable)?;
    let (public, rest): (Vec<&[u8]>, &[u8]) = match algo {
        ALGO_RSA | ALGO_RSA_SIGN => {
            let (n, rest) = mpi(params).ok_or(SignError::Unreadable)?;
            let (e, rest) = mpi(rest).ok_or(SignError::Unreadable)?;
            (vec![n, e], rest)
        }
        ALGO_EDDSA => {
            let oid_len = usize::from(*params.first().ok_or(SignError::Unreadable)?);
            if params.get(1..1 + oid_len) != Some(ED25519_OID) {
                return Err(SignError::Algorithm(algorithm_name(algo)));
            }
            let point = params.get(1 + oid_len..).ok_or(SignError::Unreadable)?;
            let (point, rest) = mpi(point).ok_or(SignError::Unreadable)?;
            (vec![point], rest)
        }
        other => return Err(SignError::Algorithm(algorithm_name(other))),
    };
    let public_part = body.get(..body.len() - rest.len()).ok_or(SignError::Unreadable)?;
    let (usage, secret) = rest.split_first().ok_or(SignError::Unreadable)?;
    if *usage != 0 {
        return Err(SignError::Protected);
    }
    let signer = match public[..] {
        [n, e] => {
            let bits = n.len() * 8 - n.first().map_or(8, |b| b.leading_zeros() as usize);
            if !(2048..=8192).contains(&bits) {
                return Err(SignError::Algorithm(format!("RSA-{bits}")));
            }
            let (d, rest) = mpi(secret).ok_or(SignError::Unreadable)?;
            let (p, rest) = mpi(rest).ok_or(SignError::Unreadable)?;
            let (q, rest) = mpi(rest).ok_or(SignError::Unreadable)?;
            let (u, _) = mpi(rest).ok_or(SignError::Unreadable)?;
            let der = zeroize::Zeroizing::new(rsa_pkcs1(n, e, d, p, q, u));
            Signer::Rsa(RsaKeyPair::from_der(&der).map_err(|_| SignError::Failed)?)
        }
        [point] => {
            // The native point format: 0x40, then the 32-byte key.
            let public = point.strip_prefix(&[0x40]).filter(|p| p.len() == 32).ok_or(SignError::Unreadable)?;
            let (secret, _) = mpi(secret).ok_or(SignError::Unreadable)?;
            if secret.len() > 32 {
                return Err(SignError::Unreadable);
            }
            let mut seed = zeroize::Zeroizing::new([0u8; 32]);
            seed[32 - secret.len()..].copy_from_slice(secret);
            Signer::Ed25519(Ed25519KeyPair::from_seed_and_public_key(&*seed, public).map_err(|_| SignError::Failed)?)
        }
        _ => return Err(SignError::Unreadable),
    };
    // v4 fingerprint: SHA-1 over 0x99, the public part's length and the public part.
    let len = u16::try_from(public_part.len()).map_err(|_| SignError::Unreadable)?;
    let fingerprint = crypto::sha1(&[&[0x99], len.to_be_bytes().as_slice(), public_part].concat())
        .try_into()
        .map_err(|_| SignError::Unreadable)?;
    Ok(Key { signer, algo, fingerprint })
}

/// A subpacket: its length (type byte included), type and data.
fn subpacket(out: &mut Vec<u8>, kind: u8, data: &[u8]) {
    out.push(u8::try_from(data.len() + 1).unwrap_or(u8::MAX));
    out.push(kind);
    out.extend_from_slice(data);
}

/// A detached, armored signature over `data` (SHA-256, binary document) with the key's primary key, as Apprise signs, and its `micalg` label.
pub fn sign(key: &[u8], data: &[u8], env: &dyn Env) -> Result<(String, &'static str), SignError> {
    let key = secret_key(key)?;
    let created = u32::try_from(env.unix_time()).unwrap_or(u32::MAX);
    let mut hashed_sub = Vec::new();
    subpacket(&mut hashed_sub, 2, &created.to_be_bytes());
    subpacket(&mut hashed_sub, 33, &[[4].as_slice(), &key.fingerprint].concat());
    let mut unhashed_sub = Vec::new();
    subpacket(&mut unhashed_sub, 16, key.fingerprint.get(12..).unwrap_or_default());

    let mut hashed = vec![4, SIG_BINARY, key.algo, HASH_SHA256];
    hashed.extend_from_slice(&u16::try_from(hashed_sub.len()).unwrap_or(0).to_be_bytes());
    hashed.extend_from_slice(&hashed_sub);
    let trailer_len = u32::try_from(hashed.len()).unwrap_or(0);
    let signed = [data, &hashed, &[4, 0xff], &trailer_len.to_be_bytes()].concat();
    let digest = crypto::sha256(&signed);

    let mut body = hashed;
    body.extend_from_slice(&u16::try_from(unhashed_sub.len()).unwrap_or(0).to_be_bytes());
    body.extend_from_slice(&unhashed_sub);
    body.extend_from_slice(digest.get(..2).unwrap_or_default());
    match &key.signer {
        // EdDSA signs the hash: the two halves R and S.
        Signer::Ed25519(pair) => {
            let sig = pair.sign(&digest);
            let (r, s) = sig.as_ref().split_at(32);
            put_mpi(&mut body, r);
            put_mpi(&mut body, s);
        }
        // RSA PKCS#1 v1.5 over SHA-256, hashed by ring from the same bytes.
        Signer::Rsa(pair) => {
            let mut sig = vec![0u8; pair.public().modulus_len()];
            #[expect(clippy::disallowed_methods, reason = "ring's SecureRandom is sealed; the signature does not depend on it")]
            let rng = SystemRandom::new();
            pair.sign(&RSA_PKCS1_SHA256, &rng, &signed, &mut sig).map_err(|_| SignError::Failed)?;
            put_mpi(&mut body, &sig);
        }
    }

    let mut packet = vec![0xc0 | TAG_SIGNATURE];
    match u16::try_from(body.len()) {
        Ok(l @ 0..=191) => packet.push(l.to_be_bytes()[1]),
        Ok(l) => {
            let l = l - 192;
            packet.extend_from_slice(&[(l / 256 + 192).to_be_bytes()[1], (l % 256).to_be_bytes()[1]]);
        }
        Err(_) => return Err(SignError::Failed),
    }
    packet.extend_from_slice(&body);
    Ok((armor("SIGNATURE", &packet), "pgp-sha256"))
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
    use ring::signature::{ED25519, KeyPair, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

    use super::*;

    const ED25519_KEY: &str = include_str!("../../../tests/fixtures/data/pgp/ed25519.asc");
    const LOCKED_KEY: &str = include_str!("../../../tests/fixtures/data/pgp/ed25519-locked.asc");
    const RSA_KEY: &str = include_str!("../../../tests/fixtures/data/pgp/rsa.asc");
    /// `gpg --fingerprint` of `ED25519_KEY`.
    const ED25519_FPR: &str = "91C4B7D9E4C600F7122145D5B401712C1AE117D4";

    /// Check an armored detached signature over `data` against `key` (armored): the packet parsed back, the digest recomputed, the signature verified.
    fn verify_with(key: &str, sig: &str, data: &[u8]) {
        let packet = dearmor(sig).expect("armor");
        let (tag, body) = first_packet(&packet).expect("packet");
        assert_eq!(tag, TAG_SIGNATURE);
        let key = secret_key(key.as_bytes()).unwrap();
        assert_eq!(&body[..4], &[4, SIG_BINARY, key.algo, HASH_SHA256]);
        let hashed_len = 6 + usize::from(u16::from_be_bytes([body[4], body[5]]));
        let hashed = &body[..hashed_len];
        let unhashed_len = usize::from(u16::from_be_bytes([body[hashed_len], body[hashed_len + 1]]));
        let rest = &body[hashed_len + 2 + unhashed_len..];
        let trailer = u32::try_from(hashed.len()).unwrap().to_be_bytes();
        let digest = crypto::sha256(&[data, hashed, &[4, 0xff], &trailer].concat());
        assert_eq!(&rest[..2], &digest[..2], "hash prefix");
        let pad = |v: &[u8], n: usize| [vec![0; n - v.len()], v.to_vec()].concat();
        match &key.signer {
            Signer::Ed25519(pair) => {
                let (r, rest) = mpi(&rest[2..]).unwrap();
                let (s, _) = mpi(rest).unwrap();
                let public = UnparsedPublicKey::new(&ED25519, pair.public_key().as_ref().to_vec());
                public.verify(&digest, &[pad(r, 32), pad(s, 32)].concat()).expect("Ed25519 signature");
            }
            Signer::Rsa(pair) => {
                let (s, _) = mpi(&rest[2..]).unwrap();
                let signed = [data, hashed, &[4, 0xff], &trailer].concat();
                let public = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pair.public().as_ref().to_vec());
                public.verify(&signed, &pad(s, pair.public().modulus_len())).expect("RSA signature");
            }
        }
    }

    fn verify(sig: &str, data: &[u8]) {
        verify_with(ED25519_KEY, sig, data);
    }

    #[test]
    fn gnupg_key_fingerprint() {
        let key = secret_key(ED25519_KEY.as_bytes()).unwrap();
        assert_eq!(crypto::hex(&key.fingerprint).to_uppercase(), ED25519_FPR);
    }

    #[test]
    fn signatures_verify() {
        let data = b"Content-Type: text/plain\r\n\r\nhello";
        let (sig, micalg) = sign(ED25519_KEY.as_bytes(), data, crate::testing::test_env()).unwrap();
        assert_eq!(micalg, "pgp-sha256");
        assert!(sig.starts_with("-----BEGIN PGP SIGNATURE-----\r\n\r\n"), "{sig}");
        assert!(sig.ends_with("-----END PGP SIGNATURE-----\r\n"), "{sig}");
        assert!(!sig.replace("\r\n", "").contains('\n'), "CRLF line endings: {sig}");
        verify(&sig, data);
    }

    #[test]
    fn rsa_signatures_verify() {
        let data = b"Content-Type: text/plain\r\n\r\nhello";
        let (sig, micalg) = sign(RSA_KEY.as_bytes(), data, crate::testing::test_env()).unwrap();
        assert_eq!(micalg, "pgp-sha256");
        verify_with(RSA_KEY, &sig, data);
    }

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
    fn other_keys_are_refused() {
        let env = crate::testing::test_env();
        assert_eq!(sign(LOCKED_KEY.as_bytes(), b"x", env), Err(SignError::Protected));
        assert_eq!(sign(b"not a key", b"x", env), Err(SignError::Unreadable));
        // A damaged armor checksum.
        let damaged = ED25519_KEY.replacen("lFgE", "lFgF", 1);
        assert_eq!(sign(damaged.as_bytes(), b"x", env), Err(SignError::Unreadable));
    }

    #[test]
    fn crc24_vector() {
        assert_eq!(crc24(b""), 0x00b7_04ce);
        assert_eq!(crc24(b"123456789"), 0x0021_cf02);
    }

    /// A signed e-mail end to end: the key from `?pgpprv=`, the message through a scripted SMTP server, the signature checked over the exact signed part.
    #[test]
    fn signed_mail_verifies() {
        use std::sync::{Arc, Mutex};

        use crate::testing::{FakeTransport, ScriptedConn};
        use crate::{Asset, Message};

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
        let fake = FakeTransport::new();
        fake.push_conn(conn);
        fake.file("/keys/me.asc", ED25519_KEY);
        let url = "mailto://user:pass@example.com:2525?to=bob@example.org&pgp=sign&pgpprv=/keys/me.asc";
        let d = crate::parse(url).unwrap().send(&Message::new("hello").title("T"), &fake, &Asset::default());
        assert!(d.is_success(), "{d:?}");

        let mail = data.lock().unwrap().join("\r\n");
        let head = mail.lines().find(|l| l.starts_with("Content-Type: multipart/signed")).expect(&mail);
        assert!(head.contains("micalg=\"pgp-sha256\"; protocol=\"application/pgp-signature\""), "{head}");
        let boundary = head.split("boundary=\"").nth(1).unwrap().trim_end_matches('"');
        let parts: Vec<&str> = mail.split(&format!("--{boundary}")).collect();
        let signed = parts[1].strip_prefix("\r\n").unwrap().strip_suffix("\r\n").unwrap();
        let sig_part = parts[2];
        assert!(sig_part.contains("Content-Type: application/pgp-signature\r\n"), "{sig_part}");
        assert!(sig_part.contains("Content-Disposition: attachment; filename=\"signature.asc\""), "{sig_part}");
        let armored = format!("-----BEGIN{}", sig_part.split_once("-----BEGIN").unwrap().1);
        verify(&armored, signed.as_bytes());
        assert!(signed.contains("hello"), "{signed}");
    }
}
