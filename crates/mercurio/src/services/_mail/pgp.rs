//! OpenPGP for e-mail and Delta Chat (`?pgp=`): detached signatures (RFC 3156) written in-house, with `ring` doing the cryptography.
//!
//! Only what signing needs is implemented (RFC 9580): ASCII armor, the v4 secret key packet of an Ed25519 key in GnuPG's EdDSA encoding (algorithm 22), its fingerprint, and a v4 binary-document signature over SHA-256. Other keys are refused with their algorithm named.

use ring::signature::Ed25519KeyPair;

use crate::crypto;
use crate::env::Env;

/// Why a key could not sign.
#[derive(Debug, PartialEq, Eq)]
pub enum SignError {
    /// Not an OpenPGP secret key.
    Unreadable,
    /// Locked with a passphrase (Apprise does not support those either).
    Protected,
    /// Not an Ed25519 key in GnuPG's encoding (the algorithm is named).
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
            SignError::Algorithm(alg) => {
                format!("PGP Private Key is {alg}; mercurio signs only with Ed25519 keys (GnuPG's EdDSA encoding)")
            }
            SignError::Failed => "PGP signing failed; key may lack Sign capability".into(),
        }
    }
}

/// Packet tags.
const TAG_SIGNATURE: u8 = 2;
const TAG_SECRET_KEY: u8 = 5;
/// Public-key algorithm: EdDSA in GnuPG's (legacy) encoding.
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

/// An unlocked Ed25519 signing key and its v4 fingerprint.
struct Key {
    pair: Ed25519KeyPair,
    fingerprint: [u8; 20],
}

/// Read the primary key of an armored (or binary) secret key.
fn secret_key(data: &[u8]) -> Result<Key, SignError> {
    let bytes = match std::str::from_utf8(data).ok().and_then(dearmor) {
        Some(b) => b,
        None => data.to_vec(),
    };
    let (tag, body) = first_packet(&bytes).ok_or(SignError::Unreadable)?;
    if tag != TAG_SECRET_KEY || body.first() != Some(&4) {
        return Err(SignError::Unreadable);
    }
    let algo = *body.get(5).ok_or(SignError::Unreadable)?;
    let oid_len = usize::from(*body.get(6).ok_or(SignError::Unreadable)?);
    let oid = body.get(7..7 + oid_len).ok_or(SignError::Unreadable)?;
    if algo != ALGO_EDDSA || oid != ED25519_OID {
        return Err(SignError::Algorithm(algorithm_name(algo)));
    }
    let (public, rest) = mpi(body.get(7 + oid_len..).ok_or(SignError::Unreadable)?).ok_or(SignError::Unreadable)?;
    // The native point format: 0x40, then the 32-byte key.
    let public = public.strip_prefix(&[0x40]).filter(|p| p.len() == 32).ok_or(SignError::Unreadable)?;
    let public_part = body.get(..body.len() - rest.len()).ok_or(SignError::Unreadable)?;
    let (usage, rest) = rest.split_first().ok_or(SignError::Unreadable)?;
    if *usage != 0 {
        return Err(SignError::Protected);
    }
    let (secret, _) = mpi(rest).ok_or(SignError::Unreadable)?;
    if secret.len() > 32 {
        return Err(SignError::Unreadable);
    }
    let mut seed = [0u8; 32];
    seed[32 - secret.len()..].copy_from_slice(secret);
    let pair = Ed25519KeyPair::from_seed_and_public_key(&seed, public).map_err(|_| SignError::Failed)?;
    // v4 fingerprint: SHA-1 over 0x99, the public part's length and the public part.
    let len = u16::try_from(public_part.len()).map_err(|_| SignError::Unreadable)?;
    let fingerprint = crypto::sha1(&[&[0x99], len.to_be_bytes().as_slice(), public_part].concat())
        .try_into()
        .map_err(|_| SignError::Unreadable)?;
    Ok(Key { pair, fingerprint })
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

    let mut hashed = vec![4, SIG_BINARY, ALGO_EDDSA, HASH_SHA256];
    hashed.extend_from_slice(&u16::try_from(hashed_sub.len()).unwrap_or(0).to_be_bytes());
    hashed.extend_from_slice(&hashed_sub);
    let trailer_len = u32::try_from(hashed.len()).unwrap_or(0);
    let digest = crypto::sha256(&[data, &hashed, &[4, 0xff], &trailer_len.to_be_bytes()].concat());
    let sig = key.pair.sign(&digest);
    let (r, s) = sig.as_ref().split_at(32);

    let mut body = hashed;
    body.extend_from_slice(&u16::try_from(unhashed_sub.len()).unwrap_or(0).to_be_bytes());
    body.extend_from_slice(&unhashed_sub);
    body.extend_from_slice(digest.get(..2).unwrap_or_default());
    put_mpi(&mut body, r);
    put_mpi(&mut body, s);

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
    use ring::signature::{ED25519, KeyPair, UnparsedPublicKey};

    use super::*;

    const ED25519_KEY: &str = include_str!("../../../tests/fixtures/data/pgp/ed25519.asc");
    const LOCKED_KEY: &str = include_str!("../../../tests/fixtures/data/pgp/ed25519-locked.asc");
    const RSA_KEY: &str = include_str!("../../../tests/fixtures/data/pgp/rsa.asc");
    /// `gpg --fingerprint` of `ED25519_KEY`.
    const ED25519_FPR: &str = "91C4B7D9E4C600F7122145D5B401712C1AE117D4";

    /// Check an armored detached signature over `data` against the GnuPG key: the packet parsed back, the digest recomputed, Ed25519 verified.
    fn verify(sig: &str, data: &[u8]) {
        let packet = dearmor(sig).expect("armor");
        let (tag, body) = first_packet(&packet).expect("packet");
        assert_eq!(tag, TAG_SIGNATURE);
        assert_eq!(&body[..4], &[4, SIG_BINARY, ALGO_EDDSA, HASH_SHA256]);
        let hashed_len = 6 + usize::from(u16::from_be_bytes([body[4], body[5]]));
        let hashed = &body[..hashed_len];
        let unhashed_len = usize::from(u16::from_be_bytes([body[hashed_len], body[hashed_len + 1]]));
        let rest = &body[hashed_len + 2 + unhashed_len..];
        let trailer = u32::try_from(hashed.len()).unwrap().to_be_bytes();
        let digest = crypto::sha256(&[data, hashed, &[4, 0xff], &trailer].concat());
        assert_eq!(&rest[..2], &digest[..2], "hash prefix");
        let (r, rest) = mpi(&rest[2..]).unwrap();
        let (s, _) = mpi(rest).unwrap();
        let pad = |v: &[u8]| [vec![0; 32 - v.len()], v.to_vec()].concat();
        let key = secret_key(ED25519_KEY.as_bytes()).unwrap();
        let public = UnparsedPublicKey::new(&ED25519, key.pair.public_key().as_ref().to_vec());
        public.verify(&digest, &[pad(r), pad(s)].concat()).expect("Ed25519 signature");
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
    fn other_keys_are_refused() {
        let env = crate::testing::test_env();
        assert_eq!(sign(RSA_KEY.as_bytes(), b"x", env), Err(SignError::Algorithm("RSA".into())));
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
