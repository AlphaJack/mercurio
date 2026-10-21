//! Encryption to a recipient's public key (RFC 9580): the key's encryption subkey picked by its key flags, the session key sealed for it (PKESK v3), and the message in a SEIPD v1 packet (AES-256 CFB with a modification detection code), not compressed.
//!
//! Recipients: Curve25519 ECDH (GnuPG's `cv25519`, RFC 6637 key derivation and AES key wrap) and RSA (PKCS#1 v1.5, public-key arithmetic only).

use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use curve25519_dalek::montgomery::MontgomeryPoint;
use zeroize::Zeroizing;

use super::{ALGO_RSA, armor, big_mod, dearmor, limbs, magnitude, mpi, next_packet, put_mpi};
use crate::crypto;
use crate::env::Env;

/// Why a public key could not be used.
#[derive(Debug, PartialEq, Eq)]
pub enum EncryptError {
    /// Not an OpenPGP public key.
    Unreadable,
    /// No key in it may encrypt.
    NoEncryptionKey,
    /// The encryption key's algorithm is not supported (named).
    Algorithm(String),
}

impl EncryptError {
    /// The warning logged before Apprise's "Unable to encrypt" error.
    pub fn warning(&self) -> String {
        match self {
            EncryptError::Unreadable => "PGP Public Key file could not be parsed".into(),
            EncryptError::NoEncryptionKey => "PGP Public Key has no key that may encrypt".into(),
            EncryptError::Algorithm(alg) => {
                format!("PGP Public Key encrypts with {alg}; mercurio encrypts to Curve25519 (cv25519) and RSA keys")
            }
        }
    }
}

const TAG_PKESK: u8 = 1;
const TAG_SIGNATURE: u8 = 2;
const TAG_PUBLIC_KEY: u8 = 6;
const TAG_LITERAL: u8 = 11;
const TAG_PUBLIC_SUBKEY: u8 = 14;
const TAG_SEIPD: u8 = 18;
const TAG_MDC: u8 = 19;
const ALGO_RSA_ENCRYPT: u8 = 2;
const ALGO_ECDH: u8 = 18;
/// The curve OID of Curve25519 in GnuPG's ECDH encoding.
const CV25519_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
/// Symmetric algorithms: AES-128, AES-192, AES-256.
const SYM_AES128: u8 = 7;
const SYM_AES192: u8 = 8;
const SYM_AES256: u8 = 9;
/// Key flags that allow encryption (communications, storage).
const FLAGS_ENCRYPT: u8 = 0x04 | 0x08;

/// AES with a 128, 192 or 256-bit key.
enum Aes {
    A128(Box<Aes128>),
    A192(Box<Aes192>),
    A256(Box<Aes256>),
}

impl Aes {
    fn new(key: &[u8]) -> Option<Aes> {
        Some(match key.len() {
            16 => Aes::A128(Box::new(Aes128::new_from_slice(key).ok()?)),
            24 => Aes::A192(Box::new(Aes192::new_from_slice(key).ok()?)),
            32 => Aes::A256(Box::new(Aes256::new_from_slice(key).ok()?)),
            _ => return None,
        })
    }

    fn encrypt(&self, block: &mut [u8; 16]) {
        let mut b = Array::from(*block);
        match self {
            Aes::A128(c) => c.encrypt_block(&mut b),
            Aes::A192(c) => c.encrypt_block(&mut b),
            Aes::A256(c) => c.encrypt_block(&mut b),
        }
        *block = b.into();
    }
}

/// RFC 3394 AES key wrap of `plain` (a multiple of 8 bytes) under `kek`.
fn key_wrap(kek: &[u8], plain: &[u8]) -> Option<Vec<u8>> {
    let aes = Aes::new(kek)?;
    let mut a = [0xa6u8; 8];
    let mut r: Vec<[u8; 8]> = plain.as_chunks::<8>().0.to_vec();
    let n = r.len();
    for j in 0..6 {
        for (i, ri) in r.iter_mut().enumerate() {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&a);
            b[8..].copy_from_slice(ri);
            aes.encrypt(&mut b);
            let t = u64::try_from(n * j + i + 1).unwrap_or(0).to_be_bytes();
            for (k, ak) in a.iter_mut().enumerate() {
                *ak = b[k] ^ t[k];
            }
            ri.copy_from_slice(&b[8..]);
        }
    }
    Some([a.as_slice(), &r.concat()].concat())
}

/// OpenPGP's CFB mode as SEIPD uses it: a zero IV and no resynchronisation.
fn cfb(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let aes = Aes::new(key)?;
    let mut prev = [0u8; 16];
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut ks = prev;
        aes.encrypt(&mut ks);
        let start = out.len();
        out.extend(chunk.iter().zip(ks.iter()).map(|(p, k)| p ^ k));
        if chunk.len() == 16 {
            prev.copy_from_slice(&out[start..]);
        }
    }
    Some(out)
}

/// Big-endian magnitudes multiplied.
fn big_mul(a: &[u8], b: &[u8]) -> Vec<u8> {
    let (la, lb) = (limbs(a, a.len().div_ceil(8)), limbs(b, b.len().div_ceil(8)));
    let mut out = vec![0u64; la.len() + lb.len()];
    for (i, x) in la.iter().enumerate() {
        let mut carry = 0u128;
        for (j, y) in lb.iter().enumerate() {
            let t = u128::from(out[i + j]) + u128::from(*x) * u128::from(*y) + carry;
            out[i + j] = t as u64;
            carry = t >> 64;
        }
        out[i + lb.len()] = carry as u64;
    }
    magnitude(&out, out.len() * 8)
}

/// `base^exp mod m` (public values only: RSA encryption).
fn mod_pow(base: &[u8], exp: &[u8], m: &[u8]) -> Vec<u8> {
    let base = big_mod(base, m);
    let mut r = vec![1u8];
    let mut started = false;
    for byte in exp {
        for bit in (0..8).rev() {
            if started {
                r = big_mod(&big_mul(&r, &r), m);
            }
            if (byte >> bit) & 1 == 1 {
                r = if started { big_mod(&big_mul(&r, &base), m) } else { base.clone() };
                started = true;
            }
        }
    }
    r
}

/// The public key packets of a certificate: each key's body and the key flags its self-signatures give it.
struct Candidate<'a> {
    subkey: bool,
    body: &'a [u8],
    flags: Option<u8>,
}

/// The key flags (subpacket 27) in the hashed area of a v4 signature.
fn key_flags(sig: &[u8]) -> Option<u8> {
    if sig.first() != Some(&4) {
        return None;
    }
    let len = usize::from(u16::from_be_bytes(sig.get(4..6)?.try_into().ok()?));
    let mut area = sig.get(6..6 + len)?;
    while let Some(&first) = area.first() {
        let (sub_len, head) = match first {
            0..=191 => (usize::from(first), 1),
            192..=254 => ((usize::from(first) - 192) * 256 + usize::from(*area.get(1)?) + 192, 2),
            255 => (usize::try_from(u32::from_be_bytes(area.get(1..5)?.try_into().ok()?)).ok()?, 5),
        };
        let sub = area.get(head..head + sub_len)?;
        if sub.first().map(|t| t & 0x7f) == Some(27) {
            return sub.get(1).copied();
        }
        area = area.get(head + sub_len..)?;
    }
    None
}

/// The keys of an armored (or binary) certificate, with their key flags.
fn candidates(data: &[u8]) -> Result<Vec<Candidate<'_>>, EncryptError> {
    let mut rest = data;
    let mut keys: Vec<Candidate<'_>> = Vec::new();
    while !rest.is_empty() {
        let (tag, body, next) = next_packet(rest).ok_or(EncryptError::Unreadable)?;
        rest = next;
        match tag {
            TAG_PUBLIC_KEY | TAG_PUBLIC_SUBKEY => {
                keys.push(Candidate { subkey: tag == TAG_PUBLIC_SUBKEY, body, flags: None });
            }
            TAG_SIGNATURE => {
                if let (Some(key), Some(flags)) = (keys.last_mut(), key_flags(body)) {
                    key.flags = Some(key.flags.unwrap_or(0) | flags);
                }
            }
            _ => {}
        }
    }
    if keys.first().is_none_or(|k| k.subkey) {
        return Err(EncryptError::Unreadable);
    }
    Ok(keys)
}

/// A key that may encrypt.
enum Recipient {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Cv25519 { point: [u8; 32], hash: u8, kek: u8 },
}

/// The encryption key of a certificate: the first subkey whose flags allow encryption, else the primary key when its flags (or, without flags, its algorithm) allow it.
fn recipient(data: &[u8]) -> Result<(Recipient, [u8; 20]), EncryptError> {
    let keys = candidates(data)?;
    let may_encrypt = |k: &Candidate<'_>| match k.flags {
        Some(f) => f & FLAGS_ENCRYPT != 0,
        None => matches!(k.body.get(5), Some(&(ALGO_RSA | ALGO_RSA_ENCRYPT | ALGO_ECDH))),
    };
    let key = keys
        .iter()
        .filter(|k| k.subkey)
        .find(|k| may_encrypt(k))
        .or_else(|| keys.first().filter(|k| may_encrypt(k)))
        .ok_or(EncryptError::NoEncryptionKey)?;
    let body = key.body;
    if body.first() != Some(&4) {
        return Err(EncryptError::Algorithm(format!("a version {} key", body.first().copied().unwrap_or(0))));
    }
    let algo = *body.get(5).ok_or(EncryptError::Unreadable)?;
    let params = body.get(6..).ok_or(EncryptError::Unreadable)?;
    let recipient = match algo {
        ALGO_RSA | ALGO_RSA_ENCRYPT => {
            let (n, rest) = mpi(params).ok_or(EncryptError::Unreadable)?;
            let (e, _) = mpi(rest).ok_or(EncryptError::Unreadable)?;
            Recipient::Rsa { n: n.to_vec(), e: e.to_vec() }
        }
        ALGO_ECDH => {
            let oid_len = usize::from(*params.first().ok_or(EncryptError::Unreadable)?);
            if params.get(1..1 + oid_len) != Some(CV25519_OID) {
                return Err(EncryptError::Algorithm("ECDH on a curve other than Curve25519".into()));
            }
            let (point, kdf) = mpi(params.get(1 + oid_len..).ok_or(EncryptError::Unreadable)?).ok_or(EncryptError::Unreadable)?;
            let point: [u8; 32] = point
                .strip_prefix(&[0x40])
                .and_then(|p| p.try_into().ok())
                .ok_or(EncryptError::Unreadable)?;
            // KDF parameters: length 3, reserved 1, hash, key wrap algorithm.
            match kdf.get(..4) {
                Some(&[3, 1, hash, kek]) => Recipient::Cv25519 { point, hash, kek },
                _ => return Err(EncryptError::Unreadable),
            }
        }
        other => return Err(EncryptError::Algorithm(super::algorithm_name(other))),
    };
    let len = u16::try_from(body.len()).map_err(|_| EncryptError::Unreadable)?;
    let fingerprint: [u8; 20] = crypto::sha1(&[&[0x99], len.to_be_bytes().as_slice(), body].concat())
        .try_into()
        .map_err(|_| EncryptError::Unreadable)?;
    Ok((recipient, fingerprint))
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

/// The session key sealed for the recipient: the PKESK v3 body.
fn pkesk(recipient: &Recipient, fingerprint: &[u8; 20], session: &[u8], env: &dyn Env) -> Option<Vec<u8>> {
    // The symmetric algorithm, the key and its 16-bit checksum.
    let sum = session.iter().map(|b| u32::from(*b)).sum::<u32>() & 0xffff;
    let sum = u16::try_from(sum).unwrap_or(0).to_be_bytes();
    let m = Zeroizing::new([[SYM_AES256].as_slice(), session, &sum].concat());
    let mut out = vec![3];
    out.extend_from_slice(fingerprint.get(12..)?);
    match recipient {
        Recipient::Rsa { n, e } => {
            // EME-PKCS1-v1_5: 0x00 0x02, non-zero random padding, 0x00, the message.
            let k = n.len();
            let mut padding = vec![0u8; k.checked_sub(m.len() + 3).filter(|l| *l >= 8)?];
            env.fill_random(&mut padding);
            for b in &mut padding {
                while *b == 0 {
                    let mut one = [0u8; 1];
                    env.fill_random(&mut one);
                    *b = one[0];
                }
            }
            let em = Zeroizing::new([&[0, 2], padding.as_slice(), &[0], &m].concat());
            out.push(ALGO_RSA);
            put_mpi(&mut out, &mod_pow(&em, e, n));
        }
        Recipient::Cv25519 { point, hash, kek } => {
            let mut secret = Zeroizing::new([0u8; 32]);
            env.fill_random(&mut *secret);
            let ephemeral = MontgomeryPoint::mul_base_clamped(*secret).to_bytes();
            let shared = Zeroizing::new(MontgomeryPoint(*point).mul_clamped(*secret).to_bytes());
            let mut param = vec![u8::try_from(CV25519_OID.len()).ok()?];
            param.extend_from_slice(CV25519_OID);
            param.extend_from_slice(&[ALGO_ECDH, 3, 1, *hash, *kek]);
            param.extend_from_slice(b"Anonymous Sender    ");
            param.extend_from_slice(fingerprint);
            let input = [&[0, 0, 0, 1], shared.as_slice(), &param].concat();
            let derived = Zeroizing::new(match hash {
                8 => crypto::sha256(&input),
                9 => ring::digest::digest(&ring::digest::SHA384, &input).as_ref().to_vec(),
                10 => crypto::sha512(&input),
                _ => return None,
            });
            let kek_len = match *kek {
                SYM_AES128 => 16,
                SYM_AES192 => 24,
                SYM_AES256 => 32,
                _ => return None,
            };
            // PKCS#5 padding to a multiple of 8 bytes.
            let pad = 8 - m.len() % 8;
            let padded = Zeroizing::new([m.as_slice(), &vec![u8::try_from(pad).ok()?; pad]].concat());
            let wrapped = key_wrap(derived.get(..kek_len)?, &padded)?;
            out.push(ALGO_ECDH);
            put_mpi(&mut out, &[[0x40].as_slice(), &ephemeral].concat());
            out.push(u8::try_from(wrapped.len()).ok()?);
            out.extend_from_slice(&wrapped);
        }
    }
    Some(out)
}

/// `message` encrypted to the certificate `public_key` (armored or binary), as an armored `PGP MESSAGE`.
pub fn encrypt(public_key: &[u8], message: &[u8], env: &dyn Env) -> Result<String, EncryptError> {
    let cert = match std::str::from_utf8(public_key).ok().and_then(dearmor) {
        Some(b) => b,
        None => public_key.to_vec(),
    };
    let (recipient, fingerprint) = recipient(&cert)?;
    let mut session = Zeroizing::new([0u8; 32]);
    env.fill_random(&mut *session);
    let pkesk = pkesk(&recipient, &fingerprint, &*session, env).ok_or(EncryptError::Unreadable)?;

    // Literal data: binary, no file name, the time.
    let created = u32::try_from(env.unix_time()).unwrap_or(u32::MAX);
    let literal = packet(TAG_LITERAL, &[&[b'b', 0], created.to_be_bytes().as_slice(), message].concat());
    // A random block whose last two bytes repeat, the packets, then the modification detection code over all of it.
    let mut prefix = [0u8; 18];
    env.fill_random(&mut prefix[..16]);
    let (head, tail) = prefix.split_at_mut(16);
    tail.copy_from_slice(&head[14..]);
    let mut plain = Zeroizing::new([prefix.as_slice(), &literal, &[0xc0 | TAG_MDC, 20]].concat());
    let mdc = crypto::sha1(&plain);
    plain.extend_from_slice(&mdc);
    let encrypted = cfb(&*session, &plain).ok_or(EncryptError::Unreadable)?;
    let seipd = packet(TAG_SEIPD, &[[1].as_slice(), &encrypted].concat());
    Ok(armor("MESSAGE", &[packet(TAG_PKESK, &pkesk), seipd].concat()))
}

#[cfg(test)]
mod tests {
    use aes::cipher::BlockCipherDecrypt;

    use super::super::first_packet;
    use super::*;

    const BOB_CV25519_PUB: &str = include_str!("../../../../tests/fixtures/data/pgp_bob_cv25519_pub.asc");
    const BOB_CV25519_SEC: &str = include_str!("../../../../tests/fixtures/data/pgp_bob_cv25519_sec.asc");
    const BOB_RSA_PUB: &str = include_str!("../../../../tests/fixtures/data/pgp_bob_rsa_pub.asc");
    /// `gpg --with-subkey-fingerprints` of Bob's cv25519 encryption subkey.
    const BOB_CV25519_SUBKEY: &str = "946F55CCF3AB98C5FAABD87286B5F9FA0B249A8B";

    fn hex(s: &str) -> Vec<u8> {
        crypto::unhex(&s.to_lowercase())
    }

    #[test]
    fn rfc3394_key_wrap() {
        let kek = hex("000102030405060708090A0B0C0D0E0F");
        let wrapped = key_wrap(&kek, &hex("00112233445566778899AABBCCDDEEFF")).unwrap();
        assert_eq!(wrapped, hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"));
    }

    #[test]
    fn mod_pow_small() {
        let r = mod_pow(&[4], &[13], &[0x01, 0xf1]);
        assert_eq!(r.into_iter().skip_while(|b| *b == 0).collect::<Vec<_>>(), [0x01, 0xbd], "4^13 mod 497 = 445");
    }

    #[test]
    fn encryption_subkeys_are_picked() {
        let cert = dearmor(BOB_CV25519_PUB).unwrap();
        let (r, fpr) = recipient(&cert).unwrap();
        assert!(matches!(r, Recipient::Cv25519 { hash: 8, kek: SYM_AES128, .. }), "GnuPG's defaults: SHA-256, AES-128");
        assert_eq!(crypto::hex(&fpr).to_uppercase(), BOB_CV25519_SUBKEY);
        let cert = dearmor(BOB_RSA_PUB).unwrap();
        let (r, _) = recipient(&cert).unwrap();
        assert!(matches!(r, Recipient::Rsa { ref n, .. } if n.len() == 384), "RSA-3072");
        assert!(matches!(recipient(b"junk"), Err(EncryptError::Unreadable)));
    }

    /// Bob's cv25519 secret scalar, from his secret subkey (the MPI holds it byte-reversed).
    fn bob_scalar() -> [u8; 32] {
        let data = dearmor(BOB_CV25519_SEC).unwrap();
        let mut rest = data.as_slice();
        while let Some((tag, body, next)) = next_packet(rest) {
            rest = next;
            if tag == 7 {
                let oid_len = usize::from(body[6]);
                let (_, after_point) = mpi(&body[7 + oid_len..]).unwrap();
                // KDF parameters (4 bytes), then the S2K usage octet.
                let (secret, _) = mpi(&after_point[5..]).unwrap();
                let mut be = [0u8; 32];
                be[32 - secret.len()..].copy_from_slice(secret);
                be.reverse();
                return be;
            }
        }
        panic!("no secret subkey");
    }

    fn aes_decrypt(key: &[u8], block: &mut [u8; 16]) {
        let mut b = Array::from(*block);
        match key.len() {
            16 => Aes128::new_from_slice(key).unwrap().decrypt_block(&mut b),
            32 => Aes256::new_from_slice(key).unwrap().decrypt_block(&mut b),
            other => panic!("AES-{other}?"),
        }
        *block = b.into();
    }

    /// RFC 3394 unwrap.
    fn key_unwrap(kek: &[u8], wrapped: &[u8]) -> Vec<u8> {
        let mut a: [u8; 8] = wrapped[..8].try_into().unwrap();
        let mut r: Vec<[u8; 8]> = wrapped[8..].chunks(8).map(|c| c.try_into().unwrap()).collect();
        let n = r.len();
        for j in (0..6).rev() {
            for i in (0..n).rev() {
                let t = u64::try_from(n * j + i + 1).unwrap().to_be_bytes();
                let mut b = [0u8; 16];
                for k in 0..8 {
                    b[k] = a[k] ^ t[k];
                }
                b[8..].copy_from_slice(&r[i]);
                aes_decrypt(kek, &mut b);
                a.copy_from_slice(&b[..8]);
                r[i].copy_from_slice(&b[8..]);
            }
        }
        assert_eq!(a, [0xa6; 8], "integrity check");
        r.concat()
    }

    /// Decrypt a message to Bob's cv25519 key: the PKESK opened, the SEIPD decrypted, the MDC checked, the literal data returned.
    fn bob_decrypts(armored: &str) -> Vec<u8> {
        let data = dearmor(armored).unwrap();
        let (tag, pkesk, rest) = next_packet(&data).unwrap();
        assert_eq!((tag, pkesk[0]), (TAG_PKESK, 3));
        assert!(BOB_CV25519_SUBKEY.ends_with(&crypto::hex(&pkesk[1..9]).to_uppercase()), "key id");
        assert_eq!(pkesk[9], ALGO_ECDH);
        let (eph, rest_pk) = mpi(&pkesk[10..]).unwrap();
        let eph: [u8; 32] = eph[1..].try_into().unwrap();
        let wrapped = &rest_pk[1..1 + usize::from(rest_pk[0])];
        let shared = MontgomeryPoint(eph).mul_clamped(bob_scalar()).to_bytes();
        let mut param = vec![10];
        param.extend_from_slice(CV25519_OID);
        param.extend_from_slice(&[ALGO_ECDH, 3, 1, 8, SYM_AES128]);
        param.extend_from_slice(b"Anonymous Sender    ");
        param.extend_from_slice(&hex(BOB_CV25519_SUBKEY));
        let kek = crypto::sha256(&[&[0, 0, 0, 1], shared.as_slice(), &param].concat());
        let m = key_unwrap(&kek[..16], wrapped);
        assert_eq!(m[0], SYM_AES256);
        let session = &m[1..33];
        let sum = session.iter().map(|b| u32::from(*b)).sum::<u32>() & 0xffff;
        assert_eq!(u32::from(u16::from_be_bytes([m[33], m[34]])), sum, "session key checksum");

        let (tag, seipd) = first_packet(rest).unwrap();
        assert_eq!((tag, seipd[0]), (TAG_SEIPD, 1));
        let aes = Aes::new(session).unwrap();
        let mut plain = Vec::new();
        let mut prev = [0u8; 16];
        for chunk in seipd[1..].chunks(16) {
            let mut ks = prev;
            aes.encrypt(&mut ks);
            plain.extend(chunk.iter().zip(ks.iter()).map(|(c, k)| c ^ k));
            if chunk.len() == 16 {
                prev.copy_from_slice(chunk);
            }
        }
        assert_eq!(plain[14..16], plain[16..18], "prefix check bytes");
        let (body, mdc) = plain.split_at(plain.len() - 22);
        assert_eq!(&mdc[..2], &[0xd3, 0x14]);
        assert_eq!(&mdc[2..], crypto::sha1(&[body, &mdc[..2]].concat()).as_slice(), "modification detection code");
        let (tag, literal) = first_packet(&body[18..]).unwrap();
        assert_eq!((tag, literal[0], literal[1]), (TAG_LITERAL, b'b', 0));
        literal[6..].to_vec()
    }

    #[test]
    fn cv25519_round_trip() {
        let message = "Content-Type: text/plain\r\n\r\nsecret ✓".repeat(300);
        let armored = encrypt(BOB_CV25519_PUB.as_bytes(), message.as_bytes(), crate::testing::test_env()).unwrap();
        assert!(armored.starts_with("-----BEGIN PGP MESSAGE-----\r\n"), "{armored}");
        assert_eq!(bob_decrypts(&armored), message.as_bytes());
    }

    #[test]
    fn rsa_session_key_is_sealed() {
        let armored = encrypt(BOB_RSA_PUB.as_bytes(), b"hi", crate::testing::test_env()).unwrap();
        let data = dearmor(&armored).unwrap();
        let (tag, pkesk) = first_packet(&data).unwrap();
        assert_eq!((tag, pkesk[0], pkesk[9]), (TAG_PKESK, 3, ALGO_RSA));
        let (c, _) = mpi(&pkesk[10..]).unwrap();
        assert!(c.len() <= 384 && c.len() > 370, "one RSA-3072 block: {}", c.len());
    }

    /// The armored message and the outer headers of a captured `multipart/encrypted` mail.
    fn encrypted_part(mail: &str) -> (String, String) {
        let head = mail.lines().find(|l| l.starts_with("Content-Type: multipart/encrypted")).expect(mail);
        assert!(head.contains("protocol=\"application/pgp-encrypted\""), "{head}");
        let boundary = head.split("boundary=\"").nth(1).unwrap().trim_end_matches('"');
        let parts: Vec<&str> = mail.split(&format!("--{boundary}")).collect();
        assert!(parts[1].contains("Content-Type: application/pgp-encrypted") && parts[1].contains("Version: 1"), "{}", parts[1]);
        assert!(parts[2].contains("Content-Type: application/octet-stream"), "{}", parts[2]);
        let armored = format!("-----BEGIN{}", parts[2].split_once("-----BEGIN").unwrap().1);
        let outer = mail.split("\r\n\r\n").next().unwrap().to_string();
        (armored, outer)
    }

    /// `?pgp=encrypt` end to end: Bob's key from `?pgppub=`, the mail through a scripted SMTP server, decrypted with Bob's secret key.
    #[test]
    fn encrypted_mail_decrypts() {
        use crate::testing::FakeTransport;
        use crate::{Asset, Message};

        let fake = FakeTransport::new();
        let data = super::super::tests::capture_smtp(&fake);
        fake.file("/keys/bob.asc", BOB_CV25519_PUB);
        let url = "mailto://user:pass@example.com:2525?from=alice@example.com&to=bob@example.org&pgp=encrypt&pgppub=/keys/bob.asc";
        let report = crate::Attachment::new("report.txt", "text/plain", b"quarterly numbers".to_vec());
        let msg = Message::new("the secret").title("Hidden title").attach(report);
        let d = crate::parse(url).unwrap().send(&msg, &fake, &Asset::default());
        assert!(d.is_success(), "{d:?}");
        let mail = data.lock().unwrap().join("\r\n");
        let (armored, outer) = encrypted_part(&mail);
        assert!(!mail.contains("the secret") && !mail.contains("report.txt"), "{mail}");
        assert!(outer.contains("Subject: Hidden title"), "Apprise keeps the outer subject: {outer}");
        let inner = String::from_utf8(bob_decrypts(&armored)).unwrap();
        assert!(inner.contains("From: alice@example.com\r\nTo: bob@example.org\r\nSubject: Hidden title\r\n"), "{inner}");
        assert!(inner.contains("the secret"), "{inner}");
        // The attachment is inside the encrypted part (base64 of "quarterly numbers").
        assert!(inner.contains("filename=\"report.txt\"") && inner.contains(&crypto::b64(b"quarterly numbers")), "{inner}");
    }

    /// `?pgp=sign` encrypts too when the recipient's key is in the storage folder; without it, the mail is only signed.
    #[test]
    fn signed_mail_is_encrypted_when_a_key_exists() {
        use crate::testing::FakeTransport;
        use crate::{Asset, Message};

        let alice = include_str!("../../../../tests/fixtures/data/pgp_alice_ed25519.asc");
        let url = "mailto://user:pass@example.com:2525?from=alice@example.com&to=bob@example.org&pgp=sign&pgpprv=/keys/alice.asc";
        let target = crate::parse(url).unwrap();
        let asset = Asset { storage_path: Some("/data".into()), ..Asset::default() };
        let folder = std::path::Path::new("/data").join(target.url_id(&asset).unwrap());
        for with_key in [true, false] {
            let fake = FakeTransport::new();
            let data = super::super::tests::capture_smtp(&fake);
            fake.file("/keys/alice.asc", alice);
            if with_key {
                fake.file(folder.join("bob@example.org-pub.asc"), BOB_CV25519_PUB);
            }
            let d = target.send(&Message::new("signed body"), &fake, &asset);
            assert!(d.is_success(), "{d:?}");
            let mail = data.lock().unwrap().join("\r\n");
            if with_key {
                let (armored, _) = encrypted_part(&mail);
                let inner = String::from_utf8(bob_decrypts(&armored)).unwrap();
                assert!(inner.contains("multipart/signed") && inner.contains("signed body"), "{inner}");
            } else {
                assert!(mail.contains("multipart/signed") && !mail.contains("multipart/encrypted"), "{mail}");
            }
        }
    }
}
