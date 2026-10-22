//! Detached signatures (RFC 3156): the v4 secret key packet of an Ed25519 key in GnuPG's EdDSA encoding (algorithm 22) or of an RSA key (algorithms 1 and 3, 2048 to 8192 bits), and a v4 binary-document signature over SHA-256. Other keys are refused with their algorithm named.
//!
//! An RSA key is handed to `ring` as PKCS#1: OpenPGP keeps `u = p⁻¹ mod q`, so `p` and `q` trade places and `u` becomes PKCS#1's `q⁻¹ mod p` as it is; only `d mod (p − 1)` and `d mod (q − 1)` are computed, by a reduction that runs the same steps whatever the secret values.

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};
use zeroize::Zeroizing;

use super::*;
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

/// An unlocked signing key.
pub(super) enum Signer {
    Ed25519(Ed25519KeyPair),
    Rsa(RsaKeyPair),
}

/// An unlocked primary key: how it signs, its algorithm id and its v4 fingerprint.
pub(super) struct Key {
    pub(super) signer: Signer,
    pub(super) algo: u8,
    pub(super) fingerprint: [u8; 20],
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
///
/// Both buffers are sized up front: a reallocation would leave a copy of the secret behind.
fn rsa_pkcs1(n: &[u8], e: &[u8], d: &[u8], p: &[u8], q: &[u8], u: &[u8]) -> Zeroizing<Vec<u8>> {
    let (p, q) = (q, p);
    let dp = Zeroizing::new(big_mod(d, &minus_one(p)));
    let dq = Zeroizing::new(big_mod(d, &minus_one(q)));
    let values = [&[0u8][..], n, e, d, p, q, &dp, &dq, u];
    // Tag, at most 5 length bytes, a padding zero.
    let mut body = Zeroizing::new(Vec::with_capacity(values.iter().map(|v| v.len() + 7).sum()));
    for v in values {
        der_uint(&mut body, v);
    }
    let mut der = Zeroizing::new(Vec::with_capacity(body.len() + 6));
    der.push(0x30);
    der_len(&mut der, body.len());
    der.extend_from_slice(&body);
    der
}

/// Read the primary key of an armored (or binary) secret key.
pub(super) fn secret_key(data: &[u8]) -> Result<Key, SignError> {
    let bytes = match std::str::from_utf8(data).ok().and_then(dearmor) {
        Some(b) => Zeroizing::new(b),
        None => Zeroizing::new(data.to_vec()),
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
            let der = rsa_pkcs1(n, e, d, p, q, u);
            Signer::Rsa(RsaKeyPair::from_der(&der).map_err(|_| SignError::Failed)?)
        }
        [point] => {
            // The native point format: 0x40, then the 32-byte key.
            let public = point.strip_prefix(&[0x40]).filter(|p| p.len() == 32).ok_or(SignError::Unreadable)?;
            let (secret, _) = mpi(secret).ok_or(SignError::Unreadable)?;
            if secret.len() > 32 {
                return Err(SignError::Unreadable);
            }
            let mut seed = Zeroizing::new([0u8; 32]);
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
pub(super) fn subpacket(out: &mut Vec<u8>, kind: u8, data: &[u8]) {
    out.push(u8::try_from(data.len() + 1).unwrap_or(u8::MAX));
    out.push(kind);
    out.extend_from_slice(data);
}

/// A v4 signature packet of `sig_type` over `prefix` (the signed data, or the keys and user ID a certification covers), SHA-256: creation time, `hashed` subpackets and the issuer fingerprint in the hashed area, the issuer key ID in the unhashed one.
pub(super) fn signature_packet(key: &Key, sig_type: u8, hashed_extra: &[u8], prefix: &[u8], created: u32) -> Result<Vec<u8>, SignError> {
    let mut hashed_sub = Vec::new();
    subpacket(&mut hashed_sub, 2, &created.to_be_bytes());
    hashed_sub.extend_from_slice(hashed_extra);
    subpacket(&mut hashed_sub, 33, &[[4].as_slice(), &key.fingerprint].concat());
    let mut unhashed_sub = Vec::new();
    subpacket(&mut unhashed_sub, 16, key.fingerprint.get(12..).unwrap_or_default());

    let mut hashed = vec![4, sig_type, key.algo, HASH_SHA256];
    hashed.extend_from_slice(&u16::try_from(hashed_sub.len()).unwrap_or(0).to_be_bytes());
    hashed.extend_from_slice(&hashed_sub);
    let trailer_len = u32::try_from(hashed.len()).unwrap_or(0);
    let signed = [prefix, &hashed, &[4, 0xff], &trailer_len.to_be_bytes()].concat();
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
    Ok(packet(TAG_SIGNATURE, &body))
}

/// A detached, armored signature over `data` (SHA-256, binary document) with the key's primary key, as Apprise signs, and its `micalg` label.
pub fn sign(key: &[u8], data: &[u8], env: &dyn Env) -> Result<(String, &'static str), SignError> {
    let key = secret_key(key)?;
    let created = u32::try_from(env.unix_time()).unwrap_or(u32::MAX);
    let packet = signature_packet(&key, SIG_BINARY, &[], data, created)?;
    Ok((armor("SIGNATURE", &packet), "pgp-sha256"))
}

#[cfg(test)]
mod tests {
    use ring::signature::{ED25519, KeyPair, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

    use super::*;


    const ALICE_ED25519: &str = include_str!("../../../../tests/fixtures/data/pgp_alice_ed25519.asc");

    const ALICE_LOCKED: &str = include_str!("../../../../tests/fixtures/data/pgp_alice_ed25519_locked.asc");

    const ALICE_RSA: &str = include_str!("../../../../tests/fixtures/data/pgp_alice_rsa.asc");

    /// `gpg --fingerprint` of `ALICE_ED25519`.
    const ALICE_ED25519_FPR: &str = "91C4B7D9E4C600F7122145D5B401712C1AE117D4";

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
        verify_with(ALICE_ED25519, sig, data);
    }

    #[test]
    fn gnupg_key_fingerprint() {
        let key = secret_key(ALICE_ED25519.as_bytes()).unwrap();
        assert_eq!(crypto::hex(&key.fingerprint).to_uppercase(), ALICE_ED25519_FPR);
    }

    #[test]
    fn signatures_verify() {
        let data = b"Content-Type: text/plain\r\n\r\nhello";
        let (sig, micalg) = sign(ALICE_ED25519.as_bytes(), data, crate::testing::test_env()).unwrap();
        assert_eq!(micalg, "pgp-sha256");
        assert!(sig.starts_with("-----BEGIN PGP SIGNATURE-----\r\n\r\n"), "{sig}");
        assert!(sig.ends_with("-----END PGP SIGNATURE-----\r\n"), "{sig}");
        assert!(!sig.replace("\r\n", "").contains('\n'), "CRLF line endings: {sig}");
        verify(&sig, data);
    }

    #[test]
    fn rsa_signatures_verify() {
        let data = b"Content-Type: text/plain\r\n\r\nhello";
        let (sig, micalg) = sign(ALICE_RSA.as_bytes(), data, crate::testing::test_env()).unwrap();
        assert_eq!(micalg, "pgp-sha256");
        verify_with(ALICE_RSA, &sig, data);
    }

    #[test]
    fn other_keys_are_refused() {
        let env = crate::testing::test_env();
        assert_eq!(sign(ALICE_LOCKED.as_bytes(), b"x", env), Err(SignError::Protected));
        assert_eq!(sign(b"not a key", b"x", env), Err(SignError::Unreadable));
        // A damaged armor checksum.
        let damaged = ALICE_ED25519.replacen("lFgE", "lFgF", 1);
        assert_eq!(sign(damaged.as_bytes(), b"x", env), Err(SignError::Unreadable));
    }

    /// A signed e-mail end to end: the key from `?pgpprv=`, the message through a scripted SMTP server, the signature checked over the exact signed part.
    #[test]
    fn signed_mail_verifies() {
        use crate::testing::FakeTransport;
        use crate::{Asset, Message};

        let fake = FakeTransport::new();
        let data = super::super::tests::capture_smtp(&fake);
        fake.file("/keys/me.asc", ALICE_ED25519);
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
