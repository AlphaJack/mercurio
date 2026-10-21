//! Key generation (Apprise's `keygen`, with Ed25519 and Curve25519 keys) and the Autocrypt header (Apprise's `autocrypt_header`).

use curve25519_dalek::montgomery::MontgomeryPoint;
use ring::signature::{Ed25519KeyPair, KeyPair};
use zeroize::Zeroizing;

use super::{
    ALGO_ECDH, ALGO_EDDSA, ALGO_RSA, ALGO_RSA_SIGN, CV25519_OID, ED25519_OID, Key, Signer, armor, dearmor, mpi,
    next_packet, packet, put_mpi, signature_packet, subpacket,
};
use crate::crypto;
use crate::env::Env;

const TAG_SECRET_KEY: u8 = 5;
const TAG_PUBLIC_KEY: u8 = 6;
const TAG_SECRET_SUBKEY: u8 = 7;
const TAG_USER_ID: u8 = 13;
const TAG_PUBLIC_SUBKEY: u8 = 14;
const TAG_USER_ATTRIBUTE: u8 = 17;
const TAG_SIGNATURE: u8 = 2;
/// Signature types: positive certification of a user ID, subkey binding; revocations.
const SIG_POSITIVE_CERT: u8 = 0x13;
const SIG_SUBKEY_BINDING: u8 = 0x18;
const SIG_REVOCATIONS: [u8; 3] = [0x20, 0x28, 0x30];

/// Largest Autocrypt header (Apprise's `max_autocrypt_header_size`).
const MAX_AUTOCRYPT: usize = 10 * 1024;

/// A generated key pair, armored.
pub struct Generated {
    pub public: String,
    pub secret: Zeroizing<String>,
}

/// v4 fingerprint of a public key packet body.
fn fingerprint(public: &[u8]) -> [u8; 20] {
    let len = u16::try_from(public.len()).unwrap_or(u16::MAX).to_be_bytes();
    crypto::sha1(&[&[0x99], len.as_slice(), public].concat()).try_into().unwrap_or([0; 20])
}

/// `0x99`, the length and the body of a public key packet: how certifications hash a key.
fn hashed_key(public: &[u8]) -> Vec<u8> {
    [&[0x99], u16::try_from(public.len()).unwrap_or(u16::MAX).to_be_bytes().as_slice(), public].concat()
}

/// A secret key packet body: the public part, S2K usage 0, the secret MPIs and their 16-bit checksum.
fn secret_body(public: &[u8], secrets: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut mpis = Zeroizing::new(Vec::new());
    for s in secrets {
        put_mpi(&mut mpis, s);
    }
    let sum = mpis.iter().map(|b| u32::from(*b)).sum::<u32>() & 0xffff;
    let sum = u16::try_from(sum).unwrap_or(0).to_be_bytes();
    Zeroizing::new([public, &[0], &mpis, &sum].concat())
}

/// A new key for `name <email>`, as GnuPG makes them by default: an Ed25519 primary key that certifies and signs, and a Curve25519 subkey that encrypts (SHA-256, AES-128 key wrap). The self-signatures carry Apprise's preferences: AES-256, SHA-256, ZLIB.
pub fn generate(name: &str, email: &str, env: &dyn Env) -> Option<Generated> {
    let created = u32::try_from(env.unix_time()).unwrap_or(u32::MAX);
    let mut seed = Zeroizing::new([0u8; 32]);
    env.fill_random(&mut *seed);
    let pair = Ed25519KeyPair::from_seed_unchecked(&*seed).ok()?;
    let mut scalar = Zeroizing::new([0u8; 32]);
    env.fill_random(&mut *scalar);
    // X25519 clamping, as GnuPG stores it.
    scalar[0] &= 248;
    scalar[31] = (scalar[31] & 127) | 64;
    let cv_public = MontgomeryPoint::mul_base_clamped(*scalar).to_bytes();

    let mut primary = vec![4];
    primary.extend_from_slice(&created.to_be_bytes());
    primary.extend_from_slice(&[ALGO_EDDSA, u8::try_from(ED25519_OID.len()).ok()?]);
    primary.extend_from_slice(ED25519_OID);
    put_mpi(&mut primary, &[[0x40].as_slice(), pair.public_key().as_ref()].concat());
    let mut subkey = vec![4];
    subkey.extend_from_slice(&created.to_be_bytes());
    subkey.extend_from_slice(&[ALGO_ECDH, u8::try_from(CV25519_OID.len()).ok()?]);
    subkey.extend_from_slice(CV25519_OID);
    put_mpi(&mut subkey, &[[0x40].as_slice(), &cv_public].concat());
    subkey.extend_from_slice(&[3, 1, 8, 7]);

    let key = Key { signer: Signer::Ed25519(pair), algo: ALGO_EDDSA, fingerprint: fingerprint(&primary) };
    let uid = format!("{name} <{email}>");
    let uid_len = u32::try_from(uid.len()).ok()?.to_be_bytes();
    let mut cert_sub = Vec::new();
    subpacket(&mut cert_sub, 27, &[0x03]); // certify, sign
    subpacket(&mut cert_sub, 11, &[9]); // AES-256
    subpacket(&mut cert_sub, 21, &[8]); // SHA-256
    subpacket(&mut cert_sub, 22, &[2]); // ZLIB
    subpacket(&mut cert_sub, 30, &[0x01]); // modification detection
    let cert_prefix = [hashed_key(&primary).as_slice(), &[0xb4], &uid_len, uid.as_bytes()].concat();
    let cert = signature_packet(&key, SIG_POSITIVE_CERT, &cert_sub, &cert_prefix, created).ok()?;
    let mut bind_sub = Vec::new();
    subpacket(&mut bind_sub, 27, &[0x0c]); // encrypt communications and storage
    let bind_prefix = [hashed_key(&primary), hashed_key(&subkey)].concat();
    let binding = signature_packet(&key, SIG_SUBKEY_BINDING, &bind_sub, &bind_prefix, created).ok()?;

    let uid_packet = packet(TAG_USER_ID, uid.as_bytes());
    let public = [
        packet(TAG_PUBLIC_KEY, &primary),
        uid_packet.clone(),
        cert.clone(),
        packet(TAG_PUBLIC_SUBKEY, &subkey),
        binding.clone(),
    ]
    .concat();
    // The Curve25519 secret is stored byte-reversed (big-endian), as GnuPG does.
    let mut reversed = Zeroizing::new(*scalar);
    reversed.reverse();
    let secret = Zeroizing::new(
        [
            packet(TAG_SECRET_KEY, &secret_body(&primary, &[&*seed])),
            uid_packet,
            cert,
            packet(TAG_SECRET_SUBKEY, &secret_body(&subkey, &[&*reversed])),
            binding,
        ]
        .concat(),
    );
    Some(Generated { public: armor("PUBLIC KEY BLOCK", &public), secret: Zeroizing::new(armor("PRIVATE KEY BLOCK", &secret)) })
}

/// The length of the public part of a key packet body (what precedes the secret material).
fn public_len(body: &[u8]) -> Option<usize> {
    if body.first() != Some(&4) {
        return None;
    }
    let params = body.get(6..)?;
    let rest = match *body.get(5)? {
        ALGO_RSA | 2 | ALGO_RSA_SIGN => mpi(mpi(params)?.1)?.1,
        ALGO_EDDSA => mpi(params.get(1 + usize::from(*params.first()?)..)?)?.1,
        ALGO_ECDH => {
            let after = mpi(params.get(1 + usize::from(*params.first()?)..)?)?.1;
            after.get(1 + usize::from(*after.first()?)..)?
        }
        _ => return None,
    };
    Some(body.len() - rest.len())
}

/// The public certificate of a secret key (secret packets cut to their public part), when it suits Autocrypt: one user ID, no user attributes, no revocation, and a subkey bound for encryption (Apprise's `_has_encryption_subkey`).
fn autocrypt_cert(secret: &[u8]) -> Option<Vec<u8>> {
    let data = match std::str::from_utf8(secret).ok().and_then(dearmor) {
        Some(b) => Zeroizing::new(b),
        None => Zeroizing::new(secret.to_vec()),
    };
    let mut rest = data.as_slice();
    let mut out = Vec::new();
    let (mut uids, mut encrypting_subkeys, mut last_tag) = (0, 0, 0);
    while !rest.is_empty() {
        let (tag, body, next) = next_packet(rest)?;
        rest = next;
        match tag {
            TAG_SECRET_KEY | TAG_PUBLIC_KEY => {
                out.extend(packet(TAG_PUBLIC_KEY, body.get(..public_len(body)?)?));
            }
            TAG_SECRET_SUBKEY | TAG_PUBLIC_SUBKEY => {
                out.extend(packet(TAG_PUBLIC_SUBKEY, body.get(..public_len(body)?)?));
            }
            TAG_USER_ID => {
                uids += 1;
                out.extend(packet(tag, body));
            }
            TAG_USER_ATTRIBUTE => return None,
            TAG_SIGNATURE => {
                let sig_type = *body.get(1)?;
                if SIG_REVOCATIONS.contains(&sig_type) {
                    return None;
                }
                if matches!(last_tag, TAG_SECRET_SUBKEY | TAG_PUBLIC_SUBKEY)
                    && sig_type == SIG_SUBKEY_BINDING
                    && super::encrypt::key_flags(body).is_some_and(|f| f & 0x0c != 0)
                {
                    encrypting_subkeys += 1;
                }
                out.extend(packet(tag, body));
            }
            _ => continue,
        }
        if tag != TAG_SIGNATURE {
            last_tag = tag;
        }
    }
    (uids == 1 && encrypting_subkeys == 1).then_some(out)
}

/// The `Autocrypt` header value advertising the key of `secret` for `email`, folded at 76 characters; `None` when the key does not suit Autocrypt or the header would exceed 10 KiB.
pub fn autocrypt_header(email: &str, secret: &[u8]) -> Option<String> {
    let Some(cert) = autocrypt_cert(secret) else {
        log::debug!("PGP private key lacks an Autocrypt-compatible encryption subkey; omitting Autocrypt header");
        return None;
    };
    let keydata = crypto::b64(&cert);
    let folded: Vec<&str> =
        keydata.as_bytes().chunks(76).map(|c| std::str::from_utf8(c).unwrap_or_default()).collect();
    let header = format!("addr={email}; prefer-encrypt=mutual; keydata={}", folded.join("\r\n "));
    if format!("Autocrypt: {header}").len() > MAX_AUTOCRYPT {
        log::debug!("Autocrypt header exceeds the {MAX_AUTOCRYPT} byte spec limit; omitting");
        return None;
    }
    Some(header)
}

#[cfg(test)]
mod tests {
    use super::super::{secret_key, sign};
    use super::*;

    #[test]
    fn generated_keys_sign_and_take_encryption() {
        let env = crate::testing::test_env();
        let g = generate("Mercurio", "me@example.com", env).unwrap();
        assert!(g.public.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n"));
        assert!(g.secret.starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n"));
        // The secret key reads back and its primary key matches the public one.
        let key = secret_key(g.secret.as_bytes()).unwrap();
        let public = dearmor(&g.public).unwrap();
        let (_, primary, _) = next_packet(&public).unwrap();
        assert_eq!(key.fingerprint, fingerprint(primary));
        let (sig, _) = sign(g.secret.as_bytes(), b"data", env).unwrap();
        assert!(sig.contains("BEGIN PGP SIGNATURE"));
        // Encryption picks the Curve25519 subkey.
        let armored = super::super::encrypt(g.public.as_bytes(), b"to myself", env).unwrap();
        assert!(armored.contains("BEGIN PGP MESSAGE"));
    }

    #[test]
    fn autocrypt_headers() {
        let env = crate::testing::test_env();
        let g = generate("Mercurio", "me@example.com", env).unwrap();
        let header = autocrypt_header("me@example.com", g.secret.as_bytes()).unwrap();
        assert!(header.starts_with("addr=me@example.com; prefer-encrypt=mutual; keydata="), "{header}");
        assert!(header.split("\r\n ").all(|l| l.len() <= 76 + "addr=me@example.com; prefer-encrypt=mutual; keydata=".len()));
        // The keydata is the public certificate: no secret material.
        let keydata = crypto::b64_decode(&header.split("keydata=").nth(1).unwrap().replace("\r\n ", "")).unwrap();
        let (tag, _, _) = next_packet(&keydata).unwrap();
        assert_eq!(tag, TAG_PUBLIC_KEY);
        assert!(keydata.len() < dearmor(&g.secret).unwrap().len());
        // GnuPG's default key qualifies; a sign-only key has no encryption subkey.
        let bob = include_str!("../../../../tests/fixtures/data/pgp_bob_cv25519_sec.asc");
        assert!(autocrypt_header("bob@example.org", bob.as_bytes()).is_some());
        let alice = include_str!("../../../../tests/fixtures/data/pgp_alice_ed25519.asc");
        assert_eq!(autocrypt_header("alice@example.com", alice.as_bytes()), None);
    }
}
