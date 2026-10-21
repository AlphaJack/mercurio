//! OpenPGP for e-mail and Delta Chat (`?pgp=`), through rpgp: where keys are looked for, and detached signatures (RFC 3156).
//!
//! Keys come from `?pgpprv=` / `?pgppub=` (a path, `file://` or `http(s)://`) or from the URL's storage folder, under Apprise's file names. Only Ed25519 private keys sign: rpgp's RSA has an open timing side channel (RUSTSEC-2023-0071), so RSA private keys are refused.

use pgp::composed::{ArmorOptions, Deserializable, DetachedSignature, SignedSecretKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::types::{KeyDetails, Password};

use crate::env::Env;

/// The `Env` as the random source rpgp asks for, so signatures are reproducible under a fixed `Env`.
struct EnvRng<'a>(&'a dyn Env);

impl rand_core::RngCore for EnvRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.fill_random(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.fill_random(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_random(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.fill_random(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for EnvRng<'_> {}

/// Why a key could not sign.
#[derive(Debug, PartialEq, Eq)]
pub enum SignError {
    /// Not an OpenPGP secret key.
    Unreadable,
    /// Locked with a passphrase (Apprise does not support those either).
    Protected,
    /// Not Ed25519 (the algorithm is named).
    Algorithm(String),
    /// rpgp refused to sign.
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
                "PGP Private Key is {alg}; mercurio signs only with Ed25519 keys (RSA signing in rpgp has an open \
                 timing side channel, RUSTSEC-2023-0071)"
            ),
            SignError::Failed => "PGP signing failed; key may lack Sign capability".into(),
        }
    }
}

/// Read an armored (or binary) secret key.
fn secret_key(data: &[u8]) -> Result<SignedSecretKey, SignError> {
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok((key, _)) = SignedSecretKey::from_string(text)
    {
        return Ok(key);
    }
    SignedSecretKey::from_bytes(data).map_err(|_| SignError::Unreadable)
}

/// A detached, armored signature over `data` (SHA-256, binary document) with the key's primary key, as Apprise signs, and its `micalg` label.
pub fn sign(key: &[u8], data: &[u8], env: &dyn Env) -> Result<(String, &'static str), SignError> {
    let key = secret_key(key)?;
    let alg = key.primary_key.algorithm();
    if alg != PublicKeyAlgorithm::EdDSALegacy {
        return Err(SignError::Algorithm(format!("{alg:?}")));
    }
    if key.primary_key.secret_params().is_encrypted() {
        return Err(SignError::Protected);
    }
    let sig =
        DetachedSignature::sign_binary_data(EnvRng(env), &key.primary_key, &Password::empty(), HashAlgorithm::Sha256, data)
            .map_err(|_| SignError::Failed)?;
    let armored = sig.to_armored_string(ArmorOptions::default()).map_err(|_| SignError::Failed)?;
    Ok((crlf(&armored), "pgp-sha256"))
}

/// CRLF line endings, as every part of the message has.
pub fn crlf(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\n', "\r\n")
}

#[cfg(test)]
mod tests {
    use pgp::composed::{KeyType, SecretKeyParamsBuilder, SignedPublicKey};

    use super::*;

    fn key(key_type: KeyType, passphrase: Option<&str>) -> SignedSecretKey {
        let params = SecretKeyParamsBuilder::default()
            .key_type(key_type)
            .can_sign(true)
            .can_certify(true)
            .primary_user_id("Me <me@example.com>".into())
            .passphrase(passphrase.map(str::to_string))
            .build()
            .unwrap();
        params.generate(EnvRng(crate::testing::test_env())).unwrap()
    }

    fn armored(k: &SignedSecretKey) -> Vec<u8> {
        k.to_armored_bytes(ArmorOptions::default()).unwrap()
    }

    #[test]
    fn ed25519_signatures_verify() {
        {
            let k = key(KeyType::Ed25519Legacy, None);
            let data = b"Content-Type: text/plain\r\n\r\nhello";
            let (sig, micalg) = sign(&armored(&k), data, crate::testing::test_env()).unwrap();
            assert_eq!(micalg, "pgp-sha256");
            assert!(sig.starts_with("-----BEGIN PGP SIGNATURE-----\r\n"), "{sig}");
            assert!(!sig.replace("\r\n", "").contains('\n'), "CRLF line endings: {sig}");
            let (parsed, _) = DetachedSignature::from_string(&sig).unwrap();
            let public = SignedPublicKey::from(k.clone());
            parsed.verify(&public, data).unwrap();
            assert!(parsed.verify(&public, b"tampered").is_err());
        }
    }

    #[test]
    fn other_keys_are_refused() {
        let env = crate::testing::test_env();
        let rsa = key(KeyType::Rsa(2048), None);
        assert!(matches!(sign(&armored(&rsa), b"x", env), Err(SignError::Algorithm(a)) if a.contains("RSA")));
        let locked = key(KeyType::Ed25519Legacy, Some("secret"));
        assert_eq!(sign(&armored(&locked), b"x", env), Err(SignError::Protected));
        assert_eq!(sign(b"not a key", b"x", env), Err(SignError::Unreadable));
    }

    /// A signed e-mail end to end: the key from `?pgpprv=`, the message through a scripted SMTP server, the signature checked over the exact signed part.
    #[test]
    fn signed_mail_verifies() {
        use std::sync::{Arc, Mutex};

        use crate::testing::{FakeTransport, ScriptedConn};
        use crate::{Asset, Message};

        let k = key(KeyType::Ed25519Legacy, None);
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
        fake.file("/keys/me.asc", armored(&k));
        let t = crate::parse("mailto://user:pass@example.com:2525?to=bob@example.org&pgp=sign&pgpprv=/keys/me.asc").unwrap();
        let d = t.send(&Message::new("hello").title("T"), &fake, &Asset::default());
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
        let armored_sig = format!("-----BEGIN{}", sig_part.split_once("-----BEGIN").unwrap().1);
        let (sig, _) = DetachedSignature::from_string(armored_sig.trim_end()).unwrap();
        sig.verify(&SignedPublicKey::from(k.clone()), signed.as_bytes()).unwrap();
        assert!(signed.contains("hello"), "{signed}");
    }
}
