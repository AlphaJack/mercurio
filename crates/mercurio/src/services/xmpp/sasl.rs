//! SASL mechanisms: PLAIN (RFC 4616) and SCRAM-SHA-1/-256/-512 (RFC 5802, RFC 7677), with or without channel binding (`-PLUS`, RFC 5929 and RFC 9266).

use std::num::NonZeroU32;

use crate::crypto;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mech {
    ScramSha512,
    ScramSha256,
    ScramSha1,
    Plain,
}

impl Mech {
    /// Strongest first.
    pub(super) const PREFERENCE: [Mech; 4] = [Mech::ScramSha512, Mech::ScramSha256, Mech::ScramSha1, Mech::Plain];

    pub(super) fn name(self) -> &'static str {
        match self {
            Mech::ScramSha512 => "SCRAM-SHA-512",
            Mech::ScramSha256 => "SCRAM-SHA-256",
            Mech::ScramSha1 => "SCRAM-SHA-1",
            Mech::Plain => "PLAIN",
        }
    }

    /// Best SCRAM mechanism the server offers with channel binding (`SCRAM-*-PLUS`).
    pub(super) fn choose_plus<'a>(offered: impl IntoIterator<Item = &'a str> + Clone) -> Option<Mech> {
        Mech::PREFERENCE.into_iter().filter(|m| *m != Mech::Plain).find(|m| {
            let plus = format!("{}-PLUS", m.name());
            offered.clone().into_iter().any(|o| o.trim().eq_ignore_ascii_case(&plus))
        })
    }

    /// Best mechanism the server offers. PLAIN is refused on an unencrypted stream (it would reveal the password).
    pub(super) fn choose<'a>(offered: impl IntoIterator<Item = &'a str> + Clone, encrypted: bool) -> Option<Mech> {
        Mech::PREFERENCE.into_iter().find(|m| {
            (encrypted || *m != Mech::Plain) && offered.clone().into_iter().any(|o| o.trim().eq_ignore_ascii_case(m.name()))
        })
    }
}

/// `\0user\0password`, base64.
pub(super) fn plain(user: &str, password: &str) -> String {
    crypto::b64(format!("\0{user}\0{password}").as_bytes())
}

#[derive(Debug, Clone, Copy)]
enum Hash {
    Sha1,
    Sha256,
    Sha512,
}

impl Hash {
    fn hash(self, d: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha1 => crypto::sha1(d),
            Hash::Sha256 => crypto::sha256(d),
            Hash::Sha512 => crypto::sha512(d),
        }
    }

    fn hmac(self, k: &[u8], d: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha1 => crypto::hmac_sha1(k, d),
            Hash::Sha256 => crypto::hmac_sha256(k, d),
            Hash::Sha512 => crypto::hmac_sha512(k, d),
        }
    }

    /// Tests derive the same few keys again and again, each in a new session: there, each is derived once per process.
    fn pbkdf2(self, password: &[u8], salt: &[u8], iterations: NonZeroU32) -> Vec<u8> {
        let (alg, len) = match self {
            Hash::Sha1 => (ring::pbkdf2::PBKDF2_HMAC_SHA1, 20),
            Hash::Sha256 => (ring::pbkdf2::PBKDF2_HMAC_SHA256, 32),
            Hash::Sha512 => (ring::pbkdf2::PBKDF2_HMAC_SHA512, 64),
        };
        let derive = || {
            let mut out = vec![0u8; len];
            ring::pbkdf2::derive(alg, iterations, salt, password, &mut out);
            out
        };
        #[cfg(any(test, feature = "testing"))]
        {
            type Derived = std::collections::BTreeMap<(usize, Vec<u8>, Vec<u8>, u32), Vec<u8>>;
            static DERIVED: std::sync::Mutex<Derived> = std::sync::Mutex::new(std::collections::BTreeMap::new());
            let id = (len, password.to_vec(), salt.to_vec(), iterations.get());
            if let Some(k) = DERIVED.lock().ok().and_then(|d| d.get(&id).cloned()) {
                return k;
            }
            let k = derive();
            if let Ok(mut d) = DERIVED.lock() {
                d.insert(id, k.clone());
            }
            k
        }
        #[cfg(not(any(test, feature = "testing")))]
        derive()
    }
}

/// Client side of one SCRAM exchange.
#[derive(Debug)]
pub(super) struct Scram {
    hash: Hash,
    /// The GS2 header: `n,,` without channel binding, `p={type},,` with it.
    gs2: String,
    /// The channel binding data sent (base64) with the GS2 header in `c=`.
    binding: Vec<u8>,
    first_bare: String,
    nonce: String,
    server_signature: Option<Vec<u8>>,
}

/// Iteration counts above this are refused (a hostile server could otherwise stall us for minutes).
const MAX_ITERATIONS: u32 = 1_000_000;

/// SCRAM `saslname`: `=` and `,` escaped.
fn saslname(s: &str) -> String {
    s.replace('=', "=3D").replace(',', "=2C")
}

impl Scram {
    pub(super) fn new(mech: Mech, user: &str, env: &dyn crate::Env) -> Scram {
        Scram::with_nonce(mech, user, &crypto::b64(&random24(env)))
    }

    pub(super) fn with_nonce(mech: Mech, user: &str, nonce: &str) -> Scram {
        let hash = match mech {
            Mech::ScramSha512 => Hash::Sha512,
            Mech::ScramSha256 => Hash::Sha256,
            Mech::ScramSha1 | Mech::Plain => Hash::Sha1,
        };
        Scram {
            hash,
            gs2: "n,,".into(),
            binding: Vec::new(),
            first_bare: format!("n={},r={nonce}", saslname(user)),
            nonce: nonce.to_owned(),
            server_signature: None,
        }
    }

    /// Bind the exchange to the TLS session: `kind` is the binding type's name (`tls-exporter`), `data` what the connection reported. The mechanism must then be sent with `-PLUS`.
    pub(super) fn with_binding(mut self, kind: &str, data: Vec<u8>) -> Scram {
        self.gs2 = format!("p={kind},,");
        self.binding = data;
        self
    }

    /// The channel binding type in use, or `no channel binding`.
    pub(super) fn binding_name(&self) -> &str {
        self.gs2.strip_prefix("p=").and_then(|g| g.strip_suffix(",,")).unwrap_or("no channel binding")
    }

    /// `client-first-message`: the GS2 header, then `n=user,r=nonce`.
    pub(super) fn client_first(&self) -> String {
        format!("{}{}", self.gs2, self.first_bare)
    }

    /// Answer the `server-first-message` with the `client-final-message`.
    pub(super) fn client_final(&mut self, server_first: &str, password: &str) -> Result<String> {
        let bad = || Error::service("XMPP: malformed SCRAM challenge");
        let mut nonce = None;
        let mut salt = None;
        let mut iterations = None;
        for part in server_first.split(',') {
            if let Some(v) = part.strip_prefix("r=") {
                nonce = Some(v);
            } else if let Some(v) = part.strip_prefix("s=") {
                salt = crypto::b64_decode(v);
            } else if let Some(v) = part.strip_prefix("i=") {
                iterations = v.parse::<u32>().ok();
            } else if part.starts_with("m=") {
                return Err(Error::service("XMPP: unsupported SCRAM extension"));
            }
        }
        let nonce = nonce.ok_or_else(bad)?;
        let salt = salt.ok_or_else(bad)?;
        let iterations = iterations.and_then(NonZeroU32::new).ok_or_else(bad)?;
        if iterations.get() > MAX_ITERATIONS {
            return Err(Error::service("XMPP: SCRAM iteration count too high"));
        }
        if !nonce.starts_with(&self.nonce) || nonce.len() <= self.nonce.len() {
            return Err(Error::service("XMPP: SCRAM server nonce mismatch"));
        }
        let h = self.hash;
        let salted = h.pbkdf2(password.as_bytes(), &salt, iterations);
        let client_key = h.hmac(&salted, b"Client Key");
        let stored_key = h.hash(&client_key);
        let cbind = crypto::b64(&[self.gs2.as_bytes(), &self.binding].concat());
        let without_proof = format!("c={cbind},r={nonce}");
        let auth_message = format!("{},{server_first},{without_proof}", self.first_bare);
        let client_sig = h.hmac(&stored_key, auth_message.as_bytes());
        let proof: Vec<u8> = client_key.iter().zip(&client_sig).map(|(a, b)| a ^ b).collect();
        let server_key = h.hmac(&salted, b"Server Key");
        self.server_signature = Some(h.hmac(&server_key, auth_message.as_bytes()));
        Ok(format!("{without_proof},p={}", crypto::b64(&proof)))
    }

    /// Check the `server-final-message` (`v=...`).
    pub(super) fn verify(&self, server_final: &str) -> Result<()> {
        if let Some(e) = server_final.strip_prefix("e=") {
            return Err(Error::service(format!("XMPP authentication failed: {e}")));
        }
        let got = server_final.split(',').find_map(|p| p.strip_prefix("v=")).and_then(crypto::b64_decode);
        match (&self.server_signature, got) {
            (Some(expected), Some(got)) if *expected == got => Ok(()),
            _ => Err(Error::service("XMPP: SCRAM server signature mismatch")),
        }
    }
}

fn random24(env: &dyn crate::Env) -> [u8; 24] {
    let mut b = [0u8; 24];
    env.fill_random(&mut b);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc5802_sha1_vector() {
        let mut s = Scram::with_nonce(Mech::ScramSha1, "user", "fyko+d2lbbFgONRv9qkxdawL");
        assert_eq!(s.client_first(), "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL");
        let fin = s
            .client_final("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", "pencil")
            .unwrap();
        assert_eq!(fin, "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=");
        s.verify("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=").unwrap();
        assert!(s.verify("v=AAAA").is_err());
        assert!(s.verify("e=invalid-proof").is_err());
    }

    #[test]
    fn plus_mechanisms_and_binding() {
        assert_eq!(Mech::choose_plus(["SCRAM-SHA-1-PLUS", "SCRAM-SHA-256-PLUS", "SCRAM-SHA-512"]), Some(Mech::ScramSha256));
        assert_eq!(Mech::choose_plus(["SCRAM-SHA-256", "PLAIN"]), None);
        let mut s = Scram::with_nonce(Mech::ScramSha1, "user", "abc").with_binding("tls-exporter", b"xyz".to_vec());
        assert_eq!(s.client_first(), "p=tls-exporter,,n=user,r=abc");
        let fin = s.client_final("r=abcdef,s=QSXCR+Q6sek8bf92,i=4096", "pencil").unwrap();
        // c = base64("p=tls-exporter,," + "xyz")
        assert!(fin.starts_with("c=cD10bHMtZXhwb3J0ZXIsLHh5eg==,r=abcdef,p="), "{fin}");
    }

    #[test]
    fn rfc7677_sha256_vector() {
        let mut s = Scram::with_nonce(Mech::ScramSha256, "user", "rOprNGfwEbeRWgbNEkqO");
        let fin = s
            .client_final(
                "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
                "pencil",
            )
            .unwrap();
        assert_eq!(
            fin,
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        s.verify("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=").unwrap();
    }

    #[test]
    fn rejects_bad_challenges() {
        let mut s = Scram::with_nonce(Mech::ScramSha1, "u", "abc");
        assert!(s.client_final("r=xyz,s=QSXCR+Q6sek8bf92,i=4096", "p").is_err());
        assert!(s.client_final("r=abcd,s=QSXCR+Q6sek8bf92,i=0", "p").is_err());
        assert!(s.client_final("r=abcd,s=QSXCR+Q6sek8bf92,i=99999999", "p").is_err());
        assert!(s.client_final("r=abcd,i=1", "p").is_err());
    }

    #[test]
    fn choose_prefers_scram_and_guards_plain() {
        assert_eq!(Mech::choose(["PLAIN", "SCRAM-SHA-1"], true), Some(Mech::ScramSha1));
        assert_eq!(Mech::choose(["PLAIN"], true), Some(Mech::Plain));
        assert_eq!(Mech::choose(["PLAIN"], false), None);
        assert_eq!(Mech::choose(["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"], false), Some(Mech::ScramSha256));
        assert_eq!(plain("u", "p"), crypto::b64(b"\0u\0p"));
        assert_eq!(saslname("a=b,c"), "a=3Db=2Cc");
    }
}
