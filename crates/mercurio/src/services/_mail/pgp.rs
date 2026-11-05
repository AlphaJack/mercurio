//! OpenPGP for e-mail and Delta Chat (`?pgp=`), written in-house on `ring` (RFC 9580): what the parts share (ASCII armor, packets, MPIs, big-number reduction). Signing is in `sign`, encryption in `encrypt`, key generation and the Autocrypt header in `keys`, Web Key Directory lookups in `wkd`.

mod packets;
use packets::{algorithm_name, armor, big_mod, dearmor, first_packet, limbs, magnitude, minus_one, mpi, next_packet, packet, put_mpi};
use crate::crypto;

mod encrypt;
mod keys;
mod sign;
pub(crate) mod wkd;
pub(crate) use encrypt::encrypt;
pub(crate) use keys::{autocrypt_header, generate};
pub(crate) use sign::sign;
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














#[cfg(test)]
mod tests {
    use super::*;
    use super::packets::crc24;

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
                seen.lock().unwrap().push(line.to_owned());
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
