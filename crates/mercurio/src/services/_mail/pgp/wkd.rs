//! Web Key Directory (RFC 9080): where a recipient's OpenPGP key is published, as Apprise's `AppriseWKDController` looks it up.

use crate::parse::is_hostname;

/// The z-base-32 alphabet (RFC 6189).
const ZB32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// Largest key answer accepted (Apprise's `max_response_size`).
pub const MAX_RESPONSE: usize = 65_536;

/// z-base-32 of `data`: five bits per character, the last group zero-padded.
fn zb32(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in data {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ZB32[((acc >> bits) & 0x1f) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ZB32[((acc << (5 - bits)) & 0x1f) as usize]));
    }
    out
}

/// The advanced (`openpgpkey.` subdomain) and direct lookup URLs for `email`, tried in that order; `None` when it is not an address on a host name.
pub fn urls(email: &str) -> Option<(String, String)> {
    let (local_orig, domain) = email.trim().split_once('@')?;
    let (local, domain) = (local_orig.to_lowercase(), domain.to_lowercase());
    if local.is_empty() || domain.is_empty() || is_hostname(&domain, false, false, false).is_none() {
        return None;
    }
    let hash = zb32(&crate::crypto::sha1(local.as_bytes()));
    let l = crate::url::quote(local_orig, "/");
    Some((
        format!("https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{hash}?l={l}"),
        format!("https://{domain}/.well-known/openpgpkey/hu/{hash}?l={l}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9080's example: `Joe.Doe@Example.ORG`.
    #[test]
    fn rfc9080_example() {
        let (advanced, direct) = urls("Joe.Doe@Example.ORG").unwrap();
        assert_eq!(
            advanced,
            "https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe"
        );
        assert_eq!(direct, "https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe");
        assert_eq!(urls("nobody"), None);
        assert_eq!(urls("a@b_c"), None);
    }
}
