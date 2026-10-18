//! Helpers shared by the crypto services: local key files; PEM and DER decoding; JSON merging.

use base64::Engine;

use crate::url::unquote;

/// Read a file referenced as a plain local path or a `file://` URL. Remote (`http://`, ...) sources are not supported. Files larger than `max_size` bytes (when non-zero) are refused, like `AttachBase.max_file_size`.
pub fn read_local_file(spec: &str, max_size: u64) -> Option<Vec<u8>> {
    let path = local_path(spec)?;
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() || (max_size > 0 && meta.len() > max_size) {
        return None;
    }
    std::fs::read(&path).ok()
}

/// The local filesystem path a keyfile/subfile reference points at; `None` for remote URLs.
pub fn local_path(spec: &str) -> Option<String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    if let Some(scheme) = crate::url::scheme_of(spec) {
        if scheme != "file" {
            return None;
        }
        let (_, rest) = spec.split_once("://")?;
        let rest = rest.split(['?', '#']).next().unwrap_or("");
        return Some(unquote(rest)).filter(|p| !p.is_empty());
    }
    Some(spec.to_string())
}

/// Decode the first PEM block; returns `(label, der)`.
pub fn pem_decode(text: &str) -> Option<(String, Vec<u8>)> {
    let (_, rest) = text.split_once("-----BEGIN ")?;
    let (label, body) = rest.split_once("-----")?;
    let label = label.trim().to_string();
    let (body, _) = body.split_once(&format!("-----END {label}-----"))?;
    let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    Some((label, der))
}

/// One DER TLV: `(tag, contents, rest)`.
pub fn der_next(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (&first, mut rest) = rest.split_first()?;
    let len = if first & 0x80 == 0 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let mut len = 0usize;
        for &b in &rest[..n] {
            len = (len << 8) | b as usize;
        }
        rest = &rest[n..];
        len
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// Extract the raw P-256 private scalar and uncompressed public point from a PKCS#8 or SEC1 (`EC PRIVATE KEY`) DER structure.
pub fn p256_keys_from_der(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (tag, seq, _) = der_next(der)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, version, rest) = der_next(seq)?;
    if tag != 0x02 {
        return None;
    }
    if version == [0] {
        // PKCS#8: AlgorithmIdentifier, then the ECPrivateKey in an OCTET STRING.
        let (tag, alg, rest) = der_next(rest)?;
        if tag != 0x30 {
            return None;
        }
        let (tag, oid, params) = der_next(alg)?;
        if tag != 0x06 || oid != OID_EC_PUBLIC_KEY {
            return None;
        }
        if let Some((0x06, curve, _)) = der_next(params)
            && curve != OID_PRIME256V1
        {
            return None;
        }
        let (tag, inner, _) = der_next(rest)?;
        if tag != 0x04 {
            return None;
        }
        return p256_keys_from_der(inner);
    }
    if version != [1] {
        return None;
    }
    let (tag, private, mut rest) = der_next(rest)?;
    if tag != 0x04 || private.len() > 32 {
        return None;
    }
    let mut scalar = vec![0u8; 32 - private.len()];
    scalar.extend_from_slice(private);
    let mut public = None;
    while let Some((tag, value, next)) = der_next(rest) {
        match tag {
            0xa0 => {
                let (t, oid, _) = der_next(value)?;
                if t != 0x06 || oid != OID_PRIME256V1 {
                    return None;
                }
            }
            0xa1 => {
                let (t, bits, _) = der_next(value)?;
                if t != 0x03 || bits.first() != Some(&0) {
                    return None;
                }
                public = Some(bits[1..].to_vec());
            }
            _ => {}
        }
        rest = next;
    }
    Some((scalar, public?))
}

/// Recursively merge `src` into `dst`.
pub fn json_full_update(dst: &mut serde_json::Value, src: &serde_json::Value) {
    match (dst, src) {
        (serde_json::Value::Object(d), serde_json::Value::Object(s)) => {
            for (k, v) in s {
                match d.get_mut(k) {
                    Some(existing) if existing.is_object() && v.is_object() => json_full_update(existing, v),
                    _ => {
                        d.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        (d, s) => *d = s.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(local_path("/tmp/a b.json").as_deref(), Some("/tmp/a b.json"));
        assert_eq!(local_path("file:///tmp/a%20b.json").as_deref(), Some("/tmp/a b.json"));
        assert_eq!(local_path("https://example.com/a.json"), None);
    }
}
