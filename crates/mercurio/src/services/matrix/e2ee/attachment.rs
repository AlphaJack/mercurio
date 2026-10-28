//! Attachment encryption (Matrix `EncryptedFile` v2, AES-256-CTR).

use super::*;

/// Encrypt attachment bytes (Matrix `EncryptedFile` v2, AES-256-CTR).
pub(crate) fn encrypt_attachment(data: &[u8], env: &dyn Env) -> (Vec<u8>, Value) {
    let key = Zeroizing::new(random32(env));
    let mut iv = [0u8; 16];
    env.fill_random(&mut iv[..8]);
    encrypt_attachment_with(data, &key, &iv)
}

pub(super) fn encrypt_attachment_with(data: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> (Vec<u8>, Value) {
    let ct = aes_ctr(key, iv, data);
    let digest = sha256(&ct);
    let info = json!({
        "v": "v2",
        "key": {
            "kty": "oct",
            "key_ops": ["encrypt", "decrypt"],
            "alg": "A256CTR",
            "k": b64url_nopad(key),
            "ext": true,
        },
        "iv": b64enc(iv),
        "hashes": {"sha256": b64enc(&digest)},
    });
    (ct, info)
}
