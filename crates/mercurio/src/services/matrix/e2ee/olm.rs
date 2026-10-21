//! The outbound half of Olm: the device's account (identity and one-time keys) and the sessions that carry room keys to other devices.

use super::*;

/// Device-level Curve25519 identity key + Ed25519 signing key.
#[derive(Debug)]
pub struct OlmAccount {
    ik: XKey,
    sk: SigningKey,
    /// `{"id": ..., "sk": ...}` of the published fallback key.
    fallback_otk: Option<Value>,
}

impl Drop for OlmAccount {
    fn drop(&mut self) {
        if let Some(Value::Object(f)) = &mut self.fallback_otk
            && let Some(Value::String(sk)) = f.get_mut("sk")
        {
            sk.zeroize();
        }
    }
}

impl OlmAccount {
    pub fn new(env: &dyn Env) -> Self {
        Self { ik: XKey::generate(env), sk: SigningKey::generate(env), fallback_otk: None }
    }

    #[cfg(test)]
    pub fn from_keys(ik: XKey, sk: SigningKey) -> Self {
        Self { ik, sk, fallback_otk: None }
    }

    pub fn identity_key(&self) -> String {
        b64enc(&self.ik.public())
    }

    pub fn signing_key(&self) -> String {
        b64enc(self.sk.public())
    }

    pub fn sign(&self, data: &[u8]) -> String {
        self.sk.sign_b64(data)
    }

    #[cfg(test)]
    pub fn identity_private(&self) -> &XKey {
        &self.ik
    }

    pub fn to_value(&self) -> Value {
        json!({"ik": self.ik.to_b64(), "sk": self.sk.seed_b64(), "fallback_otk": self.fallback_otk})
    }

    pub fn from_value(v: &Value) -> CResult<Self> {
        let ik = v.get("ik").and_then(Value::as_str).ok_or(CryptoError("missing ik"))?;
        let sk = v.get("sk").and_then(Value::as_str).ok_or(CryptoError("missing sk"))?;
        let ik = XKey::from_b64(ik)?;
        let sk = SigningKey::from_b64(sk)?;
        let fallback_otk = v.get("fallback_otk").filter(|f| !f.is_null()).cloned();
        Ok(Self { ik, sk, fallback_otk })
    }

    /// Signed `device_keys` for `POST /keys/upload`.
    pub fn device_keys_payload(&self, user_id: &str, device_id: &str) -> Value {
        let mut dk = json!({
            "algorithms": [OLM_ALGORITHM, MEGOLM_ALGORITHM],
            "device_id": device_id,
            "keys": {
                format!("curve25519:{device_id}"): self.identity_key(),
                format!("ed25519:{device_id}"): self.signing_key(),
            },
            "user_id": user_id,
        });
        let sig = self.sign(canonical_json(&dk).as_bytes());
        dk["signatures"] = json!({user_id: {format!("ed25519:{device_id}"): sig}});
        dk
    }

    fn signed_curve25519_key(&self, user_id: &str, device_id: &str, key_b64: &str) -> Value {
        let mut p = json!({"key": key_b64});
        let sig = self.sign(canonical_json(&p).as_bytes());
        p["signatures"] = json!({user_id: {format!("ed25519:{device_id}"): sig}});
        p
    }

    /// Signed `fallback_keys` (creates the fallback key on first use).
    pub fn fallback_keys_payload(&mut self, user_id: &str, device_id: &str, env: &dyn Env) -> Value {
        let parsed = self.fallback_otk.as_ref().and_then(|f| {
            let id = f.get("id")?.as_str()?.to_string();
            let sk = XKey::from_b64(f.get("sk")?.as_str()?).ok()?;
            Some((id, sk))
        });
        let (id, sk) = match parsed {
            Some(p) => p,
            None => {
                let id = env.uuid4().replace('-', "").get(..10).unwrap_or_default().to_string();
                let sk = XKey::generate(env);
                self.fallback_otk = Some(json!({"id": id, "sk": sk.to_b64()}));
                (id, sk)
            }
        };
        json!({format!("signed_curve25519:{id}"): self.signed_curve25519_key(user_id, device_id, &b64enc(&sk.public()))})
    }

    /// Outbound Olm session (X3DH) to a device.
    pub fn create_outbound_session(&self, their_ik_b64: &str, their_otk_b64: &str, env: &dyn Env) -> CResult<OlmSession> {
        self.create_outbound_session_with(their_ik_b64, their_otk_b64, XKey::generate(env))
    }

    pub fn create_outbound_session_with(
        &self,
        their_ik_b64: &str,
        their_otk_b64: &str,
        eph: XKey,
    ) -> CResult<OlmSession> {
        let their_ik = b64dec(their_ik_b64)?;
        let their_otk = b64dec(their_otk_b64)?;
        if their_ik.len() != 32 || their_otk.len() != 32 {
            return Err(CryptoError("curve25519 keys must be 32 bytes"));
        }
        let dh1 = Zeroizing::new(self.ik.exchange(&their_otk)?);
        let dh2 = Zeroizing::new(eph.exchange(&their_ik)?);
        let dh3 = Zeroizing::new(eph.exchange(&their_otk)?);
        let mut ikm = Zeroizing::new(Vec::with_capacity(96));
        ikm.extend_from_slice(&dh1[..]);
        ikm.extend_from_slice(&dh2[..]);
        ikm.extend_from_slice(&dh3[..]);
        let keys = hkdf_sha256(&ikm, 64, None, b"OLM_ROOT");
        let mut chain = [0u8; 32];
        chain.copy_from_slice(&keys[32..]);
        Ok(OlmSession {
            our_ik_pub: self.ik.public(),
            eph_pub: eph.public(),
            their_otk_pub: their_otk,
            chain_key: chain,
            counter: 0,
        })
    }
}

/// Single-use outbound Olm session (pre-key messages only).
#[derive(Debug)]
pub struct OlmSession {
    our_ik_pub: [u8; 32],
    eph_pub: [u8; 32],
    their_otk_pub: Vec<u8>,
    chain_key: [u8; 32],
    counter: u64,
}

impl Drop for OlmSession {
    fn drop(&mut self) {
        self.chain_key.zeroize();
    }
}

impl OlmSession {
    /// Encrypt as an Olm pre-key (type 0) message: `{"type": 0, "body": ...}`.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Value {
        let msg_key = Zeroizing::new(hmac_sha256(&self.chain_key, b"\x01"));
        self.chain_key = hmac_sha256(&self.chain_key, b"\x02");
        let keys = hkdf_sha256(&msg_key[..], 80, Some(&[0u8; 32]), b"OLM_KEYS");
        let (aes_key, mac_key, iv) = split_keys(&keys);
        let ct = aes_cbc_encrypt(&aes_key, &iv, plaintext);
        let mut inner = vec![3u8];
        inner.extend(pb_bytes(1, &self.eph_pub));
        inner.extend(pb_varint(2, self.counter));
        inner.extend(pb_bytes(4, &ct));
        let mac = hmac_sha256(&mac_key[..], &inner);
        inner.extend_from_slice(&mac[..8]);
        let mut outer = vec![3u8];
        outer.extend(pb_bytes(1, &self.their_otk_pub));
        outer.extend(pb_bytes(2, &self.eph_pub));
        outer.extend(pb_bytes(3, &self.our_ik_pub));
        outer.extend(pb_bytes(4, &inner));
        self.counter += 1;
        json!({"type": 0, "body": b64enc(&outer)})
    }
}

