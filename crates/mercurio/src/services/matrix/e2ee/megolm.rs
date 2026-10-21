//! The outbound half of Megolm: the room session that encrypts messages, and when it rotates.

use super::*;

/// Outbound Megolm session (ratchet wiped on drop).
#[derive(Debug)]
pub struct MegolmSession {
    pub(super) ratchet: [[u8; 32]; 4],
    counter: u32,
    sk: SigningKey,
    pub session_id: String,
    pub created_at: f64,
}

impl Drop for MegolmSession {
    fn drop(&mut self) {
        self.ratchet.zeroize();
    }
}

impl MegolmSession {
    pub fn new(env: &dyn Env) -> Self {
        let ratchet = [random32(env), random32(env), random32(env), random32(env)];
        Self::from_parts(ratchet, 0, SigningKey::generate(env), env.unix_time_f64())
    }

    pub fn from_parts(ratchet: [[u8; 32]; 4], counter: u32, sk: SigningKey, created_at: f64) -> Self {
        let session_id = b64enc(sk.public());
        Self { ratchet, counter, sk, session_id, created_at }
    }

    #[cfg(test)]
    pub fn counter(&self) -> u32 {
        self.counter
    }

    pub(super) fn advance(&mut self) {
        let r = &mut self.ratchet;
        let n1 = self.counter.wrapping_add(1);
        let h = if n1.is_multiple_of(1 << 24) {
            0
        } else if n1.is_multiple_of(1 << 16) {
            1
        } else if n1.is_multiple_of(1 << 8) {
            2
        } else {
            3
        };
        let orig = Zeroizing::new(r[h]);
        for i in (h..4).rev() {
            r[i] = hmac_sha256(&orig[..], &[i as u8]);
        }
        self.counter = n1;
    }

    pub(super) fn message_keys(&self) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>, [u8; 16]) {
        let ratchet = Zeroizing::new(self.ratchet.concat());
        let keys = hkdf_sha256(&ratchet, 80, None, b"MEGOLM_KEYS");
        split_keys(&keys)
    }

    pub fn should_rotate(&self, env: &dyn Env) -> bool {
        self.counter >= MEGOLM_ROTATION_MSGS || env.unix_time_f64() - self.created_at >= MEGOLM_ROTATION_AGE
    }

    /// Encrypt bytes; returns the base64 Megolm message.
    pub fn encrypt_bytes(&mut self, plaintext: &[u8]) -> String {
        let (aes_key, mac_key, iv) = self.message_keys();
        let ct = aes_cbc_encrypt(&aes_key, &iv, plaintext);
        let mut body = vec![3u8];
        body.extend(pb_varint(1, self.counter as u64));
        body.extend(pb_bytes(2, &ct));
        let mac = hmac_sha256(&mac_key[..], &body);
        body.extend_from_slice(&mac[..8]);
        let sig = self.sk.sign(&body);
        body.extend_from_slice(&sig);
        self.advance();
        b64enc(&body)
    }

    /// Encrypt a JSON event (compact serialisation).
    pub fn encrypt(&mut self, event: &Value) -> String {
        self.encrypt_bytes(event.to_string().as_bytes())
    }

    /// Exportable session key (`m.room_key` `session_key`).
    pub fn session_key(&self) -> String {
        let mut payload = Zeroizing::new(Vec::with_capacity(229));
        payload.push(2u8);
        payload.extend_from_slice(&self.counter.to_be_bytes());
        for part in &self.ratchet {
            payload.extend_from_slice(part);
        }
        payload.extend_from_slice(self.sk.public());
        let sig = self.sk.sign(&payload);
        payload.extend_from_slice(&sig);
        b64enc(&payload)
    }

    pub fn to_value(&self) -> Value {
        json!({
            "version": MATRIX_MEGOLM_STORE_VERSION,
            "ratchet": self.ratchet.iter().map(|r| b64enc(r)).collect::<Vec<_>>(),
            "counter": self.counter,
            "sk": self.sk.seed_b64(),
            "session_id": self.session_id,
            "created_at": self.created_at,
        })
    }

    pub fn from_value(v: &Value, env: &dyn Env) -> CResult<Self> {
        if v.get("version").and_then(Value::as_u64) != Some(MATRIX_MEGOLM_STORE_VERSION) {
            return Err(CryptoError("incompatible Megolm session cache format"));
        }
        let parts = v.get("ratchet").and_then(Value::as_array).ok_or(CryptoError("missing ratchet"))?;
        if parts.len() != 4 {
            return Err(CryptoError("ratchet must have 4 parts"));
        }
        let mut ratchet = Zeroizing::new([[0u8; 32]; 4]);
        for (slot, p) in ratchet.iter_mut().zip(parts) {
            let raw = Zeroizing::new(b64dec(p.as_str().ok_or(CryptoError("ratchet part"))?)?);
            *slot = <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| CryptoError("ratchet part must be 32 bytes"))?;
        }
        let counter = v.get("counter").and_then(Value::as_u64).ok_or(CryptoError("missing counter"))?;
        let counter = u32::try_from(counter).map_err(|_| CryptoError("counter out of range"))?;
        let sk = SigningKey::from_b64(v.get("sk").and_then(Value::as_str).ok_or(CryptoError("missing sk"))?)?;
        let created_at = v.get("created_at").and_then(Value::as_f64).unwrap_or_else(|| env.unix_time_f64());
        Ok(Self::from_parts(*ratchet, counter, sk, created_at))
    }
}
