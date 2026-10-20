//! Session Open Group Server (`session://`, `sessions://`, `sogs://`): messages to Session open group rooms.
//!
//! Every request is authenticated with the `X-SOGS-*` headers: an Ed25519 signature (by the bot's seed) over the server key, a random nonce, the timestamp, method, path and the BLAKE2b-512 hash of the body.

use blake2::{Blake2b512, Digest};
use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::crypto::{b64, hex};
use crate::error::Error;
use crate::parse::parse_list;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "sogs",
    name: "Session Open Group Server",
    schemes: &["session", "sessions", "sogs"],
    service_url: "https://getsession.org/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 2000, body_max_line_count: 0 },
    templates: &[
        "{schema}://{user}:{password}@{host}/{targets}",
        "{schema}://{user}:{password}@{host}:{port}/{targets}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("password", "Seed").required().secret(),
        Param::new("port", "Port").port(),
        Param::new("targets", "Rooms").list("/"),
        Param::new("user", "Public Key").required(),
    ],
    params: &[
        Param::sets("key", &["user"]),
        Param::sets("public_key", &["user"]),
        Param::sets("seed", &["password"]),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

/// Responses larger than this are not accepted (`max_response_size`).
const MAX_RESPONSE_SIZE: usize = 32768;

struct Sogs {
    base: String,
    /// Server public key (raw 32 bytes).
    server_key: Vec<u8>,
    seed: Secret,
    key: Ed25519KeyPair,
    rooms: Vec<String>,
}

impl std::fmt::Debug for Sogs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sogs").field("base", &self.base).field("seed", &self.seed).field("rooms", &self.rooms).finish()
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}


fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let mut public_key = u.user.as_deref().filter(|s| !s.is_empty()).map(unquote);
    let mut seed = u.password.as_deref().filter(|s| !s.is_empty()).map(unquote);
    if let Some(k) = SERVICE.text(u, "key") {
        public_key = Some(k);
    }
    if let Some(k) = SERVICE.text(u, "public_key") {
        public_key = Some(k);
    }
    if let Some(s) = SERVICE.text(u, "seed") {
        seed = Some(s);
    }
    let mut targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(crate::parse::parse_list_unquoted([to]));
    }

    let pk = public_key.unwrap_or_default().trim().to_lowercase();
    if !is_hex64(&pk) {
        return Err(SERVICE.err("the SOGS public_key must be exactly 64 hex characters"));
    }
    let seed = seed.unwrap_or_default().trim().to_lowercase();
    if !is_hex64(&seed) {
        return Err(SERVICE.err("the SOGS bot seed must be exactly 64 hex characters"));
    }
    let key = Ed25519KeyPair::from_seed_unchecked(&crate::crypto::unhex(&seed))
        .map_err(|_| SERVICE.err("the SOGS bot seed could not be loaded"))?;

    let room_re = crate::regex!(r"^[a-z0-9_-]{1,64}$");
    let rooms: Vec<String> =
        parse_list(&targets).into_iter().map(|t| t.trim().to_lowercase()).filter(|t| room_re.is_match(t)).collect();
    if rooms.is_empty() {
        return Err(SERVICE.err("at least one valid SOGS room token must be specified"));
    }

    let default_port = if u.secure { 443 } else { 80 };
    let host = match u.port {
        Some(p) if p != default_port => format!("{}:{p}", u.host()),
        _ => u.host(),
    };
    Ok(Box::new(Sogs {
        base: format!("{}://{host}", u.http_scheme()),
        server_key: crate::crypto::unhex(&pk),
        seed: Secret::new(seed),
        key,
        rooms,
    }))
}

fn encode_varint(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
}

fn ld_field(field: usize, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 6);
    encode_varint((field << 3) | 2, &mut out);
    encode_varint(data.len(), &mut out);
    out.extend_from_slice(data);
    out
}

/// `Content { dataMessage { body } }` plus the Session padding marker.
fn build_session_message(text: &str) -> Vec<u8> {
    let mut content = ld_field(1, &ld_field(1, text.as_bytes()));
    content.push(0x80);
    content
}

impl Sogs {
    /// The four `X-SOGS-*` headers for one request.
    fn auth_headers(&self, method: &str, path: &str, body: &[u8], nonce: &[u8; 16], ts: u64) -> Vec<(String, String)> {
        let ts = ts.to_string();
        let mut to_sign = self.server_key.clone();
        to_sign.extend_from_slice(nonce);
        to_sign.extend_from_slice(ts.as_bytes());
        to_sign.extend_from_slice(method.to_uppercase().as_bytes());
        to_sign.extend_from_slice(path.as_bytes());
        if !body.is_empty() {
            to_sign.extend_from_slice(&Blake2b512::digest(body));
        }
        let sig = self.key.sign(&to_sign);
        vec![
            ("X-SOGS-Pubkey".into(), format!("00{}", hex(self.key.public_key().as_ref()))),
            ("X-SOGS-Nonce".into(), b64(nonce)),
            ("X-SOGS-Timestamp".into(), ts),
            ("X-SOGS-Signature".into(), b64(sig.as_ref())),
        ]
    }
}

impl Notify for Sogs {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let data = build_session_message(msg.body);
        let sig = self.key.sign(&data);
        let (data_b64, sig_b64) = (b64(&data), b64(sig.as_ref()));
        let body = serde_json::json!({"data": data_b64, "signature": sig_b64}).to_string().into_bytes();

        Plan::all(self.rooms.iter().map(|room| {
            let path = format!("/room/{room}/message");
            let mut nonce = [0u8; 16];
            ctx.env().fill_random(&mut nonce);
            let mut req = ctx.post(format!("{}{path}", self.base)).header("Content-Type", "application/json");
            for (k, v) in self.auth_headers("POST", &path, &body, &nonce, ctx.env().unix_time()) {
                req = req.header(k, v);
            }
            let req = req.body(body.clone(), None);
            Plan::http(req, |res| match res {
                Err(e) => Plan::Fail(e),
                Ok(r) if r.body.len() > MAX_RESPONSE_SIZE => {
                    Plan::Fail(Error::Service("SOGS response exceeds the size limit".into()))
                }
                Ok(r) if matches!(r.status, 200 | 201) => Plan::Done,
                Ok(r) => Plan::Fail(r.http_error()),
            })
            .target(room.clone())
        }))
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{ED25519, UnparsedPublicKey};

    #[test]
    fn protobuf_message() {
        assert_eq!(build_session_message("hi"), vec![0x0a, 0x04, 0x0a, 0x02, b'h', b'i', 0x80]);
        let long = "x".repeat(200);
        let m = build_session_message(&long);
        // Inner: 0x0a, varint(200)=[0xc8,0x01]; outer len = 203 = [0xcb, 0x01]
        assert_eq!(&m[..5], &[0x0a, 0xcb, 0x01, 0x0a, 0xc8]);
        assert_eq!(*m.last().unwrap(), 0x80);
    }

    #[test]
    fn auth_signature_verifies() {
        let seed = "11".repeat(32);
        let pk = "a0".repeat(32);
        let u = crate::url::parse_url(&format!("sogs://{pk}:{seed}@example.com/room")).unwrap();
        let _ = parse(&u).unwrap();
        let key = Ed25519KeyPair::from_seed_unchecked(&crate::crypto::unhex(&seed)).unwrap();
        let s = Sogs {
            base: "https://example.com".into(),
            server_key: crate::crypto::unhex(&pk),
            seed: Secret::new(seed.clone()),
            key,
            rooms: vec!["room".into()],
        };
        let nonce = [7u8; 16];
        let body = b"{}";
        let h = s.auth_headers("post", "/room/room/message", body, &nonce, 1_700_000_000);
        let mut signed = crate::crypto::unhex(&pk);
        signed.extend_from_slice(&nonce);
        signed.extend_from_slice(b"1700000000POST/room/room/message");
        signed.extend_from_slice(&Blake2b512::digest(body));
        let sig = crate::crypto::b64_decode(&h[3].1).unwrap();
        let public = crate::crypto::unhex(h[0].1.get(2..).unwrap_or_default());
        UnparsedPublicKey::new(&ED25519, &public).verify(&signed, &sig).unwrap();
        assert_eq!(h[2].1, "1700000000");
        // BLAKE2b-512("abc") known answer.
        assert!(hex(&Blake2b512::digest(b"abc")).starts_with("ba80a53f981c4d0d6a2797b69f12f6e9"));
    }
}
