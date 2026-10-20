//! Vapid / Web Push (`vapid://`): Web Push messages signed with VAPID keys.
//!
//! Messages are encrypted per subscription with RFC 8291 (`aes128gcm`: ephemeral ECDH P-256, HKDF-SHA256, AES-128-GCM) and authorised with an RFC 8292 VAPID ES256 JWT addressed to each endpoint's origin.
//!
//! The private key (`?keyfile=`, PEM) and the subscriptions (`?subfile=`, JSON) are read from local files or downloaded from `http(s)://` URLs. Without `?keyfile=`, a disk-backed persistent store holds them: `private_key.pem` (generated on first use, with `public_key.pem`) and `subscriptions.json` in the URL's store directory. Expired (404/410) endpoints are kept in the store (`retired`, 30 days) and skipped.
//!
//! # Differences with Apprise
//!
//! - Both files are re-read on every send. *intentional*
//! - Expired endpoints are never pruned from the subscription file (Apprise rewrites a writable one) and no starter file is written. *intentional*

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ring::agreement::{ECDH_P256, EphemeralPrivateKey, UnparsedPublicKey, agree_ephemeral};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use ring::{aead, hkdf};
use serde_json::{Value, json};

use super::_keys::{local_file_ops, p256_keys_from_der, pem_decode, read_local_file, remote_fetches};
use crate::crypto::{b64_url_decode, b64_url_nopad};
use crate::env::Env;
use crate::error::Error;
use crate::parse::{is_email, is_hostname, parse_list, parse_list_unquoted};
use crate::service::{Context, Limits, Notify, Param, ServiceDef, UrlIdentifier};
use crate::transport::FileOp;
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "vapid",
    name: "Vapid Web Push Notifications",
    schemes: &["vapid"],
    service_url: "https://datatracker.ietf.org/doc/html/draft-thomson-webpush-vapid",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 4000, body_max_line_count: 0 },
    templates: &[
        "{schema}://{subscriber}",
        "{schema}://{subscriber}/{targets}",
    ],
    tokens: &[
        Param::new("subscriber", "API Key").required().secret(),
        Param::new("targets", "Targets").list("/"),
    ],
    params: &[
        Param::sets("from", &["subscriber"]),
        Param::new("keyfile", "PEM Private KeyFile").secret(),
        Param::new("mode", "Mode").choice(&["chrome", "firefox", "edge", "opera", "apple"]).default("chrome"),
        Param::new("subfile", "Subscripion File").secret(),
        Param::sets("to", &["targets"]),
        Param::new("ttl", "ttl").int().default("0").range(0, 60),
    ],
    ..ServiceDef::DEFAULTS
};

const MODES: &[&str] = &["chrome", "firefox", "edge", "opera", "apple"];
const MAX_KEYFILE_SIZE: u64 = 8000;
const MAX_SUBFILE_SIZE: u64 = 5_242_880;
const JWT_EXPIRATION_SECS: u64 = 43200;
const RECORD_SIZE: u32 = 4096;
const MAX_LOAD_FAILURES: usize = 3;
/// Store key and lifetime of retired (expired) endpoints.
const RETIRED_KEY: &str = "retired";
const RETIRED_EXPIRY: std::time::Duration = std::time::Duration::from_secs(60 * 60 * 24 * 30);
/// Key files looked for in the store directory.
const PRIVATE_KEY_FILES: &[&str] = &["private_key.pem", "private.pem", "prv.pem"];
/// DER prefix of a P-256 `SubjectPublicKeyInfo` (then the 65-byte point).
const SPKI_P256_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

#[derive(Debug)]
struct Vapid {
    subscriber: String,
    ttl: i64,
    keyfile: Option<String>,
    subfile: Option<String>,
    targets: Vec<String>,
    /// Lower-cased `?mode=` (default `chrome`), for the URL id.
    mode: String,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let user = u.user.as_deref().map(unquote).unwrap_or_default();
    let host = u.host();
    let mut targets = Vec::new();
    let subscriber = match u.param_nonempty("from") {
        Some(from) => {
            if !user.is_empty() && !host.is_empty() {
                targets.push(format!("{user}@{host}"));
            } else if !host.is_empty() {
                targets.push(host);
            }
            unquote(from)
        }
        None => format!("{user}@{host}"),
    };
    targets.extend(u.path_segments());
    let mode = u.param("mode").map(str::to_string);
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list_unquoted([to]));
    }
    let keyfile = SERVICE.text(u, "keyfile");
    let subfile = SERVICE.text(u, "subfile");
    let ttl_raw = SERVICE.text(u, "ttl");

    let mut ttl = 0;
    if let Some(t) = ttl_raw {
        ttl = crate::util::parse_int(&t).unwrap_or(0);
        if !(0..=60).contains(&ttl) {
            return Err(SERVICE.err("the Vapid TTL specified is out of range"));
        }
    }
    let subscriber = is_email(&subscriber)
        .map(|e| e.full_email)
        .ok_or_else(|| SERVICE.err("an invalid Vapid Subscriber was specified"))?;
    let mode = mode.map_or_else(|| MODES[0].to_string(), |m| m.to_lowercase());
    if !MODES.contains(&mode.as_str()) {
        return Err(SERVICE.err("the Vapid mode specified is invalid"));
    }
    let mut targets = parse_list(&targets);
    if targets.is_empty() {
        targets.push(subscriber.clone());
    }
    Ok(Box::new(Vapid { subscriber, ttl, keyfile, subfile, targets, mode }))
}

/// The HTTPS origin of a push endpoint.
fn webpush_origin(endpoint: &str) -> Option<String> {
    if endpoint.contains('#') {
        return None;
    }
    let (scheme, rest) = endpoint.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let netloc = rest.split(['/', '?']).next().unwrap_or("");
    if netloc.contains('@') {
        return None;
    }
    let (hostname, port) = if let Some(inner) = netloc.strip_prefix('[') {
        let (h, after) = inner.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p),
            None if after.is_empty() => None,
            None => return None,
        };
        (h.to_lowercase(), port)
    } else {
        match netloc.split_once(':') {
            Some((h, p)) => (h.to_lowercase(), Some(p)),
            None => (netloc.to_lowercase(), None),
        }
    };
    let port = match port.filter(|p| !p.is_empty()) {
        None => None,
        Some(p) => {
            if !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let n = u32::from(p.parse::<u16>().ok()?);
            if n == 0 {
                return None;
            }
            Some(n)
        }
    };
    if hostname.is_empty() || is_hostname(&hostname, true, true, true).is_none() {
        return None;
    }
    let host = if hostname.contains(':') { format!("[{hostname}]") } else { hostname };
    Some(match port {
        None | Some(443) => format!("https://{host}"),
        Some(p) => format!("https://{host}:{p}"),
    })
}

/// A validated subscription.
#[derive(Debug, Clone)]
struct Subscription {
    endpoint: String,
    origin: String,
    /// Uncompressed P-256 point of the user agent.
    public_key: Vec<u8>,
    auth_secret: Vec<u8>,
}

/// ring's generator, for the key generation, ECDH and ECDSA calls that take one. ring's `SecureRandom` is sealed, so the transport's [`Env`] can not stand in; the salt and the timestamps still come from it.
#[expect(clippy::disallowed_methods, reason = "ring's SecureRandom is sealed")]
fn ring_rng() -> SystemRandom {
    SystemRandom::new()
}

/// Check a point is on P-256 by running an ECDH against it.
/// A SEC1 P-256 point in its 65-byte uncompressed form, which the RFC 8291 key derivation hashes: a 33-byte compressed one is expanded (as Apprise re-encodes it), anything else is kept for [`valid_p256_point`] to judge. `None` for a compressed point not on the curve.
fn uncompressed(point: Vec<u8>) -> Option<Vec<u8>> {
    if point.len() != 33 || !matches!(point[0], 2 | 3) {
        return Some(point);
    }
    use p256::elliptic_curve::sec1::ToSec1Point;
    let key = p256::PublicKey::from_sec1_bytes(&point).ok()?;
    Some(key.to_sec1_point(false).as_bytes().to_vec())
}

fn valid_p256_point(point: &[u8]) -> bool {
    let rng = ring_rng();
    let Ok(eph) = EphemeralPrivateKey::generate(&ECDH_P256, &rng) else { return false };
    agree_ephemeral(eph, &UnparsedPublicKey::new(&ECDH_P256, point), |_| ()).is_ok()
}

fn load_subscription(content: &Value) -> Option<Subscription> {
    let obj = content.as_object()?;
    let endpoint = obj.get("endpoint")?.as_str()?.trim().to_string();
    let origin = webpush_origin(&endpoint)?;
    let keys = obj.get("keys")?.as_object()?;
    let p256dh = uncompressed(b64_url_decode(keys.get("p256dh")?.as_str()?).filter(|k| !k.is_empty())?)?;
    let auth = b64_url_decode(keys.get("auth")?.as_str()?).filter(|k| !k.is_empty())?;
    if !valid_p256_point(&p256dh) {
        return None;
    }
    Some(Subscription { endpoint, origin, public_key: p256dh, auth_secret: auth })
}

/// Named subscriptions, in file order.
type Subscriptions = Vec<(String, Subscription)>;

/// Load the subscriptions from a local JSON file.
fn load_subscriptions(ctx: &Context<'_>, spec: &str) -> Option<Subscriptions> {
    let data = read_local_file(ctx, spec, MAX_SUBFILE_SIZE)?;
    let content: Value = serde_json::from_slice(data).ok()?;
    let obj = content.as_object()?;
    let mut subs: Vec<(String, Subscription)> = Vec::new();
    let mut add = |name: String, s: Subscription| {
        subs.retain(|(n, _)| *n != name);
        subs.push((name, s));
    };
    if obj.contains_key("endpoint") && obj.contains_key("keys") {
        let s = load_subscription(&content)?;
        let last = s.endpoint.rsplit('/').next().unwrap_or("");
        let name: String = last.chars().take(16).collect::<String>().to_lowercase();
        add(name, s);
    } else {
        let mut errors = 0;
        for (name, entry) in obj {
            match load_subscription(entry) {
                Some(s) => add(name.to_lowercase(), s),
                None => {
                    errors += 1;
                    if errors > MAX_LOAD_FAILURES {
                        return None;
                    }
                }
            }
        }
    }
    Some(subs)
}

struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Option<Vec<u8>> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm);
    let info = [info];
    let okm = prk.expand(&info, HkdfLen(len)).ok()?;
    let mut out = vec![0u8; len];
    okm.fill(&mut out).ok()?;
    Some(out)
}

/// The deterministic part of RFC 8291 `aes128gcm` encryption: given the ECDH secret, both public keys, the auth secret and the salt, build the body.
fn encrypt_with(
    shared: &[u8],
    ua_public: &[u8],
    as_public: &[u8],
    auth: &[u8],
    salt: &[u8; 16],
    message: &[u8],
) -> Option<Vec<u8>> {
    let mut info = b"WebPush: info\x00".to_vec();
    info.extend_from_slice(ua_public);
    info.extend_from_slice(as_public);
    let ikm = hkdf_sha256(auth, shared, &info, 32)?;
    let cek = hkdf_sha256(salt, &ikm, b"Content-Encoding: aes128gcm\x00", 16)?;
    let nonce = hkdf_sha256(salt, &ikm, b"Content-Encoding: nonce\x00", 12)?;
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &cek).ok()?);
    let mut data = message.to_vec();
    data.push(0x02);
    key.seal_in_place_append_tag(aead::Nonce::try_assume_unique_for_key(&nonce).ok()?, aead::Aad::empty(), &mut data)
        .ok()?;
    let mut out = salt.to_vec();
    out.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    out.push(as_public.len() as u8);
    out.extend_from_slice(as_public);
    out.extend_from_slice(&data);
    Some(out)
}

/// Encrypt one message for a subscription (RFC 8291, `aes128gcm`).
fn encrypt_webpush(message: &[u8], ua_public: &[u8], auth: &[u8], env: &dyn Env) -> Option<Vec<u8>> {
    let rng = ring_rng();
    let eph = EphemeralPrivateKey::generate(&ECDH_P256, &rng).ok()?;
    let as_public = eph.compute_public_key().ok()?.as_ref().to_vec();
    let shared = agree_ephemeral(eph, &UnparsedPublicKey::new(&ECDH_P256, ua_public), |s| s.to_vec()).ok()?;
    let mut salt = [0u8; 16];
    env.fill_random(&mut salt);
    encrypt_with(&shared, ua_public, &as_public, auth, &salt, message)
}

/// Load the P-256 signing key from a PEM file (PKCS#8 or SEC1).
fn load_signing_key(ctx: &Context<'_>, spec: &str) -> Option<EcdsaKeyPair> {
    let data = read_local_file(ctx, spec, MAX_KEYFILE_SIZE)?;
    let (label, der) = pem_decode(std::str::from_utf8(data).ok()?)?;
    if label != "PRIVATE KEY" && label != "EC PRIVATE KEY" {
        return None;
    }
    let (private, public) = p256_keys_from_der(&der)?;
    EcdsaKeyPair::from_private_key_and_public_key(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &private,
        &public,
        &ring_rng(),
    )
    .ok()
}

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = crate::crypto::b64(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The key kept in the store directory and the steps that save it: generated (with its public key) when there is none.
fn stored_key(ctx: &Context<'_>, dir: &Path) -> Option<(EcdsaKeyPair, Plan)> {
    if let Some(found) = PRIVATE_KEY_FILES.iter().map(|f| dir.join(f)).find(|p| ctx.stat(p).is_some_and(|m| m.is_file)) {
        return Some((load_signing_key(ctx, found.to_str()?)?, Plan::Done));
    }
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &ring_rng()).ok()?;
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &ring_rng()).ok()?;
    let mut spki = SPKI_P256_PREFIX.to_vec();
    spki.extend_from_slice(key.public_key().as_ref());
    let write = |name: &str, label: &str, der: &[u8]| FileOp::WriteAtomic {
        path: dir.join(name),
        data: pem(label, der).into_bytes(),
        private: true,
    };
    let public = write("public_key.pem", "PUBLIC KEY", &spki);
    let shown = dir.display().to_string();
    let failed = move |e: Error, dir: &str| {
        log::warn!("could not write the Vapid key pair to {dir}: {e}");
        Plan::Fail(Error::Service("no Vapid/WebPush (PEM) private key could be loaded".into()))
    };
    let save = Plan::file(write("private_key.pem", "PRIVATE KEY", pkcs8.as_ref()), move |res| match res {
        Ok(_) => Plan::file(public, move |res| match res {
            Ok(_) => {
                log::info!("generated a Vapid key pair in {shown}");
                Plan::Done
            }
            Err(e) => failed(e, &shown),
        }),
        Err(e) => failed(e, &shown),
    });
    Some((key, save))
}

/// The VAPID JWT for one endpoint origin.
fn jwt_token(key: &EcdsaKeyPair, audience: &str, subscriber: &str, now: u64) -> Option<String> {
    let header = json!({"alg": "ES256", "typ": "JWT"}).to_string();
    let payload =
        json!({"aud": audience, "exp": now + JWT_EXPIRATION_SECS, "sub": format!("mailto:{subscriber}")}).to_string();
    let input = format!("{}.{}", b64_url_nopad(header.as_bytes()), b64_url_nopad(payload.as_bytes()));
    let sig = key.sign(&ring_rng(), input.as_bytes()).ok()?;
    Some(format!("{input}.{}", b64_url_nopad(sig.as_ref())))
}

/// Per-send bookkeeping shared by the target plans and the final check.
#[derive(Default)]
struct Tally {
    delivered: usize,
    expired: Vec<String>,
}

impl Notify for Vapid {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        // Without `?keyfile=` / `?subfile=`, use the store directory.
        let dir: Option<PathBuf> = ctx.store.path();
        let key = match (&self.keyfile, &dir) {
            (Some(k), _) => load_signing_key(ctx, k).map(|k| (k, Plan::Done)),
            (None, Some(d)) => stored_key(ctx, d),
            (None, None) => None,
        };
        let Some((key, save)) = key else {
            return Plan::Fail(Error::Service("no Vapid/WebPush (PEM) private key could be loaded".into()));
        };
        let subfile = self.subfile.clone().or_else(|| {
            dir.as_ref()
                .map(|d| d.join("subscriptions.json"))
                .filter(|p| ctx.stat(p).is_some_and(|m| m.is_file))
                .and_then(|p| p.to_str().map(str::to_string))
        });
        let Some(loaded) = subfile.as_deref().and_then(|s| load_subscriptions(ctx, s)) else {
            return Plan::Fail(Error::Service("Vapid/WebPush subscriptions could not be loaded".into()));
        };
        if loaded.is_empty() {
            return Plan::Fail(Error::Service("Vapid could not load subscriptions".into()));
        }
        let public_key = b64_url_nopad(key.public_key().as_ref());
        let retired: Vec<String> = ctx
            .store
            .get(RETIRED_KEY)
            .and_then(|v| v.as_array().map(|a| a.iter().filter_map(|e| e.as_str().map(str::to_string)).collect()))
            .unwrap_or_default();
        let tally = Arc::new(Mutex::new(Tally::default()));
        let now = ctx.env().unix_time();

        let mut plans = Vec::new();
        for target in &self.targets {
            let Some((_, entry)) = loaded.iter().find(|(n, _)| *n == target.to_lowercase()) else {
                plans.push(
                    Plan::Fail(Error::Service("Vapid user not found in the subscriptions".into()))
                        .target(target.clone()),
                );
                continue;
            };
            if retired.contains(&entry.endpoint) {
                continue;
            }
            let (Some(jwt), Some(body)) = (
                jwt_token(&key, &entry.origin, &self.subscriber, now),
                encrypt_webpush(msg.body.as_bytes(), &entry.public_key, &entry.auth_secret, ctx.env().as_ref()),
            ) else {
                plans.push(Plan::Fail(Error::Service("Vapid encryption failed".into())).target(target.clone()));
                continue;
            };
            let req = ctx
                .post(&entry.endpoint)
                .header("TTL", self.ttl.to_string())
                .header("Content-Encoding", "aes128gcm")
                .header("Content-Type", "application/octet-stream")
                .header("Authorization", format!("vapid t={jwt}, k={public_key}"))
                .body(body, None);
            let tally = tally.clone();
            let endpoint = entry.endpoint.clone();
            plans.push(
                Plan::http(req, move |res| match res {
                    Err(e) => Plan::Fail(e),
                    Ok(r) => match r.status {
                        404 | 410 => {
                            if let Ok(mut t) = tally.lock() {
                                t.expired.push(endpoint);
                            }
                            Plan::Fail(Error::Http { status: r.status, reason: "expired Vapid subscription".into() })
                        }
                        200 | 201 | 202 | 204 => {
                            if let Ok(mut t) = tally.lock() {
                                t.delivered += 1;
                            }
                            Plan::Done
                        }
                        _ => Plan::Fail(r.http_error()),
                    },
                })
                .target(target.clone()),
            );
        }

        let store = ctx.store();
        let finish = Plan::defer(move || {
            let t = tally.lock().map(|mut t| std::mem::take(&mut *t)).unwrap_or_default();
            // The user's file is never rewritten; expired entries are only remembered.
            if !t.expired.is_empty() {
                let mut r = retired;
                for e in t.expired {
                    if !r.contains(&e) {
                        r.push(e);
                    }
                }
                r.sort();
                store.set(RETIRED_KEY, Value::from(r), Some(RETIRED_EXPIRY));
            }
            if t.delivered == 0 {
                Plan::Fail(Error::Service("no Vapid subscriptions could be notified".into()))
            } else {
                Plan::Done
            }
        });
        Plan::chain([save, Plan::all([Plan::all(plans), finish])])
    }

    fn files(&self, ctx: &Context<'_>) -> Vec<FileOp> {
        let dir = ctx.store.path();
        let in_dir = |name: &str| dir.as_ref().map(|d| d.join(name).display().to_string());
        let keys: Vec<String> = match &self.keyfile {
            Some(k) => vec![k.clone()],
            None => PRIVATE_KEY_FILES.iter().filter_map(|f| in_dir(f)).collect(),
        };
        let subs = self.subfile.clone().or_else(|| in_dir("subscriptions.json"));
        keys.iter().chain(&subs).flat_map(|f| local_file_ops(f)).collect()
    }

    fn fetches(&self, ctx: &Context<'_>) -> Vec<crate::http::Request> {
        let key = self.keyfile.iter().flat_map(|k| remote_fetches(ctx, k, MAX_KEYFILE_SIZE));
        key.chain(self.subfile.iter().flat_map(|s| remote_fetches(ctx, s, MAX_SUBFILE_SIZE))).collect()
    }

    fn url_identifier(&self) -> UrlIdentifier {
        UrlIdentifier::parts(["vapid", self.mode.as_str(), self.subscriber.as_str()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FakeTransport, file_context};
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey as SigKey};

    fn b64d(s: &str) -> Vec<u8> {
        crate::crypto::b64_url_decode(s).unwrap()
    }

    fn data(name: &str) -> String {
        format!("{}/tests/fixtures/data/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    /// Decrypt an `aes128gcm` body with the user agent's ECDH secret.
    fn decrypt_with(shared: &[u8], ua_public: &[u8], auth: &[u8], body: &[u8]) -> Vec<u8> {
        let salt = &body[..16];
        assert_eq!(u32::from_be_bytes(body[16..20].try_into().unwrap()), RECORD_SIZE);
        let idlen = body[20] as usize;
        let as_public = &body[21..21 + idlen];
        let mut info = b"WebPush: info\x00".to_vec();
        info.extend_from_slice(ua_public);
        info.extend_from_slice(as_public);
        let ikm = hkdf_sha256(auth, shared, &info, 32).unwrap();
        let cek = hkdf_sha256(salt, &ikm, b"Content-Encoding: aes128gcm\x00", 16).unwrap();
        let nonce = hkdf_sha256(salt, &ikm, b"Content-Encoding: nonce\x00", 12).unwrap();
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &cek).unwrap());
        let mut ct = body[21 + idlen..].to_vec();
        let plain = key
            .open_in_place(aead::Nonce::try_assume_unique_for_key(&nonce).unwrap(), aead::Aad::empty(), &mut ct)
            .unwrap();
        assert_eq!(plain.last(), Some(&0x02));
        plain[..plain.len() - 1].to_vec()
    }

    #[test]
    fn rfc8291_test_vector() {
        // RFC 8291, Appendix A.
        let shared = b64d("kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs");
        let ua_public = b64d("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4");
        let as_public = b64d("BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8");
        let auth = b64d("BTBZMqHH6r4Tts7J_aSIgg");
        let salt: [u8; 16] = b64d("DGv6ra1nlYgDCS1FRnbzlw").try_into().unwrap();
        let body =
            encrypt_with(&shared, &ua_public, &as_public, &auth, &salt, b"When I grow up, I want to be a watermelon")
                .unwrap();
        assert_eq!(
            b64_url_nopad(&body),
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
        );
    }

    #[test]
    fn round_trip() {
        let rng = ring_rng();
        let ua = EphemeralPrivateKey::generate(&ECDH_P256, &rng).unwrap();
        let ua_public = ua.compute_public_key().unwrap().as_ref().to_vec();
        let auth = [9u8; 16];
        let msg = "héllo 🦀 web push".as_bytes();
        let body = encrypt_webpush(msg, &ua_public, &auth, crate::testing::test_env()).unwrap();
        let as_public = body[21..21 + 65].to_vec();
        let shared = agree_ephemeral(ua, &UnparsedPublicKey::new(&ECDH_P256, &as_public), |s| s.to_vec()).unwrap();
        assert_eq!(decrypt_with(&shared, &ua_public, &auth, &body), msg);
    }

    fn key_files(dir: &Path) -> Vec<FileOp> {
        PRIVATE_KEY_FILES.iter().flat_map(|f| local_file_ops(&dir.join(f).display().to_string())).collect()
    }

    fn signing_key(path: &str) -> Option<EcdsaKeyPair> {
        file_context(local_file_ops(path), &crate::BlockingTransport::new(), |ctx| load_signing_key(ctx, path))
    }

    #[test]
    fn key_generated_in_store_directory() {
        let (fake, ns) = (FakeTransport::new(), PathBuf::from("/data/ns"));
        let (key, save) = file_context(key_files(&ns), &fake, |ctx| stored_key(ctx, &ns)).expect("generated");
        crate::testing::run_files(save, &fake);
        let private = ns.join("private_key.pem");
        let files = fake.files();
        assert!(files.contains_key(&ns.join("public_key.pem")));
        assert!(fake.file_ops().contains(&FileOp::WriteAtomic { path: private.clone(), data: files[&private].clone(), private: true }));
        // The next send loads the same key instead of generating another.
        let (again, save) = file_context(key_files(&ns), &fake, |ctx| stored_key(ctx, &ns)).expect("loaded");
        assert!(matches!(save, Plan::Done));
        assert_eq!(key.public_key().as_ref(), again.public_key().as_ref());
    }

    #[test]
    fn jwt_verifies() {
        for f in ["vapid_private_key.pem", "vapid_private_key_sec1.pem"] {
            let key = signing_key(&data(f)).unwrap();
            let jwt = jwt_token(&key, "https://push.example.com:8443", "a@example.com", 1_700_000_000).unwrap();
            let parts: Vec<&str> = jwt.split('.').collect();
            assert_eq!(String::from_utf8(b64d(parts[0])).unwrap(), r#"{"alg":"ES256","typ":"JWT"}"#);
            assert_eq!(
                String::from_utf8(b64d(parts[1])).unwrap(),
                r#"{"aud":"https://push.example.com:8443","exp":1700043200,"sub":"mailto:a@example.com"}"#
            );
            SigKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key().as_ref())
                .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &b64d(parts[2]))
                .unwrap();
        }
        assert!(signing_key(&data("vapid_public_key.pem")).is_none());
    }

    #[test]
    fn origins() {
        assert_eq!(webpush_origin("https://Push.Example.com/x").as_deref(), Some("https://push.example.com"));
        assert_eq!(webpush_origin("https://h.example.com:443/x").as_deref(), Some("https://h.example.com"));
        assert_eq!(webpush_origin("https://h.example.com:8443").as_deref(), Some("https://h.example.com:8443"));
        assert_eq!(webpush_origin("https://[::1]:8443/x").as_deref(), Some("https://[::1]:8443"));
        assert_eq!(webpush_origin("http://h.example.com/x"), None);
        assert_eq!(webpush_origin("https://u@h.example.com/x"), None);
        assert_eq!(webpush_origin("https://h.example.com:0/x"), None);
        assert_eq!(webpush_origin("https://h.example.com/x#f"), None);
    }

    #[test]
    fn subscription_keys_decode_unpadded_urlsafe() {
        assert_eq!(b64_url_decode("QQ"), Some(b"A".to_vec()));
        assert_eq!(b64_url_decode("QQ=="), Some(b"A".to_vec()));
        assert_eq!(b64_url_decode("Q"), None);
        assert_eq!(b64_url_decode("<place>"), None);
        assert_eq!(b64_url_decode("-_-_"), Some(vec![0xfb, 0xff, 0xbf]));
    }

    #[test]
    #[expect(clippy::disallowed_methods, reason = "reads the test fixtures")]
    fn key_and_subscriptions_from_urls() {
        let key = std::fs::read(data("vapid_private_key.pem")).unwrap();
        let subs = std::fs::read(data("vapid_subscriptions.json")).unwrap();
        let url = "vapid://user@example.com/user1?keyfile=https://keys.example/k.pem&subfile=https://keys.example/s.json";
        let fake = crate::testing::FakeTransport::new();
        fake.on_url("keys.example/k.pem", crate::Response::new(200, key));
        fake.on_url("keys.example/s.json", crate::Response::new(200, subs));
        fake.default_response(crate::Response::new(201, Vec::new()));
        let d = crate::parse(url).unwrap().send(&crate::Message::new("b"), &fake, &crate::Asset::default());
        assert!(d.is_success(), "{d:?}");
        let reqs = fake.requests();
        let downloads: Vec<_> = reqs.iter().filter(|r| r.url.contains("keys.example")).collect();
        assert_eq!(downloads.len(), 2);
        assert_eq!(downloads[0].max_body, MAX_KEYFILE_SIZE);
        assert_eq!(downloads[1].max_body, MAX_SUBFILE_SIZE);
        assert!(reqs.iter().any(|r| r.header_value("authorization").is_some_and(|a| a.starts_with("vapid "))), "a push was sent");

        // A key that cannot be downloaded fails the send.
        let fake = crate::testing::FakeTransport::new();
        fake.on_url("keys.example", crate::Response::new(404, Vec::new()));
        assert!(!crate::parse(url).unwrap().send(&crate::Message::new("b"), &fake, &crate::Asset::default()).is_success());
    }


    #[test]
    fn compressed_p256dh_is_expanded() {
        let full = b64d("BCj-fZwrJUTWDRmq8yO88_xKJkB9jMqiAUS2rbgK35U0SH76DdeqRu2Oaq7iYGqO4yw_tbdKKxWPfnMTj1wW3gg");
        assert_eq!(full.len(), 65);
        // SEC1 compression: 0x02 or 0x03 by the parity of y, then x.
        let mut compressed = vec![2 + (full[64] & 1)];
        compressed.extend_from_slice(&full[1..33]);
        assert_eq!(uncompressed(compressed.clone()), Some(full.clone()));
        let sub = json!({"endpoint": "https://push.example/x", "keys": {"p256dh": b64_url_nopad(&compressed), "auth": "5I3XwN-msGG8E7PQhSzs1Q"}});
        assert_eq!(load_subscription(&sub).map(|s| s.public_key), Some(full));
        // An x with no point on the curve is refused.
        let mut off_curve = vec![2u8];
        off_curve.extend_from_slice(&[0xff; 32]);
        assert_eq!(uncompressed(off_curve), None);
    }

}
