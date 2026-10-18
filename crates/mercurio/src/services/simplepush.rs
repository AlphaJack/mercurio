//! Simplepush (`spush://`, `simplepush://`): push notifications through Simplepush, optionally encrypted.
//!
//! Every message is sent as a task. Encryption is end-to-end:
//! - personal sends with a password: Argon2id (libsodium `crypto_pwhash`, 3 passes, 64 MiB) over the password salted with the topic (or the account's password salt), expanded with HKDF-SHA256 into a key;
//! - organization sends with an integration token (`spi_<credential>.<seed>`): the organization keys are wrapped to the token with NaCl `crypto_box` (X25519 + XSalsa20-Poly1305) and opened with the seed.
//!
//! Fields, links and attachments are sealed with XChaCha20-Poly1305 (24 byte nonce + ciphertext + tag).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use serde_json::{Map, Value, json};

use crate::crypto::{b64, b64_decode, b64_url_decode, hmac_sha256, random_bytes, sha256, sha512};
use crate::error::Error;
use crate::http::{Request, Response};
use crate::parse::{parse_bool, parse_list_unquoted, validate_nonblank};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::util::json_has_value;
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "simplepush",
    name: "Simplepush",
    schemes: &["spush", "simplepush"],
    service_url: "https://simplepu.sh/",
    parse,
    limits: Limits { title_maxlen: 300, body_maxlen: 7000, body_max_line_count: 0 },
    formats: &[NotifyFormat::Markdown],
    attachments: true,
    templates: &[
        "{schema}://{token}",
        "{schema}://{token}/{targets}",
        "{schema}://{password}@{token}",
        "{schema}://{password}@{token}/{targets}",
    ],
    tokens: &[
        Param::new("password", "Password").secret(),
        Param::new("target_member", "Target Member").prefix("@"),
        Param::new("target_topic", "Target Topic"),
        Param::new("targets", "Targets").list("/").group(&["target_member", "target_topic"]),
        Param::new("token", "API Token").required().secret(),
    ],
    params: &[
        Param::new("broadcast", "Broadcast").bool(false),
        Param::new("critical_volume", "Volume").float().range(0, 1),
        Param::new("links", "Link").list(", "),
        Param::new("priority", "Priority").choice(&["1", "2", "3", "4", "5"]),
        Param::new("shared", "Shared").bool(false),
        Param::new("sptag", "Tag"),
        Param::sets("to", &["targets"]),
        Param::new("topic_auth_token", "Auth Token").secret(),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.simplepu.sh/v1/tasks/json";
const ATTACHMENT_URL: &str = "https://api.simplepu.sh/v1/attachments";
const USER_URL: &str = "https://api.simplepu.sh/v1/user";
const INTEGRATION_KEYS_URL: &str = "https://api.simplepu.sh/v1/org/integration/keys";
const INTEGRATION_PREFIX: &str = "spi_";
const LINKS_MAX: usize = 25;
/// Server limits for the ciphertext of an encrypted field.
const ENCRYPTED_MAXLEN: &[(&str, usize)] = &[("title", 500), ("content", 10000)];

/// Prefix -> priority, in match order.
const PRIORITY_MAP: &[(&str, u8)] = &[("mi", 1), ("l", 2), ("d", 3), ("n", 3), ("h", 4), ("c", 5), ("e", 5), ("ma", 5)];

#[derive(Default)]
struct Cache {
    /// Salt -> (key, fingerprint); Argon2id is deliberately slow.
    keys: BTreeMap<String, ([u8; 32], String)>,
    account_salt: Option<String>,
    /// Version -> organization key; empty when the organization has no encryption.
    org_keys: Option<BTreeMap<i64, Vec<u8>>>,
}

struct Inner {
    integration: bool,
    credential: Secret,
    seed: Option<[u8; 32]>,
    password: Option<Secret>,
    topics: Vec<String>,
    members: Vec<String>,
    broadcast: bool,
    shared: bool,
    priority: Option<u8>,
    critical_volume: Option<f64>,
    sptag: Option<String>,
    links: Vec<String>,
    topic_auth_token: Option<Secret>,
    cache: Mutex<Cache>,
}

struct SimplePush(Arc<Inner>);

impl std::fmt::Debug for SimplePush {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = &self.0;
        f.debug_struct("SimplePush")
            .field("integration", &i.integration)
            .field("credential", &i.credential)
            .field("password", &i.password)
            .field("topics", &i.topics)
            .field("members", &i.members)
            .field("broadcast", &i.broadcast)
            .finish_non_exhaustive()
    }
}

/// Split on `[];,` only (not whitespace), keeping order and duplicates.
fn split_targets(items: &[String]) -> Vec<String> {
    let re = crate::regex!(r"[\[\];,]+");
    items
        .iter()
        .flat_map(|a| re.split(a).map(|s| s.trim().to_string()).collect::<Vec<_>>())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let token_raw = u.host();
    let mut targets = u.path_segments();
    // The password is unquoted once more.
    let mut password = u.user.as_deref().filter(|s| !s.is_empty()).map(|s| unquote(&unquote(s)));
    if let Some(p) = u.param_nonempty("password") {
        password = Some(unquote(&unquote(p)));
    }
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list_unquoted([to]));
    }
    let arg = |k: &str| u.param_nonempty(k).map(unquote);
    let (priority_raw, volume_raw, sptag, links_raw, topic_auth_token) =
        (arg("priority"), arg("critical_volume"), arg("sptag"), arg("links"), arg("topic_auth_token"));
    let flag = |k: &str| u.param_nonempty(k).map(|v| parse_bool(v, false)).unwrap_or(false);
    let (broadcast, shared) = (flag("broadcast"), flag("shared"));
    let password = password.filter(|p| !p.is_empty());

    let token =
        validate_nonblank(&token_raw).ok_or_else(|| SERVICE.err("an invalid Simplepush API Token was specified"))?;
    let integration = token.starts_with(INTEGRATION_PREFIX);
    let mut credential = token.clone();
    let mut seed = None;
    if integration {
        let (cred, seed_b64) = token.split_once('.').unwrap_or((&token, ""));
        credential = cred.to_string();
        seed = b64_url_decode(seed_b64).and_then(|s| <[u8; 32]>::try_from(s).ok());
        if credential == INTEGRATION_PREFIX || seed.is_none() {
            return Err(SERVICE.err("an invalid Simplepush integration token was specified"));
        }
    }

    let mut topics = Vec::new();
    let mut members = Vec::new();
    for target in split_targets(&targets) {
        match target.strip_prefix('@') {
            None => topics.push(target),
            Some(m) => {
                let m = m.trim();
                if m.is_empty() {
                    return Err(SERVICE.err("an invalid Simplepush member was specified"));
                }
                members.push(m.to_string());
            }
        }
    }
    if !integration {
        if !members.is_empty() || broadcast {
            return Err(SERVICE.err("Simplepush members and broadcast require an organization integration token"));
        }
    } else {
        if broadcast && (!topics.is_empty() || !members.is_empty()) {
            return Err(SERVICE.err("a Simplepush broadcast can not be combined with topics or members"));
        }
        if !(broadcast || !topics.is_empty() || !members.is_empty()) {
            return Err(SERVICE.err("a Simplepush organization send requires a topic, a member or broadcast"));
        }
        if password.is_some() {
            return Err(SERVICE.err("Simplepush organization sends can not be encrypted with a password"));
        }
    }

    let priority = match priority_raw.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        None => None,
        Some(p) => {
            let v = p.to_lowercase();
            let found = if let Some(n) = ["1", "2", "3", "4", "5"].iter().position(|d| *d == v) {
                Some(n as u8 + 1)
            } else if !v.chars().next().is_some_and(|c| c.is_numeric()) {
                PRIORITY_MAP.iter().find(|(k, _)| v.starts_with(k)).map(|(_, n)| *n)
            } else {
                None
            };
            Some(found.ok_or_else(|| SERVICE.err("an invalid Simplepush priority was specified"))?)
        }
    };
    let critical_volume = match volume_raw.as_deref().filter(|v| !v.trim().is_empty()) {
        None => None,
        Some(v) => {
            let f = v.trim().parse::<f64>().ok().filter(|f| *f > 0.0 && *f <= 1.0).ok_or_else(|| {
                SERVICE
                    .err("an invalid Simplepush critical volume was specified; it must be greater than 0 and at most 1")
            })?;
            if priority != Some(5) {
                return Err(SERVICE.err("the Simplepush critical volume requires priority 5"));
            }
            Some(f)
        }
    };
    let links: Vec<String> = links_raw
        .map(|l| crate::regex!(r"\s+").split(&l).filter(|s| !s.is_empty()).map(str::to_string).collect())
        .unwrap_or_default();
    if links.len() > LINKS_MAX {
        return Err(SERVICE.err("at most 25 Simplepush links can be specified"));
    }

    Ok(Box::new(SimplePush(Arc::new(Inner {
        integration,
        credential: Secret::new(credential),
        seed,
        password: password.map(Secret::new),
        topics,
        members,
        broadcast,
        shared,
        priority,
        critical_volume,
        sptag: sptag.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        links,
        topic_auth_token: topic_auth_token.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).map(Secret::new),
        cache: Mutex::new(Cache::default()),
    }))))
}

/// libsodium `crypto_pwhash` (Argon2id v1.3, opslimit 3, memlimit 64 MiB) into 64 bytes, salted with `sha256(salt)[:16]`; then HKDF-expand.
fn derive_key(password: &str, salt: &str) -> Option<([u8; 32], String)> {
    let params = Params::new(64 * 1024, 3, 1, Some(64)).ok()?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut master = [0u8; 64];
    argon.hash_password_into(password.as_bytes(), &sha256(salt.as_bytes())[..16], &mut master).ok()?;
    let key: [u8; 32] = hmac_sha256(&master, b"symmetric-key\x01").try_into().ok()?;
    let fingerprint = b64(&sha256(&key)[..8]);
    Some((key, fingerprint))
}

/// XChaCha20-Poly1305 with a random nonce: `nonce || ciphertext || tag`.
fn seal(data: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).ok()?;
    let mut nonce = [0u8; 24];
    random_bytes(&mut nonce);
    let mut out = nonce.to_vec();
    out.extend(cipher.encrypt(&XNonce::from(nonce), data).ok()?);
    Some(out)
}

fn encrypt_text(text: &str, key: &[u8]) -> Option<String> {
    seal(text.as_bytes(), key).map(|s| b64(&s))
}

/// NaCl `crypto_box_open`: X25519, HSalsa20, then XSalsa20-Poly1305 over `tag || ciphertext`. `None` when the tag does not match.
fn box_open(sk: &[u8; 32], pk: &[u8; 32], nonce: &[u8; 24], sealed: &[u8]) -> Option<Vec<u8>> {
    use poly1305::Poly1305;
    use poly1305::universal_hash::KeyInit as _;
    use salsa20::cipher::consts::U10;
    use salsa20::cipher::{KeyIvInit, StreamCipher};

    if sealed.len() < 16 {
        return None;
    }
    let (tag, ct) = sealed.split_at(16);
    let shared = MontgomeryPoint(*pk).mul_clamped(*sk).to_bytes();
    let key = salsa20::hsalsa::<U10>(&shared.into(), &[0u8; 16].into());
    let mut cipher = salsa20::XSalsa20::new(&key, &(*nonce).into());
    // The first 32 keystream bytes are the Poly1305 key; the message starts after them.
    let mut mac_key = [0u8; 32];
    cipher.apply_keystream(&mut mac_key);
    let expected = Poly1305::new(&mac_key.into()).compute_unpadded(ct);
    if expected.iter().zip(tag).fold(0u8, |acc, (a, b)| acc | (a ^ b)) != 0 {
        return None;
    }
    let mut out = ct.to_vec();
    cipher.apply_keystream(&mut out);
    Some(out)
}

/// Open the organization keys wrapped to this integration token.
fn open_org_keys(seed: &[u8; 32], response: &Map<String, Value>) -> Option<BTreeMap<i64, Vec<u8>>> {
    let admin: [u8; 32] = b64_decode(response.get("adminPubkeyB64")?.as_str()?)?.try_into().ok()?;
    let sk: [u8; 32] = sha512(seed)[..32].try_into().ok()?;
    let mut keys = BTreeMap::new();
    for wrap in response.get("wrappedKeys")?.as_array()? {
        let wrap = wrap.as_object()?;
        let blob = b64_decode(wrap.get("blob")?.as_str()?)?;
        let version = wrap.get("version")?;
        let version = crate::util::json_int(version).or_else(|| version.as_bool().map(i64::from))?;
        if blob.len() < 24 {
            return None;
        }
        let (nonce, sealed) = blob.split_at(24);
        let key = box_open(&sk, &admin, nonce.try_into().ok()?, sealed)?;
        keys.insert(version, key);
    }
    Some(keys)
}

/// `send` is among the scopes (list item, substring or object key).
fn has_send_scope(scopes: Option<&Value>) -> bool {
    match scopes {
        Some(Value::Array(a)) => a.iter().any(|v| v.as_str() == Some("send")),
        Some(Value::String(s)) => s.contains("send"),
        Some(Value::Object(o)) => o.contains_key("send"),
        _ => false,
    }
}

fn has_value(v: Option<&Value>) -> bool {
    v.is_some_and(json_has_value)
}

/// A non-empty string or non-zero number as URL text.
fn id_text(v: &Value) -> Option<String> {
    if v.is_boolean() { None } else { crate::util::scalar_text(v) }
}

type Key = Option<(Vec<u8>, Value)>;

/// The message as captured for the deferred per-target plans.
struct Msg {
    title: String,
    body: String,
    markdown: bool,
    /// (filename, content type, data)
    files: Vec<(String, String, Vec<u8>)>,
    app_id: String,
}

impl Inner {
    fn auth(&self, req: Request) -> Request {
        if self.integration {
            req.header("Authorization", format!("Bearer {}", self.credential.expose()))
        } else {
            req.header("API-Token", self.credential.expose())
        }
    }

    /// GET a JSON object with the sender credential.
    fn get_json(
        self: &Arc<Self>,
        url: &str,
        app_id: &str,
        then: impl FnOnce(Map<String, Value>) -> Plan + Send + 'static,
    ) -> Plan {
        let req = self.auth(Request::get(url).header("User-Agent", app_id).header("Accept", "application/json"));
        Plan::http(req, move |res| match res {
            Err(e) => Plan::Fail(e),
            Ok(r) if r.status != 200 => Plan::Fail(r.http_error()),
            Ok(r) => match r.json() {
                Some(Value::Object(m)) => then(m),
                _ => Plan::Fail(Error::Service("Simplepush returned an unreadable response".into())),
            },
        })
    }

    fn derive(&self, salt: &str) -> Option<([u8; 32], String)> {
        if let Some(k) = self.cache.lock().ok().and_then(|c| c.keys.get(salt).cloned()) {
            return Some(k);
        }
        let k = derive_key(self.password.as_ref()?.expose(), salt)?;
        if let Ok(mut c) = self.cache.lock() {
            c.keys.insert(salt.to_string(), k.clone());
        }
        Some(k)
    }

    fn personal(&self, salt: &str) -> Plan2 {
        match self.derive(salt) {
            Some((key, fp)) => Ok(Some((key.to_vec(), json!({"type": "personal", "keyFingerprint": fp})))),
            None => Err(Error::Service("the Simplepush key could not be derived".into())),
        }
    }

    /// Resolve the encryption key for one task, then continue.
    fn with_encryption(
        self: &Arc<Self>,
        kind: Option<&'static str>,
        target: Option<String>,
        app_id: &str,
        then: impl FnOnce(Key) -> Plan + Send + 'static,
    ) -> Plan {
        if self.integration {
            let cached = self.cache.lock().ok().and_then(|c| c.org_keys.clone());
            let finish = |keys: BTreeMap<i64, Vec<u8>>| match keys.iter().next_back() {
                None => then(None),
                Some((v, k)) => then(Some((k.clone(), json!({"type": "org", "v": v})))),
            };
            if let Some(keys) = cached {
                return finish(keys);
            }
            let me = self.clone();
            return self.get_json(INTEGRATION_KEYS_URL, app_id, move |resp| {
                if !has_send_scope(resp.get("scopes")) {
                    return Plan::Fail(Error::Service("the Simplepush integration token lacks the send scope".into()));
                }
                let mut keys = BTreeMap::new();
                if has_value(resp.get("enabled")) {
                    if !has_value(resp.get("wrappedKeys")) {
                        return Plan::Fail(Error::Service(
                            "the Simplepush organization holds no keys for this integration token".into(),
                        ));
                    }
                    match me.seed.as_ref().and_then(|s| open_org_keys(s, &resp)) {
                        Some(k) => keys = k,
                        None => {
                            return Plan::Fail(Error::Service(
                                "could not open the Simplepush organization keys with this integration token".into(),
                            ));
                        }
                    }
                }
                if let Ok(mut c) = me.cache.lock() {
                    c.org_keys = Some(keys.clone());
                }
                finish(keys)
            });
        }
        if self.password.is_none() {
            return then(None);
        }
        if kind == Some("topic") {
            return match self.personal(target.as_deref().unwrap_or("")) {
                Ok(k) => then(k),
                Err(e) => Plan::Fail(e),
            };
        }
        if let Some(salt) = self.cache.lock().ok().and_then(|c| c.account_salt.clone()) {
            return match self.personal(&salt) {
                Ok(k) => then(k),
                Err(e) => Plan::Fail(e),
            };
        }
        let me = self.clone();
        self.get_json(USER_URL, app_id, move |resp| {
            if !has_value(resp.get("passwordSalt")) {
                return Plan::Fail(Error::Service("Simplepush returned no password salt".into()));
            }
            let Some(salt) = resp.get("passwordSalt").and_then(Value::as_str).map(str::to_string) else {
                return Plan::Fail(Error::Service("Simplepush returned an unusable password salt".into()));
            };
            if let Ok(mut c) = me.cache.lock() {
                c.account_salt = Some(salt.clone());
            }
            match me.personal(&salt) {
                Ok(k) => then(k),
                Err(e) => Plan::Fail(e),
            }
        })
    }

    fn task(self: &Arc<Self>, kind: Option<&'static str>, target: Option<String>, msg: Arc<Msg>) -> Plan {
        let me = self.clone();
        let app_id = msg.app_id.clone();
        self.with_encryption(kind, target.clone(), &app_id, move |key| me.send_task(kind, target, &msg, key))
    }

    fn send_task(
        self: &Arc<Self>,
        kind: Option<&'static str>,
        target: Option<String>,
        msg: &Arc<Msg>,
        key: Key,
    ) -> Plan {
        let mut payload = Map::new();
        if let (Some(k), Some(t)) = (kind, &target) {
            payload.insert(k.into(), json!(t));
        }
        if self.broadcast {
            payload.insert("broadcast".into(), json!(true));
        }
        if self.shared {
            payload.insert("shared".into(), json!(true));
        }
        if let Some(t) = &self.topic_auth_token
            && kind == Some("topic")
        {
            payload.insert("topicAuthToken".into(), json!(t.expose()));
        }
        if let Some(p) = self.priority {
            payload.insert("priority".into(), json!(p));
        }
        if let Some(v) = self.critical_volume {
            payload.insert("criticalVolume".into(), json!(v));
        }
        if !msg.body.is_empty() && msg.markdown {
            payload.insert("contentFormat".into(), json!("markdown"));
        }
        let names: Vec<&str> = msg.files.iter().map(|(n, _, _)| n.as_str()).collect();
        let content = if !msg.body.is_empty() {
            msg.body.clone()
        } else if !msg.title.is_empty() {
            msg.title.clone()
        } else {
            names.join(", ")
        };
        let title = if !msg.body.is_empty() { msg.title.clone() } else { String::new() };
        let mut fields: Vec<(&str, String)> =
            vec![("title", title), ("content", content), ("tag", self.sptag.clone().unwrap_or_default())];
        let mut links = self.links.clone();
        let mut blobs: Vec<Vec<u8>> = msg.files.iter().map(|(_, _, d)| d.clone()).collect();

        if let Some((key, marker)) = key {
            let fail = || Plan::Fail(Error::Service("Simplepush encryption failed".into()));
            for (_, v) in fields.iter_mut() {
                if !v.is_empty() {
                    match encrypt_text(v, &key) {
                        Some(e) => *v = e,
                        None => return fail(),
                    }
                }
            }
            for (name, max) in ENCRYPTED_MAXLEN {
                if fields.iter().any(|(k, v)| k == name && v.len() > *max) {
                    return Plan::Fail(Error::Message(format!("the Simplepush {name} is too long once encrypted")));
                }
            }
            let Some(l) = links.iter().map(|l| encrypt_text(l, &key)).collect::<Option<Vec<_>>>() else {
                return fail();
            };
            links = l;
            let Some(b) = blobs.iter().map(|b| seal(b, &key)).collect::<Option<Vec<_>>>() else { return fail() };
            blobs = b;
            payload.insert("encryption".into(), marker);
        }
        for (k, v) in fields {
            if !v.is_empty() {
                payload.insert(k.into(), json!(v));
            }
        }
        if !links.is_empty() {
            payload.insert("links".into(), json!(links));
        }
        if !blobs.is_empty() {
            let files: Vec<Value> = msg
                .files
                .iter()
                .zip(&blobs)
                .map(|((name, ct, _), blob)| {
                    json!({"filename": name, "contentType": ct, "size": blob.len(), "checksumSha256": b64(&sha256(blob))})
                })
                .collect();
            payload.insert("files".into(), Value::Array(files));
        }

        let req = self.auth(Request::post(NOTIFY_URL).header("User-Agent", &msg.app_id)).json(&Value::Object(payload));
        let me = self.clone();
        let app_id = msg.app_id.clone();
        Plan::http(req, move |res| {
            let r = match res {
                Err(e) => return Plan::Fail(e),
                Ok(r) if !matches!(r.status, 200 | 201) => {
                    return Plan::Fail(r.http_error());
                }
                Ok(r) => r,
            };
            let created = match r.json() {
                Some(Value::Object(m)) => m.get("attachments").cloned().unwrap_or(Value::Null),
                _ => Value::Null,
            };
            let created: Vec<Value> = if let Value::Array(a) = created {
                a
            } else if !has_value(Some(&created)) {
                Vec::new()
            } else {
                return Plan::Fail(Error::Service("Simplepush returned unusable attachments".into()));
            };
            let uploads: Vec<Plan> = created
                .into_iter()
                .zip(blobs)
                .map(|(att, blob)| match att.as_object() {
                    None => Plan::Fail(Error::Service("Simplepush returned an unusable attachment".into())),
                    Some(a) => match a.get("id").and_then(id_text) {
                        None => Plan::Fail(Error::Service("Simplepush returned no attachment id".into())),
                        Some(id) => me.upload(id, blob, &app_id),
                    },
                })
                .collect();
            Plan::all(uploads)
        })
    }

    fn step_request(&self, id: &str, step: &str, app_id: &str) -> Request {
        self.auth(Request::post(format!("{ATTACHMENT_URL}/{id}/{step}")).header("User-Agent", app_id))
    }

    /// Presign, PUT the bytes, complete; report `failed` on any error.
    fn upload(self: &Arc<Self>, id: String, blob: Vec<u8>, app_id: &str) -> Plan {
        let step_ok = |r: &Response| matches!(r.status, 200 | 201 | 204);
        let failed = self.step_request(&id, "failed", app_id);
        let fail_plan = move |reason: String| {
            let failed = failed.clone();
            Plan::all([Plan::http(failed, |_| Plan::Done), Plan::Fail(Error::Service(reason))])
        };
        let complete = self.step_request(&id, "complete", app_id);
        Plan::http(self.step_request(&id, "upload-url", app_id), move |res| {
            let presigned = match res {
                Ok(r) if step_ok(&r) => {
                    r.json().and_then(|v| v.get("presignedPutUrl").and_then(Value::as_str).map(str::to_string))
                }
                _ => None,
            };
            let valid = presigned.filter(|u| crate::regex!(r"(?i)^https?://[^/?#\s]+").is_match(u));
            let Some(url) = valid else {
                return fail_plan("Simplepush attachment could not be presigned".into());
            };
            let put = Request::put(url).body(blob, Some("application/octet-stream"));
            Plan::http(put, move |res| match res {
                Ok(r) if step_ok(&r) => Plan::http(complete, move |res| match res {
                    Ok(r) if step_ok(&r) => Plan::Done,
                    _ => fail_plan("Simplepush attachment could not be completed".into()),
                }),
                _ => fail_plan("Simplepush attachment upload failed".into()),
            })
        })
    }
}

type Plan2 = std::result::Result<Key, Error>;

impl Notify for SimplePush {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let inner = &self.0;
        let files = msg
            .attachments
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let name = if a.name.is_empty() { format!("file{:03}.dat", i + 1) } else { a.name.clone() };
                let mime = if a.mime.is_empty() { "application/octet-stream".to_string() } else { a.mime.clone() };
                (name, mime, a.data.clone())
            })
            .collect();
        let m = Arc::new(Msg {
            title: msg.title.to_string(),
            body: msg.body.to_string(),
            markdown: msg.format == NotifyFormat::Markdown,
            files,
            app_id: ctx.app_id().to_string(),
        });
        let mut targets: Vec<(Option<&'static str>, Option<String>)> = inner
            .topics
            .iter()
            .map(|t| (Some("topic"), Some(t.clone())))
            .chain(inner.members.iter().map(|t| (Some("member"), Some(t.clone()))))
            .collect();
        if targets.is_empty() {
            targets.push((None, None));
        }
        Plan::all(targets.into_iter().map(|(kind, target)| {
            let me = inner.clone();
            let m = m.clone();
            let label = target.clone();
            let p = Plan::defer(move || me.task(kind, target, m));
            match label {
                Some(l) => p.target(l),
                None => p,
            }
        }))
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sealed with RustCrypto `crypto_box` 0.9 (`SalsaBox`): admin secret `[7; 32]`, token secret `[42; 32]`, nonce `[9; 24]`.
    #[test]
    fn box_open_matches_crypto_box() {
        let hex = crate::crypto::unhex;
        let admin: [u8; 32] = hex("13be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe97b6d").try_into().unwrap();
        let mut sealed = hex(
            "2e95b4069bbfc979951cd198eed4febadd94273fd82107ccbce7914c2ef13aeb0e8e16fb2a60b051a1285e2e2f6fd6da8f7731b8",
        );
        assert_eq!(box_open(&[42; 32], &admin, &[9; 24], &sealed).as_deref(), Some(&b"organization key v1 0123456789abcdef"[..]));
        sealed[20] ^= 1;
        assert_eq!(box_open(&[42; 32], &admin, &[9; 24], &sealed), None);
        assert_eq!(box_open(&[42; 32], &admin, &[9; 24], &sealed[..15]), None);
    }

    // Reference vectors (made with libsodium in JavaScript).
    const SEED: &str = "RfD2e8N6R92NKuRlF1RHlK7HHe3g2-3pGtdcuc9hOw8";
    const ADMIN_PUBKEY: &str = "+YniNIIKOH65XTGVPLUsdswQU/1CGu2QYYkurmD52k4=";
    const WRAP: &str =
        "YUb0wK3wrPMFzt6i7a3gkoDmbJ/QG8gbsLvAQDEnpQKgzbJ089V6m4yGCr2uZ7dvu4Hsh1TbtFhddcrSfDBtH0xbIzRU4zzm";
    const MASTER_KEY: &str = "9g21kyfkj0gn/gllmJEtXYvUqV/BFDdcZ/wrc2qrQ0E=";

    #[test]
    fn opens_wrapped_org_key() {
        let seed: [u8; 32] = b64_url_decode(SEED).unwrap().try_into().unwrap();
        let resp = json!({"adminPubkeyB64": ADMIN_PUBKEY, "wrappedKeys": [{"version": 1, "blob": WRAP}]});
        let keys = open_org_keys(&seed, resp.as_object().unwrap()).unwrap();
        assert_eq!(keys.get(&1).unwrap(), &crate::crypto::b64_decode(MASTER_KEY).unwrap());
        // A wrong seed cannot open it.
        assert!(open_org_keys(&[1u8; 32], resp.as_object().unwrap()).is_none());
    }

    #[test]
    fn seal_round_trip() {
        let key = [7u8; 32];
        let sealed = seal("héllo".as_bytes(), &key).unwrap();
        assert_eq!(sealed.len(), 24 + "héllo".len() + 16);
        let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let plain = cipher.decrypt(&XNonce::try_from(&sealed[..24]).unwrap(), &sealed[24..]).unwrap();
        assert_eq!(plain, "héllo".as_bytes());
    }

    #[test]
    fn argon2id_matches_libsodium() {
        // Known answer computed with libsodium crypto_pwhash_alg (Argon2id13, opslimit 3, memlimit 64 MiB).
        let (key, fp) = derive_key("secret", "alerts").unwrap();
        assert_eq!(fp, KNOWN_FINGERPRINT);
        assert_eq!(b64(&key), KNOWN_KEY);
    }

    const KNOWN_FINGERPRINT: &str = "CQaZgA2pRm0=";
    const KNOWN_KEY: &str = "9mI0HX1p1U2VckiSHX8jBmHx/6gqIXYEPctmfuN9ak4=";
}
