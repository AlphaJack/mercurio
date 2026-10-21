//! Bark (`bark://`, `barks://`): push notifications to the Bark iOS app through a Bark server.
//!
//! With `?key=` every payload is encrypted with AES-GCM (16, 24 or 32 byte ASCII key, fresh 12 character IV per request) the way the Bark app expects.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm, Nonce};
use serde_json::{Value, json};

use crate::env::Env;
use crate::asset::ImageSize;
use crate::crypto::{b64, b64_url_nopad};
use crate::error::Error;
use crate::parse::{parse_list, parse_list_unquoted};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::util::parse_int;
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "bark",
    name: "Bark",
    schemes: &["bark", "barks"],
    service_url: "https://github.com/Finb/Bark",
    parse,
    templates: &[
        "{schema}://{host}/{targets}",
        "{schema}://{host}:{port}/{targets}",
        "{schema}://{user}:{password}@{host}/{targets}",
        "{schema}://{user}:{password}@{host}:{port}/{targets}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("password", "Password").secret(),
        Param::new("port", "Port").port(),
        Param::new("target_device", "Target Device").secret(),
        Param::new("targets", "Targets").list("/").required().secret().group(&["target_device"]),
        Param::new("user", "Username"),
    ],
    params: &[
        Param::new("badge", "Badge").int().min(0),
        Param::new("call", "Call").bool(false),
        Param::new("category", "Category"),
        Param::new("click", "Click"),
        Param::new("group", "Group"),
        Param::new("icon", "Icon URL"),
        Param::new("image", "Include Image").bool(true),
        Param::new("key", "Encryption Key").secret(),
        Param::new("level", "Level").choice(&["active", "timeSensitive", "passive", "critical"]),
        Param::new("sound", "Sound").choice(&["alarm.caf", "anticipate.caf", "bell.caf", "birdsong.caf", "bloom.caf", "calypso.caf", "chime.caf", "choo.caf", "descent.caf", "electronic.caf", "fanfare.caf", "glass.caf", "gotosleep.caf", "healthnotification.caf", "horn.caf", "ladder.caf", "mailsent.caf", "minuet.caf", "multiwayinvitation.caf", "newmail.caf", "newsflash.caf", "noir.caf", "paymentsuccess.caf", "shake.caf", "sherwoodforest.caf", "silence.caf", "spell.caf", "suspense.caf", "telegraph.caf", "tiptoes.caf", "typewriters.caf", "update.caf"]),
        Param::sets("to", &["targets"]),
        Param::new("volume", "Volume").int().range(0, 10),
    ],
    ..ServiceDef::DEFAULTS
};

const SOUNDS: &[&str] = &[
    "alarm.caf",
    "anticipate.caf",
    "bell.caf",
    "birdsong.caf",
    "bloom.caf",
    "calypso.caf",
    "chime.caf",
    "choo.caf",
    "descent.caf",
    "electronic.caf",
    "fanfare.caf",
    "glass.caf",
    "gotosleep.caf",
    "healthnotification.caf",
    "horn.caf",
    "ladder.caf",
    "mailsent.caf",
    "minuet.caf",
    "multiwayinvitation.caf",
    "newmail.caf",
    "newsflash.caf",
    "noir.caf",
    "paymentsuccess.caf",
    "shake.caf",
    "sherwoodforest.caf",
    "silence.caf",
    "spell.caf",
    "suspense.caf",
    "telegraph.caf",
    "tiptoes.caf",
    "typewriters.caf",
    "update.caf",
];

const LEVELS: &[&str] = &["active", "timeSensitive", "passive", "critical"];

type Aes192Gcm = AesGcm<aes_gcm::aes::Aes192, aes_gcm::aead::consts::U12>;

#[derive(Debug)]
struct Bark {
    notify_url: String,
    user: Option<String>,
    password: Option<Secret>,
    targets: Vec<String>,
    include_image: bool,
    sound: Option<&'static str>,
    category: Option<String>,
    group: Option<String>,
    level: Option<&'static str>,
    click: Option<String>,
    badge: Option<i64>,
    volume: Option<i64>,
    icon: Option<String>,
    call: bool,
    key: Option<Secret>,
}

fn param_unquoted(u: &ParsedUrl, key: &str) -> Option<String> {
    u.param_nonempty(key).map(|v| unquote(v.trim()))
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let mut targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list_unquoted([to]));
    }
    let category = param_unquoted(u, "category");
    let group = param_unquoted(u, "group");
    let badge_raw = param_unquoted(u, "badge");
    let volume_raw = param_unquoted(u, "volume");
    let level_raw = param_unquoted(u, "level");
    let click = param_unquoted(u, "click");
    let sound_raw = param_unquoted(u, "sound");
    let include_image = SERVICE.flag_strict(u, "image");
    let icon = param_unquoted(u, "icon");
    let call = SERVICE.flag(u, "call");
    let key = SERVICE.text(u, "key");

    let badge = badge_raw.as_deref().and_then(parse_int).filter(|b| *b >= 0);
    let sound = sound_raw.as_deref().filter(|s| !s.is_empty()).and_then(|s| {
        let s = s.to_lowercase();
        SOUNDS.iter().copied().find(|f| f.starts_with(&s))
    });
    // Out-of-range integers are kept.
    let volume = volume_raw.as_deref().and_then(parse_int);
    let level = level_raw.as_deref().and_then(|l| {
        let first = l.chars().next()?;
        LEVELS.iter().copied().find(|f| f.starts_with(first))
    });
    let key = match key {
        Some(k) if !k.is_empty() => {
            if !k.is_ascii() {
                return Err(SERVICE.err("the Bark encryption key must contain only ASCII characters"));
            }
            if ![16, 24, 32].contains(&k.len()) {
                return Err(SERVICE.err("the Bark encryption key must contain exactly 16, 24, or 32 ASCII characters"));
            }
            Some(Secret::new(k))
        }
        _ => None,
    };

    let mut notify_url = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = u.port {
        notify_url.push_str(&format!(":{p}"));
    }
    notify_url.push_str("/push");

    Ok(Box::new(Bark {
        notify_url,
        user: u.user().filter(|s| !s.is_empty()),
        password: u.password().map(Secret::new),
        targets: parse_list(&targets),
        include_image,
        sound,
        category,
        group,
        level,
        click,
        badge,
        volume,
        icon,
        call,
        key,
    }))
}

/// AES-GCM encrypt with a 16/24/32 byte key; ciphertext has the tag appended.
fn aes_gcm_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    let nonce = &Nonce::try_from(iv).ok()?;
    match key.len() {
        16 => Aes128Gcm::new_from_slice(key).ok()?.encrypt(nonce, plaintext).ok(),
        24 => Aes192Gcm::new_from_slice(key).ok()?.encrypt(nonce, plaintext).ok(),
        32 => Aes256Gcm::new_from_slice(key).ok()?.encrypt(nonce, plaintext).ok(),
        _ => None,
    }
}

/// Inverse of [`aes_gcm_encrypt`] (tests).
#[cfg(test)]
fn aes_gcm_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let nonce = &Nonce::try_from(iv).ok()?;
    match key.len() {
        16 => Aes128Gcm::new_from_slice(key).ok()?.decrypt(nonce, ciphertext).ok(),
        24 => Aes192Gcm::new_from_slice(key).ok()?.decrypt(nonce, ciphertext).ok(),
        32 => Aes256Gcm::new_from_slice(key).ok()?.decrypt(nonce, ciphertext).ok(),
        _ => None,
    }
}

/// Compact JSON object keeping the payload's insertion order.
fn compact_json(pairs: &[(&str, Value)], text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + text.len() / 64 + 1024);
    out.push(b'{');
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        let ok = serde_json::to_writer(&mut out, k).is_ok() && {
            out.push(b':');
            crate::http::write_json_text(&mut out, v, text).is_ok()
        };
        if !ok {
            return Vec::new();
        }
    }
    out.push(b'}');
    out
}

/// Encrypt one payload; returns `(base64 ciphertext, iv)`.
fn encrypt_payload(key: &[u8], pairs: &[(&str, Value)], text: &str, env: &dyn Env) -> Option<(String, String)> {
    let mut raw = [0u8; 9];
    env.fill_random(&mut raw);
    let iv = b64_url_nopad(&raw);
    let ct = aes_gcm_encrypt(key, iv.as_bytes(), &compact_json(pairs, text))?;
    Some((b64(&ct), iv))
}

impl Notify for Bark {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(SERVICE.err("there are no Bark devices to notify"));
        }
        let title = if msg.title.is_empty() { ctx.app_desc() } else { msg.title };
        let mut pairs: Vec<(&str, Value)> = vec![("title", json!(title))];
        if msg.format == NotifyFormat::Markdown {
            pairs.push(("markdown", json!(crate::http::TEXT)));
        } else {
            pairs.push(("body", json!(crate::http::TEXT)));
        }
        let image = if self.include_image { ctx.asset.image_url(msg.kind, ImageSize::Xy128) } else { None };
        if let Some(icon) = self.icon.clone().filter(|i| !i.is_empty()).or(image) {
            pairs.push(("icon", json!(icon)));
        }
        if let Some(s) = self.sound {
            pairs.push(("sound", json!(s)));
        }
        if let Some(c) = self.click.as_deref().filter(|c| !c.is_empty()) {
            pairs.push(("url", json!(c)));
        }
        if let Some(b) = self.badge.filter(|b| *b != 0) {
            pairs.push(("badge", json!(b)));
        }
        if let Some(l) = self.level {
            pairs.push(("level", json!(l)));
        }
        if let Some(c) = self.category.as_deref().filter(|c| !c.is_empty()) {
            pairs.push(("category", json!(c)));
        }
        if let Some(g) = self.group.as_deref().filter(|g| !g.is_empty()) {
            pairs.push(("group", json!(g)));
        }
        if let Some(v) = self.volume.filter(|v| *v != 0) {
            pairs.push(("volume", json!(v)));
        }
        if self.call {
            pairs.push(("call", json!(1)));
        }

        Plan::all(self.targets.iter().map(|target| {
            let payload = match &self.key {
                Some(key) => match encrypt_payload(key.expose().as_bytes(), &pairs, msg.body, ctx.env().as_ref()) {
                    Some((ciphertext, iv)) => json!({"device_key": target, "ciphertext": ciphertext, "iv": iv}),
                    None => return Plan::Fail(Error::Service("failed to encrypt Bark notification".into())),
                },
                None => {
                    let mut m = serde_json::Map::new();
                    m.insert("device_key".into(), json!(target));
                    for (k, v) in &pairs {
                        m.insert((*k).into(), v.clone());
                    }
                    Value::Object(m)
                }
            };
            let mut req =
                ctx.post(&self.notify_url).header("Content-Type", "application/json; charset=utf-8").json_text(&payload, msg.body);
            req = req.basic_auth_opt(self.user.as_deref(), self.password.as_ref().map(Secret::expose));
            Plan::send_expect(req, &[200]).target(target.clone())
        }))
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcm_known_answer() {
        // NIST GCM test case 2 (AES-128, zero key/IV, one zero block).
        let ct = aes_gcm_encrypt(&[0u8; 16], &[0u8; 12], &[0u8; 16]).unwrap();
        assert_eq!(crate::crypto::hex(&ct), "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf");
    }

    #[test]
    fn round_trip_all_key_sizes() {
        let pairs = vec![("title", json!("t")), ("body", json!("héllo \"x\"")), ("badge", json!(3))];
        for key in ["0123456789abcdef", "0123456789abcdef01234567", "0123456789abcdef0123456789abcdef"] {
            let (ct, iv) = encrypt_payload(key.as_bytes(), &pairs, "", crate::testing::test_env()).unwrap();
            assert_eq!(iv.len(), 12);
            let plain =
                aes_gcm_decrypt(key.as_bytes(), iv.as_bytes(), &crate::crypto::b64_decode(&ct).unwrap()).unwrap();
            assert_eq!(String::from_utf8(plain).unwrap(), r#"{"title":"t","body":"héllo \"x\"","badge":3}"#);
        }
    }
}
