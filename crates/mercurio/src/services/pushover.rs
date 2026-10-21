//! Pushover (`pover://`): push notifications through the Pushover API, with optional end-to-end encryption (`?key=<64 hex>`).
//!
//! # Differences with Apprise
//!
//! - HTML that Apprise's parser rejects (a malformed `<![` declaration) is sent unreduced.
//! - E2EE gzip members use stored deflate blocks with a zero mtime; they decompress identically.
//! - Split overflow: Apprise splits the source and sends each piece through its HTML reducer, while mercurio reduces each chunk once and splits the reduced HTML at line or word boundaries, closing open tags at a cut and reopening them in the next piece.

use std::sync::Arc;

use aes::Aes256;
use aes::cipher::{BlockCipherEncrypt, KeyInit};

use crate::env::Env;
use crate::convert::html;
use crate::error::Error;
use crate::http::{Multipart, Request};
use crate::message::Attachment;
use crate::parse::{parse_bool, parse_list, validate_nonblank};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, parse_url_unverified, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

/// Longest emergency `?expire=` in seconds.
const MAX_EXPIRE: i64 = 10_800;
/// Shortest emergency `?interval=` in seconds.
const MIN_INTERVAL: i64 = 30;

pub static SERVICE: ServiceDef = ServiceDef {
    id: "pushover",
    name: "Pushover",
    schemes: &["pover"],
    service_url: "https://pushover.net/",
    parse,
    limits: Limits { title_maxlen: 250, body_maxlen: 1024, body_max_line_count: 0 },
    formats: &[NotifyFormat::Text, NotifyFormat::Html, NotifyFormat::Markdown],
    attachments: true,
    templates: &[
        "{schema}://{user_key}@{token}",
        "{schema}://{user_key}@{token}/{targets}",
    ],
    tokens: &[
        Param::new("target_device", "Target Device").pattern("^[a-z0-9_-]{1,25}$"),
        Param::new("target_group", "Target Group").prefix("#"),
        Param::new("targets", "Targets").list("/").group(&["target_device", "target_group"]),
        Param::new("token", "Access Token").required().secret(),
        Param::new("user_key", "User Key").required().secret(),
    ],
    params: &[
        Param::new("e2ee", "E2EE").bool(true),
        Param::new("expire", "Expire").int().default("3600").range(0, MAX_EXPIRE),
        Param::new("interval", "Emergency Retry Interval").int().default("900").min(MIN_INTERVAL),
        Param::new("key", "Encryption Key").secret(),
        Param::new("priority", "Priority").choice(&["-2", "-1", "0", "1", "2"]).default("0"),
        Param::new("sound", "Sound").default("pushover").pattern("^[a-z]{1,12}$"),
        Param::sets("to", &["targets"]),
        Param::new("url", "URL"),
        Param::new("url_title", "URL Title"),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.pushover.net/1/messages.json";
const SEND_TO_ALL: &str = "ALL_DEVICES";
const ATTACH_MAX_BYTES: usize = 5_242_880;
const EMERGENCY: i64 = 2;

/// Prefix -> priority, in match order.
const PRIORITY_MAP: &[(&str, i64)] =
    &[("l", -2), ("m", -1), ("n", 0), ("h", 1), ("e", 2), ("-2", -2), ("-1", -1), ("0", 0), ("1", 1), ("2", 2)];

#[derive(Debug)]
struct Pushover {
    token: Secret,
    user_key: Secret,
    devices: Vec<String>,
    groups: Vec<String>,
    priority: i64,
    sound: String,
    url: Option<String>,
    url_title: Option<String>,
    /// `(retry, expire)` for emergency priority.
    emergency: Option<(i64, i64)>,
    encryption_key: Option<Secret>,
    e2ee: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    // `#` is escaped in the path (group markers) before parsing.
    let (path, rest) = match u.original.find('?') {
        Some(i) => u.original.split_at(i),
        None => (u.original.as_str(), ""),
    };
    let rebuilt = format!("{}{}", path.replace('#', "%23"), rest);
    let r = parse_url_unverified(&rebuilt).ok_or_else(|| SERVICE.err("unparseable Pushover URL"))?;

    let mut targets = r.path_segments();
    if let Some(to) = r.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }
    let token =
        validate_nonblank(&r.host()).ok_or_else(|| SERVICE.err("an invalid Pushover Access Token was specified"))?;
    let user_key = validate_nonblank(&r.user().unwrap_or_default())
        .ok_or_else(|| SERVICE.err("an invalid Pushover User Key was specified"))?;

    let mut devices = Vec::new();
    let mut groups = Vec::new();
    let targets = parse_list(&targets);
    if targets.is_empty() {
        devices.push(SEND_TO_ALL.to_string());
    }
    for t in targets {
        if let Some(c) = crate::regex!(r"(?i)^\s*(?:%23|#)(?P<group>[a-z0-9]+)\s*$").captures(&t) {
            groups.push(c["group"].to_string());
        } else if let Some(c) = crate::regex!(r"(?i)^\s*(?P<device>[a-z0-9_-]{1,25})\s*$").captures(&t) {
            devices.push(c["device"].to_string());
        } else {
            log::warn!("Pushover: dropped invalid target");
        }
    }

    let sound = SERVICE.text_or_default(&r, "sound").to_lowercase();
    let priority = {
        let p = SERVICE.text_or_default(&r, "priority").to_lowercase();
        PRIORITY_MAP.iter().find(|(k, _)| p.starts_with(k)).map(|(_, v)| *v).unwrap_or(0)
    };
    let emergency = if priority == EMERGENCY {
        let interval = SERVICE.int_or_default(&r, "interval");
        let expire = SERVICE.int_or_default(&r, "expire");
        if interval < MIN_INTERVAL {
            return Err(SERVICE.err(format!("the emergency interval must be at least {MIN_INTERVAL} seconds")));
        }
        if !(0..=MAX_EXPIRE).contains(&expire) {
            return Err(SERVICE.err(format!("expire must reside in the range of 0 to {MAX_EXPIRE} seconds")));
        }
        Some((interval, expire))
    } else {
        None
    };
    let encryption_key = match r.param_nonempty("key") {
        None => None,
        Some(k) => {
            let k = unquote(k).trim().to_lowercase();
            if !crate::regex!(r"^[0-9a-f]{64}$").is_match(&k) {
                return Err(SERVICE.err("the encryption key must be exactly 64 hex characters"));
            }
            Some(Secret::new(k))
        }
    };
    let e2ee = r.param_nonempty("e2ee").map(|v| parse_bool(v, false)).unwrap_or(true);

    Ok(Box::new(Arc::new(Pushover {
        token: Secret::new(token),
        user_key: Secret::new(user_key),
        devices,
        groups,
        priority,
        sound,
        url: SERVICE.text(&r, "url"),
        url_title: SERVICE.text(&r, "url_title"),
        emergency,
        encryption_key,
        e2ee,
    })))
}

type Payload = Vec<(&'static str, String)>;

fn set(p: &mut Payload, key: &'static str, value: impl Into<String>) {
    let value = value.into();
    match p.iter_mut().find(|(k, _)| *k == key) {
        Some(e) => e.1 = value,
        None => p.push((key, value)),
    }
}

impl Pushover {
    fn request(&self, payload: &Payload, attach: Option<&Attachment>, ua: &str, env: &dyn Env) -> Request {
        let req = Request::post(NOTIFY_URL).header("User-Agent", ua).basic_auth(self.token.expose(), Some(""));
        match attach {
            Some(a) => {
                let mut form = Multipart::with_env(env);
                for (k, v) in payload {
                    form = form.text(*k, v.clone());
                }
                req.multipart(form.file("attachment", a.name.clone(), "", a.data.clone()))
            }
            None => req.form(payload),
        }
    }

    fn send(&self, payload: &Payload, attach: Option<&Attachment>, ua: &str, env: &dyn Env) -> Plan {
        if let Some(a) = attach
            && a.mime.to_ascii_lowercase().starts_with("image/")
            && !(1..=ATTACH_MAX_BYTES).contains(&a.data.len())
        {
            return Plan::Fail(Error::Message("Pushover attachment size exceeds the limit".into()));
        }
        // Unsupported attachments are dropped; the message still goes out.
        let attach = attach.filter(|a| a.mime.to_ascii_lowercase().starts_with("image/"));
        Plan::http(self.request(payload, attach, ua, env), |res| match res {
            Ok(r) if r.status == 200 => Plan::Done,
            Ok(r) if r.status == 401 => {
                Plan::Fail(Error::Http { status: 401, reason: "Unauthorized - Invalid Token.".into() })
            }
            Ok(r) => Plan::Fail(r.http_error()),
            Err(e) => Plan::Fail(e),
        })
    }
}

/// The tags Pushover shows; headings become bold lines.
const PUSHOVER_HTML: html::Filter = html::Filter {
    tags: &[
        ("b", "b"),
        ("strong", "b"),
        ("i", "i"),
        ("em", "i"),
        ("u", "u"),
        ("ins", "u"),
        ("font", "font"),
        ("a", "a"),
        ("h1", "b"),
        ("h2", "b"),
        ("h3", "b"),
        ("h4", "b"),
        ("h5", "b"),
        ("h6", "b"),
    ],
    attrs: &[("font", "color"), ("a", "href")],
    line_break: "<br>",
    keep_newlines: false,
};

impl Notify for Arc<Pushover> {
    /// Markdown is rendered as HTML, then HTML is reduced to the tags Pushover shows; plain text is unchanged.
    fn convert(&self, body: &str, format: NotifyFormat) -> Option<String> {
        let source = match format {
            NotifyFormat::Markdown => crate::convert::markdown_to_html(body),
            NotifyFormat::Html => body.to_string(),
            NotifyFormat::Text => return None,
        };
        Some(html::filter(&source, &PUSHOVER_HTML))
    }

    /// The filter's output is well-nested HTML.
    fn split_converted(&self) -> bool {
        true
    }

    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.devices.is_empty() && self.groups.is_empty() {
            return Plan::Fail(Error::Message("there were no Pushover targets to notify".into()));
        }
        let ua = ctx.app_id();
        let mut base: Payload = vec![
            ("token", self.token.expose().to_string()),
            ("priority", self.priority.to_string()),
            ("title", if msg.title.is_empty() { ctx.app_desc().to_string() } else { msg.title.to_string() }),
            ("message", msg.body.to_string()),
            ("sound", self.sound.clone()),
        ];
        if let Some(u) = &self.url {
            base.push(("url", u.clone()));
        }
        if let Some(t) = &self.url_title {
            base.push(("url_title", t.clone()));
        }
        if msg.format == NotifyFormat::Html || (msg.format == NotifyFormat::Markdown && !msg.passthrough) {
            base.push(("html", "1".into()));
        }
        if let Some((retry, expire)) = self.emergency {
            base.push(("retry", retry.to_string()));
            base.push(("expire", expire.to_string()));
        }
        if let Some(key) = self.encryption_key.as_ref().filter(|_| self.e2ee) {
            // `parse` accepts only 64 hex characters.
            let Ok(key) = <[u8; 32]>::try_from(crate::crypto::unhex(key.expose())) else {
                return Plan::Fail(SERVICE.err("the encryption key must be exactly 64 hex characters"));
            };
            for field in ["message", "title", "url", "url_title"] {
                if let Some(e) = base.iter_mut().find(|(k, _)| *k == field) {
                    e.1 = encrypt_field(&e.1, &key, &random_iv(ctx.env().as_ref()));
                }
            }
            base.push(("encrypted", "1".into()));
        }

        let mut recipients: Vec<(String, Payload)> = Vec::new();
        if !self.devices.is_empty() {
            let mut p = base.clone();
            p.push(("user", self.user_key.expose().to_string()));
            p.push(("device", self.devices.join(",")));
            recipients.push(("account".into(), p));
        }
        for g in &self.groups {
            let mut p = base.clone();
            p.push(("user", g.clone()));
            recipients.push((format!("group:{g}"), p));
        }

        Plan::all(recipients.into_iter().map(|(label, payload)| {
            if msg.attachments.is_empty() {
                return self.send(&payload, None, ua, ctx.env().as_ref()).target(label);
            }
            // Every attachment is posted, even after a failure.
            let mut p = payload;
            let mut plans = Vec::new();
            for (no, a) in msg.attachments.iter().enumerate() {
                if no > 0 || msg.body.is_empty() {
                    set(&mut p, "message", a.name.clone());
                }
                plans.push(self.send(&p, Some(a), ua, ctx.env().as_ref()));
                set(&mut p, "title", "");
                set(&mut p, "sound", "none");
            }
            Plan::all(plans).target(label)
        }))
    }

}

// E2EE (https://pushover.net/api#e2ee)


fn random_iv(env: &dyn Env) -> [u8; 16] {
    let mut iv = [0u8; 16];
    env.fill_random(&mut iv);
    iv
}

/// `base64(iv || AES-256-CBC(gzip(text)) || HMAC-SHA256(iv || ciphertext))`.
fn encrypt_field(text: &str, key: &[u8; 32], iv: &[u8; 16]) -> String {
    let ct = aes256_cbc_pkcs7(key, iv, &gzip_stored(text.as_bytes()));
    let mut out = iv.to_vec();
    out.extend_from_slice(&ct);
    let mac = crate::crypto::hmac_sha256(key, &out);
    out.extend_from_slice(&mac);
    crate::crypto::b64(&out)
}

fn aes256_cbc_pkcs7(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new(&(*key).into());
    let pad = 16 - data.len() % 16;
    let mut buf = data.to_vec();
    buf.extend(std::iter::repeat_n(pad as u8, pad));
    let mut prev = *iv;
    // Padding makes `buf` a whole number of blocks: the remainder is empty.
    let mut rest = buf.as_mut_slice();
    while let Some((chunk, tail)) = rest.split_first_chunk_mut::<16>() {
        rest = tail;
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        let mut block = (*chunk).into();
        cipher.encrypt_block(&mut block);
        *chunk = block.into();
        prev = *chunk;
    }
    buf
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// A gzip member holding `data` in stored (uncompressed) deflate blocks.
fn gzip_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    let mut chunks = data.chunks(65_535).peekable();
    if chunks.peek().is_none() {
        out.extend_from_slice(&[1, 0, 0, 0xff, 0xff]);
    }
    while let Some(c) = chunks.next() {
        out.push(chunks.peek().is_none() as u8);
        let len = c.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(c);
    }
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{Array, BlockCipherDecrypt};

    fn h(s: &str) -> Vec<u8> {
        crate::crypto::unhex(s)
    }

    /// NIST SP 800-38A F.2.5 (CBC-AES256.Encrypt), first two blocks.
    #[test]
    fn cbc_known_answer() {
        let key: [u8; 32] = h("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").try_into().unwrap();
        let iv: [u8; 16] = h("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let pt = h("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        let ct = aes256_cbc_pkcs7(&key, &iv, &pt);
        assert_eq!(crate::crypto::hex(&ct[..32]), "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d");
        // Full padding block appended for block-aligned input.
        assert_eq!(ct.len(), 48);
    }

    #[test]
    fn crc_and_gzip() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        let g = gzip_stored(b"hello");
        assert_eq!(&g[..3], &[0x1f, 0x8b, 8]);
        assert_eq!(&g[10..15], &[1, 5, 0, 0xfa, 0xff]);
        assert_eq!(&g[15..20], b"hello");
        assert_eq!(gzip_stored(b"").len(), 10 + 5 + 8);
    }

    /// Round trip: split the field, check the MAC, decrypt and unpad.
    #[test]
    fn e2ee_field_layout() {
        let key: [u8; 32] = h(&"ab".repeat(32)).try_into().unwrap();
        let iv = [7u8; 16];
        let field = crate::crypto::b64_decode(&encrypt_field("Hello World", &key, &iv)).unwrap();
        let (body, mac) = field.split_at(field.len() - 32);
        assert_eq!(&body[..16], &iv);
        assert_eq!(mac, crate::crypto::hmac_sha256(&key, body).as_slice());
        let cipher = Aes256::new_from_slice(&key).expect("AES-256 key");
        let mut prev = iv.to_vec();
        let mut plain = Vec::new();
        for c in body[16..].chunks(16) {
            let mut b = Array::try_from(c).expect("16-byte block");
            cipher.decrypt_block(&mut b);
            plain.extend(b.iter().zip(&prev).map(|(x, y)| x ^ y));
            prev = c.to_vec();
        }
        let pad = *plain.last().unwrap() as usize;
        plain.truncate(plain.len() - pad);
        assert_eq!(plain, gzip_stored(b"Hello World"));
    }

    /// Fixed IV; this value was decrypted and gunzipped with an independent AES-CBC + gzip implementation back to "Hello Wörld".
    #[test]
    fn e2ee_known_answer() {
        assert_eq!(
            encrypt_field("Hello Wörld", &crate::crypto::unhex(&"ab".repeat(32)).try_into().unwrap(), &[3u8; 16]),
            "AwMDAwMDAwMDAwMDAwMDAxTymuP63nr2qVpE6L97kGVkqDlxxkSDa3bkUtFtUl0TO2pnwBTZZ7puKqzovK8PIVqXX3/b9m0Ka64kyEnFXxoFMAEKWSqaNv7pKa3YVsOM"
        );
    }
}
