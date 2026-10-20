//! Firebase Cloud Messaging (`fcm://`).
//!
//! Reads a service account JSON key file, signs an RS256 JWT assertion, trades it for an access token and sends through the HTTP v1 API. The legacy API (server keys, `fcm/send`) was shut down in July 2024: URLs without a key file are rejected. So are URLs with `?mode=legacy`.
//!
//! # Differences
//!
//! - The key file must be local (a path or `file://`); only RSA service account keys are supported (Apprise fails on others as well). *intentional*
//! - Legacy mode (server API key, `fcm/send`) defaults on in Apprise when no key file is given -> mercurio rejects such URLs and `?mode=legacy`: Google shut that API down in July 2024. Only the HTTP v1 API is used. *intentional*

use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde_json::{Map, Value, json};

use super::_keys::{json_full_update, local_file_ops, pem_decode, read_local_file};
use crate::asset::ImageSize;
use crate::crypto::b64_url_nopad;
use crate::time::unix_time;
use crate::error::Error;
use crate::http::Request;
use crate::parse::{parse_bool, parse_list, parse_list_unquoted, validate_nonblank};
use crate::service::{Context, Limits, Notify, Param, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{FileOp, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "fcm",
    name: "Firebase Cloud Messaging",
    schemes: &["fcm"],
    service_url: "https://firebase.google.com",
    parse,
    limits: Limits { title_maxlen: 250, body_maxlen: 1024, body_max_line_count: 0 },
    templates: &["{schema}://{project}/{targets}?keyfile={keyfile}"],
    tokens: &[
        Param::new("keyfile", "OAuth2 KeyFile").required().secret(),
        Param::new("project", "Project ID"),
        Param::new("target_device", "Target Device"),
        Param::new("target_topic", "Target Topic").prefix("#"),
        Param::new("targets", "Targets").list("/").required().group(&["target_device", "target_topic"]),
    ],
    params: &[
        Param::new("color", "Notification Color").default("no"),
        Param::new("image", "Include Image").bool(false).inferred(),
        Param::new("image_url", "Custom Image URL"),
        Param::new("mode", "Mode")
            .choice(&["oauth2"])
            .default("oauth2")
            .note("`legacy` is rejected: that API was shut down in July 2024"),
        Param::new("priority", "Mode").choice(&["min", "low", "normal", "high", "max"]),
        Param::sets("to", &["targets"]),
        Param::new("data_kwargs", "Data Entries").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_OAUTH2_URL: &str = "https://fcm.googleapis.com/v1/projects/{project}/messages:send";
const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const MAX_KEYFILE_SIZE: u64 = 5000;
const TOKEN_LIFETIME_SECS: u64 = 3600;

const LEGACY_API_SHUT_DOWN: &str = "the FCM legacy API (server key) was shut down in July 2024: give the project ID and \
     ?keyfile= with a service account JSON key";

const PRIORITIES: &[&str] = &["min", "low", "normal", "high", "max"];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Color {
    Off,
    Asset,
    /// `rrggbb` (lower case, no `#`).
    Rgb(String),
}

#[derive(Debug)]
struct Fcm {
    project: String,
    keyfile: String,
    targets: Vec<String>,
    data: Vec<(String, String)>,
    include_image: bool,
    image_src: Option<String>,
    priority: Option<&'static str>,
    color: Color,
}

fn parse_color(color: Option<&str>) -> Color {
    let Some(c) = color else { return Color::Off };
    let re = crate::regex!(
        r"(?i)^#?(?:(?P<r1>[0-9A-F]{2})(?P<g1>[0-9A-F]{2})(?P<b1>[0-9A-F]{2})|(?P<r2>[0-9A-F])(?P<g2>[0-9A-F])(?P<b2>[0-9A-F]))"
    );
    if let Some(m) = re.captures(c) {
        let s = if let Some(r) = m.name("r1") {
            format!("{}{}{}", r.as_str(), &m["g1"], &m["b1"])
        } else {
            let (r, g, b) = (&m["r2"], &m["g2"], &m["b2"]);
            format!("{r}{r}{g}{g}{b}{b}")
        };
        return Color::Rgb(s.to_lowercase());
    }
    if parse_bool(c, false) { Color::Asset } else { Color::Off }
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut project = u.host();
    let mut targets = u.path_segments();
    let mode_raw = SERVICE.raw(u, "mode").map(str::to_string);
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list_unquoted([to]));
    }
    if let Some(p) = u.param_nonempty("project") {
        project = unquote(p);
    }
    let keyfile = u.text("keyfile");
    let priority_raw = SERVICE.text(u, "priority");
    let color_raw = SERVICE.text(u, "color");
    let mut include_image = SERVICE.flag(u, "image");
    let mut image_src = None;
    if let Some(i) = SERVICE.raw(u, "image_url") {
        image_src = Some(unquote(i));
        if !u.has_param("image") {
            include_image = true;
        }
    }

    let missing = match mode_raw.map(|m| m.to_lowercase()).as_deref() {
        None => LEGACY_API_SHUT_DOWN,
        Some("oauth2") => "no FCM JSON KeyFile was specified",
        Some("legacy") => return Err(SERVICE.err(LEGACY_API_SHUT_DOWN)),
        Some(_) => return Err(SERVICE.err("the FCM mode specified is invalid")),
    };
    let keyfile = keyfile.ok_or_else(|| SERVICE.err(missing))?;
    let project = validate_nonblank(&project).ok_or_else(|| SERVICE.err("an invalid FCM Project ID was specified"))?;
    let priority = match priority_raw {
        None => None,
        Some(p) => {
            let head: String = p.chars().take(2).collect::<String>().to_lowercase();
            Some(
                PRIORITIES
                    .iter()
                    .copied()
                    .find(|x| x.starts_with(&head))
                    .ok_or_else(|| SERVICE.err("an invalid FCM Priority was specified"))?,
            )
        }
    };

    Ok(Box::new(Fcm {
        project,
        keyfile,
        targets: parse_list(&targets),
        data: u.query_plus.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        include_image,
        image_src,
        priority,
        color: parse_color(color_raw.as_deref()),
    }))
}

fn priority_payload(priority: &str) -> Value {
    let (android, apns, urgency) = match priority {
        "min" => ("NORMAL", json!({"apns-priority": "5"}), "very-low"),
        "low" => ("NORMAL", json!({"apns-priority": "5"}), "low"),
        "normal" => ("NORMAL", json!({"apns-priority": "5"}), "normal"),
        _ => ("HIGH", json!({"apns-priority": "10", "apns-push-type": "alert"}), "high"),
    };
    json!({"message": {
        "android": {"priority": android},
        "apns": {"headers": apns},
        "webpush": {"headers": {"Urgency": urgency}},
    }})
}

struct ServiceAccount {
    project_id: String,
    client_email: String,
    key_id: String,
    token_uri: String,
    key: RsaKeyPair,
}

/// Load the RSA private key of a service account (PKCS#8 or PKCS#1 PEM).
fn load_rsa_key(pem: &str) -> Option<RsaKeyPair> {
    let (label, der) = pem_decode(pem)?;
    match label.as_str() {
        "PRIVATE KEY" => RsaKeyPair::from_pkcs8(&der).ok(),
        "RSA PRIVATE KEY" => RsaKeyPair::from_der(&der).ok(),
        _ => None,
    }
}

/// Load and check a service account key file.
fn load_keyfile(ctx: &Context<'_>, path: &str) -> std::result::Result<ServiceAccount, &'static str> {
    let data = read_local_file(ctx, path, MAX_KEYFILE_SIZE).ok_or("FCM keyfile could not be accessed")?;
    let content: Value = serde_json::from_slice(data).map_err(|_| "FCM keyfile is not valid JSON")?;
    let obj = content.as_object().ok_or("FCM keyfile is incorrectly structured")?;
    if !["client_email", "private_key_id", "private_key", "type", "project_id"].iter().all(|k| obj.get(*k).is_some_and(crate::util::json_has_value)) {
        return Err("FCM keyfile is missing required information");
    }
    if obj.get("type").and_then(Value::as_str) != Some("service_account") {
        return Err("FCM keyfile is not of type service_account");
    }
    let s = |k: &str| obj.get(k).and_then(Value::as_str).map(str::to_string);
    let key = s("private_key").as_deref().and_then(load_rsa_key).ok_or("FCM provided private key is invalid")?;
    Ok(ServiceAccount {
        project_id: s("project_id").ok_or("FCM keyfile project_id is not a string")?,
        client_email: s("client_email").ok_or("FCM keyfile client_email is not a string")?,
        key_id: s("private_key_id").ok_or("FCM keyfile private_key_id is not a string")?,
        token_uri: match obj.get("token_uri") {
            None => DEFAULT_TOKEN_URI.to_string(),
            Some(v) => v.as_str().ok_or("FCM keyfile token_uri is not a string")?.to_string(),
        },
        key,
    })
}

/// Build the signed RS256 JWT assertion.
fn jwt_assertion(sa: &ServiceAccount, now: u64) -> Option<String> {
    let header = json!({"typ": "JWT", "alg": "RS256", "kid": sa.key_id}).to_string();
    let payload = json!({
        "iat": now,
        "exp": now + TOKEN_LIFETIME_SECS,
        "iss": sa.client_email,
        "aud": sa.token_uri,
        "scope": SCOPE,
    })
    .to_string();
    let signing_input = format!("{}.{}", b64_url_nopad(header.as_bytes()), b64_url_nopad(payload.as_bytes()));
    let mut sig = vec![0u8; sa.key.public().modulus_len()];
    sa.key.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), signing_input.as_bytes(), &mut sig).ok()?;
    Some(format!("{signing_input}.{}", b64_url_nopad(&sig)))
}

/// Extract the access token from the token endpoint's response (`None` fails the notification).
fn access_token(body: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let obj = v.as_object()?;
    let token = match obj.get("access_token")? {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => return None,
    };
    if let Some(e) = obj.get("expires_in") {
        let ok = match e {
            Value::Number(_) | Value::Bool(_) => true,
            Value::String(s) => crate::util::parse_int(s).is_some(),
            Value::Null | Value::Array(_) | Value::Object(_) => false,
        };
        if !ok {
            return None;
        }
    }
    Some(token).filter(|t| !t.is_empty())
}

impl Fcm {
    fn payload(&self, recipient: &str, msg: &Prepared<'_>, ctx: &Context<'_>) -> Value {
        let image = match self.image_src.as_deref().filter(|s| !s.is_empty()) {
            Some(s) => Some(s.to_string()),
            None => ctx.asset.image_url(msg.kind, ImageSize::Xy256),
        };
        let color = match &self.color {
            Color::Off => None,
            Color::Asset => Some(ctx.asset.color(msg.kind).to_string()),
            Color::Rgb(c) => Some(format!("#{c}")),
        };
        let data: Map<String, Value> = self.data.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
        let mut message = json!({"notification": {"title": msg.title, "body": msg.body}});
        if let Some(c) = color {
            message["android"] = json!({"notification": {"color": c}});
        }
        if self.include_image
            && let Some(i) = &image
        {
            message["notification"]["image"] = json!(i);
        }
        if !data.is_empty() {
            message["data"] = Value::Object(data);
        }
        match recipient.strip_prefix('#') {
            Some(topic) => message["topic"] = json!(topic),
            None => message["token"] = json!(recipient),
        }
        let mut payload = json!({ "message": message });
        if let Some(pr) = self.priority {
            json_full_update(&mut payload, &priority_payload(pr));
        }
        payload
    }
}

impl Notify for Fcm {
    fn files(&self, _: &Context<'_>) -> Vec<FileOp> {
        local_file_ops(&self.keyfile)
    }

    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(SERVICE.err("there are no FCM devices or topics to notify"));
        }
        let project = &self.project;
        let sa = match load_keyfile(ctx, &self.keyfile) {
            Ok(sa) => sa,
            Err(e) => return Plan::Fail(Error::Service(e.into())),
        };
        if sa.project_id != *project {
            return Plan::Fail(Error::Service("FCM keyfile identifies itself for a different project".into()));
        }
        let Some(assertion) = jwt_assertion(&sa, unix_time()) else {
            return Plan::Fail(Error::Service("FCM JWT assertion could not be signed".into()));
        };
        let token_req = Request::post(&sa.token_uri)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("User-Agent", ctx.app_id())
            .form(&[
                ("assertion", assertion.as_str()),
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ]);
        // Build every per-target request now; the continuation only adds the token.
        let url = NOTIFY_OAUTH2_URL.replace("{project}", project);
        let pending: Vec<(String, Request)> = self
            .targets
            .iter()
            .map(|r| {
                let req = ctx.post(&url).json(&self.payload(r, msg, ctx));
                (r.clone(), req)
            })
            .collect();
        Plan::http(token_req, move |res| {
            let r = match res {
                Ok(r) => r,
                Err(e) => return Plan::Fail(e),
            };
            if r.status != 200 {
                return Plan::Fail(r.http_error());
            }
            let Some(token) = access_token(&r.body) else {
                return Plan::Fail(Error::Service("FCM access token could not be acquired".into()));
            };
            Plan::all(pending.into_iter().map(|(recipient, req)| {
                Plan::send_expect(req.header("Authorization", format!("Bearer {token}")), &[200, 204])
                    .context("send")
                    .target(recipient)
            }))
        })
        .context("token")
    }
}

#[cfg(test)]
#[expect(clippy::disallowed_methods, reason = "tests set up real files")]
mod tests {
    use super::*;
    use crate::testing::file_context;
    use ring::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

    fn data(name: &str) -> String {
        format!("{}/tests/fixtures/data/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn jwt_verifies_with_public_key() {
        for file in ["fcm_service_account.json", "fcm_service_account_pkcs1.json"] {
            let ops = local_file_ops(&data(file));
            let sa = file_context(ops, &crate::BlockingTransport::new(), |ctx| load_keyfile(ctx, &data(file))).unwrap();
            let jwt = jwt_assertion(&sa, 1_700_000_000).unwrap();
            let parts: Vec<&str> = jwt.split('.').collect();
            assert_eq!(parts.len(), 3);
            let header = crate::crypto::b64_url_decode(parts[0]).unwrap();
            assert_eq!(
                String::from_utf8(header).unwrap(),
                r#"{"alg":"RS256","kid":"0123456789abcdef0123456789abcdef01234567","typ":"JWT"}"#
            );
            let claims: Value = serde_json::from_slice(&crate::crypto::b64_url_decode(parts[1]).unwrap()).unwrap();
            assert_eq!(claims["iat"], 1_700_000_000u64);
            assert_eq!(claims["exp"], 1_700_003_600u64);
            assert_eq!(claims["scope"], SCOPE);
            assert_eq!(claims["iss"], sa.client_email.as_str());
            assert_eq!(claims["aud"], sa.token_uri.as_str());

            let (_, spki) = pem_decode(&std::fs::read_to_string(data("fcm_rsa_public.pem")).unwrap()).unwrap();
            // SubjectPublicKeyInfo -> RSAPublicKey (the BIT STRING contents).
            let (_, seq, _) = super::super::_keys::der_next(&spki).unwrap();
            let (_, _, rest) = super::super::_keys::der_next(seq).unwrap();
            let (_, bits, _) = super::super::_keys::der_next(rest).unwrap();
            let sig = crate::crypto::b64_url_decode(parts[2]).unwrap();
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &bits[1..])
                .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
                .unwrap();
        }
    }

    #[test]
    fn colors() {
        assert_eq!(parse_color(None), Color::Off);
        assert_eq!(parse_color(Some("yes")), Color::Asset);
        assert_eq!(parse_color(Some("no")), Color::Off);
        assert_eq!(parse_color(Some("#12AAbb")), Color::Rgb("12aabb".into()));
        assert_eq!(parse_color(Some("abc")), Color::Rgb("aabbcc".into()));
    }

    #[test]
    fn token_parsing() {
        assert_eq!(access_token(br#"{"access_token": "abc", "expires_in": 3599}"#).as_deref(), Some("abc"));
        assert_eq!(access_token(br#"{"access_token": "abc", "expires_in": "x"}"#), None);
        assert_eq!(access_token(br#"{"expires_in": 1}"#), None);
        assert_eq!(access_token(b"invalid"), None);
    }
}
