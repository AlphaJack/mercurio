//! OneSignal (`onesignal://`): push notifications through the OneSignal API.

use serde_json::{Map, Value, json};

use crate::asset::ImageSize;
use crate::parse::{is_email, parse_list, validate_nonblank};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "onesignal",
    name: "OneSignal",
    schemes: &["onesignal"],
    service_url: "https://onesignal.com",
    parse,
    templates: &[
        "{schema}://{app}@{apikey}/{targets}",
        "{schema}://{template}:{app}@{apikey}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret(),
        Param::new("app", "App ID").required().secret(),
        Param::new("target_email", "Target Email").email(),
        Param::new("target_player", "Target Player ID"),
        Param::new("target_segment", "Include Segment").prefix("#"),
        Param::new("target_user", "Target User").prefix("@"),
        Param::new("targets", "Targets").list("/").required().group(&["target_email", "target_player", "target_segment", "target_user"]),
        Param::new("template", "Template").secret(),
    ],
    params: &[
        Param::new("batch", "Batch Mode").bool(false),
        Param::new("contents", "Enable Contents").bool(true),
        Param::new("decode", "Decode Template Args").bool(false),
        Param::new("image", "Include Image").bool(true),
        Param::new("language", "Language").default("en").aliases(&["lang"]),
        Param::new("subtitle", "Subtitle"),
        Param::sets("template", &["template"]),
        Param::sets("to", &["targets"]),
        Param::new("custom", "Custom Data").prefix(":"),
        Param::new("postback", "Postback Data").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.onesignal.com/notifications";
const BATCH_SIZE: usize = 2000;

/// Payload keys, in send order: players, emails, users, segments.
const CATEGORIES: [&str; 4] =
    ["include_player_ids", "include_email_tokens", "include_external_user_ids", "included_segments"];

#[derive(Debug)]
struct OneSignal {
    app: Secret,
    apikey: Secret,
    template: Option<String>,
    subtitle: Option<String>,
    language: String,
    include_image: bool,
    batch_size: usize,
    use_contents: bool,
    /// Indexed like [`CATEGORIES`].
    targets: [Vec<String>; 4],
    custom: Map<String, Value>,
    postback: Map<String, Value>,
}

/// Decode `b64:`-prefixed values holding base64 JSON.
fn decode_b64_value(v: &str) -> Value {
    if let Some(rest) = v.strip_prefix("b64:")
        && let Some(raw) = crate::crypto::b64_decode(rest)
        && let Ok(parsed) = serde_json::from_slice::<Value>(&raw)
    {
        return parsed;
    }
    json!(v)
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let user = u.user.as_deref().map(unquote).unwrap_or_default();
    let (mut app, mut template) = match u.password.as_deref().filter(|p| !p.is_empty()) {
        None => (user, None),
        Some(p) => (unquote(p), Some(user)),
    };
    let mut apikey = u.host();
    let include_image = SERVICE.flag(u, "image");
    let batch = SERVICE.flag(u, "batch");
    let use_contents = SERVICE.flag(u, "contents");
    let decode = SERVICE.flag(u, "decode");

    let mut raw_targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        raw_targets.extend(parse_list([to]));
    }
    if let Some(v) = u.param_nonempty("app") {
        app = unquote(v);
    }
    if let Some(v) = u.param_nonempty("apikey") {
        apikey = unquote(v);
    }
    if let Some(v) = u.param_nonempty("template") {
        template = Some(unquote(v));
    }
    let subtitle = SERVICE.text(u, "subtitle");
    let language = u.param_nonempty("language").or_else(|| u.param_nonempty("lang")).map(unquote);

    let apikey = validate_nonblank(&apikey).ok_or_else(|| SERVICE.err("an invalid OneSignal API key was specified"))?;
    let app =
        validate_nonblank(&app).ok_or_else(|| SERVICE.err("an invalid OneSignal Application ID was specified"))?;
    let language = match language {
        Some(l) => l.trim().to_lowercase().chars().take(2).collect::<String>(),
        None => "en".to_owned(),
    };
    if language.chars().count() != 2 {
        return Err(SERVICE.err("an invalid OneSignal Language was specified"));
    }

    let mut targets: [Vec<String>; 4] = Default::default();
    for t in parse_list(raw_targets) {
        let t = t.trim().to_owned();
        if t.chars().count() < 2 {
            continue;
        }
        if t.starts_with('@') {
            targets[2].push(t);
        } else if t.starts_with('#') {
            targets[3].push(t);
        } else if let Some(e) = is_email(&t) {
            targets[1].push(e.full_email);
        } else {
            targets[0].push(t);
        }
    }

    let custom =
        u.query_colon.iter().map(|(k, v)| (k.to_owned(), if decode { decode_b64_value(v) } else { json!(v) })).collect();
    let postback = u.query_plus.iter().map(|(k, v)| (k.to_owned(), json!(v))).collect();

    Ok(Box::new(OneSignal {
        app: Secret::new(app),
        apikey: Secret::new(apikey),
        template: template.filter(|t| !t.is_empty()),
        subtitle,
        language,
        include_image,
        batch_size: if batch { BATCH_SIZE } else { 1 },
        use_contents,
        targets,
        custom,
        postback,
    }))
}

impl Notify for OneSignal {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let lang = self.language.as_str();
        let mut payload = Map::new();
        payload.insert("app_id".into(), json!(self.app.expose()));
        payload.insert("contents".into(), json!({ lang: msg.body }));
        payload.insert("content_available".into(), json!(true));
        if let Some(t) = &self.template {
            payload.insert("template_id".into(), json!(t));
            if !self.use_contents {
                payload.remove("contents");
            }
        }
        if !self.custom.is_empty() {
            payload.insert("custom_data".into(), Value::Object(self.custom.clone()));
        }
        if !self.postback.is_empty() {
            payload.insert("data".into(), Value::Object(self.postback.clone()));
        }
        if !msg.title.is_empty() {
            payload.insert("headings".into(), json!({ lang: msg.title }));
        }
        if let Some(s) = &self.subtitle {
            payload.insert("subtitle".into(), json!({ lang: s }));
        }
        if self.include_image {
            if let Some(url) = ctx.asset.image_url(msg.kind, ImageSize::Xy72) {
                payload.insert("large_icon".into(), json!(url));
            }
            if let Some(url) = ctx.asset.image_url(msg.kind, ImageSize::Xy32) {
                payload.insert("small_icon".into(), json!(url));
            }
        }

        let mut plans = Vec::new();
        for (cat, targets) in CATEGORIES.iter().zip(self.targets.iter()) {
            for (n, chunk) in targets.chunks(self.batch_size).enumerate() {
                let batch: Vec<&str> = chunk.iter().map(|t| strip_prefix(cat, t)).collect();
                let mut data = payload.clone();
                data.insert((*cat).to_owned(), json!(batch));
                let req = ctx.post(NOTIFY_URL)
                    .header("Content-Type", "application/json; charset=utf-8")
                    .header("Authorization", format!("Basic {}", self.apikey.expose()))
                    .body(serde_json::to_vec(&Value::Object(data)).unwrap_or_default(), None);
                plans.push(Plan::send_expect(req, &[200, 204]).target(format!("{cat}[{}]", n * self.batch_size)));
            }
        }
        if plans.is_empty() {
            return Plan::Fail(crate::Error::Message("there are no OneSignal targets to notify".into()));
        }
        Plan::all(plans)
    }

}

/// Users (`@`) and segments (`#`) are sent without their prefix.
fn strip_prefix<'a>(cat: &str, t: &'a str) -> &'a str {
    if cat == CATEGORIES[2] || cat == CATEGORIES[3] {
        let mut chars = t.chars();
        chars.next();
        chars.as_str()
    } else {
        t
    }
}
