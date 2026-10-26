//! WhatsApp Cloud API (`whatsapp://`): messages to WhatsApp numbers.

use std::time::Duration;

use serde_json::{Value, json};

use crate::error::Error;
use crate::http::Response;
use crate::parse::{is_phone_no, parse_phone_no, parse_phone_no_unquoted, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "whatsapp",
    name: "WhatsApp",
    schemes: &["whatsapp"],
    service_url: "https://developers.facebook.com/docs/whatsapp/cloud-api/get-started",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 1024, body_max_line_count: 0 },
    throttle: Duration::from_millis(200),
    templates: &[
        "{schema}://{token}@{from_phone_id}/{targets}",
        "{schema}://{template}:{token}@{from_phone_id}/{targets}",
    ],
    tokens: &[
        Param::new("from_phone_id", "From Phone ID").required().secret().pattern("^[0-9]+$"),
        Param::new("language", "Language").default("en_US").pattern(r"^[^0-9\s]+$"),
        Param::new("target_group", "Target Group ID").pattern("^[0-9]{16,}$").prefix("#"),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").required().group(&["target_group", "target_phone"]),
        Param::new("template", "Template Name").pattern(r"^[^\s]+$"),
        Param::new("token", "Access Token").required().secret().pattern("^[a-z0-9]+$"),
    ],
    params: &[
        Param::sets("from", &["from_phone_id"]).aliases(&["source"]),
        Param::sets("lang", &["language"]),
        Param::sets("template", &["template"]),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
        Param::new("template_mapping", "Template Mapping").prefix(":"),
    ],
    ..ServiceDef::DEFAULTS
};

const FB_GRAPH_VERSION: &str = "v26.0";

/// A template body parameter: fixed text or the message body / notify type.
#[derive(Debug, Clone)]
enum Component {
    Text(String),
    Body,
    Type,
}

#[derive(Debug)]
struct WhatsApp {
    token: Secret,
    from_phone_id: String,
    /// `(name, language)`.
    template: Option<(String, String)>,
    targets: Vec<String>,
    components: Vec<Component>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let mut from_phone_id = u.host();
    let mut template = None;
    let mut token = if u.password.is_some() {
        template = Some(u.user.as_deref().map(unquote).unwrap_or_default());
        u.password.as_deref().map(unquote).unwrap_or_default()
    } else {
        u.user.as_deref().map(unquote).unwrap_or_default()
    };
    if let Some(t) = u.param_nonempty("token") {
        token = unquote(t);
    }
    if let Some(t) = u.param_nonempty("template") {
        template = Some(t.to_string());
    }
    let mut language = u.param_nonempty("lang").map(str::to_string);
    if let Some(l) = u.param_nonempty("language") {
        language = Some(l.to_string());
    }
    if let Some(f) = u.param_nonempty("from") {
        from_phone_id = unquote(f);
    }
    if let Some(f) = u.param_nonempty("source") {
        from_phone_id = unquote(f);
    }
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_phone_no_unquoted([to], false));
    }
    let mut mapping: Vec<(String, String)> = Vec::new();
    for (k, v) in u.query_colon.iter() {
        let (k, v) = (unquote(k), unquote(v));
        match mapping.iter_mut().find(|(x, _)| *x == k) {
            Some(slot) => slot.1 = v,
            None => mapping.push((k, v)),
        }
    }

    let token = validate_regex(&token, r"^[a-z0-9]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid WhatsApp Access Token was specified"))?;
    let from_phone_id = validate_regex(&from_phone_id, r"^[0-9]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid WhatsApp From Phone ID was specified"))?;
    let template = match template.filter(|t| !t.is_empty()) {
        None => None,
        Some(t) => {
            let name = validate_regex(&t, r"^[^\s]+$", "i", true)
                .ok_or_else(|| SERVICE.err("an invalid WhatsApp Template Name was specified"))?;
            let lang = match language.filter(|l| !l.is_empty()) {
                Some(l) => validate_regex(&l, r"^[^0-9\s]+$", "i", true)
                    .ok_or_else(|| SERVICE.err("an invalid WhatsApp Template Language Code was specified"))?,
                None => "en_US".to_string(),
            };
            Some((name, lang))
        }
    };

    let group_suffix = crate::regex!(r"(?i)@g\.us$");
    let group_re = crate::regex!(r"^[0-9]{16,}$");
    let mut out = Vec::new();
    for target in parse_phone_no(targets, true, false) {
        if let Some(p) = is_phone_no(&target, 11) {
            out.push(format!("+{}", p.full));
            continue;
        }
        let gid = group_suffix.replace(&target, "");
        let gid = gid.trim().trim_start_matches('#');
        if group_re.is_match(gid) {
            out.push(format!("#{gid}"));
            continue;
        }
        crate::warning!("WhatsApp: dropped invalid target specified");
    }

    // `:key=value` template component mapping (insertion ordered by index key).
    let key_re = crate::regex!(r"(?i)^(?:(?P<id>[1-9][0-9]*)|(?P<map>body|type))");
    let mut components: Vec<(String, Component)> = Vec::new();
    for (key, val) in mapping {
        let caps =
            key_re.captures(&key).ok_or_else(|| SERVICE.err("an invalid Template Component ID was specified"))?;
        let (index, comp) = if let Some(id) = caps.name("id") {
            (id.as_str().to_string(), Component::Text(val))
        } else {
            let comp = if caps["map"].eq_ignore_ascii_case("body") { Component::Body } else { Component::Type };
            let id = key_re
                .captures(&val)
                .and_then(|c| c.name("id").map(|m| m.as_str().to_string()))
                .ok_or_else(|| SERVICE.err("an invalid Template Component Mapping was specified"))?;
            (id, comp)
        };
        if components.iter().any(|(i, _)| *i == index) {
            return Err(SERVICE.err("the Template Component index was already assigned"));
        }
        components.push((index, comp));
    }

    Ok(Box::new(WhatsApp {
        token: Secret::new(token),
        from_phone_id,
        template,
        targets: out,
        components: components.into_iter().map(|(_, c)| c).collect(),
    }))
}

fn check(r: &Response) -> Result<()> {
    if r.status == 200 || r.status == 201 {
        return Ok(());
    }
    let msg = r
        .json()
        .and_then(|v| v.get("error").and_then(|e| e.get("message")).and_then(Value::as_str).map(str::to_string));
    Err(r.http_error_with(msg.unwrap_or_else(|| r.snippet())))
}

impl Notify for WhatsApp {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Service("there are no valid WhatsApp targets to notify".into()));
        }
        let url = format!("https://graph.facebook.com/{FB_GRAPH_VERSION}/{}/messages", self.from_phone_id);
        let mut payload = json!({"messaging_product": "whatsapp", "to": null});
        match &self.template {
            None => {
                payload["recipient_type"] = json!("individual");
                payload["type"] = json!("text");
                payload["text"] = json!({"body": crate::http::TEXT});
            }
            Some((name, lang)) => {
                payload["type"] = json!("template");
                payload["template"] = json!({"name": name, "language": {"code": lang}});
                if !self.components.is_empty() {
                    let params: Vec<Value> = self
                        .components
                        .iter()
                        .map(|c| match c {
                            Component::Text(t) => json!({"type": "text", "text": t}),
                            Component::Body => json!({"type": "text", "text": crate::http::TEXT}),
                            Component::Type => json!({"type": "text", "text": msg.kind.as_str()}),
                        })
                        .collect();
                    payload["template"]["components"] = json!([{"type": "body", "parameters": params}]);
                }
            }
        }
        Plan::all(self.targets.iter().map(|target| {
            let mut p = payload.clone();
            if let Some(gid) = target.strip_prefix('#') {
                p["to"] = json!(format!("{gid}@g.us"));
                p["recipient_type"] = json!("group");
            } else {
                p["to"] = json!(target);
                p["recipient_type"] = json!("individual");
            }
            let req = ctx.post(&url)
                .header("Accept", "application/json")
                .bearer(self.token.expose())
                .json_text(&p, msg.body);
            Plan::send_check(req, check).target(target.clone())
        }))
    }

}
