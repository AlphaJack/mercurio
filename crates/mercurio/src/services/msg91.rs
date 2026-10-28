//! MSG91 flows (`msg91://`): SMS through MSG91 flow templates.

use serde_json::{Map, Value, json};

use super::_sms::{expect, full_numbers, no_targets, to_param};
use crate::parse::validate_regex;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "msg91",
    name: "MSG91",
    schemes: &["msg91"],
    service_url: "https://msg91.com",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    templates: &[
        "{schema}://{template}@{authkey}/{targets}",
    ],
    tokens: &[
        Param::new("authkey", "Authentication Key").required().secret().pattern("^[a-z0-9]+$"),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").required().group(&["target_phone"]),
        Param::new("template", "Template ID").required().secret().pattern("^[a-z0-9 _-]+$"),
    ],
    params: &[
        Param::new("short_url", "Short URL").bool(false),
        Param::sets("to", &["targets"]),
        Param::new("template_mapping", "Template Mapping").prefix(":"),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Msg91 {
    template: Secret,
    authkey: Secret,
    short_url: bool,
    targets: Vec<String>,
    mapping: Vec<(String, String)>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let authkey = u.host();
    let template = u.user().unwrap_or_default();
    let short_url = SERVICE.flag(u, "short_url");
    targets.extend(to_param(u));
    // Later duplicates overwrite earlier values in place.
    let mut mapping: Vec<(String, String)> = Vec::new();
    for (k, v) in u.query_colon.iter() {
        let (k, v) = (unquote(k), unquote(v));
        match mapping.iter_mut().find(|(ek, _)| *ek == k) {
            Some(e) => e.1 = v,
            None => mapping.push((k, v)),
        }
    }

    let authkey = validate_regex(&authkey, r"^[a-z0-9]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid MSG91 Authentication Key was specified"))?;
    let template = validate_regex(&template, r"^[a-z0-9 _-]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid MSG91 Template ID was specified"))?;
    Ok(Box::new(Msg91 {
        template: Secret::new(template),
        authkey: Secret::new(authkey),
        short_url,
        targets: full_numbers(&targets),
        mapping,
    }))
}

impl Notify for Msg91 {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return no_targets("MSG91");
        }
        let mut recipient = Map::new();
        recipient.insert("mobiles".into(), Value::Null);
        recipient.insert("body".into(), json!(crate::http::TEXT));
        recipient.insert("type".into(), json!(msg.kind.as_str()));
        for (key, value) in &self.mapping {
            if key == "mobiles" {
                continue;
            }
            // `payload[value] = payload[key]; del payload[key]` drops the key when both match.
            if let Some(v) = recipient.remove(key) {
                if !value.is_empty() && value != key {
                    recipient.insert(value.clone(), v);
                }
            } else {
                recipient.insert(key.clone(), json!(value));
            }
        }
        let recipients: Vec<Value> = self
            .targets
            .iter()
            .map(|t| {
                let mut r = recipient.clone();
                r.insert("mobiles".into(), json!(t));
                Value::Object(r)
            })
            .collect();
        let payload = json!({
            "template_id": self.template.expose(),
            "short_url": if self.short_url { 1 } else { 0 },
            "recipients": recipients,
        });
        let req = ctx.post("https://control.msg91.com/api/v5/flow/")
            .header("authkey", self.authkey.expose())
            .json_text(&payload, msg.body);
        Plan::send_check(req, |r| expect(r, &[200]))
    }

}
