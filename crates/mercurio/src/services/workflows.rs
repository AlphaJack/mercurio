//! Power Automate / Workflows for MS Teams (`workflow://`, `workflows://`): Adaptive Card messages through a workflow webhook.
//!
//! `?template=` reads a local JSON file when the message is sent, or downloads an `http(s)://` one before the first send and keeps it.

use serde_json::{Map, Value, json};

use super::_chat::{TemplateSrc, apply_template_json, read_template, template_fetches, template_files, template_source};
use crate::asset::ImageSize;
use crate::http::Request;
use crate::parse::validate_regex;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Error, FileOp, NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "workflows",
    name: "Power Automate / Workflows (for MSTeams)",
    schemes: &["workflow", "workflows"],
    service_url: "https://www.microsoft.com/power-platform/products/power-automate",
    parse,
    parse_native: Some(parse_native),
    limits: Limits { title_maxlen: 250, body_maxlen: 1000, body_max_line_count: 0 },
    formats: &[NotifyFormat::Markdown],
    templates: &[
        "{schema}://{host}/{workflow}/{signature}",
        "{schema}://{host}:{port}/{workflow}/{signature}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("port", "Port").port(),
        Param::new("signature", "Signature").required().secret().pattern("^[a-z0-9_-]+$"),
        Param::new("workflow", "Workflow ID").required().secret().pattern("^[A-Z0-9_-]+$"),
    ],
    params: &[
        Param::sets("id", &["workflow"]),
        Param::new("image", "Include Image").bool(true),
        Param::new("pa", "Use Power Automate URL").bool(false).aliases(&["powerautomate"]),
        Param::new("route", "Power Automate Routing ID").pattern("^[0-9]+$").aliases(&["routeid"]),
        Param::sets("sig", &["signature"]),
        Param::new("template", "Template Path").secret(),
        Param::new("ver", "API Version").aliases(&["api-version"]),
        Param::new("wrap", "Wrap Text").bool(true),
        Param::new("tokens", "Template Tokens").prefix(":"),
    ],
    ..ServiceDef::DEFAULTS
};

const MAX_TEMPLATE_SIZE: u64 = 35000;

#[derive(Debug)]
struct Workflows {
    host: String,
    port: Option<u16>,
    workflow: Secret,
    signature: Secret,
    include_image: bool,
    power_automate: bool,
    routing_id: Option<String>,
    wrap: bool,
    api_version: String,
    template: Option<TemplateSrc>,
    tokens: Vec<(String, String)>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let mut entries = u.path_segments().into_iter();
    let power_automate = match u.param("powerautomate").or_else(|| u.param("pa")) {
        Some(v) => crate::parse::parse_bool(v, false),
        None => false,
    };
    let routing_id = u.param_nonempty("route").or_else(|| u.param_nonempty("routeid")).map(unquote);
    let template = SERVICE.text(u, "template");
    let workflow = match u.param_nonempty("workflow").or_else(|| u.param_nonempty("id")) {
        Some(v) => Some(unquote(v)),
        None => entries.next().map(|e| unquote(&e)),
    };
    let signature = match u.param_nonempty("signature").or_else(|| u.param_nonempty("sig")) {
        Some(v) => Some(unquote(v)),
        None => entries.next().map(|e| unquote(&e)),
    };
    let version = u.param_nonempty("api-version").or_else(|| u.param_nonempty("ver")).map(unquote);

    let workflow = workflow
        .as_deref()
        .and_then(|w| validate_regex(w, r"^[A-Z0-9_-]+$", "i", true))
        .ok_or_else(|| SERVICE.err("an invalid Workflows ID was specified"))?;
    let signature = signature
        .as_deref()
        .and_then(|s| validate_regex(s, r"^[a-z0-9_-]+$", "i", true))
        .ok_or_else(|| SERVICE.err("an invalid Signature was specified"))?;
    let routing_id = match routing_id {
        Some(r) => Some(
            validate_regex(&r, r"^[0-9]+$", "", true)
                .ok_or_else(|| SERVICE.err("an invalid Workflows Routing ID was specified"))?,
        ),
        None => None,
    };
    let template = match template {
        Some(t) => Some(
            template_source(&t).ok_or_else(|| SERVICE.err("the Workflows template specified could not be loaded"))?,
        ),
        None => None,
    };
    let api_version =
        version.unwrap_or_else(|| if power_automate { "2022-03-01-preview".into() } else { "2016-06-01".into() });
    Ok(Box::new(Workflows {
        host: u.host(),
        port: u.port,
        workflow: Secret::new(workflow),
        signature: Secret::new(signature),
        include_image: SERVICE.flag_strict(u, "image"),
        power_automate,
        routing_id,
        wrap: SERVICE.flag_strict(u, "wrap"),
        api_version,
        template,
        tokens: u.query_colon.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
    }))
}

fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(
        r"(?i)^https?://(?P<host>[A-Z0-9_.-]+)(?P<port>:[1-9][0-9]{0,5})?(?P<pa>/powerautomate/automations/direct(?:/cu/(?P<routing_id>[0-9]+))?)?/workflows/(?P<workflow>[A-Z0-9_-]+)/triggers/manual/paths/invoke/?(?P<params>\?.+)\n?\z"
    );
    let c = re.captures(url)?;
    let mut out = format!(
        "workflow://{}{}/{}/{}{}",
        &c["host"],
        c.name("port").map_or("", |m| m.as_str()),
        &c["workflow"],
        &c["params"],
        if c.name("pa").is_some() { "&pa=yes" } else { "" }
    );
    if let Some(r) = c.name("routing_id") {
        // The id from the path overrides any `?route=`.
        out.push_str(&format!("&route={}", r.as_str()));
    }
    Some(out)
}

impl Workflows {
    fn default_payload(&self, msg: &Prepared<'_>, image: Option<String>) -> Value {
        let mut body = Vec::new();
        if let Some(url) = image {
            body.push(json!({"type": "Image", "url": url, "height": "32px", "altText": msg.kind.as_str()}));
        }
        if !msg.title.is_empty() {
            body.push(json!({
                "type": "TextBlock", "text": msg.title, "style": "heading",
                "weight": "Bolder", "size": "Large", "id": "title",
            }));
        }
        body.push(json!({"type": "TextBlock", "text": crate::http::TEXT, "style": "default", "wrap": self.wrap, "id": "body"}));

        let mut seen: Vec<String> = Vec::new();
        let mut entities = Vec::new();
        for c in crate::regex!(r"(?i)<at>([^<]+)</at>").captures_iter(msg.body) {
            let key = c[1].trim().to_string();
            if key.is_empty() || seen.contains(&key) {
                continue;
            }
            entities.push(json!({"type": "mention", "text": &c[0], "mentioned": {"id": key, "name": key}}));
            seen.push(key);
        }
        let mut msteams = Map::new();
        msteams.insert("width".into(), json!("full"));
        if !entities.is_empty() {
            msteams.insert("entities".into(), Value::Array(entities));
        }
        json!({
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": null,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body,
                    "msteams": msteams,
                },
            }],
        })
    }

    fn template_payload(
        &self,
        src: &TemplateSrc,
        msg: &Prepared<'_>,
        ctx: &Context<'_>,
        image: Option<String>,
    ) -> std::result::Result<Value, Error> {
        let fail = |why: &str| Error::Message(format!("Workflow template {why}"));
        let text = read_template(ctx, src, MAX_TEMPLATE_SIZE).ok_or_else(|| fail("could not be accessed"))?;
        let mut tokens = self.tokens.clone();
        let color = ctx.asset.color(msg.kind).to_string();
        for (k, v) in [
            ("app_body", msg.body.to_string()),
            ("app_title", msg.title.to_string()),
            ("app_type", msg.kind.as_str().to_string()),
            ("app_id", ctx.app_id().to_string()),
            ("app_desc", ctx.app_desc().to_string()),
            ("app_color", color.clone()),
            ("app_color_hex", color),
            ("app_image_url", image.unwrap_or_default()),
            ("app_url", ctx.app_url().to_string()),
        ] {
            tokens.retain(|(key, _)| key != k);
            tokens.push((k.to_string(), v));
        }
        let applied = apply_template_json(&text, &tokens).ok_or_else(|| fail("uses an unknown token"))?;
        let content: Value = serde_json::from_str(&applied).map_err(|_| fail("contains invalid JSON"))?;
        let obj = content.as_object().ok_or_else(|| fail("must be a JSON object"))?;
        if obj.get("type").and_then(Value::as_str) != Some("message") {
            return Err(fail("must have 'type': 'message'"));
        }
        let atts = obj.get("attachments").and_then(Value::as_array).filter(|a| !a.is_empty());
        let atts = atts.ok_or_else(|| fail("must contain a non-empty 'attachments' list"))?;
        if !atts.iter().all(|a| a.get("contentType").is_some_and(Value::is_string)) {
            return Err(fail("contains an attachment missing a 'contentType' string"));
        }
        Ok(content)
    }
}

impl Notify for Workflows {
    fn files(&self, _: &Context<'_>) -> Vec<FileOp> {
        template_files(self.template.as_ref())
    }

    fn fetches(&self, ctx: &Context<'_>) -> Vec<Request> {
        template_fetches(ctx, self.template.as_ref(), MAX_TEMPLATE_SIZE)
    }

    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let image = if self.include_image { ctx.asset.image_url(msg.kind, ImageSize::Xy32) } else { None };
        let payload = match &self.template {
            None => self.default_payload(msg, image),
            Some(src) => match self.template_payload(src, msg, ctx, image) {
                Ok(p) => p,
                Err(e) => return Plan::Fail(e),
            },
        };
        let mut path = String::new();
        if self.power_automate {
            path.push_str("/powerautomate/automations/direct");
            if let Some(r) = &self.routing_id {
                path.push_str(&format!("/cu/{r}"));
            }
        }
        let port = self.port.map(|p| format!(":{p}")).unwrap_or_default();
        let url = format!(
            "https://{}{port}{path}/workflows/{}/triggers/manual/paths/invoke",
            self.host,
            self.workflow.expose()
        );
        let req = Request::post(url)
            .query(&[
                ("api-version", self.api_version.as_str()),
                ("sp", "/triggers/manual/run"),
                ("sv", "1.0"),
                ("sig", self.signature.expose()),
            ])
            .header("User-Agent", ctx.app_id())
            .json_text(&payload, msg.body);
        Plan::send_expect(req, &[200, 202])
    }
}

#[cfg(test)]
#[expect(clippy::disallowed_methods, reason = "tests set up real files")]
mod tests {
    use crate::testing::FakeTransport;
    use crate::{Asset, Message};

    #[test]
    fn template_file() {
        let dir = std::env::temp_dir().join(format!("mercurio-wf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("card.json");
        std::fs::write(
            &path,
            r#"{"type": "message", "attachments": [{"contentType": "x", "content": {"t": "{{app_title}}", "b": "{{ app_body }}", "c": "{{custom}}", "u": "{{unknown}}"}}]}"#,
        )
        .unwrap();
        let url =
            format!("workflow://host/wf/sig?template={}&:custom=val", crate::url::quote(path.to_str().unwrap(), ""));
        let target = crate::parse(&url).unwrap();
        let fake = FakeTransport::new();
        let d = target.send(&Message::new("he said \"hi\"").title("T"), &fake, &Asset::default());
        assert!(d.is_success(), "{d:?}");
        let body: serde_json::Value = serde_json::from_slice(&fake.requests()[0].body).unwrap();
        let content = &body["attachments"][0]["content"];
        assert_eq!(content["t"], "T");
        assert_eq!(content["b"], "he said \"hi\"");
        assert_eq!(content["c"], "val");
        assert_eq!(content["u"], "{{unknown}}");

        // A case mismatch in a template placeholder fails the send.
        std::fs::write(&path, r#"{"type": "message", "attachments": [{"contentType": "x", "b": "{{APP_BODY}}"}]}"#)
            .unwrap();
        let fake = FakeTransport::new();
        assert!(!target.send(&Message::new("b"), &fake, &Asset::default()).is_success());
        assert!(fake.requests().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remote_template_is_downloaded_once() {
        let url = "workflow://host/wf/sig?template=http://tpl.example/card.json&:custom=val";
        let target = crate::parse(url).unwrap();
        let fake = FakeTransport::new();
        let card = r#"{"type": "message", "attachments": [{"contentType": "x", "text": "{{app_title}} {{custom}}"}]}"#;
        fake.on_url("tpl.example", crate::Response::new(200, card.as_bytes().to_vec()));
        fake.default_response(crate::Response::new(202, Vec::new()));
        for _ in 0..2 {
            let d = target.send(&Message::new("b").title("T"), &fake, &Asset::default());
            assert!(d.is_success(), "{d:?}");
        }
        let reqs = fake.requests();
        let downloads: Vec<_> = reqs.iter().filter(|r| r.url.contains("tpl.example")).collect();
        assert_eq!(downloads.len(), 1, "kept after the first send");
        assert_eq!(downloads[0].max_body, super::MAX_TEMPLATE_SIZE);
        let posted: Vec<_> = reqs.iter().filter(|r| r.url.contains("host")).collect();
        assert_eq!(posted.len(), 2);
        assert!(String::from_utf8_lossy(&posted[1].body).contains("T val"), "{posted:?}");

        // A template that cannot be downloaded fails the send.
        let target = crate::parse(url).unwrap();
        let fake = FakeTransport::new();
        fake.on_url("tpl.example", crate::Response::new(404, Vec::new()));
        assert!(!target.send(&Message::new("b"), &fake, &Asset::default()).is_success());
    }

}
