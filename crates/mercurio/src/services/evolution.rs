//! Evolution API (`evolution://`, `evolutions://`): WhatsApp messages through an Evolution API server.

use crate::convert::markup::{Markup, same};
use serde_json::json;

use crate::parse::{is_phone_no, parse_phone_no, parse_phone_no_unquoted, validate_nonblank};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "evolution",
    name: "Evolution API",
    schemes: &["evolution", "evolutions"],
    service_url: "https://github.com/EvolutionAPI/evolution-api",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 32768, body_max_line_count: 0 },
    formats: &[NotifyFormat::Markdown],
    templates: &[
        "{schema}://{apikey}@{host}/{instance}/{targets}",
        "{schema}://{apikey}@{host}:{port}/{instance}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret(),
        Param::new("host", "Hostname").required(),
        Param::new("instance", "Instance Name").required(),
        Param::new("port", "Port").port(),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").group(&["target_phone"]),
    ],
    params: &[
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Evolution {
    url: String,
    apikey: Secret,
    phone: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let apikey = u
        .user
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|k| validate_nonblank(&unquote(k)))
        .ok_or_else(|| SERVICE.err("an invalid Evolution API key was specified"))?;
    let mut entries = u.path_segments();
    let instance = if entries.is_empty() { None } else { Some(unquote(&entries.remove(0))) };
    let instance = instance
        .and_then(|i| validate_nonblank(&i))
        .ok_or_else(|| SERVICE.err("an invalid Evolution API instance name was specified"))?;
    if let Some(to) = u.param_nonempty("to") {
        entries.extend(parse_phone_no_unquoted([to], false));
    }
    let phone: Vec<String> =
        parse_phone_no(&entries, true, false).iter().filter_map(|t| is_phone_no(t, 10)).map(|p| p.full).collect();
    if phone.is_empty() {
        return Err(SERVICE.err("no valid Evolution API phone numbers were specified"));
    }
    let default_port = if u.secure { 443 } else { 80 };
    let port = u.port.filter(|p| *p != 0 && *p != default_port).map(|p| format!(":{p}")).unwrap_or_default();
    let url = format!("{}://{}{}/message/sendText/{}", u.http_scheme(), u.host(), port, instance);
    Ok(Box::new(Evolution { url, apikey: Secret::new(apikey), phone }))
}

/// WhatsApp formatting: `*bold*`, `_italic_`, `~strike~`, triple-backtick code and `label (url)` links.
const WHATSAPP: Markup = Markup {
    bold: ("*", "*"),
    italic: ("_", "_"),
    strike: ("~", "~"),
    code: ("```", "```"),
    code_block: ("```\n", "```"),
    heading_prefix: false,
    list_indent: "  ",
    link: crate::convert::markup::plain_link,
    escape: same,
    escape_code: same,
};

/// Markdown as WhatsApp text.
pub fn commonmark_to_whatsapp(body: &str) -> String {
    crate::convert::markup::render(body, &WHATSAPP)
}

impl Notify for Evolution {
    fn convert(&self, body: &str, format: NotifyFormat) -> Option<String> {
        (format == NotifyFormat::Markdown).then(|| commonmark_to_whatsapp(body))
    }

    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        Plan::all(self.phone.iter().map(|number| {
            let req = ctx
                .post(&self.url)
                .header("Content-Type", "application/json")
                .header("apikey", self.apikey.expose())
                .json_text(&json!({"number": number, "text": crate::http::TEXT}), msg.body);
            Plan::send_expect(req, &[200, 201]).target(number.clone())
        }))
    }

}
