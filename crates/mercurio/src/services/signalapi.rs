//! Signal API (`signal://`, `signals://`): Signal messages through a signal-cli REST API server (bbernhard/signal-cli-rest-api).

use crate::convert::markup::{Markup, same};
use serde_json::{Value, json};

use crate::crypto::b64;
use crate::parse::{is_phone_no, parse_phone_no};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Error, NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "signalapi",
    name: "Signal API",
    schemes: &["signal", "signals"],
    service_url: "https://bbernhard.github.io/signal-cli-rest-api/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 32768, body_max_line_count: 0 },
    attachments: true,
    templates: &[
        "{schema}://{host}/{from_phone}",
        "{schema}://{host}:{port}/{from_phone}",
        "{schema}://{user}@{host}/{from_phone}",
        "{schema}://{user}@{host}:{port}/{from_phone}",
        "{schema}://{user}:{password}@{host}/{from_phone}",
        "{schema}://{user}:{password}@{host}:{port}/{from_phone}",
        "{schema}://{host}/{from_phone}/{targets}",
        "{schema}://{host}:{port}/{from_phone}/{targets}",
        "{schema}://{user}@{host}/{from_phone}/{targets}",
        "{schema}://{user}@{host}:{port}/{from_phone}/{targets}",
        "{schema}://{user}:{password}@{host}/{from_phone}/{targets}",
        "{schema}://{user}:{password}@{host}:{port}/{from_phone}/{targets}",
    ],
    tokens: &[
        Param::new("from_phone", "From Phone No").required().pattern(r"^\+?[0-9\s)(+-]+$"),
        Param::new("host", "Hostname").required(),
        Param::new("password", "Password").secret(),
        Param::new("port", "Port").int().range(1, 65535),
        Param::new("target_channel", "Target Group ID").pattern("^[a-z0-9_=-]+$").prefix("@"),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").group(&["target_channel", "target_phone"]),
        Param::new("user", "Username"),
    ],
    params: &[
        Param::new("batch", "Batch Mode").bool(false),
        Param::sets("from", &["from_phone"]),
        Param::new("status", "Show Status").bool(false),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const DEFAULT_BATCH_SIZE: usize = 10;

#[derive(Debug)]
struct SignalApi {
    url: String,
    user: Option<String>,
    password: Option<Secret>,
    source: String,
    targets: Vec<String>,
    batch: bool,
    status: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let source = match u.param_nonempty("from") {
        Some(f) => Some(unquote(f)),
        None if !targets.is_empty() => Some(targets.remove(0)),
        None => None,
    };
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_phone_no([to], true, false));
    }
    let batch = SERVICE.flag(u, "batch");
    let status = SERVICE.flag(u, "status");

    let source = source
        .as_deref()
        .and_then(|s| is_phone_no(s, 10))
        .map(|p| format!("+{}", p.full))
        .ok_or_else(|| SERVICE.err("an invalid Signal API source phone number was provided"))?;

    let group = crate::regex!(r"(?i)^\s*(?:(?:@|%40)?group\.|@|%40)([a-z0-9_=-]+)");
    let mut valid = Vec::new();
    if targets.is_empty() {
        valid.push(source.clone());
    } else {
        for t in parse_phone_no(&targets, true, false) {
            if let Some(p) = is_phone_no(&t, 10) {
                valid.push(format!("+{}", p.full));
            } else if let Some(c) = group.captures(&t) {
                valid.push(format!("group.{}", &c[1]));
            } else {
                log::warn!("Signal API: dropped an invalid phone/group");
            }
        }
    }

    let mut url = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = u.port {
        url.push_str(&format!(":{p}"));
    }
    url.push_str("/v2/send");

    Ok(Box::new(SignalApi {
        url,
        user: u.user().filter(|s| !s.is_empty()),
        password: u.password().map(Secret::new),
        source,
        targets: valid,
        batch,
        status,
    }))
}

/// signal-cli-rest-api styled text: `**bold**`, `*italic*`, `~strike~`, `` `code` `` and `label (url)` links; markup characters in text are backslash-escaped.
const SIGNAL: Markup = Markup {
    bold: ("**", "**"),
    italic: ("*", "*"),
    strike: ("~", "~"),
    code: ("`", "`"),
    code_block: ("`", "`"),
    heading_prefix: false,
    list_indent: "  ",
    link: crate::convert::markup::plain_link,
    escape: signal_escape,
    escape_code: same,
};

fn signal_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if "*`~|\\".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Markdown as Signal styled text.
pub fn commonmark_to_signal(body: &str) -> String {
    crate::convert::markup::render(body, &SIGNAL)
}

impl Notify for SignalApi {
    fn convert(&self, body: &str, format: NotifyFormat) -> Option<String> {
        (format == NotifyFormat::Markdown).then(|| commonmark_to_signal(body))
    }

    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Service("there were no Signal API targets to notify".into()));
        }
        let prefix = if self.status { format!("{} ", ctx.asset.ascii(msg.kind)) } else { String::new() };
        let message = format!("{prefix}{}", msg.body);
        let message = message.trim_end();
        let text_mode = if msg.format == NotifyFormat::Markdown { "styled" } else { "normal" };
        let mut payload = json!({
            "message": message,
            "number": self.source,
            "text_mode": text_mode,
            "recipients": [],
        });
        if !msg.attachments.is_empty() {
            payload["base64_attachments"] = Value::Array(msg.attachments.iter().map(|a| json!(b64(&a.data))).collect());
        }
        let batch_size = if self.batch { DEFAULT_BATCH_SIZE } else { 1 };
        Plan::all(self.targets.chunks(batch_size).map(|chunk| {
            let mut p = payload.clone();
            p["recipients"] = json!(chunk);
            let mut req = ctx.post(&self.url).json(&p);
            req = req.basic_auth_opt(self.user.as_deref(), self.password.as_ref().map(Secret::expose));
            Plan::send_expect(req, &[200, 201]).target(chunk.join(","))
        }))
    }

}
