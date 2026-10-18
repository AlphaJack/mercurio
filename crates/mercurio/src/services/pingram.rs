//! Pingram (`pingram://`): messages through the Pingram notification API.

use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::asset::ImageSize;
use crate::error::Error;
use crate::parse::{is_email, is_phone_no, parse_emails, parse_list, parse_list_unsorted, validate_regex};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "pingram",
    name: "Pingram",
    schemes: &["pingram"],
    service_url: "https://www.pingram.io/",
    parse,
    formats: &[NotifyFormat::Text, NotifyFormat::Html],
    throttle: Duration::from_millis(200),
    templates: &[
        "{schema}://{apikey}/{targets}",
        "{schema}://{type}@{apikey}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret().pattern(r"^pingram_(sk|pk)_[\w.-]+$"),
        Param::new("target_email", "Target Email").email(),
        Param::new("target_id", "Target ID").prefix("@"),
        Param::new("target_sms", "Target SMS"),
        Param::new("targets", "Targets").list("/").group(&["target_email", "target_id", "target_sms"]),
        Param::new("type", "Message Type").pattern("^[A-Z0-9_-]+$").note("defaults to the app id"),
    ],
    params: &[
        Param::sets("apikey", &["apikey"]),
        Param::new("bcc", "Blind Carbon Copy").list(", "),
        Param::new("cc", "Carbon Copy").list(", "),
        Param::new("channels", "Channels").list(", ").values(&["call", "email", "inapp", "mobile_push", "slack", "sms", "web_push"]),
        Param::new("from", "From Email"),
        Param::new("mode", "Mode").choice(&["message", "template"]),
        Param::new("region", "Region Name").choice(&["us", "ca", "eu"]).default("us"),
        Param::sets("to", &["targets"]),
        Param::sets("type", &["type"]),
        Param::new("tokens", "Template Tokens").prefix(":"),
    ],
    ..ServiceDef::DEFAULTS
};

const CHANNELS: &[&str] = &["email", "sms", "inapp", "web_push", "mobile_push", "slack", "call"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Template,
    Message,
}

/// One recipient: any of id / number / email.
#[derive(Debug, Clone, Default)]
struct Recipient {
    id: Option<String>,
    number: Option<String>,
    email: Option<String>,
}

impl Recipient {
    fn is_empty(&self) -> bool {
        self.id.is_none() && self.number.is_none() && self.email.is_none()
    }
    fn to_json(&self) -> Value {
        let mut m = Map::new();
        if let Some(v) = &self.email {
            m.insert("email".into(), json!(v));
        }
        if let Some(v) = &self.number {
            m.insert("number".into(), json!(v));
        }
        if let Some(v) = &self.id {
            m.insert("id".into(), json!(v));
        }
        Value::Object(m)
    }
    fn desc(&self) -> String {
        self.id.clone().or_else(|| self.number.clone()).or_else(|| self.email.clone()).unwrap_or_default()
    }
}

#[derive(Debug)]
struct Pingram {
    apikey: Secret,
    /// `None` sends the application id ([`Context::app_id`]).
    message_type: Option<String>,
    mode: Mode,
    base: &'static str,
    /// Insertion-ordered set.
    channels: Vec<String>,
    targets: Vec<Recipient>,
    /// `(email, name)` when `?from=` is a valid email.
    from: Option<(String, String)>,
    cc: Vec<String>,
    bcc: Vec<String>,
    tokens: Vec<(String, String)>,
}

fn add_unique(v: &mut Vec<String>, s: String) {
    if !v.contains(&s) {
        v.push(s);
    }
}

/// `^\s*(@|%40)?(?P<id>[\w_-]+)\s*$`
fn match_id(entry: &str) -> Option<String> {
    let re = crate::regex!(r"(?i)^\s*(?:@|%40)?([\w_-]+)\s*$");
    re.captures(entry).map(|c| c[1].to_string())
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets: Vec<String> = Vec::new();
    if !u.host.is_empty() {
        targets.push(u.host());
    }
    let from_addr = u.param_nonempty("from").map(|f| unquote(f.trim_end()));
    targets.extend(u.path_segments());
    let apikey = if let Some(k) = u.param_nonempty("apikey") {
        Some(unquote(k))
    } else if !targets.is_empty() {
        Some(targets.remove(0))
    } else {
        None
    };
    let region = SERVICE.text(u, "region");
    let channels = SERVICE.text(u, "channels");
    let mode = SERVICE.text(u, "mode");
    let message_type = if let Some(t) = u.param_nonempty("type") {
        Some(unquote(t))
    } else {
        u.user.as_deref().filter(|s| !s.is_empty()).map(unquote)
    };
    if let Some(to) = u.param_nonempty("to") {
        targets.push(unquote(to));
    }
    let cc = SERVICE.text(u, "cc");
    let bcc = SERVICE.text(u, "bcc");
    let tokens: Vec<(String, String)> = u.query_colon.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();

    let apikey = apikey
        .as_deref()
        .and_then(|k| validate_regex(k, r"^pingram_(sk|pk)_[\w.-]+$", "i", true))
        .ok_or_else(|| SERVICE.err("an invalid Pingram API Key was specified"))?;

    let mut from = None;
    if let Some(f) = &from_addr
        && let Some(r) = is_email(f)
    {
        let name = if r.name.is_empty() { None } else { Some(r.name.clone()) };
        from = Some((r.full_email.clone(), name));
    }

    let mode = match mode.as_deref().filter(|m| !m.is_empty()) {
        Some(m) => {
            if "template".starts_with(m) {
                Mode::Template
            } else if "message".starts_with(m) {
                Mode::Message
            } else {
                return Err(SERVICE.err("the Pingram mode specified is invalid"));
            }
        }
        None => {
            if message_type.as_deref().is_none_or(str::is_empty) {
                Mode::Message
            } else {
                Mode::Template
            }
        }
    };

    let message_type = match message_type.as_deref().filter(|m| !m.is_empty()) {
        None => None,
        Some(t) => Some(
            validate_regex(t, r"^[A-Z0-9_-]+$", "i", true)
                .ok_or_else(|| SERVICE.err("an invalid Pingram Message Type was specified"))?,
        ),
    };

    let base = match region.as_deref().map(str::to_lowercase).as_deref() {
        None | Some("us") => "https://api.pingram.io",
        Some("ca") => "https://api.ca.pingram.io",
        Some("eu") => "https://api.eu.pingram.io",
        Some(_) => return Err(SERVICE.err("the Pingram region specified is invalid")),
    };

    let mut chans: Vec<String> = Vec::new();
    for c in parse_list(channels.iter()) {
        let c = c.to_lowercase();
        if !CHANNELS.contains(&c.as_str()) {
            return Err(SERVICE.err("the Pingram forced channel specified is invalid"));
        }
        add_unique(&mut chans, c);
    }

    let mut recipients = Vec::new();
    let mut cur = Recipient::default();
    for entry in parse_list_unsorted(targets.iter()) {
        if let Some(r) = is_email(&entry) {
            if cur.email.is_none() {
                cur.email = Some(r.full_email);
                if chans.is_empty() {
                    chans.push("email".into());
                }
            } else {
                recipients.push(std::mem::take(&mut cur));
                cur.email = Some(r.full_email);
            }
            continue;
        }
        if let Some(r) = is_phone_no(&entry, 10) {
            if cur.number.is_none() {
                let plus = if entry.starts_with('+') { "+" } else { "" };
                cur.number = Some(format!("{plus}{}", r.full));
                if chans.is_empty() {
                    chans.push("sms".into());
                }
            } else {
                recipients.push(std::mem::take(&mut cur));
                cur.number = Some(r.full);
            }
            continue;
        }
        if let Some(id) = match_id(&entry) {
            if cur.id.is_none() {
                cur.id = Some(id);
            } else {
                recipients.push(std::mem::take(&mut cur));
                cur.id = Some(id);
            }
            continue;
        }
        log::warn!("Pingram: dropped an invalid target");
    }
    if !cur.is_empty() {
        recipients.push(cur);
    }

    let collect = |s: Option<&String>| {
        let mut out = Vec::new();
        for r in parse_emails(s.iter(), true) {
            if let Some(e) = is_email(&r) {
                add_unique(&mut out, e.full_email);
            }
        }
        out
    };
    let cc = collect(cc.as_ref());
    let bcc = collect(bcc.as_ref());

    Ok(Box::new(Pingram {
        apikey: Secret::new(apikey),
        message_type,
        mode,
        base,
        channels: chans,
        targets: recipients,
        from: from.map(|(e, n)| (e, n.unwrap_or_default())),
        cc,
        bcc,
        tokens,
    }))
}

impl Pingram {
    fn payload(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Map<String, Value> {
        let mut p = Map::new();
        p.insert("type".into(), json!(self.message_type.as_deref().unwrap_or(ctx.app_id())));
        let title = msg.title;
        let image = ctx.asset.image_url(msg.kind, ImageSize::Xy72);
        let title_or_app = if title.is_empty() { ctx.app_id() } else { title };
        if self.mode == Mode::Template {
            let mut params = Map::new();
            for (k, v) in &self.tokens {
                params.insert(k.clone(), json!(v));
            }
            params.insert("appBody".into(), json!(msg.body));
            params.insert("appTitle".into(), json!(title));
            params.insert("appType".into(), json!(msg.kind.as_str()));
            params.insert("appId".into(), json!(ctx.app_id()));
            params.insert("appDescription".into(), json!(ctx.app_desc()));
            params.insert("appColor".into(), json!(ctx.asset.color(msg.kind)));
            params.insert("appImageUrl".into(), json!(image));
            params.insert("appUrl".into(), json!(ctx.app_url()));
            p.insert("parameters".into(), Value::Object(params));
        } else {
            // SMS and calls need text: derive it from an HTML body.
            let text_owned =
                if msg.format == NotifyFormat::Html { crate::convert::html_to_text(msg.body) } else { msg.body.to_string() };
            let text_body = text_owned.as_str();
            let joined = if title.is_empty() { text_body.to_string() } else { format!("{title}\n{text_body}") };
            for ch in &self.channels {
                let v = match ch.as_str() {
                    "sms" | "call" => json!({"message": joined}),
                    "email" => {
                        let html = if msg.format != NotifyFormat::Html {
                            crate::convert::text_to_html(msg.body)
                        } else {
                            msg.body.to_string()
                        };
                        let mut e = json!({"subject": title_or_app, "html": html});
                        if let Some((addr, name)) = &self.from {
                            e["senderEmail"] = json!(addr);
                            e["senderName"] = json!(sender_name(name, ctx));
                        }
                        e
                    }
                    "inapp" => json!({"title": title_or_app, "image": image}),
                    "web_push" => json!({"title": title_or_app, "message": text_body, "icon": image}),
                    "mobile_push" => json!({"title": title_or_app, "message": text_body}),
                    _ => json!({"text": joined}),
                };
                p.insert(ch.clone(), v);
            }
        }
        if let Some((addr, name)) = &self.from {
            p.insert("options".into(), json!({"email": {"fromAddress": addr, "fromName": sender_name(name, ctx)}}));
        } else if !self.cc.is_empty() || !self.bcc.is_empty() {
            p.insert("options".into(), json!({"email": {}}));
        }
        p
    }
}

fn sender_name<'a>(name: &'a str, ctx: &'a Context<'_>) -> &'a str {
    if name.is_empty() { ctx.app_id() } else { name }
}

impl Notify for Pingram {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Service("there are no Pingram recipients to notify".into()));
        }
        let base = self.payload(msg, ctx);
        let url = format!("{}/send", self.base);
        Plan::all(self.targets.iter().map(|t| {
            let mut payload = base.clone();
            let (cc, bcc): (Vec<&String>, Vec<&String>) = match &t.email {
                Some(e) => (
                    self.cc.iter().filter(|c| !self.bcc.contains(c) && *c != e).collect(),
                    self.bcc.iter().filter(|c| *c != e).collect(),
                ),
                None => (self.cc.iter().collect(), self.bcc.iter().collect()),
            };
            payload.insert("to".into(), t.to_json());
            if let Some(Value::Object(opts)) = payload.get_mut("options")
                && let Some(Value::Object(email)) = opts.get_mut("email")
            {
                if !cc.is_empty() {
                    email.insert("ccAddresses".into(), json!(cc));
                }
                if !bcc.is_empty() {
                    email.insert("bccAddresses".into(), json!(bcc));
                }
            }
            let req = ctx.post(&url)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", self.apikey.expose()))
                .json(&Value::Object(payload));
            Plan::send_check(req, |r| {
                if r.json().is_none() {
                    return Err(Error::Service("invalid response from Pingram server".into()));
                }
                if r.status == 200 || r.status == 202 {
                    Ok(())
                } else {
                    Err(r.http_error())
                }
            })
            .target(t.desc())
        }))
    }

}

#[cfg(test)]
mod tests {
    use super::match_id;

    #[test]
    fn ids_accept_non_ascii_input() {
        assert_eq!(match_id("jörg").as_deref(), Some("jörg"));
        assert_eq!(match_id("\u{A0}@bob\u{2003}").as_deref(), Some("bob"));
        assert_eq!(match_id("user\u{663}").as_deref(), Some("user\u{663}"));
        assert_eq!(match_id("a b"), None);
    }
}
