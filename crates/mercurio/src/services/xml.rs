//! XML webhook (`xml://`, `xmls://`): posts the notification as a SOAP/XML document to any HTTP endpoint.

use std::borrow::Cow;

use crate::crypto::b64;
use crate::http::Method;
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::services::_webhook::{double_unquoted, endpoint, parse_method};
use crate::url::ParsedUrl;
use crate::util::{escape_html, escape_html_into};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "xml",
    name: "XML",
    schemes: &["xml", "xmls"],
    parse,
    formats: &[NotifyFormat::Text, NotifyFormat::Html, NotifyFormat::Markdown],
    attachments: true,
    templates: &[
        "{schema}://{host}",
        "{schema}://{host}:{port}",
        "{schema}://{user}@{host}",
        "{schema}://{user}@{host}:{port}",
        "{schema}://{user}:{password}@{host}",
        "{schema}://{user}:{password}@{host}:{port}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("password", "Password").secret(),
        Param::new("port", "Port").port(),
        Param::new("user", "Username"),
    ],
    params: &[
        Param::new("method", "Fetch Method").choice(&["POST", "GET", "DELETE", "PUT", "HEAD", "PATCH", "UPDATE", "OPTIONS"]).default("POST"),
        Param::new("headers", "HTTP Header").prefix("+"),
        Param::new("params", "GET Params").prefix("-"),
        Param::new("payload", "Payload Extras").prefix(":"),
    ],
    ..ServiceDef::DEFAULTS
};

const FIELDS: [&str; 4] = ["Version", "Subject", "Message", "MessageType"];
const PAYLOAD_VERSION: &str = "1.1";
const TEMPLATE: &str = "<?xml version='1.0' encoding='utf-8'?>
<soapenv:Envelope
    xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">
    <soapenv:Body>
        <Notification>
            {{CORE}}
            {{ATTACHMENTS}}
       </Notification>
    </soapenv:Body>
</soapenv:Envelope>";

#[derive(Debug)]
struct Xml {
    url: String,
    method: Method,
    user: Option<String>,
    password: Option<Secret>,
    headers: Vec<(String, String)>,
    field_names: [String; 4],
    extras: Vec<(String, String)>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let mut field_names = FIELDS.map(str::to_string);
    let mut extras: Vec<(String, String)> = Vec::new();
    for (k, v) in double_unquoted(&u.query_colon) {
        let key: String = k.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect();
        if key.is_empty() {
            log::warn!("XML: ignoring invalid element name {k:?}");
            continue;
        }
        match FIELDS.iter().position(|f| *f == key) {
            Some(i) => field_names[i] = v,
            None => {
                extras.retain(|(ek, _)| *ek != key);
                extras.push((key, v));
            }
        }
    }
    Ok(Box::new(Xml {
        url: endpoint(u),
        method: parse_method(&SERVICE, u)?,
        user: u.user(),
        password: u.password().map(Secret::new),
        headers: double_unquoted(&u.query_plus),
        field_names,
        extras,
    }))
}

impl Notify for Xml {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        // Values stay unescaped and borrowed until they are written: the body is escaped straight into the payload, once.
        let values = [Cow::Borrowed(PAYLOAD_VERSION), Cow::Borrowed(msg.title), Cow::Borrowed(msg.body), Cow::Borrowed(msg.kind.as_str())];
        let mut base: Vec<(&str, Cow<'_, str>)> = Vec::new();
        for (name, value) in self.field_names.iter().zip(values) {
            if !name.is_empty() {
                base.retain(|(k, _)| k != name);
                base.push((name.as_str(), value));
            }
        }
        for (k, v) in &self.extras {
            base.retain(|(bk, _)| bk != k);
            base.push((k.as_str(), Cow::Borrowed(v.as_str())));
        }
        let (head, rest) = TEMPLATE.split_once("{{CORE}}").unwrap_or((TEMPLATE, ""));
        let (middle, tail) = rest.split_once("{{ATTACHMENTS}}").unwrap_or((rest, ""));
        let size: usize = base.iter().map(|(k, v)| 2 * k.len() + v.len() + 5).sum();
        let mut payload = String::with_capacity(TEMPLATE.len() + size + size / 8);
        payload.push_str(head);
        for (k, v) in &base {
            payload.push_str(&format!("<{k}>"));
            escape_html_into(&mut payload, v, false, false);
            payload.push_str(&format!("</{k}>"));
        }
        payload.push_str(middle);
        if !msg.attachments.is_empty() {
            payload.push_str("<Attachments format=\"base64\">");
            for (i, a) in msg.attachments.iter().enumerate() {
                let name = if a.name.is_empty() { format!("file{:03}.dat", i + 1) } else { a.name.clone() };
                payload.push_str(&format!(
                    "<Attachment filename=\"{}\" mimetype=\"{}\">{}</Attachment>",
                    escape_html(&name, false, false),
                    escape_html(&a.mime, false, false),
                    b64(&a.data)
                ));
            }
            payload.push_str("</Attachments>");
        }
        payload.push_str(tail);

        let mut req = ctx.request(self.method, &self.url)
            .header("Content-Type", "application/xml")
            .headers(self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .text(payload);
        req = req.basic_auth_opt(self.user.as_deref(), self.password.as_ref().map(Secret::expose));
        Plan::send(req)
    }
}
