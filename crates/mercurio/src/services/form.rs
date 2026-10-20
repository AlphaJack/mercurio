//! Form webhook (`form://`, `forms://`): posts the notification as form fields (or multipart with attachments) to any HTTP endpoint.

use crate::http::Method;
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::services::_webhook::{double_unquoted, endpoint, parse_method};
use crate::url::ParsedUrl;
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "form",
    name: "Form",
    schemes: &["form", "forms"],
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
        Param::new("attach-as", "Attach File As").default("file*"),
        Param::new("method", "Fetch Method").choice(&["POST", "GET", "DELETE", "PUT", "HEAD", "PATCH", "UPDATE", "OPTIONS"]).default("POST"),
        Param::new("headers", "HTTP Header").prefix("+"),
        Param::new("params", "GET Params").prefix("-"),
        Param::new("payload", "Payload Extras").prefix(":"),
    ],
    ..ServiceDef::DEFAULTS
};

const FIELDS: [&str; 4] = ["version", "title", "message", "type"];

#[derive(Debug)]
struct Form {
    url: String,
    method: Method,
    user: Option<String>,
    password: Option<Secret>,
    headers: Vec<(String, String)>,
    params: Vec<(String, String)>,
    /// Output name for each of [`FIELDS`]; empty drops the field.
    field_names: [String; 4],
    extras: Vec<(String, String)>,
    /// Attachment field name; `{}` is replaced by the 1-based index.
    attach_as: String,
    attach_multi: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let mut field_names = FIELDS.map(str::to_string);
    let mut extras = Vec::new();
    for (k, v) in double_unquoted(&u.query_colon) {
        match FIELDS.iter().position(|f| *f == k) {
            Some(i) => field_names[i] = v,
            None => {
                extras.retain(|(ek, _): &(String, String)| *ek != k);
                extras.push((k, v));
            }
        }
    }
    let (attach_as, attach_multi) = match u.param_nonempty("attach-as") {
        None => ("file{}".to_string(), true),
        Some(spec) => parse_attach_as(spec.trim()).ok_or_else(|| SERVICE.err(format!("invalid attach-as {spec:?}")))?,
    };
    Ok(Box::new(Form {
        url: endpoint(u),
        method: parse_method(&SERVICE, u)?,
        user: u.user(),
        password: u.password().map(Secret::new),
        headers: double_unquoted(&u.query_plus),
        params: double_unquoted(&u.query_minus),
        field_names,
        extras,
        attach_as,
        attach_multi,
    }))
}

/// The `attach-as` grammar: `name`, `name*` (numbered) or `pre*post`.
fn parse_attach_as(spec: &str) -> Option<(String, bool)> {
    let re = crate::regex!(
        r"(?i)^(?:(?P<match1>(?P<id1a>[a-z0-9_-]+)?(?P<wc1>[*?+$:.%]+)(?P<id1b>[a-z0-9_-]+))|(?P<match2>(?P<id2>[a-z0-9_-]+)(?P<wc2>[*?+$:.%]?)))"
    );
    let c = re.captures(spec)?;
    if c.name("match1").is_some() {
        let pre = c.name("id1a").map(|m| m.as_str()).unwrap_or("");
        Some((format!("{pre}{{}}{}", &c["id1b"]), true))
    } else {
        let id = &c["id2"];
        if c.name("wc2").is_some_and(|m| !m.as_str().is_empty()) { Some((format!("{id}{{}}"), true)) } else { Some((id.to_string(), false)) }
    }
}

impl Notify for Form {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let values = ["1.0", msg.title, msg.body, msg.kind.as_str()];
        let mut payload: Vec<(String, String)> = Vec::new();
        for (name, value) in self.field_names.iter().zip(values) {
            if !name.is_empty() {
                payload.retain(|(k, _)| k != name);
                payload.push((name.clone(), value.to_string()));
            }
        }
        for (k, v) in &self.extras {
            payload.retain(|(pk, _)| pk != k);
            payload.push((k.clone(), v.clone()));
        }

        let mut req = ctx.request(self.method, &self.url)
            .headers(self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        if self.method == Method::Get {
            for (k, v) in &self.params {
                payload.retain(|(pk, _)| pk != k);
                payload.push((k.clone(), v.clone()));
            }
            req = req.query(&payload);
        } else {
            req = req.query(&self.params);
            if msg.attachments.is_empty() {
                req = req.form(&payload);
            } else {
                let mut form = ctx.multipart();
                for (k, v) in &payload {
                    form = form.text(k, v);
                }
                for (i, a) in msg.attachments.iter().enumerate() {
                    let n = i + 1;
                    let field = if self.attach_multi { self.attach_as.replace("{}", &format!("{n:02}")) } else { self.attach_as.clone() };
                    let name = if a.name.is_empty() { format!("file{n:03}.dat") } else { a.name.clone() };
                    form = form.file(field, name, &a.mime, a.data.clone());
                }
                req = req.multipart(form);
            }
        }
        req = req.basic_auth_opt(self.user.as_deref(), self.password.as_ref().map(Secret::expose));
        Plan::send(req)
    }
}
