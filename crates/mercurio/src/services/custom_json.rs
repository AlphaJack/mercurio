//! JSON webhook (`json://`, `jsons://`): posts the notification as a JSON object to any HTTP endpoint.

use crate::http::Method;
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "custom_json",
    name: "JSON",
    schemes: &["json", "jsons"],
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
        Param::new("port", "Port").int().range(1, 65535),
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

/// Methods accepted by the JSON, form and XML webhooks.
pub(crate) fn parse_method(def: &'static ServiceDef, u: &ParsedUrl) -> Result<Method> {
    match u.param_nonempty("method") {
        None => Ok(Method::Post),
        Some(m) => Method::parse(&unquote(m)).ok_or_else(|| def.err(format!("invalid method {m:?}"))),
    }
}

/// `{scheme}://{host}[:port]{fullpath}` with the raw (still quoted) path.
pub(crate) fn endpoint(u: &ParsedUrl) -> String {
    let mut url = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = u.port {
        url.push_str(&format!(":{p}"));
    }
    url.push_str(u.fullpath.as_deref().unwrap_or(""));
    url
}

/// `+`, `-` and `:` entries, unquoted a second time.
pub(crate) fn double_unquoted(p: &crate::url::Pairs) -> Vec<(String, String)> {
    p.iter().map(|(k, v)| (unquote(k), unquote(v))).collect()
}

#[derive(Debug)]
struct Json {
    url: String,
    method: Method,
    user: Option<String>,
    password: Option<Secret>,
    headers: Vec<(String, String)>,
    params: Vec<(String, String)>,
    payload: Vec<(String, String)>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    Ok(Box::new(Json {
        url: endpoint(u),
        method: parse_method(&SERVICE, u)?,
        user: u.user(),
        password: u.password().map(Secret::new),
        headers: double_unquoted(&u.query_plus),
        params: double_unquoted(&u.query_minus),
        payload: double_unquoted(&u.query_colon),
    }))
}

impl Notify for Json {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut req = ctx.request(self.method, &self.url)
            .header("Content-Type", "application/json")
            .headers(self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .query(&self.params)
            .body(super::_json::encode(super::_json::object(msg), &self.payload), None);
        req = req.basic_auth_opt(self.user.as_deref(), self.password.as_ref().map(Secret::expose));
        Plan::send(req)
    }
}
