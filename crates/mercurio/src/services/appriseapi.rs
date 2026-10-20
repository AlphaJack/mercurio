//! Apprise API relay (`apprise://`, `apprises://`): hands the notification to an Apprise API server, which delivers it to its configured services.

use std::time::Duration;

use serde_json::{Value, json};

use crate::util::unquoted_pairs;
use crate::crypto::b64;
use crate::http::{DEFAULT_CONNECT_TIMEOUT, Multipart, Request};
use crate::parse::{parse_list, validate_regex};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, quote, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "appriseapi",
    name: "Apprise API",
    schemes: &["apprise", "apprises"],
    service_url: "https://github.com/caronc/apprise-api",
    parse,
    parse_native: Some(parse_native),
    formats: &[NotifyFormat::Text, NotifyFormat::Html, NotifyFormat::Markdown],
    attachments: true,
    templates: &[
        "{schema}://{host}/{token}",
        "{schema}://{host}:{port}/{token}",
        "{schema}://:{password}@{host}/{token}",
        "{schema}://:{password}@{host}:{port}/{token}",
        "{schema}://{user}@{host}/{token}",
        "{schema}://{user}@{host}:{port}/{token}",
        "{schema}://{user}:{password}@{host}/{token}",
        "{schema}://{user}:{password}@{host}:{port}/{token}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("password", "Password").secret(),
        Param::new("port", "Port").port(),
        Param::new("token", "Token").required().secret().pattern("^[A-Z0-9_-]{1,128}$"),
        Param::new("user", "Username"),
    ],
    params: &[
        Param::new("method", "Query Method").choice(&["form", "json"]).default("form"),
        Param::new("tags", "Tags"),
        Param::sets("to", &["token"]),
        Param::new("version", "API Version").choice(&["1", "2"]).default("2").aliases(&["v"]),
        Param::new("headers", "HTTP Header").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

const READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct AppriseApi {
    url: String,
    token: Secret,
    json: bool,
    v1: bool,
    tags: Vec<String>,
    headers: Vec<(String, String)>,
    user: Option<String>,
    password: Option<Secret>,
    format_override: Option<NotifyFormat>,
    /// One random id per instance, sent as `X-Apprise-ID`.
    uid: String,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let q = |k: &str| u.param_nonempty(k);
    let (token, fullpath) = if let Some(t) = q("token").or_else(|| q("to")) {
        (Some(unquote(t)), unquote(u.fullpath.as_deref().unwrap_or("")))
    } else {
        let mut entries = u.path_segments();
        match entries.pop() {
            Some(t) => (Some(t), unquote(&entries.join("/"))),
            None => (None, unquote(u.fullpath.as_deref().unwrap_or(""))),
        }
    };
    let token = token
        .and_then(|t| validate_regex(&t, r"^[A-Z0-9_-]{1,128}$", "i", true))
        .ok_or_else(|| SERVICE.err("the Apprise API token specified is invalid"))?;
    let method = SERVICE.text_or_default(u, "method").to_lowercase();
    if method != "form" && method != "json" {
        return Err(SERVICE.err("the method specified is invalid"));
    }
    let version = q("version").or_else(|| q("v")).map(unquote).unwrap_or_else(|| SERVICE.default_of("version").into());
    if version != "1" && version != "2" {
        return Err(SERVICE.err("the Apprise API version specified is invalid"));
    }
    let tags = q("tags").map(|t| parse_list(parse_list([t]))).unwrap_or_default();

    let mut url = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = u.port {
        url.push_str(&format!(":{p}"));
    }
    let path = fullpath.trim_matches('/');
    if !path.is_empty() {
        url.push('/');
        url.push_str(&quote(path, "/!$&'()*+,;=:@~"));
    }
    url.push_str("/notify");
    let v1 = version == "1";
    if v1 {
        url.push('/');
        url.push_str(&token);
    }
    Ok(Box::new(AppriseApi {
        url,
        token: Secret::new(token),
        json: method == "json",
        v1,
        tags,
        headers: unquoted_pairs(&u.query_plus),
        user: u.user().filter(|s| !s.is_empty()),
        password: u.password().filter(|s| !s.is_empty()).map(Secret::new),
        format_override: u.format,
        uid: crate::crypto::uuid4(),
    }))
}

/// `http(s)://host[:port][/path]/notify/{token}[/][?params]` -> `apprise(s)://...` (version 1 unless the query names one).
fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(
        r"(?i)^http(?P<secure>s?)://(?P<hostname>[A-Z0-9._-]+)(:(?P<port>[0-9]+))?(?P<path>/[^?]+?)?/notify/(?P<token>[A-Z0-9_-]{1,32})/?(?P<params>\?.+)?$"
    );
    let c = re.captures(url)?;
    let g = |n: &str| c.name(n).map(|m| m.as_str()).unwrap_or("");
    let schema = if g("secure").is_empty() { "apprise" } else { "apprises" };
    let port = if g("port").is_empty() { String::new() } else { format!(":{}", g("port")) };
    let params = g("params");
    let mut out = format!("{schema}://{}{port}{}/{}/{params}", g("hostname"), g("path"), g("token"));
    let parsed = crate::url::parse_url(&out)?;
    if parsed.param_nonempty("version").is_none() && parsed.param_nonempty("v").is_none() {
        out.push_str(if params.is_empty() { "?version=1" } else { "&version=1" });
    }
    Some(out)
}

impl Notify for AppriseApi {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let format = if msg.passthrough { self.format_override } else { Some(msg.format) };
        let mut req = Request::post(&self.url)
            .timeouts(DEFAULT_CONNECT_TIMEOUT, READ_TIMEOUT)
            .header("User-Agent", ctx.app_id())
            .headers(self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())));

        if self.json {
            let mut payload = json!({"title": msg.title, "body": msg.body, "type": msg.kind.as_str()});
            if let Some(f) = format {
                payload["format"] = json!(f.as_str());
            }
            if !self.tags.is_empty() {
                payload["tag"] = json!(self.tags);
            }
            if !msg.attachments.is_empty() {
                let atts: Vec<Value> = msg
                    .attachments
                    .iter()
                    .enumerate()
                    .map(|(i, a)| {
                        let name = if a.name.is_empty() { format!("file{:03}.dat", i + 1) } else { a.name.clone() };
                        json!({"filename": name, "base64": b64(&a.data), "mimetype": a.mime})
                    })
                    .collect();
                payload["attachments"] = Value::Array(atts);
            }
            req = req
                .set_header("Content-Type", "application/json")
                .body(serde_json::to_vec(&payload).unwrap_or_default(), None);
        } else {
            let mut fields: Vec<(&str, String)> =
                vec![("title", msg.title.into()), ("body", msg.body.into()), ("type", msg.kind.as_str().into())];
            if let Some(f) = format {
                fields.push(("format", f.as_str().into()));
            }
            fields.extend(self.tags.iter().map(|t| ("tag", t.clone())));
            if msg.attachments.is_empty() {
                req = req.form(&fields);
            } else {
                let mut mp = Multipart::new();
                for (k, v) in &fields {
                    mp = mp.text(*k, v.as_str());
                }
                for (i, a) in msg.attachments.iter().enumerate() {
                    let name = if a.name.is_empty() { format!("file{:03}.dat", i + 1) } else { a.name.clone() };
                    mp = mp.file(format!("file{:02}", i + 1), name, a.mime.as_str(), a.data.clone());
                }
                req = req.multipart(mp);
            }
        }

        if self.user.is_some() || self.password.is_some() {
            req = req.basic_auth(self.user.as_deref().unwrap_or(""), self.password.as_ref().map(Secret::expose));
        }
        if !self.v1 {
            req = req.set_header("X-Apprise-Config-ID", self.token.expose());
        }
        req = req
            .set_header("Accept", "application/json")
            .set_header("X-Apprise-ID", ctx.asset.uid.as_deref().unwrap_or(&self.uid))
            .set_header("X-Apprise-Recursion-Count", (ctx.asset.recursion + 1).to_string());
        Plan::send_expect(req, &[200])
    }
}
