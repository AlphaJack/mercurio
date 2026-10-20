//! Notifico (`notifico://`, `notificos://`): messages to IRC channels through a Notifico project's message hook.
//!
//! `notifico://{project_id}/{msghook}` posts to the hosted service (`n.tkte.ch`); with a host (`notifico://[user[:password]@]host[:port]/{project_id}/{msghook}`) it posts to a self-hosted server, over HTTPS with `notificos://`. The message is a `GET /h/{project_id}/{msghook}?payload=...`, prefixed with the notification type and app id in IRC colors unless `?prefix=no` / `?color=no`. As in Apprise, `?color=no` also strips the literal text `\x03` followed by a color code (a backslash, not the control character) from the body.

use crate::http::Request;
use crate::parse::validate_regex;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef, UrlIdentifier};
use crate::url::ParsedUrl;
use crate::{NotifyType, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "notifico",
    name: "Notifico",
    schemes: &["notifico", "notificos"],
    service_url: "https://notifico.tech/",
    parse,
    parse_native: Some(parse_native),
    limits: Limits { title_maxlen: 0, body_maxlen: 512, body_max_line_count: 0 },
    templates: &[
        "{schema}://{project_id}/{msghook}",
        "{schema}://{host}/{project_id}/{msghook}",
        "{schema}://{host}:{port}/{project_id}/{msghook}",
        "{schema}://{user}@{host}/{project_id}/{msghook}",
        "{schema}://{user}@{host}:{port}/{project_id}/{msghook}",
        "{schema}://{user}:{password}@{host}/{project_id}/{msghook}",
        "{schema}://{user}:{password}@{host}:{port}/{project_id}/{msghook}",
    ],
    tokens: &[
        Param::new("host", "Hostname"),
        Param::new("port", "Port").port(),
        Param::new("user", "Username"),
        Param::new("password", "Password").secret(),
        Param::new("project_id", "Project ID").required().secret().pattern("^[0-9]+$"),
        Param::new("msghook", "Message Hook").required().secret().pattern("^[a-z0-9]+$"),
    ],
    params: &[
        Param::new("color", "IRC Colors").bool(true),
        Param::new("prefix", "Prefix").bool(true),
        Param::sets("token", &["msghook"]),
        Param::sets("project", &["project_id"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://n.tkte.ch/h";

/// IRC formatting codes.
const RESET: &str = "\x0f";
const BOLD: &str = "\x02";
const COLOR_RESET: &str = "\x03";

/// A self-hosted server.
#[derive(Debug)]
struct Server {
    secure: bool,
    host: String,
    port: Option<u16>,
    user: Option<String>,
    password: Option<Secret>,
}

#[derive(Debug)]
struct Notifico {
    /// `None`: the hosted service.
    server: Option<Server>,
    project_id: Secret,
    msghook: Secret,
    color: bool,
    prefix: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let entries = u.path_segments();
    let host = u.host();
    // A numeric host is the project id of the hosted service.
    let (server, mut project_id, mut msghook) = if crate::regex!(r"^[0-9]+$").is_match(&host) {
        (None, Some(host), entries.first().cloned())
    } else {
        let server = Server { secure: u.secure, host, port: u.port, user: u.user(), password: u.password().map(Secret::new) };
        (Some(server), entries.first().cloned(), entries.get(1).cloned())
    };
    if let Some(token) = u.text("token") {
        msghook = Some(token);
    }
    if let Some(project) = u.text("project") {
        project_id = Some(project);
    }
    let project_id = project_id
        .and_then(|p| validate_regex(&p, r"^[0-9]+$", "", true))
        .ok_or_else(|| SERVICE.err("an invalid Notifico Project ID was specified"))?;
    let msghook = msghook
        .and_then(|h| validate_regex(&h, r"^[a-z0-9]+$", "i", true))
        .ok_or_else(|| SERVICE.err("an invalid Notifico Message Token was specified"))?;
    Ok(Box::new(Notifico {
        server,
        project_id: Secret::new(project_id),
        msghook: Secret::new(msghook),
        color: SERVICE.flag_strict(u, "color"),
        prefix: SERVICE.flag_strict(u, "prefix"),
    }))
}

/// `https://n.tkte.ch/h/{project_id}/{msghook}[/][?params]`.
fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(r"(?i)^https?://n\.tkte\.ch/h/(?P<proj>[0-9]+)/(?P<hook>[A-Z0-9]+)/?(?P<params>\?.+)?\z");
    let c = re.captures(url)?;
    Some(format!("notifico://{}/{}/{}", &c["proj"], &c["hook"], c.name("params").map_or("", |m| m.as_str())))
}

/// The IRC color and marker of a notification type.
fn marker(kind: NotifyType) -> (&'static str, &'static str) {
    match kind {
        NotifyType::Info => ("\x0310", "i"),
        NotifyType::Success => ("\x0309", "✔"),
        NotifyType::Warning => ("\x0307", "!"),
        NotifyType::Failure => ("\x0304", "✗"),
    }
}

impl Notifico {
    fn payload(&self, body: &str, kind: NotifyType, app_id: &str) -> String {
        let body = if self.color {
            body.to_string()
        } else {
            crate::regex!(r"\\x03(\d{1,2}(,[0-9]{1,2})?)?").replace_all(body, "").into_owned()
        };
        if !self.prefix {
            return body;
        }
        let (color, token) = marker(kind);
        let on = |code: &'static str| if self.color { code } else { "" };
        format!("{}[{token}]{} {}{app_id}{}: {body}{}", on(color), on(COLOR_RESET), on(BOLD), on(RESET), on(RESET))
    }
}

impl Notify for Notifico {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let (project, hook) = (self.project_id.expose(), self.msghook.expose());
        let url = match &self.server {
            None => format!("{NOTIFY_URL}/{project}/{hook}"),
            Some(s) => {
                let port = s.port.map(|p| format!(":{p}")).unwrap_or_default();
                format!("{}://{}{port}/h/{project}/{hook}", if s.secure { "https" } else { "http" }, s.host)
            }
        };
        let mut req = Request::get(url)
            .header("User-Agent", ctx.app_id())
            .header("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
            .query(&[("payload", self.payload(msg.body, msg.kind, ctx.app_id()))]);
        if let Some(s) = &self.server {
            req = req.basic_auth_opt(s.user.as_deref(), Some(s.password.as_ref().map_or("", Secret::expose)));
        }
        Plan::send_expect(req, &[200])
    }

    fn url_identifier(&self) -> UrlIdentifier {
        let (scheme, mode, host, port) = match &self.server {
            None => ("notifico", "official", String::new(), String::new()),
            Some(s) => (
                if s.secure { "notificos" } else { "notifico" },
                "selfhosted",
                s.host.clone(),
                s.port.map(|p| p.to_string()).unwrap_or_default(),
            ),
        };
        UrlIdentifier::parts([
            scheme.to_string(),
            mode.to_string(),
            host,
            port,
            self.project_id.expose().to_string(),
            self.msghook.expose().to_string(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notifico(color: bool, prefix: bool) -> Notifico {
        Notifico { server: None, project_id: Secret::new("1"), msghook: Secret::new("a"), color, prefix }
    }

    #[test]
    fn payloads() {
        assert_eq!(notifico(true, true).payload("b", NotifyType::Info, "App"), "\x0310[i]\x03 \x02App\x0f: b\x0f");
        assert_eq!(notifico(false, true).payload("b", NotifyType::Failure, "App"), "[✗] App: b");
        assert_eq!(notifico(false, false).payload(r"a\x0312,4b\x03c", NotifyType::Info, "App"), "abc");
        assert_eq!(notifico(true, false).payload(r"a\x0312b", NotifyType::Info, "App"), r"a\x0312b");
    }

    #[test]
    fn native_urls() {
        assert_eq!(parse_native("https://n.tkte.ch/h/2144/uJmKaBW9WFk42miB146ci3Kj").as_deref(), Some("notifico://2144/uJmKaBW9WFk42miB146ci3Kj/"));
        assert_eq!(parse_native("https://n.tkte.ch/h/2144/abc/?color=no").as_deref(), Some("notifico://2144/abc/?color=no"));
        assert_eq!(parse_native("https://n.tkte.ch/h/x/abc"), None);
    }
}
