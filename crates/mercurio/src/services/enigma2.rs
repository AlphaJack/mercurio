//! Enigma2 (`enigma2://`, `enigma2s://`): on-screen messages on Enigma2 set-top boxes through their web API.

use std::time::Duration;

use crate::util::{json_has_value, unquoted_pairs};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};

use crate::url::ParsedUrl;
use crate::{Error, NotifyType, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "enigma2",
    name: "Enigma2",
    schemes: &["enigma2", "enigma2s"],
    service_url: "https://dreambox.de/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 1000, body_max_line_count: 0 },
    throttle: Duration::from_millis(500),
    templates: &[
        "{schema}://{host}",
        "{schema}://{host}:{port}",
        "{schema}://{user}@{host}",
        "{schema}://{user}@{host}:{port}",
        "{schema}://{user}:{password}@{host}",
        "{schema}://{user}:{password}@{host}:{port}",
        "{schema}://{host}/{fullpath}",
        "{schema}://{host}:{port}/{fullpath}",
        "{schema}://{user}@{host}/{fullpath}",
        "{schema}://{user}@{host}:{port}/{fullpath}",
        "{schema}://{user}:{password}@{host}/{fullpath}",
        "{schema}://{user}:{password}@{host}:{port}/{fullpath}",
    ],
    tokens: &[
        Param::new("fullpath", "Path"),
        Param::new("host", "Hostname").required(),
        Param::new("password", "Password").secret(),
        Param::new("port", "Port").int().range(1, 65535),
        Param::new("user", "Username"),
    ],
    params: &[
        Param::new("timeout", "Server Timeout").int().default("13").min(-1),
        Param::new("headers", "HTTP Header").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Enigma2 {
    url: String,
    user: Option<String>,
    password: Option<Secret>,
    timeout: i64,
    headers: Vec<(String, String)>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let timeout = SERVICE.int_or_default(u, "timeout").max(-1);
    let fullpath = u.fullpath.as_deref().unwrap_or("/");
    let mut url = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = u.port {
        url.push_str(&format!(":{p}"));
    }
    url.push_str(fullpath.trim_end_matches('/'));
    url.push_str("/api/message");
    Ok(Box::new(Enigma2 {
        url,
        user: u.user().filter(|s| !s.is_empty()),
        password: u.password().map(Secret::new),
        timeout,
        headers: unquoted_pairs(&u.query_plus),
    }))
}

impl Notify for Enigma2 {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let kind = match msg.kind {
            NotifyType::Warning => 2,
            NotifyType::Failure => 3,
            NotifyType::Info | NotifyType::Success => 1,
        };
        let params = [
            ("text", msg.body.to_string()),
            ("type", kind.to_string()),
            ("timeout", self.timeout.to_string()),
        ];
        let mut req = ctx.get(&self.url)
            .headers(self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .query(&params);
        req = req.basic_auth_opt(self.user.as_deref(), self.password.as_ref().map(Secret::expose));
        Plan::send_check(req, |r| {
            if r.status != 200 {
                return Err(r.http_error());
            }
            let ack = r.json().and_then(|v| v.as_object().map(|o| o.get("result").is_some_and(json_has_value)));
            if ack == Some(true) {
                Ok(())
            } else {
                Err(Error::Service("there was no server acknowledgement".into()))
            }
        })
    }
}
