//! Home Assistant (`hassio://`, `hassios://`): notifications through the Home Assistant REST API.
//!
//! Without targets a persistent notification is created; otherwise each `[domain.]service[:target,...]` entry calls `/api/services/{domain}/{service}`.

use serde_json::{Value, json};

use crate::parse::{parse_list, validate_nonblank, validate_regex};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, split_path, unquote};
use crate::{Error, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "homeassistant",
    name: "HomeAssistant",
    schemes: &["hassio", "hassios"],
    service_url: "https://www.home-assistant.io/",
    parse,
    templates: &[
        "{schema}://{host}/{accesstoken}",
        "{schema}://{host}/{accesstoken}/{targets}",
        "{schema}://{host}:{port}/{accesstoken}",
        "{schema}://{host}:{port}/{accesstoken}/{targets}",
        "{schema}://{user}@{host}/{accesstoken}",
        "{schema}://{user}@{host}/{accesstoken}/{targets}",
        "{schema}://{user}@{host}:{port}/{accesstoken}",
        "{schema}://{user}@{host}:{port}/{accesstoken}/{targets}",
        "{schema}://{user}:{password}@{host}/{accesstoken}",
        "{schema}://{user}:{password}@{host}/{accesstoken}/{targets}",
        "{schema}://{user}:{password}@{host}:{port}/{accesstoken}",
        "{schema}://{user}:{password}@{host}:{port}/{accesstoken}/{targets}",
    ],
    tokens: &[
        Param::new("accesstoken", "Long-Lived Access Token").required().secret(),
        Param::new("host", "Hostname").required(),
        Param::new("password", "Password").secret(),
        Param::new("port", "Port").port(),
        Param::new("target_device", "Target Device"),
        Param::new("targets", "Targets").list("/").group(&["target_device"]),
        Param::new("user", "Username"),
    ],
    params: &[
        Param::new("batch", "Batch Mode").bool(false),
        Param::new("nid", "Notification ID").pattern("^[a-z0-9_-]+$"),
        Param::new("prefix", "Path Prefix"),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["accesstoken"]),
    ],
    ..ServiceDef::DEFAULTS
};

const DEFAULT_INSECURE_PORT: u16 = 8123;
const DEFAULT_BATCH_SIZE: usize = 10;
const DEFAULT_DOMAIN: &str = "notify";

#[derive(Debug)]
struct Target {
    domain: String,
    service: String,
    devices: Vec<String>,
}

#[derive(Debug)]
struct HomeAssistant {
    /// `{schema}://{host}[:port]`.
    base: String,
    prefix: String,
    token: Secret,
    nid: Option<String>,
    batch: bool,
    user: Option<String>,
    password: Option<Secret>,
    /// `None`: persistent notification mode (no targets given).
    targets: Option<Vec<Target>>,
}

fn is_long_lived_token(s: &str) -> bool {
    crate::regex!(r"(?i)^(?:[0-9a-f]{8}\.[0-9a-f]{64}|[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+)$").is_match(s)
}

/// Split `[domain.]service[:target,...]` entries. Whitespace, `;` and brackets separate entries; a comma does too, except inside an entry with `:`, where it separates that entry's targets until a part that has its own `:` or `.`.
fn domain_service_entries(args: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for word in args.iter().flat_map(|a| a.split(|c: char| matches!(c, '[' | ']' | ';') || c.is_whitespace())) {
        let mut current: Option<String> = None;
        for part in word.split(',').filter(|p| !p.is_empty()) {
            match current.as_mut() {
                Some(entry) if entry.contains(':') && !part.contains([':', '.']) => {
                    entry.push(',');
                    entry.push_str(part);
                }
                _ => out.extend(current.replace(part.to_string())),
            }
        }
        out.extend(current);
    }
    out
}

/// One `[domain.]service[:target,...]` entry; the domain defaults to `notify`.
fn domain_service_target(entry: &str) -> Option<Target> {
    let re = crate::regex!(r"(?i)^(?:(?P<domain>[a-z0-9_-]+)\.)?(?P<service>[a-z0-9_-]+)(?::(?P<targets>[a-z0-9_,-]+))?$");
    let c = re.captures(entry)?;
    Some(Target {
        domain: c.name("domain").map_or(DEFAULT_DOMAIN, |m| m.as_str()).to_string(),
        service: c["service"].to_string(),
        devices: c.name("targets").map(|m| parse_list([m.as_str()])).unwrap_or_default(),
    })
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets: Vec<String> = Vec::new();
    let fullpath = u.fullpath.as_deref().unwrap_or("");
    let token = if let Some(t) = u.param_nonempty("accesstoken").or_else(|| u.param_nonempty("token")) {
        targets = split_path(fullpath, true);
        Some(unquote(t))
    } else {
        let tokens = split_path(fullpath, true);
        match tokens.iter().position(|t| is_long_lived_token(t)) {
            Some(idx) => {
                targets.extend(tokens[idx + 1..].iter().rev().cloned());
                targets.extend(tokens[..idx].iter().rev().cloned());
                Some(tokens[idx].clone())
            }
            None => tokens.last().cloned(),
        }
    };
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(split_path(&unquote(to), true));
    }
    let prefix = SERVICE.text(u, "prefix").unwrap_or_default();
    let batch = SERVICE.flag(u, "batch");
    let nid = SERVICE.text(u, "nid");

    let token = token
        .as_deref()
        .and_then(validate_nonblank)
        .ok_or_else(|| SERVICE.err("an invalid Home Assistant Long-Lived Access Token was specified"))?;
    let nid = match nid.filter(|n| !n.is_empty()) {
        None => None,
        Some(n) => Some(
            validate_regex(&n, r"^[a-z0-9_-]+$", "i", true)
                .ok_or_else(|| SERVICE.err("an invalid Home Assistant Notification Identifier was specified"))?,
        ),
    };

    let targets = if targets.is_empty() {
        None
    } else {
        let mut out = Vec::new();
        for t in domain_service_entries(&targets) {
            match domain_service_target(&t) {
                Some(target) => out.push(target),
                None => log::warn!("Home Assistant: dropped invalid [domain.]service[:target] entry"),
            }
        }
        Some(out)
    };

    let port = match u.port {
        None if !u.secure => Some(DEFAULT_INSECURE_PORT),
        p => p,
    };
    let mut base = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = port {
        base.push_str(&format!(":{p}"));
    }

    Ok(Box::new(HomeAssistant {
        base,
        prefix,
        token: Secret::new(token),
        nid,
        batch,
        user: u.user().filter(|s| !s.is_empty()),
        password: u.password().map(Secret::new),
        targets,
    }))
}

impl HomeAssistant {
    fn post(&self, url: String, payload: &Value, text: &str, ctx: &Context<'_>) -> Plan {
        let mut req = ctx.post(url)
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.token.expose()))
            .json_text(payload, text);
        req = req.basic_auth_opt(self.user.as_deref(), self.password.as_ref().map(Secret::expose));
        Plan::send_expect(req, &[200])
    }
}

impl Notify for HomeAssistant {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let payload = json!({"title": msg.title, "message": crate::http::TEXT});
        let Some(targets) = &self.targets else {
            let mut payload = payload;
            let nid = self.nid.clone().unwrap_or_else(|| ctx.env().uuid4());
            payload["notification_id"] = json!(nid);
            let url = format!("{}/api/services/persistent_notification/create", self.base);
            return self.post(url, &payload, msg.body, ctx);
        };
        if targets.is_empty() {
            return Plan::Fail(Error::Service("no valid Home Assistant service targets to notify".into()));
        }
        let batch_size = if self.batch { DEFAULT_BATCH_SIZE } else { 1 };
        let prefix = self.prefix.trim_end_matches('/');
        let mut plans = Vec::new();
        for t in targets {
            let url = format!("{}{}/api/services/{}/{}", self.base, prefix, t.domain, t.service);
            let label = format!("{}.{}", t.domain, t.service);
            if t.devices.is_empty() {
                plans.push(self.post(url, &payload, msg.body, ctx).target(label));
                continue;
            }
            for chunk in t.devices.chunks(batch_size) {
                let mut p = payload.clone();
                p["targets"] = json!(chunk);
                plans.push(self.post(url.clone(), &p, msg.body, ctx).target(label.clone()));
            }
        }
        Plan::chain(plans)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries() {
        let cases: &[(&str, &[&str])] = &[
            ("notify.mobile:dev1,dev2,dev3", &["notify.mobile:dev1,dev2,dev3"]),
            ("a:b", &["a:b"]),
            ("a.b:c,d,,e f", &["a.b:c,d,e", "f"]),
            ("a.b:c,d:e,f", &["a.b:c", "d:e,f"]),
            (" a ,b, c", &["a", "b", "c"]),
            ("a,b:c,d,e", &["a", "b:c,d,e"]),
            ("a:b,c.d", &["a:b", "c.d"]),
        ];
        for (input, want) in cases {
            assert_eq!(domain_service_entries(&[input.to_string()]), *want, "{input:?}");
        }
        let t = domain_service_target("light.kitchen:a,b").unwrap();
        assert_eq!((t.domain.as_str(), t.service.as_str(), t.devices), ("light", "kitchen", vec!["a".into(), "b".into()]));
        assert_eq!(domain_service_target("mobile").unwrap().domain, "notify");
        assert!(domain_service_target("x.y.z:a").is_none());
    }
}
