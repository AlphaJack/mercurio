//! Nextcloud (`ncloud://`, `nclouds://`): notifications to Nextcloud users.
//!
//! Targets are users, `#group`s or `all`/`everyone`/`*`; groups are expanded through the OCS provisioning API before sending.
//!
//! Group lookups are cached for a day in the persistent store.
//!
//! # Differences
//!
//! - URL order is kept (users first, then group members); Apprise iterates unordered sets. *intentional*

use std::sync::Arc;

use serde_json::Value;

use crate::http::{Request, Response};
use crate::parse::parse_list;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef, UrlIdentifier};
use crate::store::StoreRef;
use crate::url::{ParsedUrl, quote, unquote};
use crate::util::{json_text, parse_int};
use crate::{Error, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "nextcloud",
    name: "Nextcloud",
    schemes: &["ncloud", "nclouds"],
    service_url: "https://nextcloud.com/",
    parse,
    limits: Limits { title_maxlen: 255, body_maxlen: 4000, body_max_line_count: 0 },
    templates: &[
        "{schema}://{host}/{targets}",
        "{schema}://{host}:{port}/{targets}",
        "{schema}://{user}:{password}@{host}/{targets}",
        "{schema}://{user}:{password}@{host}:{port}/{targets}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("password", "Password").secret(),
        Param::new("port", "Port").port(),
        Param::new("target_group", "Target Group").prefix("#"),
        Param::new("target_user", "Target User").prefix("@"),
        Param::new("targets", "Targets").list("/").required().group(&["target_group", "target_user"]),
        Param::new("user", "Username"),
    ],
    params: &[
        Param::sets("to", &["targets"]),
        Param::new("url_prefix", "URL Prefix"),
        Param::new("version", "Version").int().default("21").min(1),
        Param::new("headers", "HTTP Header").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

const ALL_GROUP: &str = "all";

#[derive(Debug)]
struct Nextcloud {
    base: String,
    user: Option<String>,
    password: Option<Secret>,
    version: i64,
    headers: Vec<(String, String)>,
    users: Vec<String>,
    groups: Vec<String>,
    /// Parts of the URL identity (namespace of the persistent store).
    id: Vec<String>,
}

/// Group lookups are cached a day.
const GROUP_CACHE: std::time::Duration = std::time::Duration::from_secs(86400);

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let mut targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }
    let version = SERVICE.text(u, "version");
    let url_prefix = SERVICE.text(u, "url_prefix");
    let headers: Vec<(String, String)> = u.query_plus.iter().map(|(k, v)| (unquote(k), unquote(v))).collect();

    let is_group = crate::regex!(r"(?i)^\s*(?:(?:#|%23)([a-z0-9_-]+)|(?:#|%23)?(all|everyone|\*))\s*$");
    let is_user = crate::regex!(r"(?i)^\s*(?:@|%40)?([a-z0-9_-]+)\s*$");
    let mut users = Vec::new();
    let mut groups: Vec<String> = Vec::new();
    for t in parse_list(&targets) {
        if let Some(c) = is_group.captures(&t) {
            let g = if c.get(2).is_some() { ALL_GROUP.to_string() } else { c[1].to_string() };
            if !groups.contains(&g) {
                groups.push(g);
            }
        } else if let Some(c) = is_user.captures(&t) {
            users.push(c[1].to_string());
        } else {
            log::warn!("Nextcloud: ignored an invalid user/group");
        }
    }

    let version = match version {
        None => 21,
        Some(v) => parse_int(&v)
            .filter(|v| *v >= 1)
            .ok_or_else(|| SERVICE.err("an invalid Nextcloud version was specified"))?,
    };

    let mut base = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = u.port {
        base.push_str(&format!(":{p}"));
    }
    let prefix = url_prefix.filter(|p| !p.is_empty()).map(|p| format!("/{}", p.trim_matches('/'))).unwrap_or_default();
    base.push_str(&prefix);
    let id = vec![
        if u.secure { "nclouds" } else { "ncloud" }.to_string(),
        u.user().as_deref().unwrap_or_default().to_string(),
        u.password().as_deref().unwrap_or_default().to_string(),
        u.host(),
        u.port.map(|p| p.to_string()).as_deref().unwrap_or_default().to_string(),
        prefix,
    ];

    Ok(Box::new(Nextcloud {
        base,
        user: u.user().filter(|s| !s.is_empty()),
        password: u.password().map(Secret::new),
        version,
        headers,
        users,
        groups,
        id,
    }))
}

/// A JSON list entry as trimmed text.
fn entry_text(v: &Value) -> String {
    json_text(v).trim().to_string()
}

/// Users listed in an OCS response; `Err` when the response is malformed.
fn listed_users(r: &Response) -> Result<Vec<String>> {
    let content = r.json().unwrap_or_else(|| Value::Object(Default::default()));
    let bad = || Error::Service("unexpected Nextcloud response".into());
    let ocs = content.as_object().ok_or_else(bad)?.get("ocs").cloned().unwrap_or(Value::Object(Default::default()));
    let data = ocs.as_object().ok_or_else(bad)?.get("data").cloned().unwrap_or(Value::Object(Default::default()));
    let users = data.as_object().ok_or_else(bad)?.get("users").cloned();
    Ok(match users {
        Some(Value::Array(a)) => a.iter().map(entry_text).filter(|s| !s.is_empty()).collect(),
        _ => Vec::new(),
    })
}

/// Request templates shared by the discovery continuations.
struct Shared {
    base: String,
    version: i64,
    post: Request,
    get: Request,
}

impl Shared {
    fn notify(&self, target: &str) -> Request {
        let t = quote(target, "/");
        let mut r = self.post.clone();
        r.url = if self.version < 21 {
            format!("{}/ocs/v2.php/apps/admin_notifications/api/v1/notifications/{t}", self.base)
        } else {
            format!("{}/ocs/v2.php/apps/notifications/api/v2/admin_notifications/{t}", self.base)
        };
        r
    }

    fn lookup(&self, group: Option<&str>) -> Request {
        let mut r = self.get.clone();
        r.url = match group {
            Some(g) => format!("{}/ocs/v1.php/cloud/groups/{}", self.base, quote(g, "/")),
            None => format!("{}/ocs/v1.php/cloud/users", self.base),
        };
        r.query(&[("format", "json")])
    }
}

impl Nextcloud {
    fn request(&self, req: Request, ctx: &Context<'_>) -> Request {
        let mut req = req
            .header("User-Agent", ctx.app_id())
            .header("OCS-APIREQUEST", "true")
            .header("Accept", "application/json")
            .headers(self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        req = req.basic_auth_opt(self.user.as_deref(), self.password.as_ref().map(Secret::expose));
        req
    }
}

fn add_users(targets: &mut Vec<String>, users: Vec<String>) {
    for u in users {
        if !targets.contains(&u) {
            targets.push(u);
        }
    }
}

fn discover(shared: Arc<Shared>, store: StoreRef, mut groups: Vec<String>, mut targets: Vec<String>) -> Plan {
    if groups.is_empty() {
        if targets.is_empty() {
            return Plan::Fail(Error::Service("there were no Nextcloud targets to notify".into()));
        }
        return Plan::all(targets.into_iter().map(|t| Plan::send_expect(shared.notify(&t), &[200]).target(t)));
    }
    let group = groups.remove(0);
    // Every lookup is cached (keyed by group, `all` for every user).
    if let Some(Value::Array(cached)) = store.get(&group) {
        add_users(&mut targets, cached.iter().map(entry_text).collect());
        return discover(shared, store, groups, targets);
    }
    let req = shared.lookup(if group == ALL_GROUP { None } else { Some(&group) });
    Plan::http(req, move |res| {
        let found = match res {
            Ok(r) if r.status == 200 => listed_users(&r),
            Ok(r) => Err(r.http_error()),
            Err(e) => Err(e),
        };
        match found {
            Ok(users) => {
                // An empty "all users" answer is not cached.
                if group != ALL_GROUP || !users.is_empty() {
                    store.set(&group, serde_json::json!(users), Some(GROUP_CACHE));
                }
                add_users(&mut targets, users);
                discover(shared, store, groups, targets)
            }
            Err(e) => Plan::Fail(e.context("group lookup")),
        }
    })
}

impl Notify for Nextcloud {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut form = vec![(
            "shortMessage".to_string(),
            if msg.title.is_empty() { ctx.app_desc().to_string() } else { msg.title.to_string() },
        )];
        if !msg.body.is_empty() {
            form.push(("longMessage".to_string(), msg.body.to_string()));
        }
        let shared = Arc::new(Shared {
            base: self.base.clone(),
            version: self.version,
            post: self.request(Request::post(String::new()), ctx).form(&form),
            get: self.request(Request::get(String::new()), ctx),
        });
        let mut targets: Vec<String> = Vec::new();
        for u in &self.users {
            if !targets.contains(u) {
                targets.push(u.clone());
            }
        }
        discover(shared, ctx.store(), self.groups.clone(), targets)
    }

    fn url_identifier(&self) -> UrlIdentifier {
        UrlIdentifier::Parts(self.id.clone())
    }
}
