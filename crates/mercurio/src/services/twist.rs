//! Twist (`twist://`): messages to Twist threads and channels.
//!
//! The login session lives on the parsed URL: the token, workspace and channel lookups are kept between sends (channel names are resolved once). `users/logout` runs from [`Target::close`](crate::Target::close).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use super::_chat::name_id_map;
use crate::http::Request;
use crate::parse::{is_email, parse_list};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::util::{json_text, json_has_value};
use crate::{Error, NotifyFormat, Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "twist",
    name: "Twist",
    schemes: &["twist"],
    service_url: "https://twist.com",
    parse,
    limits: Limits { title_maxlen: 250, body_maxlen: 1000, body_max_line_count: 0 },
    formats: &[NotifyFormat::Markdown],
    throttle: Duration::from_millis(200),
    templates: &[
        "{schema}://{password}:{email}",
        "{schema}://{password}:{email}/{targets}",
    ],
    tokens: &[
        Param::new("email", "Email").email().required(),
        Param::new("password", "Password").required().secret(),
        Param::new("target_channel", "Target Channel").prefix("#"),
        Param::new("target_channel_id", "Target Channel ID"),
        Param::new("targets", "Targets").list("/").group(&["target_channel", "target_channel_id"]),
    ],
    params: &[
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const API: &str = "https://api.twist.com/api/v3/";
const FORM_CT: &str = "application/x-www-form-urlencoded; charset=utf-8";

fn is_channel(s: &str) -> Option<crate::re::Captures<'_>> {
    crate::regex!(r"^#?(?P<name>((?P<workspace>[A-Za-z0-9_-]+):)?(?P<channel>[^\s]{1,64}))$").captures(s)
}

fn is_channel_id(s: &str) -> Option<crate::re::Captures<'_>> {
    crate::regex!(r"^(?P<name>((?P<workspace>[0-9]+):)?(?P<channel>[0-9]+))$").captures(s)
}

#[derive(Debug)]
struct Twist {
    email: String,
    password: Secret,
    state: Arc<Mutex<State>>,
}

/// Mutable session state.
#[derive(Debug, Default)]
struct State {
    token: Value,
    default_workspace: Value,
    workspaces: BTreeMap<String, Value>,
    channel_cache: BTreeMap<String, BTreeMap<String, Value>>,
    channels: Vec<String>,
    channel_ids: BTreeSet<String>,
    failed: bool,
    aborted: bool,
    logging_out: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    if u.user.as_deref().is_none_or(str::is_empty) {
        return Err(SERVICE.err("no Twist user was specified"));
    }
    let mut targets = u.path_segments();
    let (user, password) = match u.password.as_deref().filter(|p| !p.is_empty()) {
        None => {
            if targets.is_empty() {
                return Err(SERVICE.err("no Twist password was specified"));
            }
            (u.user().unwrap_or_default(), targets.remove(0))
        }
        Some(_) => (u.password().unwrap_or_default(), u.user().unwrap_or_default()),
    };
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }
    let email = is_email(&format!("{user}@{}", u.host()))
        .ok_or_else(|| SERVICE.err("the Twist Auth email specified is invalid"))?
        .full_email;
    if password.is_empty() {
        return Err(SERVICE.err("no Twist password was specified"));
    }
    let mut channels = BTreeSet::new();
    let mut channel_ids = BTreeSet::new();
    for t in parse_list(targets) {
        if let Some(c) = is_channel_id(&t) {
            channel_ids.insert(c["name"].to_string());
        } else if let Some(c) = is_channel(&t) {
            channels.insert(c["name"].to_lowercase());
        }
    }
    if channels.is_empty() && channel_ids.is_empty() {
        channels.insert("general".to_owned());
    }
    Ok(Box::new(Twist {
        email,
        password: Secret::new(password),
        state: Arc::new(Mutex::new(State {
            // `_channel_migration` pops names off the end.
            channels: channels.iter().rev().cloned().collect(),
            channel_ids,
            ..State::default()
        })),
    }))
}

/// Everything one piece's continuations need.
#[derive(Debug)]
struct Run {
    email: String,
    password: Secret,
    ua: String,
    title: String,
    body: String,
    st: Arc<Mutex<State>>,
}

type R = Arc<Run>;
type K<T> = Box<dyn FnOnce(R, T) -> Plan + Send>;

impl Run {
    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        let mut g = self.st.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut g)
    }
}

struct Fetched {
    ok: bool,
    status: Option<u16>,
    content: Value,
}

fn form_pairs(pairs: &[(&str, &Value)]) -> Vec<(String, String)> {
    // requests drops `None` values from `data=`.
    pairs.iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k.to_string(), json_text(v))).collect()
}

/// One Twist API call, with a re-login and retry on error codes 120/200.
fn fetch(r: R, path: &'static str, payload: Option<Vec<(String, String)>>, login: bool, k: K<Fetched>) -> Plan {
    Plan::defer(move || {
        let token = r.with(|s| s.token.clone());
        let mut req = Request::post(format!("{API}{path}")).header("User-Agent", &r.ua).header("Content-Type", FORM_CT);
        if json_has_value(&token) {
            req = req.header("Authorization", format!("Bearer {}", json_text(&token)));
        }
        if let Some(p) = &payload {
            req = req.form(p);
        }
        let again = req.clone();
        Plan::http(req, move |res| {
            let Ok(resp) = res else {
                return k(r, Fetched { ok: false, status: None, content: json!({}) });
            };
            let content = resp.json().unwrap_or_else(|| json!({}));
            let retry = resp.status != 200
                && !login
                && content.get("error_code").and_then(Value::as_f64).is_some_and(|c| c == 120.0 || c == 200.0);
            if !retry {
                return k(r, Fetched { ok: resp.status == 200, status: Some(resp.status), content });
            }
            let first = Fetched { ok: false, status: Some(resp.status), content };
            do_login(
                r,
                Box::new(move |r, ok| {
                    if !ok {
                        return k(r, first);
                    }
                    Plan::http(again, move |res| match res {
                        Ok(resp) => {
                            let content = resp.json().unwrap_or_else(|| json!({}));
                            k(r, Fetched { ok: resp.status == 200, status: Some(resp.status), content })
                        }
                        Err(_) => k(r, Fetched { ok: false, status: None, content: first.content }),
                    })
                }),
            )
        })
    })
}

/// Unexpected response shape: abort the notification (the session is still closed).
fn abort(r: R, step: &str) -> Plan {
    let in_logout = r.with(|s| {
        s.aborted = true;
        s.logging_out
    });
    if in_logout {
        return Plan::Done;
    }
    finish(r, Some(Error::service("unexpected Twist API response").context(step)))
}

/// End of a piece (the session stays open for later sends).
fn finish(_r: R, err: Option<Error>) -> Plan {
    match err {
        Some(e) => Plan::Fail(e),
        None => Plan::Done,
    }
}

fn logout(r: R) -> Plan {
    r.with(|s| s.logging_out = true);
    fetch(
        r,
        "users/logout",
        None,
        false,
        Box::new(|r, _| {
            r.with(|s| {
                s.token = Value::Null;
                s.logging_out = false;
            });
            Plan::Done
        }),
    )
}

fn do_login(r: R, k: K<bool>) -> Plan {
    r.with(|s| {
        s.default_workspace = Value::Null;
        s.workspaces.clear();
        s.channel_cache.clear();
    });
    let payload =
        vec![("email".to_owned(), r.email.clone()), ("password".to_owned(), r.password.expose().to_owned())];
    fetch(
        r,
        "users/login",
        Some(payload),
        true,
        Box::new(move |r, f| {
            if !f.ok || !json_has_value(&f.content) {
                r.with(|s| s.token = Value::Bool(false));
                return k(r, false);
            }
            let Some(o) = f.content.as_object() else { return abort(r, "login") };
            r.with(|s| {
                s.default_workspace = o.get("default_workspace").cloned().unwrap_or(Value::Null);
                s.token = o.get("token").cloned().unwrap_or(Value::Null);
            });
            k(r, true)
        }),
    )
}

/// `if not self.token and not self.login()`.
fn ensure_token(r: R, k: K<bool>) -> Plan {
    if r.with(|s| json_has_value(&s.token)) { k(r, true) } else { do_login(r, k) }
}

fn get_workspaces(r: R, k: K<BTreeMap<String, Value>>) -> Plan {
    ensure_token(
        r,
        Box::new(move |r, ok| {
            if !ok {
                return k(r, BTreeMap::new());
            }
            fetch(
                r,
                "workspaces/get",
                None,
                false,
                Box::new(move |r, f| {
                    if !f.ok || !json_has_value(&f.content) {
                        return k(r, BTreeMap::new());
                    }
                    match f.content.as_array().and_then(|a| name_id_map(a, "id")) {
                        Some(m) => k(r, m),
                        None => abort(r, "workspace lookup"),
                    }
                }),
            )
        }),
    )
}

fn get_channels(r: R, wid: Value, k: K<BTreeMap<String, Value>>) -> Plan {
    ensure_token(
        r,
        Box::new(move |r, ok| {
            if !ok {
                return k(r, BTreeMap::new());
            }
            fetch(
                r,
                "channels/get",
                Some(form_pairs(&[("workspace_id", &wid)])),
                false,
                Box::new(move |r, f| {
                    let Some(a) = f.content.as_array().filter(|_| f.ok) else { return k(r, BTreeMap::new()) };
                    match name_id_map(a, "id") {
                        Some(m) => k(r, m),
                        None => abort(r, "channel lookup"),
                    }
                }),
            )
        }),
    )
}

fn key(v: &Value) -> String {
    v.to_string()
}

/// Resolve the configured channel names to channel IDs, fetching a workspace channel list when it is not cached.
fn migrate(r: R, k: K<bool>) -> Plan {
    ensure_token(
        r,
        Box::new(move |r, ok| {
            if !ok {
                return k(r, false);
            }
            let (empty, dw, cached) = r.with(|s| {
                (
                    s.channels.is_empty(),
                    s.default_workspace.clone(),
                    s.channel_cache.contains_key(&key(&s.default_workspace)),
                )
            });
            if empty {
                return k(r, true);
            }
            if dw.is_array() || dw.is_object() {
                return abort(r, "channel lookup");
            }
            if json_has_value(&dw) && !cached {
                return get_channels(
                    r,
                    dw,
                    Box::new(move |r, map| {
                        r.with(|s| {
                            let k = key(&s.default_workspace);
                            s.channel_cache.insert(k, map);
                        });
                        next_channel(r, false, k)
                    }),
                );
            }
            next_channel(r, false, k)
        }),
    )
}

fn next_channel(r: R, has_error: bool, k: K<bool>) -> Plan {
    let Some(ch) = r.with(|s| s.channels.pop()) else { return k(r, !has_error) };
    let Some(c) = is_channel(&ch) else { return abort(r, "channel lookup") };
    let channel = c["channel"].to_lowercase();
    let Some(ws) = c.name("workspace").map(|m| m.as_str().to_lowercase()) else {
        let wid = r.with(|s| s.default_workspace.clone());
        return lookup(r, wid, channel, has_error, k);
    };
    let resolve = move |r: R, has_error: bool, k: K<bool>| {
        let Some(wid) = r.with(|s| s.workspaces.get(&ws).cloned()) else { return next_channel(r, true, k) };
        lookup(r, wid, channel, has_error, k)
    };
    if r.with(|s| s.workspaces.is_empty()) {
        get_workspaces(
            r,
            Box::new(move |r, m| {
                r.with(|s| s.workspaces = m);
                resolve(r, has_error, k)
            }),
        )
    } else {
        resolve(r, has_error, k)
    }
}

fn lookup(r: R, wid: Value, channel: String, has_error: bool, k: K<bool>) -> Plan {
    let found = r.with(|s| {
        let id = s.channel_cache.get(&key(&wid)).and_then(|m| m.get(&channel)).cloned();
        if let Some(id) = &id {
            s.channel_ids.insert(format!("{}:{}", json_text(&wid), json_text(id)));
        }
        id.is_some()
    });
    next_channel(r, has_error || !found, k)
}

/// After channel migration: post a thread to every channel id.
fn post_all(r: R) -> Plan {
    let ids: Vec<String> = r.with(|s| s.channel_ids.iter().cloned().collect());
    if ids.is_empty() {
        return finish(r, Some(Error::service("no Twist channels to notify").context("channel lookup")));
    }
    let mut plans = Vec::new();
    for id in ids {
        let Some(c) = is_channel_id(&id) else {
            let r2 = r.clone();
            plans.push(Plan::defer(move || abort(r2, "post")));
            break;
        };
        let name = c["name"].to_string();
        let digits = c["channel"].trim_start_matches('0');
        let channel_id = if digits.is_empty() { "0".to_owned() } else { digits.to_owned() };
        let payload = vec![
            ("channel_id".to_owned(), channel_id),
            ("title".to_owned(), r.title.clone()),
            ("content".to_owned(), r.body.clone()),
        ];
        let r2 = r.clone();
        plans.push(
            Plan::defer(move || {
                if r2.with(|s| s.aborted) {
                    return Plan::Done;
                }
                fetch(
                    r2,
                    "threads/add",
                    Some(payload),
                    false,
                    Box::new(|r, f| {
                        if f.ok {
                            return Plan::Done;
                        }
                        r.with(|s| s.failed = true);
                        Plan::Fail(match f.status {
                            Some(status) => Error::Http { status, reason: f.content.to_string() },
                            None => Error::transport("Twist connection error"),
                        }
                        .context("post"))
                    }),
                )
            })
            .target(name),
        );
    }
    let r2 = r;
    plans.push(Plan::defer(move || if r2.with(|s| s.aborted) { Plan::Done } else { finish(r2, None) }));
    Plan::all(plans)
}

impl Notify for Twist {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let run = self.run(ctx, msg.title, msg.body);
        let first = msg.index == 0;
        Plan::defer(move || {
            if first {
                run.with(|s| {
                    s.failed = false;
                    s.aborted = false;
                });
            }
            ensure_token(
                run,
                Box::new(|r, ok| {
                    if !ok {
                        return finish(r, Some(Error::service("Twist login failed").context("login")));
                    }
                    if r.with(|s| s.channels.is_empty()) {
                        return post_all(r);
                    }
                    migrate(r, Box::new(|r, _| post_all(r)))
                }),
            )
        })
    }

    fn close(&self, ctx: &Context<'_>) -> Option<Plan> {
        let run = self.run(ctx, "", "");
        if !run.with(|s| json_has_value(&s.token)) {
            return None;
        }
        Some(logout(run))
    }
}

impl Twist {
    fn run(&self, ctx: &Context<'_>, title: &str, body: &str) -> R {
        Arc::new(Run {
            email: self.email.clone(),
            password: self.password.clone(),
            ua: ctx.app_id().to_owned(),
            title: title.to_owned(),
            body: body.to_owned(),
            st: self.state.clone(),
        })
    }
}
