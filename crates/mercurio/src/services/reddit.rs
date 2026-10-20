//! Reddit (`reddit://`): posts to subreddits through the Reddit API.
//!
//! The OAuth access token is kept for the lifetime of the parsed URL (a non-persistent store entry) and replaced whenever a failed submit logs in again.
//!
//! # Differences with Apprise
//!
//! - The token is dropped after `expires_in` (Apprise computes the expiry but never checks it). *intentional*
//! - `X-RateLimit-Reset` is read as the seconds left in the window, as Reddit documents it; Apprise reads it as a Unix time, so its back-off never waits. The budget is kept for the life of the URL, as in Apprise. *intentional*
//! - After a failed submit Apprise retries with the previous bearer token (stale headers) -> mercurio retries with the fresh one. *intentional*

use std::sync::Arc;

use super::_ratelimit::{RateLimit, Reset};

use serde_json::Value;

use crate::env::Env;
use crate::error::Error;
use crate::http::{Request, Response};
use crate::parse::{parse_list, validate_nonblank, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef, UrlIdentifier};
use crate::store::StoreRef;
use crate::url::{ParsedUrl, parse_url, unquote};
use crate::util::{json_int, json_text, json_has_value};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "reddit",
    name: "Reddit",
    schemes: &["reddit"],
    service_url: "https://reddit.com",
    parse,
    limits: Limits { title_maxlen: 300, body_maxlen: 6000, body_max_line_count: 0 },
    formats: &[NotifyFormat::Markdown],
    templates: &[
        "{schema}://{user}:{password}@{app_id}/{app_secret}/{targets}",
    ],
    tokens: &[
        Param::new("app_id", "Application ID").required().secret().pattern("^[a-z0-9_-]+$"),
        Param::new("app_secret", "Application Secret").required().secret().pattern("^[a-z0-9_-]+$"),
        Param::new("password", "Password").required().secret(),
        Param::new("target_subreddit", "Target Subreddit"),
        Param::new("targets", "Targets").list("/").required().group(&["target_subreddit"]),
        Param::new("user", "User Name").required(),
    ],
    params: &[
        Param::new("ad", "Is Ad?").bool(false),
        Param::new("flair_id", "Flair ID"),
        Param::new("flair_text", "Flair Text"),
        Param::new("kind", "Kind").choice(&["auto", "self", "link"]).default("auto"),
        Param::new("nsfw", "NSFW").bool(false),
        Param::new("resubmit", "Resubmit Flag").bool(false),
        Param::new("spoiler", "Is Spoiler").bool(false),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const AUTH_URL: &str = "https://www.reddit.com/api/v1/access_token";
const SUBMIT_URL: &str = "https://oauth.reddit.com/api/submit";
const KINDS: &[&str] = &["auto", "self", "link"];

#[derive(Debug, Clone)]
struct Creds {
    user: String,
    password: Secret,
    client_id: Secret,
    client_secret: Secret,
    /// Where the token is kept (set per send).
    store: Option<StoreRef>,
    /// The app id (set per send).
    user_agent: String,
    /// The request budget, shared by every send of this URL.
    rate: Arc<RateLimit>,
    /// The clock and random source (set per send).
    env: Arc<dyn Env>,
}

const TOKEN_KEY: &str = "access_token";
/// Added to every rate-limit wait (Apprise's `clock_skew`).
const CLOCK_SKEW: std::time::Duration = std::time::Duration::from_secs(10);
/// Access token lifetime, in seconds.
const TOKEN_LIFETIME: f64 = 3600.0;

#[derive(Debug)]
struct Reddit {
    creds: Arc<Creds>,
    subreddits: Vec<String>,
    kind: &'static str,
    nsfw: bool,
    resubmit: bool,
    spoiler: bool,
    flair_id: Option<String>,
    flair_text: Option<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let kind = match u.param_nonempty("kind") {
        Some(k) => unquote(&k.trim().to_lowercase()),
        None => "auto".to_string(),
    };
    let nsfw = SERVICE.flag(u, "nsfw");
    let resubmit = SERVICE.flag(u, "resubmit");
    let spoiler = SERVICE.flag(u, "spoiler");
    // `?ad=` and `?replies=` are ignored: posts are never ads and always accept replies.
    let flair_text = SERVICE.text(u, "flair_text");
    let flair_id = SERVICE.text(u, "flair_id");
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }
    let app_id = match u.param("app_id") {
        Some(a) => unquote(a),
        None => u.host(),
    };
    let app_secret = match u.param("app_secret") {
        Some(s) => Some(unquote(s)),
        None if targets.is_empty() => None,
        None => Some(targets.remove(0)),
    };

    let kind = kind.trim().to_lowercase();
    let kind = KINDS
        .iter()
        .copied()
        .find(|k| *k == kind)
        .ok_or_else(|| SERVICE.err("an invalid Reddit message kind was specified"))?;
    let user = u
        .user()
        .as_deref()
        .and_then(validate_nonblank)
        .ok_or_else(|| SERVICE.err("an invalid Reddit User ID was specified"))?;
    let password = u
        .password()
        .as_deref()
        .and_then(validate_nonblank)
        .ok_or_else(|| SERVICE.err("an invalid Reddit Password was specified"))?;
    let client_id = validate_regex(&app_id, r"^[a-z0-9_-]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Reddit App ID was specified"))?;
    let client_secret = app_secret
        .as_deref()
        .and_then(|s| validate_regex(s, r"^[a-z0-9_-]+$", "i", true))
        .ok_or_else(|| SERVICE.err("an invalid Reddit App Secret was specified"))?;
    let subreddits = parse_list(targets)
        .into_iter()
        .map(|s| s.trim_start_matches('#').to_string())
        .filter(|s| !s.is_empty())
        .collect();

    Ok(Box::new(Reddit {
        creds: Arc::new(Creds {
            user,
            password: Secret::new(password),
            client_id: Secret::new(client_id),
            client_secret: Secret::new(client_secret),
            store: None,
            user_agent: String::new(),
            rate: RateLimit::new(Reset::SecondsLeft, CLOCK_SKEW),
            env: parse_time_env(),
        }),
        subreddits,
        kind,
        nsfw,
        resubmit,
        spoiler,
        flair_id,
        flair_text,
    }))
}

/// Outcome of [`fetch`]: `Abort` is an unexpected response that ends the whole send.
enum Fetched {
    Ok(Value),
    Fail(Error),
    Abort(Error),
}

/// Body handling shared by every response.
fn process(r: &Response) -> Fetched {
    let Some(content) = r.json() else {
        return Fetched::Fail(r.http_error());
    };
    if r.status != 200 {
        return Fetched::Fail(r.http_error());
    }
    if json_has_value(&content) {
        let Some(obj) = content.as_object() else {
            return Fetched::Abort(Error::Service("unexpected Reddit response".into()));
        };
        if let Some(j) = obj.get("json") {
            let Some(j) = j.as_object() else {
                return Fetched::Abort(Error::Service("unexpected Reddit response".into()));
            };
            if j.get("errors").is_some_and(json_has_value) {
                return Fetched::Fail(Error::Service("Reddit reported errors".into()));
            }
        }
    }
    Fetched::Ok(content)
}

fn form_request(url: &str, payload: &[(String, String)], ua: &str) -> Request {
    Request::post(url).header("User-Agent", ua).form(payload)
}

/// One submit per subreddit: `(subreddit, form payload)`.
type Submits = Vec<(String, Vec<(String, String)>)>;

type Next = Box<dyn FnOnce(Fetched, Option<String>) -> Plan + Send>;

/// A placeholder until the first send sets the transport's [`Env`] (as `store` and `user_agent`).
#[expect(clippy::disallowed_methods, reason = "replaced by the transport's Env on every send")]
fn parse_time_env() -> Arc<dyn Env> {
    crate::env::system().clone()
}

/// Submit or log in: the URL and auth depend on whether a token is held.
fn fetch(creds: Arc<Creds>, token: Option<String>, payload: Vec<(String, String)>, next: Next) -> Plan {
    let req = match &token {
        Some(t) => form_request(SUBMIT_URL, &payload, &creds.user_agent).bearer(t),
        None => form_request(AUTH_URL, &payload, &creds.user_agent)
            .basic_auth(creds.client_id.expose(), Some(creds.client_secret.expose())),
    };
    let (rate, env) = (creds.rate.clone(), creds.env.clone());
    rate.send(req, &[200], &env, move |res| {
        let r = match res {
            Ok(r) => r,
            Err(e) => return next(Fetched::Fail(e), token),
        };
        if r.status != 200 && token.is_some() {
            // Countermeasure: log in again and retry once.
            let (ua, rate, env) = (creds.user_agent.clone(), creds.rate.clone(), creds.env.clone());
            return login(
                creds,
                Box::new(move |res, new_token| match (res, new_token) {
                    (Fetched::Ok(_), Some(t)) => {
                        let req = form_request(SUBMIT_URL, &payload, &ua).bearer(&t);
                        rate.send(req, &[200], &env, move |res| match res {
                            Ok(r) => next(process(&r), Some(t)),
                            Err(e) => next(Fetched::Fail(e), Some(t)),
                        })
                    }
                    (Fetched::Abort(e), _) => Plan::Fail(e.context("login").context("post")),
                    (Fetched::Fail(e), t) => next(Fetched::Fail(e.context("login")), t),
                    (Fetched::Ok(_), None) => {
                        next(Fetched::Fail(Error::Service("Reddit login failed".into()).context("login")), None)
                    }
                }),
            );
        }
        next(process(&r), token)
    })
}

/// Log in; on success hands the new token to `next`.
fn login(creds: Arc<Creds>, next: Next) -> Plan {
    // Forget the cached token until the login works.
    if let Some(s) = &creds.store {
        s.clear(&[TOKEN_KEY]);
    }
    let store = creds.store.clone();
    let payload = vec![
        ("grant_type".to_string(), "password".to_string()),
        ("username".to_string(), creds.user.clone()),
        ("password".to_string(), creds.password.expose().to_string()),
    ];
    fetch(
        creds,
        None,
        payload,
        Box::new(move |res, _| match res {
            Fetched::Ok(content) => {
                if !json_has_value(&content) {
                    return next(Fetched::Fail(Error::Service("Reddit login failed".into())), None);
                }
                let Some(obj) = content.as_object() else {
                    return next(Fetched::Abort(Error::Service("unexpected Reddit response".into())), None);
                };
                if obj.get("expires_in").is_some_and(|v| json_int(v).is_none()) {
                    return next(Fetched::Abort(Error::Service("unexpected Reddit expires_in".into())), None);
                }
                let token = obj.get("access_token").filter(|v| json_has_value(v)).map(json_text);
                match token {
                    Some(t) => {
                        if let Some(s) = &store {
                            let secs = obj.get("expires_in").and_then(json_int).map_or(TOKEN_LIFETIME, |n| n as f64);
                            let ttl = std::time::Duration::from_secs_f64(secs.clamp(0.0, 1e9));
                            s.remember(TOKEN_KEY, Value::String(t.clone()), Some(ttl));
                        }
                        next(Fetched::Ok(content), Some(t))
                    }
                    None => next(Fetched::Fail(Error::Service("Reddit login returned no token".into())), None),
                }
            }
            other @ (Fetched::Fail(_) | Fetched::Abort(_)) => next(other, None),
        }),
    )
}

/// Submit to `subs[i..]`, carrying the current token state.
fn submit_from(creds: Arc<Creds>, token: Option<String>, subs: Arc<Submits>, i: usize) -> Plan {
    let Some((sub, payload)) = subs.get(i).cloned() else {
        return Plan::Done;
    };
    let creds2 = creds.clone();
    fetch(
        creds,
        token,
        payload,
        Box::new(move |res, token| {
            let here = match res {
                Fetched::Ok(_) => Plan::Done,
                Fetched::Fail(e) => Plan::Fail(e.context("post")),
                Fetched::Abort(e) => return Plan::Fail(e.context("post")),
            };
            Plan::all([here.target(sub), submit_from(creds2, token, subs, i + 1)])
        }),
    )
}

impl Notify for Reddit {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let link = if msg.format == NotifyFormat::Markdown && !msg.passthrough {
            crate::convert::markup::unescape(msg.body)
        } else {
            msg.body.to_string()
        };
        let kind = if self.kind == "auto" {
            match parse_url(&link) {
                Some(p) if p.scheme.starts_with("http") && !p.host.is_empty() => "link",
                _ => "self",
            }
        } else {
            self.kind
        };
        let title = if msg.title.is_empty() { ctx.app_desc() } else { msg.title };
        let subs: Submits = self
            .subreddits
            .iter()
            .rev()
            .map(|sr| {
                let mut p: Vec<(String, String)> = vec![
                    ("ad".into(), false.to_string()),
                    ("api_type".into(), "json".into()),
                    ("extension".into(), "json".into()),
                    ("sr".into(), sr.clone()),
                    ("title".into(), title.to_string()),
                    ("kind".into(), kind.to_string()),
                    ("nsfw".into(), self.nsfw.to_string()),
                    ("resubmit".into(), self.resubmit.to_string()),
                    ("sendreplies".into(), true.to_string()),
                    ("spoiler".into(), self.spoiler.to_string()),
                ];
                if let Some(f) = &self.flair_id {
                    p.push(("flair_id".into(), f.clone()));
                }
                if let Some(f) = &self.flair_text {
                    p.push(("flair_text".into(), f.clone()));
                }
                if kind == "link" {
                    p.push(("url".into(), link.clone()));
                } else {
                    p.push(("text".into(), msg.body.to_string()));
                }
                (sr.clone(), p)
            })
            .collect();
        let subs = Arc::new(subs);
        let creds = Arc::new(Creds {
            store: Some(ctx.store()),
            user_agent: ctx.app_id().to_string(),
            env: ctx.env().clone(),
            ..(*self.creds).clone()
        });
        if let Some(token) = ctx.store.get_str(TOKEN_KEY).filter(|t| !t.is_empty()) {
            if subs.is_empty() {
                return Plan::Fail(Error::Service("there are no Reddit subreddits to notify".into()));
            }
            return submit_from(creds, Some(token), subs, 0);
        }
        login(
            creds.clone(),
            Box::new(move |res, token| match res {
                Fetched::Ok(_) if subs.is_empty() => {
                    Plan::Fail(Error::Service("there are no Reddit subreddits to notify".into()))
                }
                Fetched::Ok(_) => submit_from(creds, token, subs, 0),
                Fetched::Fail(e) | Fetched::Abort(e) => Plan::Fail(e.context("login")),
            }),
        )
    }

    fn url_identifier(&self) -> UrlIdentifier {
        let c = &self.creds;
        UrlIdentifier::parts([
            "reddit",
            c.client_id.expose(),
            c.client_secret.expose(),
            c.user.as_str(),
            c.password.expose(),
        ])
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn rate_limit_is_kept_between_sends() {
        use crate::http::Response;
        let login = Response::new(200, br#"{"access_token": "tok", "expires_in": 3600}"#.to_vec());
        let ok = || Response::new(200, br#"{"json": {"errors": []}}"#.to_vec());
        // `X-RateLimit-Reset` is the seconds left; the wait adds the 10 s clock skew.
        let spent = ok().with_header("X-RateLimit-Remaining", "0").with_header("X-RateLimit-Reset", "30");
        let url = "reddit://user:password@app-id/app-secret/mercurio";
        let wait = super::super::_ratelimit::second_send_waits(url, vec![login, spent], ok());
        assert!(wait > std::time::Duration::from_secs(38) && wait <= std::time::Duration::from_secs(40), "{wait:?}");
    }
}
