//! Twitter / X (`x://`, `twitter://`, `tweet://`): direct messages and public tweets through the X API v2, with image uploads; requests are signed with OAuth 1.0a HMAC-SHA1 (header signature, body never signed).
//!
//! # Differences with Apprise
//!
//! - The `?cache=` user lookup cache lives for one send. *todo*

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use crate::env::Env;
use crate::util::scalar_text;
use crate::error::Error;
use crate::http::{Multipart, Request, Response};
use crate::message::Attachment;
use crate::parse::{parse_bool, parse_list, validate_nonblank};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, quote, unquote, unquote_plus};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "twitter",
    name: "Twitter",
    schemes: &["x", "twitter", "tweet"],
    service_url: "https://twitter.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 10000, body_max_line_count: 0 },
    attachments: true,
    templates: &[
        "{schema}://{ckey}/{csecret}/{akey}/{asecret}",
        "{schema}://{ckey}/{csecret}/{akey}/{asecret}/{targets}",
    ],
    tokens: &[
        Param::new("akey", "Access Key").required().secret(),
        Param::new("asecret", "Access Secret").required().secret(),
        Param::new("ckey", "Consumer Key").required().secret(),
        Param::new("csecret", "Consumer Secret").required().secret(),
        Param::new("target_user", "Target User").prefix("@"),
        Param::new("targets", "Targets").list("/").group(&["target_user"]),
    ],
    params: &[
        Param::new("batch", "Batch Mode").bool(true),
        Param::new("mode", "Message Mode").choice(&["dm", "tweet"]).default("dm").inferred(),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const TWEET_URL: &str = "https://api.twitter.com/2/tweets";
const WHOAMI_URL: &str = "https://api.twitter.com/2/users/me";
const LOOKUP_URL: &str = "https://api.twitter.com/2/users/by";
const DM_URL: &str = "https://api.twitter.com/2/dm_conversations/with/";
const MEDIA_URL: &str = "https://api.x.com/2/media/upload";
const TWEET_IMAGE_BATCH: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Dm,
    Tweet,
}

#[derive(Debug)]
struct Twitter {
    ckey: Secret,
    csecret: Secret,
    akey: Secret,
    asecret: Secret,
    /// `None`: every target given was invalid.
    targets: Option<Vec<String>>,
    mode: Mode,
    batch: bool,
    /// `(x-rate-limit-remaining, x-rate-limit-reset)` of the last response.
    ratelimit: Mutex<(i64, f64)>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut tokens = u.path_segments().into_iter();
    let ckey = u.host();
    let csecret = tokens.next();
    let akey = tokens.next();
    let asecret = tokens.next();
    let mode = match u.param_nonempty("mode") {
        Some(m) => Some(unquote(m)),
        None if u.scheme.starts_with("tweet") => Some("tweet".to_string()),
        None => None,
    };
    let mut raw_targets: Vec<String> = Vec::new();
    if let Some(user) = u.user.as_deref().filter(|s| !s.is_empty()) {
        raw_targets.push(user.to_string());
    }
    raw_targets.extend(tokens);
    if let Some(to) = u.param_nonempty("to") {
        raw_targets.extend(parse_list([to]));
    }
    let batch = u.param("batch").map(|b| parse_bool(b, false)).unwrap_or(true);

    let invalid = |what: &str| SERVICE.err(format!("an invalid Twitter {what} was specified"));
    let ckey = validate_nonblank(&ckey).ok_or_else(|| invalid("Consumer Key"))?;
    let csecret = csecret.as_deref().and_then(validate_nonblank).ok_or_else(|| invalid("Consumer Secret"))?;
    let akey = akey.as_deref().and_then(validate_nonblank).ok_or_else(|| invalid("Access Key"))?;
    let asecret = asecret.as_deref().and_then(validate_nonblank).ok_or_else(|| invalid("Access Secret"))?;

    let mode = match mode {
        Some(m) => {
            let m = m.trim().to_lowercase();
            if "dm".starts_with(&m) {
                Mode::Dm
            } else if "tweet".starts_with(&m) {
                Mode::Tweet
            } else {
                return Err(SERVICE.err("the Twitter message mode specified is invalid"));
            }
        }
        None => Mode::Dm,
    };

    let mut has_error = false;
    let mut targets = Vec::new();
    for t in parse_list(&raw_targets) {
        match crate::regex!(r"(?i)^\s*@?(?P<user>[A-Z0-9_]+)$").captures(&t) {
            Some(c) => targets.push(c["user"].to_string()),
            None => {
                has_error = true;
                log::warn!("Twitter: dropped invalid user");
            }
        }
    }

    Ok(Box::new(Arc::new(Twitter {
        ckey: Secret::new(ckey),
        csecret: Secret::new(csecret),
        akey: Secret::new(akey),
        asecret: Secret::new(asecret),
        targets: if has_error && targets.is_empty() { None } else { Some(targets) },
        mode,
        batch,
        ratelimit: Mutex::new((1, 0.0)),
    })))
}

// OAuth 1.0a (RFC 5849)

/// Percent-encode everything except unreserved characters (`~` included).
fn escape(s: &str) -> String {
    quote(s, "~")
}

struct OAuth1<'a> {
    consumer_key: &'a str,
    consumer_secret: &'a str,
    token: &'a str,
    token_secret: &'a str,
}

impl OAuth1<'_> {
    /// `Authorization` header for `method url` (query parameters signed), plus any form-encoded `body_params`.
    fn header(
        &self,
        method: &str,
        url: &str,
        body_params: &[(String, String)],
        nonce: &str,
        timestamp: &str,
    ) -> String {
        let (base, query) = url.split_once('?').unwrap_or((url, ""));
        let base_uri = normalize_base_uri(base);
        let oauth = [
            ("oauth_nonce", nonce),
            ("oauth_timestamp", timestamp),
            ("oauth_version", "1.0"),
            ("oauth_signature_method", "HMAC-SHA1"),
            ("oauth_consumer_key", self.consumer_key),
            ("oauth_token", self.token),
        ];
        let mut params: Vec<(String, String)> = query
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| match p.split_once('=') {
                Some((k, v)) => (unquote_plus(k), unquote_plus(v)),
                None => (unquote_plus(p), String::new()),
            })
            .collect();
        params.extend(body_params.iter().cloned());
        params.extend(oauth.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        let mut encoded: Vec<(String, String)> = params.iter().map(|(k, v)| (escape(k), escape(v))).collect();
        encoded.sort();
        let normalized = encoded.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");
        let base_string = format!("{}&{}&{}", method.to_ascii_uppercase(), escape(&base_uri), escape(&normalized));
        let key = format!("{}&{}", escape(self.consumer_secret), escape(self.token_secret));
        let signature = crate::crypto::b64(&crate::crypto::hmac_sha1(key.as_bytes(), base_string.as_bytes()));
        let fields = oauth.iter().map(|(k, v)| (*k, v.to_string())).chain([("oauth_signature", signature)]);
        format!("OAuth {}", fields.map(|(k, v)| format!("{k}=\"{}\"", escape(&v))).collect::<Vec<_>>().join(", "))
    }
}

/// RFC 5849 3.4.1.2: lower-case scheme and host, drop default ports.
fn normalize_base_uri(uri: &str) -> String {
    let (scheme, rest) = uri.split_once("://").unwrap_or(("", uri));
    let scheme = scheme.to_ascii_lowercase();
    let (authority, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, "/"),
    };
    let mut host = authority.to_ascii_lowercase();
    if (scheme == "https" && host.ends_with(":443")) || (scheme == "http" && host.ends_with(":80")) {
        host.truncate(host.rfind(':').unwrap_or(host.len()));
    }
    format!("{scheme}://{host}{path}")
}

/// Nonce: a random 64-bit number followed by the timestamp.
fn nonce(timestamp: u64, env: &dyn Env) -> String {
    let mut b = [0u8; 8];
    env.fill_random(&mut b);
    format!("{}{}", u64::from_le_bytes(b), timestamp)
}

type Then = Box<dyn FnOnce(std::result::Result<Value, Error>) -> Plan + Send>;
/// Receives the resolved `(screen name, user id)` DM targets.
type Deliver = Box<dyn FnOnce(Vec<(String, String)>) -> Plan + Send>;

#[derive(Clone)]
struct Media {
    id: String,
    mime: String,
}

impl Twitter {
    fn sign(&self, req: Request, env: &dyn Env) -> Request {
        let ts = env.unix_time();
        let auth = OAuth1 {
            consumer_key: self.ckey.expose(),
            consumer_secret: self.csecret.expose(),
            token: self.akey.expose(),
            token_secret: self.asecret.expose(),
        }
        .header(req.method.as_str(), &req.url, &[], &nonce(ts, env), &ts.to_string());
        req.header("Authorization", auth)
    }

    fn rate_wait(&self, env: &dyn Env) -> Option<Duration> {
        let (remaining, reset) = *self.ratelimit.lock().unwrap_or_else(|e| e.into_inner());
        let now = env.unix_time_ms() as f64 / 1000.0;
        (remaining == 0 && now < reset).then(|| Duration::from_secs_f64(reset - now + 0.5))
    }

    fn record_rate(&self, r: &Response) {
        let remaining = r.header("x-rate-limit-remaining").and_then(|v| v.trim().parse::<i64>().ok());
        let reset = r.header("x-rate-limit-reset").and_then(|v| v.trim().parse::<i64>().ok());
        let mut rl = self.ratelimit.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(rem) = remaining {
            rl.0 = rem;
            if let Some(reset) = reset {
                rl.1 = reset as f64;
            }
        }
    }

    /// Sign and send when execution reaches it, then hand the parsed JSON (or the error) to `then`.
    fn fetch(self: &Arc<Self>, req: Request, env: &Arc<dyn Env>, then: Then) -> Plan {
        let (me, env) = (self.clone(), env.clone());
        Plan::defer(move || {
            let wait = me.rate_wait(env.as_ref());
            let req = me.sign(req, env.as_ref());
            let plan = Plan::http(req, move |res| match res {
                Err(e) => then(Err(e)),
                Ok(r) if !r.is_success() => then(Err(r.http_error())),
                Ok(r) => {
                    me.record_rate(&r);
                    then(Ok(r.json().unwrap_or_else(|| json!({}))))
                }
            });
            match wait {
                Some(d) => Plan::chain([Plan::Sleep(d), plan]),
                None => plan,
            }
        })
    }

    fn json_post(url: &str, ua: &str, payload: &Value) -> Request {
        Request::post(url).header("User-Agent", ua).header("Content-Type", "application/json").json(payload)
    }

    /// Upload the image attachments one by one (stop at the first failure).
    fn upload(self: &Arc<Self>, mut pending: Vec<Attachment>, mut done: Vec<Media>, ctx: Job) -> Plan {
        if pending.is_empty() {
            return match self.mode {
                Mode::Tweet => self.send_tweet(done, ctx),
                Mode::Dm => self.send_dm(done, ctx),
            };
        }
        let a = pending.remove(0);
        let category = if self.mode == Mode::Tweet { "tweet_image" } else { "dm_image" };
        let req = Request::post(MEDIA_URL)
            .header("User-Agent", &ctx.ua)
            .multipart(
                Multipart::with_boundary(ctx.env.random_hex(16))
                    .text("media_category", category)
                    .file("media", a.name.clone(), "", a.data),
            );
        let (me, env) = (self.clone(), ctx.env.clone());
        self.fetch(
            req,
            &env,
            Box::new(move |res| {
                let content = match res {
                    Ok(c) => c,
                    Err(e) => return Plan::Fail(e),
                };
                match content.get("data").and_then(|d| d.get("id")).and_then(scalar_text) {
                    Some(id) => done.push(Media { id, mime: a.mime }),
                    None => log::debug!("Twitter: could not attach {}", a.name),
                }
                me.upload(pending, done, ctx)
            }),
        )
    }

    fn send_tweet(self: &Arc<Self>, media: Vec<Media>, ctx: Job) -> Plan {
        let mut payloads = Vec::new();
        if media.is_empty() {
            payloads.push(json!({"text": ctx.body}));
        } else {
            let size = if self.batch { TWEET_IMAGE_BATCH } else { 1 };
            let mut batches: Vec<Vec<String>> = Vec::new();
            let mut batch: Vec<String> = Vec::new();
            for m in media {
                if !crate::regex!(r"(?i)^image/(png|jpe?g)").is_match(&m.mime) {
                    if !batch.is_empty() {
                        batches.push(std::mem::take(&mut batch));
                    }
                    batches.push(vec![m.id]);
                } else {
                    batch.push(m.id);
                    if batch.len() >= size {
                        batches.push(std::mem::take(&mut batch));
                    }
                }
            }
            if !batch.is_empty() {
                batches.push(batch);
            }
            let total = batches.len();
            for (no, ids) in batches.into_iter().enumerate() {
                let text = if no > 0 || ctx.body.is_empty() {
                    format!("{:02}/{:02}", no + 1, total)
                } else {
                    ctx.body.clone()
                };
                payloads.push(json!({"text": text, "media": {"media_ids": ids}}));
            }
        }
        Plan::all(payloads.into_iter().map(|p| {
            let req = Self::json_post(TWEET_URL, &ctx.ua, &p);
            self.fetch(req, &ctx.env, Box::new(|res| Plan::from_result(res.map(|_| ()))))
        }))
    }

    fn send_dm(self: &Arc<Self>, media: Vec<Media>, ctx: Job) -> Plan {
        let mut payloads = Vec::new();
        if media.is_empty() {
            payloads.push(json!({"text": ctx.body}));
        } else {
            let total = media.len();
            for (no, m) in media.into_iter().enumerate() {
                let text = if no == 0 && !ctx.body.is_empty() {
                    ctx.body.clone()
                } else {
                    format!("{:02}/{:02}", no + 1, total)
                };
                payloads.push(json!({"text": text, "attachments": [{"media_id": m.id}]}));
            }
        }
        let me = self.clone();
        let (ua, env) = (ctx.ua.clone(), ctx.env.clone());
        let deliver = Box::new(move |targets: Vec<(String, String)>| -> Plan {
            if targets.is_empty() {
                return Plan::Fail(Error::service("failed to acquire user(s) to Direct Message via Twitter"));
            }
            let mut plans = Vec::new();
            for p in &payloads {
                for (name, id) in &targets {
                    let req = Self::json_post(&format!("{DM_URL}{id}/messages"), &ctx.ua, p);
                    plans.push(
                        me.fetch(req, &ctx.env, Box::new(|res| Plan::from_result(res.map(|_| ())))).target(format!("@{name}")),
                    );
                }
            }
            Plan::all(plans)
        });
        let targets = self.targets.clone().unwrap_or_default();
        if targets.is_empty() {
            let req = Request::get(WHOAMI_URL).header("User-Agent", &ua);
            return self.fetch(
                req,
                &env,
                Box::new(move |res| {
                    let found = res
                        .ok()
                        .and_then(|c| {
                            let d = c.get("data")?;
                            Some((d.get("username").and_then(scalar_text)?, d.get("id").and_then(scalar_text)?))
                        })
                        .into_iter()
                        .collect();
                    deliver(found)
                }),
            );
        }
        let names = parse_list(&targets);
        let batches: Vec<Vec<String>> = names.chunks(100).map(|c| c.to_vec()).collect();
        self.lookup(batches, Vec::new(), ua, env, deliver)
    }

    /// `_user_lookup`: one GET per 100 names; failed batches are skipped.
    fn lookup(
        self: &Arc<Self>,
        mut batches: Vec<Vec<String>>,
        mut found: Vec<(String, String)>,
        ua: String,
        env: Arc<dyn Env>,
        deliver: Deliver,
    ) -> Plan {
        if batches.is_empty() {
            return deliver(found);
        }
        let batch = batches.remove(0);
        let url =
            format!("{LOOKUP_URL}?usernames={}", batch.iter().map(|n| quote(n, "")).collect::<Vec<_>>().join(","));
        let req = Request::get(url).header("User-Agent", &ua);
        let me = self.clone();
        self.fetch(
            req,
            &env.clone(),
            Box::new(move |res| {
                if let Ok(Value::Object(c)) = res
                    && let Some(Value::Array(entries)) = c.get("data")
                {
                    for e in entries {
                        if let (Some(name), Some(id)) =
                            (e.get("username").and_then(scalar_text), e.get("id").and_then(scalar_text))
                        {
                            match found.iter_mut().find(|(n, _)| *n == name) {
                                Some(slot) => slot.1 = id,
                                None => found.push((name, id)),
                            }
                        }
                    }
                }
                me.lookup(batches, found, ua, env, deliver)
            }),
        )
    }
}

/// Per-send data carried through the continuations.
#[derive(Clone)]
struct Job {
    body: String,
    ua: String,
    env: Arc<dyn Env>,
}

impl Notify for Arc<Twitter> {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_none() {
            return Plan::Fail(Error::Message("no valid Twitter targets to notify".into()));
        }
        let images: Vec<Attachment> =
            msg.attachments.iter().filter(|a| a.mime.to_ascii_lowercase().starts_with("image/")).cloned().collect();
        let job = Job { body: msg.body.to_string(), ua: ctx.app_id().to_string(), env: ctx.env().clone() };
        self.upload(images, Vec::new(), job)
    }

    fn limits(&self, _title: &str, _body: &str, _format: crate::NotifyFormat, _ctx: &Context<'_>) -> Option<Limits> {
        Some(Limits { body_maxlen: if self.mode == Mode::Dm { 10000 } else { 280 }, ..SERVICE.limits })
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    /// Twitter's "Creating a signature" documentation example.
    #[test]
    fn oauth1_twitter_docs_example() {
        let o = OAuth1 {
            consumer_key: "xvz1evFS4wEEPTGEFPHBog",
            consumer_secret: "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
            token: "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
            token_secret: "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
        };
        let h = o.header(
            "post",
            "https://api.twitter.com/1.1/statuses/update.json?include_entities=true",
            &[("status".into(), "Hello Ladies + Gentlemen, a signed OAuth request!".into())],
            "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",
            "1318622958",
        );
        assert!(h.ends_with("oauth_signature=\"hCtSmYh%2BiHYCEqBWrE7C7hYmtUk%3D\""), "{h}");
    }

    /// Known-answer signatures for a fixed nonce and timestamp.
    #[test]
    fn oauth1_known_answers() {
        let o = OAuth1 { consumer_key: "ckey", consumer_secret: "csecret", token: "akey", token_secret: "as/ecret+" };
        let pre = "OAuth oauth_nonce=\"12345678901234567890\", oauth_timestamp=\"1792152000\", \
                   oauth_version=\"1.0\", oauth_signature_method=\"HMAC-SHA1\", \
                   oauth_consumer_key=\"ckey\", oauth_token=\"akey\", ";
        assert_eq!(
            o.header(
                "GET",
                "https://api.twitter.com/2/users/by?usernames=apprise,caronc",
                &[],
                "12345678901234567890",
                "1792152000"
            ),
            format!("{pre}oauth_signature=\"YYzthQfzAvbvPWcF%2B5BL%2FMP7Hbo%3D\"")
        );
        assert_eq!(
            o.header("POST", "https://api.twitter.com/2/tweets", &[], "12345678901234567890", "1792152000"),
            format!("{pre}oauth_signature=\"DFWUNVJRN9XKbqkVz3zra5CsB68%3D\"")
        );
    }

    #[test]
    fn base_uri() {
        assert_eq!(normalize_base_uri("HTTPS://Api.X.com:443/2/a"), "https://api.x.com/2/a");
        assert_eq!(normalize_base_uri("http://h:8080"), "http://h:8080/");
        assert!(nonce(5, crate::testing::test_env()).ends_with('5'));
    }
}
