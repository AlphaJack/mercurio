//! The fixture runner and its request comparators (see [`super`]).

use std::sync::Arc;

use serde_json::{Map, Value, json};

use crate::asset::Asset;
use crate::http::{Request, Response};
use crate::message::{Attachment, Message, NotifyFormat, NotifyType};
use crate::report::Attempt;
use crate::testing::FakeTransport;
use crate::transport::Blocking;
use crate::url::unquote_plus;

use crate::http::parse_multipart;

const IGNORED: &str = "<ignored>";

/// The message fields a case without its own `title`, `body` or `type` gets.
const DEFAULT_MESSAGE: &[(&str, &str)] = &[("title", "Mercurio Title"), ("body", "Mercurio Body"), ("type", "info")];

/// The shared formatting cases a fixture's `pipeline` runs.
const PIPELINE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pipeline.json"));

/// Headers left out of the fixture requests (constant or transport-specific).
const SKIPPED_HEADERS: &[&str] = &["user-agent", "content-length", "accept-encoding", "connection", "host"];

/// Snapshot `value` as `tests/snapshots/<dir>/<name>.snap` (an absolute path, so it holds whatever the build does to source paths).
#[cfg(test)]
pub fn snapshot(dir: &str, name: &str, value: &Value) {
    let mut settings = insta::Settings::clone_current();
    settings.set_snapshot_path(format!("{}/tests/snapshots/{dir}", env!("CARGO_MANIFEST_DIR")));
    settings.set_prepend_module_to_snapshot(false);
    settings.set_omit_expression(true);
    settings.bind(|| insta::assert_yaml_snapshot!(name, value));
}

/// Which API runs the cases: the blocking [`crate::Target`] calls, or [`crate::AsyncMercurio`] on the same fake. The parity suite checks both record the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Front {
    /// [`crate::Target::send_attempts`] and [`crate::Target::close`].
    Blocking,
    /// [`crate::AsyncMercurio::notify`] and [`crate::AsyncMercurio::close`] over [`Blocking`].
    Async,
}

/// What mercurio did for every case of the fixture at `path`, by case name.
pub fn record_fixture(path: &str) -> Value {
    record_fixture_with(path, Front::Blocking)
}

/// [`record_fixture`] through `front`.
#[expect(clippy::disallowed_methods, reason = "the fixture runner reads its fixture file")]
pub fn record_fixture_with(path: &str, front: Front) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut doc: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path}: invalid JSON: {e}"));
    if doc.get("service").is_none() {
        let stem = std::path::Path::new(path).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        doc["service"] = json!(stem.split("__").next().unwrap_or_default());
    }
    expand_pipeline(&mut doc);
    let cases = doc["cases"].as_array().unwrap_or_else(|| panic!("{path}: missing cases"));
    assert!(!cases.is_empty(), "{path}: no cases");
    let mut out = Map::new();
    for case in cases {
        let name = case["name"].as_str().unwrap_or_else(|| panic!("{path}: a case has no name"));
        let prev = out.insert(name.to_string(), record_case_with(&doc, &with_defaults(&doc, case), front));
        assert!(prev.is_none(), "{path}: duplicate case {name}");
    }
    let mut out = Value::Object(out);
    mask_version(&mut out);
    out
}

/// Replace the crate version in every string with `<version>`, so a release does not change the snapshots.
fn mask_version(v: &mut Value) {
    match v {
        Value::String(s) if s.contains(env!("CARGO_PKG_VERSION")) => {
            let re = crate::regex!(r"(^|[^0-9.])([0-9]+\.[0-9]+\.[0-9]+)($|[^0-9.])");
            let masked = re.replace_all(s, |c: &crate::re::Captures<'_>| {
                let ver = if &c[2] == env!("CARGO_PKG_VERSION") { "<version>" } else { &c[2] };
                format!("{}{ver}{}", &c[1], &c[3])
            });
            *s = masked.into_owned();
        }
        Value::Array(a) => {
            for x in a {
                mask_version(x);
            }
        }
        Value::Object(m) => {
            for x in m.values_mut() {
                mask_version(x);
            }
        }
        Value::String(_) | Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn ignores(case: &Value) -> Vec<String> {
    case.get("ignore")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// What mercurio did for one case (after [`with_defaults`]).
pub fn record_case(doc: &Value, case: &Value) -> Value {
    record_case_with(doc, case, Front::Blocking)
}

/// Send each of `msgs` to `target` through `front`: per send, every attempt and the number of requests made so far. `close` runs the target's clean-up at the end.
pub(super) fn run_sends(
    front: Front,
    target: crate::Target,
    msgs: &[Message],
    fake: &Arc<FakeTransport>,
    asset: &Asset,
    close: bool,
) -> Vec<(Vec<Attempt>, usize)> {
    match front {
        Front::Blocking => {
            let out =
                msgs.iter().map(|m| (target.send_attempts(m, fake.as_ref(), asset), fake.requests().len())).collect();
            if close {
                target.close(fake.as_ref(), asset);
            }
            out
        }
        Front::Async => pollster::block_on(async {
            let mut m = crate::AsyncMercurio::with_transport(Arc::new(Blocking(fake.clone()))).asset(asset.clone());
            m.push(target);
            let mut out = Vec::new();
            for msg in msgs {
                let mut report = m.notify(msg).await;
                out.push((report.entries.remove(0).attempts, fake.requests().len()));
            }
            if close {
                m.close().await;
            }
            out
        }),
    }
}

fn record_case_with(doc: &Value, case: &Value, front: Front) -> Value {
    let url = case["url"].as_str().expect("case has no url").replace("{FIXTURES}", &fixtures_dir());
    let target = match crate::parse(&url) {
        Ok(t) => t,
        Err(e) => return json!({"valid": false, "error": e.to_string()}),
    };
    let ignore = ignores(case);
    if let Some(c) = super::events::comparator(doc["service"].as_str().unwrap_or("")) {
        return super::events::record(c, doc, case, target, &ignore, front);
    }
    let fake = case_transport(case);
    let asset = fixture_asset(doc);
    if case.get("sends").is_some() || case.get("messages").is_some() {
        return record_sends(case, target, &fake, &asset, &ignore, front);
    }
    let (mut attempts, _) = run_sends(front, target, &[case_message(case)], &fake, &asset, true).remove(0);
    let delivery = attempts.pop().map(|a| a.delivery).unwrap_or_default();
    let mut out = outcome(delivery.is_success(), delivery.errors().map(ToString::to_string).collect());
    out["requests"] = requests(&fake.requests(), &ignore);
    out
}

/// `{valid, ok, errors}` of a delivery.
pub fn outcome(ok: bool, errors: Vec<String>) -> Value {
    let mut out = json!({"valid": true, "ok": ok});
    if !errors.is_empty() {
        out["errors"] = json!(errors);
    }
    out
}

/// One target (and so one store) notified once per entry of `messages` or `sends` times.
fn record_sends(
    case: &Value,
    target: crate::Target,
    fake: &Arc<FakeTransport>,
    asset: &Asset,
    ignore: &[String],
    front: Front,
) -> Value {
    let base = case_message(case);
    let messages: Vec<Value> = match case.get("messages").and_then(Value::as_array) {
        Some(m) => m.clone(),
        None => vec![json!({}); case.get("sends").and_then(Value::as_u64).unwrap_or(1) as usize],
    };
    let msgs: Vec<Message> = messages
        .iter()
        .map(|m| {
            let mut msg = base.clone();
            if let Some(t) = m.get("title").and_then(Value::as_str) {
                msg.title = t.to_string();
            }
            if let Some(b) = m.get("body").and_then(Value::as_str) {
                msg.body = b.to_string();
            }
            if let Some(t) = m.get("type").and_then(Value::as_str) {
                msg.kind = NotifyType::parse(t).unwrap_or_default();
            }
            msg
        })
        .collect();
    let url_id = target.url_id(asset);
    let mut before = fake.requests().len();
    let sends: Vec<Value> = run_sends(front, target, &msgs, fake, asset, false)
        .into_iter()
        .map(|(attempts, after)| {
            let last = attempts.last().map(|a| &a.delivery);
            let errors = last.map(|d| d.errors().map(ToString::to_string).collect()).unwrap_or_default();
            let mut send = outcome(last.is_some_and(|d| d.is_success()), errors);
            send.as_object_mut().unwrap().remove("valid");
            send["attempts"] = json!(attempts.len());
            send["requests"] = requests(&fake.requests()[before..after], ignore);
            before = after;
            send
        })
        .collect();
    json!({"valid": true, "url_id": url_id, "sends": sends})
}

/// Requests as plain data, with `ignore` masks applied.
pub fn requests(reqs: &[Request], ignore: &[String]) -> Value {
    Value::Array(reqs.iter().map(|r| request(r, ignore)).collect())
}

fn masked(ignore: &[String], prefix: &str, key: &str) -> bool {
    ignore.iter().any(|i| i.strip_prefix(prefix).is_some_and(|k| k.eq_ignore_ascii_case(key)))
}

fn request(g: &Request, ignore: &[String]) -> Value {
    let mut headers = Map::new();
    for (k, v) in &g.headers {
        let lk = k.to_ascii_lowercase();
        if SKIPPED_HEADERS.contains(&lk.as_str()) {
            continue;
        }
        let v = if masked(ignore, "header:", &lk) {
            IGNORED.to_string()
        } else if lk == "content-type" && v.starts_with("multipart/") {
            // The boundary is random.
            v.split(';').next().unwrap_or("").to_string()
        } else {
            v.clone()
        };
        headers.insert(k.clone(), Value::String(v));
    }
    let (base, query) = match g.url.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (g.url.as_str(), None),
    };
    let path_start =
        base.find("://").and_then(|i| base.get(i + 3..)?.find('/').map(|j| i + 3 + j)).unwrap_or(base.len());
    let (head, path) = base.split_at(path_start);
    let mut url = format!("{head}{}", mask_path(path, ignore));
    if let Some(q) = query {
        let pairs: Vec<String> = q
            .split('&')
            .map(|p| match p.split_once('=') {
                Some((k, _)) if masked(ignore, "query:", k) => format!("{k}={IGNORED}"),
                _ => p.to_string(),
            })
            .collect();
        url = format!("{url}?{}", pairs.join("&"));
    }
    json!({"method": g.method.as_str(), "url": url, "headers": headers, "body": body(g, ignore)})
}

fn body(g: &Request, ignore: &[String]) -> Value {
    if g.body.is_empty() {
        return Value::Null;
    }
    let ct = g.header_value("content-type").unwrap_or("");
    let lct = ct.to_ascii_lowercase();
    if lct.contains("json")
        && let Ok(mut v) = serde_json::from_slice::<Value>(&g.body)
    {
        for ptr in ignore.iter().filter_map(|i| i.strip_prefix("json:")) {
            blank(&mut v, ptr);
        }
        return json!({"json": v});
    }
    if lct.starts_with("application/x-www-form-urlencoded") {
        let pairs: Vec<Value> = parse_form(&g.body_text())
            .into_iter()
            .map(|(k, v)| if masked(ignore, "form:", &k) { json!([k, IGNORED]) } else { json!([k, v]) })
            .collect();
        return json!({"form": pairs});
    }
    if lct.starts_with("multipart/") {
        let mut parts = parse_multipart(ct, &g.body);
        for p in &mut parts {
            if let Some(o) = p.as_object_mut()
                && o.get("name").and_then(Value::as_str).is_some_and(|n| masked(ignore, "part:", n))
            {
                o.insert("value".into(), json!(IGNORED));
                o.remove("b64");
            }
        }
        return json!({"multipart": parts});
    }
    // A masked body is masked whatever it holds (random bytes can be UTF-8).
    if ignore.iter().any(|i| i == "bytes") {
        return json!({"bytes": IGNORED});
    }
    if ignore.iter().any(|i| i == "text") {
        return json!({"text": IGNORED});
    }
    match std::str::from_utf8(&g.body) {
        Ok(t) => json!({"text": t}),
        Err(_) => json!({"bytes": crate::crypto::b64(&g.body)}),
    }
}

/// Append the cases of `tests/fixtures/pipeline.json` when the fixture has a `pipeline` object: each case runs on its `url` (plus the case's `query`) with its other fields (`responses`, `ignore`, ...).
fn expand_pipeline(doc: &mut Value) {
    let Some(base) = doc.get("pipeline").and_then(Value::as_object).cloned() else { return };
    let shared: Value = serde_json::from_str(PIPELINE).unwrap_or_else(|e| panic!("pipeline.json: {e}"));
    let url = base.get("url").and_then(Value::as_str).unwrap_or_else(|| panic!("pipeline: missing url"));
    let mut added = Vec::new();
    for case in shared["cases"].as_array().into_iter().flatten() {
        let mut c = base.clone();
        let query = case["query"].as_str().unwrap_or_default();
        let sep = if url.contains('?') { '&' } else { '?' };
        let full = if query.is_empty() { url.to_string() } else { format!("{url}{sep}{query}") };
        c.insert("url".into(), json!(full));
        for (k, v) in case.as_object().into_iter().flatten().filter(|(k, _)| *k != "query") {
            c.insert(k.clone(), v.clone());
        }
        added.push(Value::Object(c));
    }
    if let Some(cases) = doc["cases"].as_array_mut() {
        cases.extend(added);
    }
}

/// `case` with the fixture's `defaults` (`title`, `body`, `type`; built-in values when the fixture has none) filled in where the case has none.
pub fn with_defaults(doc: &Value, case: &Value) -> Value {
    let mut case = case.clone();
    let builtin: Map<String, Value> = DEFAULT_MESSAGE.iter().map(|(k, v)| ((*k).to_string(), json!(v))).collect();
    let defaults = doc.get("defaults").and_then(Value::as_object).unwrap_or(&builtin);
    if let Some(c) = case.as_object_mut() {
        for (k, v) in defaults {
            c.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
    case
}

/// The [`Asset`] a fixture's targets run with: its `asset` identity (`app_id`, `app_desc`, `app_url`) over the defaults, with `example.org` app and image URLs.
pub fn fixture_asset(doc: &Value) -> Asset {
    // Fixed placeholder URLs: snapshots do not depend on where mercurio is hosted.
    let mut asset = Asset {
        app_url: "https://example.org".into(),
        image_url_mask: Some("https://example.org/{TYPE}-{XY}.png".into()),
        image_url_logo: Some("https://example.org/logo.png".into()),
        ..Asset::default()
    };
    let field = |k: &str| doc.get("asset").and_then(|a| a.get(k)).and_then(Value::as_str).map(str::to_string);
    if let Some(v) = field("app_id") {
        asset.app_id = v;
    }
    if let Some(v) = field("app_desc") {
        asset.app_desc = v;
    }
    if let Some(v) = field("app_url") {
        asset.app_url = v;
    }
    asset
}

/// Build the message a case describes (after [`with_defaults`]).
pub fn case_message(case: &Value) -> Message {
    let title = case.get("title").and_then(Value::as_str).unwrap_or_default();
    let body = case.get("body").and_then(Value::as_str).unwrap_or_default();
    let mut msg = Message::new(body).title(title);
    if let Some(t) = case.get("type").and_then(Value::as_str) {
        msg.kind = NotifyType::parse(t).unwrap_or_default();
    }
    if let Some(f) = case.get("format").and_then(Value::as_str) {
        msg.format = NotifyFormat::parse(f);
    }
    if let Some(atts) = case.get("attachments").and_then(Value::as_array) {
        for a in atts {
            let name = a["name"].as_str().unwrap_or("file.txt");
            let mime = a.get("mime").and_then(Value::as_str).unwrap_or_else(|| crate::message::guess_mime(name));
            let data = match (a.get("b64").and_then(Value::as_str), a.get("text").and_then(Value::as_str)) {
                (Some(b), _) => crate::crypto::b64_decode(b).unwrap_or_default(),
                (None, Some(t)) => t.as_bytes().to_vec(),
                _ => Vec::new(),
            };
            msg.attachments.push(Attachment::new(name, mime, data));
        }
    }
    msg
}

/// Scripted responses for a case.
pub fn case_transport(case: &Value) -> Arc<FakeTransport> {
    let fake = Arc::new(FakeTransport::new());
    if let Some(rs) = case.get("responses").and_then(Value::as_array) {
        for r in rs {
            let status = r.get("status").and_then(Value::as_u64).unwrap_or(200) as u16;
            let body = match r.get("body") {
                Some(Value::String(s)) => s.clone().into_bytes(),
                Some(v @ (Value::Object(_) | Value::Array(_))) => serde_json::to_vec(v).unwrap(),
                _ => b"{}".to_vec(),
            };
            let mut resp = Response::new(status, body);
            let mut has_ct = false;
            if let Some(h) = r.get("headers").and_then(Value::as_object) {
                for (k, v) in h {
                    has_ct |= k.eq_ignore_ascii_case("content-type");
                    resp = resp.with_header(k, v.as_str().unwrap_or(""));
                }
            }
            if !has_ct {
                resp = resp.with_header("Content-Type", "application/json");
            }
            if r.get("error").and_then(Value::as_bool).unwrap_or(false) {
                fake.fail(crate::Error::transport("scripted connection error"));
            } else {
                fake.respond_with(resp);
            }
        }
    }
    fake
}

/// `{FIXTURES}` in a case URL expands to the absolute `tests/fixtures/data` directory.
pub fn fixtures_dir() -> String {
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/data").to_string()
}

/// Apply `path:<index>` and `path~<regex>` ignores to a decoded URL path (same rules as the fixtures).
fn mask_path(path: &str, ignore: &[String]) -> String {
    let mut path = path.to_string();
    for rule in ignore {
        if let Some(re) = rule.strip_prefix("path~") {
            match crate::re::Regex::new(re) {
                Ok(re) => path = re.replace_all(&path, IGNORED).into_owned(),
                Err(e) => panic!("ignore {rule:?}: {e}"),
            }
        } else if let Some(index) = rule.strip_prefix("path:") {
            let index: isize = index.parse().unwrap_or_else(|_| panic!("ignore {rule:?}: not a segment index"));
            let mut segs: Vec<String> = path.split('/').map(str::to_string).collect();
            let real: Vec<usize> = segs.iter().enumerate().filter(|(_, s)| !s.is_empty()).map(|(i, _)| i).collect();
            let pos = if index < 0 { real.len().checked_sub(index.unsigned_abs()) } else { Some(index as usize) };
            if let Some(&i) = pos.and_then(|p| real.get(p)) {
                segs[i] = IGNORED.into();
            }
            path = segs.join("/");
        }
    }
    path
}

fn parse_form(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (unquote_plus(k), unquote_plus(v)),
            None => (unquote_plus(p), String::new()),
        })
        .collect()
}

/// Set the value at a JSON pointer (`/a/0/b`, `*` matches any key/index) to null.
pub(super) fn blank(v: &mut Value, path: &str) {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    blank_parts(v, &parts);
}

fn blank_parts(v: &mut Value, parts: &[&str]) {
    let Some((head, rest)) = parts.split_first() else {
        *v = Value::Null;
        return;
    };
    match v {
        Value::Object(m) => {
            if *head == "*" {
                for child in m.values_mut() {
                    blank_parts(child, rest);
                }
            } else if let Some(child) = m.get_mut(*head) {
                blank_parts(child, rest);
            }
        }
        Value::Array(a) => {
            if *head == "*" {
                for child in a.iter_mut() {
                    blank_parts(child, rest);
                }
            } else if let Ok(i) = head.parse::<usize>()
                && let Some(child) = a.get_mut(i)
            {
                blank_parts(child, rest);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(r: &[&str]) -> Vec<String> {
        r.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn path_ignores() {
        let p = "/_matrix/client/v3/rooms/!r/send/m.room.message/abc-123";
        assert_eq!(mask_path(p, &rules(&["path:-1"])), "/_matrix/client/v3/rooms/!r/send/m.room.message/<ignored>");
        assert_eq!(mask_path(p, &rules(&["path:0"])), "/<ignored>/client/v3/rooms/!r/send/m.room.message/abc-123");
        assert_eq!(mask_path(p, &rules(&["path:99", "query:x"])), p);
        assert_eq!(mask_path(p, &rules(&[r"path~/send/[^/]+/[a-z0-9-]+$"])), "/_matrix/client/v3/rooms/!r<ignored>");
        assert_eq!(mask_path("/a//b/", &rules(&["path:1"])), "/a//<ignored>/");
    }

    #[test]
    fn blank_pointer_wildcards() {
        let mut v = serde_json::json!({"a": [{"b": 1, "c": 2}, {"b": 3}]});
        blank(&mut v, "/a/*/b");
        assert_eq!(v, serde_json::json!({"a": [{"b": null, "c": 2}, {"b": null}]}));
    }

    #[test]
    fn every_event_service_has_a_comparator() {
        for s in ["email", "deltachat", "smpp", "irc", "aprs", "mqtt", "syslog", "rsyslog", "xmpp", "gnome"] {
            assert!(super::super::events::comparator(s).is_some(), "{s}");
        }
        assert!(super::super::events::comparator("gotify").is_none());
    }
}
