//! Helpers that the Matrix session and its parts share: paths, identifiers and JSON fields.

use serde_json::Value;
use crate::url::quote;
use crate::regex;

/// `key` as a string; `None` for other types.
pub(in super::super) fn get_str(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// The homeserver part of a user id.
pub(in super::super) fn hs_of(user_id: &str) -> Option<String> {
    user_id.split_once(':').map(|(_, hs)| hs.to_owned())
}

/// Whether `url` is a plain `https://` URL: a valid host and port, no user info, no fragment.
pub(in super::super) fn is_secure_http_url(url: &str) -> bool {
    if url.contains('#') {
        return false;
    }
    let Some(rest) = url.get(..8).filter(|p| p.eq_ignore_ascii_case("https://")).and_then(|_| url.get(8..)) else {
        return false;
    };
    let netloc = crate::util::authority(rest);
    if netloc.contains('@') {
        return false;
    }
    let (host, port) = if let Some(stripped) = netloc.strip_prefix('[') {
        match stripped.split_once(']') {
            Some((h, p)) => (h, p.strip_prefix(':')),
            None => return false,
        }
    } else {
        match netloc.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (netloc, None),
        }
    };
    if let Some(p) = port
        && !p.is_empty()
        && crate::parse::port(p).is_none()
    {
        return false;
    }
    !host.is_empty() && crate::parse::is_hostname(&host.to_lowercase(), true, true, true).is_some()
}

pub(super) fn label_of(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), str::to_owned)
}

pub(in super::super) fn match_room_alias(s: &str) -> Option<(String, Option<String>)> {
    let c = regex!(r"(?i)^\s*(?:#|%23)?([A-Za-z0-9._=-]+)(?:(?::|%3A)([A-Za-z0-9.-]+))?\s*$").captures(s)?;
    Some((c[1].to_string(), c.get(2).map(|m| m.as_str().to_owned())))
}

/// Matrix room id / alias / user patterns.
pub(in super::super) fn match_room_id(s: &str) -> Option<(String, Option<String>)> {
    let c = regex!(r"(?i)^\s*(?:!|&#33;|%21)([A-Za-z0-9._=-]+)(?:(?::|%3A)([A-Za-z0-9.-]+))?\s*$").captures(s)?;
    Some((c[1].to_string(), c.get(2).map(|m| m.as_str().to_owned())))
}

pub(in super::super) fn match_user(s: &str) -> Option<(String, Option<String>)> {
    let c = regex!(r"(?i)^\s*(?:@|%40)([A-Za-z0-9._=+/-]+)(?:(?::|%3A)([A-Za-z0-9.-]+))?\s*$").captures(s)?;
    Some((c[1].to_string(), c.get(2).map(|m| m.as_str().to_owned())))
}

pub(super) fn non_empty(s: Option<&str>) -> bool {
    s.is_some_and(|s| !s.is_empty())
}

/// Percent-encode `s`, keeping `/`.
pub(in super::super) fn quote_path(s: &str) -> String {
    quote(s, "/")
}
