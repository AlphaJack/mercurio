//! Folding YAML settings into a service URL.

use super::spec::{group_prefix, is_reserved, prefixes};
use super::yaml::Yaml;
use crate::url::{parse_url_unverified, quote, unquote};

/// `VALID_TOKEN.match`: `[a-z0-9][a-z0-9_]+` at the start.
pub(super) fn valid_token(key: &str) -> bool {
    crate::regex!(r"(?i)^[a-z0-9][a-z0-9_]+").is_match(key)
}

/// YAML scalar as a URL value (scalars as text, booleans as `yes`/`no`).
pub(super) fn url_value(v: &Yaml) -> Option<String> {
    match v {
        Yaml::Null => None,
        Yaml::Bool(b) => Some(if *b { "yes" } else { "no" }.into()),
        Yaml::Int(_) | Yaml::Float(_) => Some(v.to_text()),
        Yaml::Str(s) => Some(s.clone()),
        Yaml::Seq(items) => {
            let mut parts = Vec::new();
            flatten(items, &mut parts);
            if parts.is_empty() { None } else { Some(parts.join(",")) }
        }
        Yaml::Map(_) => None,
    }
}

pub(super) fn flatten(items: &[Yaml], out: &mut Vec<String>) {
    for i in items {
        match i {
            Yaml::Seq(s) => flatten(s, out),
            Yaml::Map(_) | Yaml::Null => {}
            other @ (Yaml::Bool(_) | Yaml::Int(_) | Yaml::Float(_) | Yaml::Str(_)) => out.extend(url_value(other)),
        }
    }
}

/// Characters that would change a URL's structure inside the authority.
pub(super) const AUTH_ESCAPE: &[char] = &['@', ':', '/', '?', '#', '&', ' ', '\\'];

pub(super) fn quote_auth(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if AUTH_ESCAPE.contains(&c) {
            for b in c.to_string().bytes() {
                out.push_str(&format!("%{b:02X}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Fold YAML settings into the URL. `url` is `None` when the URL itself did not parse (the service is then built from the settings alone).
pub(super) fn fold_url(
    url: Option<&str>,
    schema: &str,
    tokens: &[(String, Yaml)],
    warnings: &mut Vec<String>,
) -> String {
    let get = |k: &str| tokens.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v).filter(|v| !v.is_null());
    let password = get("password").or_else(|| get("pass"));
    let (user, host, port) = (get("user"), get("host"), get("port"));
    let base = url.unwrap_or("");
    let (head, query) = match base.split_once('?') {
        Some((h, q)) => (h.to_string(), q.to_string()),
        None => (base.to_string(), String::new()),
    };
    let head = if url.is_none() || user.is_some() || password.is_some() || host.is_some() || port.is_some() {
        let parsed = url.and_then(parse_url_unverified);
        let raw_user = user.and_then(url_value).map(|v| quote_auth(&v)).or_else(|| parsed.as_ref()?.user.clone());
        let raw_pass =
            password.and_then(url_value).map(|v| quote_auth(&v)).or_else(|| parsed.as_ref()?.password.clone());
        let raw_host = host
            .and_then(url_value)
            .map(|v| v.replace(['/', '?', '#', '@'], ""))
            .or_else(|| parsed.as_ref().map(|p| p.host.clone()))
            .unwrap_or_default();
        let raw_port = match port.and_then(url_value) {
            Some(p) => Some(p),
            None => parsed.as_ref().and_then(|p| p.port.map(|n| n.to_string()).or_else(|| p.port_raw.clone())),
        };
        let mut h = format!("{schema}://");
        match (&raw_user, &raw_pass) {
            (Some(u), Some(p)) => h.push_str(&format!("{u}:{p}@")),
            (Some(u), None) => h.push_str(&format!("{u}@")),
            (None, Some(p)) => h.push_str(&format!(":{p}@")),
            (None, None) => {}
        }
        h.push_str(&raw_host);
        if let Some(p) = raw_port {
            h.push(':');
            h.push_str(&p);
        }
        if let Some(fp) = parsed.as_ref().and_then(|p| p.fullpath.clone()) {
            h.push_str(&fp);
        }
        h
    } else {
        head
    };
    // YAML `user` / `password` replace the URL's, including the `?user=` / `?pass=` query forms the URL parser honours.
    let query = if user.is_some() || password.is_some() {
        query
            .split('&')
            .filter(|kv| {
                let k = unquote(kv.split('=').next().unwrap_or("")).trim().to_lowercase();
                !((user.is_some() && k == "user") || (password.is_some() && (k == "pass" || k == "password")))
            })
            .collect::<Vec<_>>()
            .join("&")
    } else {
        query
    };
    // YAML `+key` / `headers:` (and the `-` / `:` groups) build a new set of entries that replaces the URL's own entries of that group.
    let replaced: Vec<char> = prefixes()
        .filter(|p| {
            tokens.iter().any(|(k, v)| k.starts_with(*p) || (group_prefix(k) == Some(*p) && matches!(v, Yaml::Map(_))))
        })
        .collect();
    let query = if replaced.is_empty() {
        query
    } else {
        query.split('&').filter(|kv| !unquote(kv).starts_with(|c| replaced.contains(&c))).collect::<Vec<_>>().join("&")
    };
    let mut q: Vec<String> = if query.is_empty() { Vec::new() } else { vec![query] };
    for (k, v) in tokens {
        if is_reserved(k) {
            continue;
        }
        if let Some(prefix) = group_prefix(k)
            && let Yaml::Map(m) = v
        {
            for (mk, mv) in m {
                if let Some(val) = url_value(mv) {
                    q.push(format!("{prefix}{}={}", quote(&mk.to_text(), ""), quote(&val, "")));
                }
            }
            continue;
        }
        let key = match k.chars().next() {
            Some(p) if prefixes().any(|x| x == p) => format!("{p}{}", quote(k.split_at(1).1, "")),
            _ if valid_token(k) => quote(k, ""),
            _ => {
                warnings.push(format!("Ignoring invalid token ({k}) found in YAML configuration"));
                continue;
            }
        };
        match url_value(v) {
            Some(val) => q.push(format!("{key}={}", quote(&val, ""))),
            None if matches!(v, Yaml::Map(_)) => warnings
                .push(format!("The {schema}:// {k} keyword can only be defined from within a URL; ignoring it.")),
            None => {}
        }
    }
    if q.is_empty() { head } else { format!("{head}?{}", q.join("&")) }
}

/// String-keyed view of a YAML mapping (non-string keys are skipped).
pub(super) fn str_items(m: &[(Yaml, Yaml)]) -> Vec<(String, Yaml)> {
    m.iter().filter_map(|(k, v)| k.as_str().map(|k| (k.to_string(), v.clone()))).collect()
}

/// Merge `b` over `a`: existing keys keep their position and take the new value, new keys are appended.
pub(super) fn update(a: &mut Vec<(String, Yaml)>, b: &[(String, Yaml)]) {
    for (k, v) in b {
        match a.iter_mut().find(|(n, _)| n == k) {
            Some(slot) => slot.1 = v.clone(),
            None => a.push((k.clone(), v.clone())),
        }
    }
}

/// `URL_TOKEN_ALIASES` (`pass` -> `password`).
pub(super) fn alias_tokens(t: &mut Vec<(String, Yaml)>) {
    let Some(i) = t.iter().position(|(k, _)| k == "pass") else { return };
    let canonical = t.iter().position(|(k, v)| k == "password" && !v.is_null());
    let (_, v) = t.remove(i);
    if canonical.is_none() {
        t.retain(|(k, _)| k != "password");
        t.push(("password".into(), v));
    }
}
