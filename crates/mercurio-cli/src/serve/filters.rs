//! Server-wide rules: which services may be used, which attachment URLs may be downloaded and the result webhook.

use std::collections::BTreeSet;
use std::net::{IpAddr, ToSocketAddrs};

use serde_json::{Value, json};

use super::notify::LogEntry;

/// Services switched off by `APPRISE_ALLOW_SERVICES` / `APPRISE_DENY_SERVICES`.
#[derive(Debug, Default)]
pub struct ServiceFilter {
    disabled: BTreeSet<&'static str>,
}

/// Leading `[a-z][a-z0-9]+` of each comma or space separated entry.
fn names(list: &str) -> Vec<String> {
    list.split([',', ' '])
        .filter_map(|e| {
            let e = e.trim().to_ascii_lowercase();
            let n: String = e.chars().take_while(char::is_ascii_alphanumeric).collect();
            (n.len() >= 2 && n.starts_with(|c: char| c.is_ascii_alphabetic())).then_some(n)
        })
        .collect()
}

impl ServiceFilter {
    /// `allow` wins when set; one scheme names its whole service.
    pub fn new(allow: Option<&str>, deny: Option<&str>) -> Self {
        let ids = |list: &str| -> BTreeSet<&'static str> {
            names(list).iter().filter_map(|n| mercurio::service_for_scheme(n)).map(|d| d.id).collect()
        };
        let disabled = match (allow.filter(|a| !a.trim().is_empty()), deny) {
            (Some(allow), _) => {
                let keep = ids(allow);
                mercurio::services().iter().map(|d| d.id).filter(|id| !keep.contains(id)).collect()
            }
            (None, Some(deny)) => ids(deny),
            (None, None) => BTreeSet::new(),
        };
        ServiceFilter { disabled }
    }

    pub fn enabled(&self, service_id: &str) -> bool {
        !self.disabled.contains(service_id)
    }
}

/// `APPRISE_ATTACH_ALLOW_URL` / `APPRISE_ATTACH_REJECT_URL` rules.
#[derive(Debug)]
pub struct UrlFilter {
    allow: Vec<Rule>,
    deny: Vec<Rule>,
}

#[derive(Debug)]
enum Rule {
    /// Any address that is not public.
    Internal,
    /// `host[:port]` glob, any scheme.
    Host(String),
    /// Scheme(s), host glob and path prefix glob.
    Url { schemes: Vec<String>, host: String, path: String },
}

fn rules(list: &str) -> Vec<Rule> {
    list.split([',', ' ', '\t', '\n'])
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .map(|t| {
            if t == "internal" {
                return Rule::Internal;
            }
            let (schemes, rest) = match t.split_once("://") {
                Some((s, r)) => (vec![s.to_string()], r.to_string()),
                None if t.contains('/') => (vec!["http".into(), "https".into()], t.clone()),
                None => return Rule::Host(t),
            };
            let (host, path) =
                rest.split_once('/').map(|(h, p)| (h.to_string(), format!("/{p}"))).unwrap_or((rest, String::new()));
            Rule::Url { schemes, host, path }
        })
        .collect()
}

/// `*` matches any run of characters, `?` one character.
fn glob(pattern: &str, value: &str) -> bool {
    let (p, v): (Vec<char>, Vec<char>) = (pattern.chars().collect(), value.chars().collect());
    let mut prev = vec![false; v.len() + 1];
    prev[0] = true;
    for &c in &p {
        let mut cur = vec![false; v.len() + 1];
        if c == '*' {
            cur[0] = prev[0];
            for i in 1..=v.len() {
                cur[i] = prev[i] || cur[i - 1];
            }
        } else {
            for i in 1..=v.len() {
                cur[i] = prev[i - 1] && (c == '?' || c == v[i - 1]);
            }
        }
        prev = cur;
    }
    prev[v.len()]
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_broadcast()
                || a.is_documentation()
                || a.is_unspecified()
                || a.octets()[0] == 100 && (a.octets()[1] & 0xc0) == 64
                || a.octets()[0] >= 240)
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let seg = a.segments()[0];
            !(a.is_loopback() || a.is_unspecified() || (seg & 0xfe00) == 0xfc00 || (seg & 0xffc0) == 0xfe80)
        }
    }
}

impl UrlFilter {
    pub fn new(allow: &str, deny: &str) -> Self {
        UrlFilter { allow: rules(allow), deny: rules(deny) }
    }

    fn matches(rule: &Rule, scheme: &str, authority: &str, host: &str, path: &str) -> bool {
        match rule {
            Rule::Internal => {
                let target = if host.contains(':') { format!("[{host}]:0") } else { format!("{host}:0") };
                match target.to_socket_addrs() {
                    Ok(addrs) => {
                        let addrs: Vec<_> = addrs.collect();
                        addrs.is_empty() || addrs.iter().any(|a| !is_public(a.ip()))
                    }
                    Err(_) => true,
                }
            }
            Rule::Host(p) => glob(p, authority) || glob(p, host),
            Rule::Url { schemes, host: h, path: p } => {
                schemes.iter().any(|s| s == scheme)
                    && (glob(h, authority) || glob(h, host))
                    && (p.is_empty()
                        || p == "/"
                        || glob(p, path)
                        || glob(&format!("{}/*", p.trim_end_matches('/')), path))
            }
        }
    }

    /// Deny rules first; then an allow rule must match.
    pub fn allowed(&self, url: &str) -> bool {
        let lower = url.to_ascii_lowercase();
        let Some((scheme, rest)) = lower.split_once("://") else { return false };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        let host = if let Some(v6) = authority.strip_prefix('[') {
            v6.split(']').next().unwrap_or(v6)
        } else {
            authority.split(':').next().unwrap_or(authority)
        };
        let path = path.split(['?', '#']).next().unwrap_or("");
        let path = if path.is_empty() { "/" } else { path };
        let hit = |r: &Rule| Self::matches(r, scheme, authority, host, path);
        !self.deny.iter().any(hit) && self.allow.iter().any(hit)
    }
}

/// POST the result of a notification call to `APPRISE_WEBHOOK_URL`.
pub async fn send_webhook(
    transport: &dyn mercurio::transport::AsyncTransport,
    url: &str,
    source: &str,
    ok: bool,
    logs: &[LogEntry],
) {
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        log::warn!("The webhook result URL is not using the HTTP protocol");
        return;
    }
    let output: Vec<Value> = logs.iter().map(|l| json!([l.level, l.asctime(), l.message])).collect();
    let body = json!({"source": source, "status": if ok { 0 } else { 1 }, "output": output});
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let mut req = match authority.rsplit_once('@') {
        Some((userinfo, host)) => {
            let (u, p) = userinfo.split_once(':').map(|(u, p)| (u, Some(p))).unwrap_or((userinfo, None));
            let u = mercurio::__private::unquote(u);
            let p = p.map(mercurio::__private::unquote);
            mercurio::transport::Request::post(format!("{scheme}://{host}{tail}")).basic_auth(&u, p.as_deref())
        }
        None => mercurio::transport::Request::post(url.to_string()),
    };
    req = req.header("User-Agent", format!("Mercurio/{}", env!("CARGO_PKG_VERSION"))).json(&body);
    match transport.http(&req).await {
        Ok(r) if r.is_success() => {}
        Ok(r) => log::warn!("The webhook result URL returned HTTP {}", r.status),
        Err(e) => log::warn!("A connection error occurred sending the webhook results: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_rules() {
        let f = UrlFilter::new("*", "127.0.* localhost*");
        assert!(f.allowed("https://example.com/a.png"));
        assert!(!f.allowed("http://127.0.0.1:8000/x"));
        assert!(!f.allowed("http://localhost/x"));
        let f = UrlFilter::new("example.com/files/ *.cdn.net", "");
        assert!(f.allowed("https://example.com/files/a.png"));
        assert!(!f.allowed("https://example.com/other/a.png"));
        assert!(f.allowed("http://img.cdn.net/x"));
        assert!(!f.allowed("http://cdn.org/x"));
        assert!(!UrlFilter::new("*", "internal").allowed("http://10.0.0.1/x"));
    }

    #[test]
    fn service_rules() {
        let f = ServiceFilter::new(None, Some("windows, dbus, json"));
        let json = mercurio::service_for_scheme("jsons").map(|d| d.id).unwrap_or_default();
        assert!(!f.enabled(json));
        let f = ServiceFilter::new(Some("json"), Some("json"));
        assert!(f.enabled(json));
        assert!(!f.enabled(mercurio::service_for_scheme("form").map(|d| d.id).unwrap_or_default()));
    }
}
