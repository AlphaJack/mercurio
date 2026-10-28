//! The forward proxies of the environment: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY`.

use crate::crypto::b64;
use crate::http1::url::Url;

/// A forward proxy from the environment: HTTP or HTTPS, optionally with Basic credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Proxy {
    /// `https://` proxy: TLS to the proxy itself.
    pub(crate) tls: bool,
    pub(crate) host: String,
    pub(crate) port: u16,
    /// The `Proxy-Authorization` value.
    pub(crate) auth: Option<String>,
}

impl Proxy {
    fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let s = if s.contains("://") { s.to_owned() } else { format!("http://{s}") };
        let url = Url::parse(&s).ok()?;
        let auth = url.userinfo.map(|(u, p)| format!("Basic {}", b64(format!("{u}:{p}").as_bytes())));
        Some(Self { tls: url.tls, host: url.host, port: url.port, auth })
    }
}

/// `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` (either case), read once. Under CGI (`REQUEST_METHOD` set) none is used, as hyper-util (reqwest) does: a client can set `HTTP_PROXY` through a `Proxy:` header (httpoxy), and the others may come from the request too.
#[derive(Debug, Default, Clone)]
pub(crate) struct ProxyEnv {
    http: Option<Proxy>,
    https: Option<Proxy>,
    no_proxy: Vec<String>,
}

impl ProxyEnv {
    pub(crate) fn from_env() -> Self {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    pub(crate) fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        if get("REQUEST_METHOD").is_some() {
            return Self::default();
        }
        let var = |upper: &str| {
            let lower = upper.to_ascii_lowercase();
            [upper, lower.as_str()].into_iter().find_map(|n| get(n).filter(|v| !v.trim().is_empty()))
        };
        let all = var("ALL_PROXY").and_then(|v| Proxy::parse(&v));
        Self {
            http: var("HTTP_PROXY").and_then(|v| Proxy::parse(&v)).or_else(|| all.clone()),
            https: var("HTTPS_PROXY").and_then(|v| Proxy::parse(&v)).or(all),
            no_proxy: var("NO_PROXY")
                .map(|v| v.split(',').map(|e| e.trim().to_ascii_lowercase()).filter(|e| !e.is_empty()).collect())
                .unwrap_or_default(),
        }
    }

    /// The proxy `url` goes through, if any.
    pub(crate) fn for_url(&self, url: &Url) -> Option<&Proxy> {
        let proxy = if url.tls { self.https.as_ref() } else { self.http.as_ref() }?;
        (!self.excluded(&url.host)).then_some(proxy)
    }

    fn excluded(&self, host: &str) -> bool {
        let ip = host.parse::<std::net::IpAddr>().ok();
        self.no_proxy.iter().any(|entry| {
            if let Some(matched) = ip.and_then(|ip| ip_matches(ip, entry)) {
                return matched;
            }
            let entry = entry.trim_start_matches("*.").trim_start_matches('.');
            entry == "*" || host == entry || host.strip_suffix(entry).is_some_and(|p| p.ends_with('.'))
        })
    }
}

/// Whether `ip` is the address or in the `addr/prefix` range `entry`; `None` when `entry` is not an address.
fn ip_matches(ip: std::net::IpAddr, entry: &str) -> Option<bool> {
    use std::net::IpAddr;
    let (addr, prefix) = match entry.split_once('/') {
        Some((a, p)) => (a, Some(p.parse::<u32>().ok()?)),
        None => (entry, None),
    };
    let net: IpAddr = addr.trim_matches(['[', ']']).parse().ok()?;
    Some(match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let bits = prefix.unwrap_or(32).min(32);
            let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let bits = prefix.unwrap_or(128).min(128);
            let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
            u128::from(a) & mask == u128::from(b) & mask
        }
        (IpAddr::V4(_) | IpAddr::V6(_), IpAddr::V4(_) | IpAddr::V6(_)) => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http1::url::Url;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn proxy_environment() {
        let env = ProxyEnv::from_lookup(|n| match n {
            "http_proxy" => Some("http://u:p@proxy.test:3128".into()),
            "ALL_PROXY" => Some("other.test:1080".into()),
            "NO_PROXY" => Some("localhost, .internal.test,10.0.0.1,192.168.0.0/16,::1".into()),
            _ => None,
        });
        let http = env.for_url(&url("http://example.com/")).unwrap();
        assert_eq!((http.host.as_str(), http.port), ("proxy.test", 3128));
        assert_eq!(http.auth.as_deref(), Some("Basic dTpw"));
        let https = env.for_url(&url("https://example.com/")).unwrap();
        assert_eq!((https.host.as_str(), https.port), ("other.test", 1080));
        for skipped in [
            "http://localhost/",
            "http://a.internal.test/",
            "http://internal.test/",
            "http://10.0.0.1/",
            "http://192.168.4.2/",
            "http://[::1]/",
        ] {
            assert!(env.for_url(&url(skipped)).is_none(), "{skipped}");
        }
        assert!(env.for_url(&url("http://notinternal.test/")).is_some());
        assert!(env.for_url(&url("http://10.0.0.2/")).is_some());
        assert!(ProxyEnv::default().for_url(&url("http://x/")).is_none());

        let cgi = ProxyEnv::from_lookup(|n| match n {
            "REQUEST_METHOD" => Some("GET".into()),
            "HTTP_PROXY" | "http_proxy" | "HTTPS_PROXY" | "ALL_PROXY" => Some("evil.test:80".into()),
            _ => None,
        });
        for target in ["http://example.com/", "https://example.com/"] {
            assert!(cgi.for_url(&url(target)).is_none(), "no proxy under CGI: {target}");
        }
        let tls = ProxyEnv::from_lookup(|n| (n == "HTTPS_PROXY").then(|| "https://p.test".into()));
        let p = tls.for_url(&url("https://example.com/")).unwrap();
        assert_eq!((p.tls, p.port), (true, 443));
    }
}
