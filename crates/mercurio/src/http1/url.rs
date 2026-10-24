//! URLs of the HTTP client: parsing, `Location` resolution, credentials and `Referer` on redirects.

/// An absolute `http` or `https` URL, with its path and query percent-encoded the way a browser sends them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Url {
    pub(crate) tls: bool,
    /// Lower-case; an IPv6 address has no brackets.
    pub(crate) host: String,
    pub(crate) port: u16,
    /// Starts with `/`; includes the query.
    pub(crate) target: String,
    /// The `user:password@` part, percent-decoded.
    pub(crate) userinfo: Option<(String, String)>,
}

impl Url {
    pub(crate) fn parse(s: &str) -> Result<Self, String> {
        let (scheme, rest) = s.split_once("://").ok_or("not an absolute URL")?;
        let tls = if scheme.eq_ignore_ascii_case("https") {
            true
        } else if scheme.eq_ignore_ascii_case("http") {
            false
        } else {
            return Err(format!("unsupported scheme {scheme}"));
        };
        let rest = rest.split('#').next().unwrap_or_default();
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let default_port = if tls { 443 } else { 80 };
        let (host, port) = split_host_port(hostport, default_port)?;
        let userinfo = userinfo.map(|u| {
            let (user, pass) = u.split_once(':').unwrap_or((u, ""));
            (crate::url::unquote(user), crate::url::unquote(pass))
        });
        Ok(Self { tls, host, port, target: target(tail), userinfo })
    }

    /// `host[:port]` as the `Host` header and the authority of a proxied request write it.
    pub(crate) fn authority(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == if self.tls { 443 } else { 80 } { host } else { format!("{host}:{}", self.port) }
    }

    /// Same scheme, host and port: what decides whether credentials follow a redirect (as reqwest), so they never go from `https` to `http`.
    pub(crate) fn same_origin(&self, other: &Self) -> bool {
        (self.tls, &self.host, self.port) == (other.tls, &other.host, other.port)
    }

    /// The `Referer` a redirect from `self` to `next` carries: `self` without credentials, none from `https` to `http`.
    pub(crate) fn referer_for(&self, next: &Self) -> Option<String> {
        (!self.tls || next.tls)
            .then(|| format!("{}://{}{}", if self.tls { "https" } else { "http" }, self.authority(), self.target))
    }

    /// The URL a `Location` header points to, `None` when it is not an `http(s)` URL.
    pub(crate) fn join(&self, location: &str) -> Option<Self> {
        let location = location.trim();
        let scheme = if self.tls { "https" } else { "http" };
        let origin = format!("{scheme}://{}", self.authority());
        if let Some((s, _)) = location.split_once("://")
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        {
            return Self::parse(location).ok();
        }
        let joined = if location.starts_with("//") {
            format!("{scheme}:{location}")
        } else if location.starts_with('/') {
            format!("{origin}{location}")
        } else if location.starts_with('?') {
            let path = self.target.split('?').next().unwrap_or("/");
            format!("{origin}{path}{location}")
        } else if location.starts_with('#') || location.is_empty() {
            format!("{origin}{}", self.target)
        } else {
            let path = self.target.split('?').next().unwrap_or("/");
            let dir = path.rfind('/').map_or("/", |i| path.split_at(i + 1).0);
            format!("{origin}{dir}{location}")
        };
        Self::parse(&joined).ok()
    }
}

fn split_host_port(hostport: &str, default_port: u16) -> Result<(String, u16), String> {
    let (host, port) = if let Some(inner) = hostport.strip_prefix('[') {
        let (host, after) = inner.split_once(']').ok_or("unterminated IPv6 address")?;
        (host, after.strip_prefix(':').unwrap_or(after))
    } else {
        hostport.rsplit_once(':').unwrap_or((hostport, ""))
    };
    if host.is_empty() {
        return Err("no host".into());
    }
    let host = if host.is_ascii() { host.to_string() } else { idna(host)? };
    let host = host.as_str();
    if host.bytes().any(|b| b.is_ascii_control() || matches!(b, b' ' | b'%' | b'\\' | b'@' | b'[' | b']')) {
        return Err(format!("invalid host {host}"));
    }
    if !hostport.starts_with('[') && host.contains(':') {
        return Err(format!("invalid host {host}"));
    }
    let port = if port.is_empty() { default_port } else { port.parse().map_err(|_| format!("invalid port {port}"))? };
    Ok((host.to_ascii_lowercase(), port))
}

/// A Unicode host name as its ASCII (Punycode) form: labels are lower-cased, and those with non-ASCII letters become `xn--…`.
fn idna(host: &str) -> Result<String, String> {
    host.to_lowercase()
        .split('.')
        .map(
            |label| {
                if label.is_ascii() { Some(label.to_string()) } else { punycode(label).map(|p| format!("xn--{p}")) }
            },
        )
        .collect::<Option<Vec<_>>>()
        .map(|labels| labels.join("."))
        .ok_or_else(|| format!("invalid host {host}"))
}

/// RFC 3492 Punycode encoding of one label.
fn punycode(label: &str) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    fn adapt(delta: u32, points: u32, first: bool) -> u32 {
        let mut delta = if first { delta / 700 } else { delta / 2 };
        delta += delta / points;
        let mut k = 0;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            k += BASE;
        }
        k + (BASE - TMIN + 1) * delta / (delta + 38)
    }
    /// 0 to 25 are `a` to `z`, 26 to 35 are `0` to `9`.
    fn digit(d: u32) -> char {
        let d = u8::try_from(d).unwrap_or(0);
        char::from(if d < 26 { b'a' + d } else { b'0' + d - 26 })
    }
    let input: Vec<u32> = label.chars().map(u32::from).collect();
    let mut out: String = label.chars().filter(char::is_ascii).collect();
    let basic = u32::try_from(out.len()).ok()?;
    if basic > 0 {
        out.push('-');
    }
    let (mut n, mut delta, mut bias, mut handled) = (128u32, 0u32, 72u32, basic);
    while (handled as usize) < input.len() {
        let m = input.iter().copied().filter(|&c| c >= n).min()?;
        delta = delta.checked_add((m - n).checked_mul(handled + 1)?)?;
        n = m;
        for &c in &input {
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        TMIN
                    } else if k >= bias + TMAX {
                        TMAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    out.push(digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                out.push(digit(q));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }
    Some(out)
}

/// The path and query of `tail` (what follows the authority): `\` is `/`, dot segments are resolved, unsafe bytes are percent-encoded.
fn target(tail: &str) -> String {
    let (path, query) = match tail.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (tail, None),
    };
    let mut out = String::with_capacity(tail.len() + 1);
    out.push_str(&remove_dot_segments(&path.replace('\\', "/")));
    if let Some(q) = query {
        out.push('?');
        out.push_str(q);
    }
    escape(&out)
}

fn remove_dot_segments(path: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    let mut parts = path.split('/').skip(1).peekable();
    let mut trailing = path.is_empty();
    while let Some(part) = parts.next() {
        let last = parts.peek().is_none();
        match part {
            "." => trailing = last,
            ".." => {
                stack.pop();
                trailing = last;
            }
            _ => {
                stack.push(part);
                trailing = false;
            }
        }
    }
    let mut out = String::from("/");
    out.push_str(&stack.join("/"));
    if trailing && !stack.is_empty() {
        out.push('/');
    }
    out
}

/// Percent-encode what must not appear raw in a request target; existing escapes stay as they are.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b <= b' ' || b >= 0x7f || matches!(b, b'"' | b'<' | b'>' | b'`' | b'{' | b'}') {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push(char::from(b));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn parses_and_normalizes() {
        let u = url("HTTPS://User:p%40ss@Example.COM:8443/a b/./c/../d?x=1 2&y=é#frag");
        assert_eq!((u.tls, u.host.as_str(), u.port), (true, "example.com", 8443));
        assert_eq!(u.target, "/a%20b/d?x=1%202&y=%C3%A9");
        assert_eq!(u.userinfo, Some(("User".into(), "p@ss".into())));
        assert_eq!(u.authority(), "example.com:8443");

        assert_eq!(url("http://h").target, "/");
        assert_eq!(url("http://h?q=1").target, "/?q=1");
        assert_eq!(url("http://h/a/b/").target, "/a/b/");
        assert_eq!(url("http://h/a/b/..").target, "/a/");
        assert_eq!(url("http://h/%7Efoo").target, "/%7Efoo");
        let v6 = url("http://[::1]:80/x");
        assert_eq!((v6.host.as_str(), v6.port, v6.authority().as_str()), ("::1", 80, "[::1]"));
        assert_eq!(url("https://h:443/").authority(), "h");
    }

    #[test]
    fn rejects_what_it_cannot_send() {
        for bad in ["ftp://h/", "h/path", "http://", "http://h:99999/", "http://h:x/", "http://a b/"] {
            assert!(Url::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn internationalized_hosts() {
        assert_eq!(url("http://München.de/").host, "xn--mnchen-3ya.de");
        assert_eq!(url("http://bücher.example/").host, "xn--bcher-kva.example");
        assert_eq!(url("http://例え.テスト/").host, "xn--r8jz45g.xn--zckzah");
    }

    #[test]
    fn referer_and_credentials_on_redirects() {
        let a = url("https://u:p@a.test/x?t=1");
        assert_eq!(a.referer_for(&url("https://b.test/")).as_deref(), Some("https://a.test/x?t=1"));
        assert_eq!(a.referer_for(&url("http://b.test/")), None);
        assert!(a.same_origin(&url("https://a.test:443/y")));
        assert!(!a.same_origin(&url("http://a.test/y")), "the port changes with the scheme");
        assert!(!url("https://a.test:8443/").same_origin(&url("http://a.test:8443/")), "so does the scheme alone");
        assert!(!url("http://a.test/").same_origin(&url("http://b.test/")));
    }

    #[test]
    fn joins_locations() {
        let base = url("http://a.test:8080/x/y/z?q=1");
        let join = |l: &str| base.join(l).map(|u| format!("{}{}", u.authority(), u.target));
        assert_eq!(join("/abs").as_deref(), Some("a.test:8080/abs"));
        assert_eq!(join("rel").as_deref(), Some("a.test:8080/x/y/rel"));
        assert_eq!(join("../up").as_deref(), Some("a.test:8080/x/up"));
        assert_eq!(join("?n=2").as_deref(), Some("a.test:8080/x/y/z?n=2"));
        assert_eq!(join("//b.test/p").as_deref(), Some("b.test/p"));
        assert_eq!(join("https://c.test/p?q").as_deref(), Some("c.test/p?q"));
        assert_eq!(join("ftp://c.test/"), None);
    }
}
