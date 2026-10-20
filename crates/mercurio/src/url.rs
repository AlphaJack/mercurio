//! Lenient notification-URL parsing.
//!
//! Notification URLs are not RFC 3986: tokens may contain `:`, `/` or `@`. Paths carry targets. The query string carries options plus `+header`, `-field` and `:field` overrides. Parsing splits the URL, then reads the common options (`format`, `overflow`, retries, timeouts).

use std::borrow::Cow;
use std::fmt;

use crate::message::{NotifyFormat, OverflowMode};
use crate::parse::{is_hostname, parse_bool};
use crate::regex;
use crate::service::Param;

/// Ordered key/value list in insertion order.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Pairs(Vec<(String, String)>);

impl Pairs {
    /// An empty list.
    pub fn new() -> Self {
        Self(Vec::new())
    }
    /// Insert, replacing an existing key in place.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        if let Some(slot) = self.0.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            self.0.push((key, value));
        }
    }
    /// Value of `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
    /// `true` when `key` is present.
    pub fn contains(&self, key: &str) -> bool {
        self.0.iter().any(|(k, _)| k == key)
    }
    /// Remove `key` and return its value.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        let idx = self.0.iter().position(|(k, _)| k == key)?;
        Some(self.0.remove(idx).1)
    }
    /// Entries in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
    /// Number of entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// `true` when empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Pairs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.0.iter().map(|(k, v)| (k, v))).finish()
    }
}

impl<K: Into<String>, V: Into<String>> FromIterator<(K, V)> for Pairs {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut p = Pairs::new();
        for (k, v) in iter {
            p.insert(k, v);
        }
        p
    }
}

/// A parsed notification URL. Field values are still percent-encoded as given; services call [`unquote`] where they need the decoded value.
#[derive(Clone, PartialEq)]
pub struct ParsedUrl {
    /// Lower-cased scheme, e.g. `tgram`.
    pub scheme: String,
    /// User part, still percent-encoded ([`ParsedUrl::user`] gives it decoded).
    pub user: Option<String>,
    /// Password part, still percent-encoded ([`ParsedUrl::password`] gives it decoded).
    pub password: Option<String>,
    /// Host part (may be any token for services that use it as a key).
    pub host: String,
    /// Numeric port, if present and valid.
    pub port: Option<u16>,
    /// Raw port text when it was present but not numeric (only when not verifying hosts).
    pub port_raw: Option<String>,
    /// Path including leading `/`, re-quoted. `None` when empty.
    pub fullpath: Option<String>,
    /// Directory part of `fullpath` (ends with `/`).
    pub path: Option<String>,
    /// Last segment of `fullpath` when it does not end with `/`.
    pub last_segment: Option<String>,
    /// Query options: keys lower-cased and trimmed, values unquoted and trimmed.
    pub query: Pairs,
    /// `?+Key=Value` entries (case preserved). Usually extra HTTP headers.
    pub query_plus: Pairs,
    /// `?-key=value` entries. Usually payload fields to drop.
    pub query_minus: Pairs,
    /// `?:key=value` entries. Usually payload field remaps.
    pub query_colon: Pairs,
    /// Scheme ends with `s`.
    pub secure: bool,
    /// TLS certificate verification (`?verify=no` disables).
    pub verify: bool,
    /// Follow HTTP redirects.
    pub redirect: bool,
    /// Reassembled base URL without query.
    pub url: String,
    /// `?format=`: `text`, `html` or `markdown`.
    pub format: Option<NotifyFormat>,
    /// `?overflow=`: `upstream`, `truncate` or `split`.
    pub overflow: Option<OverflowMode>,
    /// `?tz=`: time zone name, passed to services that use one.
    pub tz: Option<String>,
    /// Connect timeout (`cto`) in seconds.
    pub cto: Option<f64>,
    /// Read timeout (`rto`) in seconds.
    pub rto: Option<f64>,
    /// `?retry=`: extra attempts after a retryable failure.
    pub retry: Option<u32>,
    /// `?wait=`: seconds between attempts (default 0.5).
    pub wait: Option<f64>,
    /// `?optional=`: parsed and kept; the core does not act on it.
    pub optional: Option<bool>,
    /// The original input string.
    pub original: String,
}

impl fmt::Debug for ParsedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print credentials.
        f.debug_struct("ParsedUrl")
            .field("scheme", &self.scheme)
            .field("user", &self.user.as_ref().map(|_| "***"))
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("host", &"***")
            .field("port", &self.port)
            .field("query_keys", &self.query.iter().map(|(k, _)| k).collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// Options for [`parse_url_with`].
#[derive(Debug, Clone, Copy)]
pub struct ParseOptions {
    /// Validate the host as a hostname or IP address.
    pub verify_host: bool,
    /// Reject ports outside 1-65535; with `verify_host` off, keep a non-numeric port in `port_raw` instead of the host.
    pub strict_port: bool,
    /// Lower-case and trim query keys.
    pub sanitize: bool,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self { verify_host: true, strict_port: false, sanitize: true }
    }
}

/// Parse with default options (`verify_host = true`).
pub fn parse_url(url: &str) -> Option<ParsedUrl> {
    parse_url_with(url, ParseOptions::default())
}

/// Parse without hostname validation; for services whose "host" is a token.
pub fn parse_url_unverified(url: &str) -> Option<ParsedUrl> {
    parse_url_with(url, ParseOptions { verify_host: false, ..Default::default() })
}

/// Parse `url` with explicit [`ParseOptions`]. `None` when it is not a notification URL.
pub fn parse_url_with(url: &str, opts: ParseOptions) -> Option<ParsedUrl> {
    let mut r = parse_raw(url, "unknown", opts)?;
    post_process(&mut r);
    Some(r)
}

fn parse_raw(url: &str, default_schema: &str, opts: ParseOptions) -> Option<ParsedUrl> {
    // Optional `scheme://`, then everything up to `?` (host and path), then the query string.
    let re = regex!(r"^\s*(?:(?P<schema>[^:\s]+):[/\\]+)?(?:(?P<path>[^?]+)(?:\?(?P<query>.+))?)?\s*$");
    let caps = re.captures(url)?;
    let scheme =
        caps.name("schema").map(|m| m.as_str().trim().to_lowercase()).unwrap_or_else(|| default_schema.to_string());
    let host_part = caps.name("path").map(|m| m.as_str().trim().to_string()).unwrap_or_default();
    let query_string = caps.name("query").map(|m| m.as_str().trim().to_string());

    let mut out = ParsedUrl {
        scheme,
        user: None,
        password: None,
        host: String::new(),
        port: None,
        port_raw: None,
        fullpath: None,
        path: None,
        last_segment: None,
        query: Pairs::new(),
        query_plus: Pairs::new(),
        query_minus: Pairs::new(),
        query_colon: Pairs::new(),
        secure: false,
        verify: true,
        redirect: true,
        url: String::new(),
        format: None,
        overflow: None,
        tz: None,
        cto: None,
        rto: None,
        retry: None,
        wait: None,
        optional: None,
        original: url.to_string(),
    };

    if let Some(qs) = query_string.as_deref().filter(|q| !q.is_empty()) {
        parse_query_into(qs, opts.sanitize, &mut out);
    }

    // urlparse("http://" + host) first drops \t, \r and \n (WHATWG), then the netloc runs up to the first '/', '?' or '#'.
    let host_part =
        if host_part.contains(['\t', '\r', '\n']) { host_part.replace(['\t', '\r', '\n'], "") } else { host_part };
    let (netloc, rest) = split_netloc(&host_part);
    out.host = netloc.trim().to_string();
    // urlparse drops the fragment, the query and `;params` of the last segment.
    let raw_path = rest.split(['#', '?']).next().unwrap_or("");
    let raw_path = match raw_path.rfind('/').map(|slash| raw_path.split_at(slash).1.find(';').map(|i| slash + i)) {
        Some(Some(i)) => raw_path.split_at(i).0,
        Some(None) => raw_path,
        None => raw_path.split(';').next().unwrap_or(""),
    };
    let tidy = tidy_path(raw_path.trim());
    let mut fullpath = quote(&unquote(&tidy), PATH_SAFE);
    let trimmed_url = url.trim();
    if !fullpath.is_empty()
        && !fullpath.ends_with(['/', '\\'])
        && (url.ends_with('/') || url.ends_with('\\'))
        && let Some(last) = trimmed_url.chars().last()
    {
        fullpath.push(last);
    }
    if !fullpath.is_empty() {
        if let Some(i) = fullpath.rfind(['/', '\\']) {
            // Both separators are one byte, so `i + 1` is a char boundary.
            let (path, last) = fullpath.split_at(i + 1);
            out.path = Some(path.to_string());
            out.last_segment = Some(last).filter(|q| !q.is_empty()).map(str::to_string);
        }
        out.fullpath = Some(fullpath);
    }

    // User[:password]@host: re.split(r"[@]+")[:2], only with 2 or more parts
    {
        let parts: Vec<&str> = split_runs(&out.host, '@');
        if parts.len() >= 2 {
            let user = parts[0].to_string();
            let host = parts[1].to_string();
            out.user = Some(user);
            out.host = host;
        }
    }
    if let Some(user) = out.user.clone() {
        let parts: Vec<&str> = split_runs(&user, ':');
        if parts.len() >= 2 {
            out.user = Some(parts[0].to_string());
            out.password = Some(parts[1].to_string());
        }
    }

    let pre = regex!(r"^(?P<host>(?:\[[0-9a-fA-F:]+\]|[^:]+)):(?P<port>[^:]*)$");
    let mut port_text: Option<String> = None;
    let mut port_numeric: Option<i64> = None;
    let host_port = if out.host.contains(':') {
        pre.captures(&out.host).map(|m| (m["host"].to_string(), m["port"].to_string()))
    } else {
        None
    };
    if let Some((host, port)) = host_port {
        out.host = host;
        port_text = Some(port.clone());
        if port.chars().any(|c| c.is_ascii_digit()) {
            match crate::util::parse_int(&port) {
                Some(n) => port_numeric = Some(n),
                None if opts.verify_host => return None,
                None => {}
            }
        } else if opts.verify_host {
            return None;
        }
    }

    if opts.verify_host {
        out.host = is_hostname(&out.host, true, true, true)?;
        if let Some(p) = port_numeric
            && opts.strict_port
            && !u16::try_from(p).is_ok_and(|p| p > 0)
        {
            return None;
        }
    } else if let (Some(text), None) = (&port_text, port_numeric) {
        if opts.strict_port {
            out.port_raw = Some(text.trim().to_string());
        } else {
            out.host = format!("{}:{}", out.host, text);
        }
    }
    out.port = port_numeric.and_then(|p| u16::try_from(p).ok());
    if port_numeric.is_some() && out.port.is_none() {
        out.port_raw = port_text.clone();
    }

    let mut base = String::with_capacity(out.original.len() + 8);
    base.push_str(&out.scheme);
    base.push_str("://");
    if let Some(u) = &out.user {
        base.push_str(u);
        if let Some(p) = &out.password {
            base.push(':');
            base.push_str(p);
        }
        base.push('@');
    }
    base.push_str(&out.host);
    if let Some(p) = port_numeric {
        base.push(':');
        base.push_str(&p.to_string());
    } else if let Some(p) = &out.port_raw {
        base.push(':');
        base.push_str(p);
    }
    if let Some(fp) = &out.fullpath {
        base.push_str(fp);
    }
    out.url = base;
    Some(out)
}

/// `re.split(r"[c]+", s)`.
fn split_runs(s: &str, c: char) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = s;
    loop {
        match rest.find(c) {
            Some(i) => {
                let (head, tail) = rest.split_at(i);
                out.push(head);
                rest = tail.trim_start_matches(c);
            }
            None => {
                out.push(rest);
                break;
            }
        }
    }
    out
}

fn split_netloc(s: &str) -> (&str, &str) {
    match s.find(['/', '?', '#']) {
        Some(i) => s.split_at(i),
        None => (s, ""),
    }
}

/// Collapse repeated `/` and `\`. Trim trailing whitespace and `\`.
fn tidy_path(path: &str) -> String {
    let win = regex!(r"(^[\\]{2}|[^\\\s][\\]|[\s][\\]{2}])([\\]+)");
    let nux = regex!(r"([/])([/]+)");
    let trim = regex!(r"^(.+[^:][^\\])[\s\\]*$");
    // Each pattern is skipped when it cannot change the text: `win` needs a `\` and `nux` a `//`. `trim` keeps the text unless it ends in `\s` or `\`.
    let p = path.trim();
    let p = if p.contains('\\') { win.replace_all(p, "$1") } else { Cow::Borrowed(p) };
    let p = if p.contains("//") { Cow::Owned(nux.replace_all(&p, "$1").into_owned()) } else { p };
    if p.ends_with(|c: char| c.is_whitespace() || c == '\\') {
        trim.replace_all(&p, "$1").into_owned()
    } else {
        p.into_owned()
    }
}

fn parse_query_into(qs: &str, sanitize: bool, out: &mut ParsedUrl) {
    for name_value in qs.split('&').flat_map(|s| s.split(';')) {
        let (name, value) = match name_value.split_once('=') {
            Some((n, v)) => (n, v),
            None => (name_value, ""),
        };
        // First char kept verbatim (so a leading '+' marks a header), rest '+' -> ' '.
        let mut key = String::new();
        let mut chars = name.chars();
        if let Some(first) = chars.next() {
            key.push(first);
            key.push_str(&chars.as_str().replace('+', " "));
        }
        let key = unquote(&key);
        let val = value.to_string();
        let val = unquote(&val).trim().to_string();
        let qkey = if sanitize { key.to_lowercase().trim().to_string() } else { key.clone() };
        out.query.insert(qkey, val.clone());

        // ^( |\+)(?P<key>.*)\s*   (a leading space is what '+' becomes after unquote)
        if let Some(rest) = key.strip_prefix([' ', '+']) {
            out.query_plus.insert(rest.to_string(), val.clone());
        }
        if let Some(rest) = key.strip_prefix('-') {
            out.query_minus.insert(rest.to_string(), val.clone());
        }
        if let Some(rest) = key.strip_prefix(':') {
            out.query_colon.insert(rest.to_string(), val.clone());
        }
    }
}

/// The query parameters every URL accepts, read by `post_process` and the target builder. The book's common-parameter table is generated from it.
pub static COMMON_PARAMS: &[Param] = &[
    Param::new("format", "Body format the service receives")
        .choice(&["text", "html", "markdown"])
        .note("default: the service's own"),
    Param::new("overflow", "What to do with messages over the service's limits")
        .choice(&["upstream", "truncate", "split"])
        .default("upstream"),
    Param::new("verify", "Verify TLS certificates").bool(true),
    Param::new("redirect", "Follow HTTP redirects").bool(true),
    Param::new("cto", "Connect timeout, in seconds").float().default("5"),
    Param::new("rto", "Read timeout, in seconds").float().default("30"),
    Param::new("retry", "Extra attempts after a retryable failure").int().range(0, 10).default("0"),
    Param::new("wait", "Pause before each retry, in seconds").float().range(0, 20).default("0.5"),
    Param::new("store", "Use the persistent store on disk").bool(true),
    Param::new("tag", "Tags for `--tag` filtering").list(", "),
    Param::new("tz", "Time zone name").note("passed to the services that use one, not validated"),
    Param::new("user", "User name; replaces the one in the URL"),
    Param::new("password", "Password; replaces the one in the URL").aliases(&["pass"]).secret(),
    Param::new("port", "Port; replaces the one in the URL").port(),
    Param::new("optional", "Optional").bool(false).ignored(),
    Param::new("emojis", "Emoji shortcodes").ignored(),
];

fn post_process(r: &mut ParsedUrl) {
    r.secure = r.scheme.ends_with('s');
    if let Some(v) = r.query.get("verify") {
        r.verify = parse_bool(v, true);
    }
    if let Some(v) = r.query.get("redirect") {
        r.redirect = parse_bool(v, true);
    }
    if let Some(p) = r.query.get("password") {
        r.password = Some(p.to_string());
    }
    if let Some(p) = r.query.get("pass") {
        r.password = Some(p.to_string());
    }
    if let Some(u) = r.query.get("user") {
        let had_password = r.password.is_some();
        r.user = Some(u.to_string());
        if !had_password {
            // The original user@ becomes the password.
            if let Some(again) = parse_raw(&r.url, "unknown", ParseOptions::default()) {
                r.password = again.user;
            }
        }
    }
    if let Some(v) = r.query.get("rto") {
        r.rto = v.trim().parse().ok();
    }
    if let Some(v) = r.query.get("cto") {
        r.cto = v.trim().parse().ok();
    }
    if let Some(v) = r.query.get("port") {
        r.port = v.trim().parse::<u16>().ok();
    }
    if let Some(v) = r.query.get("format") {
        r.format = NotifyFormat::parse(&v.to_lowercase());
        if r.format.is_none() {
            log::warn!("Unsupported format specified {v:?}");
        }
    }
    if let Some(v) = r.query.get("overflow") {
        r.overflow = OverflowMode::parse(&v.to_lowercase());
        if r.overflow.is_none() {
            log::warn!("Unsupported overflow mode specified {v:?}");
        }
    }
    if let Some(v) = r.query.get("tz") {
        r.tz = Some(v.to_string());
    }
    if let Some(v) = r.query.get("retry").filter(|v| !v.is_empty()) {
        r.retry = v.trim().parse().ok();
    }
    if let Some(v) = r.query.get("wait").filter(|v| !v.is_empty()) {
        r.wait = v.trim().parse().ok();
    }
    if let Some(v) = r.query.get("optional") {
        r.optional = Some(parse_bool(v, false));
    }
}

impl ParsedUrl {
    /// Unquoted user, if any.
    pub fn user(&self) -> Option<String> {
        self.user.as_deref().map(unquote)
    }
    /// Unquoted password, if any.
    pub fn password(&self) -> Option<String> {
        self.password.as_deref().map(unquote)
    }
    /// Unquoted host.
    pub fn host(&self) -> String {
        unquote(&self.host)
    }
    /// Unquoted, decoded path segments.
    pub fn path_segments(&self) -> Vec<String> {
        split_path(self.fullpath.as_deref().unwrap_or(""), true)
    }
    /// Query option (already unquoted).
    pub fn param(&self, key: &str) -> Option<&str> {
        self.query.get(key)
    }
    /// First present key among `keys`.
    pub fn param_any(&self, keys: &[&str]) -> Option<&str> {
        keys.iter().find_map(|k| self.query.get(k))
    }
    /// `true` when query option `key` is present (even if empty).
    pub fn has_param(&self, key: &str) -> bool {
        self.query.contains(key)
    }
    /// `parse_bool(query[key], default)`; `default` when absent.
    pub fn param_bool(&self, key: &str, default: bool) -> bool {
        self.query.get(key).map(|v| parse_bool(v, default)).unwrap_or(default)
    }
    /// Non-empty param value.
    pub fn param_nonempty(&self, key: &str) -> Option<&str> {
        self.query.get(key).filter(|v| !v.is_empty())
    }
    /// Non-empty param value, percent-decoded.
    pub fn text(&self, key: &str) -> Option<String> {
        self.param_nonempty(key).map(unquote)
    }
    /// Param value as an integer (`None` when absent or not a number).
    pub fn int(&self, key: &str) -> Option<i64> {
        self.param_nonempty(key).and_then(crate::util::parse_int)
    }
    /// Param value split into a list (`a,b c` -> `[a, b, c]`).
    pub fn list(&self, key: &str) -> Vec<String> {
        self.param_nonempty(key).map(|v| crate::parse::parse_list([v])).unwrap_or_default()
    }
    /// `http`/`https` depending on `secure`.
    pub fn http_scheme(&self) -> &'static str {
        if self.secure { "https" } else { "http" }
    }
}

/// Split on whitespace, `,`, `/`, `\`.
pub fn split_path(path: &str, unquote_parts: bool) -> Vec<String> {
    let re = regex!(r"[ \t\r\n,\\/]+");
    re.split(path.trim_start_matches('/'))
        .filter(|s| !s.is_empty())
        .map(|s| if unquote_parts { unquote(s) } else { s.to_string() })
        .collect()
}

/// Percent-decoding (UTF-8; invalid bytes become U+FFFD; malformed escapes kept).
pub fn unquote(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if let (b'%', Some(hi), Some(lo)) =
            (b[i], b.get(i + 1).and_then(|&c| hex(c)), b.get(i + 2).and_then(|&c| hex(c)))
        {
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// [`unquote`] with `+` as a space.
pub fn unquote_plus(s: &str) -> String {
    unquote(&s.replace('+', " "))
}

/// Characters left unescaped in URL paths.
pub const PATH_SAFE: &str = "/:@!$&'()*+=";

/// Percent-encoding: keeps ASCII alphanumerics, `_.-~` and the `safe` characters; percent-encodes UTF-8 bytes otherwise.
pub fn quote(s: &str, safe: &str) -> String {
    let mut out = String::with_capacity(s.len());
    quote_into(&mut out, s, safe, false);
    out
}

/// [`quote`] with spaces as `+`.
pub fn quote_plus(s: &str, safe: &str) -> String {
    let mut out = String::with_capacity(s.len());
    quote_into(&mut out, s, safe, true);
    out
}

/// Append `s` percent-encoded to `out`; `plus` writes spaces as `+`.
fn quote_into(out: &mut String, s: &str, safe: &str, plus: bool) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in s.as_bytes() {
        if plus && b == b' ' {
            out.push('+');
        } else if b.is_ascii_alphanumeric() || b"_.-~".contains(&b) || (b.is_ascii() && safe.as_bytes().contains(&b)) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0xF) as usize] as char);
        }
    }
}

/// `application/x-www-form-urlencoded` encoding (form bodies and query strings).
pub fn form_urlencode<'a, I, K, V>(pairs: I) -> String
where
    I: IntoIterator<Item = &'a (K, V)>,
    K: AsRef<str> + 'a,
    V: AsRef<str> + 'a,
{
    let mut out = String::new();
    for (k, v) in pairs {
        if !out.is_empty() {
            out.push('&');
        }
        quote_into(&mut out, k.as_ref(), "", true);
        out.push('=');
        quote_into(&mut out, v.as_ref(), "", true);
    }
    out
}

/// Extract the scheme from a URL. Same as matching `^\s*([a-zA-Z0-9]{1,32})://` (`\s` is Unicode whitespace).
pub fn scheme_of(url: &str) -> Option<String> {
    let rest = url.trim_start();
    let len = rest.bytes().take_while(u8::is_ascii_alphanumeric).count();
    let (scheme, tail) = rest.split_at(len);
    ((1..=32).contains(&len) && tail.starts_with("://")).then(|| scheme.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    #[test]
    fn common_timeouts_are_the_transport_defaults() {
        let default = |k: &str| {
            super::COMMON_PARAMS.iter().find(|p| p.key == k).map(|p| p.default.parse::<f64>().unwrap_or(-1.0))
        };
        assert_eq!(default("cto"), Some(crate::http::DEFAULT_CONNECT_TIMEOUT.as_secs_f64()));
        assert_eq!(default("rto"), Some(crate::http::DEFAULT_READ_TIMEOUT.as_secs_f64()));
    }

    use super::*;

    #[test]
    fn tidy_path_matches_the_regexes() {
        let full = |path: &str| -> String {
            let p = regex!(r"(^[\\]{2}|[^\\\s][\\]|[\s][\\]{2}])([\\]+)").replace_all(path.trim(), "$1");
            let p = regex!(r"([/])([/]+)").replace_all(&p, "$1");
            regex!(r"^(.+[^:][^\\])[\s\\]*$").replace_all(&p, "$1").into_owned()
        };
        let alphabet = ["a", ":", "/", "\\", " ", "\u{2003}", "\n", "]"];
        let mut srcs = vec![String::new()];
        let mut frontier = srcs.clone();
        for _ in 0..6 {
            frontier = frontier.iter().flat_map(|s| alphabet.iter().map(move |a| format!("{s}{a}"))).collect();
            srcs.extend(frontier.iter().cloned());
        }
        for src in &srcs {
            assert_eq!(tidy_path(src), full(src), "{src:?}");
        }
    }

    #[test]
    fn scheme_of_matches_the_regex() {
        let re = regex!(r"^\s*([a-zA-Z0-9]{1,32})://");
        let long = "a".repeat(32);
        let longer = "a".repeat(33);
        let alphabet = ["a", "Z", "9", ":", "/", " ", "\u{2003}", "\n", "é", "_", "://", &long, &longer];
        let mut srcs = vec![String::new()];
        let mut frontier = srcs.clone();
        for _ in 0..4 {
            frontier = frontier.iter().flat_map(|s| alphabet.iter().map(move |a| format!("{s}{a}"))).collect();
            srcs.extend(frontier.iter().cloned());
        }
        for src in &srcs {
            assert_eq!(scheme_of(src), re.captures(src).map(|c| c[1].to_lowercase()), "{src:?}");
        }
    }

    #[test]
    fn basic_parts() {
        let u = parse_url("json://user:pass@localhost:8080/path/to?verify=no&+X-Head=1&-drop=&:map=new").unwrap();
        assert_eq!(u.scheme, "json");
        assert_eq!(u.user.as_deref(), Some("user"));
        assert_eq!(u.password.as_deref(), Some("pass"));
        assert_eq!(u.host, "localhost");
        assert_eq!(u.port, Some(8080));
        assert_eq!(u.fullpath.as_deref(), Some("/path/to"));
        assert_eq!(u.path.as_deref(), Some("/path/"));
        assert_eq!(u.last_segment.as_deref(), Some("to"));
        assert!(!u.verify);
        assert_eq!(u.query_plus.get("X-Head"), Some("1"));
        assert!(u.query_minus.contains("drop"));
        assert_eq!(u.query_colon.get("map"), Some("new"));
        assert_eq!(u.url, "json://user:pass@localhost:8080/path/to");
    }

    #[test]
    fn trailing_slash_kept() {
        let u = parse_url("json://localhost/a/").unwrap();
        assert_eq!(u.fullpath.as_deref(), Some("/a/"));
        assert_eq!(u.last_segment, None);
    }

    #[test]
    fn invalid_host_rejected() {
        assert!(parse_url("json://-bad-/").is_none());
        assert!(parse_url_unverified("tgram://123:abc/").is_some());
    }

    #[test]
    fn user_param_moves_user_to_password() {
        let u = parse_url("json://secret@localhost?user=bob").unwrap();
        assert_eq!(u.user.as_deref(), Some("bob"));
        assert_eq!(u.password.as_deref(), Some("secret"));
    }

    #[test]
    fn percent_encoding() {
        assert_eq!(quote("a b/c", "/"), "a%20b/c");
        assert_eq!(quote_plus("a b&c", ""), "a+b%26c");
        assert_eq!(unquote("a%20b%zz"), "a b%zz");
        assert_eq!(unquote("%E2%82%ac%"), "€%");
        assert_eq!(unquote("%ff"), "\u{FFFD}");
    }

    #[test]
    fn tidy() {
        assert_eq!(tidy_path("//a//b///"), "/a/b/");
        assert_eq!(tidy_path("/"), "/");
        assert_eq!(tidy_path("/a/b/ "), "/a/b/");
        assert_eq!(tidy_path("http://x//y"), "http:/x/y");
    }
}
