//! Parsing helpers for URL values: booleans, lists, phone numbers, e-mail addresses, URLs, call signs, hosts and validated tokens.
//!
//! The `regex` crate has no lookarounds. Where a pattern needs them, the helpers below emulate the lookaround by scanning anchored candidates by hand.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock, Mutex};

use crate::re::Regex;

use crate::url::unquote;

/// Compile a regex once and return a `&'static Regex`.
#[macro_export]
#[doc(hidden)]
macro_rules! regex {
    ($re:expr $(,)?) => {{
        static RE: ::std::sync::LazyLock<$crate::__private::Regex> =
            ::std::sync::LazyLock::new(|| $crate::__private::Regex::new($re).expect("valid regex"));
        &*RE
    }};
}

/// Parse a yes/no word by its first two letters (`yes`, `on`, `true`, `enable`, `1`, ... and their negatives); anything else is `default`.
/// `s` as a port: digits only, 1 to 65535.
pub(crate) fn port(s: &str) -> Option<u16> {
    s.bytes().all(|b| b.is_ascii_digit()).then(|| s.parse().ok()).flatten().filter(|p| *p > 0)
}

/// Apprise's boolean: `yes`, `true`, `on`, `1`, ... are `true`, `no`, `false`, `off`, `0`, ... are `false`; anything else is `default`.
pub fn parse_bool(arg: &str, default: bool) -> bool {
    let lower = arg.to_lowercase();
    let head: String = lower.chars().take(2).collect();
    match head.as_str() {
        "de" | "di" | "ne" | "f" | "n" | "no" | "of" | "0" | "fa" => false,
        "en" | "al" | "t" | "y" | "ye" | "on" | "1" | "tr" => true,
        _ => default,
    }
}

/// The non-empty items between runs of `[\[\];,\s]+` (`\s` is Unicode whitespace).
fn delimited(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| matches!(c, '[' | ']' | ';' | ',') || c.is_whitespace()).filter(|s| !s.is_empty())
}

/// Split on `[](),; whitespace`, dedupe, sort.
pub(crate) fn parse_list<I, S>(args: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut set: BTreeSet<String> = BTreeSet::new();
    for a in args {
        set.extend(delimited(a.as_ref()).map(str::to_owned));
    }
    set.into_iter().collect()
}

/// Split like [`parse_list`], keeping order and duplicates.
pub(crate) fn parse_list_unsorted<I, S>(args: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = Vec::new();
    for a in args {
        out.extend(delimited(a.as_ref()).map(str::to_owned));
    }
    out
}

/// Split on `[];,` only (not whitespace); items trimmed, sorted and deduplicated.
pub(crate) fn parse_list_keep_spaces<I, S>(args: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let re = regex!(r"[\[\];,]+");
    let set: BTreeSet<String> = args
        .into_iter()
        .flat_map(|a| re.split(a.as_ref()).map(|s| s.trim().to_owned()).collect::<Vec<_>>())
        .filter(|s| !s.is_empty())
        .collect();
    set.into_iter().collect()
}

/// [`parse_list`], then unquote each item.
pub(crate) fn parse_list_unquoted<I, S>(args: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    parse_list(args).into_iter().map(|s| unquote(&s)).filter(|s| !s.is_empty()).collect()
}

fn split_unparseable(arg: &str) -> Vec<String> {
    delimited(arg).map(str::to_owned).collect()
}

/// `$` inside a lookahead: end of string or a final `\n`.
fn at_end(rest: &str) -> bool {
    rest.is_empty() || rest == "\n"
}

/// Emulates `re.findall` for `CORE(?=LOOKAHEAD)` patterns.
///
/// `core` must be anchored with `^` and `$`. At each start position the longest (greedy) or shortest (lazy) candidate whose remainder satisfies `lookahead` wins, which is what a backtracking engine yields for these patterns.
fn findall_lookahead(
    text: &str,
    core: &Regex,
    lookahead: impl Fn(&str) -> bool,
    lazy: bool,
    max_len: usize,
) -> Vec<String> {
    let mut out = Vec::new();
    let bounds: Vec<usize> = text.char_indices().map(|(i, _)| i).chain([text.len()]).collect();
    let mut si = 0;
    while si < bounds.len() - 1 {
        let s = bounds[si];
        // Candidate ends are `bounds[si + 1..last]`.
        let last = si + 1 + bounds.get(si + 1..).unwrap_or_default().partition_point(|&e| e - s <= max_len);
        let matches = |&ei: &usize| {
            let e = bounds[ei];
            text.get(s..e).is_some_and(|head| core.is_match(head)) && lookahead(text.get(e..).unwrap_or_default())
        };
        let found = if lazy { (si + 1..last).find(matches) } else { (si + 1..last).rev().find(matches) };
        match found {
            Some(ei) => {
                out.push(text.get(s..bounds[ei]).unwrap_or_default().to_owned());
                si = ei;
            }
            None => si += 1,
        }
    }
    out
}

/// Phone numbers found in `args`; `prefix` also accepts a `label:` prefix. `store_unparseable` keeps the leftovers that are not numbers.
pub(crate) fn parse_phone_no<I, S>(args: I, store_unparseable: bool, prefix: bool) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = Vec::new();
    for arg in args {
        let arg = arg.as_ref();
        if arg.is_empty() {
            continue;
        }
        let found = if prefix {
            let core = regex!(r"(?i)^(?:[a-z]{1,32}:)?(?:[+(][+(\s]{0,32})?[0-9][0-9()\s-]{1,32}[0-9]$");
            let la = regex!(r"(?i)^(?:[a-z]{1,32}:)?[\s,+(]+[0-9]");
            findall_lookahead(arg, core, |r| at_end(r) || la.is_match(r), false, 140)
        } else {
            let core = regex!(r"^(?:[+(][+(\s]{0,32})?[0-9][0-9()\s-]{1,32}[0-9]$");
            let la = regex!(r"^[\s,+(]+[0-9]");
            findall_lookahead(arg, core, |r| at_end(r) || la.is_match(r), false, 100)
        };
        if !found.is_empty() {
            out.extend(found);
        } else if store_unparseable {
            out.extend(split_unparseable(arg));
        }
    }
    out
}

/// Unquote each entry, then [`parse_phone_no`].
pub(crate) fn parse_phone_no_unquoted<I, S>(args: I, prefix: bool) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let unq: Vec<String> = args.into_iter().map(|a| unquote(a.as_ref())).collect();
    parse_phone_no(unq, true, prefix)
}

/// Result of [`is_phone_no`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhoneNo {
    /// Last 7 digits (the subscriber number).
    pub line: String,
    /// The 3 digits before `line`, if any.
    pub area: String,
    /// Digits before `area` (country code), if any.
    pub country: String,
    /// Readable form, e.g. `+1 800-555-1234`.
    pub pretty: String,
    /// Digits only.
    pub full: String,
}

/// Validate a phone number with at least `min_len` digits.
pub(crate) fn is_phone_no(phone: &str, min_len: usize) -> Option<PhoneNo> {
    if !regex!(r"^\+?[0-9\s)(+-]+\s*$").is_match(phone) {
        return None;
    }
    let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() > 14 || digits.len() < min_len {
        return None;
    }
    let full = digits.clone();
    let n = digits.len();
    let (rest, line) = digits.split_at(n.saturating_sub(7));
    let line = line.to_owned();
    let (country, area) = rest.split_at(rest.len().saturating_sub(3));
    let mut pretty = String::new();
    if !country.is_empty() {
        pretty.push_str(&format!("+{country} "));
    }
    if !area.is_empty() {
        pretty.push_str(&format!("{area}-"));
    }
    if line.len() >= 7 {
        let (exchange, number) = line.split_at(3);
        pretty.push_str(&format!("{exchange}-{number}"));
    } else {
        pretty.push_str(&line);
    }
    Some(PhoneNo { line, area: area.to_owned(), country: country.to_owned(), pretty, full })
}

/// Result of [`is_email`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EmailAddr {
    /// Display name before the address, if any.
    pub name: String,
    /// Address without the `label+` part.
    pub email: String,
    /// Address as written, including any `label+` prefix.
    pub full_email: String,
    /// The `label` of `label+user@domain`, if any.
    pub label: String,
    /// Local part (before `@`).
    pub user: String,
    /// Domain part (after `@`).
    pub domain: String,
}

/// Parse an e-mail address, optionally with a display name and `+label`.
pub(crate) fn is_email(address: &str) -> Option<EmailAddr> {
    let re = regex!(
        r#"(?i)^(?:(?:[\s"']{0,32})?(?P<name>[^:<'"]{0,128})?[:<\s'"]{1,32})?(?P<full_email>(?:(?P<label>[^+\s]{1,128})\+)?(?P<email>(?P<userid>[a-z0-9_!#$%&*/=?%`{|}~^-]+(?:\.[a-z0-9_!#$%&'*/=?%`{|}~^-]+)*)@(?P<domain>(?:(?:[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9_-]*[a-z0-9]))|[a-z0-9][a-z0-9_-]{5,})))\s*>?"#
    );
    if !address.contains('@') {
        return None;
    }
    let c = re.captures(address)?;
    let g = |n: &str| c.name(n).map(|m| m.as_str().to_owned()).unwrap_or_default();
    Some(EmailAddr {
        name: g("name").trim_end_matches([' ', '\t', '\r', '\n', '\x0b', '\x0c', '+']).to_owned(),
        email: g("email"),
        full_email: g("full_email"),
        label: g("label").trim_matches([' ', '\t', '\r', '\n', '\x0b', '\x0c', '+']).to_owned(),
        user: g("userid"),
        domain: g("domain"),
    })
}

/// E-mail addresses found in `args`; `store_unparseable` keeps the leftovers.
pub(crate) fn parse_emails<I, S>(args: I, store_unparseable: bool) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    // The leading (?=[^\s,;]) lookahead is enforced by scanning start positions. No length bounds needed: the regex crate is linear-time.
    let core = regex!(
        r#"(?i)^(?:(?:"(?:[^"\\]|\\.)*"|[^<>"@,;\r\n])*?<[^@>\r\n]{1,64}@(?:[a-z0-9][a-z0-9_-]*\.)+[a-z]{2,63}>|[^\s@,;\r\n][^@,;\r\n]*@(?:[a-z0-9][a-z0-9_-]*\.)+[a-z]{2,63})"#
    );
    let mut out = Vec::new();
    for arg in args {
        let arg = arg.as_ref();
        if arg.is_empty() {
            continue;
        }
        let mut found = Vec::new();
        if arg.contains('@') {
            let mut i = 0;
            while i < arg.len() {
                let tail = arg.get(i..).unwrap_or_default();
                let Some(ch) = tail.chars().next() else { break };
                if !(ch.is_whitespace() || ch == ',' || ch == ';')
                    && let Some(m) = core.find(tail)
                    && !m.as_str().is_empty()
                {
                    found.push(m.as_str().to_owned());
                    i += m.end();
                    continue;
                }
                i += ch.len_utf8();
            }
        }
        if !found.is_empty() {
            out.extend(found);
        } else if store_unparseable {
            out.extend(split_unparseable(arg));
        }
    }
    out
}

/// URLs (`scheme://...`) found in `args`; `store_unparseable` keeps the leftovers.
pub fn parse_urls<I, S>(args: I, store_unparseable: bool) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let core = regex!(r"(?i)^[a-z0-9]+?://.*?$");
    let la = regex!(r"(?i)^[\s,;]{1,32}[a-z0-9]{1,32}?://");
    let mut out = Vec::new();
    for arg in args {
        let arg = arg.as_ref();
        if arg.is_empty() {
            continue;
        }
        let trimmed = arg.trim_end();
        let found = if arg.contains("://") {
            findall_lookahead(trimmed, core, |r| at_end(r) || la.is_match(r), true, usize::MAX)
        } else {
            Vec::new()
        };
        if !found.is_empty() {
            out.extend(found);
        } else if store_unparseable {
            out.extend(split_unparseable(arg));
        }
    }
    out
}

/// Result of [`is_call_sign`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallSign {
    /// Upper-cased call sign without SSID.
    pub callsign: String,
    /// SSID digits after `-` (may be empty).
    pub ssid: String,
}

/// Validate an amateur-radio call sign with an optional `-SSID`.
pub(crate) fn is_call_sign(callsign: &str) -> Option<CallSign> {
    let re = regex!(r"(?i)^(?P<callsign>[0-9a-z]{1,2}[0-9][a-z0-9]{1,3})(?:-(?P<ssid>[0-9]{1,2}))?\s*$");
    let c = re.captures(callsign)?;
    Some(CallSign {
        callsign: c["callsign"].to_uppercase(),
        ssid: c.name("ssid").map(|m| m.as_str().to_owned()).unwrap_or_default(),
    })
}

/// Call signs found in `args`; `store_unparseable` keeps the leftovers.
pub(crate) fn parse_call_sign<I, S>(args: I, store_unparseable: bool) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let core = regex!(r"(?i)^\s*[0-9a-z]{1,2}[0-9][a-z0-9]{1,3}(?:-[0-9]{1,2})?$");
    let la = regex!(r"^\s*[,;\s]+");
    let mut out = Vec::new();
    for arg in args {
        let arg = arg.as_ref();
        if arg.is_empty() {
            continue;
        }
        let found: Vec<String> = findall_lookahead(
            arg,
            core,
            |r| at_end(r.trim_start_matches(char::is_whitespace)) || la.is_match(r),
            false,
            64,
        )
        .into_iter()
        .map(|s| s.trim_start().to_owned())
        .collect();
        if !found.is_empty() {
            out.extend(found);
        } else if store_unparseable {
            out.extend(split_unparseable(arg));
        }
    }
    out
}

/// Whether the string starts with a UUID4.
pub(crate) fn is_uuid(s: &str) -> bool {
    regex!(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}").is_match(s)
}

/// Validate an IPv4 and/or IPv6 address. IPv6 results are returned wrapped in `[...]`.
pub(crate) fn is_ipaddr(addr: &str, ipv4: bool, ipv6: bool) -> Option<String> {
    if ipv4 {
        let re =
            regex!(r"^((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\n?$");
        if re.is_match(addr) {
            return Some(addr.to_owned());
        }
    }
    if ipv6 {
        let mut ip = addr;
        if let Some(inner) = ip.strip_prefix('[') {
            ip = inner.strip_suffix(']')?;
        } else if ip.ends_with(']') {
            return None;
        }
        let re = regex!(
            r"(?i)^((([0-9a-f]{1,4}:){7,7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}|([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}|([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}|([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})|:((:[0-9a-f]{1,4}){1,7}|:)|fe80:(:[0-9a-f]{0,4}){0,4}%[0-9a-z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-f]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])))\n?$"
        );
        if re.is_match(ip) {
            return Some(format!("[{ip}]"));
        }
    }
    None
}

/// For services that connect to the URL host: reject a host that is not a hostname or IP address. Also reject a port that is not a valid number.
pub(crate) fn require_host(u: &crate::url::ParsedUrl, def: &'static crate::service::ServiceDef) -> crate::Result<()> {
    if u.port_raw.is_some() || is_hostname(&u.host, true, true, true).is_none() {
        return Err(def.err("an invalid hostname or port was specified"));
    }
    Ok(())
}

/// Validate a hostname or IP address. Returns the normalised hostname.
pub(crate) fn is_hostname(hostname: &str, ipv4: bool, ipv6: bool, underscore: bool) -> Option<String> {
    if hostname.is_empty() || hostname.chars().count() > 253 {
        return None;
    }
    let mut h = hostname;
    if let Some(stripped) = h.strip_suffix('.') {
        h = stripped;
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels.len() == 4 && regex!(r"^[0-9.]+\n?$").is_match(h) {
        return is_ipaddr(h, ipv4, false);
    }
    let ok = |label: &str| -> bool {
        let re = if underscore {
            regex!(r"(?i)^(?:[a-z0-9][a-z0-9_-]{1,62}|[a-z_-])\n?$")
        } else {
            regex!(r"(?i)^(?:[a-z0-9][a-z0-9-]{1,62}|[a-z-])\n?$")
        };
        // (?<![_-]) / (?<!-): the label may not end with those characters (checked before the optional final newline).
        let core = label.strip_suffix('\n').unwrap_or(label);
        re.is_match(label) && !core.ends_with(['-']) && !(underscore && core.ends_with('_'))
    };
    if !labels.iter().all(|l| ok(l)) {
        return is_ipaddr(h, ipv4, ipv6);
    }
    Some(h.to_owned())
}

// `Arc`: a cloned `Regex` starts with an empty match cache, which costs more than the match. Keyed by pattern, then flags, so a lookup needs no allocation.
type RegexCache = BTreeMap<String, BTreeMap<String, Arc<Regex>>>;
static VALIDATE_CACHE: LazyLock<Mutex<RegexCache>> = LazyLock::new(|| Mutex::new(BTreeMap::new()));
/// Compiled patterns kept at most. mercurio's services use about a hundred; a caller passing patterns built at run time empties the cache when it fills.
const MAX_CACHED_REGEXES: usize = 256;

/// `value` (trimmed when `strip`) when it matches `pattern`.
///
/// The pattern is anchored at the start only. `flags` is a subset of `imsx`.
pub(crate) fn validate_regex(value: &str, pattern: &str, flags: &str, strip: bool) -> Option<String> {
    let re = compiled(pattern, flags)?;
    if !re.is_match(value) {
        return None;
    }
    Some(if strip { value.trim().to_owned() } else { value.to_owned() })
}

/// [`validate_regex`], then the named groups substituted into `fmt` (e.g. `"{token}"`).
pub(crate) fn validate_regex_fmt(value: &str, pattern: &str, flags: &str, fmt: &str) -> Option<String> {
    let re = compiled(pattern, flags)?;
    let caps = re.captures(value)?;
    let mut out = fmt.to_owned();
    for name in re.capture_names().flatten() {
        let v = caps.name(name).map(|m| m.as_str()).unwrap_or("");
        out = out.replace(&format!("{{{name}}}"), v);
    }
    Some(out.trim().to_owned())
}

/// Default `validate_regex` pattern: any non-whitespace start.
pub(crate) fn validate_nonblank(value: &str) -> Option<String> {
    validate_regex(value, r"[^\s]+", "i", true)
}

/// `None` for an invalid pattern (a bug in the calling service): nothing validates.
fn compiled(pattern: &str, flags: &str) -> Option<Arc<Regex>> {
    let mut cache = VALIDATE_CACHE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(r) = cache.get(pattern).and_then(|by_flags| by_flags.get(flags)) {
        return Some(r.clone());
    }
    let fl: String = flags.chars().filter(|c| "imsx".contains(*c)).collect();
    let prefix = if fl.is_empty() { String::new() } else { format!("(?{fl})") };
    let re = match Regex::new(&format!("{prefix}^(?:{})", pattern)) {
        Ok(re) => Arc::new(re),
        Err(e) => {
            log::error!("bad validate regex {pattern:?}: {e}");
            return None;
        }
    };
    if cache.values().map(BTreeMap::len).sum::<usize>() >= MAX_CACHED_REGEXES {
        cache.clear();
    }
    cache.entry(pattern.to_owned()).or_default().insert(flags.to_owned(), re.clone());
    Some(re)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_cache_is_bounded() {
        for i in 0..MAX_CACHED_REGEXES * 2 {
            assert!(validate_regex(&format!("x{i}"), &format!("x{i}"), "", false).is_some());
        }
        let cached: usize = VALIDATE_CACHE.lock().unwrap().values().map(BTreeMap::len).sum();
        assert!(cached <= MAX_CACHED_REGEXES, "{cached}");
    }

    /// With `regex-unicode`, `\s`, `\d`, `\w` and `(?i)` are Unicode-aware.
    #[cfg(feature = "regex-unicode")]
    #[test]
    fn regex_classes_are_unicode() {
        assert!(regex!(r"^\s+$").is_match("\u{A0}\u{2003}\u{3000}"));
        assert!(regex!(r"^\d$").is_match("\u{663}"));
        assert!(regex!(r"^\w+$").is_match("éж"));
        assert!(regex!(r"^(?i)é$").is_match("É"));
    }

    /// Without `regex-unicode`, `regex-lite` matches the same classes in ASCII only.
    #[cfg(not(feature = "regex-unicode"))]
    #[test]
    fn regex_classes_are_ascii() {
        assert!(!regex!(r"^\s+$").is_match("\u{A0}\u{2003}\u{3000}"));
        assert!(!regex!(r"^\d$").is_match("\u{663}"));
        assert!(!regex!(r"^\w+$").is_match("éж"));
        assert!(!regex!(r"^(?i)é$").is_match("É"));
        assert!(regex!(r"^\s+\d\w+$").is_match(" \t1a_"));
    }

    #[test]
    fn bools() {
        assert!(parse_bool("yes", false));
        assert!(!parse_bool("no", true));
        assert!(parse_bool("whatever", true));
        assert!(!parse_bool("disabled", true));
    }

    // The reference is a Unicode-aware regex; `regex-lite` classes are ASCII-only.
    #[cfg(feature = "regex-unicode")]
    #[test]
    fn delimited_matches_the_regex() {
        let re = regex!(r"[\[\];,\s]+");
        let alphabet = ["a", "[", "]", ";", ",", " ", "\u{2003}", "\n", "é", "("];
        let mut srcs = vec![String::new()];
        let mut frontier = srcs.clone();
        for _ in 0..5 {
            frontier = frontier.iter().flat_map(|s| alphabet.iter().map(move |a| format!("{s}{a}"))).collect();
            srcs.extend(frontier.iter().cloned());
        }
        for src in &srcs {
            let want: Vec<&str> = re.split(src).filter(|s| !s.is_empty()).collect();
            assert_eq!(delimited(src).collect::<Vec<_>>(), want, "{src:?}");
        }
    }

    #[test]
    fn lists() {
        assert_eq!(parse_list(["b, a ;c", "a"]), vec!["a", "b", "c"]);
        assert_eq!(parse_list_unsorted(["b,a,b"]), vec!["b", "a", "b"]);
    }

    #[test]
    fn phones() {
        assert_eq!(
            parse_phone_no(["+1 555 123 4567, 15551234568"], true, false),
            vec!["+1 555 123 4567", "15551234568"]
        );
        assert_eq!(parse_phone_no(["abc"], true, false), vec!["abc"]);
        let p = is_phone_no("+1 (555) 123-4567", 10).unwrap();
        assert_eq!(p.full, "15551234567");
        assert_eq!(p.pretty, "+1 555-123-4567");
    }

    #[test]
    fn emails() {
        let e = is_email("Name <user+label@example.com>").unwrap();
        // "label+" prefix convention, so `user` is the label here.
        assert_eq!(e.email, "label@example.com");
        assert_eq!(e.label, "user");
        assert_eq!(e.name, "Name");
        assert_eq!(parse_emails(["a@example.com, b@example.org"], true), vec!["a@example.com", "b@example.org"]);
        assert_eq!(parse_call_sign(["DF1ABC-1, W1AW"], true), vec!["DF1ABC-1", "W1AW"]);
    }

    #[test]
    fn hostnames() {
        assert_eq!(is_hostname("example.com", true, true, true).as_deref(), Some("example.com"));
        assert!(is_hostname("-bad", true, true, true).is_none());
        assert_eq!(is_hostname("[::1]", true, true, true).as_deref(), Some("[::1]"));
        assert_eq!(is_hostname("127.0.0.1", true, true, true).as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn urls() {
        assert_eq!(parse_urls(["json://a, xml://b/c"], true), vec!["json://a", "xml://b/c"]);
    }

    #[test]
    fn validate() {
        assert_eq!(validate_regex(" abc ", r"[a-z]+", "i", true), None);
        assert_eq!(validate_regex("abc ", r"[a-z]+", "i", true).as_deref(), Some("abc"));
        assert_eq!(validate_regex_fmt("bot123", r"bot(?P<id>[0-9]+)", "i", "{id}").as_deref(), Some("123"));
    }
}
