//! Small helpers shared by many services.

use serde_json::{Map, Value};

/// The first line of `text`, trimmed.
pub(crate) fn first_line(text: &str) -> &str {
    text.split('\n').next().unwrap_or_default().trim()
}

/// The first of `options` that starts with `prefix`.
pub(crate) fn starting_with<'a>(options: &[&'a str], prefix: &str) -> Option<&'a str> {
    options.iter().copied().find(|x| x.starts_with(prefix))
}

/// Escapes `&`, `<` and `>` only.
pub(crate) fn html_escape_noquote(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// [`html_escape_noquote`] plus `"`, for double-quoted attribute values.
pub(crate) fn html_escape_attr(s: &str) -> String {
    html_escape_noquote(s).replace('"', "&quot;")
}

/// Escape `&`, `<`, `>`, quotes; optionally turn newlines into `<br/>` (`convert_new_lines`) and spaces and tabs into `&nbsp;` / `&emsp;` (`whitespace`).
pub(crate) fn escape_html(s: &str, convert_new_lines: bool, whitespace: bool) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 8);
    escape_html_into(&mut out, s, convert_new_lines, whitespace);
    out
}

/// [`escape_html`] appended to `out` in one pass, with no copy of `s` per replacement.
pub(crate) fn escape_html_into(out: &mut String, s: &str, convert_new_lines: bool, whitespace: bool) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&apos;"),
            '"' => out.push_str("&quot;"),
            '\t' if whitespace => out.push_str("&emsp;"),
            ' ' if whitespace => out.push_str("&nbsp;"),
            '\n' if convert_new_lines => out.push_str("<br/>"),
            other => out.push(other),
        }
    }
}

/// XML text escaping (`&`, `<`, `>`).
pub(crate) fn xml_escape(s: &str) -> String {
    html_escape_noquote(s)
}

/// First `n` characters (not bytes).
pub(crate) fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Apply `:key=newkey` payload remaps: an existing key is renamed (or dropped when `newkey` is empty); an unknown key is added.
pub(crate) fn remap_payload<'a>(
    payload: &mut Map<String, Value>,
    remaps: impl IntoIterator<Item = (&'a str, &'a str)>,
) {
    for (key, new) in remaps {
        if let Some(v) = payload.remove(key) {
            if !new.is_empty() {
                payload.insert(new.to_owned(), v);
            }
        } else {
            payload.insert(key.to_owned(), Value::String(new.to_owned()));
        }
    }
}

/// The value of the first key in `map` that `text` starts with, else the default.
pub(crate) fn by_prefix<V: Copy + Default>(map: &[(&str, V)], text: &str) -> V {
    map.iter().find(|(k, _)| text.starts_with(k)).map(|(_, v)| *v).unwrap_or_default()
}

/// The `host[:port]` that starts `rest`, the part of a URL after `scheme://`.
pub(crate) fn authority(rest: &str) -> &str {
    rest.split(['/', '?']).next().unwrap_or("")
}

/// Whether `s` has more than whitespace.
pub(crate) fn non_blank<S: AsRef<str>>(s: &S) -> bool {
    !s.as_ref().trim().is_empty()
}

/// The text of a JSON string.
pub(crate) fn json_string<V: std::borrow::Borrow<Value>>(v: V) -> Option<String> {
    v.borrow().as_str().map(str::to_owned)
}

/// The text of a regex match, parsed as a `T`.
pub(crate) fn parse_match<T: std::str::FromStr>(m: crate::re::Match<'_>) -> Option<T> {
    m.as_str().parse().ok()
}

/// The text of a regex match, trimmed.
pub(crate) fn trimmed_match(m: crate::re::Match<'_>) -> String {
    m.as_str().trim().to_owned()
}

/// The parts of `text` that `separators` splits it into, without empty ones.
pub(crate) fn split_nonempty(separators: &crate::re::Regex, text: &str) -> Vec<String> {
    separators.split(text).filter(|s| !s.is_empty()).map(str::to_owned).collect()
}

/// `n` as a `u32`, `u32::MAX` when it is larger.
pub(crate) fn saturating_u32<N: TryInto<u32>>(n: N) -> u32 {
    n.try_into().unwrap_or(u32::MAX)
}

/// The first of `options` that starts with `prefix`, when `prefix` is not empty.
pub(crate) fn completing<'a>(options: &[&'a str], prefix: &str) -> Option<&'a str> {
    if prefix.is_empty() { None } else { starting_with(options, prefix) }
}

/// `?` and the text of a regex match.
pub(crate) fn query_suffix(m: crate::re::Match<'_>) -> String {
    format!("?{}", m.as_str())
}

/// The strings of a JSON list.
pub(crate) fn json_strings_of(list: &[Value]) -> Vec<String> {
    list.iter().filter_map(json_string).collect()
}

/// `derive()`, once per process for each `id`: tests derive the same few slow keys again and again.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn derive_once<K: Ord, V: Clone>(
    cache: &std::sync::Mutex<std::collections::BTreeMap<K, V>>,
    id: K,
    derive: impl FnOnce() -> V,
) -> V {
    if let Some(v) = cache.lock().ok().and_then(|d| d.get(&id).cloned()) {
        return v;
    }
    let v = derive();
    if let Ok(mut d) = cache.lock() {
        d.insert(id, v.clone());
    }
    v
}

/// Decode a variable byte integer; returns (value, bytes used).
pub(crate) fn decode_varint(data: &[u8]) -> Option<(usize, usize)> {
    let mut value = 0usize;
    let mut mult = 1usize;
    for (i, b) in data.iter().enumerate().take(4) {
        value += (*b as usize & 0x7f) * mult;
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
        mult *= 128;
    }
    None
}

/// A copy of what `m` holds, even after a panic poisoned it.
pub(crate) fn held<T: Clone>(m: &std::sync::Mutex<T>) -> T {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
}

/// A JSON object of `pairs`, each value a string.
pub(crate) fn json_strings(pairs: &[(String, String)]) -> Map<String, Value> {
    pairs.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect()
}

/// A decimal integer with optional sign, surrounding whitespace ignored.
pub(crate) fn parse_int(s: &str) -> Option<i64> {
    parse_trimmed(s)
}

/// `s` without its surrounding whitespace, parsed as a `T`.
pub(crate) fn parse_trimmed<T: std::str::FromStr>(s: &str) -> Option<T> {
    s.trim().parse().ok()
}

/// `s` with each run of whitespace made one space, and none at the ends.
pub(crate) fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// `s` in lower case, without surrounding whitespace.
pub(crate) fn lower_trimmed(s: &str) -> String {
    s.to_lowercase().trim().to_owned()
}

/// Whether `v` holds a value: false for `null`, `false`, zero, empty strings, empty arrays and empty objects.
pub(crate) fn json_has_value(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// A JSON value as plain text: strings unquoted, `null` empty, the rest as JSON.
pub(crate) fn json_text(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other @ (Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_)) => other.to_string(),
    }
}

/// A JSON scalar that holds a value, as text (tokens, ids, names).
pub(crate) fn scalar_text(v: &Value) -> Option<String> {
    (!v.is_array() && !v.is_object() && json_has_value(v)).then(|| json_text(v))
}

/// An integer JSON value: a number (truncated) or a decimal string.
pub(crate) fn json_int(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_f64().map(|f| f.trunc() as i64)).or_else(|| v.as_str().and_then(parse_int))
}

/// `s` escaped for use inside a JSON string literal (no surrounding quotes).
pub(crate) fn json_escape(s: &str) -> String {
    let quoted = Value::from(s).to_string();
    quoted.strip_prefix('"').and_then(|q| q.strip_suffix('"')).unwrap_or_default().to_owned()
}

/// `re.sub(f, text)`: every match replaced by `f(captures)`; `None` from `f` aborts.
pub(crate) fn replace_all(
    re: &crate::re::Regex,
    text: &str,
    mut f: impl FnMut(&crate::re::Captures<'_>) -> Option<String>,
) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for c in re.captures_iter(text) {
        let Some(m) = c.get(0) else { continue };
        out.push_str(text.get(last..m.start())?);
        out.push_str(&f(&c)?);
        last = m.end();
    }
    out.push_str(text.get(last..)?);
    Some(out)
}

/// Query pairs with keys and values percent-decoded.
pub(crate) fn unquoted_pairs(p: &crate::url::Pairs) -> Vec<(String, String)> {
    p.iter().map(|(k, v)| (crate::url::unquote(k), crate::url::unquote(v))).collect()
}

#[cfg(test)]
mod escape_tests {
    use super::*;

    /// What `escape_html` did before it wrote in one pass: a replacement per character class.
    fn chained(s: &str, new_lines: bool, whitespace: bool) -> String {
        let mut out = s
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('\'', "&apos;")
            .replace('"', "&quot;");
        if whitespace {
            out = out.replace('\t', "&emsp;").replace(' ', "&nbsp;");
        }
        if new_lines {
            out = out.replace('\n', "<br/>");
        }
        out
    }

    #[test]
    fn one_pass_matches_the_chained_replacements() {
        for s in ["", "plain", "a & b < c > d 'e' \"f\"\n\tg  h", "&amp; already", "ünï\u{1F680}<b>\r\n</b>"] {
            for (nl, ws) in [(false, false), (true, false), (false, true), (true, true)] {
                assert_eq!(escape_html(s, nl, ws), chained(s, nl, ws), "{s:?} {nl} {ws}");
            }
        }
    }
}
