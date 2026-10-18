//! Small helpers shared by many services.

use serde_json::{Map, Value};

/// Escapes `&`, `<` and `>` only.
pub fn html_escape_noquote(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// [`html_escape_noquote`] plus `"`, for double-quoted attribute values.
pub fn html_escape_attr(s: &str) -> String {
    html_escape_noquote(s).replace('"', "&quot;")
}

/// Escape `&`, `<`, `>`, quotes; optionally turn newlines into `<br/>` (`convert_new_lines`) and spaces and tabs into `&nbsp;` / `&emsp;` (`whitespace`).
pub fn escape_html(s: &str, convert_new_lines: bool, whitespace: bool) -> String {
    let mut out = s
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&apos;")
        .replace('"', "&quot;");
    if whitespace {
        out = out.replace('\t', "&emsp;").replace(' ', "&nbsp;");
    }
    if convert_new_lines {
        out = out.replace('\n', "<br/>");
    }
    out
}

/// XML text escaping (`&`, `<`, `>`).
pub fn xml_escape(s: &str) -> String {
    html_escape_noquote(s)
}

/// First `n` characters (not bytes).
pub fn truncate_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Apply `:key=newkey` payload remaps: an existing key is renamed (or dropped when `newkey` is empty); an unknown key is added.
pub fn remap_payload<'a>(payload: &mut Map<String, Value>, remaps: impl IntoIterator<Item = (&'a str, &'a str)>) {
    for (key, new) in remaps {
        if let Some(v) = payload.remove(key) {
            if !new.is_empty() {
                payload.insert(new.to_string(), v);
            }
        } else {
            payload.insert(key.to_string(), Value::String(new.to_string()));
        }
    }
}

/// A decimal integer with optional sign, surrounding whitespace ignored.
pub fn parse_int(s: &str) -> Option<i64> {
    s.trim().parse().ok()
}

/// Whether `v` holds a value: false for `null`, `false`, zero, empty strings, empty arrays and empty objects.
pub fn json_has_value(v: &Value) -> bool {
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
pub fn json_text(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other @ (Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_)) => other.to_string(),
    }
}

/// A JSON scalar that holds a value, as text (tokens, ids, names).
pub fn scalar_text(v: &Value) -> Option<String> {
    (!v.is_array() && !v.is_object() && json_has_value(v)).then(|| json_text(v))
}

/// An integer JSON value: a number (truncated) or a decimal string.
pub fn json_int(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_f64().map(|f| f.trunc() as i64)).or_else(|| v.as_str().and_then(parse_int))
}

/// `s` escaped for use inside a JSON string literal (no surrounding quotes).
pub fn json_escape(s: &str) -> String {
    let quoted = Value::from(s).to_string();
    quoted.strip_prefix('"').and_then(|q| q.strip_suffix('"')).unwrap_or_default().to_string()
}

/// `re.sub(f, text)`: every match replaced by `f(captures)`; `None` from `f` aborts.
pub fn replace_all(
    re: &regex::Regex,
    text: &str,
    mut f: impl FnMut(&regex::Captures<'_>) -> Option<String>,
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
pub fn unquoted_pairs(p: &crate::url::Pairs) -> Vec<(String, String)> {
    p.iter().map(|(k, v)| (crate::url::unquote(k), crate::url::unquote(v))).collect()
}
