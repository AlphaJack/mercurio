//! Small helpers on text that several endpoints share.

/// Whether `s` has more than white space: an empty or blank setting counts as unset.
pub(super) fn non_blank<S: AsRef<str>>(s: &S) -> bool {
    !s.as_ref().trim().is_empty()
}

/// Parse `a=b&c=d` (a form or a query string).
pub(super) fn form_pairs(s: &str) -> Vec<(String, String)> {
    use mercurio::__private::unquote_plus;
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (unquote_plus(k), unquote_plus(v)),
            None => (unquote_plus(p), String::new()),
        })
        .collect()
}

/// A JSON value as text: a string as it is, anything else as JSON.
pub(super) fn value_text(v: &serde_json::Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), str::to_owned)
}

/// An optional value, trimmed; empty when absent.
pub(super) fn trimmed(v: Option<String>) -> String {
    v.unwrap_or_default().trim().to_owned()
}
