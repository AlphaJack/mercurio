//! Local configuration paths: `~` and, on Windows, environment variables expanded, made absolute.

use std::env::var;
use std::path::PathBuf;

/// `path_decode`: expand `~` (Windows: `%VAR%`, `$VAR`, `${VAR}`), make absolute.
pub(crate) fn path_decode(path: &str) -> PathBuf {
    let expanded = if cfg!(windows) {
        PathBuf::from(expand_vars(path, |name| var(name).ok()))
    } else if path == "~" || path.starts_with("~/") {
        match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(path.trim_start_matches('~').trim_start_matches('/')),
            None => PathBuf::from(path),
        }
    } else {
        PathBuf::from(path)
    };
    if expanded.is_absolute() {
        expanded
    } else {
        std::env::current_dir().map(|d| d.join(&expanded)).unwrap_or(expanded)
    }
}

/// Windows-style variable expansion: `%name%`, `$name` and `${name}` are replaced by `var(name)`; unknown names, unclosed forms and text inside `'...'` stay as written; `%%` and `$$` become `%` and `$`.
pub(crate) fn expand_vars(path: &str, var: impl Fn(&str) -> Option<String>) -> String {
    let is_name = |c: &u8| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-';
    let put = |out: &mut String, name: &str, form: String| match var(name).filter(|_| !name.is_empty()) {
        Some(v) => out.push_str(&v),
        None => out.push_str(&form),
    };
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(at) = rest.find(['\'', '%', '$']) {
        let (text, tail) = rest.split_at(at);
        out.push_str(text);
        rest = tail;
        if let Some(after) = rest.strip_prefix("%%").or_else(|| rest.strip_prefix("$$")) {
            out.push_str(rest.split_at(1).0);
            rest = after;
            continue;
        }
        if let Some(after) = rest.strip_prefix('\'') {
            let Some((quoted, tail)) = after.split_once('\'') else { break };
            out.push_str(&format!("'{quoted}'"));
            rest = tail;
            continue;
        }
        let (name, form, tail) = if let Some(after) = rest.strip_prefix('%') {
            let Some((name, tail)) = after.split_once('%') else { break };
            (name, format!("%{name}%"), tail)
        } else if let Some(after) = rest.strip_prefix("${") {
            let Some((name, tail)) = after.split_once('}') else { break };
            (name, format!("${{{name}}}"), tail)
        } else {
            let after = rest.strip_prefix('$').unwrap_or(rest);
            let (name, tail) = after.split_at(after.bytes().take_while(is_name).count());
            (name, format!("${name}"), tail)
        };
        put(&mut out, name, form);
        rest = tail;
    }
    out.push_str(rest);
    out
}
