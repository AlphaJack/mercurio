//! Helpers shared by services (chat/webhook platforms).

use std::collections::BTreeMap;

use serde_json::Value;

use crate::service::Context;
use crate::transport::FileOp;
use crate::util::json_escape;

/// Lowercased `{name: id}` map from a list of `{"name": .., "id": ..}` objects (a missing name counts as `""`). `None` on a non-object entry or a non-string name.
pub(crate) fn name_id_map(entries: &[Value], id_key: &str) -> Option<BTreeMap<String, Value>> {
    let mut out = BTreeMap::new();
    for e in entries {
        let o = e.as_object()?;
        let name = match o.get("name") {
            None => String::new(),
            Some(Value::String(s)) => s.to_lowercase(),
            Some(_) => return None,
        };
        out.insert(name, o.get(id_key).cloned().unwrap_or_else(|| Value::String(String::new())));
    }
    Some(out)
}

/// Where a `?template=` points: a local path, a `file://` URL or an `http(s)://` URL.
#[derive(Debug, Clone)]
pub(crate) enum TemplateSrc {
    /// Local file (plain path or `file://`).
    File(String),
    /// Remote template, downloaded before the first send and kept for the life of the URL (as Apprise keeps an attachment).
    Remote(String, std::sync::Arc<std::sync::Mutex<Option<String>>>),
}

/// Parse a template location; `None` for an unsupported scheme.
pub(crate) fn template_source(s: &str) -> Option<TemplateSrc> {
    let scheme =
        crate::regex!(r"(?i)^\s*(?P<schema>[a-z0-9]{1,32})://").captures(s).map(|c| c["schema"].to_lowercase());
    match scheme.as_deref() {
        None => Some(TemplateSrc::File(s.to_owned())),
        Some("file") => {
            let c = crate::regex!(r"(?i)^file://(?P<path>[^?]+)").captures(s)?;
            Some(TemplateSrc::File(crate::url::unquote(&c["path"])))
        }
        Some("http" | "https") => Some(TemplateSrc::Remote(s.trim().to_owned(), Default::default())),
        Some(_) => None,
    }
}

/// The file steps behind [`read_template`], for [`crate::Notify::files`].
pub(crate) fn template_files(src: Option<&TemplateSrc>) -> Vec<FileOp> {
    match src {
        Some(TemplateSrc::File(path)) => FileOp::local_file(path).into(),
        _ => Vec::new(),
    }
}

/// The download behind [`read_template`], for [`crate::Notify::fetches`]: none for a local or an already downloaded template.
pub(crate) fn template_fetches(ctx: &Context<'_>, src: Option<&TemplateSrc>, max: u64) -> Vec<crate::http::Request> {
    match src {
        Some(TemplateSrc::Remote(url, kept)) if kept.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_none() => {
            vec![crate::http::Request::get(url.clone()).header("User-Agent", ctx.app_id()).max_body(max)]
        }
        _ => Vec::new(),
    }
}

/// The template (at most `max` bytes) read by [`template_files`] or downloaded by [`template_fetches`]; `Err` says why it is inaccessible.
pub(crate) fn load_template(ctx: &Context<'_>, src: &TemplateSrc, max: u64) -> Result<String, &'static str> {
    match src {
        TemplateSrc::File(path) => {
            String::from_utf8(ctx.local_file(path, max)?.to_vec()).ok().ok_or("could not be read")
        }
        TemplateSrc::Remote(url, kept) => {
            let mut kept = kept.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(text) = kept.as_ref() {
                return Ok(text.clone());
            }
            let text = String::from_utf8(ctx.fetched(url)?.to_vec()).ok().ok_or("could not be read")?;
            *kept = Some(text.clone());
            Ok(text)
        }
    }
}

/// [`load_template`] without the reason.
pub(crate) fn read_template(ctx: &Context<'_>, src: &TemplateSrc, max: u64) -> Option<String> {
    load_template(ctx, src, max).ok()
}

/// Fill `{{ token }}` placeholders in a JSON template (values JSON-escaped). Keys match case-insensitively but are looked up exactly: a case mismatch returns `None`.
pub(crate) fn apply_template_json(template: &str, tokens: &[(String, String)]) -> Option<String> {
    if tokens.is_empty() {
        return Some(template.to_owned());
    }
    let alts: Vec<String> = tokens.iter().map(|(k, _)| crate::re::escape(k)).collect();
    let re = crate::re::Regex::new(&format!(r"(?i)\{{\{{\s*({})\s*\}}\}}", alts.join("|"))).ok()?;
    crate::util::replace_all(&re, template, |c| {
        let key = c[0].strip_prefix("{{")?.strip_suffix("}}")?.trim();
        // Later duplicates win.
        tokens.iter().rev().find(|(k, _)| k == key).map(|(_, v)| json_escape(v))
    })
}
