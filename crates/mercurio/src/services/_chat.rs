//! Helpers shared by services (chat/webhook platforms).

use std::collections::BTreeMap;

use serde_json::Value;

use crate::service::Context;
use crate::transport::FileOp;
use crate::util::json_escape;

/// Lowercased `{name: id}` map from a list of `{"name": .., "id": ..}` objects (a missing name counts as `""`). `None` on a non-object entry or a non-string name.
pub fn name_id_map(entries: &[Value], id_key: &str) -> Option<BTreeMap<String, Value>> {
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

/// Where a `?template=` points: a local path or `file://` URL.
#[derive(Debug, Clone)]
pub enum TemplateSrc {
    /// Local file (plain path or `file://`).
    File(String),
    /// Remote template (`http://`, `https://`): not fetched by mercurio.
    Remote,
}

/// Parse a template location; `None` for an unsupported scheme.
pub fn template_source(s: &str) -> Option<TemplateSrc> {
    let scheme =
        crate::regex!(r"(?i)^\s*(?P<schema>[a-z0-9]{1,32})://").captures(s).map(|c| c["schema"].to_lowercase());
    match scheme.as_deref() {
        None => Some(TemplateSrc::File(s.to_string())),
        Some("file") => {
            let c = crate::regex!(r"(?i)^file://(?P<path>[^?]+)").captures(s)?;
            Some(TemplateSrc::File(crate::url::unquote(&c["path"])))
        }
        Some("http" | "https") => Some(TemplateSrc::Remote),
        Some(_) => None,
    }
}

/// The file steps behind [`read_template`], for [`crate::Notify::files`].
pub fn template_files(src: Option<&TemplateSrc>) -> Vec<FileOp> {
    match src {
        Some(TemplateSrc::File(path)) => FileOp::local_file(path).into(),
        _ => Vec::new(),
    }
}

/// The template (at most `max` bytes) read by [`template_files`]; `None` when it is inaccessible.
pub fn read_template(ctx: &Context<'_>, src: &TemplateSrc, max: u64) -> Option<String> {
    let TemplateSrc::File(path) = src else { return None };
    String::from_utf8(ctx.local_file(path, max).ok()?.to_vec()).ok()
}

/// Fill `{{ token }}` placeholders in a JSON template (values JSON-escaped). Keys match case-insensitively but are looked up exactly: a case mismatch returns `None`.
pub fn apply_template_json(template: &str, tokens: &[(String, String)]) -> Option<String> {
    if tokens.is_empty() {
        return Some(template.to_string());
    }
    let alts: Vec<String> = tokens.iter().map(|(k, _)| regex::escape(k)).collect();
    let re = regex::Regex::new(&format!(r"(?i)\{{\{{\s*({})\s*\}}\}}", alts.join("|"))).ok()?;
    crate::util::replace_all(&re, template, |c| {
        let key = c[0].strip_prefix("{{")?.strip_suffix("}}")?.trim();
        // Later duplicates win.
        tokens.iter().rev().find(|(k, _)| k == key).map(|(_, v)| json_escape(v))
    })
}
