//! URL helpers shared by the JSON, form and XML webhooks (`json://`, `form://`, `xml://`).

use crate::http::Method;
use crate::service::ServiceDef;
use crate::url::{ParsedUrl, unquote};
use crate::Result;

/// Methods accepted by the JSON, form and XML webhooks.
pub(crate) fn parse_method(def: &'static ServiceDef, u: &ParsedUrl) -> Result<Method> {
    match u.param_nonempty("method") {
        None => Ok(Method::Post),
        Some(m) => Method::parse(&unquote(m)).ok_or_else(|| def.err(format!("invalid method {m:?}"))),
    }
}

/// `{scheme}://{host}[:port]{fullpath}` with the raw (still quoted) path.
pub(crate) fn endpoint(u: &ParsedUrl) -> String {
    let mut url = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = u.port {
        url.push_str(&format!(":{p}"));
    }
    url.push_str(u.fullpath.as_deref().unwrap_or(""));
    url
}

/// `+`, `-` and `:` entries, unquoted a second time.
pub(crate) fn double_unquoted(p: &crate::url::Pairs) -> Vec<(String, String)> {
    p.iter().map(|(k, v)| (unquote(k), unquote(v))).collect()
}
