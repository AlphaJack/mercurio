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

/// `{scheme}://{host}[:port]{fullpath}` with the raw (still quoted) path; an encoded `/` (`%2F`) stays encoded, so it is one path segment (Apprise turns it into a separator, its issue #1799).
pub(crate) fn endpoint(u: &ParsedUrl) -> String {
    let mut url = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = u.port {
        url.push_str(&format!(":{p}"));
    }
    let path = crate::url::fullpath_keeping_encoded_slashes(u).or_else(|| u.fullpath.clone());
    url.push_str(path.as_deref().unwrap_or(""));
    url
}

/// `+`, `-` and `:` entries, unquoted a second time.
pub(crate) fn double_unquoted(p: &crate::url::Pairs) -> Vec<(String, String)> {
    p.iter().map(|(k, v)| (unquote(k), unquote(v))).collect()
}

#[cfg(test)]
mod tests {
    use crate::{Asset, Message, Plan};

    fn request_url(url: &str) -> String {
        let plan = crate::parse(url).unwrap().plan(&Message::new("b"), &Asset::default()).unwrap();
        let Plan::Http(req, _) = plan else { panic!("{plan:?}") };
        req.url
    }

    #[test]
    fn encoded_slash_stays_one_segment() {
        for scheme in ["json", "xml", "form"] {
            assert_eq!(request_url(&format!("{scheme}://host/a%2Fb/c")), "http://host/a%2Fb/c", "{scheme}");
            assert_eq!(request_url(&format!("{scheme}://host/a%2fb")), "http://host/a%2Fb", "{scheme}");
            // Everything else is as before.
            assert_eq!(request_url(&format!("{scheme}://host/a/b/")), "http://host/a/b/", "{scheme}");
            assert_eq!(request_url(&format!("{scheme}://host:8080/x%20y")), "http://host:8080/x%20y", "{scheme}");
            assert_eq!(request_url(&format!("{scheme}://host")), "http://host", "{scheme}");
        }
    }
}
