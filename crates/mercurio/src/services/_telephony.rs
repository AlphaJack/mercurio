//! Helpers shared by SMS/pager services.

use serde_json::Value;

use crate::error::Error;
use crate::http::Response;
use crate::parse::{PhoneNo, is_phone_no, parse_phone_no};
use crate::url::{ParsedUrl, unquote};

/// Query option `key` when present and non-empty, unquoted a second time.
pub(crate) fn param_unquoted(u: &ParsedUrl, key: &str) -> Option<String> {
    u.param_nonempty(key).map(unquote)
}

/// `v` unquoted; empty when absent.
pub(crate) fn unquote_or_empty(v: Option<&str>) -> String {
    v.map(unquote).unwrap_or_default()
}

/// `parse_phone_no(targets)` followed by `is_phone_no(target, min_len)`: each raw entry with its parse result.
pub(crate) fn phone_entries<I, S>(targets: I, min_len: usize) -> Vec<(String, Option<PhoneNo>)>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    parse_phone_no(targets, true, false)
        .into_iter()
        .map(|t| {
            let r = is_phone_no(&t, min_len);
            (t, r)
        })
        .collect()
}

/// The valid numbers (`result["full"]`) of [`phone_entries`].
pub(crate) fn valid_phones<I, S>(targets: I, min_len: usize) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    phone_entries(targets, min_len).into_iter().filter_map(|(_, r)| r.map(|p| p.full)).collect()
}

/// The `{apikey}@{from_phone}/{targets}` layout shared by telnyx, httpsms and eight00com: `?from=` moves the host into the targets. Returns the source number (`full`) and the targets; when no targets were given at all, the source itself is notified. `None` when the source is not a phone number.
pub(crate) fn source_and_targets(u: &ParsedUrl, min_len: usize) -> Option<(String, Vec<String>)> {
    let (source, mut raw) = match param_unquoted(u, "from") {
        Some(f) => {
            let mut t = crate::parse::parse_phone_no_unquoted([u.host.as_str()], false);
            t.extend(u.path_segments());
            (f, t)
        }
        None => (u.host(), u.path_segments()),
    };
    if let Some(to) = u.param_nonempty("to") {
        raw.extend(crate::parse::parse_phone_no_unquoted([to], false));
    }
    let source = is_phone_no(&source, 10)?.full;
    let mut has_error = false;
    let mut targets = Vec::new();
    for (_, r) in phone_entries(&raw, min_len) {
        match r {
            Some(p) => targets.push(p.full),
            None => has_error = true,
        }
    }
    if raw.is_empty() && !has_error {
        targets.push(source.clone());
    }
    Some((source, targets))
}

/// `loads(r.content)` when it is a JSON object, else `None`.
pub(crate) fn json_object(r: &Response) -> Option<serde_json::Map<String, Value>> {
    match r.json() {
        Some(Value::Object(m)) => Some(m),
        _ => None,
    }
}

pub(crate) use crate::util::json_has_value as has_value;

pub(crate) fn http_err(r: &Response) -> Error {
    r.http_error()
}

/// `multipart/form-data` builder where any part may carry a filename and/or a content type (requests' `files=[(name, (None, data, mime))]`).
#[derive(Debug, Default)]
pub(crate) struct Form {
    parts: Vec<FormPart>,
}

#[derive(Debug)]
struct FormPart {
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    data: Vec<u8>,
}

impl Form {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn part(
        mut self,
        name: &str,
        filename: Option<&str>,
        content_type: Option<&str>,
        data: impl Into<Vec<u8>>,
    ) -> Self {
        self.parts.push(FormPart {
            name: name.into(),
            filename: filename.map(Into::into),
            content_type: content_type.map(Into::into),
            data: data.into(),
        });
        self
    }

    pub(crate) fn text(self, name: &str, value: &str) -> Self {
        self.part(name, None, None, value.as_bytes().to_vec())
    }

    /// `(content_type, body)`.
    pub(crate) fn finish(self) -> (String, Vec<u8>) {
        let boundary = crate::crypto::random_hex(16);
        let mut body = Vec::new();
        for FormPart { name, filename, content_type: ct, data } in &self.parts {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            let mut disp = format!("Content-Disposition: form-data; name=\"{}\"", name.replace('"', "%22"));
            if let Some(f) = filename {
                disp.push_str(&format!("; filename=\"{}\"", f.replace('"', "%22")));
            }
            body.extend_from_slice(disp.as_bytes());
            body.extend_from_slice(b"\r\n");
            if let Some(ct) = ct.as_ref().filter(|c| !c.is_empty()) {
                body.extend_from_slice(format!("Content-Type: {ct}\r\n").as_bytes());
            }
            body.extend_from_slice(b"\r\n");
            body.extend_from_slice(data);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        (format!("multipart/form-data; boundary={boundary}"), body)
    }

    pub(crate) fn apply(self, req: crate::http::Request) -> crate::http::Request {
        let (ct, body) = self.finish();
        req.body(body, Some(&ct))
    }
}
