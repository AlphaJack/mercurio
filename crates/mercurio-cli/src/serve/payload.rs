//! Reading notification payloads: form, JSON, multipart or a plain text body; `X-Apprise-*` headers; `?:src=dest` field mapping; tag expressions; templates and attachments.

use mercurio::__private::yaml::Yaml;
use mercurio::{Attachment, TagFilter, TemplateVars};
use serde_json::{Map, Value};

use super::http::{Reply, Req, form_pairs};

/// A file part from a multipart body.
pub struct Upload {
    pub name: String,
    pub mime: Option<String>,
    /// A slice of the request body, not a copy of it.
    pub data: axum::body::Bytes,
}

#[derive(Default)]
pub struct Content {
    pub fields: Map<String, Value>,
    pub uploads: Vec<Upload>,
    /// `attach` / `attachment` / `attachments` values from a form, every repeat.
    pub form_attach: Option<Vec<String>>,
    /// Validated template values.
    pub template: Option<TemplateVars>,
}

impl Content {
    /// A non-empty string field.
    pub fn str(&self, key: &str) -> Option<&str> {
        self.fields.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
    }

    fn has(&self, key: &str) -> bool {
        self.fields.get(key).is_some_and(|v| match v {
            Value::Null => false,
            Value::String(s) => !s.is_empty(),
            Value::Array(a) => !a.is_empty(),
            Value::Object(o) => !o.is_empty(),
            Value::Bool(b) => *b,
            Value::Number(_) => true,
        })
    }
}

/// Fields a notification form knows.
const NOTIFY_FIELDS: &[&str] = &["format", "type", "title", "body", "attachment", "tag", "tags"];
const NOTIFY_TYPES: &[&str] = &["info", "success", "warning", "failure"];
const NOTIFY_FORMATS: &[&str] = &["text", "markdown", "html"];

/// Fields that name attachments in a form.
const ATTACH_FIELDS: [&str; 3] = ["attach", "attachment", "attachments"];

/// Form fields (`application/x-www-form-urlencoded` or multipart): the last value per name, the `(name, value)` pairs of `template[...]` and attachment fields (every repeat) and the uploaded files.
pub type FormFields = (Map<String, Value>, Vec<(String, String)>, Vec<Upload>);

pub fn form_fields(req: &Req) -> FormFields {
    let mut pairs = Vec::new();
    let mut uploads = Vec::new();
    if req.content_type() == "multipart/form-data" {
        let ct = req.header("content-type").unwrap_or("");
        // The body is moved into shared bytes, and an upload is a slice of them: no copy of the file.
        let body = axum::body::Bytes::from(req.take_body());
        for part in mercurio::__private::multipart_parts(ct, &body) {
            let name = part.name.unwrap_or_default();
            if let Some(filename) = part.filename {
                let mime = part.content_type.map(|m| m.to_ascii_lowercase());
                uploads.push(Upload { name: filename.trim().to_string(), mime, data: body.slice_ref(part.data) });
            } else if let Ok(v) = std::str::from_utf8(part.data) {
                pairs.push((name, v.to_string()));
            }
        }
    } else {
        pairs =
            req.with_body(|body| if body.is_empty() { Vec::new() } else { form_pairs(&String::from_utf8_lossy(body)) });
    }
    // Values move into the map; only the pairs `load_notify` still reads by name are copied (the body field can be huge).
    let mut map = Map::new();
    let mut kept = Vec::new();
    for (k, v) in pairs {
        if k.starts_with("template[") || ATTACH_FIELDS.contains(&k.as_str()) {
            kept.push((k.clone(), v.clone()));
        }
        map.insert(k, Value::String(v));
    }
    (map, kept, uploads)
}

pub fn json_object(req: &Req) -> Result<Map<String, Value>, Reply> {
    let v: Value = req
        .with_body(|body| serde_json::from_slice::<Value>(body))
        .map_err(|_| Reply::error(req, 400, "Invalid JSON Payload provided"))?;
    match v {
        Value::Object(m) => Ok(m),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Array(_) => {
            Err(Reply::error(req, 400, "The JSON payload must be an object"))
        }
    }
}

/// Read a notification payload. `stateless` adds the `urls` field.
pub fn load_notify(req: &Req, stateless: bool, key: Option<&str>, max_depth: usize) -> Result<Content, Reply> {
    let rules: Vec<(String, String)> =
        req.query.iter().filter_map(|(k, v)| k.strip_prefix(':').map(|k| (k.to_string(), v.clone()))).collect();
    let raw_format = match req.content_type().as_str() {
        "text/plain" => Some("text"),
        "text/html" => Some("html"),
        "text/markdown" => Some("markdown"),
        _ => None,
    };
    if let Some(fmt) = raw_format {
        let body = String::from_utf8(req.take_body())
            .map_err(|_| Reply::error(req, 400, "The message body could not be decoded"))?;
        let mut c = Content::default();
        c.fields.insert("body".into(), Value::String(body));
        c.fields.insert(
            "format".into(),
            Value::String(req.query("format").filter(|f| !f.is_empty()).unwrap_or(fmt).into()),
        );
        apply_headers(req, &mut c)?;
        return Ok(c);
    }
    let mut expected: Vec<&str> = NOTIFY_FIELDS.to_vec();
    if stateless {
        expected.push("urls");
    }
    let json = req.json_payload();
    let (mut data, pairs, uploads) = if json { (json_object(req)?, Vec::new(), Vec::new()) } else { form_fields(req) };
    req.release_body();
    if !rules.is_empty() && !remap_fields(&rules, &mut data, &expected, max_depth) {
        let msg = match key {
            Some(k) => format!("Payload field mapping failed using KEY: {k}"),
            None => "Payload field mapping failed".to_string(),
        };
        return Err(Reply::error(req, 400, &msg));
    }
    let mut c = Content { uploads, ..Content::default() };
    if json && super::alerts::is_alert_payload(&data) {
        super::alerts::convert(&mut data);
    }
    if json {
        for field in ["body", "title", "type"] {
            if data.get(field).is_some_and(|v| !v.is_string()) {
                return Err(Reply::field_error(req, 400, &format!("The {field} field must be a string"), field));
            }
        }
        if data.get("format").is_some_and(|v| !v.is_string() && !v.is_null()) {
            return Err(Reply::field_error(req, 400, "The format field must be a string or null", "format"));
        }
        if stateless && data.get("urls").is_some_and(|v| !is_str_or_str_list(v)) {
            return Err(Reply::field_error(req, 400, "The urls field must be a string or list of strings", "urls"));
        }
        if let Some(t) = data.get("template") {
            let vars = template_from_json(t).map_err(|_| {
                Reply::field_error(req, 400, "The template field must be an object of name/value pairs", "template")
            })?;
            c.template = vars;
        }
        c.fields = data;
    } else {
        // NotifyForm validation: an unknown type or format, an over-long field or bad template[...] values make the whole form invalid.
        let bad_choice = |k: &str, choices: &[&str]| {
            data.get(k).and_then(Value::as_str).is_some_and(|v| !v.is_empty() && !choices.contains(&v))
        };
        let template = template_from_form(&pairs, &data);
        if bad_choice("type", NOTIFY_TYPES) || bad_choice("format", NOTIFY_FORMATS) || template.is_err() {
            log::warn!("NOTIFY - {} - Invalid FORM Payload provided", req.remote);
            return Err(Reply::error(req, 400, "Bad FORM Payload provided"));
        }
        c.template = template.unwrap_or_default();
        let attach_key = ATTACH_FIELDS.into_iter().find(|k| pairs.iter().any(|(n, _)| n == k));
        if let Some(k) = attach_key {
            c.form_attach =
                Some(pairs.iter().filter(|(n, v)| n == k && !v.trim().is_empty()).map(|(_, v)| v.clone()).collect());
        }
        // `type` left empty may still come from a header or the query.
        if data.get("type").and_then(Value::as_str).is_some_and(str::is_empty) {
            data.remove("type");
        }
        c.fields = data;
    }
    apply_headers(req, &mut c)?;
    Ok(c)
}

fn is_str_or_str_list(v: &Value) -> bool {
    match v {
        Value::String(_) => true,
        Value::Array(a) => a.iter().all(Value::is_string),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_) => false,
    }
}

/// `X-Apprise-Title`, `-Type`, `-Tag` and `-Template` fill fields the payload left out.
fn apply_headers(req: &Req, c: &mut Content) -> Result<(), Reply> {
    for (name, header) in [("title", "Title"), ("type", "Type"), ("tag", "Tag")] {
        if let Some(v) = req.x_header(header)
            && !(c.has(name) || (name == "tag" && c.has("tags")))
        {
            c.fields.insert(name.into(), Value::String(v.to_string()));
        }
    }
    let Some(raw) = req.x_header("Template") else { return Ok(()) };
    if c.template.as_ref().is_some_and(|t| !t.is_empty()) {
        return Ok(());
    }
    let bad = || Reply::field_error(req, 400, "The X-Apprise-Template header is invalid", "template");
    let mut entries = Vec::new();
    for pair in raw.split('&') {
        let (k, v) = pair.split_once('=').ok_or_else(bad)?;
        if has_bad_escape(k) || has_bad_escape(v) {
            return Err(bad());
        }
        entries.push((mercurio::__private::unquote_plus(k), mercurio::__private::unquote_plus(v)));
    }
    c.template = template_vars(entries.into_iter().map(|(k, v)| (k, Value::String(v)))).map_err(|_| bad())?;
    Ok(())
}

fn has_bad_escape(s: &str) -> bool {
    let b = s.as_bytes();
    b.iter().enumerate().any(|(i, &c)| {
        c == b'%'
            && !(b.get(i + 1).is_some_and(u8::is_ascii_hexdigit) && b.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
    })
}

/// Template values: names validated and de-duplicated (case-insensitively), blank text skipped. `None` when nothing remains.
fn template_vars(entries: impl IntoIterator<Item = (String, Value)>) -> Result<Option<TemplateVars>, ()> {
    let mut vars = TemplateVars::new();
    let mut seen = std::collections::BTreeSet::new();
    for (name, value) in entries {
        if !mercurio::__private::valid_name(&name) || !seen.insert(name.to_lowercase()) {
            return Err(());
        }
        let yaml = match value {
            Value::String(s) if s.trim().is_empty() => continue,
            Value::String(s) => Yaml::Str(s.trim().to_string()),
            Value::Bool(b) => Yaml::Bool(b),
            Value::Number(n) => match n.as_i64() {
                Some(i) => Yaml::Int(i128::from(i)),
                None => Yaml::Float(n.as_f64().unwrap_or_default()),
            },
            Value::Null => continue,
            Value::Array(_) | Value::Object(_) => return Err(()),
        };
        let v = mercurio::__private::validate_value(&name, &yaml).map_err(|_| ())?;
        vars.set(&name, v).map_err(|_| ())?;
    }
    Ok(if vars.is_empty() { None } else { Some(vars) })
}

/// The JSON `template` field: an object of name/value pairs. Plain `NAME=VALUE` strings are also accepted.
fn template_from_json(v: &Value) -> Result<Option<TemplateVars>, ()> {
    match v {
        Value::Null => Ok(None),
        Value::Object(m) => template_vars(m.iter().map(|(k, v)| (k.clone(), v.clone()))),
        Value::String(_) | Value::Array(_) => {
            let items: Vec<&str> = match v {
                Value::String(s) => vec![s.as_str()],
                Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_) => Vec::new(),
            };
            let mut entries = Vec::new();
            for item in items {
                let (k, v) = item.split_once('=').ok_or(())?;
                entries.push((k.trim().to_string(), Value::String(v.to_string())));
            }
            template_vars(entries)
        }
        Value::Bool(_) | Value::Number(_) => Err(()),
    }
}

/// `template[name]=value` form fields (each at most once) or the `template=NAME=VALUE` shorthand.
fn template_from_form(pairs: &[(String, String)], data: &Map<String, Value>) -> Result<Option<TemplateVars>, ()> {
    let mut entries = Vec::new();
    for (k, v) in pairs {
        if let Some(rest) = k.strip_prefix("template[") {
            let name = rest.strip_suffix(']').ok_or(())?;
            if pairs.iter().filter(|(n, _)| n == k).count() > 1 {
                return Err(());
            }
            entries.push((name.to_string(), Value::String(v.clone())));
        }
    }
    if entries.is_empty() {
        if let Some(t) = data.get("template") {
            return template_from_json(t);
        }
        return Ok(None);
    }
    template_vars(entries)
}

/// Field mapping (`?:src=dest`). Returns `false` on a bad or missing nested path and on one deeper than `max_depth` (`APPRISE_WEBHOOK_MAPPING_MAX_DEPTH`).
pub fn remap_fields(
    rules: &[(String, String)],
    payload: &mut Map<String, Value>,
    expected: &[&str],
    max_depth: usize,
) -> bool {
    for (key, value) in rules {
        if key.contains(['.', '[', ']']) {
            let Some(steps) = parse_path(key) else {
                log::warn!("Payload mapping path '{key}' is malformed");
                return false;
            };
            if steps.len() > max_depth {
                log::warn!("Payload mapping path '{key}' exceeds the maximum depth of {max_depth}");
                return false;
            }
            let mut cur = Value::Object(payload.clone());
            for step in &steps {
                let next = match step {
                    Step::Key(k) => cur.as_object().and_then(|o| o.get(k)).cloned(),
                    Step::Index(i) => cur.as_array().and_then(|a| a.get(*i)).cloned(),
                };
                let Some(n) = next else {
                    log::warn!("Payload mapping path '{key}' not found in payload");
                    return false;
                };
                cur = n;
            }
            if expected.contains(&value.as_str()) {
                payload.insert(value.clone(), cur);
            }
            continue;
        }
        if payload.contains_key(key) && value.is_empty() {
            payload.remove(key);
            continue;
        }
        if expected.contains(&value.as_str()) && payload.contains_key(key) {
            if !expected.contains(&key.as_str()) || !payload.contains_key(value) {
                if let Some(v) = payload.remove(key) {
                    payload.insert(value.clone(), v);
                }
            } else if let (Some(a), Some(b)) = (payload.remove(key), payload.remove(value)) {
                payload.insert(value.clone(), a);
                payload.insert(key.clone(), b);
            }
        } else if expected.contains(&key.as_str()) || payload.contains_key(key) {
            payload.insert(key.clone(), Value::String(value.clone()));
        }
    }
    true
}

enum Step {
    Key(String),
    Index(usize),
}

fn parse_path(key: &str) -> Option<Vec<Step>> {
    let mut steps = Vec::new();
    for segment in key.split('.') {
        if segment.is_empty() {
            return None;
        }
        let Some(open) = segment.find('[') else {
            if segment.contains(']') {
                return None;
            }
            steps.push(Step::Key(segment.to_string()));
            continue;
        };
        let (name, mut rest) = segment.split_at(open);
        if name.contains(']') {
            return None;
        }
        if !name.is_empty() {
            steps.push(Step::Key(name.to_string()));
        }
        while !rest.is_empty() {
            let inner = rest.strip_prefix('[')?;
            let close = inner.find(']')?;
            let (digits, after) = inner.split_at(close);
            if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            steps.push(Step::Index(digits.parse().ok()?));
            rest = after.strip_prefix(']')?;
        }
    }
    Some(steps)
}

/// `[priority:]name[:retry]`.
fn valid_tag_token(t: &str) -> bool {
    let mut parts: Vec<&str> = t.split(':').collect();
    let digits = |s: &str| !s.is_empty() && s.len() <= 9 && s.bytes().all(|b| b.is_ascii_digit());
    if parts.len() > 3 {
        return false;
    }
    if parts.len() == 3 {
        if !digits(parts[0]) || !digits(parts[2]) {
            return false;
        }
        parts = vec![parts[1]];
    } else if parts.len() == 2 {
        if digits(parts[0]) && !digits(parts[1]) {
            parts = vec![parts[1]];
        } else if digits(parts[1]) {
            parts = vec![parts[0]];
        } else {
            return false;
        }
    }
    let name = parts.first().copied().unwrap_or("");
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A parsed tag selection: alternatives of AND groups.
pub type TagGroups = Vec<Vec<String>>;

/// A tag expression: commas and pipes mean OR; spaces, `&` and `+` mean AND.
pub fn parse_tag_expression(tag: &str) -> Option<TagGroups> {
    if tag.is_empty() || !tag.chars().all(|c| c.is_ascii_alphanumeric() || c.is_whitespace() || "|,_:+&-".contains(c)) {
        return None;
    }
    let mut groups = Vec::new();
    for group in tag.split([',', '|']) {
        let tokens: Vec<String> = group
            .split(|c: char| c.is_whitespace() || c == '&' || c == '+')
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect();
        if group.trim().is_empty() {
            continue;
        }
        if tokens.is_empty() || !tokens.iter().all(|t| valid_tag_token(t)) {
            return None;
        }
        groups.push(tokens);
    }
    Some(groups)
}

/// A JSON tag list: strings are alternatives, nested lists AND groups.
fn tag_list(items: &[Value]) -> Option<TagGroups> {
    let mut groups = Vec::new();
    for item in items {
        match item {
            Value::String(s) if valid_tag_token(s) => groups.push(vec![s.clone()]),
            Value::Array(a) => {
                let g: Option<Vec<String>> =
                    a.iter().map(|v| v.as_str().filter(|s| valid_tag_token(s)).map(str::to_string)).collect();
                groups.push(g.filter(|g| !g.is_empty())?);
            }
            Value::String(_) | Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_) => return None,
        }
    }
    if groups.is_empty() || groups.len() > 256 { None } else { Some(groups) }
}

/// The request's tag (`tag`, `tags`, then the query string): `Ok(None)` when none was given.
pub fn notify_tag(req: &Req, c: &Content) -> Result<Option<TagGroups>, ()> {
    let value = ["tag", "tags"]
        .iter()
        .find_map(|k| {
            Some(c.fields.get(*k)?.clone())
                .filter(|v| !matches!(v, Value::Null) && v != "" && v != &Value::Array(vec![]))
        })
        .or_else(|| {
            ["tag", "tags"].iter().find_map(|k| req.query(k).filter(|v| !v.is_empty()).map(|v| Value::String(v.into())))
        });
    match value {
        None => Ok(None),
        Some(Value::String(s)) => {
            let groups = parse_tag_expression(&s).ok_or(())?;
            Ok(if groups.is_empty() { None } else { Some(groups) })
        }
        Some(Value::Array(a)) => tag_list(&a).map(Some).ok_or(()),
        Some(_) => Err(()),
    }
}

/// Every token names a tag other than `all`.
pub fn tag_is_specific(groups: &Option<TagGroups>) -> bool {
    groups.as_ref().is_some_and(|g: &TagGroups| {
        !g.is_empty()
            && g.iter().flatten().all(|t| {
                let name = mercurio::Tag::parse(t).name;
                !name.eq_ignore_ascii_case("all")
            })
    })
}

pub fn tag_filter(groups: &TagGroups) -> TagFilter {
    TagFilter::any_of(groups.iter().map(|g| g.iter().map(String::as_str).collect::<Vec<_>>()))
}

pub struct AttachRules<'a> {
    /// Largest attachment in bytes; `0` disables attachments.
    pub size: u64,
    /// Most attachments per request; `0` means no limit.
    pub max: usize,
    /// Whether a URL may be downloaded.
    pub allowed: &'a (dyn Fn(&str) -> bool + Sync),
}

/// Attachments: hosted URLs (strings or `{"url", "filename"}`), base64 (`{"base64", "filename"}`) and uploaded files. Errors carry a log message; callers answer `400 Bad Attachment`.
pub async fn attachments(
    c: &mut Content,
    rules: &AttachRules<'_>,
    transport: &dyn mercurio::transport::AsyncTransport,
) -> Result<Vec<Attachment>, String> {
    let payload: Vec<Value> = if let Some(form) = c.form_attach.take() {
        form.into_iter().map(Value::String).collect()
    } else {
        let key = ["attach", "attachment", "attachments"].into_iter().find(|k| c.has(k));
        match key.and_then(|k| c.fields.get(k)) {
            None => Vec::new(),
            Some(Value::Array(a)) => a.clone(),
            Some(v) => vec![v.clone()],
        }
    };
    if payload.is_empty() && c.uploads.is_empty() {
        return Ok(Vec::new());
    }
    if rules.size == 0 {
        return Err("Attachment support has been disabled".into());
    }
    if rules.max > 0 && payload.len() + c.uploads.len() > rules.max {
        return Err(format!("There is a maximum of {} attachments", rules.max));
    }
    let asset = mercurio::Asset { attachment_max_size: rules.size, ..mercurio::Asset::default() };
    let mut out = Vec::new();
    for (i, entry) in payload.iter().enumerate() {
        let no = i + 1;
        let fallback = format!("attachment.{no:03}");
        let (url, name, b64) = match entry {
            Value::String(s) if s.trim().is_empty() => continue,
            Value::String(s) => (Some(s.clone()), None, None),
            Value::Object(o) => {
                let name = match o.get("filename") {
                    None => None,
                    Some(Value::String(s)) if s.trim().len() > 250 => {
                        return Err(format!("The filename associated with attachment {no} is too long"));
                    }
                    Some(Value::String(s)) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
                    Some(_) => return Err(format!("An invalid filename was provided for attachment {no}")),
                };
                let b64 = o.get("base64").cloned();
                let url = if b64.is_none() { o.get("url").and_then(Value::as_str).map(str::to_string) } else { None };
                if b64.is_none() && url.is_none() {
                    return Err(format!("Invalid filetype was provided for attachment {no}"));
                }
                (url, name, b64)
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::Array(_) => {
                return Err(format!("An invalid filename was provided for attachment {no}"));
            }
        };
        if let Some(b64) = b64 {
            let name = name.unwrap_or(fallback);
            let text: String = b64
                .as_str()
                .ok_or(format!("Invalid file content was provided for attachment {name}"))?
                .split_whitespace()
                .collect();
            let data = mercurio::__private::b64_decode(&text)
                .ok_or(format!("Invalid file content was provided for attachment {name}"))?;
            if data.len() as u64 > rules.size {
                return Err(format!("Attachment {name}'s file size is too large"));
            }
            let mime = mercurio::__private::guess_mime(&name).to_string();
            out.push(Attachment::new(name, mime, data));
            continue;
        }
        let url = url.unwrap_or_default();
        let lower = url.to_ascii_lowercase();
        if !(lower.starts_with("http://") || lower.starts_with("https://")) {
            return Err(format!("Failed to load attachment {no} (not web request)"));
        }
        if !(rules.allowed)(&url) {
            return Err(format!("Denied attachment {no} (blocked web request)"));
        }
        let mut source = mercurio::attachment::AttachSource::parse(&url)
            .map_err(|_| format!("Failed to parse attachment {no} URL"))?;
        if source.location() != mercurio::attachment::Location::Hosted {
            return Err(format!("Denied attachment {no} (not a hosted resource)"));
        }
        if let Some(n) = name {
            source = source.with_name(n);
        }
        let loaded = source
            .load_async(transport, &asset)
            .await
            .map_err(|e| format!("Failed to retrieve attachment {no}: {e}"))?;
        out.push(loaded);
    }
    for (i, up) in c.uploads.drain(..).enumerate() {
        let no = out.len() + i + 1;
        if up.name.len() > 250 {
            return Err(format!("The filename associated with attachment {no} is too long"));
        }
        if up.data.len() as u64 > rules.size {
            return Err(format!("attachment {}'s filesize is to large", up.name));
        }
        let name = if up.name.is_empty() { format!("attachment.{no:03}") } else { up.name };
        let mime = up
            .mime
            .filter(|m| !m.is_empty() && m != "application/octet-stream")
            .unwrap_or_else(|| mercurio::__private::guess_mime(&name).to_string());
        out.push(Attachment::new(name, mime, up.data));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tag_expressions() {
        assert_eq!(parse_tag_expression("a b, c"), Some(vec![vec!["a".into(), "b".into()], vec!["c".into()]]));
        assert_eq!(
            parse_tag_expression("a+b|c&d"),
            Some(vec![vec!["a".into(), "b".into()], vec!["c".into(), "d".into()]])
        );
        assert_eq!(parse_tag_expression("2:a:3"), Some(vec![vec!["2:a:3".into()]]));
        assert_eq!(parse_tag_expression("a;b"), None);
        assert_eq!(parse_tag_expression("_a"), None);
    }

    #[test]
    fn field_mapping() {
        let mut p = json!({"subject": "T", "payload": "B", "event": {"items": [{"x": "deep"}]}})
            .as_object()
            .cloned()
            .unwrap_or_default();
        let rules = vec![
            (":subject".trim_start_matches(':').to_string(), "title".to_string()),
            ("payload".into(), "body".into()),
            ("event.items[0].x".into(), "type".into()),
            ("format".into(), "markdown".into()),
        ];
        assert!(remap_fields(&rules, &mut p, NOTIFY_FIELDS, 5));
        assert_eq!(p.get("title"), Some(&json!("T")));
        assert_eq!(p.get("body"), Some(&json!("B")));
        assert_eq!(p.get("type"), Some(&json!("deep")));
        assert_eq!(p.get("format"), Some(&json!("markdown")));
        assert!(!p.contains_key("subject"));
        assert!(!remap_fields(&[("event.missing".into(), "body".into())], &mut p, NOTIFY_FIELDS, 5));
        assert!(!remap_fields(&[("a[x]".into(), "body".into())], &mut p, NOTIFY_FIELDS, 5));
        // APPRISE_WEBHOOK_MAPPING_MAX_DEPTH: `event.items[0].x` is four steps.
        let mut p = json!({"event": {"items": [{"x": "deep"}]}}).as_object().unwrap().clone();
        assert!(!remap_fields(&[("event.items[0].x".into(), "type".into())], &mut p, NOTIFY_FIELDS, 3));
        assert!(remap_fields(&[("event.items[0].x".into(), "type".into())], &mut p, NOTIFY_FIELDS, 4));
    }
}
