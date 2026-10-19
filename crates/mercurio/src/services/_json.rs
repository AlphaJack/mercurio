//! The JSON notification object shared by `json://` and `file://`.

use serde_json::{Map, Value, json};

use crate::Prepared;
use crate::crypto::b64;

/// `version`, `title`, `message`, `attachments` (name, base64 data, MIME type) and `type`.
pub(crate) fn object(msg: &Prepared<'_>) -> Map<String, Value> {
    let attachments: Vec<Value> = msg
        .attachments
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let name = if a.name.is_empty() { format!("file{:03}.dat", i + 1) } else { a.name.clone() };
            json!({"filename": name, "base64": b64(&a.data), "mimetype": a.mime})
        })
        .collect();
    let mut payload = Map::new();
    payload.insert("version".into(), json!("1.0"));
    payload.insert("title".into(), json!(msg.title));
    payload.insert("message".into(), json!(msg.body));
    payload.insert("attachments".into(), Value::Array(attachments));
    payload.insert("type".into(), json!(msg.kind.as_str()));
    payload
}

/// Apply the URL's `:key=value` entries (rename, drop or add fields) and serialize.
pub(crate) fn encode(mut payload: Map<String, Value>, extras: &[(String, String)]) -> Vec<u8> {
    crate::util::remap_payload(&mut payload, extras.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    serde_json::to_vec(&Value::Object(payload)).unwrap_or_default()
}
