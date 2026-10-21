//! The JSON notification object shared by `json://` and `file://`.

use serde_json::{Map, Value, json};

use crate::Prepared;
use crate::crypto::b64;

/// `version`, `title`, `message` (as a placeholder, see [`encode`]), `attachments` (name, base64 data, MIME type) and `type`.
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
    payload.insert("message".into(), json!(crate::http::TEXT));
    payload.insert("attachments".into(), Value::Array(attachments));
    payload.insert("type".into(), json!(msg.kind.as_str()));
    payload
}

/// Apply the URL's `:key=value` entries (rename, drop or add fields) and serialize, writing `message` (wherever the entries moved it, if they kept it) straight from the text.
pub(crate) fn encode(mut payload: Map<String, Value>, extras: &[(String, String)], message: &str) -> Vec<u8> {
    crate::util::remap_payload(&mut payload, extras.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    crate::http::json_with_text(&Value::Object(payload), message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(extras: &[(&str, &str)], message: &str) -> String {
        let extras: Vec<(String, String)> = extras.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let mut map = Map::new();
        map.insert("title".into(), json!("T"));
        map.insert("message".into(), json!(crate::http::TEXT));
        String::from_utf8(encode(map, &extras, message)).unwrap()
    }

    #[test]
    fn message_is_written_from_the_text_wherever_the_entries_put_it() {
        assert_eq!(body(&[], "a \"q\"\n"), r#"{"message":"a \"q\"\n","title":"T"}"#);
        assert_eq!(body(&[("message", "text")], "m"), r#"{"text":"m","title":"T"}"#);
        assert_eq!(body(&[("message", "")], "m"), r#"{"title":"T"}"#);
        assert_eq!(body(&[("extra", "x")], "m"), r#"{"extra":"x","message":"m","title":"T"}"#);
    }
}
