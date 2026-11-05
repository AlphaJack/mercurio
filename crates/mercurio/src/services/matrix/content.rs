//! The content of the `m.room.message` events sent, plain or encrypted.

use serde_json::{Value, json};

use super::{Config, Msg};
use crate::NotifyFormat;
use crate::util::escape_html;

/// The `m.room.message` content (also the plaintext of encrypted events).
pub(super) fn message_content(cfg: &Config, msg: &Msg) -> Value {
    let title = if msg.title.is_empty() { String::new() } else { format!("# {}\r\n", msg.title) };
    let mut payload = json!({
        "msgtype": format!("m.{}", cfg.msgtype),
        "body": format!("{title}{}", plain_fallback(msg)),
    });
    if rich(msg) {
        let mut title_html = String::new();
        if !msg.title.is_empty() {
            title_html = format!("<h1>{}</h1>", escape_html(&msg.title, false, false));
            if msg.format != NotifyFormat::Markdown {
                title_html.push_str("<br/>");
            }
        }
        payload["format"] = json!("org.matrix.custom.html");
        payload["formatted_body"] = json!(format!("{title_html}{}", html_body(msg)));
    }
    payload
}

pub(super) fn plain_fallback(msg: &Msg) -> String {
    if msg.passthrough || !matches!(msg.format, NotifyFormat::Html | NotifyFormat::Markdown) {
        msg.body.clone()
    } else {
        crate::convert::html_to_text(&msg.body)
    }
}

pub(super) fn rich(msg: &Msg) -> bool {
    matches!(msg.format, NotifyFormat::Html | NotifyFormat::Markdown)
}

pub(super) fn html_body(msg: &Msg) -> String {
    if msg.passthrough && msg.format == NotifyFormat::Markdown {
        crate::convert::markdown_to_html_plain(&msg.body)
    } else {
        msg.body.clone()
    }
}
