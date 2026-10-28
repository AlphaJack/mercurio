//! Discord (`discord://`): messages to a Discord channel through a webhook.

use crate::Result;
use crate::message::NotifyFormat;
use crate::service::{Limits, Notify, Param, ServiceDef};
use crate::url::ParsedUrl;

use super::_discord::{discord_parse, native_webhook};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "discord",
    name: "Discord",
    schemes: &["discord"],
    service_url: "https://discord.com/",
    parse,
    parse_native: Some(parse_native),
    // Title and body share one 2000-character field.
    limits: Limits { title_maxlen: 250, body_maxlen: 1750, body_max_line_count: 0 },
    formats: &[NotifyFormat::Text, NotifyFormat::Markdown],
    attachments: true,
    templates: &[
        "{schema}://{webhook_id}/{webhook_token}",
        "{schema}://{botname}@{webhook_id}/{webhook_token}",
    ],
    tokens: &[
        Param::new("botname", "Bot Name"),
        Param::new("webhook_id", "Webhook ID").required().secret(),
        Param::new("webhook_token", "Webhook Token").required().secret(),
    ],
    params: &[
        Param::new("avatar", "Avatar Image").bool(true),
        Param::new("avatar_url", "Avatar URL"),
        Param::new("batch", "Batch Attachments").bool(true),
        Param::new("emojis", "Interpret Emojis").bool(true).note("`no` escapes every `:name:` so Discord shows it as text"),
        Param::new("fields", "Use Fields").bool(true),
        Param::new("flags", "Discord Flags").int().min(0),
        Param::new("footer", "Display Footer").bool(false),
        Param::new("footer_logo", "Footer Logo").bool(true),
        Param::new("href", "URL").aliases(&["url"]),
        Param::new("image", "Include Image").bool(false),
        Param::new("ping", "Ping Users/Roles").list(", "),
        Param::new("template", "Template Path").secret(),
        Param::new("thread", "Thread ID"),
        Param::new("tts", "Text To Speech").bool(false),
        Param::new("tokens", "Template Tokens").prefix(":"),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://discord.com/api/webhooks";

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    Ok(Box::new(discord_parse(&SERVICE, NOTIFY_URL, u)?))
}

/// `https://discord(app).com/api/webhooks/ID/TOKEN[?params]`.
fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(
        r"(?i)^https?://discord(app)?\.com/api/webhooks/(?P<webhook_id>[0-9]+)/(?P<webhook_token>[A-Z0-9_-]+)/?(?P<params>\?.+)?$"
    );
    native_webhook(url, re, "discord")
}

#[cfg(test)]
#[expect(clippy::disallowed_methods, reason = "tests set up real files")]
mod tests {
    /// A fixture written at test time (it needs the template's absolute path).
    const FIXTURE: &str = r#"{"service": "discord", "cases": [{"name": "template", "url": "discord://iiiiiiii/tttttttt?template=__TPL__&:who=W%22x&ping=@joe", "body": "line1\nline2 \"q\"", "type": "warning", "attachments": [{"name": "a.txt", "mime": "text/plain", "text": "hi"}]}]}"#;

    const TEMPLATE: &str = r#"{"content": "{{app_title}}: {{ app_body }} by {{who}}", "extra": "{{app_color_int}}|{{app_type}}|{{app_image_url}}", "embeds": [{"title": "{{app_id}}"}]}"#;

    #[test]
    fn template() {
        let dir = std::env::temp_dir().join(format!("mercurio-discord-tpl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let tpl = dir.join("t.json");
        std::fs::write(&tpl, TEMPLATE).unwrap();
        let fixture = dir.join("fixture.json");
        let tpl_path = tpl.to_string_lossy().replace('\\', "/");
        std::fs::write(&fixture, FIXTURE.replace("__TPL__", &tpl_path)).unwrap();
        let out = crate::testing::fixtures::record_fixture(&fixture.to_string_lossy());
        crate::testing::fixtures::snapshot("unit", "discord_template", &out);
        std::fs::remove_dir_all(&dir).ok();
    }
}
