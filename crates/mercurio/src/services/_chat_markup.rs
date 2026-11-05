//! The `<url|label>` chat markup shared by `slack` and `googlechat`.

use crate::convert::markup::{self, Markup};

/// `*bold*`, `_italic_`, `~strike~`, `<url|label>` links; `&`, `<` and `>` are entity-escaped.
pub(crate) const ANCHOR: Markup = Markup {
    bold: ("*", "*"),
    italic: ("_", "_"),
    strike: ("~", "~"),
    code: ("`", "`"),
    code_block: ("```\n", "```"),
    heading_prefix: false,
    list_indent: "  ",
    link: anchor_link,
    escape: crate::util::html_escape_noquote,
    escape_code: crate::util::html_escape_noquote,
};

fn anchor_link(text: &str, url: &str) -> String {
    if text.is_empty() || text == url { format!("<{url}>") } else { format!("<{url}|{text}>") }
}

/// `s` escaped for Slack's `mrkdwn`; `None` when it holds `\r*\n`, which Slack cannot show.
pub(crate) fn slack_escape(s: &str) -> Option<String> {
    if s.contains("\r*\n") {
        return None;
    }
    Some(crate::util::html_escape_noquote(s))
}

/// Markdown rendered with `markup`.
pub(crate) fn render(body: &str, markup: &Markup) -> String {
    markup::render(body, markup)
}
