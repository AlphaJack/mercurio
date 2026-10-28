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
    escape,
    escape_code: escape,
};

fn anchor_link(text: &str, url: &str) -> String {
    if text.is_empty() || text == url { format!("<{url}>") } else { format!("<{url}|{text}>") }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Markdown rendered with `markup`.
pub(crate) fn render(body: &str, markup: &Markup) -> String {
    markup::render(body, markup)
}
