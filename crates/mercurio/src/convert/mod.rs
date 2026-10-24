//! Body format conversion: Markdown to HTML, HTML to text / Markdown, text to HTML / Markdown, Markdown to a service's own markup and the size-aware splitting helpers. All index arithmetic is in code points.

pub mod dialect;
#[cfg(feature = "emojis")]
pub mod emoji;
pub mod html;
#[cfg(feature = "markdown")]
mod markdown;
pub mod markup;
pub mod split;

use crate::message::NotifyFormat;

pub use dialect::{split_dialect_chunk, truncate_dialect_chunk};
pub use split::smart_split;

/// Convert `content` from one format to another. Pairs without a converter (e.g. Markdown to text) return the input.
pub fn convert_between(from: NotifyFormat, to: NotifyFormat, content: &str) -> String {
    use NotifyFormat::*;
    match (from, to) {
        (Markdown, Html) => markdown_to_html(content),
        (Text, Html) => text_to_html(content),
        (Html, Text) => html_to_text(content),
        (Html, Markdown) => html_to_markdown(content),
        (Text, Markdown) => text_to_markdown(content),
        _ => content.to_string(),
    }
}

/// Markdown to HTML (with `nl2br` and `tables`); escaped text without the `markdown` feature.
pub fn markdown_to_html(content: &str) -> String {
    #[cfg(feature = "markdown")]
    return markdown::markdown_to_html(content);
    #[cfg(not(feature = "markdown"))]
    {
        markdown_unavailable();
        text_to_html(content)
    }
}

/// Markdown to HTML without extensions (as Matrix uses it); escaped text without the `markdown` feature.
pub fn markdown_to_html_plain(content: &str) -> String {
    #[cfg(feature = "markdown")]
    return markdown::markdown_to_html_plain(content);
    #[cfg(not(feature = "markdown"))]
    {
        markdown_unavailable();
        text_to_html(content)
    }
}

#[cfg(not(feature = "markdown"))]
fn markdown_unavailable() {
    log::warn!("Markdown is sent as plain text: this build lacks the Cargo feature `markdown`");
}

/// Plain text to HTML: escape and turn newlines into `<br/>`.
pub fn text_to_html(content: &str) -> String {
    crate::util::escape_html(content, true, true)
}

/// Plain text to CommonMark: backslash-escape every syntax character (`&` only when it would start an entity such as `&amp;`).
pub fn text_to_markdown(content: &str) -> String {
    let chars: Vec<char> = content.chars().collect();
    let mut out = String::with_capacity(content.len() + 8);
    for (i, &c) in chars.iter().enumerate() {
        let special = matches!(
            c,
            '\\' | '_'
                | '*'
                | '['
                | ']'
                | '('
                | ')'
                | '~'
                | '`'
                | '>'
                | '#'
                | '+'
                | '='
                | '|'
                | '{'
                | '}'
                | '.'
                | '!'
                | '-'
        );
        if special || (c == '&' && entity_follows(&chars[i + 1..])) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// `#?[0-9A-Za-z]{1,32};` at the start of `rest`.
fn entity_follows(rest: &[char]) -> bool {
    let rest = rest.strip_prefix(&['#']).unwrap_or(rest);
    let n = rest.iter().take(33).take_while(|c| c.is_ascii_alphanumeric()).count();
    (1..=32).contains(&n) && rest.get(n) == Some(&';')
}

/// HTML to plain text.
pub fn html_to_text(content: &str) -> String {
    html::html_to_text(content)
}

/// HTML to CommonMark.
pub fn html_to_markdown(content: &str) -> String {
    html::html_to_markdown(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_to_text_examples() {
        assert_eq!(html_to_text("line one\nline two   spaced"), "line one line two spaced");
        assert_eq!(
            html_to_text(
                "<p>Hello <b>World</b> &amp; friends</p><br/>Next line<ul><li>one</li><li>two</li></ul><script>var x = '<b>';</script>"
            ),
            "Hello World & friends\n\nNext line\n\n- one\n- two"
        );
        assert_eq!(html_to_text("<p>See <img src=\"cid:doc.pdf\"></p><br/><img src=\"cid:a.png\">"), "See");
        assert_eq!(html_to_text("a < b <!-- c --> d"), "a < b d");
        assert_eq!(html_to_text("<pre>x\n  y</pre>"), "x\n  y");
    }

    #[test]
    fn text_conversions() {
        assert_eq!(text_to_html("a <b>\nc d"), "a&nbsp;&lt;b&gt;<br/>c&nbsp;d");
        assert_eq!(text_to_markdown("a_b & &amp; *x*"), "a\\_b & \\&amp; \\*x\\*");
        assert_eq!(convert_between(NotifyFormat::Markdown, NotifyFormat::Text, "*x*"), "*x*");
    }
}
