//! Markdown to HTML through `pulldown-cmark` (CommonMark, plus GFM tables and strike-through).

use pulldown_cmark::{Event, Options, Parser, html};

/// Markdown to HTML with soft breaks as `<br />`, tables and strike-through.
pub fn markdown_to_html(content: &str) -> String {
    markdown_to_html_with(content, true, true)
}

/// Markdown to HTML without extensions.
pub fn markdown_to_html_plain(content: &str) -> String {
    markdown_to_html_with(content, false, false)
}

pub fn markdown_to_html_with(content: &str, nl2br: bool, tables: bool) -> String {
    let mut opts = Options::empty();
    if tables {
        opts.insert(Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH);
    }
    let parser = Parser::new_ext(content, opts)
        .map(|e| if nl2br && matches!(e, Event::SoftBreak) { Event::HardBreak } else { e });
    let mut out = String::with_capacity(content.len() * 3 / 2);
    html::push_html(&mut out, parser);
    out.truncate(out.trim_end_matches('\n').len());
    out
}
