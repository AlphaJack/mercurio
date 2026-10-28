//! Markdown to a service's own markup (Slack `mrkdwn`, Telegram Markdown, WhatsApp, ...), rendered from `pulldown-cmark` events.

#[cfg(feature = "markdown")]
use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};

/// How a service writes each Markdown construct.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(feature = "markdown"), expect(dead_code, reason = "only the Markdown renderer reads the styling"))]
pub(crate) struct Markup {
    pub bold: (&'static str, &'static str),
    pub italic: (&'static str, &'static str),
    pub strike: (&'static str, &'static str),
    pub code: (&'static str, &'static str),
    pub code_block: (&'static str, &'static str),
    /// Headings render as `bold`; `heading_prefix` keeps `#` marks instead.
    pub heading_prefix: bool,
    /// Indent per nested list level.
    pub list_indent: &'static str,
    /// `(text, url)` to a link.
    pub link: fn(&str, &str) -> String,
    /// Escapes literal text.
    pub escape: fn(&str) -> String,
    /// Escapes code span and code block content.
    pub escape_code: fn(&str) -> String,
}

impl Markup {
    /// Plain text: markup dropped, links as `text (url)`.
    pub(crate) const PLAIN: Markup = Markup {
        bold: ("", ""),
        italic: ("", ""),
        strike: ("", ""),
        code: ("", ""),
        code_block: ("", ""),
        heading_prefix: false,
        list_indent: "  ",
        link: plain_link,
        escape: same,
        escape_code: same,
    };

    /// Standard Markdown, normalised (used where a service reads Markdown).
    #[cfg(test)]
    #[cfg(feature = "markdown")]
    pub(crate) const MARKDOWN: Markup = Markup {
        bold: ("**", "**"),
        italic: ("*", "*"),
        strike: ("~~", "~~"),
        code: ("`", "`"),
        code_block: ("```\n", "```"),
        heading_prefix: false,
        list_indent: "  ",
        link: markdown_link,
        escape: same,
        escape_code: same,
    };
}

/// `[text](url)`.
pub(crate) fn markdown_link(text: &str, url: &str) -> String {
    if text.is_empty() { url.to_owned() } else { format!("[{text}]({url})") }
}

/// `text (url)`; the URL alone when it is also the text.
pub(crate) fn plain_link(text: &str, url: &str) -> String {
    if text.is_empty() || text == url { url.to_owned() } else { format!("{text} ({url})") }
}

/// Returns its input.
pub(crate) fn same(s: &str) -> String {
    s.to_owned()
}

/// Render `markdown` with `m`. Paragraphs are separated by a blank line, soft breaks stay line breaks, lists use `- ` / `1. `, quotes `> `, tables become ` | `-separated lines and raw HTML is escaped as text.
#[cfg(feature = "markdown")]
#[expect(clippy::wildcard_enum_match_arm, reason = "events and tags a dialect does not style are skipped")]
pub(crate) fn render(markdown: &str, m: &Markup) -> String {
    let mut out = String::with_capacity(markdown.len());
    // Text collected for open links, with their URL.
    let mut links: Vec<(String, String)> = Vec::new();
    let mut lists: Vec<Option<u64>> = Vec::new();
    let mut quote = 0usize;
    let mut in_code_block = false;
    let push = |out: &mut String, links: &mut Vec<(String, String)>, s: &str| match links.last_mut() {
        Some((text, _)) => text.push_str(s),
        None => out.push_str(s),
    };
    let new_block = |out: &mut String, quote: usize| {
        if !out.is_empty() {
            while out.ends_with(' ') {
                out.pop();
            }
            if !out.ends_with('\n') {
                out.push('\n');
            }
        }
        out.push_str(&"> ".repeat(quote));
    };
    let blank_line = |out: &mut String| {
        if !out.is_empty() && !out.ends_with("\n\n") {
            out.push_str(if out.ends_with('\n') { "\n" } else { "\n\n" });
        }
    };
    let opts = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH;
    for event in Parser::new_ext(markdown, opts) {
        match event {
            Event::Start(tag) => match tag {
                Tag::Paragraph => {
                    if lists.is_empty() {
                        blank_line(&mut out);
                    }
                    if !out.ends_with(' ') && !out.ends_with("- ") && !out.ends_with(". ") {
                        out.push_str(&"> ".repeat(quote));
                    }
                }
                Tag::Heading { level, .. } => {
                    blank_line(&mut out);
                    if m.heading_prefix {
                        out.push_str(&format!("{} ", "#".repeat(heading_level(level))));
                    } else {
                        out.push_str(m.bold.0);
                    }
                }
                Tag::BlockQuote(_) => {
                    blank_line(&mut out);
                    quote += 1;
                }
                Tag::CodeBlock(kind) => {
                    blank_line(&mut out);
                    in_code_block = true;
                    out.push_str(m.code_block.0);
                    if let CodeBlockKind::Fenced(lang) = kind
                        && m.code_block.0.ends_with('\n')
                        && !lang.is_empty()
                    {
                        // A language goes on the fence line (```rust).
                        out.pop();
                        out.push_str(&lang);
                        out.push('\n');
                    }
                }
                Tag::List(start) => {
                    if lists.is_empty() {
                        blank_line(&mut out);
                    }
                    lists.push(start);
                }
                Tag::Item => {
                    new_block(&mut out, quote);
                    out.push_str(&m.list_indent.repeat(lists.len().saturating_sub(1)));
                    match lists.last_mut() {
                        Some(Some(n)) => {
                            out.push_str(&format!("{n}. "));
                            *n += 1;
                        }
                        _ => out.push_str("- "),
                    }
                }
                Tag::Table(_) => blank_line(&mut out),
                Tag::TableHead | Tag::TableRow => new_block(&mut out, quote),
                Tag::TableCell if !out.ends_with('\n') && !out.is_empty() && !out.ends_with("> ") => {
                    out.push_str(" | ");
                }
                Tag::Emphasis => push(&mut out, &mut links, m.italic.0),
                Tag::Strong => push(&mut out, &mut links, m.bold.0),
                Tag::Strikethrough => push(&mut out, &mut links, m.strike.0),
                Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. } => {
                    links.push((String::new(), dest_url.to_string()));
                }
                _ => {}
            },
            Event::End(tag) => match tag {
                TagEnd::Heading(_) if !m.heading_prefix => out.push_str(m.bold.1),
                TagEnd::BlockQuote(_) => quote = quote.saturating_sub(1),
                TagEnd::CodeBlock => {
                    in_code_block = false;
                    if !out.ends_with('\n') && m.code_block.1.starts_with('`') {
                        out.push('\n');
                    }
                    out.push_str(m.code_block.1);
                }
                TagEnd::List(_) => {
                    lists.pop();
                }
                TagEnd::Emphasis => push(&mut out, &mut links, m.italic.1),
                TagEnd::Strong => push(&mut out, &mut links, m.bold.1),
                TagEnd::Strikethrough => push(&mut out, &mut links, m.strike.1),
                TagEnd::Link | TagEnd::Image => {
                    if let Some((text, url)) = links.pop() {
                        let rendered = (m.link)(&text, &url);
                        push(&mut out, &mut links, &rendered);
                    }
                }
                _ => {}
            },
            Event::Text(t) => {
                if in_code_block {
                    let body = (m.escape_code)(&t);
                    // Quoted code keeps its quote marks on each line.
                    let body = if quote > 0 { body.replace('\n', &format!("\n{}", "> ".repeat(quote))) } else { body };
                    out.push_str(&body);
                } else {
                    push(&mut out, &mut links, &(m.escape)(&t));
                }
            }
            Event::Code(t) => {
                let s = format!("{}{}{}", m.code.0, (m.escape_code)(&t), m.code.1);
                push(&mut out, &mut links, &s);
            }
            Event::Html(t) | Event::InlineHtml(t) => push(&mut out, &mut links, &(m.escape)(&t)),
            Event::SoftBreak | Event::HardBreak => {
                let s = format!("\n{}", "> ".repeat(quote));
                push(&mut out, &mut links, &s);
            }
            Event::Rule => {
                blank_line(&mut out);
                out.push_str("---");
            }
            _ => {}
        }
    }
    out.trim_end().to_owned()
}

/// Without the `markdown` feature: `markdown` as literal text, escaped for `m`.
#[cfg(not(feature = "markdown"))]
pub(crate) fn render(markdown: &str, m: &Markup) -> String {
    super::markdown_unavailable();
    (m.escape)(markdown)
}

#[cfg(feature = "markdown")]
fn heading_level(level: HeadingLevel) -> usize {
    level as usize
}

/// Remove CommonMark backslash escapes (`\*` becomes `*`).
pub(crate) fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\'
            && let Some(&next) = chars.peek()
            && next.is_ascii_punctuation()
        {
            out.push(next);
            chars.next();
        } else {
            out.push(c);
        }
    }
    out
}

/// `# heading` lines become `**heading**`; everything else is unchanged. Lines inside code fences are left alone.
pub(crate) fn headings_to_bold(markdown: &str) -> String {
    let re = crate::regex!(r"^ {0,3}#{1,6}[ \t]+(.*?)(?:[ \t]+#+)?[ \t]*$");
    let mut fence = false;
    let lines: Vec<String> = markdown
        .split('\n')
        .map(|line| {
            if line.trim_start().starts_with("```") {
                fence = !fence;
            }
            match re.captures(line) {
                Some(c) if !fence => format!("**{}**", &c[1]),
                _ => line.to_owned(),
            }
        })
        .collect();
    lines.join("\n")
}

/// Split Markdown into a description and `(heading, content)` sections at `#` headings (as embed fields). Headings are cut to `name_max` chars and contents to `value_max`.
pub(crate) fn sections(markdown: &str, name_max: usize, value_max: usize) -> (String, Vec<(String, String)>) {
    let re = crate::regex!(r"^ {0,3}#{1,6}[ \t]+(.*?)(?:[ \t]+#+)?[ \t]*$");
    let mut description = String::new();
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in markdown.split('\n') {
        match re.captures(line.trim_end_matches('\r')) {
            Some(c) => fields.push((c[1].chars().take(name_max).collect(), String::new())),
            None => {
                let target = match fields.last_mut() {
                    Some((_, v)) => v,
                    None => &mut description,
                };
                if !target.is_empty() {
                    target.push('\n');
                }
                target.push_str(line);
            }
        }
    }
    for (_, v) in &mut fields {
        *v = v.trim().chars().take(value_max).collect();
    }
    (description.trim().to_owned(), fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "markdown")]
    const SLACK: Markup = Markup {
        bold: ("*", "*"),
        italic: ("_", "_"),
        strike: ("~", "~"),
        code: ("`", "`"),
        code_block: ("```\n", "```"),
        heading_prefix: false,
        list_indent: "  ",
        link: |t, u| if t.is_empty() { format!("<{u}>") } else { format!("<{u}|{t}>") },
        escape: |s| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;"),
        escape_code: same,
    };

    #[cfg(feature = "markdown")]
    #[test]
    fn inline_styles_and_links() {
        assert_eq!(render("**b** *i* ~~s~~ `c` [l](https://x)", &SLACK), "*b* _i_ ~s~ `c` <https://x|l>");
        assert_eq!(render("a & <b>", &SLACK), "a &amp; &lt;b&gt;");
    }

    #[cfg(feature = "markdown")]
    #[test]
    fn blocks() {
        assert_eq!(
            render("# Title\n\npara one\nline two\n\n- a\n- b", &SLACK),
            "*Title*\n\npara one\nline two\n\n- a\n- b"
        );
        assert_eq!(render("1. x\n2. y", &SLACK), "1. x\n2. y");
        assert_eq!(render("> q", &SLACK), "> q");
        assert_eq!(render("```rust\nfn x() {}\n```", &SLACK), "```rust\nfn x() {}\n```");
    }

    #[cfg(feature = "markdown")]
    #[test]
    fn normalised_markdown() {
        assert_eq!(render("__b__ _i_", &Markup::MARKDOWN), "**b** *i*");
    }

    #[test]
    fn helpers() {
        assert_eq!(unescape(r"\*a\* \q"), r"*a* \q");
        assert_eq!(headings_to_bold("# T #\ntext"), "**T**\ntext");
        assert_eq!(headings_to_bold("```\n# code\n```"), "```\n# code\n```");
        let (d, f) = sections("intro\n# A\none\n## B\ntwo", 10, 10);
        assert_eq!(d, "intro");
        assert_eq!(f, vec![("A".into(), "one".into()), ("B".into(), "two".into())]);
    }
}
