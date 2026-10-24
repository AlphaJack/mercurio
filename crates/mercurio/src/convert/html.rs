//! HTML input: a small tokenizer, HTML to plain text, HTML to Markdown and [`filter`], which rewrites HTML into the tag subset a service accepts.

/// One piece of HTML. Text and attribute values are entity-decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Start { tag: String, attrs: Vec<(String, String)>, self_closing: bool },
    End(String),
    Text(String),
}

impl Token {
    fn attr(attrs: &[(String, String)], name: &str) -> Option<String> {
        attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
    }
}

/// Elements whose content is never shown.
const HIDDEN: &[&str] = &["script", "style", "head", "title", "template"];

/// Elements that start and end their own line.
const BLOCKS: &[&str] = &[
    "p",
    "div",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "li",
    "ul",
    "ol",
    "tr",
    "table",
    "pre",
    "blockquote",
    "hr",
    "section",
    "article",
    "header",
    "footer",
    "nav",
    "aside",
    "main",
    "form",
    "dl",
    "dt",
    "dd",
    "figure",
];

/// Blocks separated from their neighbours by a blank line.
const PARAGRAPHS: &[&str] =
    &["p", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "pre", "blockquote", "table", "hr", "dl", "figure"];

/// Split `html` into tokens. Comments, doctypes and processing instructions are dropped; a `<` that does not start a tag is text.
pub fn tokens(html: &str) -> Vec<Token> {
    let mut out = Vec::new();
    scan(html, |t| out.push(t));
    out
}

/// [`tokens`], handing each token to `emit` in order.
fn scan(html: &str, mut emit: impl FnMut(Token)) {
    let mut text = String::new();
    let mut rest = html;
    while let Some(lt) = rest.find('<') {
        let (before, tail) = rest.split_at(lt);
        text.push_str(before);
        let skip_to = |end: &str| tail.find(end).map(|i| i + end.len()).unwrap_or(tail.len());
        let consumed = if tail.starts_with("<!--") {
            skip_to("-->")
        } else if tail.starts_with("<!") || tail.starts_with("<?") {
            skip_to(">")
        } else if let Some((tok, len)) = tag(tail) {
            flush(&mut text, &mut emit);
            let raw = if let Token::Start { tag, self_closing: false, .. } = &tok
                && matches!(tag.as_str(), "script" | "style")
            {
                Some(tag.clone())
            } else {
                None
            };
            emit(tok);
            match raw {
                // Raw text elements end only at their own closing tag.
                Some(name) => {
                    let close = format!("</{name}");
                    let body = tail.get(len..).unwrap_or_default();
                    match body.to_ascii_lowercase().find(&close) {
                        Some(i) => len + i,
                        None => tail.len(),
                    }
                }
                None => len,
            }
        } else {
            text.push('<');
            1
        };
        rest = tail.get(consumed..).unwrap_or_default();
    }
    text.push_str(rest);
    flush(&mut text, &mut emit);
}

fn flush(text: &mut String, emit: &mut impl FnMut(Token)) {
    if text.is_empty() {
        return;
    }
    // Every entity starts with `&`; without one the text is kept as is. The buffer is copied, not taken, so it keeps its capacity.
    emit(Token::Text(if text.contains('&') { decode(text) } else { text.as_str().to_owned() }));
    text.clear();
}

#[cfg(feature = "html")]
fn decode(s: &str) -> String {
    html_escape::decode_html_entities(s).into_owned()
}

/// Without the `html` feature: numeric references and the few named ones markup needs; other entities are kept as written.
#[cfg(not(feature = "html"))]
fn decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some((head, tail)) = rest.split_once('&') {
        out.push_str(head);
        match tail.split_once(';').filter(|(e, _)| e.len() <= 32).and_then(|(e, after)| Some((entity(e)?, after))) {
            Some((c, after)) => {
                out.push(c);
                rest = after;
            }
            None => {
                out.push('&');
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The character `&name;` stands for: a numeric reference or one of the named entities markup needs.
#[cfg(not(feature = "html"))]
fn entity(name: &str) -> Option<char> {
    Some(match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        "nbsp" => '\u{a0}',
        e => {
            let e = e.strip_prefix('#')?;
            let code = match e.strip_prefix(['x', 'X']) {
                Some(h) => u32::from_str_radix(h, 16).ok()?,
                None => e.parse().ok()?,
            };
            char::from_u32(code)?
        }
    })
}

/// Parse a start or end tag at the start of `s`; `None` when `s` is not one.
fn tag(s: &str) -> Option<(Token, usize)> {
    let b = s.as_bytes();
    let closing = b.get(1) == Some(&b'/');
    let name_start = if closing { 2 } else { 1 };
    if !b.get(name_start)?.is_ascii_alphabetic() {
        return None;
    }
    let end = find_tag_end(s)?;
    let inner = s.get(name_start..end)?;
    let name_len = inner.find(|c: char| c.is_whitespace() || c == '/' || c == '>').unwrap_or(inner.len());
    let (name, attr_src) = inner.split_at(name_len);
    let name = name.to_ascii_lowercase();
    if closing {
        return Some((Token::End(name), end + 1));
    }
    let attr_src = attr_src.trim_end();
    let self_closing = attr_src.ends_with('/');
    let attrs = attributes(attr_src.trim_end_matches('/'));
    Some((Token::Start { tag: name, attrs, self_closing }, end + 1))
}

/// Index of the `>` ending the tag at the start of `s`, skipping quoted values.
fn find_tag_end(s: &str) -> Option<usize> {
    let mut quote = None;
    for (i, c) in s.char_indices().skip(1) {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(c),
            (None, '>') => return Some(i),
            (None, '<') => return None,
            _ => {}
        }
    }
    None
}

/// Attributes as matched, left to right, by `([^\s=/"'>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?`: a name, then optionally `=` and a quoted or bare value.
fn attributes(src: &str) -> Vec<(String, String)> {
    let is_name = |c: char| !(c.is_whitespace() || matches!(c, '=' | '/' | '"' | '\'' | '>'));
    let is_bare = |c: char| !(c.is_whitespace() || matches!(c, '"' | '\'' | '>'));
    let skip_ws = |s: &str| s.len() - s.trim_start().len();
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(start) = rest.find(is_name) {
        let tail = rest.get(start..).unwrap_or_default();
        let name_len = tail.find(|c: char| !is_name(c)).unwrap_or(tail.len());
        let (name, after) = tail.split_at(name_len);
        let name = name.to_ascii_lowercase();
        let mut consumed = name_len;
        let mut value = String::new();
        let eq = skip_ws(after);
        if let Some(eq_tail) = after.get(eq..).and_then(|t| t.strip_prefix('=')) {
            let v_at = eq + 1 + skip_ws(eq_tail);
            let v = after.get(v_at..).unwrap_or_default();
            let quoted = v.chars().next().filter(|q| matches!(q, '"' | '\'')).and_then(|q| {
                let body = v.get(1..)?;
                body.find(q).and_then(|close| Some((body.get(..close)?, close + 2)))
            });
            let found = match quoted {
                Some(q) => Some(q),
                None => {
                    let n = v.find(|c: char| !is_bare(c)).unwrap_or(v.len());
                    (n > 0).then(|| (v.split_at(n).0, n))
                }
            };
            if let Some((raw, len)) = found {
                value = decode(raw);
                consumed += v_at + len;
            }
        }
        out.push((name, value));
        rest = tail.get(consumed..).unwrap_or_default();
    }
    out
}

/// Collapse whitespace runs to one space.
fn collapse(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if !c.is_whitespace() {
            out.push(c);
        } else if !out.ends_with(' ') {
            out.push(' ');
        }
    }
    out
}

/// [`collapse`] for owned text, kept as is when it has no run to collapse.
fn collapse_owned(s: String) -> String {
    let mut space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if c != ' ' || space {
                return collapse(&s);
            }
            space = true;
        } else {
            space = false;
        }
    }
    s
}

/// Output under construction: inline text with explicit line breaks.
#[derive(Default)]
struct Lines {
    out: String,
    /// The last line was ended by a block element (a `<br>` adds nothing).
    block_ended: bool,
}

impl Lines {
    fn push(&mut self, s: &str) {
        // A space never starts a line.
        let s = if self.at_line_start() { s.trim_start_matches(' ') } else { s };
        if !s.is_empty() {
            self.block_ended = false;
        }
        self.out.push_str(s);
    }

    /// Text written as is (preformatted).
    fn raw(&mut self, s: &str) {
        if !s.is_empty() {
            self.block_ended = false;
        }
        self.out.push_str(s);
    }

    fn at_line_start(&self) -> bool {
        self.out.is_empty() || self.out.ends_with('\n')
    }

    fn newline(&mut self) {
        if std::mem::take(&mut self.block_ended) {
            return;
        }
        while self.out.ends_with(' ') {
            self.out.pop();
        }
        self.out.push('\n');
    }

    /// End the current line unless it is empty.
    fn block(&mut self) {
        if !self.at_line_start() {
            self.newline();
            self.block_ended = true;
        }
    }

    /// End the current line and leave a blank line after it.
    fn paragraph(&mut self) {
        self.block();
        if !self.out.is_empty() && !self.out.ends_with("\n\n") {
            self.out.push('\n');
        }
        self.block_ended = true;
    }

    /// [`Lines::paragraph`] for paragraph-level tags, else [`Lines::block`].
    fn block_for(&mut self, tag: &str) {
        if PARAGRAPHS.contains(&tag) { self.paragraph() } else { self.block() }
    }

    fn finish(self) -> String {
        let lines: Vec<&str> = self.out.lines().map(str::trim_end).collect();
        let mut out = String::new();
        let mut blank = 0;
        for line in lines {
            if line.is_empty() {
                blank += 1;
                continue;
            }
            if !out.is_empty() {
                out.push_str(if blank > 0 { "\n\n" } else { "\n" });
            }
            blank = 0;
            out.push_str(line);
        }
        out
    }
}

/// HTML to plain text: tags dropped, blocks and `<br>` on their own lines.
pub fn html_to_text(html: &str) -> String {
    let mut out = Lines::default();
    let mut hidden = 0usize;
    let mut pre = 0usize;
    for tok in tokens(html) {
        match tok {
            Token::Start { tag, self_closing, .. } => {
                if HIDDEN.contains(&tag.as_str()) && !self_closing {
                    hidden += 1;
                } else if tag == "br" {
                    out.newline();
                } else if BLOCKS.contains(&tag.as_str()) {
                    out.block_for(&tag);
                    pre += usize::from(tag == "pre");
                    if tag == "li" {
                        out.push("- ");
                    } else if tag == "hr" {
                        out.push("---");
                        out.paragraph();
                    }
                }
            }
            Token::End(tag) => {
                if HIDDEN.contains(&tag.as_str()) {
                    hidden = hidden.saturating_sub(1);
                } else if BLOCKS.contains(&tag.as_str()) {
                    out.block_for(&tag);
                    if tag == "pre" {
                        pre = pre.saturating_sub(1);
                    }
                }
            }
            Token::Text(t) if hidden == 0 => {
                if pre > 0 {
                    out.raw(&t);
                } else {
                    out.push(&collapse(&t));
                }
            }
            Token::Text(_) => {}
        }
    }
    out.finish()
}

fn md_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '*' | '_' | '`' | '[' | ']' | '<' | '>' | '#' | '~' | '|') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// HTML to CommonMark: emphasis, code, links, images, headings, lists, quotes and rules keep their meaning; other tags are dropped.
pub fn html_to_markdown(html: &str) -> String {
    let mut out = Lines::default();
    let mut hidden = 0usize;
    let mut pre = false;
    let mut quote = 0usize;
    // Open lists: `Some(n)` numbers the next item `n`.
    let mut lists: Vec<Option<u64>> = Vec::new();
    // Open links: the href and where their text starts in `out`.
    let mut links: Vec<(String, usize)> = Vec::new();
    let prefix = |out: &mut Lines, quote: usize| {
        if quote > 0 && out.at_line_start() {
            out.out.push_str(&"> ".repeat(quote));
        }
    };
    for tok in tokens(html) {
        match tok {
            Token::Start { tag, attrs, self_closing } => {
                if HIDDEN.contains(&tag.as_str()) {
                    hidden += usize::from(!self_closing);
                    continue;
                }
                match tag.as_str() {
                    "b" | "strong" => out.push("**"),
                    "i" | "em" => out.push("_"),
                    "s" | "strike" | "del" => out.push("~~"),
                    "code" if !pre => out.push("`"),
                    "br" => out.newline(),
                    "hr" => {
                        out.paragraph();
                        out.push("---");
                        out.paragraph();
                    }
                    "pre" => {
                        out.paragraph();
                        out.push("```");
                        out.newline();
                        pre = true;
                    }
                    "blockquote" => {
                        out.paragraph();
                        quote += 1;
                    }
                    "ul" => {
                        if lists.is_empty() {
                            out.paragraph()
                        } else {
                            out.block()
                        }
                        lists.push(None);
                    }
                    "ol" => {
                        if lists.is_empty() {
                            out.paragraph()
                        } else {
                            out.block()
                        }
                        let start = Token::attr(&attrs, "start").and_then(|s| s.trim().parse().ok()).unwrap_or(1);
                        lists.push(Some(start));
                    }
                    "li" => {
                        out.block();
                        prefix(&mut out, quote);
                        let indent = "  ".repeat(lists.len().saturating_sub(1));
                        let marker = match lists.last_mut() {
                            Some(Some(n)) => {
                                *n += 1;
                                format!("{}. ", *n - 1)
                            }
                            _ => "- ".to_string(),
                        };
                        out.out.push_str(&format!("{indent}{marker}"));
                    }
                    "a" => {
                        let href = Token::attr(&attrs, "href").unwrap_or_default();
                        out.push("[");
                        links.push((href, out.out.len()));
                    }
                    "img" => {
                        let alt = Token::attr(&attrs, "alt").unwrap_or_default();
                        let src = Token::attr(&attrs, "src").unwrap_or_default();
                        out.push(&format!("![{}]({src})", md_escape(&alt)));
                    }
                    h if h.len() == 2 && h.starts_with('h') && h.as_bytes()[1].is_ascii_digit() => {
                        out.paragraph();
                        prefix(&mut out, quote);
                        let level = (h.as_bytes()[1] - b'0') as usize;
                        out.out.push_str(&format!("{} ", "#".repeat(level.clamp(1, 6))));
                    }
                    t if BLOCKS.contains(&t) => out.block_for(t),
                    _ => {}
                }
            }
            Token::End(tag) => {
                if HIDDEN.contains(&tag.as_str()) {
                    hidden = hidden.saturating_sub(1);
                    continue;
                }
                match tag.as_str() {
                    "b" | "strong" => out.push("**"),
                    "i" | "em" => out.push("_"),
                    "s" | "strike" | "del" => out.push("~~"),
                    "code" if !pre => out.push("`"),
                    "pre" => {
                        out.block();
                        out.raw("```");
                        out.paragraph();
                        pre = false;
                    }
                    "blockquote" => {
                        out.paragraph();
                        quote = quote.saturating_sub(1);
                    }
                    "ul" | "ol" => {
                        lists.pop();
                        if lists.is_empty() { out.paragraph() } else { out.block() }
                    }
                    "a" => {
                        if let Some((href, start)) = links.pop() {
                            if href.is_empty() || out.out.len() == start {
                                // No target or no text: keep the text (or the URL) alone.
                                out.out.remove(start - 1);
                                out.push(&href);
                            } else {
                                out.out.push_str(&format!("]({href})"));
                            }
                        }
                    }
                    t if BLOCKS.contains(&t) => out.block_for(t),
                    _ => {}
                }
            }
            Token::Text(t) if hidden == 0 => {
                if pre {
                    out.raw(&t);
                } else {
                    prefix(&mut out, quote);
                    out.push(&md_escape(&collapse(&t)));
                }
            }
            Token::Text(_) => {}
        }
    }
    out.finish()
}

/// What [`filter`] keeps of an HTML document.
#[derive(Debug, Clone, Copy)]
pub struct Filter {
    /// `(input tag, output tag)`: tags kept, possibly renamed.
    pub tags: &'static [(&'static str, &'static str)],
    /// `(tag, attribute)`: attributes kept on kept tags.
    pub attrs: &'static [(&'static str, &'static str)],
    /// Written for `<br>` and around block elements.
    pub line_break: &'static str,
    /// Line breaks in text become `line_break` (a run of them, one) instead of spaces, for services that render a raw `\n` as a new line.
    pub keep_newlines: bool,
}

/// Rewrite `html` into the tags `f` allows. Text is escaped again and hidden elements are dropped. Every kept tag is closed. Stray closing tags are removed.
pub fn filter(html: &str, f: &Filter) -> String {
    let mut out = String::with_capacity(html.len());
    let mut open: Vec<&'static str> = Vec::new();
    let mut hidden = 0usize;
    let mut pre = 0usize;
    // A line was just ended by a block element; a `<br>` adds nothing.
    let mut block_ended = false;
    let keeps_pre = f.tags.iter().any(|(from, _)| *from == "pre");
    let line = |out: &mut String, block_ended: &mut bool| {
        if !out.is_empty() && !out.ends_with(f.line_break) {
            out.push_str(f.line_break);
            *block_ended = true;
        }
    };
    let mapped = |tag: &str| f.tags.iter().find(|(from, _)| *from == tag).map(|(_, to)| *to);
    scan(html, |tok| {
        match tok {
            Token::Start { tag, attrs, self_closing } => {
                if HIDDEN.contains(&tag.as_str()) {
                    hidden += usize::from(!self_closing);
                    return;
                }
                if tag == "br" {
                    if !std::mem::take(&mut block_ended) {
                        out.push_str(f.line_break);
                    }
                    return;
                }
                if BLOCKS.contains(&tag.as_str()) {
                    line(&mut out, &mut block_ended);
                    pre += usize::from(tag == "pre" && !self_closing);
                    if tag == "li" {
                        out.push_str("- ");
                    }
                }
                if let Some(to) = mapped(&tag) {
                    out.push('<');
                    out.push_str(to);
                    for (k, v) in &attrs {
                        if f.attrs.iter().any(|(t, a)| *t == to && a == k) {
                            out.push(' ');
                            out.push_str(k);
                            out.push_str("=\"");
                            out.push_str(&crate::util::html_escape_attr(v));
                            out.push('"');
                        }
                    }
                    out.push('>');
                    if self_closing {
                        close_tag(&mut out, to);
                    } else {
                        open.push(to);
                    }
                }
            }
            Token::End(tag) => {
                if HIDDEN.contains(&tag.as_str()) {
                    hidden = hidden.saturating_sub(1);
                    return;
                }
                if let Some(to) = mapped(&tag)
                    && let Some(i) = open.iter().rposition(|t| *t == to)
                {
                    for t in open.drain(i..).rev() {
                        close_tag(&mut out, t);
                    }
                }
                if BLOCKS.contains(&tag.as_str()) {
                    line(&mut out, &mut block_ended);
                    if tag == "pre" {
                        pre = pre.saturating_sub(1);
                    }
                }
            }
            Token::Text(t) if hidden == 0 => {
                let t = if pre > 0 {
                    t
                } else if f.keep_newlines && t.contains('\n') {
                    let re = crate::regex!(r"[ \t\r\x0b\x0c]*\n[\s]*");
                    re.split(&t).map(|l| collapse_owned(l.to_string())).collect::<Vec<_>>().join(f.line_break)
                } else {
                    collapse_owned(t)
                };
                let t = if pre == 0 && (out.is_empty() || out.ends_with(f.line_break)) { t.trim_start() } else { &t };
                let t = crate::util::html_escape_noquote(t);
                if !t.is_empty() {
                    block_ended = false;
                }
                // Without a kept `<pre>`, preformatted line breaks need explicit breaks.
                if pre > 0 && !keeps_pre { out.push_str(&t.replace('\n', f.line_break)) } else { out.push_str(&t) }
            }
            Token::Text(_) => {}
        }
    });
    for t in open.into_iter().rev() {
        close_tag(&mut out, t);
    }
    let kept = out.trim_end_matches(f.line_break).trim_end().len();
    out.truncate(kept);
    out
}

fn close_tag(out: &mut String, tag: &str) {
    out.push_str("</");
    out.push_str(tag);
    out.push('>');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "html"))]
    #[test]
    fn decode_without_feature() {
        assert_eq!(decode("a &amp; &lt;b&gt; &quot;&apos;&nbsp;&#65;&#x42;"), "a & <b> \"'\u{a0}AB");
        assert_eq!(decode("&copy; &#xZZ; &#1114112; & x; &amp"), "&copy; &#xZZ; &#1114112; & x; &amp");
    }

    #[test]
    fn tokenizes_tags_text_and_entities() {
        let t = tokens(r#"a &amp; b<br/><a href="x?a=1&amp;b=2">l</a><!-- c --><x 1 < 2"#);
        assert_eq!(t[0], Token::Text("a & b".into()));
        assert_eq!(t[1], Token::Start { tag: "br".into(), attrs: vec![], self_closing: true });
        assert_eq!(
            t[2],
            Token::Start { tag: "a".into(), attrs: vec![("href".into(), "x?a=1&b=2".into())], self_closing: false }
        );
        assert_eq!(t.last(), Some(&Token::Text("<x 1 < 2".into())));
    }

    // The reference is a Unicode-aware regex; `regex-lite` classes are ASCII-only.
    #[cfg(feature = "regex-unicode")]
    #[test]
    fn attributes_match_the_regex_grammar() {
        let re = crate::regex!(r#"([^\s=/"'>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?"#);
        let by_regex = |src: &str| -> Vec<(String, String)> {
            re.captures_iter(src)
                .map(|c| {
                    let v = c.get(2).or(c.get(3)).or(c.get(4)).map(|m| decode(m.as_str())).unwrap_or_default();
                    (c[1].to_ascii_lowercase(), v)
                })
                .collect()
        };
        let alphabet = ["a", "B", "=", "\"", "'", " ", "\t", "\u{2003}", "/", ">", "&amp;", "é"];
        // Every string of up to 5 symbols.
        let mut srcs = vec![String::new()];
        let mut frontier = srcs.clone();
        for _ in 0..5 {
            frontier = frontier.iter().flat_map(|s| alphabet.iter().map(move |a| format!("{s}{a}"))).collect();
            srcs.extend(frontier.iter().cloned());
        }
        srcs.push(r#" href = "x?a=1&amp;b=2" Data-X='y z' c=d/ e"#.into());
        for src in &srcs {
            assert_eq!(attributes(src), by_regex(src), "{src:?}");
        }
    }

    #[test]
    fn script_content_is_raw() {
        assert_eq!(html_to_text("<script>if (a<b) {}</script>ok"), "ok");
    }

    #[test]
    fn text() {
        assert_eq!(html_to_text("<p>Hello   <b>world</b></p><p>two<br>lines</p>"), "Hello world\n\ntwo\nlines");
        assert_eq!(html_to_text("<pre>  keep\n  this</pre>"), "  keep\n  this");
    }

    #[test]
    fn markdown() {
        assert_eq!(
            html_to_markdown("<h2>T</h2><p><b>b</b> <i>i</i> <a href='u'>l</a></p>"),
            "## T\n\n**b** _i_ [l](u)"
        );
        assert_eq!(html_to_markdown("<ol start=3><li>a</li><li>b</li></ol>"), "3. a\n4. b");
        assert_eq!(html_to_markdown("<ul><li>x*y</li></ul>"), "- x\\*y");
        assert_eq!(html_to_markdown("<blockquote>q</blockquote>"), "> q");
    }

    #[test]
    fn filter_keeps_allowed_tags_closed() {
        const F: Filter = Filter {
            tags: &[("b", "b"), ("strong", "b"), ("a", "a")],
            attrs: &[("a", "href")],
            line_break: "\n",
            keep_newlines: false,
        };
        assert_eq!(
            filter("<p><strong>x</strong> <a href='h' x=1>y</a> <i>z</i></p><p>w", &F),
            "<b>x</b> <a href=\"h\">y</a> z\nw"
        );
        assert_eq!(filter("<b>open</i> & 1<2", &F), "<b>open &amp; 1&lt;2</b>");
    }
}
