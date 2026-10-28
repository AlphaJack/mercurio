//! Fit a service's markup conversion to its size limit: the source is cut at safe positions and each piece converted on its own, as long as the converted piece fits.

use crate::convert::split::{HTML_ENTITY_MAXLEN, find, html_tag_end};
use crate::message::NotifyFormat;

fn clen(s: &str) -> usize {
    s.chars().count()
}

/// Positions a piece may end at: outside HTML tags and entities, after whitespace for Markdown (so markup in a word is not cut), anywhere in plain text. The end is always included.
fn cuts(body: &[char], format: Option<NotifyFormat>) -> Vec<usize> {
    match format {
        Some(NotifyFormat::Html) => html_safe_cuts(body),
        Some(NotifyFormat::Markdown) | None => {
            let mut c: Vec<usize> = (1..body.len()).filter(|&i| body[i - 1].is_whitespace()).collect();
            c.push(body.len());
            c
        }
        Some(NotifyFormat::Text) => (0..=body.len()).collect(),
    }
}

/// The source being split: its chars (for cut positions) and the byte offset of each char (so a piece is sliced, not collected).
struct Source<'a> {
    text: &'a str,
    chars: &'a [char],
    /// `bytes[i]` is the byte offset of char `i`; `bytes[n]` is `text.len()`.
    bytes: Vec<usize>,
}

impl<'a> Source<'a> {
    fn new(text: &'a str, chars: &'a [char]) -> Self {
        let mut bytes: Vec<usize> = Vec::with_capacity(chars.len() + 1);
        bytes.extend(text.char_indices().map(|(i, _)| i));
        bytes.push(text.len());
        Source { text, chars, bytes }
    }

    /// Chars `start..end` of the source.
    fn slice(&self, start: usize, end: usize) -> &'a str {
        self.text.get(self.bytes[start]..self.bytes[end]).unwrap_or_default()
    }
}

/// Sorted cut positions: an explicit list or every position `0..=n`.
#[derive(Clone, Copy)]
enum Cuts<'a> {
    At(&'a [usize]),
    Anywhere(usize),
}

impl Cuts<'_> {
    fn len(self) -> usize {
        match self {
            Cuts::At(a) => a.len(),
            Cuts::Anywhere(n) => n + 1,
        }
    }

    fn get(self, i: usize) -> usize {
        match self {
            Cuts::At(a) => a[i],
            Cuts::Anywhere(_) => i,
        }
    }

    /// Index after the last cut at index `>= lo` that is `<= x`.
    fn bisect_right(self, x: usize, lo: usize) -> usize {
        match self {
            Cuts::At(a) => lo + a[lo.min(a.len())..].partition_point(|&v| v <= x),
            Cuts::Anywhere(n) => lo + (x.min(n) + 1).saturating_sub(lo),
        }
    }
}

/// The longest fitting piece from `offset`, falling back to cutting anywhere when no safe cut fits.
fn fit(
    src: &Source<'_>,
    offset: usize,
    limit: usize,
    convert: &dyn Fn(&str) -> String,
    safe: &[usize],
) -> (String, usize) {
    let (piece, consumed) = longest_fitting_cut(src, offset, limit, convert, Cuts::At(safe));
    if clen(&piece) <= limit {
        return (piece, consumed);
    }
    longest_fitting_cut(src, offset, limit, convert, Cuts::Anywhere(src.chars.len()))
}

/// Cut positions outside HTML tags and entities (the end is always included).
fn html_safe_cuts(body: &[char]) -> Vec<usize> {
    let mut cuts = Vec::new();
    let mut entity_end: isize = -1;
    let n = body.len();
    let mut idx = 0;
    while idx < n {
        if idx as isize > entity_end {
            cuts.push(idx);
        }
        let ch = body[idx];
        if ch == '<' {
            match html_tag_end(body, idx, None) {
                Some(e) => idx = e,
                None => break,
            }
        } else if ch == '&'
            && let Some(semi) = find(body, ';', idx, idx + HTML_ENTITY_MAXLEN)
            && !body[idx..semi].iter().any(|c| c.is_whitespace())
        {
            entity_end = semi as isize;
        }
        idx += 1;
    }
    cuts.push(n);
    cuts
}

/// The longest converted prefix ending at one of `cuts`: `(converted, consumed)`.
fn longest_fitting_cut(
    src: &Source<'_>,
    offset: usize,
    limit: usize,
    convert: &dyn Fn(&str) -> String,
    cuts: Cuts<'_>,
) -> (String, usize) {
    let conv = |end: usize| convert(src.slice(offset, end));
    let first = cuts.bisect_right(offset, 0);
    let mut lo = first as isize;
    let mut hi = cuts.len() as isize - 1;
    let mut best: Option<(String, usize)> = None;
    // The conversion at `first` when it was probed and too long; it is the answer when nothing fits.
    let mut rejected_first: Option<String> = None;
    let mut span = limit.max(1);
    while lo <= hi {
        let probe = (lo as usize).max(cuts.bisect_right(offset + span, lo as usize).saturating_sub(1));
        let candidate = conv(cuts.get(probe));
        if clen(&candidate) > limit {
            if probe == first {
                rejected_first = Some(candidate);
            }
            hi = probe as isize - 1;
            break;
        }
        best = Some((candidate, cuts.get(probe) - offset));
        lo = probe as isize + 1;
        span *= 2;
    }
    while lo <= hi {
        let mid = ((lo + hi) / 2) as usize;
        let candidate = conv(cuts.get(mid));
        if clen(&candidate) <= limit {
            best = Some((candidate, cuts.get(mid) - offset));
            lo = mid as isize + 1;
        } else {
            if mid == first {
                rejected_first = Some(candidate);
            }
            hi = mid as isize - 1;
        }
    }
    best.unwrap_or_else(|| {
        let end = cuts.get(first);
        (rejected_first.unwrap_or_else(|| conv(end)), end - offset)
    })
}

/// Split `body` into converted pieces within `limit` chars.
pub(crate) fn split_dialect_chunk(
    body: &str,
    limit: usize,
    convert: &dyn Fn(&str) -> String,
    format: Option<NotifyFormat>,
) -> Vec<String> {
    let converted = convert(body);
    if body.is_empty() || clen(&converted) <= limit {
        return vec![converted];
    }
    let chars: Vec<char> = body.chars().collect();
    let safe = cuts(&chars, format);
    let src = Source::new(body, &chars);
    let mut pieces: Vec<String> = Vec::new();
    let mut offset = 0;
    while offset < chars.len() {
        let (piece, consumed) = fit(&src, offset, limit, convert, &safe);
        if !piece.is_empty() || pieces.is_empty() {
            pieces.push(piece);
        }
        offset += consumed.max(1);
    }
    pieces
}

/// The longest converted prefix of `body` within `limit` chars.
pub(crate) fn truncate_dialect_chunk(
    body: &str,
    limit: usize,
    convert: &dyn Fn(&str) -> String,
    format: Option<NotifyFormat>,
) -> String {
    let converted = convert(body);
    if body.is_empty() || clen(&converted) <= limit {
        return converted;
    }
    let chars: Vec<char> = body.chars().collect();
    fit(&Source::new(body, &chars), 0, limit, convert, &cuts(&chars, format)).0
}

/// What a unit of converted HTML is, for [`split_html`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum AtomKind<'a> {
    /// An opening tag that needs a matching close (`<b>`, `<a href="…">`).
    Open(&'a str),
    Close(&'a str),
    /// `<br>`: a line boundary.
    Br,
    /// Any other tag (void, self-closing, comment).
    Tag,
    Newline,
    /// Other whitespace.
    Space,
    /// A character or a whole entity.
    Text,
}

/// A unit that is never divided: a tag, an entity or one character.
#[derive(Clone, Copy)]
struct Atom<'a> {
    start: usize,
    end: usize,
    chars: usize,
    kind: AtomKind<'a>,
}

/// Elements without a closing tag.
const VOID: &[&str] =
    &["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"];

/// Where the tag opened at byte `start` ends (after its `>`), skipping quoted attribute values; `None` when unclosed.
fn tag_end(b: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    while let Some(&c) = b.get(i) {
        match c {
            b'>' => return Some(i + 1),
            q @ (b'"' | b'\'') => i += 1 + b.get(i + 1..)?.iter().position(|&c| c == q)?,
            _ => {}
        }
        i += 1;
    }
    None
}

/// `&name;` / `&#123;` at byte `i`: its end.
fn entity_end(b: &[u8], i: usize) -> Option<usize> {
    let window = b.get(i + 1..b.len().min(i + HTML_ENTITY_MAXLEN))?;
    let semi = window.iter().position(|&c| c == b';')?;
    let name = window.get(..semi)?;
    (semi > 0 && name.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'#')).then_some(i + semi + 2)
}

fn atoms(html: &str) -> Vec<Atom<'_>> {
    let b = html.as_bytes();
    let mut out = Vec::with_capacity(html.len());
    let mut i = 0;
    while let Some(&byte) = b.get(i) {
        let next = b.get(i + 1).copied().unwrap_or(0);
        if byte == b'<'
            && (next.is_ascii_alphabetic() || matches!(next, b'/' | b'!'))
            && let Some(end) = tag_end(b, i)
        {
            let tag = html.get(i..end).unwrap_or_default();
            let closing = next == b'/';
            let name_start = i + 1 + usize::from(closing);
            let name_len =
                b.get(name_start..end).unwrap_or_default().iter().take_while(|c| c.is_ascii_alphanumeric()).count();
            let name = html.get(name_start..name_start + name_len).unwrap_or_default();
            let kind = if name.eq_ignore_ascii_case("br") {
                AtomKind::Br
            } else if name.is_empty() || tag.ends_with("/>") || VOID.iter().any(|v| v.eq_ignore_ascii_case(name)) {
                AtomKind::Tag
            } else if closing {
                AtomKind::Close(name)
            } else {
                AtomKind::Open(name)
            };
            out.push(Atom { start: i, end, chars: clen(tag), kind });
            i = end;
            continue;
        }
        if byte == b'&'
            && let Some(end) = entity_end(b, i)
        {
            out.push(Atom { start: i, end, chars: end - i, kind: AtomKind::Text });
            i = end;
            continue;
        }
        let c = html.get(i..).and_then(|s| s.chars().next()).unwrap_or(' ');
        let kind = match c {
            '\n' => AtomKind::Newline,
            c if c.is_whitespace() => AtomKind::Space,
            _ => AtomKind::Text,
        };
        out.push(Atom { start: i, end: i + c.len_utf8(), chars: 1, kind });
        i += c.len_utf8();
    }
    out
}

/// Open tags: `(name, opening tag)`.
type Stack<'a> = Vec<(&'a str, &'a str)>;

fn close_len(name: &str) -> usize {
    clen(name) + 3
}

fn track<'a>(stack: &mut Stack<'a>, atom: &Atom<'a>, html: &'a str) {
    match atom.kind {
        AtomKind::Open(name) => stack.push((name, html.get(atom.start..atom.end).unwrap_or_default())),
        AtomKind::Close(name) => {
            if let Some(p) = stack.iter().rposition(|(n, _)| n.eq_ignore_ascii_case(name)) {
                stack.truncate(p);
            }
        }
        AtomKind::Br | AtomKind::Tag | AtomKind::Newline | AtomKind::Space | AtomKind::Text => {}
    }
}

/// Where the piece starting at atom `i` (with `stack` open) ends: the exclusive atom index.
fn piece_end(atoms: &[Atom<'_>], html: &str, i: usize, stack: &Stack<'_>, limit: usize) -> usize {
    let mut st = stack.clone();
    let mut closing: usize = st.iter().map(|(n, _)| close_len(n)).sum();
    let mut len: usize = st.iter().map(|(_, open)| clen(open)).sum();
    // Candidate ends with the piece length there.
    let mut line: Option<(usize, usize)> = None;
    let mut word: Option<(usize, usize)> = None;
    let mut any: Option<usize> = None;
    let mut j = i;
    while let Some(a) = atoms.get(j) {
        // Open tags add their closing tag too, so `len + closing` only grows.
        let next_closing = match a.kind {
            AtomKind::Open(n) => closing + close_len(n),
            AtomKind::Close(_) => {
                let mut next = st.clone();
                track(&mut next, a, html);
                next.iter().map(|(n, _)| close_len(n)).sum()
            }
            AtomKind::Br | AtomKind::Tag | AtomKind::Newline | AtomKind::Space | AtomKind::Text => closing,
        };
        // At least one atom past the reopened tags goes in every piece.
        if len + a.chars + next_closing > limit && any.is_some() {
            break;
        }
        track(&mut st, a, html);
        len += a.chars;
        closing = next_closing;
        j += 1;
        match a.kind {
            AtomKind::Br | AtomKind::Newline => line = Some((j, len)),
            AtomKind::Space => word = Some((j, len)),
            AtomKind::Open(_) | AtomKind::Close(_) | AtomKind::Tag | AtomKind::Text => {}
        }
        if !matches!(a.kind, AtomKind::Open(_)) {
            any = Some(j);
        }
    }
    let half = limit / 2;
    if j == atoms.len() {
        j
    } else if let Some((e, _)) = line.filter(|&(_, l)| l >= half) {
        e
    } else if let Some((e, _)) = word.filter(|&(_, l)| l >= half) {
        e
    } else {
        any.unwrap_or(j).max(i + 1)
    }
}

/// Split well-nested HTML (a service's converted output) into pieces of at most `limit` chars (`0`: no limit), at most `max_pieces` of them. Cuts fall outside tags and entities, at a line break or else whitespace once the piece is at least half full, anywhere else otherwise. Tags open at a cut are closed at the end of the piece and reopened at the start of the next; a `<br>` at a cut is dropped (the piece boundary breaks the line). A piece only exceeds `limit` when a single tag (or the tags reopened in front of it) does.
pub(crate) fn split_html(html: &str, limit: usize, max_pieces: usize) -> Vec<String> {
    if limit == 0 || clen(html) <= limit {
        return vec![html.to_owned()];
    }
    let atoms = atoms(html);
    let is_text = |a: &Atom<'_>| matches!(a.kind, AtomKind::Text | AtomKind::Space | AtomKind::Newline);
    let last_text = atoms.iter().rposition(is_text);
    let mut pieces = Vec::new();
    let mut stack: Stack<'_> = Vec::new();
    let mut i = 0;
    while pieces.len() < max_pieces {
        while atoms.get(i).is_some_and(|a| a.kind == AtomKind::Br) {
            i += 1;
        }
        if last_text.is_none_or(|t| i > t) {
            break;
        }
        let end = piece_end(&atoms, html, i, &stack, limit);
        let mut piece = String::with_capacity(limit + 16);
        for (_, open) in &stack {
            piece.push_str(open);
        }
        let dropped_br = end < atoms.len() && atoms.get(end - 1).is_some_and(|a| a.kind == AtomKind::Br);
        let content_end = end - usize::from(dropped_br);
        if let (Some(first), Some(last)) = (atoms.get(i), atoms.get(content_end.wrapping_sub(1)))
            && content_end > i
        {
            piece.push_str(html.get(first.start..last.end).unwrap_or_default());
        }
        for a in atoms.get(i..end).unwrap_or_default() {
            track(&mut stack, a, html);
        }
        for (name, _) in stack.iter().rev() {
            piece.push_str("</");
            piece.push_str(name);
            piece.push('>');
        }
        pieces.push(piece);
        i = end;
    }
    if pieces.is_empty() {
        pieces.push(String::new());
    }
    pieces
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Text with every tag removed.
    fn text(html: &str) -> String {
        atoms(html)
            .iter()
            .filter(|a| matches!(a.kind, AtomKind::Text | AtomKind::Space | AtomKind::Newline))
            .map(|a| html.get(a.start..a.end).unwrap_or_default())
            .collect()
    }

    /// Every piece: within `limit`, balanced tags, no cut tag or entity; together they hold the same text.
    fn check(html: &str, limit: usize) -> Vec<String> {
        let pieces = split_html(html, limit, usize::MAX);
        for p in &pieces {
            assert!(clen(p) <= limit, "{} > {limit}: {p}", clen(p));
            let mut stack: Stack<'_> = Vec::new();
            for a in atoms(p) {
                if let AtomKind::Close(n) = a.kind {
                    assert_eq!(stack.last().map(|(o, _)| *o), Some(n), "unbalanced: {p}");
                }
                track(&mut stack, &a, p);
            }
            assert!(stack.is_empty(), "unclosed tags: {p}");
            // A cut tag or entity leaves a stray `<`, `>` or `&` in the text.
            let t = text(p);
            assert!(!t.contains(['<', '>']), "cut tag: {p}");
            assert!(atoms(p).iter().all(|a| p.get(a.start..a.end) != Some("&")), "cut entity: {p}");
        }
        assert_eq!(pieces.iter().map(|p| text(p)).collect::<String>(), text(html));
        pieces
    }

    #[test]
    fn short_input_is_one_piece() {
        assert_eq!(split_html("<b>a</b>", 10, usize::MAX), vec!["<b>a</b>"]);
        assert_eq!(split_html("", 10, usize::MAX), vec![""]);
        assert_eq!(split_html("abc", 0, usize::MAX), vec!["abc"]);
    }

    #[test]
    fn prefers_line_then_word_boundaries() {
        let html = "first line here<br>second line is longer";
        assert_eq!(check(html, 30), vec!["first line here", "second line is longer"]);
        assert_eq!(check("aaaa bbbb cccc dddd", 12), vec!["aaaa bbbb ", "cccc dddd"]);
        // No boundary in the second half: cut anywhere.
        assert_eq!(check("abcdefghij", 4), vec!["abcd", "efgh", "ij"]);
    }

    #[test]
    fn closes_and_reopens_tags() {
        let html = r#"<b>bold <a href="http://x/?a=1&amp;b=2">link text here</a> tail</b> end"#;
        let pieces = check(html, 50);
        assert!(pieces.len() > 1);
        assert!(pieces[1].starts_with("<b>"), "{pieces:?}");
        assert!(pieces.iter().all(|p| !p.contains("<b></b>")), "{pieces:?}");
    }

    #[test]
    fn never_cuts_entities() {
        let html = "x&amp;&lt;&gt;&#8212;y ".repeat(40);
        for limit in [7, 13, 50] {
            check(&html, limit);
        }
    }

    #[test]
    fn long_mixed_document() {
        let unit = "<b>Section</b><br>Para has <b>bold</b> and <i>it&amp;alic</i>, <a href=\"http://e.com/1\">a link</a>. \
                    Sentences keep going so splitting has to pick a boundary.<br>- point a<br>- point b<br>";
        let html = unit.repeat(200);
        let html = html.trim_end_matches("<br>");
        for limit in [64, 100, 256, 1024] {
            let pieces = check(html, limit);
            assert!(pieces.iter().all(|p| !p.starts_with("<br>") && !p.ends_with("<br>")), "{pieces:#?}");
        }
        assert_eq!(split_html(html, 256, 1), vec![check(html, 256).remove(0)]);
    }

    #[test]
    fn oversized_tag_still_progresses() {
        let html = format!("<a href=\"{}\">x</a> y", "u".repeat(50));
        let pieces = split_html(&html, 20, usize::MAX);
        assert_eq!(pieces.iter().map(|p| text(p)).collect::<String>(), "x y");
    }
}
