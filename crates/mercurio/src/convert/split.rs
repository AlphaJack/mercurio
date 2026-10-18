//! Splitting long bodies into pieces, with HTML/Markdown-aware split points. Indices are code points.

use crate::message::NotifyFormat;

/// The longest an HTML entity can be, `&` and `;` included.
pub const HTML_ENTITY_MAXLEN: usize = 33;

/// First `c` in `text[start..end]` (`end` clamped to the length).
pub(crate) fn find(text: &[char], c: char, start: usize, end: usize) -> Option<usize> {
    let end = end.min(text.len());
    if start >= end {
        return None;
    }
    text[start..end].iter().position(|&x| x == c).map(|p| p + start)
}

/// Last `c` in `text[start..end]` (`end` clamped to the length).
pub(crate) fn rfind(text: &[char], c: char, start: usize, end: usize) -> Option<usize> {
    let end = end.min(text.len());
    if start >= end {
        return None;
    }
    text[start..end].iter().rposition(|&x| x == c).map(|p| p + start)
}

/// Where the tag opened at `start` ends (the `>`); `None` when unclosed. A `>` inside a quoted attribute value does not end the tag.
pub fn html_tag_end(text: &[char], start: usize, end: Option<usize>) -> Option<usize> {
    let end = end.unwrap_or(text.len()).min(text.len());
    let mut idx = start + 1;
    loop {
        if idx >= end {
            return None;
        }
        let rel = text[idx..end].iter().position(|c| matches!(c, '>' | '"' | '\''))?;
        idx += rel;
        let q = text[idx];
        if q == '>' {
            return Some(idx);
        }
        idx = find(text, q, idx + 1, end)?;
        idx += 1;
    }
}

/// Move a split before any HTML entity it would divide.
pub fn html_adjust(text: &[char], window_start: usize, split_at: usize) -> usize {
    if split_at <= window_start || split_at > text.len() {
        return split_at;
    }
    let search_start = window_start.max(split_at.saturating_sub(HTML_ENTITY_MAXLEN));
    let Some(amp) = rfind(text, '&', search_start, split_at) else {
        return split_at;
    };
    let forward_end = text.len().min(split_at + HTML_ENTITY_MAXLEN);
    if let Some(semi) = find(text, ';', amp, forward_end)
        && amp > window_start
        && amp < split_at
        && split_at <= semi
    {
        return amp;
    }
    split_at
}

/// Move a split out of an HTML tag.
pub fn html_tag_adjust(text: &[char], window_start: usize, split_at: usize, window_end: Option<usize>) -> usize {
    if split_at <= window_start || split_at > text.len() {
        return split_at;
    }
    let mut lt = find(text, '<', window_start, split_at);
    let mut gt: Option<usize> = None;
    while let Some(l) = lt {
        gt = html_tag_end(text, l, window_end);
        match gt {
            Some(g) if g < split_at => lt = find(text, '<', g + 1, split_at),
            _ => break,
        }
    }
    let Some(l) = lt else {
        return split_at;
    };
    if l > window_start {
        return l;
    }
    gt.map(|g| g + 1).unwrap_or(split_at)
}

/// Move a split left when it cuts a Markdown or chat link.
pub fn markdown_adjust(text: &[char], window_start: usize, split_at: usize) -> usize {
    if split_at <= window_start || split_at > text.len() {
        return split_at;
    }
    let search_start = window_start;
    let forward_end = text.len().min(split_at + (split_at - window_start) + 1);

    let mut link_start = rfind(text, '[', search_start, split_at);
    if link_start.is_none()
        && let Some(image_mark) = rfind(text, '!', search_start, split_at)
        && image_mark + 1 < text.len()
        && text[image_mark + 1] == '['
    {
        link_start = Some(image_mark);
    }
    if let Some(ls) = link_start
        && let Some(le) = find(text, ')', ls, forward_end)
        && ls < split_at
        && split_at < le
    {
        return ls;
    }

    if let Some(angle) = rfind(text, '<', search_start, split_at)
        && let Some(pipe) = find(text, '|', angle + 1, forward_end)
        && let Some(ae) = find(text, '>', pipe, forward_end)
        && angle < split_at
        && split_at <= ae
    {
        return angle;
    }
    split_at
}

fn is_punct_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n' | '\x0b' | '\x0c')
}

/// Split text within `limit` chars, preferring newlines, then spaces/tabs, then punctuation followed by whitespace, then a hard cut. HTML avoids splitting entities and tags; Markdown also protects links and escapes.
pub fn smart_split(text: &str, limit: isize, format: NotifyFormat) -> Vec<String> {
    if text.is_empty() || limit <= 0 {
        return vec![String::new()];
    }
    let chars: Vec<char> = text.chars().collect();
    smart_split_chars(&chars, limit as usize, format).into_iter().map(|s| s.iter().collect()).collect()
}

pub(crate) fn smart_split_chars(text: &[char], limit: usize, format: NotifyFormat) -> Vec<&[char]> {
    let mut result = Vec::new();
    let mut start = 0;
    let length = text.len();
    while start < length {
        let remaining = length - start;
        if remaining <= limit {
            result.push(&text[start..]);
            break;
        }
        let window_end = (start + limit).min(length);

        let last_nl =
            [rfind(text, '\n', start, window_end), rfind(text, '\r', start, window_end)].into_iter().flatten().max();
        let last_sp =
            [rfind(text, ' ', start, window_end), rfind(text, '\t', start, window_end)].into_iter().flatten().max();

        let mut split_punct = None;
        let mut i = start;
        while i < window_end {
            if matches!(text[i], '.' | '!' | '?' | ':' | ';') && i + 1 < window_end && is_punct_ws(text[i + 1]) {
                let mut j = i + 1;
                while j < window_end && is_punct_ws(text[j]) {
                    j += 1;
                }
                split_punct = Some(j);
                i = j;
            } else {
                i += 1;
            }
        }

        let mut split_at = if let Some(nl) = last_nl {
            nl + 1
        } else if let Some(sp) = last_sp {
            sp + 1
        } else if let Some(p) = split_punct {
            p
        } else {
            window_end
        };

        let orig_split = split_at;
        match format {
            NotifyFormat::Html => {
                split_at = html_adjust(text, start, split_at);
                split_at = html_tag_adjust(text, start, split_at, Some(window_end));
            }
            NotifyFormat::Markdown => {
                split_at = html_adjust(text, start, split_at);
                split_at = markdown_adjust(text, start, split_at);
                let chunk = &text[start..split_at.max(start)];
                let backslashes = chunk.iter().rev().take_while(|&&c| c == '\\').count();
                if backslashes % 2 == 1 {
                    split_at -= 1;
                }
            }
            NotifyFormat::Text => {}
        }
        if split_at <= start {
            split_at = orig_split;
        }
        result.push(&text[start..split_at]);
        start = split_at;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_spaces() {
        assert_eq!(smart_split("aaa bbb ccc", 5, NotifyFormat::Text), vec!["aaa ", "bbb ", "ccc"]);
        assert_eq!(smart_split("", 5, NotifyFormat::Text), vec![""]);
    }
}
