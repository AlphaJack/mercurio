//! RFC 5322 / MIME message building: quoted-printable and base64 bodies, RFC 2047 encoded words, multipart trees. CRLF line endings throughout.

use crate::env::Env;
use crate::crypto;

/// Longest line in an encoded body or header (RFC 2045), the `=` of a quoted-printable soft break included.
const MAX_LINE: usize = 76;

const CRLF: &str = "\r\n";

/// Longest raw UTF-8 run per encoded word: `=?utf-8?b?` + 60 base64 chars + `?=` is 72 chars.
const WORD_BYTES: usize = 45;

/// Replace CR/LF (header injection) with spaces.
pub fn single_line(s: &str) -> String {
    s.chars().map(|c| if c == '\r' || c == '\n' { ' ' } else { c }).collect()
}

/// RFC 2047 `B` encoded words, split on character boundaries and joined by `sep`.
pub fn encode_words(s: &str, sep: &str) -> String {
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in s.chars() {
        if chunk.len() + c.len_utf8() > WORD_BYTES && !chunk.is_empty() {
            words.push(format!("=?utf-8?b?{}?=", crypto::b64(chunk.as_bytes())));
            chunk.clear();
        }
        chunk.push(c);
    }
    if !chunk.is_empty() || words.is_empty() {
        words.push(format!("=?utf-8?b?{}?=", crypto::b64(chunk.as_bytes())));
    }
    words.join(sep)
}

/// Header value: ASCII passes through (folded at whitespace), anything else becomes encoded words.
pub fn header_value(s: &str) -> String {
    let s = single_line(s);
    if s.is_ascii() { fold_ascii(&s) } else { encode_words(&s, "\r\n ") }
}

/// Fold long ASCII header values at spaces (RFC 5322 2.2.3).
fn fold_ascii(s: &str) -> String {
    if s.len() <= MAX_LINE {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    let mut line_len = 0;
    for (i, word) in s.split(' ').enumerate() {
        if i > 0 {
            if line_len + 1 + word.len() > MAX_LINE && line_len > 0 {
                out.push_str("\r\n ");
                line_len = 1;
            } else {
                out.push(' ');
                line_len += 1;
            }
        }
        out.push_str(word);
        line_len += word.len();
    }
    out
}

/// `Name <address>`: the name quoted when it has specials, RFC 2047 encoded when non-ASCII. An empty name gives the bare address.
pub fn formataddr(name: &str, address: &str) -> String {
    if name.is_empty() {
        return address.to_string();
    }
    let name = single_line(name);
    if !name.is_ascii() {
        return format!("{} <{address}>", encode_words(&name, " "));
    }
    let specials = name.chars().any(|c| "[]\\()<>@,:;\".".contains(c));
    let quote = if specials { "\"" } else { "" };
    let escaped = name.replace('\\', "\\\\").replace('"', "\\\"");
    format!("{quote}{escaped}{quote} <{address}>")
}

/// Quoted-printable body encoding (RFC 2045 6.7) with CRLF hard breaks.
#[cfg(test)]
pub fn qp_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + text.len() / 8);
    qp_encode_into(&mut out, text);
    out
}

/// [`qp_encode`] appended to `out`.
pub fn qp_encode_into(out: &mut String, text: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut rest = text;
    let mut first = true;
    loop {
        // Lines end at `\r\n`, `\n` or a lone `\r`; the text after the last break is a line too.
        let (line, next) = match rest.find(['\r', '\n']) {
            Some(p) => {
                let (line, tail) = rest.split_at(p);
                (line, Some(tail.strip_prefix("\r\n").or_else(|| tail.get(1..)).unwrap_or("")))
            }
            None => (rest, None),
        };
        if !first {
            out.push_str(CRLF);
        }
        first = false;
        let bytes = line.as_bytes();
        let mut len = 0;
        for (j, &b) in bytes.iter().enumerate() {
            let last = j + 1 == bytes.len();
            let literal = matches!(b, 33..=60 | 62..=126) || ((b == b' ' || b == b'\t') && !last);
            let width = if literal { 1 } else { 3 };
            let limit = if last { MAX_LINE } else { MAX_LINE - 1 };
            if len + width > limit {
                out.push_str("=\r\n");
                len = 0;
            }
            if literal {
                out.push(b as char);
            } else {
                out.push('=');
                out.push(HEX[usize::from(b >> 4)] as char);
                out.push(HEX[usize::from(b & 15)] as char);
            }
            len += width;
        }
        match next {
            Some(n) => rest = n,
            None => break,
        }
    }
}

/// Base64 in 76-character lines.
pub fn b64_lines(data: &[u8]) -> String {
    let enc = crypto::b64(data);
    let mut out = String::with_capacity(enc.len() + enc.len() / 38 + 2);
    for (i, chunk) in enc.as_bytes().chunks(MAX_LINE).enumerate() {
        if i > 0 {
            out.push_str(CRLF);
        }
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
    }
    out
}

/// What a leaf holds: text already encoded, or text still to be quoted-printable encoded when the message is rendered (so a large body is encoded straight into the output).
#[derive(Debug, Clone)]
pub enum Content<'a> {
    Encoded(String),
    Qp(std::borrow::Cow<'a, str>),
}

impl Content<'_> {
    /// An estimate of the encoded size, for sizing the output.
    fn len(&self) -> usize {
        match self {
            Content::Encoded(s) => s.len(),
            Content::Qp(t) => t.len() + t.len() / 8,
        }
    }

    fn write_to(&self, out: &mut String) {
        match self {
            Content::Encoded(s) => out.push_str(s),
            Content::Qp(t) => qp_encode_into(out, t),
        }
    }
}

/// One node of a MIME tree.
#[derive(Debug, Clone)]
pub enum Part<'a> {
    Leaf { headers: Vec<(String, String)>, content: Content<'a> },
    Multi { subtype: &'static str, parts: Vec<Part<'a>> },
}

impl<'a> Part<'a> {
    /// `MIMEText(text, subtype, "utf-8")`: quoted-printable.
    pub fn text(subtype: &str, text: impl Into<std::borrow::Cow<'a, str>>) -> Part<'a> {
        Part::Leaf {
            headers: vec![
                ("Content-Type".into(), format!("text/{subtype}; charset=\"utf-8\"")),
                ("Content-Transfer-Encoding".into(), "quoted-printable".into()),
            ],
            content: Content::Qp(text.into()),
        }
    }

    /// A base64 attachment with `Content-Disposition: {disposition}; filename="..."`.
    pub fn file(mime: &str, data: &[u8], disposition: &str, filename: &str, content_id: Option<String>) -> Part<'a> {
        let mime =
            if mime.contains('/') && mime.is_ascii() { single_line(mime) } else { "application/octet-stream".into() };
        let mut headers = vec![
            ("Content-Type".into(), mime),
            ("Content-Transfer-Encoding".into(), "base64".into()),
            ("Content-Disposition".into(), format!("{disposition}; {}", filename_param(filename))),
        ];
        if let Some(cid) = content_id {
            headers.push(("Content-ID".into(), format!("<{}>", single_line(&cid))));
        }
        Part::Leaf { headers, content: Content::Encoded(b64_lines(data)) }
    }
}

/// `filename="..."`; RFC 2231 `filename*=` for names that are not plain ASCII.
fn filename_param(name: &str) -> String {
    let name = single_line(name);
    if name.is_ascii() && !name.contains(['"', '\\']) {
        return format!("filename=\"{name}\"");
    }
    let mut enc = String::new();
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&b) {
            enc.push(b as char);
        } else {
            enc.push_str(&format!("%{b:02X}"));
        }
    }
    format!("filename*=utf-8''{enc}")
}

fn boundary(env: &dyn Env) -> String {
    format!("=============mercurio{}==", env.random_hex(12))
}

/// [`render`] that consumes the tree and frees each leaf's content once it is written, so a large body is not held twice at the end.
pub fn render_owned(headers: &[(String, String)], body: Part<'_>, env: &dyn Env) -> String {
    let mut out = String::with_capacity(content_len(&body) + 4096);
    write_headers(headers, &mut out);
    render_part_owned(body, &mut out, env);
    out
}

fn render_part_owned(part: Part<'_>, out: &mut String, env: &dyn Env) {
    match part {
        Part::Leaf { headers, content } => {
            for (k, v) in &headers {
                out.push_str(k);
                out.push_str(": ");
                out.push_str(v);
                out.push_str(CRLF);
            }
            out.push_str(CRLF);
            content.write_to(out);
        }
        Part::Multi { subtype, parts } => {
            let b = boundary(env);
            out.push_str(&format!("Content-Type: multipart/{subtype}; boundary=\"{b}\"\r\n\r\n"));
            for p in parts {
                out.push_str(&format!("--{b}\r\n"));
                render_part_owned(p, out, env);
                out.push_str(CRLF);
            }
            out.push_str(&format!("--{b}--"));
        }
    }
}

fn write_headers(headers: &[(String, String)], out: &mut String) {
    for (k, v) in headers {
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push_str(CRLF);
    }
    out.push_str("MIME-Version: 1.0\r\n");
}

/// Serialise a message: `headers` first, then the MIME tree. CRLF everywhere.
pub fn render(headers: &[(String, String)], body: &Part<'_>, env: &dyn Env) -> String {
    let mut out = String::with_capacity(content_len(body) + 4096);
    for (k, v) in headers {
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push_str(CRLF);
    }
    out.push_str("MIME-Version: 1.0\r\n");
    render_part(body, &mut out, env);
    out
}

/// Bytes of leaf content in the tree: what `render` sizes its buffer for, so a large body is written without regrowing.
fn content_len(part: &Part<'_>) -> usize {
    match part {
        Part::Leaf { content, .. } => content.len(),
        Part::Multi { parts, .. } => parts.iter().map(content_len).sum(),
    }
}

fn render_part(part: &Part<'_>, out: &mut String, env: &dyn Env) {
    match part {
        Part::Leaf { headers, content } => {
            for (k, v) in headers {
                out.push_str(k);
                out.push_str(": ");
                out.push_str(v);
                out.push_str(CRLF);
            }
            out.push_str(CRLF);
            content.write_to(out);
        }
        Part::Multi { subtype, parts } => {
            let b = boundary(env);
            out.push_str(&format!("Content-Type: multipart/{subtype}; boundary=\"{b}\"\r\n\r\n"));
            for p in parts {
                out.push_str(&format!("--{b}\r\n"));
                render_part(p, out, env);
                out.push_str(CRLF);
            }
            out.push_str(&format!("--{b}--"));
        }
    }
}

/// SMTP DATA payload: dot-stuffed, CRLF-terminated, without the final `.`.
#[cfg(test)]
pub fn dot_stuff(message: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 16);
    dot_stuff_into(&mut out, message);
    out
}

/// [`dot_stuff_into`] for a message nobody needs afterwards: when no line starts with a dot the message's own buffer becomes the output, with no copy.
pub fn dot_stuff_owned(out: &mut Vec<u8>, message: String) {
    if message.starts_with('.') || message.contains("\r\n.") {
        dot_stuff_into(out, &message);
        return;
    }
    let mut bytes = message.into_bytes();
    if !bytes.ends_with(b"\r\n") {
        bytes.extend_from_slice(b"\r\n");
    }
    if out.is_empty() {
        *out = bytes;
    } else {
        out.extend_from_slice(&bytes);
    }
}

/// [`dot_stuff`] appended to `out`, which is grown once for the whole message.
pub fn dot_stuff_into(out: &mut Vec<u8>, message: &str) {
    out.reserve(message.len() + message.len() / 64 + 16);
    for (i, line) in message.split("\r\n").enumerate() {
        if i > 0 {
            out.extend_from_slice(b"\r\n");
        }
        if line.starts_with('.') {
            out.push(b'.');
        }
        out.extend_from_slice(line.as_bytes());
    }
    if !message.ends_with("\r\n") {
        out.extend_from_slice(b"\r\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qp_basics() {
        assert_eq!(qp_encode("plain"), "plain");
        assert_eq!(qp_encode("a=b"), "a=3Db");
        assert_eq!(qp_encode("trail \nx"), "trail=20\r\nx");
        assert_eq!(qp_encode("é"), "=C3=A9");
        let long = qp_encode(&"x".repeat(200));
        assert!(long.split("\r\n").all(|l| l.len() <= 76), "{long}");
        assert_eq!(long.replace("=\r\n", ""), "x".repeat(200));
        let enc = qp_encode(&"é".repeat(40));
        assert!(enc.split("\r\n").all(|l| l.len() <= 76));
        assert!(!enc.split("=\r\n").any(|l| l.ends_with('=') || l.ends_with("=C")));
    }

    #[test]
    fn words_and_addresses() {
        assert_eq!(encode_words("Jörg", " "), "=?utf-8?b?SsO2cmc=?=");
        assert_eq!(formataddr("", "a@b.co"), "a@b.co");
        assert_eq!(formataddr("Bot", "a@b.co"), "Bot <a@b.co>");
        assert_eq!(formataddr("J. \"D\"", "a@b.co"), "\"J. \\\"D\\\"\" <a@b.co>");
        assert_eq!(formataddr("@", "a@b.co"), "\"@\" <a@b.co>");
        assert!(header_value(&"é".repeat(60)).contains("\r\n "));
        assert_eq!(header_value("a\r\nBcc: x"), "a  Bcc: x");
    }

    #[test]
    fn stuffing() {
        assert_eq!(dot_stuff("a\r\n.b\r\n."), b"a\r\n..b\r\n..\r\n");
    }
}

#[cfg(test)]
mod qp_equivalence {
    use super::*;

    /// The encoder as it was before it stopped copying: normalise the line breaks, then one `String` per byte.
    fn before(text: &str) -> String {
        let text = text.replace("\r\n", "\n").replace('\r', "\n");
        let mut out = String::with_capacity(text.len() + text.len() / 8);
        for (i, line) in text.split('\n').enumerate() {
            if i > 0 {
                out.push_str(CRLF);
            }
            let bytes = line.as_bytes();
            let mut len = 0;
            for (j, &b) in bytes.iter().enumerate() {
                let last = j + 1 == bytes.len();
                let literal = matches!(b, 33..=60 | 62..=126) || ((b == b' ' || b == b'\t') && !last);
                let token = if literal { (b as char).to_string() } else { format!("={b:02X}") };
                let limit = if last { MAX_LINE } else { MAX_LINE - 1 };
                if len + token.len() > limit {
                    out.push_str("=\r\n");
                    len = 0;
                }
                out.push_str(&token);
                len += token.len();
            }
        }
        out
    }

    #[test]
    fn same_output_for_awkward_text() {
        let long = "ä".repeat(90) + &"x".repeat(80) + " ";
        for text in ["", "a", "a\n", "\n", "a\r\nb", "a\rb\r", "a\n\rb", "tab\t \n=sign", "end \r\n", &long, "é\r\n\r\n\r\nz  "] {
            assert_eq!(qp_encode(text), before(text), "{text:?}");
        }
    }
}

#[cfg(test)]
mod dot_stuff_owned_tests {
    use super::*;

    #[test]
    fn owned_matches_borrowed() {
        for msg in ["", "a", "a\r\n", ".a", "a\r\n.b\r\n", "a\r\nb", "..\r\n.", "x\r\n\r\n.\r\n"] {
            let mut owned = Vec::new();
            dot_stuff_owned(&mut owned, msg.to_string());
            assert_eq!(owned, dot_stuff(msg), "{msg:?}");
            let mut appended = b"EHLO\r\n".to_vec();
            dot_stuff_owned(&mut appended, msg.to_string());
            assert_eq!(&appended[6..], &dot_stuff(msg)[..], "{msg:?}");
        }
    }
}
