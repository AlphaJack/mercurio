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
pub fn qp_encode(text: &str) -> String {
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

/// One node of a MIME tree.
#[derive(Debug, Clone)]
pub enum Part {
    Leaf { headers: Vec<(String, String)>, content: String },
    Multi { subtype: &'static str, parts: Vec<Part> },
}

impl Part {
    /// `MIMEText(text, subtype, "utf-8")`: quoted-printable.
    pub fn text(subtype: &str, text: &str) -> Part {
        Part::Leaf {
            headers: vec![
                ("Content-Type".into(), format!("text/{subtype}; charset=\"utf-8\"")),
                ("Content-Transfer-Encoding".into(), "quoted-printable".into()),
            ],
            content: qp_encode(text),
        }
    }

    /// A base64 attachment with `Content-Disposition: {disposition}; filename="..."`.
    pub fn file(mime: &str, data: &[u8], disposition: &str, filename: &str, content_id: Option<String>) -> Part {
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
        Part::Leaf { headers, content: b64_lines(data) }
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

/// Serialise a message: `headers` first, then the MIME tree. CRLF everywhere.
pub fn render(headers: &[(String, String)], body: &Part, env: &dyn Env) -> String {
    let mut out = String::new();
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

fn render_part(part: &Part, out: &mut String, env: &dyn Env) {
    match part {
        Part::Leaf { headers, content } => {
            for (k, v) in headers {
                out.push_str(k);
                out.push_str(": ");
                out.push_str(v);
                out.push_str(CRLF);
            }
            out.push_str(CRLF);
            out.push_str(content);
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
pub fn dot_stuff(message: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 16);
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
    out
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
