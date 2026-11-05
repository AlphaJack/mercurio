//! Percent-encoding and decoding, and `application/x-www-form-urlencoded` text.

/// Percent-decoding (UTF-8; invalid bytes become U+FFFD; malformed escapes kept).
pub fn unquote(s: &str) -> String {
    if !s.contains('%') {
        return s.to_owned();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if let (b'%', Some(hi), Some(lo)) =
            (b[i], b.get(i + 1).and_then(|&c| hex(c)), b.get(i + 2).and_then(|&c| hex(c)))
        {
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The pairs of an `application/x-www-form-urlencoded` text.
pub(crate) fn parse_form(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (unquote_plus(k), unquote_plus(v)),
            None => (unquote_plus(p), String::new()),
        })
        .collect()
}

/// [`unquote`] with `+` as a space.
pub fn unquote_plus(s: &str) -> String {
    unquote(&s.replace('+', " "))
}

/// Characters left unescaped in URL paths.
pub(crate) const PATH_SAFE: &str = "/:@!$&'()*+=";

/// Percent-encoding: keeps ASCII alphanumerics, `_.-~` and the `safe` characters; percent-encodes UTF-8 bytes otherwise.
pub(crate) fn quote(s: &str, safe: &str) -> String {
    let mut out = String::with_capacity(s.len());
    quote_into(&mut out, s, safe, false);
    out
}

/// Append `s` percent-encoded to `out`; `plus` writes spaces as `+`.
fn quote_into(out: &mut String, s: &str, safe: &str, plus: bool) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in s.as_bytes() {
        if plus && b == b' ' {
            out.push('+');
        } else if b.is_ascii_alphanumeric() || b"_.-~".contains(&b) || (b.is_ascii() && safe.as_bytes().contains(&b)) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0xF) as usize] as char);
        }
    }
}

/// `application/x-www-form-urlencoded` encoding (form bodies and query strings).
pub(crate) fn form_urlencode<'a, I, K, V>(pairs: I) -> String
where
    I: IntoIterator<Item = &'a (K, V)>,
    K: AsRef<str> + 'a,
    V: AsRef<str> + 'a,
{
    let pairs: Vec<&(K, V)> = pairs.into_iter().collect();
    // Sized for text that needs no escaping, so a large body does not regrow the buffer by doubling.
    let mut out = String::with_capacity(pairs.iter().map(|(k, v)| k.as_ref().len() + v.as_ref().len() + 2).sum());
    for (k, v) in pairs {
        if !out.is_empty() {
            out.push('&');
        }
        quote_into(&mut out, k.as_ref(), "", true);
        out.push('=');
        quote_into(&mut out, v.as_ref(), "", true);
    }
    out
}
