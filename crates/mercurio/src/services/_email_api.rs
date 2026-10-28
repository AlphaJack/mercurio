//! Helpers shared by e-mail API services (sendgrid, mailgun, postmark, sparkpost, resend, brevo, mailersend, smtp2go, sendpulse, office365) and the notification-platform services (novu, knock, courier).

use crate::crypto::b64;
use crate::message::Attachment;
use crate::parse::{EmailAddr, is_email, parse_emails};

/// Attachment name fallback: `file{no:03}.{ext}` (`no` starts at 1).
pub(crate) fn attachment_name(a: &Attachment, index: usize, ext: &str) -> String {
    if a.name.is_empty() { format!("file{:03}.{ext}", index + 1) } else { a.name.clone() }
}

/// Base64 of the attachment content (`attachment.base64()`).
pub(crate) fn attachment_b64(a: &Attachment) -> String {
    b64(&a.data)
}

/// JSON array with `f(name, base64, attachment)` per attachment; names fall back to [`attachment_name`] with `ext`.
pub(crate) fn attachments_json(
    atts: &[Attachment],
    ext: &str,
    f: impl Fn(String, String, &Attachment) -> serde_json::Value,
) -> serde_json::Value {
    atts.iter().enumerate().map(|(i, a)| f(attachment_name(a, i, ext), attachment_b64(a), a)).collect()
}

/// Validate each entry with `is_email`, keeping the valid ones (the rest are logged and dropped).
pub(crate) fn valid_emails<I, S>(entries: I) -> Vec<EmailAddr>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    entries.into_iter().filter_map(|e| is_email(e.as_ref())).collect()
}

/// Insert into an insertion-ordered "set" (Vec) if not already present.
pub(crate) fn set_add(set: &mut Vec<String>, value: String) {
    if !set.contains(&value) {
        set.push(value);
    }
}

/// A notification-platform recipient (novu, knock, courier).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Recipient {
    /// Plain user / subscriber id.
    Id(String),
    /// A valid e-mail address (`full_email`).
    Email(String),
    /// `+` followed by a valid phone number, kept as `+{digits}`.
    Phone(String),
}

/// Classify one path entry: `user@host` is an e-mail, `+<digits>` a phone number, anything else an id. Digits without `+` stay ids on purpose, since numeric user ids are common.
pub(crate) fn recipient(entry: &str) -> Recipient {
    if entry.contains('@')
        && let Some(e) = is_email(entry)
    {
        return Recipient::Email(e.full_email);
    }
    if entry.starts_with('+')
        && let Some(p) = crate::parse::is_phone_no(entry, 10)
    {
        return Recipient::Phone(format!("+{}", p.full));
    }
    Recipient::Id(entry.to_owned())
}

/// API base URL from `?host=` (`host[:port][/path]` -> `https://...`; or a full `http(s)://` URL), else `default`. No trailing slash.
pub(crate) fn api_base(u: &crate::url::ParsedUrl, default: &str) -> crate::Result<String> {
    let Some(h) = u.param_nonempty("host") else { return Ok(default.to_owned()) };
    let h = crate::url::unquote(h);
    let base = if h.starts_with("http://") || h.starts_with("https://") { h } else { format!("https://{h}") };
    let base = base.trim_end_matches('/').to_owned();
    let host = base.split("://").nth(1).unwrap_or("").split(['/', ':']).next().unwrap_or("");
    if crate::parse::is_hostname(host, true, true, false).is_none() {
        return Err(crate::Error::config("host", "an invalid API host was specified"));
    }
    Ok(base)
}

/// `:key=value` entries (double-unquoted, last one wins) for payload data.
pub(crate) fn colon_data(u: &crate::url::ParsedUrl) -> Vec<(String, String)> {
    unquoted_pairs(&u.query_colon)
}

/// `+key` / `:key` entries double-unquoted; a key repeated after unquoting keeps its last value at its last position.
pub(crate) fn unquoted_pairs(p: &crate::url::Pairs) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (k, v) in p.iter() {
        let k = crate::url::unquote(k);
        out.retain(|(x, _)| *x != k);
        out.push((k, crate::url::unquote(v)));
    }
    out
}

/// Valid recipients of `entries` (`parse_emails` then `is_email`) as `(name, full_email)` pairs.
pub(crate) fn email_pairs<I, S>(entries: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    valid_emails(parse_emails(entries, true)).into_iter().map(|e| (e.name, e.full_email)).collect()
}

/// `?cc=` / `?bcc=` without display names: de-duplicated valid addresses.
pub(crate) fn unique_emails(value: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    for e in valid_emails(crate::parse::parse_list(crate::parse::parse_list(value))) {
        set_add(&mut out, e.full_email);
    }
    out
}

/// A `?cc=` / `?bcc=` style list: de-duplicated valid addresses. Each address's display name is recorded in `names` (last one wins).
pub(crate) fn copy_list(names: &mut Vec<(String, String)>, value: Option<&str>) -> Vec<String> {
    let mut set = Vec::new();
    for e in valid_emails(parse_emails(value, true)) {
        set_add(&mut set, e.full_email.clone());
        names.retain(|(k, _)| *k != e.full_email);
        names.push((e.full_email, e.name));
    }
    set
}

pub(crate) fn text_to_html(body: &str) -> String {
    crate::convert::text_to_html(body)
}

pub(crate) fn html_to_text(body: &str) -> String {
    crate::convert::html_to_text(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_to_text_examples() {
        assert_eq!(html_to_text("Mercurio Body"), "Mercurio Body");
        assert_eq!(html_to_text("  a  b \n c\n\nd  "), "a b c d");
        assert_eq!(html_to_text("<b>x</b> y<br/>z"), "x y\nz");
        assert_eq!(html_to_text("a &amp; b"), "a & b");
        assert_eq!(html_to_text("<p>one</p><p>two</p>"), "one\n\ntwo");
        assert_eq!(html_to_text("<ul><li>a</li><li>b</li></ul>"), "- a\n- b");
        assert_eq!(html_to_text("<style>x{}</style>keep"), "keep");
        assert_eq!(html_to_text("a < b"), "a < b");
        assert_eq!(html_to_text("x<hr>y"), "x\n\n---\n\ny");
        assert_eq!(html_to_text("<pre>a\n  b</pre>c"), "a\n  b\n\nc");
        assert_eq!(html_to_text("<blockquote>q</blockquote>"), "q");
        #[cfg(feature = "html")]
        assert_eq!(html_to_text("&#65;&#x42;&copy;"), "AB©");
        #[cfg(not(feature = "html"))]
        assert_eq!(html_to_text("&#65;&#x42;&copy;"), "AB&copy;");
    }

    #[test]
    fn text_to_html_escapes() {
        assert_eq!(text_to_html("a <b>\nc d"), "a&nbsp;&lt;b&gt;<br/>c&nbsp;d");
    }
}
