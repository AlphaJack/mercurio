//! Recipient lists shared by the e-mail services and the SMTP sender: sets in insertion order, and the cc and bcc of each recipient.

/// Insert into an insertion-ordered "set" (Vec) if not already present.
pub(crate) fn set_add(set: &mut Vec<String>, value: String) {
    if !set.contains(&value) {
        set.push(value);
    }
}

/// The addresses of `list` other than `target`.
pub(crate) fn except<'a>(list: &'a [String], target: &'a str) -> impl Iterator<Item = &'a String> + 'a {
    list.iter().filter(move |e| e.as_str() != target)
}

/// The cc addresses not also in bcc.
pub(crate) fn cc_only<'a>(cc: &'a [String], bcc: &'a [String]) -> impl Iterator<Item = &'a String> + 'a {
    cc.iter().filter(move |e| !bcc.contains(e))
}

/// The cc addresses for one `target`: neither in bcc nor the target itself.
pub(crate) fn cc_for<'a>(cc: &'a [String], bcc: &'a [String], target: &'a str) -> impl Iterator<Item = &'a String> + 'a {
    cc_only(cc, bcc).filter(move |e| e.as_str() != target)
}
