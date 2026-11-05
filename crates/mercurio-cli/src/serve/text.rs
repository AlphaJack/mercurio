//! Small helpers on text that several endpoints share.

/// Whether `s` has more than white space: an empty or blank setting counts as unset.
pub(super) fn non_blank<S: AsRef<str>>(s: &S) -> bool {
    !s.as_ref().trim().is_empty()
}
