//! Config IDs: which are valid.

/// Config IDs: 1 to 128 letters, digits, `_` or `-`.
pub(super) fn valid_key(key: &str) -> bool {
    let n = key.chars().count();
    (1..=128).contains(&n) && key.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-')
}
pub(super) const MISSING_KEY: &str = "A configuration ID is required (URL path or X-Apprise-Config-ID header)";
pub(super) const INVALID_KEY_HEADER: &str = "The X-Apprise-Config-ID header provided is invalid";
