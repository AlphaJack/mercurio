//! The Config ID a request names.

use super::super::call::{Call, Fault};
use super::super::key::{INVALID_KEY_HEADER, MISSING_KEY, valid_key};

/// A valid `X-Apprise-Config-ID`, or `400` for an invalid one.
pub(super) fn header_key(call: &Call<'_>, header: Option<&str>) -> Result<Option<String>, Fault> {
    match header.map(str::trim).filter(|h| !h.is_empty()) {
        Some(h) if valid_key(h) => Ok(Some(h.to_owned())),
        Some(_) => Err(call.fail(Fault::new(400, INVALID_KEY_HEADER))),
        None => Ok(None),
    }
}

/// A Config ID in the path: any other value is no route, as apprise-api's URL patterns (`404`).
pub(super) fn path_key<'k>(call: &Call<'_>, key: &'k str) -> Result<&'k str, Fault> {
    if valid_key(key) { Ok(key) } else { Err(call.fail(Fault::new(404, "Not Found"))) }
}

/// The effective Config ID: a valid header wins over the path; `400` without either.
pub(super) fn resolve_key(call: &Call<'_>, header: Option<&str>, path: Option<&str>) -> Result<String, Fault> {
    let path = path.map(|k| path_key(call, k)).transpose()?;
    match (header_key(call, header)?, path) {
        (Some(h), _) => Ok(h),
        (None, Some(p)) => Ok(p.to_owned()),
        (None, None) => Err(call.fail(Fault::new(400, MISSING_KEY))),
    }
}
