//! The Config ID a request names.

use super::super::call::{Call, Fault};
use super::super::key::MISSING_KEY;

/// The effective Config ID: the header wins over the path; `400` without either. The spec has checked both.
pub(super) fn resolve_key(call: &Call<'_>, header: Option<&str>, path: Option<&str>) -> Result<String, Fault> {
    header.or(path).map(str::to_owned).ok_or_else(|| call.fail(Fault::new(400, MISSING_KEY)))
}
