//! The Config ID a request names.

use super::super::http::{Reply, Req};
use super::super::key::{INVALID_KEY_HEADER, MISSING_KEY, valid_key};

/// The effective Config ID: a valid `Config-ID` header wins over the path.
pub(super) fn resolve_key(req: &Req, path_key: Option<&str>) -> Result<String, Reply> {
    match req.x_header("Config-ID") {
        Some(h) if valid_key(h) => Ok(h.to_owned()),
        Some(_) => Err(Reply::error(req, 400, INVALID_KEY_HEADER)),
        None => path_key.map(str::to_owned).ok_or_else(|| Reply::error(req, 400, MISSING_KEY)),
    }
}
