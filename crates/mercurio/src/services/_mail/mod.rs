//! Shared e-mail code: SMTP client, MIME builder and the e-mail engine used by `email` and `deltachat`.

pub(crate) mod email;
pub(crate) mod mime;
#[cfg(any(feature = "service-email-pgp", feature = "service-deltachat-pgp"))]
pub(crate) mod pgp;
pub(crate) mod smtp;
