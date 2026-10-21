//! Shared e-mail code: SMTP client, MIME builder and the e-mail engine used by `email` and `deltachat`.

pub mod email;
pub mod mime;
#[cfg(any(feature = "service-email-pgp", feature = "service-deltachat-pgp"))]
pub mod pgp;
pub mod smtp;
#[cfg(any(feature = "service-email-pgp", feature = "service-deltachat-pgp"))]
pub mod wkd;
