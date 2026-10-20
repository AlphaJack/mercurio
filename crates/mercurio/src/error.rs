use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Every failure mercurio reports.
///
/// Messages never contain secrets: services build them from redacted values.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The URL could not be parsed at all.
    InvalidUrl(String),
    /// No compiled-in service handles this scheme.
    UnknownScheme(String),
    /// The URL parsed, but the service rejected its configuration.
    Config {
        /// Display name of the service, e.g. `"Telegram"`.
        service: &'static str,
        /// What is wrong with the URL.
        reason: String,
    },
    /// The message itself cannot be delivered (e.g. empty body).
    Message(String),
    /// Network, TLS, DNS or timeout failure before the request was sent.
    Transport(String),
    /// The connection failed after the request (or part of it) was sent, so the service may have acted on it: a read timeout, a reset while waiting for the response, a malformed response.
    Unconfirmed(String),
    /// The remote answered, but not with success.
    Http {
        /// HTTP status code.
        status: u16,
        /// Reason text from the status line or the response body.
        reason: String,
    },
    /// The remote asked to slow down (HTTP 429; HTTP 503 with `Retry-After`). Built by [`crate::Response::http_error`] when `Retry-After` is valid; a 429 without it stays [`Error::Http`].
    RateLimited {
        /// HTTP status code (429 or 503).
        status: u16,
        /// Reason text from the status line or the response body.
        reason: String,
        /// How long the service asked to wait, from `Retry-After`.
        retry_after: Option<Duration>,
    },
    /// The remote answered successfully at HTTP level but reported failure.
    Service(String),
    /// The feature is not available in this build or on this platform.
    Unsupported(String),
    /// `source` happened during the named step of a multi-step delivery (e.g. `"login"`). Classification and `Retry-After` come from `source`.
    Context {
        /// Short lowercase step name, e.g. `"upload"`.
        context: String,
        /// The underlying failure.
        source: Box<Error>,
    },
}

impl Error {
    /// A configuration error for `service` (its display name).
    pub fn config(service: &'static str, reason: impl Into<String>) -> Self {
        Error::Config { service, reason: reason.into() }
    }

    /// A failure the service reported in a successful HTTP response.
    pub fn service(reason: impl Into<String>) -> Self {
        Error::Service(reason.into())
    }

    /// A failure before the request was sent (connect, DNS, TLS).
    pub fn transport(reason: impl fmt::Display) -> Self {
        Error::Transport(reason.to_string())
    }

    /// A transport error the service may have acted on (see [`Error::Unconfirmed`]).
    pub fn unconfirmed(reason: impl fmt::Display) -> Self {
        Error::Unconfirmed(reason.to_string())
    }

    /// Name the step that failed: displayed as `"{context}: {self}"`. Classification, status and `Retry-After` are unchanged.
    pub fn context(self, context: impl Into<String>) -> Self {
        Error::Context { context: context.into(), source: Box::new(self) }
    }

    /// The innermost error, below every [`Error::Context`].
    pub fn root(&self) -> &Error {
        if let Error::Context { source, .. } = self { source.root() } else { self }
    }

    /// A transport error caused by a connect or read timeout.
    pub fn is_timeout(&self) -> bool {
        matches!(self.root(), Error::Transport(m) | Error::Unconfirmed(m) if m.starts_with("timed out"))
    }

    /// The HTTP status the remote answered with, if any.
    pub fn status(&self) -> Option<u16> {
        if let Error::Http { status, .. } | Error::RateLimited { status, .. } = self.root() {
            Some(*status)
        } else {
            None
        }
    }

    /// What a retry could achieve; see [`ErrorClass`].
    pub fn class(&self) -> ErrorClass {
        match self {
            Error::Context { source, .. } => source.class(),
            Error::RateLimited { retry_after, .. } => ErrorClass::RateLimited { retry_after: *retry_after },
            Error::Http { status, .. } => ErrorClass::from_status(*status),
            Error::Transport(_) => ErrorClass::Transient,
            Error::Unconfirmed(_) | Error::Service(_) => ErrorClass::Unknown,
            Error::InvalidUrl(_)
            | Error::UnknownScheme(_)
            | Error::Config { .. }
            | Error::Message(_)
            | Error::Unsupported(_) => ErrorClass::InvalidTarget,
        }
    }
}

/// Why a delivery failed, as far as retrying is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorClass {
    /// Too many requests; try again, after `retry_after` when the service said.
    RateLimited {
        /// How long the service asked to wait, when it said.
        retry_after: Option<Duration>,
    },
    /// Nothing was delivered and a later attempt may work: connect, DNS or TLS failures, HTTP 408 and 5xx.
    Transient,
    /// Credentials were rejected (HTTP 401, 403).
    Auth,
    /// The URL, its configuration, the target or the message was rejected (other 4xx, configuration and message errors).
    InvalidTarget,
    /// The service may have accepted the notification: failures after the request was sent, service-reported failures, unexpected statuses.
    Unknown,
}

impl ErrorClass {
    /// Classify an HTTP status that was not accepted as success.
    pub fn from_status(status: u16) -> Self {
        match status {
            429 => ErrorClass::RateLimited { retry_after: None },
            408 | 500..=599 => ErrorClass::Transient,
            401 | 403 => ErrorClass::Auth,
            400..=499 => ErrorClass::InvalidTarget,
            _ => ErrorClass::Unknown,
        }
    }

    /// `true` when repeating the request may succeed without delivering a duplicate: [`ErrorClass::RateLimited`] and [`ErrorClass::Transient`].
    pub fn is_retryable(self) -> bool {
        matches!(self, ErrorClass::RateLimited { .. } | ErrorClass::Transient)
    }

    /// Stable snake_case name, e.g. `"rate_limited"` (used in logs and JSON).
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorClass::RateLimited { .. } => "rate_limited",
            ErrorClass::Transient => "transient",
            ErrorClass::Auth => "auth",
            ErrorClass::InvalidTarget => "invalid_target",
            ErrorClass::Unknown => "unknown",
        }
    }
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse a `Retry-After` value (RFC 9110 10.2.3): delta-seconds or an IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`), relative to `now`. A date in the past is zero. The obsolete RFC 850 and asctime forms are rejected.
pub fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    let value = value.trim();
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        return Some(Duration::from_secs(value.parse().unwrap_or(u64::MAX)));
    }
    let at = parse_imf_fixdate(value)?;
    let now = now.duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    Some(Duration::from_secs(at.saturating_sub(now).max(0) as u64))
}

/// Unix seconds of an IMF-fixdate.
fn parse_imf_fixdate(s: &str) -> Option<i64> {
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let (day_name, rest) = s.split_once(", ")?;
    let parts: Vec<&str> = rest.split(' ').collect();
    let [day, month, year, time, "GMT"] = parts[..] else { return None };
    if !DAYS.contains(&day_name) || day.len() != 2 || year.len() != 4 {
        return None;
    }
    let num = |v: &str| if v.bytes().all(|b| b.is_ascii_digit()) { v.parse::<i64>().ok() } else { None };
    let (day, year) = (num(day)?, num(year)?);
    let month = MONTHS.iter().position(|m| *m == month)? as i64 + 1;
    let hms: Vec<i64> = time.split(':').map(|v| if v.len() == 2 { num(v) } else { None }).collect::<Option<_>>()?;
    let [h, m, sec] = hms[..] else { return None };
    if !(1..=31).contains(&day) || h > 23 || m > 59 || sec > 60 {
        return None;
    }
    Some(crate::time::unix_secs(year, month, day) + h * 3600 + m * 60 + sec)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidUrl(u) => write!(f, "invalid URL: {u}"),
            Error::UnknownScheme(s) => write!(f, "unsupported URL scheme: {s}://"),
            Error::Config { service, reason } => write!(f, "{service}: {reason}"),
            Error::Message(m) => write!(f, "invalid message: {m}"),
            Error::Transport(m) | Error::Unconfirmed(m) => write!(f, "transport error: {m}"),
            Error::Http { status, reason } | Error::RateLimited { status, reason, .. } if reason.is_empty() => {
                write!(f, "HTTP {status} {}", http_reason(*status))
            }
            Error::Http { status, reason } | Error::RateLimited { status, reason, .. } => {
                write!(f, "HTTP {status}: {reason}")
            }
            Error::Service(m) => write!(f, "service error: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
            Error::Context { context, source } => write!(f, "{context}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Error::Context { source, .. } = self { Some(source.as_ref()) } else { None }
    }
}

/// `Result` with [`Error`] as the default error type.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// [`Error::context`] on the error of a [`Result`].
pub trait ResultExt<T> {
    /// Name the step that failed (see [`Error::context`]).
    fn context(self, context: impl Into<String>) -> Result<T>;
}

impl<T> ResultExt<T> for Result<T> {
    fn context(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|e| e.context(context))
    }
}

/// Short canonical phrase for common status codes.
pub fn http_reason(status: u16) -> &'static str {
    match status {
        400 => "Bad Request - Unsupported Parameters.",
        401 => "Verification Failed.",
        403 => "Forbidden",
        404 => "Page not found.",
        405 => "Method not allowed.",
        429 => "Too many requests.",
        500 => "Internal server error.",
        502 => "Bad gateway.",
        503 => "Servers are overloaded.",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes() {
        let http = |status| Error::Http { status, reason: String::new() }.class();
        assert_eq!(http(429), ErrorClass::RateLimited { retry_after: None });
        for s in [408, 500, 502, 503, 504, 599] {
            assert_eq!(http(s), ErrorClass::Transient, "{s}");
        }
        assert_eq!((http(401), http(403)), (ErrorClass::Auth, ErrorClass::Auth));
        for s in [400, 404, 413] {
            assert_eq!(http(s), ErrorClass::InvalidTarget, "{s}");
        }
        assert_eq!((http(204), http(302)), (ErrorClass::Unknown, ErrorClass::Unknown));
        assert_eq!(Error::transport("connection refused").class(), ErrorClass::Transient);
        assert_eq!(Error::unconfirmed("timed out (receive response)").class(), ErrorClass::Unknown);
        assert_eq!(Error::service("chat not found").class(), ErrorClass::Unknown);
        assert_eq!(Error::config("x", "bad").class(), ErrorClass::InvalidTarget);
        let rl = Error::RateLimited { status: 429, reason: "slow".into(), retry_after: Some(Duration::from_secs(3)) };
        assert_eq!(rl.class(), ErrorClass::RateLimited { retry_after: Some(Duration::from_secs(3)) });
        assert_eq!((rl.to_string(), rl.status()), ("HTTP 429: slow".to_string(), Some(429)));
        assert!(Error::unconfirmed("timed out (receive body)").is_timeout());
    }

    #[test]
    fn context_display_and_source() {
        let e = Error::Http { status: 500, reason: "server error".into() }.context("upload");
        assert_eq!(e.to_string(), "upload: HTTP 500: server error");
        let src = std::error::Error::source(&e).expect("source");
        assert_eq!(src.to_string(), "HTTP 500: server error");
        assert!(std::error::Error::source(&Error::service("x")).is_none());
        let r: Result<()> = Err(Error::service("room not found"));
        assert_eq!(r.context("room lookup").unwrap_err().to_string(), "room lookup: service error: room not found");
        assert_eq!(Ok::<_, Error>(1).context("login"), Ok(1));
    }

    #[test]
    fn context_delegates_class() {
        let wait = Some(Duration::from_secs(7));
        let rl = Error::RateLimited { status: 429, reason: "slow".into(), retry_after: wait }.context("send");
        assert_eq!(rl.class(), ErrorClass::RateLimited { retry_after: wait });
        assert!(rl.class().is_retryable());
        assert_eq!(rl.status(), Some(429));
        assert_eq!(Error::Http { status: 401, reason: String::new() }.context("login").class(), ErrorClass::Auth);
        assert_eq!(Error::service("x").context("post").class(), ErrorClass::Unknown);
        assert!(Error::unconfirmed("timed out (receive response)").context("upload").is_timeout());
        let e = rl.clone();
        assert_eq!(e, rl);
    }

    #[test]
    fn context_nesting() {
        let e = Error::transport("connection refused").context("key query").context("e2ee");
        assert_eq!(e.to_string(), "e2ee: key query: transport error: connection refused");
        assert_eq!(e.root(), &Error::transport("connection refused"));
        assert_eq!(e.class(), ErrorClass::Transient);
        let inner = std::error::Error::source(&e).expect("source");
        assert_eq!(inner.to_string(), "key query: transport error: connection refused");
    }

    #[test]
    fn retry_after_values() {
        // Sun, 06 Nov 1994 08:49:37 GMT
        let now = UNIX_EPOCH + Duration::from_secs(784_111_777);
        assert_eq!(parse_retry_after("120", now), Some(Duration::from_secs(120)));
        assert_eq!(parse_retry_after(" 0 ", now), Some(Duration::ZERO));
        assert_eq!(parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", now), Some(Duration::ZERO));
        assert_eq!(parse_retry_after("Sun, 06 Nov 1994 08:51:07 GMT", now), Some(Duration::from_secs(90)));
        assert_eq!(parse_retry_after("Thu, 01 Jan 1970 00:00:00 GMT", now), Some(Duration::ZERO));
        assert_eq!(
            parse_retry_after("Thu, 29 Feb 2024 12:00:00 GMT", UNIX_EPOCH),
            Some(Duration::from_secs(1_709_208_000))
        );
        for bad in [
            "",
            "-5",
            "1.5",
            "soon",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            "Sun, 06 Nov 1994 08:49:37 UTC",
            "Sun, 06 Xyz 1994 08:49:37 GMT",
            "Sun, 6 Nov 1994 08:49:37 GMT",
        ] {
            assert_eq!(parse_retry_after(bad, now), None, "{bad}");
        }
    }
}
