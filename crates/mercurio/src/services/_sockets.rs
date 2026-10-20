//! Helpers shared by the raw protocol services: syslog facilities and levels; a small writer for socket sessions.

use crate::NotifyType;
use crate::error::{Error, Result};
use crate::transport::AsyncConn;

/// Syslog facilities in lookup order (prefix lookups depend on it). Values are the shifted facility codes (`LOG_USER = 8`).
pub const SYSLOG_FACILITIES: &[(&str, u32)] = &[
    ("kern", 0),
    ("user", 8),
    ("mail", 16),
    ("daemon", 24),
    ("auth", 32),
    ("syslog", 40),
    ("lpr", 48),
    ("news", 56),
    ("uucp", 64),
    ("cron", 72),
    ("local0", 128),
    ("local1", 136),
    ("local2", 144),
    ("local3", 152),
    ("local4", 160),
    ("local5", 168),
    ("local6", 176),
    ("local7", 184),
];

/// Default facility (`user`).
pub const SYSLOG_DEFAULT_FACILITY: u32 = 8;

/// Resolve a syslog facility name: exact name, else the first name starting with it, else invalid. `None` means "use the default".
pub fn syslog_facility(name: Option<&str>) -> std::result::Result<u32, String> {
    let Some(name) = name.filter(|n| !n.is_empty()) else {
        return Ok(SYSLOG_DEFAULT_FACILITY);
    };
    let name = name.to_lowercase();
    SYSLOG_FACILITIES
        .iter()
        .find(|(k, _)| *k == name)
        .or_else(|| SYSLOG_FACILITIES.iter().find(|(k, _)| k.starts_with(&name)))
        .map(|(_, v)| *v)
        .ok_or_else(|| format!("An invalid syslog facility ({name}) was specified."))
}

/// Notify type -> syslog severity.
pub fn syslog_level(kind: NotifyType) -> u32 {
    match kind {
        NotifyType::Info => 6,
        NotifyType::Success => 5,
        NotifyType::Warning => 4,
        NotifyType::Failure => 2,
    }
}

/// Write and flush `data`; failures are transport errors.
pub async fn send(conn: &mut dyn AsyncConn, data: &[u8]) -> Result<()> {
    conn.write_all(data).await.map_err(Error::transport)?;
    conn.flush().await.map_err(Error::transport)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facility_lookup() {
        assert_eq!(syslog_facility(None), Ok(8));
        assert_eq!(syslog_facility(Some("")), Ok(8));
        assert_eq!(syslog_facility(Some("LOCAL5")), Ok(168));
        assert_eq!(syslog_facility(Some("d")), Ok(24));
        assert_eq!(syslog_facility(Some("l")), Ok(48));
        assert_eq!(syslog_facility(Some("local")), Ok(128));
        assert!(syslog_facility(Some("invalid")).is_err());
    }

    #[test]
    fn levels() {
        assert_eq!(syslog_level(NotifyType::Info), 6);
        assert_eq!(syslog_level(NotifyType::Failure), 2);
    }
}
