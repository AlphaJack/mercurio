//! Local syslog (`syslog://`): writes messages to the local syslog.
//!
//! Writes the BSD-style datagram libc `syslog` would (`<PRI>Mmm dd hh:mm:ss ident[pid]: msg`) to the local syslog socket (`/var/run/syslog` on macOS, `/dev/log` elsewhere).
//!
//! # Differences with Apprise
//!
//! - `logperror` copies the line to stderr like `LOG_PERROR`. *intentional*

use super::_sockets::{syslog_facility, syslog_level};
use crate::service::{Context, Notify, Param, ServiceDef};
use crate::transport::{Datagram, DatagramTarget};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "syslog",
    name: "Syslog",
    schemes: &["syslog"],
    service_url: "https://tools.ietf.org/html/rfc5424",
    parse,
    templates: &[
        "{schema}://",
        "{schema}://{facility}",
    ],
    tokens: &[
        Param::new("facility", "Facility").choice(&["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"]).default("user"),
    ],
    params: &[
        Param::sets("facility", &["facility"]),
        Param::new("logperror", "Log to STDERR").bool(false),
        Param::new("logpid", "Log PID").bool(true),
    ],
    ..ServiceDef::DEFAULTS
};

/// Local syslog socket path.
pub const SOCKET_PATH: &str = if cfg!(target_os = "macos") { "/var/run/syslog" } else { "/dev/log" };

#[derive(Debug)]
struct Syslog {
    facility: u32,
    log_pid: bool,
    log_perror: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut tokens = Vec::new();
    let host = u.host();
    if !u.host.is_empty() {
        tokens.push(host);
    }
    tokens.extend(u.path_segments());
    let mut facility = tokens.last().map(|t| t.to_lowercase());
    if let Some(f) = u.param_nonempty("facility") {
        facility = Some(f.to_lowercase());
    }
    let facility = syslog_facility(facility.as_deref()).map_err(|e| SERVICE.err(e))?;
    Ok(Box::new(Syslog {
        facility,
        log_pid: SERVICE.flag(u, "logpid"),
        log_perror: SERVICE.flag(u, "logperror"),
    }))
}

/// `Mmm dd hh:mm:ss` in `tz` (RFC 3164 timestamp, day space-padded; libc writes local time).
pub fn rfc3164_timestamp(secs: u64, tz: &jiff::tz::TimeZone) -> String {
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let (mo, d, h, mi, s) = crate::time::local_parts(secs, tz);
    format!("{} {d:>2} {h:02}:{mi:02}:{s:02}", MONTHS[(mo as usize).saturating_sub(1) % 12])
}

/// The datagram libc `syslog(3)` sends for one message.
pub fn format_line(pri: u32, secs: u64, tz: &jiff::tz::TimeZone, ident: &str, pid: Option<u32>, message: &str) -> String {
    let pid = pid.map(|p| format!("[{p}]")).unwrap_or_default();
    format!("<{pri}>{} {ident}{pid}: {message}", rfc3164_timestamp(secs, tz))
}

impl Notify for Syslog {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let body = if msg.title.is_empty() { msg.body.to_string() } else { format!("{}: {}", msg.title, msg.body) };
        let pri = self.facility | syslog_level(msg.kind);
        let ident = ctx.app_id().to_string();
        let pid = std::process::id();
        let log_pid = self.log_pid;
        let log_perror = self.log_perror;
        let tz = ctx.time_zone();
        Plan::defer(move || {
            let line = format_line(pri, crate::time::unix_time(), &tz, &ident, log_pid.then_some(pid), &body);
            if log_perror {
                let tag = if log_pid { format!("{ident}[{pid}]") } else { ident.clone() };
                eprintln!("{tag}: {body}");
            }
            Plan::Datagram(Datagram { target: DatagramTarget::Unix(SOCKET_PATH.into()), payload: line.into_bytes() })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_is_facility_or_level() {
        // user.info, local5.crit, kern.notice
        assert_eq!(8 | syslog_level(crate::NotifyType::Info), 14);
        assert_eq!(168 | syslog_level(crate::NotifyType::Failure), 170);
        assert_eq!(syslog_level(crate::NotifyType::Success), 5);
    }

    #[test]
    fn line_format() {
        // 2024-03-05 07:08:09 UTC
        let utc = jiff::tz::TimeZone::UTC;
        assert_eq!(rfc3164_timestamp(1_709_622_489, &utc), "Mar  5 07:08:09");
        assert_eq!(format_line(14, 1_709_622_489, &utc, "Mercurio", Some(42), "t: b"), "<14>Mar  5 07:08:09 Mercurio[42]: t: b");
        assert_eq!(format_line(13, 1_709_622_489, &utc, "x", None, "m"), "<13>Mar  5 07:08:09 x: m");
        // libc writes local time: the URL's ?tz= or the machine's zone.
        let paris = crate::time::zone("Europe/Paris").unwrap();
        assert_eq!(rfc3164_timestamp(1_709_622_489, &paris), "Mar  5 08:08:09");
    }
}
