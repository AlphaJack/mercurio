//! Remote syslog over UDP (`rsyslog://`): syslog messages to a remote host.
//!
//! Payload: `<PRI>- {pid} {message}` (or `<PRI>- {message}` without `logpid`).
//!
//! # Differences with Apprise
//!
//! - Apprise computes PRI as `level + facility * 8` with already shifted facility constants (`user.info` becomes `<70>`), while mercurio sends the RFC 5424 value (`<14>`). *intentional*

use super::_sockets::{syslog_facility, syslog_level};
use crate::service::{Context, Notify, Param, ServiceDef};
use crate::transport::{Datagram, DatagramTarget};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "rsyslog",
    name: "Remote Syslog",
    schemes: &["rsyslog"],
    service_url: "https://tools.ietf.org/html/rfc5424",
    parse,
    templates: &[
        "{schema}://{host}",
        "{schema}://{host}:{port}",
        "{schema}://{host}/{facility}",
        "{schema}://{host}:{port}/{facility}",
    ],
    tokens: &[
        Param::new("facility", "Facility").choice(&["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"]).default("user").required(),
        Param::new("host", "Hostname").required(),
        Param::new("port", "Port").port().default("514"),
    ],
    params: &[
        Param::sets("facility", &["facility"]),
        Param::new("logpid", "Log PID").bool(true),
    ],
    ..ServiceDef::DEFAULTS
};

const DEFAULT_PORT: u16 = 514;

#[derive(Debug)]
struct RSyslog {
    host: String,
    port: u16,
    facility: u32,
    log_pid: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let tokens = u.path_segments();
    let mut facility = tokens.last().map(|t| t.to_lowercase());
    if let Some(f) = u.param_nonempty("facility") {
        facility = Some(f.to_lowercase());
    }
    let facility = syslog_facility(facility.as_deref()).map_err(|e| SERVICE.err(e))?;
    Ok(Box::new(RSyslog {
        host: u.host(),
        port: u.port.filter(|p| *p != 0).unwrap_or(DEFAULT_PORT),
        facility,
        log_pid: SERVICE.flag(u, "logpid"),
    }))
}

/// The UDP payload for one message.
pub fn payload(pri: u32, pid: Option<u32>, body: &str) -> String {
    match pid {
        Some(pid) => format!("<{pri}>- {pid} {body}"),
        None => format!("<{pri}>- {body}"),
    }
}

impl Notify for RSyslog {
    fn plan(&self, msg: &Prepared<'_>, _ctx: &Context<'_>) -> Plan {
        let body = if msg.title.is_empty() { msg.body.to_string() } else { format!("{}: {}", msg.title, msg.body) };
        let pri = self.facility + syslog_level(msg.kind);
        let data = payload(pri, self.log_pid.then(std::process::id), &body);
        Plan::Datagram(Datagram {
            target: DatagramTarget::Udp { host: self.host.clone(), port: self.port },
            payload: data.into_bytes(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_format() {
        assert_eq!(payload(14, Some(123), "test"), "<14>- 123 test");
        assert_eq!(payload(190, None, "x"), "<190>- x");
    }

    #[test]
    fn rfc5424_priority() {
        // local7.crit = 23 * 8 + 2
        assert_eq!(184 + syslog_level(crate::NotifyType::Failure), 186);
    }
}
