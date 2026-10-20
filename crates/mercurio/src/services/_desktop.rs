//! Helpers shared by desktop notifiers (dbus, glib, gnome, windows, macosx, blink1).

use std::path::PathBuf;

use super::_dbus::{Call, Hint, Notification, session_bus};
use crate::env::Env;
use crate::error::Error;
use crate::transport::{Command, CommandOutput, FileOp, FileOutput};
use crate::url::ParsedUrl;
use crate::util::parse_int;
use crate::{Plan, Result};

/// Urgency levels shared by the D-Bus style notifiers.
pub const URGENCY_LOW: u8 = 0;
pub const URGENCY_NORMAL: u8 = 1;
pub const URGENCY_HIGH: u8 = 2;

/// `DBUS_URGENCY_MAP` / `GLIB_URGENCY_MAP` / `GNOME_URGENCY_MAP`, checked in order as prefixes of the lowercased urgency.
const URGENCY_MAP: &[(&str, u8)] = &[
    ("l", URGENCY_LOW),
    ("m", URGENCY_LOW),
    ("n", URGENCY_NORMAL),
    ("h", URGENCY_HIGH),
    ("e", URGENCY_HIGH),
    ("0", URGENCY_LOW),
    ("1", URGENCY_NORMAL),
    ("2", URGENCY_HIGH),
];

/// `?urgency=` (falling back to `?priority=`).
pub fn urgency(u: &ParsedUrl) -> u8 {
    let raw = u.text("urgency").or_else(|| u.text("priority"));
    match raw {
        None => URGENCY_NORMAL,
        Some(v) => {
            let v = v.to_lowercase();
            URGENCY_MAP.iter().find(|(k, _)| v.starts_with(k)).map(|(_, n)| *n).unwrap_or(URGENCY_NORMAL)
        }
    }
}

/// `?x=` / `?y=` screen coordinates (D-Bus hints). Both must be integers when either one is given.
pub fn xy(u: &ParsedUrl, service: &'static crate::ServiceDef) -> Result<Option<(i64, i64)>> {
    let x = service.text(u, "x");
    let y = service.text(u, "y");
    if x.as_deref().is_none_or(str::is_empty) && y.as_deref().is_none_or(str::is_empty) {
        return Ok(None);
    }
    match (x.as_deref().and_then(parse_int), y.as_deref().and_then(parse_int)) {
        (Some(x), Some(y)) => Ok(Some((x, y))),
        _ => Err(service.err("the x,y coordinates specified are invalid")),
    }
}

/// One `org.freedesktop.Notifications.Notify` call on the session bus.
#[derive(Debug, Clone)]
pub struct DesktopNotify<'a> {
    pub app: &'a str,
    /// `app_icon`: a file the notification daemon shows (SVG works).
    pub icon: Option<&'a crate::IconFile>,
    pub title: &'a str,
    pub body: &'a str,
    pub urgency: u8,
    pub xy: Option<(i64, i64)>,
    /// Milliseconds; `-1` lets the daemon decide.
    pub timeout_ms: i32,
}

/// Write the bundled icon (unless it is already there), then call `Notify` (replaces-id `0`, no actions, `{urgency: byte, x: int32, y: int32}` hints) over a native D-Bus connection.
pub fn notify(n: &DesktopNotify<'_>, env: &dyn Env) -> Plan {
    let ep = match session_bus(env) {
        Ok(ep) => ep,
        Err(e) => return Plan::Fail(e),
    };
    let mut hints = vec![("urgency", Hint::Byte(n.urgency))];
    if let Some((x, y)) = n.xy {
        let (Ok(x), Ok(y)) = (i32::try_from(x), i32::try_from(y)) else {
            return Plan::Fail(Error::Service("the x,y coordinates specified are out of range".into()));
        };
        hints.extend([("x", Hint::Int32(x)), ("y", Hint::Int32(y))]);
    }
    let call = Notification {
        app: n.app.to_string(),
        icon: n.icon.map_or_else(String::new, |i| i.path.clone()),
        summary: n.title.to_string(),
        body: n.body.to_string(),
        hints,
        timeout: n.timeout_ms,
    }
    .call();
    Plan::chain([
        write_icon(n.icon),
        Plan::socket(ep, move |conn, transport| Box::pin(crate::machine::drive(Call::new(call), conn, transport))),
    ])
}

/// Write the bundled icon to its path unless it already holds it: what [`with_icon`] has the transport do for a command.
fn write_icon(icon: Option<&crate::IconFile>) -> Plan {
    let Some((path, bytes)) = icon.and_then(|i| i.bundled.map(|b| (PathBuf::from(&i.path), b))) else {
        return Plan::Done;
    };
    Plan::file(FileOp::Read { path: path.clone(), max: 0 }, move |read| {
        if matches!(&read, Ok(FileOutput::Bytes(b)) if b.as_slice() == bytes) {
            return Plan::Done;
        }
        Plan::file(FileOp::WriteAtomic { path, data: bytes.to_vec(), private: false }, |res| match res {
            Ok(_) => Plan::Done,
            Err(e) => Plan::Fail(e),
        })
    })
}

/// `cmd` plus the bundled icon file it reads, when the icon is the bundled one.
pub fn with_icon(cmd: Command, icon: Option<&crate::IconFile>) -> Command {
    match icon.and_then(|i| i.bundled.map(|b| (i.path.clone(), b))) {
        Some((path, bytes)) => cmd.file(path, bytes),
        None => cmd,
    }
}

/// Fail unless the program exited with status 0.
pub fn check_exit(what: &'static str, res: Result<CommandOutput>) -> Plan {
    match res {
        Ok(out) if out.status == 0 => Plan::Done,
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let detail = stderr.trim();
            let detail: String = detail.chars().take(200).collect();
            Plan::Fail(Error::Service(if detail.is_empty() {
                format!("{what} exited with status {}", out.status)
            } else {
                format!("{what} exited with status {}: {detail}", out.status)
            }))
        }
        Err(e) => Plan::Fail(e),
    }
}
