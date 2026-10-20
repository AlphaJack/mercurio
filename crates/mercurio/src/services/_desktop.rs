//! Helpers shared by desktop notifiers (dbus, glib, gnome, windows, macosx, blink1).

use crate::error::Error;
use crate::transport::{Command, CommandOutput};
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

/// GVariant text-format string literal (`'...'`), as `gdbus call` parses it.
pub fn gvariant_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        match c {
            '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// One `org.freedesktop.Notifications.Notify` call made with `gdbus`.
#[derive(Debug, Clone)]
pub struct DesktopNotify<'a> {
    pub app: &'a str,
    /// `app_icon`: a file the notification daemon shows (SVG works).
    pub icon: Option<&'a crate::IconFile>,
    pub title: &'a str,
    pub body: &'a str,
    pub urgency: u8,
    pub xy: Option<(i64, i64)>,
    pub timeout_ms: u32,
}

/// `gdbus call --session ... Notify app 0 '' title body [] hints timeout`.
pub fn gdbus_notify(n: &DesktopNotify<'_>) -> Command {
    let mut hints = format!("{{'urgency': <byte {}>", n.urgency);
    if let Some((x, y)) = n.xy {
        hints.push_str(&format!(", 'x': <int32 {x}>, 'y': <int32 {y}>"));
    }
    hints.push('}');
    let cmd = Command::new("gdbus").args([
        "call".to_string(),
        "--session".into(),
        "--dest".into(),
        "org.freedesktop.Notifications".into(),
        "--object-path".into(),
        "/org/freedesktop/Notifications".into(),
        "--method".into(),
        "org.freedesktop.Notifications.Notify".into(),
        gvariant_str(n.app),
        "0".into(),
        gvariant_str(n.icon.map_or("", |i| i.path.as_str())),
        gvariant_str(n.title),
        gvariant_str(n.body),
        "@as []".into(),
        hints,
        n.timeout_ms.to_string(),
    ]);
    with_icon(cmd, n.icon)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gvariant_strings_are_escaped() {
        assert_eq!(gvariant_str("it's \\ a\nb"), "'it\\'s \\\\ a\\nb'");
        assert_eq!(gvariant_str("\u{1}é"), "'\\u0001é'");
    }
}
