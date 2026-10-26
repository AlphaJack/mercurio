//! D-Bus (`dbus://`, `kde://`, `qt://`): desktop notifications through `org.freedesktop.Notifications` on the session bus.
//!
//! Mercurio has no D-Bus dependency and runs no program: it connects to the session bus itself (`DBUS_SESSION_BUS_ADDRESS`, else `$XDG_RUNTIME_DIR/bus`; `unix:path=` and Linux `unix:abstract=` addresses), authenticates with `EXTERNAL` and calls `Notify` with these arguments: app name, replaces-id `0`, the icon (`image_path_mask`, the app's `image_bytes`, else the bundled SVG; empty with `?image=no`), title, body, no actions, `{urgency: byte, x: int32, y: int32}` hints and a 13 s timeout.
//!
//! # Differences with Apprise
//!
//! - `kde://` / `qt://` select a Qt/GLib main loop in Apprise, while in mercurio all schemes behave alike.
//! - Apprise attaches the icon as `icon_data` pixels (GdkPixbuf), while mercurio passes the icon file as `app_icon`.

use super::_desktop::{DesktopNotify, notify, urgency, xy};
use crate::service::{Context, Limits, Notify, Param, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "dbus",
    name: "DBus Notification",
    schemes: &["qt", "kde", "dbus"],
    service_url: "http://www.freedesktop.org/Software/dbus/",
    parse,
    limits: Limits { title_maxlen: 250, body_maxlen: 32768, body_max_line_count: 10 },
    templates: &[
        "{schema}://",
    ],
    params: &[
        Param::new("image", "Include Image").bool(true),
        Param::new("urgency", "Urgency").choice(&["0", "1", "2"]).default("1").aliases(&["priority"]),
        Param::new("x", "X-Axis").int().min(0),
        Param::new("y", "Y-Axis").int().min(0),
    ],
    ..ServiceDef::DEFAULTS
};

const TIMEOUT_MS: i32 = 13000;

#[derive(Debug)]
struct DBus {
    urgency: u8,
    xy: Option<(i64, i64)>,
    include_image: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    Ok(Box::new(DBus { urgency: urgency(u), xy: xy(u, &SERVICE)?, include_image: SERVICE.flag_strict(u, "image") }))
}

impl Notify for DBus {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let (title, body) = if msg.title.is_empty() { (msg.body, "") } else { (msg.title, msg.body) };
        let icon = if self.include_image { ctx.asset.icon_file(msg.kind, "svg") } else { None };
        notify(
            &DesktopNotify {
                app: ctx.app_id(),
                icon: icon.as_ref(),
                title,
                body,
                urgency: self.urgency,
                xy: self.xy,
                timeout_ms: TIMEOUT_MS,
            },
            ctx.env().as_ref(),
        )
    }
}
