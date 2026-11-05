//! D-Bus (`dbus://`, `kde://`, `qt://`): desktop notifications through `org.freedesktop.Notifications` on the session bus.
//!
//! Mercurio has no D-Bus dependency and runs no program: it connects to the session bus itself (`DBUS_SESSION_BUS_ADDRESS`, else `$XDG_RUNTIME_DIR/bus`; `unix:path=` and Linux `unix:abstract=` addresses), authenticates with `EXTERNAL` and calls `Notify` with these arguments: app name, replaces-id `0`, the icon (`image_path_mask`, else the app's `image_bytes` or the bundled SVG, written to `$XDG_RUNTIME_DIR/mercurio`, `$XDG_CACHE_HOME/mercurio` or `~/.cache/mercurio`; empty with `?image=no`), title, body, no actions, `{urgency: byte, x: int32, y: int32}` hints and a 13 s timeout.
//!
//! # Differences with Apprise
//!
//! - `kde://` / `qt://` select a Qt/GLib main loop in Apprise, while in mercurio all schemes behave alike.
//! - Apprise attaches the icon as `icon_data` pixels (GdkPixbuf), while mercurio passes the icon file as `app_icon`.

use super::_desktop::{URGENCY, parse_bus};
use crate::service::{Limits, Notify, Param, ServiceDef};
use crate::url::ParsedUrl;
use crate::Result;

pub(crate) static SERVICE: ServiceDef = ServiceDef {
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
        URGENCY,
        Param::new("x", "X-Axis").int().min(0),
        Param::new("y", "Y-Axis").int().min(0),
    ],
    ..ServiceDef::DEFAULTS
};

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    parse_bus(u, &SERVICE)
}
