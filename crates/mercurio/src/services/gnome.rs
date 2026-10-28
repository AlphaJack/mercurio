//! GNOME (`gnome://`): desktop notifications as libnotify sends them.
//!
//! Mercurio connects to the session bus itself (`DBUS_SESSION_BUS_ADDRESS`, else `$XDG_RUNTIME_DIR/bus`; `unix:path=` and Linux `unix:abstract=` addresses), authenticates with `EXTERNAL` and calls `Notify` the way libnotify's `Notification.new(body)` does: app id, replaces-id `0`, the icon file (empty with `?image=no`), the body as the summary (the title is merged into it), no body, no actions, `{urgency: byte}` and the daemon's default timeout (`-1`).
//!
//! # Differences with Apprise
//!
//! - Apprise uses libnotify bindings, while mercurio speaks D-Bus itself.
//! - libnotify also sends a `sender-pid` hint and the icon as `image-data` pixels, while mercurio passes the icon file as `app_icon`.

use super::_desktop::{DesktopNotify, notify, urgency};
use crate::service::{Context, Limits, Notify, Param, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "gnome",
    name: "Gnome Notification",
    schemes: &["gnome"],
    service_url: "https://www.gnome.org/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 32768, body_max_line_count: 10 },
    templates: &[
        "{schema}://",
    ],
    params: &[
        Param::new("image", "Include Image").bool(true),
        Param::new("urgency", "Urgency").choice(&["0", "1", "2"]).default("1").aliases(&["priority"]),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Gnome {
    urgency: u8,
    include_image: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    Ok(Box::new(Gnome { urgency: urgency(u), include_image: SERVICE.flag_strict(u, "image") }))
}

impl Notify for Gnome {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let icon = if self.include_image { ctx.asset.icon_file(msg.kind, "svg") } else { None };
        // libnotify's `Notification.new(body)`: the merged title and body is the summary; the daemon picks the timeout.
        notify(
            &DesktopNotify {
                app: ctx.app_id(),
                icon: icon.as_ref(),
                title: msg.body,
                body: "",
                urgency: self.urgency,
                xy: None,
                timeout_ms: -1,
            },
            ctx.env().as_ref(),
        )
    }
}
