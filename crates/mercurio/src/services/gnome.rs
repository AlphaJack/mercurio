//! GNOME (`gnome://`): desktop notifications through libnotify.
//!
//! Mercurio runs libnotify's command-line client: `notify-send --app-name=<app_id> --urgency=<level> --icon=<file> -- <body>` (the title is merged into the body).
//!
//! # Differences with Apprise
//!
//! - Apprise uses libnotify bindings -> mercurio runs `notify-send`. *todo*

use super::_desktop::{check_exit, urgency, with_icon, URGENCY_HIGH, URGENCY_LOW};
use crate::service::{Context, Limits, Notify, Param, ServiceDef};
use crate::transport::Command;
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
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

/// libnotify urgency names (`NOTIFY_URGENCY_*`).
fn urgency_name(u: u8) -> &'static str {
    match u {
        URGENCY_LOW => "low",
        URGENCY_HIGH => "critical",
        _ => "normal",
    }
}

impl Notify for Gnome {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let icon = if self.include_image { ctx.asset.icon_file(msg.kind, "svg") } else { None };
        let mut args = vec![format!("--app-name={}", ctx.app_id()), format!("--urgency={}", urgency_name(self.urgency))];
        if let Some(i) = &icon {
            args.push(format!("--icon={}", i.path));
        }
        args.extend(["--".to_string(), msg.body.to_string()]);
        let cmd = with_icon(Command::new("notify-send").args(args), icon.as_ref());
        Plan::command(cmd, |res| check_exit("notify-send", res))
    }
}
