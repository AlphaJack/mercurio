//! The comparators of the services that record events instead of HTTP requests.

use super::events::Comparator;

const BUILTIN: &[Comparator] = &[
    super::socket::SMTP,
    super::socket::SMPP,
    super::stream::LINES,
    super::stream::MQTT,
    super::stream::SYSLOG,
    super::stream::RSYSLOG,
    super::desktop::MACOSX,
    super::desktop::DBUS,
    super::desktop::GNOME,
    super::desktop::WINDOWS,
    super::desktop::BLINK1,
    super::desktop::XMPP,
];

/// The comparator for a fixture's `service`, if it records events.
pub(super) fn comparator(service: &str) -> Option<&'static Comparator> {
    BUILTIN.iter().find(|c| c.services.contains(&service))
}
