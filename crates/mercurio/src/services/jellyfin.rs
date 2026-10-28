//! Jellyfin (`jellyfin://`, `jellyfins://`): messages to the active Jellyfin client sessions; same API and code as Emby.

use crate::Result;
use crate::service::{Notify, Param, ServiceDef};
use crate::url::ParsedUrl;

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "jellyfin",
    name: "Jellyfin",
    schemes: &["jellyfin", "jellyfins"],
    service_url: "https://jellyfin.org/",
    parse,
    templates: &[
        "{schema}://{host}",
        "{schema}://{host}:{port}",
        "{schema}://{user}:{password}@{host}",
        "{schema}://{user}:{password}@{host}:{port}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("password", "Password").secret(),
        Param::new("port", "Port").port().default("8096"),
        Param::new("user", "Username"),
    ],
    params: &[
        Param::new("modal", "Modal").bool(false),
    ],
    ..ServiceDef::DEFAULTS
};

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    super::_emby::parse_with(u, &SERVICE)
}
