//! Jellyfin (`jellyfin://`, `jellyfins://`): messages to the active Jellyfin client sessions; same API and engine as Emby (`_emby.rs`).

use crate::Result;
use crate::service::{Notify, Param, ServiceDef};
use crate::url::ParsedUrl;

pub static SERVICE: ServiceDef = ServiceDef {
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
        Param::new("port", "Port").int().default("8096").range(1, 65535),
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
