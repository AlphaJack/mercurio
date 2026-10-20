//! Emby (`emby://`, `embys://`): messages to the active Emby client sessions (engine in `_emby.rs`, shared with Jellyfin).
//!
//! The login session lives as long as the parsed URL (a non-persistent store entry): later sends only look up the client sessions and post. [`Target::close`](crate::Target::close) logs out.

use crate::Result;
use crate::service::{Notify, Param, ServiceDef};
use crate::url::ParsedUrl;

pub static SERVICE: ServiceDef = ServiceDef {
    id: "emby",
    name: "Emby",
    schemes: &["emby", "embys"],
    service_url: "https://emby.media/",
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
