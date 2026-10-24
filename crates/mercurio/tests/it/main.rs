//! Integration tests, compiled as one binary.
//!
//! Fixtures under `tests/fixtures/` are frozen expected output: `services/<id>.json` (requests per service URL; the cross-language conformance suite) and `config.json`.

#![expect(clippy::unwrap_used, clippy::panic, reason = "test code fails loudly")]
// Only the YAML configuration tests call `expect`.
#![cfg_attr(feature = "config-yaml", expect(clippy::expect_used, reason = "test code fails loudly"))]
#![expect(clippy::disallowed_methods, reason = "tests set up real files and sockets")]

#[cfg(feature = "config-yaml")]
mod config;
mod description;
mod fuzz;
mod loopback;
mod params;
// Each module drives these services' wire protocols.
#[cfg(all(feature = "service-email", feature = "service-irc", feature = "service-mqtt", feature = "service-rsyslog"))]
mod protocols;
mod regex_engines;
#[cfg(all(feature = "service-email-pgp", feature = "service-xmpp"))]
mod scripted;
// The snapshots record Markdown rendered by each service.
#[cfg(feature = "markdown")]
mod services;
