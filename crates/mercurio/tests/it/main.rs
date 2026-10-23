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
mod protocols;
mod scripted;
// The snapshots record Markdown rendered by each service.
#[cfg(feature = "markdown")]
mod services;
