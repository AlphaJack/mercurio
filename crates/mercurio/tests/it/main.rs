//! Integration tests, compiled as one binary.
//!
//! Fixtures under `tests/fixtures/` are frozen expected output: `services/<id>.json` (requests per service URL; the cross-language conformance suite) and `config.json`.

#![expect(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code fails loudly")]

mod config;
mod description;
mod fuzz;
mod loopback;
mod params;
mod protocols;
mod scripted;
mod services;
