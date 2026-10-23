//! The regex engine: `regex` with the `regex-unicode` feature, `regex-lite` without it. Code names `crate::re::*`, never either crate, so both builds use only what both crates provide.
//!
//! `regex-lite` matches `\s`, `\d`, `\w` and case folding in ASCII only (`tests/it/regex_engines.rs` lists where the two differ).

#[cfg(feature = "regex-unicode")]
pub use regex::{Captures, NoExpand, Regex, escape};
#[cfg(not(feature = "regex-unicode"))]
pub use regex_lite::{Captures, NoExpand, Regex, escape};
