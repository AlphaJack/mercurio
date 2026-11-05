//! The regex engine: `regex` with the `regex-unicode` feature, `regex-lite` without it. Code names `crate::re::*`, never either crate, so both builds use only what both crates provide.
//!
//! `regex-lite` matches `\s`, `\d`, `\w` and case folding in ASCII only (`tests/it/regex_engines.rs` lists where the two differ).

#[cfg(feature = "regex-unicode")]
pub(crate) use regex::{Captures, Match, NoExpand, Regex, escape};
#[cfg(not(feature = "regex-unicode"))]
pub(crate) use regex_lite::{Captures, Match, NoExpand, Regex, escape};

/// Compile a regex once and return a `&'static Regex`.
#[macro_export]
#[doc(hidden)]
macro_rules! regex {
    ($re:expr $(,)?) => {{
        static RE: ::std::sync::LazyLock<$crate::__private::Regex> =
            ::std::sync::LazyLock::new(|| $crate::__private::Regex::new($re).expect("valid regex"));
        &*RE
    }};
}
