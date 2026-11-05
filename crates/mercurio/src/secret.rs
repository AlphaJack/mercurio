//! Secrets kept out of logs and `Debug` output.

use std::fmt;

/// A string that never shows up in `Debug` or `Display` output.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Secret(String);

impl Secret {
    /// Wrap a secret value.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// The wrapped value. Use only when building requests.
    pub fn expose(&self) -> &str {
        &self.0
    }
    /// `true` for an empty value.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"***\"")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}
