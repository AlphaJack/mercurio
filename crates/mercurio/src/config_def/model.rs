//! Public configuration types and the parsed form shared by the TEXT and YAML readers.

use crate::asset_def::AssetValue;
use std::sync::Arc;

use super::template::Placeholders;
use crate::error::Error;
use crate::registry::Handler;
use crate::registry::Registry;
use crate::service::ServiceDef;
use crate::tag::Tag;
use crate::target::Target;
use crate::url::ParsedUrl;

/// Largest configuration read (`max_buffer_size`, 128 KiB).
pub(super) const MAX_BUFFER_SIZE: usize = 131072;

/// Configuration syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    /// TEXT format: one URL per line, optionally `tag1, tag2=URL`.
    Text,
    /// YAML format (`version: 1`, `urls:`, `include:`, `template:`, `asset:`).
    Yaml,
}

impl ConfigFormat {
    /// Parse `text` or `yaml` (case-insensitive, surrounding whitespace ignored).
    pub fn parse(s: &str) -> Option<Self> {
        match crate::util::lower_trimmed(s).as_str() {
            "text" => Some(Self::Text),
            "yaml" => Some(Self::Yaml),
            _ => None,
        }
    }

    /// Lower-case name: `"text"` or `"yaml"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Yaml => "yaml",
        }
    }
}

crate::display_as_str!(ConfigFormat);

/// How configurations are loaded.
#[derive(Debug, Clone)]
pub struct ConfigOptions {
    /// Levels of `include` to follow (0, the default, ignores them; the CLI uses 1).
    pub recursion: u32,
    /// Let any source include local files (`insecure_includes`).
    pub insecure_includes: bool,
    /// Honour `template:` sections.
    pub allow_templates: bool,
    /// Force a format instead of detecting it.
    pub format: Option<ConfigFormat>,
    /// Runtime services the entries may use, besides the compiled-in ones.
    pub registry: Registry,
}

impl Default for ConfigOptions {
    fn default() -> Self {
        Self {
            recursion: 0,
            insecure_includes: false,
            allow_templates: true,
            format: None,
            registry: Registry::default(),
        }
    }
}

/// One loaded service: ready to send or waiting for template values.
// Short-lived (moved into `Mercurio` right after loading); boxing the common `Ready` case would only add an allocation per service.
#[expect(clippy::large_enum_variant, reason = "short-lived; boxing `Ready` would add an allocation per service")]
#[derive(Debug)]
pub enum ConfigService {
    /// A service ready to notify.
    Ready(Target),
    /// A templated service waiting for `${NAME}` values.
    Pending(Box<PendingTarget>),
}

impl ConfigService {
    /// Tags of this entry.
    pub fn tags(&self) -> &[Tag] {
        match self {
            ConfigService::Ready(t) => t.tag_set(),
            ConfigService::Pending(p) => &p.tags,
        }
    }
}

/// The result of loading a configuration (and everything it includes).
#[derive(Debug, Default)]
pub struct Config {
    /// Every service loaded, in file order (includes appended where they appear).
    pub services: Vec<ConfigService>,
    /// `asset:` overrides in the order they were read.
    pub asset: Vec<(String, AssetValue)>,
    /// Problems found while loading (skipped lines, bad URLs, ...).
    pub warnings: Vec<String>,
}

/// A configuration entry waiting for `${NAME}` values.
pub struct PendingTarget {
    pub(super) def: &'static ServiceDef,
    /// The closure of a [`crate::CustomScheme`] service.
    pub(super) handler: Option<Arc<Handler>>,
    pub(super) parsed: ParsedUrl,
    pub(super) placeholders: Arc<Placeholders>,
    pub(super) names: Vec<String>,
    /// Tags from the configuration entry.
    pub tags: Vec<Tag>,
    /// Where the entry was read, e.g. `line 3` or `YAML entry #1, item #2`.
    pub location: String,
    pub(super) asset: Vec<(String, AssetValue)>,
}

pub(super) fn cfg_err(reason: impl Into<String>) -> Error {
    Error::Config { service: "configuration", reason: reason.into() }
}

/// One URL from a configuration document, before its service is built.
#[derive(Debug, Clone)]
pub(super) struct RawEntry {
    pub(super) url: String,
    /// Tags as written (group expansion compares raw strings).
    pub(super) tags: Vec<String>,
    pub(super) location: String,
}

#[derive(Debug, Default)]
pub(super) struct Parsed {
    pub(super) entries: Vec<RawEntry>,
    pub(super) includes: Vec<String>,
    pub(super) asset: Vec<(String, AssetValue)>,
    pub(super) warnings: Vec<String>,
    pub(super) placeholders: Option<Placeholders>,
}
