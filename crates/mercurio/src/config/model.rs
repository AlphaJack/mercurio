//! Public configuration types and the parsed form shared by the TEXT and YAML readers.

use std::fmt;

use super::assets::apply_asset_value;
use super::loader::{Loader, Source, SourceKind};
use super::pending::PendingTarget;
use super::spec::ASSET_KEYS;
use super::template::Placeholders;
use super::text::detect_format;
use crate::asset::Asset;
use crate::error::{Error, Result};
use crate::tag::Tag;
use crate::target::Target;
use crate::transport::{AsyncTransport, Blocking, Transport};

/// Largest configuration read (`max_buffer_size`, 128 KiB).
pub const MAX_BUFFER_SIZE: usize = 131072;

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
        match s.trim().to_lowercase().as_str() {
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

impl fmt::Display for ConfigFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

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
}

impl Default for ConfigOptions {
    fn default() -> Self {
        Self { recursion: 0, insecure_includes: false, allow_templates: true, format: None }
    }
}

/// A YAML `asset:` override value: text or a flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetValue {
    /// A string value.
    Text(String),
    /// A boolean value (`yes`/`no`, `true`/`false`).
    Flag(bool),
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

impl Config {
    /// Load a configuration from a path, `file://`, `http://` or `https://` URL.
    pub fn load(source: &str, transport: &dyn Transport, opts: &ConfigOptions) -> Result<Config> {
        pollster::block_on(Self::load_async(source, &Blocking(transport), opts))
    }

    /// [`Config::load`] on an [`AsyncTransport`].
    pub async fn load_async(source: &str, transport: &dyn AsyncTransport, opts: &ConfigOptions) -> Result<Config> {
        let src = Source::instantiate(source, opts.format)?;
        Ok(Self::from_source(src, transport, opts).await)
    }

    /// Load configuration text held in memory. `format` is detected when `None`; an undetectable format is an error.
    pub fn from_text(
        content: &str,
        format: Option<ConfigFormat>,
        transport: &dyn Transport,
        opts: &ConfigOptions,
    ) -> Result<Config> {
        pollster::block_on(Self::from_text_async(content, format, &Blocking(transport), opts))
    }

    /// [`Config::from_text`] on an [`AsyncTransport`] (includes are read through it).
    pub async fn from_text_async(
        content: &str,
        format: Option<ConfigFormat>,
        transport: &dyn AsyncTransport,
        opts: &ConfigOptions,
    ) -> Result<Config> {
        let format = format.or(opts.format).or_else(|| detect_format(content));
        let Some(format) = format else {
            return Err(cfg_err("the format of the configuration could not be detected"));
        };
        let src = Source { kind: SourceKind::Memory(content.to_string()), format: Some(format) };
        Ok(Self::from_source(src, transport, opts).await)
    }

    async fn from_source(src: Source, transport: &dyn AsyncTransport, opts: &ConfigOptions) -> Config {
        let mut cfg = Config::default();
        Loader { transport, opts }.services(&src, opts.recursion, &mut cfg).await;
        cfg.apply_asset();
        cfg
    }

    /// The asset overrides applied to `base`.
    pub fn asset_for(&self, base: &Asset) -> Asset {
        let mut a = base.clone();
        for (k, v) in &self.asset {
            apply_asset_value(&mut a, k, v);
        }
        a
    }

    fn apply_asset(&mut self) {
        if !self.asset.iter().any(|(k, _)| ASSET_KEYS.iter().any(|a| a.name == k && !a.effect.is_empty())) {
            return;
        }
        let overrides = self.asset.clone();
        for s in &mut self.services {
            let ov = overrides.clone();
            match s {
                ConfigService::Ready(t) => t.set_asset_overrides(ov),
                ConfigService::Pending(p) => p.asset = ov,
            }
        }
    }
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
