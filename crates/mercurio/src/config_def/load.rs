//! Loading a [`Config`]: from a source, or from text in memory, then applying its asset overrides.

use super::loader::{Loader, Source, SourceKind};
use super::model::{Config, ConfigFormat, ConfigOptions, ConfigService, cfg_err};
use super::spec::ASSET_KEYS;
use super::text::detect_format;
use crate::asset::Asset;
use crate::error::Result;
use crate::transport::{AsyncTransport, Blocking, Transport};

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
        let src = Source { kind: SourceKind::Memory(content.to_owned()), format: Some(format) };
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
        base.with_overrides(&self.asset)
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
