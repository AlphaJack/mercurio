//! Configuration files: TEXT and YAML, from local files, HTTP(S) or memory, with `include` directives, tag groups and `${NAME}` templates.
//!
//! ```
//! # #[cfg(feature = "service-json")] {
//! use mercurio::{Config, ConfigOptions};
//! use mercurio::testing::FakeTransport;
//!
//! let text = "dev, ops=json://localhost/a\njson://localhost/b\n";
//! let cfg = Config::from_text(text, None, &FakeTransport::new(), &ConfigOptions::default()).unwrap();
//! assert_eq!(cfg.services.len(), 2);
//! # }
//! ```
//!
//! YAML settings written under a URL are folded into the URL's query string (`key=value`, `+header`, `-param`, `:payload`; `user`, `password`, `host` and `port` replace the URL's own), so every service reads them through its normal URL parser.

mod assets;
mod fold;
mod groups;
mod loader;
mod model;
mod pending;
pub mod spec;
pub(crate) mod template;
mod text;
pub mod yaml;
mod yaml_doc;

pub use loader::{default_paths, expand_path};
pub use model::{AssetValue, Config, ConfigFormat, ConfigOptions, ConfigService};
pub use pending::PendingTarget;
pub use text::detect_format;

#[cfg(test)]
mod tests;
