//! Building services, including `${NAME}` templated ones.

use std::fmt;
use std::sync::Arc;

use super::model::{AssetValue, Config, ConfigService, Parsed};
use super::template::{self, Placeholders, TemplateError, TemplateVars};
use crate::error::{Error, Result};
use crate::notify::{Target, parse, service_for_scheme};
use crate::service::ServiceDef;
use crate::tag::{Tag, parse_tags};
use crate::url::{ParseOptions, ParsedUrl, parse_url_with};

pub(super) fn uses(p: &Placeholders, text: &str) -> bool {
    let mut v = Vec::new();
    p.used_in(text, &mut v);
    !v.is_empty()
}

/// Whether the URL parses structurally.
pub(super) fn url_parses(url: &str) -> bool {
    let Some(scheme) = crate::url::scheme_of(url) else { return false };
    match service_for_scheme(&scheme) {
        Some(_) => parse_url_with(url, SERVICE_URL).is_some(),
        None => crate::parse(url).is_ok(),
    }
}

/// How service URLs parse: hosts are not checked (many are tokens).
pub(super) const SERVICE_URL: ParseOptions = ParseOptions { verify_host: false, strict_port: false, sanitize: true };

/// `dropped_template`: a declared marker the URL parser discarded.
pub(super) fn dropped(url: &str, p: Option<&Placeholders>) -> Option<String> {
    let p = p?;
    let mut wanted = Vec::new();
    p.used_in(url, &mut wanted);
    if wanted.is_empty() {
        return None;
    }
    let scheme = crate::url::scheme_of(url)?;
    service_for_scheme(&scheme)?;
    let parsed = parse_url_with(&url.replace("/#", "/%23"), SERVICE_URL)?;
    let have = p.used_by(&parsed);
    let mut missing: Vec<String> = wanted.into_iter().filter(|w| !have.contains(w)).collect();
    missing.sort();
    missing.into_iter().next()
}

/// A configuration entry waiting for `${NAME}` values.
pub struct PendingTarget {
    def: &'static ServiceDef,
    parsed: ParsedUrl,
    placeholders: Arc<Placeholders>,
    names: Vec<String>,
    /// Tags from the configuration entry.
    pub tags: Vec<Tag>,
    /// Where the entry was read, e.g. `line 3` or `YAML entry #1, item #2`.
    pub location: String,
    pub(super) asset: Vec<(String, AssetValue)>,
}

impl fmt::Debug for PendingTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingTarget").field("service", &self.def.id).field("needs", &self.names).finish()
    }
}

impl PendingTarget {
    /// The service definition this entry will use.
    pub fn service(&self) -> &'static ServiceDef {
        self.def
    }

    /// Variables this entry uses, sorted.
    pub fn template_names(&self) -> &[String] {
        &self.names
    }

    /// Variables without a configuration default.
    pub fn template_required(&self) -> Vec<String> {
        self.names.iter().filter(|n| self.placeholders.schema().is_required(n)).cloned().collect()
    }

    /// The URL with `${NAME}` markers in place (may contain secrets).
    pub fn url(&self) -> String {
        self.placeholders.display(&self.parsed.original)
    }

    /// Short label `scheme:// (Service Name)` without secrets.
    pub fn label(&self) -> String {
        format!("{}:// ({})", self.parsed.scheme, self.def.name)
    }

    /// Build the real service from `vars` (then defaults, then the environment).
    pub fn resolve(&self, vars: &TemplateVars) -> Result<Target> {
        let values = vars.resolve(self.placeholders.schema(), Some(&self.names)).map_err(|e: TemplateError| {
            Error::config(
                self.def.name,
                match &e.variable {
                    Some(v) => format!("template variable '{v}' is not available; entry skipped"),
                    None => e.message.clone(),
                },
            )
        })?;
        let parsed = self.placeholders.substitute(&self.parsed, &values);
        if parsed.original.len() > template::MAX_RESOLVED_URL_LEN {
            return Err(Error::config(self.def.name, "a template built an over-sized URL"));
        }
        let service = (self.def.parse)(&parsed)?;
        let mut t = Target::new(self.def, service, &parsed).with_tag_set(self.tags.clone());
        if !self.asset.is_empty() {
            t.set_asset_overrides(self.asset.clone());
        }
        Ok(t)
    }
}

pub(super) fn build(parsed: Parsed, cfg: &mut Config) {
    cfg.warnings.extend(parsed.warnings);
    for (k, v) in parsed.asset {
        cfg.asset.retain(|(n, _)| *n != k);
        cfg.asset.push((k, v));
    }
    let placeholders = parsed.placeholders.map(Arc::new);
    for e in parsed.entries {
        let tags = parse_tags(&e.tags);
        if let Some(p) = &placeholders
            && uses(p, &e.url)
        {
            let Some(def) = crate::url::scheme_of(&e.url).and_then(|s| service_for_scheme(&s)) else {
                cfg.warnings.push(format!("Could not load {} ({})", crate::plan::redact_url(&e.url), e.location));
                continue;
            };
            let Some(pu) = parse_url_with(&e.url.replace("/#", "/%23"), SERVICE_URL) else {
                cfg.warnings.push(format!("Could not load {} ({})", crate::plan::redact_url(&e.url), e.location));
                continue;
            };
            let names = p.used_by(&pu);
            if !names.is_empty() {
                cfg.services.push(ConfigService::Pending(Box::new(PendingTarget {
                    def,
                    parsed: pu,
                    placeholders: p.clone(),
                    names,
                    tags,
                    location: e.location,
                    asset: Vec::new(),
                })));
                continue;
            }
        }
        match parse(&e.url) {
            Ok(t) => cfg.services.push(ConfigService::Ready(t.with_tag_set(tags))),
            Err(err) => cfg.warnings.push(format!(
                "Could not load URL {} ({}): {err}",
                crate::plan::redact_url(&e.url),
                e.location
            )),
        }
    }
}
