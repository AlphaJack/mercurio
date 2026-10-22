//! YAML configuration documents.

use super::assets::parse_asset;
use super::fold::{alias_tokens, fold_url, str_items, update};
use super::groups::{apply_groups, normalize_groups, parse_groups};
use super::model::{ConfigOptions, Parsed, RawEntry};
use super::pending::{dropped, url_parses, uses};
use super::template::{self, Placeholders, TemplateSchema};
use super::text::get_schema;
use super::yaml::{self, Yaml};
use crate::parse::parse_urls;
use crate::registry::Registry;
use crate::tag::Tag;

/// `parse_list(value, cast=str)` over YAML values.
pub(super) fn yaml_list(v: &Yaml, out: &mut Vec<String>) {
    match v {
        Yaml::Str(s) => out.extend(crate::parse::parse_list_unsorted([s.as_str()])),
        Yaml::Seq(items) => {
            for i in items {
                yaml_list(i, out);
            }
        }
        Yaml::Bool(_) | Yaml::Null => {}
        other @ (Yaml::Int(_) | Yaml::Float(_) | Yaml::Map(_)) => {
            if other.has_value() {
                out.extend(crate::parse::parse_list_unsorted([other.to_text()]));
            }
        }
    }
}

pub(super) fn yaml_set(v: &Yaml) -> Vec<String> {
    let mut out = Vec::new();
    yaml_list(v, &mut out);
    out.sort();
    out.dedup();
    out
}

/// One YAML URL entry: the URL (if it parsed), its schema and the settings written under it.
type YamlItem = (Option<String>, String, Vec<(String, Yaml)>);

/// `ConfigBase.config_parse_yaml`.
pub(super) fn parse_yaml(content: &str, opts: &ConfigOptions) -> Parsed {
    let mut out = Parsed::default();
    let Some(doc) = document(content) else { return out };
    let Some(placeholders) = placeholders(&doc, content, opts) else { return out };
    let declared = placeholders.as_ref().map(|p| p.schema().names().map(str::to_string).collect()).unwrap_or_default();
    if let Some(tokens) = doc.get("asset").filter(|v| v.has_value()) {
        parse_asset(tokens, &mut out);
    }
    let mut ctx = Entries { placeholders, declared, global_tags: global_tags(&doc), registry: &opts.registry };
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    if let Some(g) = doc.get("groups") {
        parse_groups(g, &mut groups);
    }
    out.includes.extend(includes(&doc));

    let urls: &[Yaml] = match doc.get("urls") {
        Some(Yaml::Seq(items)) => items,
        _ => &[],
    };
    for (no, entry) in urls.iter().enumerate() {
        let no = no + 1;
        let results = match entry {
            Yaml::Str(url) => ctx.url_item(url, no, &mut out.warnings).into_iter().collect(),
            Yaml::Map(map) => ctx.map_items(map, no, &mut out.warnings),
            Yaml::Null | Yaml::Bool(_) | Yaml::Int(_) | Yaml::Float(_) | Yaml::Seq(_) => {
                out.warnings.push(format!("Unsupported YAML entry #{no}"));
                continue;
            }
        };
        for (item, result) in results.into_iter().enumerate() {
            if let Some(e) = ctx.raw_entry(result, no, item + 1, &mut out.warnings) {
                out.entries.push(e);
            }
        }
    }
    normalize_groups(&mut groups);
    apply_groups(&mut out.entries, &groups);
    out.placeholders = ctx.placeholders;
    out
}

/// The parsed document when it is a version 1 mapping.
fn document(content: &str) -> Option<Yaml> {
    let doc = yaml::parse(content).map_err(|e| log::error!("Invalid YAML data specified: {e}")).ok()?;
    if doc.as_map().is_none() {
        log::error!("Invalid YAML based configuration specified.");
        return None;
    }
    let version = doc.get("version").cloned().unwrap_or(Yaml::Int(1));
    let version_ok = matches!(version, Yaml::Int(1)) || matches!(version, Yaml::Float(f) if f == 1.0);
    if !version_ok {
        log::error!("Invalid YAML version specified {}.", version.to_text());
        return None;
    }
    Some(doc)
}

/// The `template:` section; `None` when it is invalid (the document is skipped).
fn placeholders(doc: &Yaml, content: &str, opts: &ConfigOptions) -> Option<Option<Placeholders>> {
    let entries = match doc.get("template") {
        Some(v) if opts.allow_templates && !v.is_null() => v,
        _ => return Some(None),
    };
    let schema = TemplateSchema::parse(entries).map_err(|e| log::error!("Invalid YAML template section. {e}")).ok()?;
    if schema.is_empty() {
        return Some(None);
    }
    Placeholders::new(schema, content).map(Some).map_err(|e| log::error!("{e}")).ok()
}

/// Document-wide `tag:` (or `tags:`) applied to every entry.
fn global_tags(doc: &Yaml) -> Vec<String> {
    let t = match doc.as_map().and_then(|m| m.iter().find(|(k, _)| k.as_str() == Some("tag"))) {
        Some((_, v)) => v.clone(),
        None => doc.get("tags").cloned().unwrap_or(Yaml::Null),
    };
    if t.has_value() && matches!(t, Yaml::Seq(_) | Yaml::Str(_)) { yaml_set(&t) } else { Vec::new() }
}

fn includes(doc: &Yaml) -> Vec<String> {
    let mut out = Vec::new();
    match doc.get("include") {
        Some(Yaml::Str(s)) => out.extend(parse_urls([s.as_str()], true)),
        Some(Yaml::Seq(items)) => {
            for i in items {
                match i {
                    Yaml::Str(s) => out.extend(parse_urls([s.as_str()], true)),
                    Yaml::Map(m) => out.extend(m.iter().map(|(k, _)| k.to_text())),
                    Yaml::Null | Yaml::Bool(_) | Yaml::Int(_) | Yaml::Float(_) | Yaml::Seq(_) => {}
                }
            }
        }
        _ => {}
    }
    out
}

/// Turns `urls:` entries into [`RawEntry`]s.
struct Entries<'a> {
    placeholders: Option<Placeholders>,
    declared: Vec<String>,
    global_tags: Vec<String>,
    registry: &'a Registry,
}

impl Entries<'_> {
    fn encode_url(&mut self, url: &str) -> String {
        match self.placeholders.as_mut() {
            Some(p) => p.encode_url(url),
            None => url.to_string(),
        }
    }

    fn schema_has_template(&self, url: &str) -> bool {
        self.placeholders.as_ref().is_some_and(|p| template::in_schema(url, p.schema()).is_some())
    }

    /// A plain `- scheme://...` entry.
    fn url_item(&mut self, url: &str, no: usize, warnings: &mut Vec<String>) -> Option<YamlItem> {
        if self.schema_has_template(url) {
            warnings.push(format!("Template variables are not permitted in URL schemas (YAML entry #{no})"));
            return None;
        }
        let url = self.encode_url(url);
        let Some(schema) = get_schema(&url) else {
            warnings.push(format!("Invalid URL, entry #{no}"));
            return None;
        };
        if !url_parses(&url, self.registry) {
            warnings.push(format!("Unparseable URL, entry #{no}"));
            return None;
        }
        if let Some(off) = dropped(&url, self.placeholders.as_ref(), self.registry) {
            warnings.push(format!(
                "Template variable '{off}' can not be used at this position for {schema}://, entry #{no}"
            ));
            return None;
        }
        Some((Some(url), schema, Vec::new()))
    }

    /// A `- scheme://...: settings` entry: one item per settings mapping.
    fn map_items(&mut self, map: &[(Yaml, Yaml)], no: usize, warnings: &mut Vec<String>) -> Vec<YamlItem> {
        let mut found: Option<(String, String, Yaml, Yaml)> = None;
        for (key, tokens) in map {
            if let Some(k) = key.as_str()
                && k.contains("://")
                && self.schema_has_template(k)
            {
                warnings.push(format!("Template variables are not permitted in URL schemas (YAML entry #{no})"));
                return Vec::new();
            }
            let Some(k) = key.as_str() else { continue };
            let encoded = self.encode_url(k);
            let Some(schema) = get_schema(&encoded) else { continue };
            found = Some((encoded, schema, key.clone(), tokens.clone()));
            break;
        }
        let Some((url, schema, url_key, mut tokens)) = found else {
            warnings.push(format!("Unsupported URL, entry #{no}"));
            return Vec::new();
        };
        let mut siblings: Vec<(String, Yaml)> = map
            .iter()
            .filter(|(k, _)| *k != url_key && k.as_str() != Some("schema"))
            .filter_map(|(k, v)| k.as_str().map(|k| (k.to_string(), v.clone())))
            .collect();
        if let Some(p) = self.placeholders.as_mut() {
            siblings = siblings.into_iter().map(|(k, v)| (k, p.encode_value(&v))).collect();
            tokens = p.encode_value(&tokens);
        }
        let parsed_ok = url_parses(&url, self.registry);
        if !parsed_ok && self.placeholders.as_ref().is_some_and(|p| uses(p, &url)) {
            warnings.push(format!("A template variable can not be used at this position for {schema}://, entry #{no}"));
            return Vec::new();
        }
        if parsed_ok && let Some(off) = dropped(&url, self.placeholders.as_ref(), self.registry) {
            warnings.push(format!(
                "Template variable '{off}' can not be used at this position for {schema}://, entry #{no}"
            ));
            return Vec::new();
        }
        let base = if parsed_ok { Some(url) } else { None };
        alias_tokens(&mut siblings);
        let merged = |m: &[(Yaml, Yaml)]| {
            let mut t = str_items(m);
            t.retain(|(k, _)| k != "schema");
            alias_tokens(&mut t);
            let mut merged = siblings.clone();
            update(&mut merged, &t);
            (base.clone(), schema.clone(), merged)
        };
        match &tokens {
            Yaml::Seq(list) => {
                list.iter().filter_map(|e| if let Yaml::Map(m) = e { Some(merged(m)) } else { None }).collect()
            }
            Yaml::Map(m) => vec![merged(m)],
            Yaml::Null | Yaml::Bool(_) | Yaml::Int(_) | Yaml::Float(_) | Yaml::Str(_) => {
                vec![(base.clone(), schema.clone(), siblings.clone())]
            }
        }
    }

    /// Validate one item's schema and tags and fold its settings into the URL.
    fn raw_entry(&self, item: YamlItem, no: usize, item_no: usize, warnings: &mut Vec<String>) -> Option<RawEntry> {
        let (base, schema, tokens) = item;
        if self.registry.service_for_scheme(&schema).is_none()
            && base.as_deref().is_none_or(|u| self.registry.parse(u).is_err())
        {
            warnings.push(format!("An invalid schema ({schema}) in YAML configuration entry #{no}, item #{item_no}"));
            return None;
        }
        let tag_value = tokens.iter().find(|(k, _)| k == "tag").map(|(_, v)| v.clone());
        let mut tags = match tag_value {
            Some(v) => yaml_set(&v),
            None => tokens.iter().find(|(k, _)| k == "tags").map(|(_, v)| yaml_set(v)).unwrap_or_default(),
        };
        for g in &self.global_tags {
            if !tags.contains(g) {
                tags.push(g.clone());
            }
        }
        if let Some(p) = &self.placeholders {
            let mut refs = Vec::new();
            for t in &tags {
                p.used_in(t, &mut refs);
                template::references(&Yaml::Str(t.clone()), &mut refs);
            }
            if refs.iter().any(|r| self.declared.contains(r)) || tags.iter().any(|t| uses(p, t)) {
                warnings.push(format!(
                    "Template variables are not permitted in tag/tags (YAML entry #{no}, item #{item_no})"
                ));
                return None;
            }
        }
        if tags.iter().any(|t| Tag::parse(t).retry.is_some()) {
            warnings.push(format!(
                "You can not specify a retry count as part of a service tag (YAML entry #{no}, item #{item_no})"
            ));
            return None;
        }
        let url = match base {
            Some(b) if tokens.is_empty() => b,
            b => fold_url(b.as_deref(), &schema, &tokens, warnings),
        };
        Some(RawEntry { url, tags, location: format!("YAML entry #{no}, item #{item_no}") })
    }
}
