//! The YAML configuration keys: the top-level keys of a document and the settings written under a URL. The loader takes its key names from these tables and the book's YAML page is rendered from them.

/// A top-level key of a YAML configuration document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopKey {
    /// The key.
    pub name: &'static str,
    /// Other spellings read for the same value.
    pub aliases: &'static [&'static str],
    /// The document is unusable without it.
    pub required: bool,
    /// What it holds (Markdown, links relative to the book's `config/` pages).
    pub meaning: &'static str,
}

/// The top-level keys a YAML document may hold; other keys are ignored.
pub const TOP_LEVEL: &[TopKey] = &[
    TopKey {
        name: "version",
        aliases: &[],
        required: false,
        meaning: "Must be `1` (or `1.0`) when present. Any other value rejects the file.",
    },
    TopKey { name: "urls", aliases: &[], required: true, meaning: "The list of services." },
    TopKey {
        name: "tag",
        aliases: &["tags"],
        required: false,
        meaning: "Tags added to every entry of this file (a string with commas or spaces, or a list). `tag` wins \
                  when both are present.",
    },
    TopKey { name: "groups", aliases: &[], required: false, meaning: "Tag groups, see [below](#groups)." },
    TopKey {
        name: "include",
        aliases: &[],
        required: false,
        meaning: "Other configuration sources, a string or a list. See [Includes](includes.md).",
    },
    TopKey {
        name: "template",
        aliases: &[],
        required: false,
        meaning: "`${NAME}` variables. See [Templates](templates.md).",
    },
    TopKey {
        name: "asset",
        aliases: &[],
        required: false,
        meaning: "Application identity and storage settings. See [Asset overrides](assets.md).",
    },
];

/// How one form of setting under a URL entry is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setting {
    /// The form as written in YAML (Markdown).
    pub form: &'static str,
    /// The keys this row is about. Keys listed here without a `group` are handled by the loader and never folded into the query string; empty for the rows that describe ordinary `key: value` settings.
    pub keys: &'static [&'static str],
    /// For `headers`, `params` and `payload`: the query prefix their entries get.
    pub group: Option<char>,
    /// What the setting becomes (Markdown).
    pub becomes: &'static str,
}

/// Every form of setting under a URL entry, in the order the book lists them.
pub const SETTINGS: &[Setting] = &[
    Setting { form: "`key: value`", keys: &[], group: None, becomes: "`?key=value` (value percent-encoded for you)" },
    Setting { form: "`key: true` / `key: false`", keys: &[], group: None, becomes: "`?key=yes` / `?key=no`" },
    Setting { form: "`key: [a, b]`", keys: &[], group: None, becomes: "`?key=a,b`" },
    Setting { form: "`key: ~` (null)", keys: &[], group: None, becomes: "nothing" },
    Setting {
        form: "`tag` / `tags`",
        keys: &["tag", "tags"],
        group: None,
        becomes: "the entry's tags (not a query parameter)",
    },
    Setting {
        form: "`user`, `password` (or `pass`), `host`, `port`",
        keys: &["user", "password", "pass", "host", "port"],
        group: None,
        becomes: "replace those parts of the URL; special characters are encoded for you",
    },
    Setting {
        form: "`+Name: value`, `-name: value`, `:name: value`",
        keys: &[],
        group: None,
        becomes: "the prefixed query parameters (`?+Name=value`, ...)",
    },
    Setting {
        form: "`headers: {Name: value}`",
        keys: &["headers"],
        group: Some('+'),
        becomes: "`?+Name=value` for each entry",
    },
    Setting {
        form: "`params: {name: value}`",
        keys: &["params"],
        group: Some('-'),
        becomes: "`?-name=value` for each entry",
    },
    Setting {
        form: "`payload: {name: value}`",
        keys: &["payload"],
        group: Some(':'),
        becomes: "`?:name=value` for each entry",
    },
    Setting { form: "`schema`", keys: &["schema"], group: None, becomes: "ignored" },
    Setting { form: "`asset`", keys: &["asset"], group: None, becomes: "ignored (it is a top-level key)" },
];

/// `true` for a key the loader handles itself instead of folding it into the URL.
pub(super) fn is_reserved(key: &str) -> bool {
    SETTINGS.iter().any(|s| s.group.is_none() && s.keys.contains(&key))
}

/// The query prefix of a grouped setting (`headers` -> `+`).
pub(super) fn group_prefix(key: &str) -> Option<char> {
    SETTINGS.iter().find(|s| s.group.is_some() && s.keys.contains(&key)).and_then(|s| s.group)
}

/// The query prefixes of the grouped settings: `+`, `-`, `:`.
pub(super) fn prefixes() -> impl Iterator<Item = char> {
    SETTINGS.iter().filter_map(|s| s.group)
}

/// A key of the YAML `asset:` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetKey {
    /// The key.
    pub name: &'static str,
    /// A yes/no value (otherwise text).
    pub flag: bool,
    /// What it changes (Markdown); empty when it is accepted without effect.
    pub effect: &'static str,
}

const fn asset(name: &'static str, effect: &'static str) -> AssetKey {
    AssetKey { name, flag: false, effect }
}

const fn asset_flag(name: &'static str) -> AssetKey {
    AssetKey { name, flag: true, effect: "" }
}

/// The keys an `asset:` section may set. Their defaults are those of [`crate::Asset::default`]; other keys are rejected with a warning.
pub const ASSET_KEYS: &[AssetKey] = &[
    asset("app_id", "`User-Agent` and sender name for many services"),
    asset("app_desc", "longer description, used by some services"),
    asset("app_url", "link in footers and buttons"),
    asset("theme", "replaces `{THEME}` in the image masks"),
    asset(
        "image_url_mask",
        "per-type images: `{TYPE}`, `{XY}`, `{THEME}`, `{EXTENSION}` are replaced; empty disables them",
    ),
    asset("image_url_logo", "the logo; empty disables it"),
    asset("default_extension", "replaces `{EXTENSION}`"),
    asset("default_html_color", "colour when no type colour applies"),
    asset("default_ascii_chars", "marker when no type marker applies"),
    asset(
        "storage_path",
        "[persistent store](../storage.md) directory (`~` expanded); the CLI's default is `--storage-path`",
    ),
    asset(
        "image_path_mask",
        "icon file for desktop notifiers, same placeholders; empty sends none. Default: the bundled icon",
    ),
    asset("image_path_logo", ""),
    asset("encoding", ""),
    asset_flag("async_mode"),
    asset_flag("interpret_escapes"),
    asset_flag("abort_on_chain_failure"),
    AssetKey {
        name: "pgp_autogen",
        flag: true,
        effect: "generate a PGP key pair in the storage folder when e-mail encryption needs one; default yes",
    },
    asset_flag("pem_autogen"),
    asset_flag("secure_logging"),
    asset_flag("http_redirects"),
];

/// Keys an `asset:` section may hold that are skipped without a warning.
pub const ASSET_SKIPPED: &[&str] = &["lang", "language", "timezone", "tz"];

/// The value of asset key `name` in `asset`, as a YAML file would write it (`None` for a key without effect or an unset value).
pub fn asset_value(asset: &crate::Asset, name: &str) -> Option<String> {
    match name {
        "app_id" => Some(asset.app_id.clone()),
        "app_desc" => Some(asset.app_desc.clone()),
        "app_url" => Some(asset.app_url.clone()),
        "theme" => Some(asset.theme.clone()),
        "image_url_mask" => asset.image_url_mask.clone(),
        "image_url_logo" => asset.image_url_logo.clone(),
        "default_extension" => Some(asset.default_extension.clone()),
        "default_html_color" => Some(asset.default_color.clone()),
        "default_ascii_chars" => Some(asset.default_ascii.clone()),
        "storage_path" => asset.storage_path.as_ref().map(|p| p.display().to_string()),
        "image_path_mask" => asset.image_path_mask.clone(),
        "pgp_autogen" => Some(if asset.pgp_autogen { "yes" } else { "no" }.into()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The string literals `re` captures in `src`.
    fn literals(re: &str, src: &str) -> BTreeSet<String> {
        regex::Regex::new(re).unwrap().captures_iter(src).map(|c| c[1].to_string()).collect()
    }

    /// Every top-level key the loader reads is in [`TOP_LEVEL`], and every key there is read.
    #[test]
    fn top_level_keys_match_the_loader() {
        let src = include_str!("yaml_doc.rs");
        let read = literals(r#"(?:doc\.get\(|k\.as_str\(\) == Some\()"([a-z_]+)""#, src);
        let spec: BTreeSet<String> = TOP_LEVEL
            .iter()
            .flat_map(|k| std::iter::once(k.name).chain(k.aliases.iter().copied()))
            .map(str::to_string)
            .collect();
        // `schema` is compared on URL entries, not on the document.
        let doc_keys: BTreeSet<String> = read.iter().filter(|k| *k != "schema").cloned().collect();
        assert!(
            doc_keys.is_subset(&spec),
            "read but not in TOP_LEVEL: {:?}",
            doc_keys.difference(&spec).collect::<Vec<_>>()
        );
        assert!(
            spec.is_subset(&doc_keys),
            "in TOP_LEVEL but never read: {:?}",
            spec.difference(&doc_keys).collect::<Vec<_>>()
        );
    }

    /// Every entry key the loader compares against is in [`SETTINGS`].
    #[test]
    fn settings_match_the_loader() {
        let src = [include_str!("fold.rs"), include_str!("yaml_doc.rs")].concat();
        let read = literals(r#"(?:get\(|k == |k != |Some\()"([a-z_]+)"\)?"#, &src);
        let spec: BTreeSet<String> = SETTINGS.iter().flat_map(|s| s.keys.iter().map(|k| (*k).to_string())).collect();
        let top: BTreeSet<String> = TOP_LEVEL.iter().map(|k| k.name.to_string()).collect();
        let entry_keys: BTreeSet<String> = read.difference(&top).cloned().collect();
        assert!(
            entry_keys.is_subset(&spec),
            "compared but not in SETTINGS: {:?}",
            entry_keys.difference(&spec).collect::<Vec<_>>()
        );
        // Grouped and reserved keys are read through `group_prefix` and `is_reserved`, so every key in SETTINGS is read by construction.
    }
}
