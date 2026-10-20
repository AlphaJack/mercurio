//! YAML `asset:` overrides.

use super::loader::path_decode;
use super::model::{AssetValue, Parsed};
use super::spec::{ASSET_KEYS, ASSET_SKIPPED};
use super::yaml::Yaml;
use crate::asset::Asset;
use crate::parse::parse_bool;

pub(super) fn apply_asset_value(a: &mut Asset, key: &str, v: &AssetValue) {
    let AssetValue::Text(t) = v else { return };
    match key {
        "app_id" => a.app_id = t.clone(),
        "app_desc" => a.app_desc = t.clone(),
        "app_url" => a.app_url = t.clone(),
        "default_html_color" => a.default_color = t.clone(),
        "default_ascii_chars" => a.default_ascii = t.clone(),
        "default_extension" => a.default_extension = t.clone(),
        "theme" => a.theme = t.clone(),
        "image_url_mask" => a.image_url_mask = Some(t.clone()).filter(|s| !s.is_empty()),
        "image_url_logo" => a.image_url_logo = Some(t.clone()).filter(|s| !s.is_empty()),
        "image_path_mask" => a.image_path_mask = Some(t.clone()),
        "storage_path" => a.storage_path = Some(path_decode(t)).filter(|p| !t.is_empty() && !p.as_os_str().is_empty()),
        "timezone" => a.timezone = Some(t.clone()),
        _ => {}
    }
}

pub(super) fn parse_asset(tokens: &Yaml, out: &mut Parsed) {
    let Some(map) = tokens.as_map() else { return };
    // As Apprise: `timezone` (or `tz`), cleaned to word characters, `/` and `-`, must name a zone.
    let get = |name: &str| map.iter().find(|(k, _)| k.as_str() == Some(name)).map(|(_, v)| v);
    match get("timezone").or_else(|| get("tz")) {
        Some(Yaml::Str(raw)) => {
            let cleaned: String = raw.chars().filter(|c| c.is_alphanumeric() || matches!(c, '_' | '/' | '-')).collect();
            match crate::time::zone(&cleaned) {
                Some(tz) => {
                    let name = tz.iana_name().map_or(cleaned, str::to_string);
                    out.asset.retain(|(n, _)| n != "timezone");
                    out.asset.push(("timezone".to_string(), AssetValue::Text(name)));
                }
                None => out.warnings.push(format!("Ignored invalid timezone \"{raw}\"")),
            }
        }
        Some(Yaml::Null) | None => {}
        Some(other) => out.warnings.push(format!("Ignored invalid timezone \"{other:?}\"")),
    }
    for (k, v) in map {
        let Some(k) = k.as_str() else { continue };
        if ASSET_SKIPPED.contains(&k) {
            continue;
        }
        if k.starts_with('_') || k.ends_with('_') {
            out.warnings.push(format!("Ignored asset key \"{k}\"."));
            continue;
        }
        let Some(flag) = ASSET_KEYS.iter().find(|a| a.name == k).map(|a| a.flag) else {
            out.warnings.push(format!("Invalid asset key \"{k}\"."));
            continue;
        };
        let value = match (v, flag) {
            (Yaml::Null, true) => AssetValue::Flag(false),
            (Yaml::Null, false) => AssetValue::Text(String::new()),
            (Yaml::Bool(b), true) => AssetValue::Flag(*b),
            (Yaml::Str(s), true) => AssetValue::Flag(parse_bool(s, false)),
            (Yaml::Str(s), false) => AssetValue::Text(s.trim().to_string()),
            _ => {
                out.warnings.push(format!("Invalid asset value to \"{k}\"."));
                continue;
            }
        };
        out.asset.retain(|(n, _)| n != k);
        out.asset.push((k.to_string(), value));
    }
}

#[cfg(test)]
mod spec_tests {
    use super::super::spec::{ASSET_KEYS, asset_value};
    use super::apply_asset_value;
    use crate::asset::Asset;
    use crate::config::model::AssetValue;

    /// Every key with an effect is applied by the loader and read back by `asset_value`; every key without one changes nothing.
    #[test]
    fn asset_keys_match_the_loader() {
        for key in ASSET_KEYS {
            let mut a = Asset::default();
            apply_asset_value(&mut a, key.name, &AssetValue::Text("x1".into()));
            if key.effect.is_empty() {
                assert_eq!(a, Asset::default(), "{} has no effect but changed the asset", key.name);
                assert_eq!(asset_value(&a, key.name), None, "{}", key.name);
            } else {
                // `storage_path` comes back resolved against the working directory.
                let value = asset_value(&a, key.name).unwrap_or_default();
                assert!(value.ends_with("x1"), "{} is not applied: {value:?}", key.name);
            }
        }
    }
}
