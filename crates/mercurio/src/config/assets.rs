//! YAML `asset:` overrides.

use super::model::Parsed;
use super::spec::{ASSET_KEYS, ASSET_SKIPPED};
use super::yaml::Yaml;
use crate::asset_def::AssetValue;
use crate::parse::parse_bool;

pub(super) fn parse_asset(tokens: &Yaml, out: &mut Parsed) {
    let Some(map) = tokens.as_map() else { return };
    // As Apprise: `timezone` (or `tz`), cleaned to word characters, `/` and `-`, must name a zone.
    let get = |name: &str| map.iter().find(|(k, _)| k.as_str() == Some(name)).map(|(_, v)| v);
    match get("timezone").or_else(|| get("tz")) {
        Some(Yaml::Str(raw)) => {
            let cleaned: String = raw.chars().filter(|c| c.is_alphanumeric() || matches!(c, '_' | '/' | '-')).collect();
            match crate::time::zone(&cleaned) {
                Some(tz) => {
                    let name = tz.iana_name().map_or(cleaned, str::to_owned);
                    out.asset.retain(|(n, _)| n != "timezone");
                    out.asset.push(("timezone".to_owned(), AssetValue::Text(name)));
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
            (Yaml::Str(s), false) => AssetValue::Text(s.trim().to_owned()),
            _ => {
                out.warnings.push(format!("Invalid asset value to \"{k}\"."));
                continue;
            }
        };
        out.asset.retain(|(n, _)| n != k);
        out.asset.push((k.to_owned(), value));
    }
}

#[cfg(test)]
mod spec_tests {
    use super::super::spec::{ASSET_KEYS, asset_value};
    use crate::asset::Asset;
    use crate::config::AssetValue;

    /// Every key with an effect is applied by the loader and read back by `asset_value`; every key without one changes nothing.
    #[test]
    fn asset_keys_match_the_loader() {
        for key in ASSET_KEYS {
            let mut a = Asset::default();
            if key.flag && !key.effect.is_empty() {
                a.apply(key.name, &AssetValue::Flag(false));
                assert_ne!(a, Asset::default(), "{} is not applied", key.name);
                assert_eq!(asset_value(&a, key.name).as_deref(), Some("no"), "{}", key.name);
                continue;
            }
            a.apply(key.name, &AssetValue::Text("x1".into()));
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
