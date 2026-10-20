//! The YAML configuration tables of the book from `mercurio::__private::spec`.

use std::path::Path;

use mercurio::__private::spec::{ASSET_KEYS, ASSET_SKIPPED, SETTINGS, TOP_LEVEL, asset_value};

/// Writes `docs/book/src/generated/yaml-top-level.md`, `yaml-settings.md`, `asset-keys.md` (keys with their `Asset::default()` value) and `asset-ignored.md` (keys accepted without effect).
pub fn render(root: &Path) -> Result<(), String> {
    let dir = root.join("docs/book/src/generated");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;

    let mut top = String::from("| Key | Required | Meaning |\n|---|---|---|\n");
    for k in TOP_LEVEL {
        let names: Vec<String> =
            std::iter::once(k.name).chain(k.aliases.iter().copied()).map(|n| format!("`{n}`")).collect();
        let required = if k.required { "yes" } else { "no" };
        top.push_str(&format!("| {} | {required} | {} |\n", names.join(" / "), k.meaning));
    }

    let mut settings = String::from("| Setting | Becomes |\n|---|---|\n");
    for s in SETTINGS {
        settings.push_str(&format!("| {} | {} |\n", s.form, s.becomes));
    }

    let defaults = mercurio::Asset::default();
    let mut assets = String::from("| Key | Default | Effect |\n|---|---|---|\n");
    for k in ASSET_KEYS.iter().filter(|k| !k.effect.is_empty()) {
        let default = asset_value(&defaults, k.name).map_or_else(|| "none".to_owned(), |v| format!("`{v}`"));
        assets.push_str(&format!("| `{}` | {default} | {} |\n", k.name, k.effect));
    }
    let ignored: Vec<String> = ASSET_KEYS
        .iter()
        .filter(|k| k.effect.is_empty())
        .map(|k| k.name)
        .chain(ASSET_SKIPPED.iter().copied())
        .map(|n| format!("`{n}`"))
        .collect();
    let ignored = format!("Accepted without effect: {}.\n", ignored.join(", "));

    for (name, content) in [
        ("yaml-top-level.md", top),
        ("yaml-settings.md", settings),
        ("asset-keys.md", assets),
        ("asset-ignored.md", ignored),
    ] {
        std::fs::write(dir.join(name), content).map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(())
}
