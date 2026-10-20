//! `cargo xtask new <id>`: a new service starts as a copy of the `acme` service in `xtask/templates/`, renamed, with its `service-<id>` Cargo feature.

use std::path::Path;

const SERVICE: &str = include_str!("../templates/acme.rs");
const FIXTURE: &str = include_str!("../templates/acme.json");

/// Writes `src/services/<id>.rs` and `tests/fixtures/services/<id>.json`, and adds the service's feature to `Cargo.toml`.
pub fn scaffold(root: &Path, id: &str) -> Result<(), String> {
    if !id.starts_with(|c: char| c.is_ascii_lowercase())
        || !id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(format!("{id:?}: use the brand name in lowercase letters and digits, without separators"));
    }
    let name = {
        let mut c = id.chars();
        c.next().map(|f| f.to_ascii_uppercase().to_string() + c.as_str()).unwrap_or_default()
    };
    let ty: String = id
        .split('_')
        .map(|w| {
            let mut c = w.chars();
            c.next().map(|f| f.to_ascii_uppercase().to_string() + c.as_str()).unwrap_or_default()
        })
        .collect();
    let fill = |t: &str| t.replace("AcmeService", &ty).replace("Acme", &name).replace("acme", id);
    let files = [
        (root.join(format!("crates/mercurio/src/services/{id}.rs")), fill(SERVICE)),
        (root.join(format!("crates/mercurio/tests/fixtures/services/{id}.json")), fill(FIXTURE)),
    ];
    for (path, _) in &files {
        if path.exists() || path.with_extension("").join("mod.rs").exists() {
            return Err(format!("{} already exists", path.display()));
        }
    }
    for (path, content) in &files {
        std::fs::write(path, content).map_err(|e| format!("{}: {e}", path.display()))?;
        eprintln!("wrote {}", path.strip_prefix(root).unwrap_or(path).display());
    }
    add_feature(&root.join("crates/mercurio/Cargo.toml"), id)?;
    eprintln!("next: edit both files, then `cargo test -p mercurio --test it services::{id}` and `cargo insta review`");
    Ok(())
}

/// Adds `service-<id>` to `all-services` and to the per-service features, each in sorted order (the names `build.rs` checks).
fn add_feature(manifest: &Path, id: &str) -> Result<(), String> {
    let feature = format!("service-{id}");
    let text = std::fs::read_to_string(manifest).map_err(|e| format!("{}: {e}", manifest.display()))?;
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let start = lines.iter().position(|l| l.starts_with("all-services = [")).ok_or("Cargo.toml: no `all-services`")?;
    let end = start + lines[start..].iter().position(|l| l == "]").ok_or("Cargo.toml: unterminated `all-services`")?;
    insert_sorted(&mut lines, start + 1..end, format!("  \"{feature}\","));
    let len = lines.len();
    insert_sorted(&mut lines, end + 1..len, format!("{feature} = []"));
    std::fs::write(manifest, lines.join("\n") + "\n").map_err(|e| format!("{}: {e}", manifest.display()))?;
    eprintln!("added `{feature}` to crates/mercurio/Cargo.toml");
    Ok(())
}

/// Insert `line` among the `service-` lines of `range`, before the first one that sorts after it.
fn insert_sorted(lines: &mut Vec<String>, range: std::ops::Range<usize>, line: String) {
    let key = |l: &str| l.trim_start().trim_start_matches('"').to_owned();
    let entries: Vec<usize> = range.filter(|&i| key(&lines[i]).starts_with("service-")).collect();
    let at = entries
        .iter()
        .find(|&&i| key(&lines[i]) > key(&line))
        .copied()
        .unwrap_or_else(|| entries.last().map_or(0, |i| i + 1));
    lines.insert(at, line);
}
