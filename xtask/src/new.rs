//! `cargo xtask new <id>`: a new service starts as a copy of the `acme` service in `xtask/templates/`, renamed.

use std::path::Path;

const SERVICE: &str = include_str!("../templates/acme.rs");
const FIXTURE: &str = include_str!("../templates/acme.json");

/// Writes `src/services/<id>.rs` and `tests/fixtures/services/<id>.json`.
pub fn scaffold(root: &Path, id: &str) -> Result<(), String> {
    if id.is_empty()
        || !id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        || id.starts_with('_')
    {
        return Err(format!("{id:?}: use lowercase letters, digits and `_`, not starting with `_`"));
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
    eprintln!("next: edit both files, then `cargo test -p mercurio --test it services::{id}` and `cargo insta review`");
    Ok(())
}
