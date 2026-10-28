//! Write the book's library page from the crate docs in `crates/mercurio/src/lib.rs`.

use std::path::Path;

const FEATURES_INCLUDE: &str = "#![doc = include_str!(concat!(env!(\"OUT_DIR\"), \"/features.md\"))]";

pub(crate) fn render(root: &Path) -> Result<(), String> {
    let path = root.join("crates/mercurio/src/lib.rs");
    let source = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut lines = Vec::new();
    for line in source.lines() {
        if let Some(rest) = line.strip_prefix("//!") {
            lines.push(rest.strip_prefix(' ').unwrap_or(rest).to_owned());
        } else if line.trim() == "#![doc = env!(\"CARGO_PKG_DESCRIPTION\")]" {
            lines.push(env!("CARGO_PKG_DESCRIPTION").to_owned());
        } else if line.trim() == FEATURES_INCLUDE {
            lines.extend(mercurio::FEATURES_TABLE.lines().map(str::to_owned));
        } else {
            break;
        }
    }
    let mut fenced = false;
    let mut out = Vec::new();
    for line in lines.into_iter().skip_while(|l| l.starts_with("# ") || l.is_empty()) {
        if let Some(info) = line.strip_prefix("```") {
            let opening = !fenced;
            fenced = !fenced;
            if opening && (info.is_empty() || info == "no_run") {
                out.push(if info.is_empty() { "```rust".to_owned() } else { "```rust,no_run".to_owned() });
                continue;
            }
        }
        out.push(line);
    }
    let text = crate::pages::plain_code_links(&out.join("\n"), true);
    let text = crate::pages::plain_code_links(&text, false);
    let dir = root.join("docs/book/src/generated");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::write(dir.join("library.md"), text + "\n").map_err(|e| format!("library.md: {e}"))
}
