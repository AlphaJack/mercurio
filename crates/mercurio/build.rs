//! Generates the service registry and the per-fixture tests.
//!
//! Every `src/services/<id>.rs` or `src/services/<id>/mod.rs` becomes a module gated by the Cargo feature `service-<id>`, which `Cargo.toml` must declare and list in `all-services`. It must export `pub static SERVICE`. Every `tests/fixtures/services/<id>.json` becomes one `#[test]` gated the same way. `src/services/_<name>.rs` helper modules are always compiled and unregistered. Adding a service therefore never touches a shared source file.

#![expect(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "a build script should fail loudly")]
#![expect(clippy::disallowed_methods, reason = "a build script reads and writes files")]

use std::collections::BTreeSet;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest = root.join("Cargo.toml");
    let table = toml_table(&manifest, "[features]");
    let features: BTreeSet<&String> = table.keys().collect();
    let all_services: BTreeSet<&String> = table.get("all-services").into_iter().flatten().collect();

    // The GitHub Pages site of the repository (`[workspace.package] repository`): the book, and the icons services link to.
    let repository = env::var("CARGO_PKG_REPOSITORY").unwrap();
    let pages = pages_url(&repository);
    println!("cargo::rustc-env=MERCURIO_PAGES_URL={pages}");

    let services_dir = root.join("src/services");
    println!("cargo::rerun-if-changed=src/services");
    println!("cargo::rerun-if-changed=tests/fixtures/services");
    println!("cargo::rerun-if-changed=Cargo.toml");

    let mut modules: Vec<(String, PathBuf)> = Vec::new();
    for entry in fs::read_dir(&services_dir).expect("src/services exists") {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if name.starts_with('.') || name == "mod.rs" {
            continue;
        }
        if path.is_dir() {
            let module = path.join("mod.rs");
            if module.exists() {
                modules.push((name, module));
            }
        } else if let Some(stem) = name.strip_suffix(".rs") {
            modules.push((stem.to_string(), path.clone()));
        }
    }
    modules.sort();

    // `_name.rs` files are shared helpers for a group of services: always compiled, never registered, no feature of their own.
    let (helpers, modules): (Vec<_>, Vec<_>) = modules.into_iter().partition(|(n, _)| n.starts_with('_'));
    let mut code = String::new();
    let helper_attr = "#[cfg_attr(not(feature = \"all-services\"), \
        expect(clippy::allow_attributes, reason = \"generated: which helpers go unused depends on the features\"), \
        allow(dead_code, reason = \"helpers serve optional services\"))]";
    for (name, path) in &helpers {
        writeln!(code, "{helper_attr}\n#[path = {path:?}]\npub mod {name};").unwrap();
    }
    for (name, _) in &modules {
        assert!(
            name.starts_with(|c: char| c.is_ascii_lowercase())
                && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
            "service id `{name}`: use the brand name in lowercase letters and digits, without separators"
        );
        let feature = service_feature(name);
        assert!(
            features.contains(&feature),
            "service `{name}` has no Cargo feature: add `{feature} = []` to [features] in Cargo.toml"
        );
        assert!(all_services.contains(&feature), "`{feature}` is missing from `all-services` in Cargo.toml");
    }
    let gate = |name: &str| format!("#[cfg(feature = \"{}\")]\n", service_feature(name));
    for (name, path) in &modules {
        writeln!(code, "{}#[path = {path:?}]\npub mod {name};", gate(name)).unwrap();
    }
    code.push_str(
        "\n/// Every service compiled into this build.\npub static ALL: &[&crate::service::ServiceDef] = &[\n",
    );
    for (name, _) in &modules {
        writeln!(code, "    {}&{name}::SERVICE,", gate(name).replace('\n', "\n    ")).unwrap();
    }
    code.push_str("];\n");
    fs::write(out.join("services_generated.rs"), code).unwrap();

    for feature in features.iter().filter(|f| f.starts_with("service-")) {
        let gates = modules.iter().any(|(m, _)| service_feature(m) == **feature);
        let extends =
            table[*feature].iter().any(|f| f.starts_with("service-") && feature.starts_with(&format!("{f}-")));
        assert!(
            gates || extends,
            "`{feature}` names no service in src/services and turns on no `service-<id>` it extends"
        );
    }

    book_doctests(&root, &out);
    features_doc(&manifest, &table, &out);

    let mut tests = String::new();
    let fixtures_dir = root.join("tests/fixtures/services");
    if let Ok(dir) = fs::read_dir(&fixtures_dir) {
        let mut files: Vec<PathBuf> = dir
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        files.sort();
        for file in files {
            let stem = file.file_stem().unwrap().to_string_lossy().to_string();
            let service = stem.split("__").next().unwrap();
            let ident: String = stem.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
            let mut cfg = gate(service);
            // Desktop services only run on their own OS.
            match service {
                "macosx" => cfg.push_str("#[cfg(target_os = \"macos\")]\n"),
                "windows" => cfg.push_str("#[cfg(windows)]\n"),
                _ => {}
            }
            writeln!(tests, "{cfg}#[test]\nfn {ident}() {{ snapshot({stem:?}, {:?}); }}\n", display(&file)).unwrap();
        }
    }
    fs::write(out.join("fixtures_generated.rs"), tests).unwrap();
}

/// `service-googlechat` for `googlechat`; a fixture file `<id>-<variant>.json` maps to the feature `service-<id>-<variant>` (`matrix-e2ee.json`).
fn service_feature(id: &str) -> String {
    format!("service-{id}")
}

fn display(p: &Path) -> String {
    p.to_string_lossy().to_string()
}

/// Every Markdown page of the book runs as a doc-test (`lib.rs`, `mod book`), so its Rust examples keep compiling. The generated service pages are not included; the book is absent from the published crate.
fn book_doctests(root: &Path, out: &Path) {
    let book = root.join("../../docs/book/src");
    println!("cargo::rerun-if-changed={}", display(&book));
    let mut pages = Vec::new();
    collect_md(&book, &mut pages);
    pages.retain(|p| {
        !p.starts_with(book.join("services"))
            && !p.starts_with(book.join("generated"))
            && p.file_name().is_some_and(|n| n != "SUMMARY.md")
    });
    pages.sort();
    let mut code = String::new();
    for (i, page) in pages.iter().enumerate() {
        writeln!(code, "#[doc = include_str!({:?})]\nstruct Page{i};", display(page)).unwrap();
    }
    fs::write(out.join("book_generated.rs"), code).unwrap();
}

fn collect_md(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for path in entries.filter_map(|e| e.ok().map(|e| e.path())) {
        if path.is_dir() {
            collect_md(&path, out);
        } else if path.extension().is_some_and(|e| e == "md") {
            out.push(path);
        }
    }
}

/// Minimal parse of a manifest table whose values are string lists (`[features]`, `feature-services`): each key and its strings. Avoids a TOML dependency.
fn toml_table(manifest: &Path, header: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    let text = fs::read_to_string(manifest).unwrap();
    let mut in_features = false;
    let mut out = std::collections::BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        let line = line.split('#').next().unwrap().trim();
        if line.starts_with('[') && current.is_none() {
            in_features = line == header;
            continue;
        }
        if !in_features || line.is_empty() {
            continue;
        }
        let values = match line.split_once('=') {
            Some((key, rest)) if current.is_none() => {
                let key = key.trim().to_string();
                out.insert(key.clone(), Vec::new());
                current = Some(key);
                rest
            }
            _ => line,
        };
        let key = current.clone().unwrap();
        let entry = out.get_mut(&key).unwrap();
        entry.extend(values.split('"').skip(1).step_by(2).map(str::to_string));
        if values.contains(']') {
            current = None;
        }
    }
    out
}

/// The static site of a forge repository: GitHub, GitLab or Codeberg Pages. Another host needs `MERCURIO_PAGES_URL` set at build time.
fn pages_url(repository: &str) -> String {
    println!("cargo::rerun-if-env-changed=MERCURIO_PAGES_URL");
    if let Ok(url) = env::var("MERCURIO_PAGES_URL") {
        return url.trim_end_matches('/').to_string();
    }
    let path = repository.trim_end_matches('/').trim_end_matches(".git");
    let forges = [
        ("https://github.com/", "github.io"),
        ("https://gitlab.com/", "gitlab.io"),
        ("https://codeberg.org/", "codeberg.page"),
    ];
    let (rest, domain) = forges
        .iter()
        .find_map(|(prefix, domain)| path.strip_prefix(prefix).map(|rest| (rest, *domain)))
        .unwrap_or_else(|| panic!("no Pages site known for {repository}: set MERCURIO_PAGES_URL"));
    let (owner, repo) = rest.split_once('/').unwrap_or_else(|| panic!("{repository}: expected OWNER/REPO"));
    format!("https://{}.{domain}/{repo}", owner.to_lowercase())
}

/// The crate docs' feature table: every feature with a comment directly above it in `Cargo.toml`, in file order, with the features it turns on (a count for the `service-*` ones).
fn features_doc(manifest: &Path, table: &std::collections::BTreeMap<String, Vec<String>>, out: &Path) {
    let text = fs::read_to_string(manifest).unwrap();
    let mut doc = String::from("| Feature | Description | Turns on |\n|---|---|---|\n");
    let (mut in_features, mut comment) = (false, Vec::new());
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') && !line.starts_with("[\"") {
            in_features = line == "[features]";
            continue;
        }
        if !in_features {
            continue;
        }
        if let Some(c) = line.strip_prefix('#') {
            comment.push(c.trim().to_string());
            continue;
        }
        if let Some((key, _)) = line.split_once('=').filter(|_| !comment.is_empty()) {
            let key = key.trim();
            let features: Vec<&String> =
                table.get(key).into_iter().flatten().filter(|f| !f.starts_with("dep:")).collect();
            let services = features.iter().filter(|f| f.starts_with("service-")).count();
            let mut on: Vec<String> = features.iter().filter(|_| services <= 1).map(|f| format!("`{f}`")).collect();
            if services > 1 {
                on = vec![format!("{services} `service-*` features")];
                on.extend(features.iter().filter(|f| !f.starts_with("service-")).map(|f| format!("`{f}`")));
            }
            writeln!(doc, "| `{key}` | {} | {} |", comment.join(" "), on.join(", ")).unwrap();
        }
        comment.clear();
    }
    fs::write(out.join("features.md"), doc).unwrap();
}
