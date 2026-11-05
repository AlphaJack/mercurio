//! The code conventions in CONTRIBUTING that a test can check, read from the sources with `syn`, in one binary.

#![expect(clippy::unwrap_used, reason = "a test fails loudly")]

use std::{
    fs,
    path::{Path, PathBuf},
};

mod paths;

/// The workspace's folder.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// The source folders of every package: `src` and `tests` of each crate and of xtask.
fn source_dirs() -> Vec<PathBuf> {
    let mut packages: Vec<PathBuf> =
        fs::read_dir(root().join("crates")).unwrap().map(|entry| entry.unwrap().path()).collect();
    packages.push(root().join("xtask"));
    packages.sort();
    packages.iter().flat_map(|p| [p.join("src"), p.join("tests")]).filter(|d| d.is_dir()).collect()
}

/// Each `.rs` file under `dir`, with its path from the workspace's folder.
fn sources(dir: &Path, found: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let file = path.strip_prefix(root()).unwrap_or(&path).display().to_string();
            found.push((file, fs::read_to_string(&path).unwrap()));
        }
    }
}

/// Every source file of the workspace, as its path and its text.
fn all_sources() -> Vec<(String, String)> {
    let mut found = Vec::new();
    for dir in source_dirs() {
        sources(&dir, &mut found);
    }
    found
}
