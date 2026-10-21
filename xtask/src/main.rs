//! Repository tasks, run as `cargo xtask <task>`.
//!
//! `cargo xtask docs` generates the service pages, `--help` output and YAML key tables, builds the rustdoc API docs (warnings are errors), runs the doc-tests (crate docs and the book's Rust examples), builds the mdBook, copies the icons and the API docs into it. Needs mdBook (`cargo install mdbook`).
//!
//! Output: `docs/book/book/` (site) and `docs/book/book/api/` (rustdoc).
//!
//! `cargo xtask new <id>` writes a service module and its fixture to start from.
//!
//! `cargo xtask try URL...` sends a set of test messages (types, formats, a long body, an attachment) to real endpoints with the working-tree code.

mod library;
mod new;
mod pages;
mod try_url;
mod vars;
mod yaml;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["docs"] => docs(),
        ["new", id] => new::scaffold(&root(), id),
        ["try", urls @ ..] => try_url::run(&root(), urls),
        ["mdbook-vars", rest @ ..] => vars::run(rest),
        _ => Err("usage: cargo xtask docs | cargo xtask new <id> | cargo xtask try URL...".to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn docs() -> Result<(), String> {
    let root = root();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());

    eprintln!("==> service pages");
    let out = Command::new(&cargo)
        .current_dir(&root)
        .args(["run", "-q", "-p", "mercurio-cli", "--", "services", "--json"])
        .output()
        .map_err(|e| format!("cargo: {e}"))?;
    if !out.status.success() {
        return Err(format!("mercurio services --json: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let services = serde_json::from_slice(&out.stdout).map_err(|e| format!("mercurio services --json: {e}"))?;
    pages::generate(&root, services)?;

    eprintln!("==> command line help");
    let out = Command::new(&cargo)
        .current_dir(&root)
        .args(["run", "-q", "-p", "mercurio-cli", "--", "--help"])
        .output()
        .map_err(|e| format!("cargo: {e}"))?;
    if !out.status.success() {
        return Err(format!("mercurio --help: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let generated = root.join("docs/book/src/generated");
    std::fs::create_dir_all(&generated).map_err(|e| format!("{}: {e}", generated.display()))?;
    std::fs::write(generated.join("cli-help.txt"), &out.stdout).map_err(|e| format!("cli-help.txt: {e}"))?;

    // `serve --help` repeats the global options; the book shows the server's own.
    let out = Command::new(&cargo)
        .current_dir(&root)
        .args(["run", "-q", "-p", "mercurio-cli", "--", "serve", "--help"])
        .output()
        .map_err(|e| format!("cargo: {e}"))?;
    if !out.status.success() {
        return Err(format!("mercurio serve --help: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let help = String::from_utf8_lossy(&out.stdout);
    for (heading, file) in [
        ("Server settings", "serve-settings.txt"),
        ("Endpoints", "serve-endpoints.txt"),
        ("Request fields", "serve-fields.txt"),
        ("Headers", "serve-headers.txt"),
    ] {
        let section = help
            .split_once(&format!("{heading}:\n"))
            .map(|(_, rest)| rest.split("\n\n").next().unwrap_or(rest))
            .ok_or(format!("serve --help: no {heading} section"))?;
        std::fs::write(generated.join(file), section.trim_end()).map_err(|e| format!("{file}: {e}"))?;
    }

    eprintln!("==> YAML configuration tables");
    yaml::render(&root)?;

    std::fs::write(generated.join("common-params.md"), pages::common_params_table())
        .map_err(|e| format!("common-params.md: {e}"))?;

    library::render(&root)?;

    // The icons are published next to the book; services link to them.
    let icons = root.join("docs/book/src/assets/icons");
    std::fs::create_dir_all(&icons).map_err(|e| format!("{}: {e}", icons.display()))?;
    for name in ["logo.svg", "logo.png", "LICENSE"] {
        let from = root.join("crates/mercurio/assets").join(name);
        std::fs::copy(&from, icons.join(name)).map_err(|e| format!("{}: {e}", from.display()))?;
    }

    eprintln!("==> rustdoc (warnings are errors)");
    run(Command::new(&cargo).current_dir(&root).env("RUSTDOCFLAGS", "-D warnings").args([
        "doc",
        "-q",
        "-p",
        "mercurio",
        "--features",
        "transport-blocking",
        "--no-deps",
    ]))?;

    eprintln!("==> doc-tests (crate docs and the book's Rust examples)");
    run(Command::new(&cargo).current_dir(&root).args([
        "test",
        "-q",
        "--doc",
        "-p",
        "mercurio",
        "--features",
        "transport-blocking",
    ]))?;

    eprintln!("==> mdbook");
    let repository = mercurio::asset::REPOSITORY_URL;
    run(Command::new("mdbook")
        .current_dir(&root)
        .env("MDBOOK_BOOK__DESCRIPTION", env!("CARGO_PKG_DESCRIPTION"))
        .env("MDBOOK_OUTPUT__HTML__GIT_REPOSITORY_URL", repository)
        .env("MDBOOK_OUTPUT__HTML__EDIT_URL_TEMPLATE", format!("{repository}/edit/main/docs/book/{{path}}"))
        .args(["build", "docs/book"]))?;

    let target = std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    let api = root.join("docs/book/book/api");
    if api.exists() {
        std::fs::remove_dir_all(&api).map_err(|e| format!("{}: {e}", api.display()))?;
    }
    copy_dir(&target.join("doc"), &api)?;
    eprintln!("==> done: open docs/book/book/index.html (API docs: docs/book/book/api/mercurio/index.html)");
    Ok(())
}

fn run(cmd: &mut Command) -> Result<(), String> {
    let status = cmd.status().map_err(|e| format!("{cmd:?}: {e}"))?;
    if status.success() { Ok(()) } else { Err(format!("{cmd:?} failed ({status})")) }
}

fn copy_dir(from: &Path, to: &Path) -> Result<(), String> {
    let err = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
    std::fs::create_dir_all(to).map_err(|e| err(to, e))?;
    for entry in std::fs::read_dir(from).map_err(|e| err(from, e))? {
        let entry = entry.map_err(|e| err(from, e))?;
        let (src, dst) = (entry.path(), to.join(entry.file_name()));
        if entry.file_type().map_err(|e| err(&src, e))?.is_dir() {
            copy_dir(&src, &dst)?;
        } else {
            std::fs::copy(&src, &dst).map_err(|e| err(&src, e))?;
        }
    }
    Ok(())
}
