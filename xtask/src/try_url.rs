//! Send a fixed set of messages to real endpoints with the code in the working tree, to see how a service renders them.

use std::path::Path;
use std::process::Command;

fn cases(attachment: &str) -> Vec<(&'static str, Vec<String>)> {
    let s = |v: &[&str]| v.iter().map(|x| (*x).to_string()).collect::<Vec<_>>();
    let long = "Long body that has to be split or truncated. ".repeat(150);
    vec![
        ("text, info", s(&["-t", "mercurio try: info", "-b", "Plain text body."])),
        ("success", s(&["-n", "success", "-t", "mercurio try: success", "-b", "It worked."])),
        ("warning", s(&["-n", "warning", "-t", "mercurio try: warning", "-b", "Something to check."])),
        ("failure", s(&["-n", "failure", "-t", "mercurio try: failure", "-b", "It failed."])),
        ("no title", s(&["-b", "A body without a title."])),
        (
            "markdown",
            s(&[
                "-i",
                "markdown",
                "-t",
                "mercurio try: markdown",
                "-b",
                "# Heading\n\n**bold**, *italic*, `code`, [link](https://example.org)\n\n- one\n- two",
            ]),
        ),
        (
            "html",
            s(&[
                "-i",
                "html",
                "-t",
                "mercurio try: html",
                "-b",
                "<h1>Heading</h1><p><b>bold</b> <i>italic</i> <a href=\"https://example.org\">link</a></p><ul><li>one</li><li>two</li></ul>",
            ]),
        ),
        ("long body", vec!["-t".into(), "mercurio try: long body".into(), "-b".into(), long]),
        ("attachment", s(&["-t", "mercurio try: attachment", "-b", "With a PNG attached.", "-a", attachment])),
    ]
}

pub fn run(root: &Path, urls: &[&str]) -> Result<(), String> {
    if urls.is_empty() {
        return Err("usage: cargo xtask try URL... (URLs of real endpoints you own)".to_owned());
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let status = Command::new(&cargo)
        .current_dir(root)
        .args(["build", "-q", "-p", "mercurio-cli"])
        .status()
        .map_err(|e| format!("cargo: {e}"))?;
    if !status.success() {
        return Err("cargo build failed".to_owned());
    }
    let target = std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), Into::into);
    let bin = target.join("debug").join(if cfg!(windows) { "mercurio.exe" } else { "mercurio" });
    let png = std::env::temp_dir().join("mercurio-try.png");
    std::fs::copy(root.join("crates/mercurio/assets/logo.png"), &png).map_err(|e| format!("{}: {e}", png.display()))?;

    let mut failed = 0;
    for (label, args) in cases(&png.to_string_lossy()) {
        let out = Command::new(&bin).args(&args).args(urls).output().map_err(|e| format!("{}: {e}", bin.display()))?;
        let err = String::from_utf8_lossy(&out.stderr);
        let first = err.lines().next().unwrap_or("");
        let code = out.status.code().unwrap_or(-1);
        if code != 0 {
            failed += 1;
        }
        eprintln!("{:<12} exit {code}  {first}", label);
    }
    eprintln!("{failed} of {} sends failed; check how each one looks on the service", cases("").len());
    if failed > 0 { Err(format!("{failed} sends failed")) } else { Ok(()) }
}
