//! End-to-end tests of the `mercurio` binary against a local HTTP server.

#![expect(clippy::unwrap_used, reason = "test code fails loudly")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;

fn tempdir(tag: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "mercurio-cli-{}-{tag}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::remove_dir_all(&d).ok();
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Variables the default configuration paths are built from (`~` and the Windows folders).
const HOME_VARS: [&str; 6] =
    ["HOME", "APPDATA", "LOCALAPPDATA", "ALLUSERSPROFILE", "PROGRAMFILES", "COMMONPROGRAMFILES"];

/// The binary with a clean environment and empty home folders, so the user's own configuration files are never picked up.
fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_mercurio"));
    let home = tempdir("home");
    for v in HOME_VARS {
        c.env(v, &home);
    }
    for v in [
        "APPRISE_URLS",
        "APPRISE_CONFIG_PATH",
        "APPRISE_CONFIG",
        "APPRISE_STORAGE_PATH",
        "APPRISE_STORAGE_PRUNE_DAYS",
        "APPRISE_STORAGE_UID_LENGTH",
    ] {
        c.env_remove(v);
    }
    c
}

/// One-shot server answering `status`; yields the request body.
fn server(status: u16) -> (String, mpsc::Receiver<Vec<u8>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut r = BufReader::new(s.try_clone().unwrap());
        let mut len = 0;
        loop {
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            if line.trim().is_empty() {
                break;
            }
            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                len = v.trim().parse().unwrap();
            }
        }
        let mut body = vec![0; len];
        r.read_exact(&mut body).unwrap();
        tx.send(body).unwrap();
        write!(s, "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    });
    (addr, rx)
}

fn json(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).unwrap()
}

#[test]
fn sends_title_and_body() {
    let (addr, rx) = server(200);
    let out = bin().args(["-t", "T", "-b", "B", "-n", "warning", &format!("json://{addr}")]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let v = json(&rx.recv().unwrap());
    assert_eq!(
        (v["title"].as_str(), v["message"].as_str(), v["type"].as_str()),
        (Some("T"), Some("B"), Some("warning"))
    );
}

#[test]
fn emoji_shortcodes_follow_j_and_the_url() {
    // (CLI flag, URL query, expected body), as Apprise: -j turns them on unless the URL says no; a URL alone can turn them on.
    for (flag, query, expected) in [
        (None, "", "deploy :rocket:"),
        (Some("-j"), "", "deploy 🚀"),
        (Some("-j"), "?emojis=no", "deploy :rocket:"),
        (None, "?emojis=yes", "deploy 🚀"),
    ] {
        let (addr, rx) = server(200);
        let url = format!("json://{addr}{query}");
        let mut c = bin();
        c.args(["-b", "deploy :rocket:", "-t", ":warning:"]).args(flag).arg(&url);
        assert!(c.status().unwrap().success(), "{flag:?} {query}");
        let v = json(&rx.recv().unwrap());
        assert_eq!(v["message"], expected, "{flag:?} {query}");
        let title = if expected.contains('🚀') { "⚠️" } else { ":warning:" };
        assert_eq!(v["title"], title, "{flag:?} {query}");
    }
}

#[test]
fn attaches_files_with_url_options() {
    let dir = std::env::temp_dir().join(format!("mercurio-cli-attach-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("data.bin");
    std::fs::write(&path, b"hello").unwrap();
    let (addr, rx) = server(200);
    let spec = format!("file://{}?name=report.csv", path.display());
    let out = bin().args(["-b", "B", "-a", &spec, &format!("json://{addr}")]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let v = json(&rx.recv().unwrap());
    assert_eq!(v["attachments"][0]["filename"], "report.csv");
    assert_eq!(v["attachments"][0]["mimetype"], "text/csv");
    assert_eq!(v["attachments"][0]["base64"], "aGVsbG8=");
    // A missing file or an invalid option stops before sending.
    let missing = dir.join("missing.txt");
    let out = bin().args(["-b", "B", "-a", missing.to_str().unwrap(), "json://localhost"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let out = bin().args(["-b", "B", "-a", &format!("{spec}&mime=invalid"), "json://localhost"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn reads_body_from_stdin_and_escapes() {
    let (addr, rx) = server(200);
    let mut child = bin().args(["-e", &format!("json://{addr}")]).stdin(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"a\\nb").unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(0));
    assert_eq!(json(&rx.recv().unwrap())["message"], "a\nb");
}

#[test]
fn urls_from_environment() {
    let (addr, rx) = server(200);
    let out = bin().env("APPRISE_URLS", format!("json://{addr}")).args(["-b", "env"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(json(&rx.recv().unwrap())["message"], "env");
    // Only the Apprise names are read.
    let out = bin().env("MERCURIO_URLS", format!("json://{addr}")).args(["-b", "env"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn exit_codes() {
    let (addr, _rx) = server(500);
    assert_eq!(bin().args(["-b", "x", &format!("json://{addr}")]).output().unwrap().status.code(), Some(1));
    assert_eq!(bin().args(["-b", "x"]).output().unwrap().status.code(), Some(2));
    assert_eq!(bin().args(["--no-such-flag"]).output().unwrap().status.code(), Some(2));
    assert_eq!(
        bin().args(["-b", "x", "-g", "missing", "json://localhost?tag=a"]).output().unwrap().status.code(),
        Some(3)
    );
    assert_eq!(bin().args(["check", "unknown://x"]).output().unwrap().status.code(), Some(1));
    // -SM takes auto, flush or memory, as Apprise.
    assert_eq!(
        bin().args(["-d", "-b", "x", "-SM", "flush", "json://localhost"]).output().unwrap().status.code(),
        Some(0)
    );
    assert_eq!(
        bin().args(["-d", "-b", "x", "-SM", "often", "json://localhost"]).output().unwrap().status.code(),
        Some(2)
    );
}

#[test]
fn dry_run_and_services() {
    let out = bin().args(["-d", "json://localhost", "gotify://localhost/token"]).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("json://") && text.contains("gotify://"), "{text}");
    let out = bin().args(["services", "--json"]).output().unwrap();
    let list: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(list.as_array().unwrap().iter().any(|s| s["id"] == "gotify"));
}

fn write(dir: &std::path::Path, name: &str, content: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    p.to_string_lossy().into_owned()
}

/// Exit code plus stdout and stderr.
fn run(c: &mut Command) -> (Option<i32>, String) {
    let out = c.output().unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr))
}

/// Entries listed by `--dry-run`.
fn listed(text: &str) -> usize {
    text.lines().filter(|l| l.trim_start().split_once(". ").is_some_and(|(n, _)| n.parse::<u32>().is_ok())).count()
}

#[test]
fn config_file_and_tags() {
    let (addr, rx) = server(200);
    let dir = tempdir("cfg");
    let cfg = write(
        &dir,
        "m.yml",
        &format!("urls:\n  - json://{addr}/dev:\n      tag: dev, ops\n  - json://localhost:1/prod:\n      tag: prod\n"),
    );
    let out = bin().args(["-b", "hi", "-c", &cfg, "-g", "dev"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(json(&rx.recv().unwrap())["message"], "hi");

    // Without --tag only untagged services are notified: none here.
    assert_eq!(bin().args(["-b", "x", "-c", &cfg]).output().unwrap().status.code(), Some(3));
    // "a,b" in one --tag requires both; separate --tag values are alternatives.
    let (code, text) = run(bin().args(["-d", "-c", &cfg, "-g", "dev,prod"]));
    assert_eq!(code, Some(3), "{text}");
    let (code, text) = run(bin().args(["-d", "-c", &cfg, "-g", "dev,ops"]));
    assert_eq!((code, listed(&text)), (Some(0), 1), "{text}");
    assert!(text.contains("tags: dev, ops"), "{text}");
    let (_, text) = run(bin().args(["-d", "-c", &cfg, "-g", "dev", "-g", "prod"]));
    assert_eq!(listed(&text), 2, "{text}");
    let (_, text) = run(bin().args(["-d", "-c", &cfg, "-g", "all"]));
    assert_eq!(listed(&text), 2, "{text}");
}

#[test]
fn text_config_untagged_and_always() {
    let dir = tempdir("text");
    let cfg = write(&dir, "m.conf", "json://localhost/plain\nalways=json://localhost/always\nx=json://localhost/x\n");
    let (code, text) = run(bin().args(["-d", "--config", &cfg]));
    assert_eq!((code, listed(&text)), (Some(0), 1), "{text}");
    let (_, text) = run(bin().args(["-d", "--config", &cfg, "--tag", "x"]));
    assert_eq!(listed(&text), 2, "{text}");
    assert!(text.contains("tags: x") && text.contains("tags: always"), "{text}");
}

#[test]
fn template_vars() {
    let (addr, rx) = server(200);
    let dir = tempdir("tpl");
    let cfg = write(&dir, "t.yml", "template:\n  - host\n  - path: def\nurls:\n  - json://${HOST}/${PATH}\n");
    let (code, text) = run(bin().args(["-d", "-c", &cfg]));
    assert_eq!(code, Some(0));
    assert!(text.contains("unresolved") && text.contains("host (required), path (has default)"), "{text}");

    let out = bin().args(["-b", "tv", "-c", &cfg, "-tv", &format!("host={addr}")]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(json(&rx.recv().unwrap())["message"], "tv");

    // A missing value fails that entry.
    assert_eq!(bin().args(["-b", "x", "-c", &cfg]).output().unwrap().status.code(), Some(1));
    // Malformed and repeated names are usage errors; values are never echoed.
    let (code, text) = run(bin().args(["-b", "x", "-c", &cfg, "-tv", "bad-name=secret"]));
    assert_eq!(code, Some(2));
    assert!(!text.contains("secret"), "{text}");
    assert_eq!(
        bin().args(["-b", "x", "-c", &cfg, "-tv", "a=1", "--template-var", "A=2"]).output().unwrap().status.code(),
        Some(2)
    );
}

#[test]
fn default_config_paths() {
    // `~/.config/apprise/apprise.yml`; `%APPDATA%\Apprise\apprise.yml` on Windows.
    let home = tempdir("defhome");
    let dir = if cfg!(windows) { home.join("Apprise") } else { home.join(".config/apprise") };
    std::fs::create_dir_all(&dir).unwrap();
    write(&dir, "apprise.yml", "urls:\n  - json://localhost/fromhome\n");
    let (code, text) = run(bin().env("HOME", &home).env("APPDATA", &home).args(["-d"]));
    assert_eq!((code, listed(&text)), (Some(0), 1), "{text}");

    // mercurio's own names are not searched.
    let home = tempdir("mercuriohome");
    std::fs::create_dir_all(home.join(".config/mercurio")).unwrap();
    write(&home.join(".config/mercurio"), "mercurio.yml", "urls:\n  - json://localhost/fromhome\n");
    let (code, _) = run(bin().env("HOME", &home).env("APPDATA", &home).args(["-d"]));
    assert_eq!(code, Some(2));

    let home = tempdir("apprisehome");
    if !cfg!(windows) {
        write(&home, ".apprise", "json://localhost/legacy\n");
        let (code, text) = run(bin().env("HOME", &home).args(["-d"]));
        assert_eq!((code, listed(&text)), (Some(0), 1), "{text}");
    }

    // The environment replaces the default list.
    let dir = tempdir("envpath");
    let cfg = write(&dir, "a.txt", "json://localhost/env\njson://localhost/env2\n");
    let (code, text) =
        run(bin().env("HOME", &home).env("APPRISE_CONFIG_PATH", format!("/nonexistent;{cfg}")).args(["-d"]));
    assert_eq!((code, listed(&text)), (Some(0), 2), "{text}");
    let (code, _) = run(bin().env("HOME", &home).env("APPRISE_CONFIG_PATH", "/nonexistent").args(["-d"]));
    assert_eq!(code, Some(2));
}

#[test]
fn includes_follow_recursion_depth() {
    let dir = tempdir("inc");
    write(&dir, "b.cfg", "json://localhost/b\n");
    write(&dir, "a.cfg", "include b.cfg\njson://localhost/a\n");
    let main = write(&dir, "main.cfg", "include a.cfg\njson://localhost/main\n");
    let count = |extra: &[&str]| listed(&run(bin().args(["-d", "-c", &main]).args(extra)).1);
    assert_eq!(count(&[]), 2);
    assert_eq!(count(&["-R", "0"]), 1);
    assert_eq!(count(&["--recursion-depth", "2"]), 3);
}

#[test]
fn storage_list_prune_and_clear() {
    let store = tempdir("store");
    let s = store.to_string_lossy().into_owned();
    let url = "json://localhost/hook";
    // A configured URL that never stored anything: listed as unused.
    let (code, text) = run(bin().args(["storage", "-S", &s, url]));
    assert_eq!(code, Some(0), "{text}");
    let first = text.lines().next().unwrap_or_default().to_string();
    assert!(first.ends_with("unused"), "{text}");
    assert!(text.contains("- json://localhost/"), "{text}");
    let uid = first.split_whitespace().nth(1).unwrap().to_string();
    assert_eq!(uid.len(), 8);
    // -SUL sets the id length (Apprise's -SUL); below 2 is a usage error.
    let (_, text) = run(bin().args(["storage", "-S", &s, "-SUL", "12", url]));
    let long = text.lines().next().unwrap_or_default().split_whitespace().nth(1).unwrap_or_default().to_string();
    assert!(long.len() == 12 && long.starts_with(&uid), "{text}");
    let (code, text) = run(bin().args(["storage", "-S", &s, "-SUL", "1"]));
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("can not be lower than two (2)"), "{text}");

    // Files on disk: active for the URL, stale otherwise.
    for ns in [uid.as_str(), "deadbeef"] {
        std::fs::create_dir_all(store.join(ns)).unwrap();
        std::fs::write(store.join(ns).join("cache.json"), b"{}").unwrap();
    }
    let (_, text) = run(bin().args(["storage", "-S", &s, url]));
    assert!(text.lines().next().unwrap().ends_with("active"), "{text}");
    let (_, text) = run(bin().args(["storage", "-S", &s]));
    assert!(text.contains("deadbeef") && text.contains("stale"), "{text}");

    // Prune keeps recent files; a dry-run clear removes nothing.
    let (code, _) = run(bin().args(["storage", "prune", "-S", &s]));
    assert_eq!(code, Some(0));
    assert!(store.join("deadbeef").join("cache.json").exists());
    let (_, text) = run(bin().args(["storage", "clear", "-d", "-S", &s, "dead"]));
    assert!(text.contains("would remove"), "{text}");
    assert!(store.join("deadbeef").exists());
    let (code, _) = run(bin().args(["storage", "clear", "-S", &s, "dead"]));
    assert_eq!(code, Some(0));
    assert!(!store.join("deadbeef").exists());
    assert!(store.join(&uid).join("cache.json").exists());
}
