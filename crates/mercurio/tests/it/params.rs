//! The declared URL tokens and query parameters ([`mercurio::service::ServiceDef::params`]) match what the service sources read: the book pages are generated from them.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn services_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/services")
}

/// `name.rs` or every `.rs` file under `name/`.
fn module(name: &str) -> Vec<PathBuf> {
    let single = services_dir().join(format!("{name}.rs"));
    if single.exists() {
        return vec![single];
    }
    let mut out = Vec::new();
    let mut dirs = vec![services_dir().join(name)];
    while let Some(dir) = dirs.pop() {
        let Ok(entries) = fs::read_dir(&dir) else { continue };
        for path in entries.map(|e| e.unwrap().path()) {
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out
}

/// The module declaring service `id`, plus the helper and sibling modules it refers to (`super::_mail`, `services::emby`, ...), as one text.
fn sources(id: &str) -> String {
    let own = fs::read_dir(services_dir())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path().file_stem().unwrap().to_string_lossy().into_owned())
        .find(|name| {
            module(name).iter().any(|p| {
                let text = fs::read_to_string(p).unwrap();
                text.split("pub static SERVICE: ServiceDef")
                    .nth(1)
                    .is_some_and(|s| s.contains(&format!("id: \"{id}\"")))
            })
        })
        .unwrap_or_else(|| panic!("{id}: no module declares it"));
    let refs = regex::Regex::new(r"\b(?:super|services)::(\w+)|\b(_[a-z_]+)::").unwrap();
    let mut seen = BTreeSet::from([own.clone()]);
    let mut queue = vec![own];
    let mut text = String::new();
    while let Some(name) = queue.pop() {
        for path in module(&name) {
            let src = fs::read_to_string(path).unwrap();
            for c in refs.captures_iter(&src) {
                let next = c.get(1).or(c.get(2)).unwrap().as_str().to_string();
                if !module(&next).is_empty() && seen.insert(next.clone()) {
                    queue.push(next);
                }
            }
            text.push_str(&src);
        }
    }
    text
}

#[test]
fn declared_params_are_read_by_the_parser() {
    let mut errors = Vec::new();
    let accessor = regex::Regex::new(
        r#"(SERVICE|def)\.(?:raw|text|text_or_default|flag|flag_strict|int|int_or_default)\(\s*&?\w+,\s*"([^"]+)""#,
    )
    .unwrap();
    let function = regex::Regex::new(r"\n[ \t]*(?:pub(?:\([^)]*\))? )?fn (\w+)").unwrap();
    for def in mercurio::services() {
        // Literals outside the `SERVICE` declaration, which names every key.
        let src = sources(def.id);
        let code: String = src
            .split("pub static SERVICE: ServiceDef")
            .enumerate()
            .map(|(i, part)| if i == 0 { part } else { part.split_once("\n};").map_or("", |(_, rest)| rest) })
            .collect();
        for p in def.params.iter().filter(|p| p.prefix.is_empty() && !p.ignored) {
            for key in std::iter::once(&p.key).chain(p.aliases) {
                if !code.contains(&format!("\"{key}\"")) {
                    errors.push(format!("{}: `?{key}=` is declared but never read", def.id));
                }
            }
            for token in p.sets {
                if !def.tokens.iter().any(|t| t.key == *token) {
                    errors.push(format!("{}: `?{}=` sets the undeclared token {{{token}}}", def.id, p.key));
                }
            }
        }
        // `SERVICE.text(u, "key")` and the other accessors read declarations. A shared helper's `def.text(u, "key")` counts for the services that call the function it is in.
        let starts: Vec<(usize, &str)> =
            function.captures_iter(&src).map(|c| (c.get(0).unwrap().start(), c.get(1).unwrap().as_str())).collect();
        let called =
            |name: &str| src.matches(&format!("{name}(")).count() > src.matches(&format!("fn {name}(")).count();
        for c in accessor.captures_iter(&src) {
            let at = c.get(0).unwrap().start();
            let in_fn = starts.iter().rev().find(|(start, _)| *start < at).map_or("", |(_, name)| *name);
            if &c[1] == "def" && !called(in_fn) {
                continue;
            }
            let key = &c[2];
            if !def.params.iter().any(|p| p.key == key) {
                errors.push(format!("{}: `{}.*(u, \"{key}\")` reads an undeclared parameter", def.id, &c[1]));
            }
        }
        for template in def.templates {
            for token in template.split('{').skip(1).filter_map(|s| s.split_once('}')).map(|(t, _)| t) {
                if token != "schema" && !def.tokens.iter().any(|t| t.key == token) {
                    errors.push(format!("{}: {template} uses the undeclared token {{{token}}}", def.id));
                }
            }
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// Every fixture case that leaves a declared query parameter out records the same result with `?key=<declared default>` added: the default the book shows is the one the parser applies. `Param::inferred` parameters, whose value without the key depends on the rest of the URL, are skipped. One valid case per service and parameter is checked.
#[test]
fn declared_defaults_are_the_parser_defaults() {
    use mercurio::testing::fixtures::{record_case, with_defaults};
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/services");
    let mut errors = BTreeSet::new();
    let mut checked = BTreeSet::new();
    let mut files: Vec<PathBuf> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
    files.sort();
    for file in files {
        let mut doc: serde_json::Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        let stem = file.file_stem().unwrap().to_string_lossy().into_owned();
        doc["service"] = serde_json::json!(stem.split("__").next().unwrap());
        for case in doc["cases"].as_array().unwrap() {
            let Some(url) = case["url"].as_str() else { continue };
            let Some(scheme) = url.split_once("://").map(|(s, _)| s.to_lowercase()) else { continue };
            let Some(def) = mercurio::services().iter().find(|d| d.handles(&scheme)) else { continue };
            let query = url.split_once('?').map_or("", |(_, q)| q);
            let present =
                |k: &str| query.split('&').any(|kv| kv.split('=').next().is_some_and(|x| x.eq_ignore_ascii_case(k)));
            let todo: Vec<_> = def
                .params
                .iter()
                .filter(|p| p.prefix.is_empty() && !p.default.is_empty() && !p.inferred)
                .filter(|p| !std::iter::once(&p.key).chain(p.aliases).any(|k| present(k)))
                .filter(|p| !checked.contains(&(def.id, p.key)))
                .collect();
            if todo.is_empty() {
                continue;
            }
            let case = with_defaults(&doc, case);
            let base = record_case(&doc, &case);
            if base["valid"] != serde_json::json!(true) {
                continue;
            }
            for p in todo {
                checked.insert((def.id, p.key));
                let sep = if url.contains('?') { '&' } else { '?' };
                let value: String = p
                    .default
                    .bytes()
                    .map(|b| {
                        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                            (b as char).to_string()
                        } else {
                            format!("%{b:02X}")
                        }
                    })
                    .collect();
                let mut with = case.clone();
                with["url"] = serde_json::json!(format!("{url}{sep}{}={value}", p.key));
                let got = record_case(&doc, &with);
                if got != base {
                    let mut changes = Vec::new();
                    diff("", &base, &got, &mut changes);
                    errors.insert(format!(
                        "{}: ?{}={} (declared default) changes {stem}/{}: {}",
                        def.id,
                        p.key,
                        p.default,
                        case["name"].as_str().unwrap_or(""),
                        changes.into_iter().take(2).collect::<Vec<_>>().join("; ")
                    ));
                }
            }
        }
    }
    assert!(
        errors.is_empty(),
        "fix the declared default or the parser, else mark the parameter `.inferred()`:\n{}",
        errors.into_iter().collect::<Vec<_>>().join("\n")
    );
}

/// The JSON pointers where `a` and `b` differ, with both values.
fn diff(path: &str, a: &serde_json::Value, b: &serde_json::Value, out: &mut Vec<String>) {
    use serde_json::Value::{Array, Null, Object};
    match (a, b) {
        (Object(x), Object(y)) => {
            for k in x.keys().chain(y.keys()).collect::<BTreeSet<_>>() {
                diff(&format!("{path}/{k}"), x.get(k).unwrap_or(&Null), y.get(k).unwrap_or(&Null), out);
            }
        }
        (Array(x), Array(y)) if x.len() == y.len() => {
            for (i, (p, q)) in x.iter().zip(y).enumerate() {
                diff(&format!("{path}/{i}"), p, q, out);
            }
        }
        _ if a != b => out.push(format!("{path}: {} -> {}", short(a), short(b))),
        _ => {}
    }
}

fn short(v: &serde_json::Value) -> String {
    let s = v.to_string();
    if s.chars().count() > 90 { format!("{}...", s.chars().take(90).collect::<String>()) } else { s }
}

/// [`mercurio::service::COMMON_PARAMS`] matches what the URL parser and the target builder read, and its numeric defaults are the ones they apply.
#[test]
fn common_params_match_the_parser() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let code = ["url.rs", "target.rs"].map(|f| fs::read_to_string(root.join(f)).unwrap()).join("\n");
    let code = code.split("pub static COMMON_PARAMS").next().unwrap().to_string()
        + code.split("pub static COMMON_PARAMS").nth(1).and_then(|s| s.split_once("\n];")).map_or("", |(_, rest)| rest);
    let declared: BTreeSet<&str> = mercurio::service::COMMON_PARAMS
        .iter()
        .flat_map(|p| std::iter::once(p.key).chain(p.aliases.iter().copied()))
        .collect();
    let read = regex::Regex::new(r#"(?:query\.get|parsed\.param)\("([a-z_]+)"\)"#).unwrap();
    let read: BTreeSet<&str> = read.captures_iter(&code).map(|c| c.get(1).unwrap().as_str()).collect();
    let ignored: BTreeSet<&str> =
        mercurio::service::COMMON_PARAMS.iter().filter(|p| p.ignored).map(|p| p.key).collect();
    let unread: Vec<_> = declared.difference(&read).filter(|k| !ignored.contains(*k)).collect();
    let undeclared: Vec<_> = read.difference(&declared).collect();
    assert!(unread.is_empty(), "declared in COMMON_PARAMS but never read: {unread:?}");
    assert!(undeclared.is_empty(), "read by the parser but not in COMMON_PARAMS: {undeclared:?}");

    let retry = mercurio::service::COMMON_PARAMS.iter().find(|p| p.key == "retry").unwrap();
    let wait = mercurio::service::COMMON_PARAMS.iter().find(|p| p.key == "wait").unwrap();
    assert!(code.contains(&format!("const MAX_RETRY: u32 = {};", retry.max.unwrap())));
    assert!(code.contains(&format!("parsed.retry.unwrap_or({}).min(MAX_RETRY)", retry.default)));
    assert!(code.contains(&format!("const DEFAULT_WAIT: f64 = {};", wait.default)));
    assert!(code.contains(&format!("const MAX_WAIT: f64 = {}.0;", wait.max.unwrap())));
    assert!(code.contains(&format!("parsed.wait.unwrap_or(DEFAULT_WAIT).clamp({}.0, MAX_WAIT)", wait.min.unwrap())));
}
