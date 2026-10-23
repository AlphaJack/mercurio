//! `regex` against `regex-lite` (feature `regex-unicode` picks the engine): every pattern literal in `src/` passed to `regex!`, `validate_regex` or `validate_regex_fmt` must compile in both and match ASCII input the same way. Non-ASCII input may differ (`regex-lite` classes and case folding are ASCII-only); those differences are printed with `--nocapture`.

use std::path::{Path, PathBuf};

/// Sample values: tokens, hosts, addresses, phone numbers, and the Unicode cases where the engines part.
const PROBES: &[&str] = &[
    "",
    " ",
    "abc",
    "ABC",
    "abc123",
    "a-b_c.d",
    "0123456789",
    "+1 (555) 123-4567",
    "user@example.com",
    "https://example.com/path?x=1",
    "example.com:8080",
    "127.0.0.1",
    "[::1]",
    "#channel",
    "@user",
    "a, b; c",
    "key=value",
    "2026-10-23T12:00:00Z",
    "Mon, 23 Oct 2026 12:00:00 +0000",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef",
    "xoxb-1234-5678-abcdefghijklmnop",
    "{{ token }}",
    "# heading",
    "line one\nline two",
    "\tTab",
    "é",
    "Éabc",
    "жук",
    "\u{663}\u{664}",
    "a\u{A0}b",
    "\u{2003}",
    "日本語",
    "ß",
    "ǅ",
];

#[derive(Debug)]
struct Pattern {
    file: String,
    line: usize,
    /// As compiled: `validate_regex` patterns get its flags and start anchor.
    source: String,
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The string literal starting at `s` (`"..."`, `r"..."`, `r#"..."#`) and the text after it.
fn literal(s: &str) -> Option<(String, &str)> {
    if let Some(raw) = s.strip_prefix('r') {
        let body = raw.trim_start_matches('#');
        let close = format!("\"{}", "#".repeat(raw.len() - body.len()));
        let (pattern, rest) = body.strip_prefix('"')?.split_once(&close)?;
        return Some((pattern.to_string(), rest));
    }
    let body = s.strip_prefix('"')?;
    let (mut out, mut chars) = (String::new(), body.char_indices());
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Some((out, body.get(i + 1..)?)),
            '\\' => match chars.next()?.1 {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                '\n' => {}
                e => out.push(e),
            },
            c => out.push(c),
        }
    }
    None
}

/// The first string literal in `s`; an `r` inside an identifier does not start one.
fn next_literal(s: &str) -> Option<(String, &str)> {
    let mut prev = ' ';
    let start = s.char_indices().find_map(|(i, c)| {
        let rest = s.get(i..)?;
        let word = prev.is_alphanumeric() || prev == '_';
        prev = c;
        (c == '"' || (!word && (rest.starts_with("r\"") || rest.starts_with("r#\"")))).then_some(rest)
    })?;
    literal(start)
}

fn patterns() -> Vec<Pattern> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files.sort();
    let mut out = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        let name = file.strip_prefix(root).unwrap().display().to_string();
        for (at, _) in text.match_indices("regex!(") {
            let (before, call) = text.split_at(at);
            // The macro definition itself.
            if before.ends_with("macro_rules! ") {
                continue;
            }
            let args = call.trim_start_matches("regex!(").trim_start();
            if let Some((source, _)) = literal(args) {
                out.push(Pattern { file: name.clone(), line: before.matches('\n').count() + 1, source });
            }
        }
        for call in ["validate_regex(", "validate_regex_fmt("] {
            for (at, _) in text.match_indices(call) {
                let (before, args) = text.split_at(at);
                if before.ends_with("fn ") {
                    continue;
                }
                // The value is not a literal; the pattern and flags are the next two.
                let args = args.trim_start_matches(call);
                let Some((pattern, rest)) = next_literal(args) else { continue };
                // A pattern built at run time (`&format!("x{i}")`) is not a literal.
                if args.strip_suffix(rest).is_some_and(|head| head.contains("format!(")) {
                    continue;
                }
                let flags = rest.trim_start().strip_prefix(',').and_then(|r| literal(r.trim_start())).map(|f| f.0);
                let flags: String = flags.unwrap_or_default().chars().filter(|c| "imsx".contains(*c)).collect();
                let prefix = if flags.is_empty() { String::new() } else { format!("(?{flags})") };
                let source = format!("{prefix}^(?:{pattern})");
                out.push(Pattern { file: name.clone(), line: before.matches('\n').count() + 1, source });
            }
        }
    }
    out
}

/// Every match of `re` in `probe`, as byte ranges of each capture group.
macro_rules! matches {
    ($re:expr, $probe:expr) => {
        $re.captures_iter($probe)
            .map(|c| c.iter().map(|m| m.map(|m| m.range())).collect::<Vec<_>>())
            .collect::<Vec<_>>()
    };
}

#[test]
fn patterns_agree_between_engines() {
    let patterns = patterns();
    assert!(patterns.len() > 150, "found only {} patterns: is the extraction broken?", patterns.len());
    let (mut failures, mut unicode) = (Vec::new(), Vec::new());
    for p in &patterns {
        let full = match regex::Regex::new(&p.source) {
            Ok(re) => re,
            Err(e) => {
                failures.push(format!("{}:{}: regex rejects {:?}: {e}", p.file, p.line, p.source));
                continue;
            }
        };
        let lite = match regex_lite::Regex::new(&p.source) {
            Ok(re) => re,
            Err(e) => {
                failures.push(format!("{}:{}: regex-lite rejects {:?}: {e}", p.file, p.line, p.source));
                continue;
            }
        };
        for probe in PROBES {
            let (a, b) = (matches!(full, probe), matches!(lite, probe));
            if a != b {
                let msg = format!("{}:{}: {:?} on {probe:?}: regex {a:?}, regex-lite {b:?}", p.file, p.line, p.source);
                if probe.is_ascii() { failures.push(msg) } else { unicode.push(msg) }
            }
        }
    }
    println!("{} patterns; {} differ on non-ASCII input:", patterns.len(), unicode.len());
    for u in &unicode {
        println!("  {u}");
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
