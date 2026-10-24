//! Random and mutated URLs, titles and bodies through every compiled service, with random server responses. Nothing may panic.
//!
//! `MERCURIO_FUZZ_ITERS=200000 MERCURIO_FUZZ_SEED=42 cargo test --test it fuzz --release` runs a long session; the default is a quick CI-sized pass.

use std::panic::{AssertUnwindSafe, catch_unwind};

use mercurio::testing::FakeTransport;
use mercurio::{Asset, Attachment, Message, NotifyFormat, NotifyType, transport::Response};

/// splitmix64: tiny, deterministic, good enough for input generation.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

const ATOMS: &[&str] = &[
    "",
    "a",
    "user",
    "pass",
    "host",
    "example.com",
    "127.0.0.1",
    "[::1]",
    "8080",
    "65536",
    "0",
    "token",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
    "1234567890",
    "+15551234567",
    "@user",
    "#chan",
    "!room:example.org",
    "a@b.co",
    "%",
    "%2",
    "%zz",
    "%00",
    "%FF",
    "%E2%9C%93",
    "é",
    "日本",
    "🦀",
    "\u{0}",
    "\u{202e}",
    " ",
    "\t",
    "\n",
    "/",
    "//",
    "\\",
    ":",
    "::",
    "@",
    "@@",
    "?",
    "&",
    "=",
    "#",
    "+",
    "-",
    ";",
    ",",
    "*",
    "[",
    "]",
    "{",
    "}",
    "<",
    ">",
    "\"",
    "'",
    "..",
    "~",
    "verify=no",
    "format=html",
    "format=markdown",
    "overflow=split",
    "overflow=truncate",
    "cto=0",
    "rto=-1",
    "retry=3",
    "wait=0",
    "priority=high",
    "priority=-5",
    "mode=x",
    "to=",
    "+X-H=v",
    "-drop",
    ":key=",
    ":k=v",
    "method=GET",
    "method=invalid",
    "tag=a,b",
    "user=x",
    "password=y",
];

const BODIES: &[&str] = &[
    "",
    "hello",
    "line1\nline2\r\nline3",
    "<b>html</b> & <script>",
    "**md** _x_ `c` [l](http://x)",
    "\u{0}\u{1}\u{7f}",
    "🦀 unicode ✓ 日本語",
    "a\u{301}",
    "\\",
    "\"quoted\"",
    "{\"json\": true}",
    "%s %d {} {{}}",
    "${HOME}",
    "\r",
    " ",
    "\t\t",
];

fn rand_text(rng: &mut Rng, max_atoms: usize) -> String {
    let mut s = String::new();
    for _ in 0..rng.below(max_atoms + 1) {
        if rng.chance(70) {
            s.push_str(rng.pick::<&str>(BODIES));
        } else {
            s.push_str(rng.pick::<&str>(ATOMS));
        }
    }
    if rng.chance(3) {
        s = s.repeat(1 + rng.below(2000));
    }
    s
}

fn rand_url(rng: &mut Rng, schemes: &[&'static str], seeds: &[String]) -> String {
    if !seeds.is_empty() && rng.chance(40) {
        // Mutate a known-good URL: insert, delete or replace a chunk.
        let mut s: Vec<char> = rng.pick(seeds).chars().collect();
        for _ in 0..1 + rng.below(3) {
            let pos = rng.below(s.len() + 1);
            match rng.below(3) {
                0 => drop(s.splice(pos..pos, rng.pick(ATOMS).chars())),
                1 if pos < s.len() => {
                    let end = (pos + 1 + rng.below(4)).min(s.len());
                    drop(s.drain(pos..end));
                }
                _ if pos < s.len() => s[pos] = *rng.pick(&['/', '@', ':', '?', '&', '%', '#', ' ', 'x']),
                _ => {}
            }
        }
        return s.into_iter().collect();
    }
    let mut url = format!("{}://", *rng.pick(schemes));
    for _ in 0..rng.below(8) {
        url.push_str(rng.pick::<&str>(ATOMS));
        if rng.chance(40) {
            url.push('/');
        }
    }
    if rng.chance(60) {
        url.push('?');
        for i in 0..rng.below(5) {
            if i > 0 {
                url.push('&');
            }
            url.push_str(rng.pick::<&str>(ATOMS));
        }
    }
    url
}

fn rand_response(rng: &mut Rng) -> Response {
    let status = *rng.pick(&[200u16, 200, 200, 201, 204, 302, 400, 401, 403, 404, 429, 500, 503, 0, 999]);
    let body: String = match rng.below(6) {
        0 => String::new(),
        1 => "{}".into(),
        2 => r#"{"ok": true, "result": {"message_id": 1}, "id": "x", "status": "success", "errors": []}"#.into(),
        3 => r#"{"ok": false, "error": "server error", "data": null, "items": [1, "2", {"a": []}]}"#.into(),
        4 => rand_text(rng, 4),
        _ => "<html>not json</html>".into(),
    };
    let mut r = Response::new(status, body);
    if rng.chance(30) {
        r = r.with_header("Retry-After", (*rng.pick(&["1", "-1", "abc", "99999999999"])).to_string());
    }
    r
}

/// URLs from the fixtures, as mutation seeds.
fn seed_urls() -> Vec<String> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/services");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let Ok(text) = std::fs::read_to_string(entry.path()) else { continue };
        let Ok(doc) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
        for case in doc["cases"].as_array().into_iter().flatten() {
            if let Some(u) = case["url"].as_str() {
                out.push(u.to_string());
            }
        }
    }
    out.sort();
    out
}

#[test]
fn nothing_panics() {
    let iters: usize = std::env::var("MERCURIO_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(3000);
    let seed: u64 = std::env::var("MERCURIO_FUZZ_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x5EED);
    let schemes: Vec<&'static str> = mercurio::services().iter().flat_map(|d| d.schemes.iter().copied()).collect();
    // Without services there is nothing to fuzz.
    if schemes.is_empty() {
        return;
    }
    let seeds = seed_urls();
    let mut rng = Rng(seed);
    let asset = Asset::default();
    let mut parsed_ok = 0usize;

    for i in 0..iters {
        let url = rand_url(&mut rng, &schemes, &seeds);
        let mut msg = Message::new(rand_text(&mut rng, 3)).title(rand_text(&mut rng, 2));
        msg.kind = *rng.pick(&NotifyType::ALL);
        msg.format =
            *rng.pick(&[None, Some(NotifyFormat::Text), Some(NotifyFormat::Html), Some(NotifyFormat::Markdown)]);
        if rng.chance(10) {
            msg.attachments.push(Attachment::new(rand_text(&mut rng, 1), "image/png", vec![0u8, 1, 2, 255]));
        }
        let fake = FakeTransport::new();
        for _ in 0..rng.below(4) {
            fake.respond_with(rand_response(&mut rng));
        }
        if rng.chance(10) {
            fake.fail(mercurio::Error::transport("connection reset"));
        }
        fake.default_response(rand_response(&mut rng));

        let result = catch_unwind(AssertUnwindSafe(|| {
            if let Ok(target) = mercurio::parse(&url) {
                let _ = target.send(&msg, &fake, &asset);
                true
            } else {
                false
            }
        }));
        match result {
            Ok(ok) => parsed_ok += ok as usize,
            Err(_) => panic!(
                "panic at iteration {i} (seed {seed}):\n  url={url:?}\n  title={:?}\n  body={:?}",
                msg.title, msg.body
            ),
        }
    }
    eprintln!("fuzz: {iters} iterations, {parsed_ok} URLs parsed and sent");
}
