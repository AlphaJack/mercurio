//! `mercurio serve`: the HTTP notification API.

#![expect(clippy::unwrap_used, reason = "test code fails loudly")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;

struct Server {
    child: Child,
    addr: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.child.kill().ok();
    }
}

fn start(config_dir: &std::path::Path) -> Server {
    start_with(config_dir, &[])
}

fn start_with(config_dir: &std::path::Path, env: &[(&str, &str)]) -> Server {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mercurio"));
    cmd.args(["serve", "--bind", "127.0.0.1:0"]).env("APPRISE_CONFIG_DIR", config_dir);
    for (k, _) in std::env::vars() {
        if k.starts_with("APPRISE_") && k != "APPRISE_CONFIG_DIR" {
            cmd.env_remove(k);
        }
    }
    cmd.envs(env.iter().copied());
    let mut child = cmd.stdout(Stdio::piped()).spawn().unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    let addr = line.trim().rsplit("http://").next().unwrap().to_string();
    Server { child, addr }
}

/// Upstream target: records request bodies, answers `status`.
fn upstream(n: usize, status: u16) -> (String, mpsc::Receiver<serde_json::Value>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for s in l.incoming().take(n) {
            let mut s = s.unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut len = 0;
            loop {
                let mut h = String::new();
                r.read_line(&mut h).unwrap();
                if h.trim().is_empty() {
                    break;
                }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
            }
            let mut b = vec![0; len];
            r.read_exact(&mut b).unwrap();
            tx.send(serde_json::from_slice(&b).unwrap_or_default()).ok();
            write!(s, "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        }
    });
    (addr, rx)
}

fn http(addr: &str, method: &str, path: &str, ctype: &str, body: &str) -> (u16, String) {
    let (status, _, body) = http_full(addr, method, path, &[("Content-Type", ctype)], body);
    (status, body)
}

/// A request with extra headers; returns status, raw headers and body.
fn http_full(addr: &str, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> (u16, String, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    let mut head =
        format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    write!(s, "{head}\r\n{body}").unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let status = out.split_whitespace().nth(1).unwrap().parse().unwrap();
    let (head, body) = out.split_once("\r\n\r\n").map(|(h, b)| (h.to_string(), b.to_string())).unwrap_or_default();
    (status, head, body)
}

fn tmpdir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("mercurio-serve-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&d).ok();
    d
}

#[cfg(unix)]
#[expect(clippy::disallowed_methods, reason = "polling a real child process requires wall-clock waits")]
fn stops_on_signal(signal: &str) {
    let mut server = start(&tmpdir(signal));
    let _idle = TcpStream::connect(&server.addr).unwrap();
    assert!(Command::new("kill").args([signal, &server.child.id().to_string()]).status().unwrap().success());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        if let Some(status) = server.child.try_wait().unwrap() {
            assert!(status.success(), "server exited unsuccessfully: {status}");
            break;
        }
        assert!(std::time::Instant::now() < deadline, "server did not stop on {signal}");
        thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(unix)]
#[test]
fn stops_on_sigint() {
    stops_on_signal("-INT");
}

#[cfg(unix)]
#[test]
fn stops_on_sigterm() {
    stops_on_signal("-TERM");
}

#[test]
fn status_and_details() {
    let s = start(&tmpdir("status"));
    assert_eq!(http(&s.addr, "GET", "/status", "text/plain", ""), (200, "OK".into()));
    let (code, body) = http(&s.addr, "GET", "/details", "text/plain", "");
    assert_eq!(code, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let gotify = v["schemas"].as_array().unwrap().iter().find(|s| s["service_name"] == "Gotify").unwrap();
    assert!(gotify["setup_url"].as_str().unwrap().ends_with("/services/gotify.html"), "{gotify}");
    assert_eq!(gotify["details"]["tokens"]["token"]["required"], true);
    assert!(gotify.get("enabled").is_none());
    assert_eq!(v["asset"]["app_id"], "Mercurio");
    let (_, body) = http(&s.addr, "GET", "/details?all=yes", "text/plain", "");
    assert!(body.contains(r#""enabled":false"#), "?all=yes lists the denied services");
}

#[test]
fn stateless_form_and_json() {
    let s = start(&tmpdir("stateless"));
    let (up, rx) = upstream(2, 200);
    let form = format!("urls=json://{up}&body=hello&title=t&type=success");
    assert_eq!(http(&s.addr, "POST", "/notify/", "application/x-www-form-urlencoded", &form).0, 200);
    let v = rx.recv().unwrap();
    assert_eq!((v["message"].as_str(), v["type"].as_str()), (Some("hello"), Some("success")));
    let json = format!(r#"{{"urls": "json://{up}", "body": "from json"}}"#);
    assert_eq!(http(&s.addr, "POST", "/notify", "application/json", &json).0, 200);
    assert_eq!(rx.recv().unwrap()["message"], "from json");
}

#[test]
fn stateless_errors() {
    let s = start(&tmpdir("errors"));
    assert_eq!(http(&s.addr, "POST", "/notify", "application/json", r#"{"body": "x"}"#).0, 400);
    assert_eq!(http(&s.addr, "POST", "/notify", "application/json", r#"{"urls": "unknown://x", "body": "x"}"#).0, 400);
    let (up, _rx) = upstream(1, 500);
    let json = format!(r#"{{"urls": "json://{up}", "body": "x"}}"#);
    assert_eq!(http(&s.addr, "POST", "/notify", "application/json", &json).0, 424);
    assert_eq!(http(&s.addr, "GET", "/unknown-path", "text/plain", "").0, 404);
    // Attachment fields may only reference hosted content.
    let json = format!(r#"{{"urls": "json://{up}", "body": "x", "attach": "/etc/passwd"}}"#);
    assert_eq!(http(&s.addr, "POST", "/notify", "application/json", &json).0, 400);
    let json = format!(r#"{{"urls": "json://{up}", "body": "x", "attachment": "file:///etc/hosts"}}"#);
    assert_eq!(http(&s.addr, "POST", "/notify", "application/json", &json).0, 400);
}

#[test]
fn stateful_keys_and_tags() {
    let s = start(&tmpdir("stateful"));
    let (up, rx) = upstream(2, 200);
    let config = format!("config=ops%3Djson%3A%2F%2F{up}%2Fops%0Adev%3Djson%3A%2F%2F{up}%2Fdev&format=text");
    assert_eq!(http(&s.addr, "POST", "/add/mykey", "application/x-www-form-urlencoded", &config).0, 200);
    let (code, cfg) = http(&s.addr, "POST", "/get/mykey", "text/plain", "");
    assert_eq!(code, 200);
    assert!(cfg.contains("ops=json://"));
    assert_eq!(http(&s.addr, "POST", "/notify/mykey", "application/json", r#"{"body": "b", "tag": "ops"}"#).0, 200);
    assert_eq!(rx.recv().unwrap()["message"], "b");
    assert_eq!(http(&s.addr, "POST", "/notify/mykey", "application/json", r#"{"body": "b", "tag": "nomatch"}"#).0, 424);
    assert_eq!(http(&s.addr, "POST", "/del/mykey", "text/plain", "").0, 200);
    assert_eq!(http(&s.addr, "POST", "/get/mykey", "text/plain", "").0, 204);
    // Invalid keys match no route.
    assert_eq!(http(&s.addr, "POST", "/add/bad%20key", "application/x-www-form-urlencoded", "urls=json://x").0, 404);
}

fn json_body(v: serde_json::Value) -> String {
    serde_json::to_string(&v).unwrap()
}

#[test]
fn stateful_yaml_tags_and_templates() {
    let s = start(&tmpdir("yaml"));
    let (up, rx) = upstream(3, 200);
    let yaml = format!(
        "version: 1\ntag: team\ntemplate:\n  - path: fallback\nurls:\n  - json://{up}/${{PATH}}:\n      tag: dev, ops\n  - json://{up}/prod:\n      tag: prod\n"
    );
    let add = json_body(serde_json::json!({"config": yaml, "format": "yaml"}));
    assert_eq!(http(&s.addr, "POST", "/add/y", "application/json", &add).0, 200);
    let (code, cfg) = http(&s.addr, "POST", "/get/y", "text/plain", "");
    assert_eq!((code, cfg.contains("template:")), (200, true));

    // Tags per URL, plus the union.
    let (code, body) = http(&s.addr, "GET", "/json/urls/y", "text/plain", "");
    assert_eq!(code, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["tags"], serde_json::json!(["dev", "ops", "prod", "team"]));
    assert_eq!(v["urls"][0]["tags"], serde_json::json!(["dev", "ops", "team"]));
    assert!(body.contains("/prod"), "URLs are shown in full: {body}");
    let (_, private) = http(&s.addr, "GET", "/json/urls/y?privacy=1", "text/plain", "");
    assert!(!private.contains("/prod"), "privacy=1 hides URL details: {private}");
    assert_eq!(v["urls"][0]["template"], serde_json::json!({"path": "fallback"}));
    let (_, body) = http(&s.addr, "GET", "/json/urls/y?tag=prod", "text/plain", "");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["urls"].as_array().unwrap().len(), 1);

    // "dev ops" requires both tags; "dev, prod" matches either.
    let both = json_body(serde_json::json!({"body": "both", "tag": "dev ops"}));
    assert_eq!(http(&s.addr, "POST", "/notify/y", "application/json", &both).0, 200);
    assert_eq!(rx.recv().unwrap()["message"], "both");
    let none = json_body(serde_json::json!({"body": "x", "tag": "dev prod"}));
    assert_eq!(http(&s.addr, "POST", "/notify/y", "application/json", &none).0, 424);
    let tv = json_body(serde_json::json!({"body": "tv", "tag": "dev", "template": {"path": "custom"}}));
    assert_eq!(http(&s.addr, "POST", "/notify/y", "application/json", &tv).0, 200);
    assert_eq!(rx.recv().unwrap()["message"], "tv");
    let either = json_body(serde_json::json!({"body": "e", "tag": "missing, prod"}));
    assert_eq!(http(&s.addr, "POST", "/notify/y", "application/json", &either).0, 200);
    assert_eq!(rx.recv().unwrap()["message"], "e");

    // Detected format, invalid YAML, unknown format.
    let detected = json_body(serde_json::json!({"config": "urls:\n  - json://localhost/a\n"}));
    assert_eq!(http(&s.addr, "POST", "/add/d", "application/json", &detected).0, 200);
    let (_, cfg) = http(&s.addr, "POST", "/get/d", "text/plain", "");
    assert!(cfg.starts_with("urls:"), "{cfg}");
    let bad = json_body(serde_json::json!({"config": "urls: [unclosed\n", "format": "yaml"}));
    assert_eq!(http(&s.addr, "POST", "/add/b", "application/json", &bad).0, 400);
    let fmt = json_body(serde_json::json!({"config": "json://localhost", "format": "toml"}));
    assert_eq!(http(&s.addr, "POST", "/add/b", "application/json", &fmt).0, 400);

    // Replacing a YAML config with TEXT keeps one stored copy.
    assert_eq!(http(&s.addr, "POST", "/add/y", "application/x-www-form-urlencoded", "urls=json://localhost").0, 200);
    let (_, cfg) = http(&s.addr, "POST", "/get/y", "text/plain", "");
    assert_eq!(cfg, "json://localhost");
    assert_eq!(http(&s.addr, "POST", "/del/y", "text/plain", "").0, 200);
    assert_eq!(http(&s.addr, "POST", "/get/y", "text/plain", "").0, 204);
}

fn form(addr: &str, path: &str, body: &str) -> (u16, String) {
    http(addr, "POST", path, "application/x-www-form-urlencoded", body)
}

#[test]
fn untagged_default_and_stateless_tags() {
    let s = start(&tmpdir("untagged"));
    let (up, rx) = upstream(3, 200);
    let config = format!("json://{up}/plain\nops=json://{up}/ops");
    let add = json_body(serde_json::json!({"config": config}));
    assert_eq!(http(&s.addr, "POST", "/add/k", "application/json", &add).0, 200);
    assert_eq!(form(&s.addr, "/notify/k", "body=untagged").0, 200);
    assert_eq!(rx.recv().unwrap()["message"], "untagged");
    assert!(rx.recv_timeout(std::time::Duration::from_millis(300)).is_err());
    assert_eq!(form(&s.addr, "/notify/missing", "body=x").0, 404);
    // Stateless honours tags; a non-matching tag sends nothing (424).
    let urls = format!("urls=json://{up}");
    assert_eq!(form(&s.addr, "/notify", &format!("{urls}&body=x&tag=nomatch")).0, 424);
    assert_eq!(form(&s.addr, "/notify", &format!("{urls}&body=all")).0, 200);
    assert_eq!(rx.recv().unwrap()["message"], "all");
    assert_eq!(form(&s.addr, "/notify", &format!("{urls}&body=x&tag=bad;tag")).0, 400);
}

#[test]
fn responses_follow_accept_and_content_type() {
    let s = start(&tmpdir("accept"));
    let (up, _rx) = upstream(3, 200);
    let json = format!(r#"{{"urls": "json://{up}", "body": "j"}}"#);
    let (code, body) = http(&s.addr, "POST", "/notify", "application/json", &json);
    assert_eq!(code, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"], serde_json::Value::Null);
    assert_eq!(v["details"][0][0], "INFO");
    let (code, body) = form(&s.addr, "/notify", &format!("urls=json://{up}&body=t"));
    assert_eq!(code, 200);
    assert!(body.contains(" - INFO - Sent "), "{body}");
    let hdrs = [("Accept", "application/json"), ("Content-Type", "text/plain")];
    let (code, _, body) = http_full(&s.addr, "POST", "/notify", &hdrs, "x");
    assert_eq!((code, body.as_str()), (400, r#"{"error":"There was no valid URLs provided to notify"}"#));
    let (_, body) = http(&s.addr, "GET", "/status", "application/json", "");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"]["details"], serde_json::json!(["OK"]));
    assert_eq!(v["max_attachments"], 6);
}

#[test]
fn headers_plain_text_and_field_mapping() {
    let s = start(&tmpdir("headers"));
    let (up, rx) = upstream(4, 200);
    assert_eq!(form(&s.addr, "/add/h", &format!("urls=json://{up}")).0, 200);
    let hdrs = [("Content-Type", "text/plain"), ("X-Apprise-Title", "T1"), ("X-Apprise-Type", "warning")];
    assert_eq!(http_full(&s.addr, "POST", "/notify/h", &hdrs, "plain body").0, 200);
    let v = rx.recv().unwrap();
    let got = (v["message"].as_str(), v["title"].as_str(), v["type"].as_str());
    assert_eq!(got, (Some("plain body"), Some("T1"), Some("warning")));
    // A header fills a field the payload left out; the payload wins.
    let hdrs = [("Content-Type", "application/json"), ("X-Apprise-Title", "A"), ("X-Apprise-Type", "failure")];
    assert_eq!(http_full(&s.addr, "POST", "/notify/h", &hdrs, r#"{"body": "b", "type": "success"}"#).0, 200);
    let v = rx.recv().unwrap();
    assert_eq!((v["title"].as_str(), v["type"].as_str()), (Some("A"), Some("success")));
    // Field mapping, nested paths included.
    let mapped = r#"{"subject": "S", "event": {"items": [{"text": "nested"}]}}"#;
    let path = "/notify/h?:subject=title&:event.items[0].text=body";
    assert_eq!(http(&s.addr, "POST", path, "application/json", mapped).0, 200);
    let v = rx.recv().unwrap();
    assert_eq!((v["message"].as_str(), v["title"].as_str()), (Some("nested"), Some("S")));
    assert_eq!(http(&s.addr, "POST", "/notify/h?:missing.x=body", "application/json", mapped).0, 400);
    // Recursion guard and template header.
    let hdrs = [("Content-Type", "text/plain"), ("X-Apprise-Recursion-Count", "2")];
    assert_eq!(http_full(&s.addr, "POST", "/notify/h", &hdrs, "x").0, 406);
    let hdrs = [("Content-Type", "text/plain"), ("X-Apprise-Template", "bad%zz=1")];
    assert_eq!(http_full(&s.addr, "POST", "/notify/h", &hdrs, "x").0, 400);
    let att = r#"{"body": "a", "attachment": [{"base64": "aGVsbG8=", "filename": "h.txt"}]}"#;
    assert_eq!(http(&s.addr, "POST", "/notify/h", "application/json", att).0, 200);
    assert_eq!(rx.recv().unwrap()["attachments"][0]["filename"], "h.txt");
}

#[test]
fn storage_layouts_list_move_and_metrics() {
    // Hash mode (default): two-character hash directories.
    let dir = tmpdir("hash");
    let s = start_with(&dir, &[("SECRET_KEY", "s3cret")]);
    let ct = [("Content-Type", "application/x-www-form-urlencoded")];
    let (code, head, _) = http_full(&s.addr, "POST", "/add/abc", &ct, "urls=json://localhost");
    assert_eq!(code, 200);
    assert!(head.contains("X-Apprise-Config-Created"), "{head}");
    let entries: Vec<String> =
        std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
    assert!(entries.iter().any(|e| e.len() == 2), "{entries:?}");
    assert_eq!(http(&s.addr, "GET", "/cfg", "application/json", "").0, 403);
    drop(s);

    // Simple mode: {key}.cfg / {key}.yml, listed by GET /cfg.
    let dir = tmpdir("simple");
    let s = start_with(&dir, &[("APPRISE_STATEFUL_MODE", "simple")]);
    assert_eq!(form(&s.addr, "/add/one", "urls=json://localhost").0, 200);
    assert!(dir.join("one.cfg").is_file());
    let (code, body) = http(&s.addr, "GET", "/cfg", "application/json", "");
    assert_eq!((code, body.as_str()), (200, r#"["one"]"#));
    // Move by header key; conflicts and missing sources.
    let hdrs = [("Content-Type", "application/json"), ("X-Apprise-Config-ID", "one")];
    assert_eq!(http_full(&s.addr, "POST", "/move", &hdrs, r#"{"to": "two"}"#).0, 200);
    assert!(dir.join("two.cfg").is_file() && !dir.join("one.cfg").exists());
    assert_eq!(http(&s.addr, "POST", "/move/one", "application/json", r#"{"to": "three"}"#).0, 404);
    assert_eq!(form(&s.addr, "/add/one", "urls=json://localhost").0, 200);
    assert_eq!(http(&s.addr, "POST", "/move/one", "application/json", r#"{"to": "two"}"#).0, 409);
    assert_eq!(http(&s.addr, "POST", "/get", "text/plain", "").0, 400);
    let (code, body) = http(&s.addr, "GET", "/metrics", "text/plain", "");
    assert_eq!(code, 200);
    assert!(body.contains("apprise_django_http_responses_total_by_status_total{status=\"409\"} 1.0"), "{body}");
    drop(s);

    // Disabled: stateful endpoints answer 403.
    let s = start_with(&tmpdir("disabled"), &[("APPRISE_STATEFUL_MODE", "disabled")]);
    assert_eq!(form(&s.addr, "/add/one", "urls=json://localhost").0, 403);
}

const ADMIN: &str = "Basic YWRtaW46cHc="; // admin:pw
const ALICE: &str = "Basic YWxpY2U6czNjcmV0"; // alice:s3cret
const ALICE_BAD: &str = "Basic YWxpY2U6YmFk"; // alice:bad

/// A per-key login as stored on disk (pbkdf2_sha256 with 1000 rounds keeps tests fast).
fn write_lock(dir: &std::path::Path, key: &str, access: &str) {
    std::fs::create_dir_all(dir).unwrap();
    let digest = "pbkdf2_sha256$1000$abcdefghijklmnopqrstuv$0bWOjLdUgcZwzhy0sj5Z6UTFDDggoi0g7CPA7gPzYZ4=";
    let rec = serde_json::json!({"access": access, "username": "alice", "digest": digest});
    std::fs::write(dir.join(format!(".{key}.lock")), rec.to_string()).unwrap();
}

#[test]
fn authentication_and_access_modes() {
    let dir = tmpdir("auth");
    write_lock(&dir, "k", "user");
    write_lock(&dir, "d", "disabled");
    let env = [
        ("APPRISE_AUTH_REQUIRED", "yes"),
        ("APPRISE_USER", "admin"),
        ("APPRISE_PASSWORD", "pw"),
        ("APPRISE_STATEFUL_MODE", "simple"),
    ];
    let s = start_with(&dir, &env);
    let (up, rx) = upstream(3, 200);
    let call = |method: &str, path: &str, auth: Option<&str>, ctype: &str, body: &str| {
        let mut h = vec![("Content-Type", ctype)];
        if let Some(a) = auth {
            h.push(("Authorization", a));
        }
        let (code, head, body) = http_full(&s.addr, method, path, &h, body);
        (code, head, body)
    };
    let form = "application/x-www-form-urlencoded";

    // Global gate: unkeyed routes need the administrator.
    let (code, head, _) = call("GET", "/status", None, "text/plain", "");
    assert_eq!(code, 401);
    assert!(head.to_lowercase().contains("www-authenticate: basic realm=\"mercurio api\""), "{head}");
    assert_eq!(call("GET", "/status", Some(ADMIN), "text/plain", "").0, 200);
    assert_eq!(call("GET", "/metrics", None, "text/plain", "").0, 401);
    assert_eq!(call("GET", "/metrics", Some(ADMIN), "text/plain", "").0, 200);

    let add = format!("config=json://{up}/a\npub=json://{up}/pub");
    assert_eq!(call("POST", "/add/k", None, form, &add).0, 401);
    assert_eq!(call("POST", "/add/k", Some(ALICE_BAD), form, &add).0, 401);
    assert_eq!(call("POST", "/add/k", Some(ALICE), form, &add).0, 200);
    assert_eq!(call("POST", "/get/k", Some(ALICE), "text/plain", "").0, 200);
    assert_eq!(call("GET", "/status/k", Some(ALICE), "text/plain", "").0, 200);
    let (_, _, body) = call("GET", "/auth/k", Some(ALICE), "application/json", "");
    assert_eq!(body, r#"{"access":"user","mode":"assigned","username":"alice"}"#);
    // A disabled login is refused even with the right password.
    assert_eq!(call("POST", "/get/d", Some(ALICE), "text/plain", "").0, 403);

    // Stateless sends: a user login needs its Config-ID header.
    let urls = format!("urls=json://{up}&body=s");
    assert_eq!(call("POST", "/notify", Some(ALICE), form, &urls).0, 401);
    let h = [("Content-Type", form), ("Authorization", ALICE), ("X-Apprise-Config-ID", "k")];
    assert_eq!(http_full(&s.addr, "POST", "/notify", &h, &urls).0, 200);
    assert_eq!(rx.recv().unwrap()["message"], "s");

    // Public access: no login, but a specific tag.
    assert_eq!(call("POST", "/add/p", Some(ADMIN), form, &add).0, 200);
    assert_eq!(call("POST", "/auth/p", Some(ADMIN), "application/json", r#"{"access": "public"}"#).0, 200);
    assert_eq!(call("POST", "/notify/p", None, form, "body=x").0, 400);
    assert_eq!(call("POST", "/notify/p", None, form, "body=x&tag=all").0, 400);
    assert_eq!(call("POST", "/notify/p", None, form, "body=public&tag=pub").0, 200);
    assert_eq!(rx.recv().unwrap()["message"], "public");
    assert_eq!(call("POST", "/get/p", None, "text/plain", "").0, 401);

    // Listing and removing logins are for the administrator.
    let (code, _, body) = call("GET", "/cfg", Some(ADMIN), "application/json", "");
    assert_eq!(code, 200);
    assert!(body.contains(r#"{"access":"user","key":"k","user":"alice"}"#), "{body}");
    assert_eq!(call("DELETE", "/auth/k", Some(ALICE), "text/plain", "").0, 403);
    assert_eq!(call("DELETE", "/auth/k", Some(ADMIN), "text/plain", "").0, 200);
    assert!(!dir.join(".k.lock").exists());
    drop(s);

    // With authentication off, /auth is unavailable and locks are ignored.
    let s = start_with(&dir, &[("APPRISE_STATEFUL_MODE", "simple")]);
    assert_eq!(http(&s.addr, "GET", "/auth/d", "text/plain", "").0, 403);
    assert_eq!(http(&s.addr, "POST", "/get/p", "text/plain", "").0, 200);
}

#[test]
fn config_lock_hides_content() {
    let s = start_with(&tmpdir("lock"), &[("APPRISE_CONFIG_LOCK", "yes")]);
    let (up, rx) = upstream(1, 200);
    assert_eq!(form(&s.addr, "/add/x", &format!("urls=json://{up}")).0, 403);
    assert_eq!(http(&s.addr, "POST", "/get/x", "text/plain", "").0, 403);
    assert_eq!(http(&s.addr, "GET", "/json/urls/x", "text/plain", "").0, 403);
    let (_, body) = http(&s.addr, "GET", "/status", "application/json", "");
    assert!(body.contains(r#""config_lock":true"#), "{body}");
    // Stateless notifications keep working.
    assert_eq!(form(&s.addr, "/notify", &format!("urls=json://{up}&body=ok")).0, 200);
    assert_eq!(rx.recv().unwrap()["message"], "ok");
}

#[test]
fn service_and_attachment_filters_and_webhook() {
    let (hook, hooks) = upstream(1, 200);
    let webhook = format!("http://{hook}/result");
    let env = [("APPRISE_DENY_SERVICES", "form"), ("APPRISE_WEBHOOK_URL", webhook.as_str())];
    let s = start_with(&tmpdir("filters"), &env);
    let (up, rx) = upstream(1, 200);
    // A denied service is skipped like an unknown URL.
    assert_eq!(form(&s.addr, "/notify", &format!("urls=form://{up}&body=x")).0, 400);
    let (_, details) = http(&s.addr, "GET", "/details", "application/json", "");
    assert!(!details.contains("\"Form\""), "denied services are hidden");
    // Local attachment URLs are rejected by default.
    let att = format!("urls=json://{up}&body=x&attach=http://127.0.0.1:9/a.png");
    assert_eq!(form(&s.addr, "/notify", &att).0, 400);
    // The result webhook receives every call's outcome.
    assert_eq!(form(&s.addr, "/notify", &format!("urls=json://{up}&body=hooked")).0, 200);
    assert_eq!(rx.recv().unwrap()["message"], "hooked");
    let v = hooks.recv().unwrap();
    assert_eq!(v["status"], 0);
    assert_eq!(v["output"][0][0], "INFO");
    drop(s);

    // An allow list replaces the deny list; attachment rules can be opened up.
    let (files, downloads) = upstream(1, 200);
    let env = [("APPRISE_ALLOW_SERVICES", "json"), ("APPRISE_ATTACH_REJECT_URL", "")];
    let s = start_with(&tmpdir("filters2"), &env);
    let (up, rx) = upstream(1, 200);
    assert_eq!(form(&s.addr, "/notify", &format!("urls=form://{up}&body=x")).0, 400);
    let att = format!("urls=json://{up}&body=x&attach=http://{files}/a.txt");
    assert_eq!(form(&s.addr, "/notify", &att).0, 200);
    assert!(downloads.recv().is_ok());
    assert_eq!(rx.recv().unwrap()["message"], "x");
}

#[test]
fn live_streams_log_levels_and_storage() {
    let dir = tmpdir("stream");
    let store = dir.join("custom-store");
    let s = start_with(&dir, &[("APPRISE_STORAGE_DIR", store.to_str().unwrap())]);
    let (up, rx) = upstream(3, 200);
    let urls = format!("urls=json://{up}&body=live");
    let ct = ("Content-Type", "application/x-www-form-urlencoded");
    let (code, head, body) = http_full(&s.addr, "POST", "/notify?stream=yes", &[ct], &urls);
    assert_eq!(code, 200);
    assert!(head.contains("text/event-stream"), "{head}");
    assert!(body.contains(": connected"), "{body}");
    assert!(body.contains("event: log"), "{body}");
    assert!(body.contains(r#"event: result"#) && body.contains(r#"{"status":"SUCCESS"}"#), "{body}");
    assert_eq!(rx.recv().unwrap()["message"], "live");
    let (_, _, body) = http_full(&s.addr, "POST", "/notify", &[ct, ("Accept", "text/event-stream")], &urls);
    assert!(body.contains("event: result"), "{body}");
    rx.recv().unwrap();
    // Log-Level: error hides the success line.
    let (code, _, body) = http_full(&s.addr, "POST", "/notify", &[ct, ("X-Apprise-Log-Level", "error")], &urls);
    assert_eq!((code, body.as_str()), (200, ""));
    rx.recv().unwrap();
    let (_, status) = http(&s.addr, "GET", "/status", "application/json", "");
    assert!(status.contains(r#""persistent_storage":true"#), "{status}");
    assert!(store.is_dir());
}

/// Send raw bytes, half-close and return everything the server wrote.
fn raw(addr: &str, bytes: &[u8]) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
    s.write_all(bytes).unwrap();
    s.shutdown(std::net::Shutdown::Write).ok();
    let mut out = Vec::new();
    s.read_to_end(&mut out).ok();
    String::from_utf8_lossy(&out).into_owned()
}

fn raw_status(out: &str) -> Option<u16> {
    out.split_whitespace().nth(1).and_then(|c| c.parse().ok())
}

#[test]
fn non_ascii_header_values_are_used() {
    let s = start(&tmpdir("utf8-headers"));
    let (up, rx) = upstream(2, 200);
    let body = format!("urls=json://{up}&body=b");
    let head = format!(
        "POST /notify HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
        body.len()
    );
    let mut req = head.clone().into_bytes();
    req.extend_from_slice("X-Apprise-Title: Größe ✓\r\n\r\n".as_bytes());
    req.extend_from_slice(body.as_bytes());
    let out = raw(&s.addr, &req);
    assert_eq!(raw_status(&out), Some(200), "{out}");
    assert_eq!(rx.recv().unwrap()["title"], "Größe ✓");
    // Bytes that are not UTF-8 are read as Latin-1.
    let mut req = head.into_bytes();
    req.extend_from_slice(b"X-Apprise-Title: Gr\xf6\xdfe\r\n\r\n");
    req.extend_from_slice(body.as_bytes());
    assert_eq!(raw_status(&raw(&s.addr, &req)), Some(200));
    assert_eq!(rx.recv().unwrap()["title"], "Größe");
}

#[test]
fn malformed_requests_get_400() {
    let s = start(&tmpdir("malformed"));
    let cases: &[&[u8]] = &[
        b"NOT-HTTP\r\n\r\n",
        b"GET /status HTTP/9\r\n\r\n",
        b"GET /status HTTP/1.1\r\nno colon here\r\n\r\n",
        b"GET /status HTTP/1.1\r\n: empty name\r\n\r\n",
        b"POST /notify HTTP/1.1\r\nContent-Length: not-a-number\r\n\r\n",
        b"POST /notify HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        b"POST /notify HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort",
        b"GET /st\xffatus HTTP/1.1\r\nHost: x\r\n\r\n",
    ];
    for case in cases {
        let out = raw(&s.addr, case);
        assert_eq!(raw_status(&out), Some(400), "{:?} -> {out:?}", String::from_utf8_lossy(case));
    }
    // A request head cut short by the client closing: hyper drops the connection without an answer.
    let out = raw(&s.addr, b"GET /status HTTP/1.1\r\nHost: x\r\n");
    assert!(matches!(raw_status(&out), None | Some(400)), "{out:?}");
    // A clean request still works afterwards. Keep-alive serves two in a row.
    let out = raw(&s.addr, b"GET /status HTTP/1.1\r\nHost: x\r\n\r\nGET /status HTTP/1.1\r\nHost: x\r\n\r\n");
    assert_eq!(out.matches("HTTP/1.1 200").count(), 2, "{out}");
    // Chunked bodies and Expect: 100-continue.
    let (up, rx) = upstream(1, 200);
    let body = format!("urls=json://{up}&body=chunked");
    let req = format!(
        "POST /notify HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nExpect: 100-continue\r\n\
         Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
        body.len()
    );
    let out = raw(&s.addr, req.as_bytes());
    assert!(out.starts_with("HTTP/1.1 100"), "{out}");
    assert!(out.contains("HTTP/1.1 200"), "{out}");
    assert_eq!(rx.recv().unwrap()["message"], "chunked");
}

#[test]
fn healthcheck_flag() {
    let dir = tmpdir("healthcheck");
    let srv = start(&dir);
    let check = |bind: &str| {
        Command::new(env!("CARGO_BIN_EXE_mercurio")).args(["serve", "--healthcheck", "--bind", bind]).status().unwrap()
    };
    assert!(check(&srv.addr).success());
    let port = srv.addr.rsplit(':').next().unwrap().to_string();
    assert!(check(&format!("0.0.0.0:{port}")).success(), "a wildcard bind is checked through loopback");
    drop(srv);
    assert_eq!(check(&format!("127.0.0.1:{port}")).code(), Some(1));
}

/// The `Endpoints:` section of `mercurio serve --help`, as (paths, methods).
fn help_section(name: &str) -> Vec<String> {
    let out = Command::new(env!("CARGO_BIN_EXE_mercurio")).args(["serve", "--help"]).output().unwrap();
    let help = String::from_utf8(out.stdout).unwrap();
    let section = help.split_once(&format!("\n{name}:\n")).unwrap().1;
    section.lines().take_while(|l| l.starts_with("  ")).map(|l| l.trim().to_string()).collect()
}

/// Every documented path answers every documented method (not 404 or 405), and refuses another method with 405.
#[test]
fn routes_match_the_router() {
    let dir = tmpdir("routes");
    let srv = start(&dir);
    for row in help_section("Endpoints") {
        let cols: Vec<&str> = row.split("  ").map(str::trim).filter(|c| !c.is_empty()).collect();
        let (paths, methods) = (cols[0], cols[1]);
        for path in paths.split(", ") {
            let path = path.replace("{key}", "k1");
            for method in methods.split(", ") {
                let (code, _, _) = http_full(&srv.addr, method, &path, &[], "");
                assert!(code != 404 && code != 405, "{method} {path} answered {code}");
            }
            let (code, _, _) = http_full(&srv.addr, "PUT", &path, &[], "");
            assert_eq!(code, 405, "PUT {path}");
        }
    }
}

/// Every documented request field and header is a name the server code uses.
#[test]
fn documented_fields_and_headers_are_read() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut code = std::fs::read_to_string(src.join("serve.rs")).unwrap();
    for entry in std::fs::read_dir(src.join("serve")).unwrap() {
        code.push_str(&std::fs::read_to_string(entry.unwrap().path()).unwrap());
    }
    let code = code.split("pub(crate) const ROUTES").next().unwrap().to_string()
        + code.split("pub(crate) fn help_tables").nth(1).unwrap();
    let literal = |name: &str| code.to_lowercase().contains(&format!("\"{}\"", name.to_lowercase()));
    for row in help_section("Request fields") {
        let names = row.split("  ").next().unwrap();
        for name in names.split([',', '+']).map(|n| n.split(" (").next().unwrap().trim()) {
            assert!(literal(name), "request field {name:?} is documented but never read");
        }
    }
    for row in help_section("Headers") {
        let name = row.split_whitespace().next().unwrap();
        let short = name.trim_start_matches("X-Apprise-");
        assert!(literal(name) || literal(short), "header {name} is documented but never read");
    }
}

/// Answers each request with `replies` in turn; sends each request's head on the channel.
fn recorder(replies: Vec<String>) -> (String, mpsc::Receiver<String>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for (s, reply) in l.incoming().zip(replies) {
            let mut s = s.unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let (mut head, mut len) = (String::new(), 0);
            loop {
                let mut h = String::new();
                r.read_line(&mut h).unwrap();
                if h.trim().is_empty() {
                    break;
                }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                head.push_str(&h);
            }
            r.read_exact(&mut vec![0; len]).unwrap();
            tx.send(head).ok();
            write!(s, "{reply}").unwrap();
        }
    });
    (addr, rx)
}

#[test]
fn http_redirects_setting_and_apprise_id() {
    let ok = || "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string();
    let (target, hits) = recorder(vec![ok(), ok()]);
    let moved =
        format!("HTTP/1.1 302 Found\r\nLocation: http://{target}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let (hop, _) = recorder(vec![moved.clone(), moved.clone(), moved]);
    let s = start_with(&tmpdir("redirects"), &[("APPRISE_HTTP_REDIRECTS", "no")]);
    assert_eq!(form(&s.addr, "/notify", &format!("urls=json://{hop}&body=x")).0, 424);
    assert_eq!(form(&s.addr, "/notify", &format!("urls=json://{hop}%3Fredirect%3Dyes&body=x")).0, 200);
    hits.recv().unwrap();
    drop(s);
    let s = start(&tmpdir("redirects-default"));
    assert_eq!(form(&s.addr, "/notify", &format!("urls=json://{hop}&body=x")).0, 200);
    hits.recv().unwrap();

    // apprise:// targets pass on the caller's X-Apprise-ID and recursion count plus one.
    let (api, heads) = recorder(vec![ok(), ok()]);
    let ct = ("Content-Type", "application/x-www-form-urlencoded");
    let body = format!("urls=apprise://{api}/abc&body=x");
    let hdrs = [ct, ("X-Apprise-ID", "chain-42"), ("X-Apprise-Recursion-Count", "1")];
    assert_eq!(http_full(&s.addr, "POST", "/notify", &hdrs, &body).0, 200);
    let head = heads.recv().unwrap().to_ascii_lowercase();
    assert!(head.contains("x-apprise-id: chain-42") && head.contains("x-apprise-recursion-count: 2"), "{head}");
    assert_eq!(http_full(&s.addr, "POST", "/notify", &[ct], &body).0, 200);
    let head = heads.recv().unwrap().to_ascii_lowercase();
    assert!(!head.contains("chain-42") && head.contains("x-apprise-recursion-count: 1"), "{head}");
}
