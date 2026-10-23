//! SMTP (email, deltachat) and SMPP comparators.
//!
//! mercurio talks to a scripted fake server; the conversation (endpoint, TLS mode, credentials, envelope, parsed message / raw PDUs) is decoded into the same event shapes. Case `responses` may carry `{"smtp_fail": "connect|starttls|login|sendmail|refused"}` or `{"smpp_fail": "connect|bind|submit"}`.

use serde_json::{Map, Value, json};

use super::events::{Comparator, Recorder, Session};
use crate::testing::ScriptedConn;

type Events = Recorder;

/// Decode base64, ignoring whitespace; empty on invalid input.
pub fn b64d(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    crate::crypto::b64_decode(&clean).unwrap_or_default()
}

fn qp_decode(s: &str) -> Vec<u8> {
    let s = s.replace("=\r\n", "").replace("=\n", "");
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'='
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// RFC 2047 decoding (B and Q), whitespace between adjacent words dropped, then every whitespace run collapsed (as in the fixtures).
fn decode_header(v: &str) -> String {
    let re = crate::re::Regex::new(r"=\?([^?]+)\?([bBqQ])\?([^?]*)\?=").unwrap();
    let mut out = String::new();
    let mut last = 0;
    let mut prev_word = false;
    for m in re.captures_iter(v) {
        let whole = m.get(0).unwrap();
        let between = v.get(last..whole.start()).unwrap_or_default();
        if !(prev_word && between.trim().is_empty()) {
            out.push_str(between);
        }
        let bytes = if m[2].eq_ignore_ascii_case("b") { b64d(&m[3]) } else { qp_decode(&m[3].replace('_', " ")) };
        out.push_str(&String::from_utf8_lossy(&bytes));
        last = whole.end();
        prev_word = true;
    }
    out.push_str(v.get(last..).unwrap_or_default());
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn split_head(raw: &str) -> (Vec<(String, String)>, &str) {
    let (head, body) = match raw.split_once("\r\n\r\n") {
        Some(parts) => parts,
        None => (raw, ""),
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in head.split("\r\n") {
        if line.starts_with([' ', '\t']) {
            if let Some(last) = headers.last_mut() {
                last.1.push_str(line);
            }
        } else if let Some((k, v)) = line.split_once(':') {
            headers.push((k.to_ascii_lowercase(), v.trim_start().to_string()));
        }
    }
    (headers, body)
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn param(value: &str, name: &str) -> Option<String> {
    for p in value.split(';').skip(1) {
        let p = p.trim();
        if let Some((k, v)) = p.split_once('=')
            && k.trim().eq_ignore_ascii_case(name)
        {
            return Some(v.trim().trim_matches('"').to_string());
        }
    }
    None
}

fn describe_part(headers: &[(String, String)], body: &str) -> Value {
    let ct_raw = header(headers, "content-type").unwrap_or("text/plain");
    let ct = ct_raw.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    let mut out = Map::new();
    out.insert("type".into(), json!(ct));
    if ct.starts_with("multipart/") {
        let boundary = param(ct_raw, "boundary").expect("boundary");
        let delim = format!("--{boundary}");
        let mut parts = Vec::new();
        let mut chunks = body.split(&delim);
        chunks.next(); // preamble
        for chunk in chunks {
            if chunk.starts_with("--") {
                break;
            }
            let chunk = chunk.strip_prefix("\r\n").unwrap_or(chunk);
            let chunk = chunk.strip_suffix("\r\n").unwrap_or(chunk);
            let (h, b) = split_head(chunk);
            parts.push(describe_part(&h, b));
        }
        out.insert("parts".into(), Value::Array(parts));
        return Value::Object(out);
    }
    if let Some(cs) = param(ct_raw, "charset") {
        out.insert("charset".into(), json!(cs.to_ascii_lowercase()));
    }
    let disp_raw = header(headers, "content-disposition");
    let disp = disp_raw.map(|d| d.split(';').next().unwrap_or("").trim().to_ascii_lowercase());
    if let Some(d) = &disp {
        out.insert("disposition".into(), json!(d));
    }
    let filename = disp_raw.and_then(|d| param(d, "filename"));
    if let Some(f) = &filename {
        out.insert("filename".into(), json!(decode_header(f)));
    }
    if let Some(cid) = header(headers, "content-id") {
        out.insert("content_id".into(), json!(cid));
    }
    let data = match header(headers, "content-transfer-encoding").map(str::to_ascii_lowercase).as_deref() {
        Some("base64") => b64d(body),
        Some("quoted-printable") => qp_decode(body),
        _ => body.as_bytes().to_vec(),
    };
    if ct.starts_with("text/") && disp.as_deref() != Some("attachment") && filename.is_none() {
        out.insert("text".into(), json!(String::from_utf8_lossy(&data).replace("\r\n", "\n")));
    } else {
        out.insert("b64".into(), json!(crate::crypto::b64(&data)));
    }
    Value::Object(out)
}

const VOLATILE: &[&str] = &["date", "message-id", "content-type", "content-transfer-encoding", "mime-version"];

/// Describe a raw MIME message as JSON (sorted headers without volatile ones, decoded body parts).
pub fn describe(raw: &str) -> Value {
    let (headers, body) = split_head(raw);
    let mut list: Vec<(String, String)> = headers
        .iter()
        .filter(|(k, _)| !VOLATILE.contains(&k.as_str()))
        .map(|(k, v)| {
            let mut d = decode_header(v);
            if k == "cc" || k == "reply-to" {
                let mut items: Vec<String> =
                    d.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
                items.sort();
                d = items.join(",");
            }
            (k.clone(), d)
        })
        .collect();
    list.sort();
    json!({
        "headers": list.into_iter().map(|(k, v)| json!([k, v])).collect::<Vec<_>>(),
        "body": describe_part(&headers, body),
    })
}

#[derive(Default)]
struct SmtpState {
    from: Option<String>,
    rcpts: Vec<String>,
    data: Option<String>,
    login_user: Option<String>,
}

fn addr(arg: &str) -> String {
    let a = arg.split_once('<').map(|(_, r)| r).unwrap_or(arg);
    a.split('>').next().unwrap_or("").trim().to_string()
}

/// A scripted SMTP server recording `sendmail` events. `fail` selects a failure: `connect`, `starttls`, `login`, `sendmail` or `refused`.
pub fn smtp_server(fail: Option<String>, events: Events) -> ScriptedConn {
    let mut st = SmtpState::default();
    let fail = fail.unwrap_or_default();
    ScriptedConn::lines("220 fake ESMTP ready\r\n", move |line| {
        let push = |v: Value| events.lock().unwrap().push(v);
        if let Some(data) = st.data.as_mut() {
            if line == "." {
                let mut raw = std::mem::take(data);
                st.data = None;
                // The CRLF before the terminating "." belongs to the terminator.
                if raw.ends_with("\r\n") {
                    raw.truncate(raw.len() - 2);
                }
                let mut to = std::mem::take(&mut st.rcpts);
                to.sort();
                push(
                    json!({"smtp": "sendmail", "from": st.from.take().unwrap_or_default(), "to": to, "message": describe(&raw)}),
                );
                return Some("250 queued\r\n".into());
            }
            let l = line.strip_prefix('.').unwrap_or(line);
            data.push_str(l);
            data.push_str("\r\n");
            return None;
        }
        if let Some(user) = st.login_user.take() {
            let pw = String::from_utf8_lossy(&b64d(line)).to_string();
            push(json!({"smtp": "login", "user": user, "password": pw}));
            return Some(if fail == "login" { "535 bad credentials\r\n" } else { "235 ok\r\n" }.into());
        }
        let upper = line.to_ascii_uppercase();
        let reply: String = if upper.starts_with("EHLO") {
            "250-fake\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 10485760\r\n".into()
        } else if upper.starts_with("HELO") {
            "250 fake\r\n".into()
        } else if upper == "STARTTLS" {
            push(json!({"smtp": "starttls"}));
            if fail == "starttls" { "454 TLS not available\r\n".into() } else { "220 go ahead\r\n".into() }
        } else if let Some(arg) = upper.strip_prefix("AUTH PLAIN ").and_then(|_| line.get(11..)) {
            let raw = b64d(arg);
            let parts: Vec<String> = raw.split(|b| *b == 0).map(|p| String::from_utf8_lossy(p).to_string()).collect();
            push(
                json!({"smtp": "login", "user": parts.get(1).cloned().unwrap_or_default(), "password": parts.get(2).cloned().unwrap_or_default()}),
            );
            if fail == "login" { "535 bad credentials\r\n".into() } else { "235 ok\r\n".into() }
        } else if upper.starts_with("AUTH LOGIN ") {
            st.login_user = Some(String::from_utf8_lossy(&b64d(line.get(11..).unwrap_or_default())).to_string());
            "334 UGFzc3dvcmQ6\r\n".into()
        } else if upper.starts_with("MAIL FROM:") {
            let from = addr(line.get(10..).unwrap_or_default());
            if fail == "sendmail" {
                push(json!({"smtp": "sendmail", "from": from, "failed": true}));
                "550 sender refused\r\n".into()
            } else {
                st.from = Some(from);
                "250 ok\r\n".into()
            }
        } else if upper.starts_with("RCPT TO:") {
            st.rcpts.push(addr(line.get(8..).unwrap_or_default()));
            if fail == "refused" { "550 no such user\r\n".into() } else { "250 ok\r\n".into() }
        } else if upper == "RSET" {
            if fail == "refused" && st.from.is_some() {
                let mut to = std::mem::take(&mut st.rcpts);
                to.sort();
                push(
                    json!({"smtp": "sendmail", "from": st.from.take().unwrap_or_default(), "to": to, "refused": true}),
                );
            }
            st.from = None;
            st.rcpts.clear();
            "250 ok\r\n".into()
        } else if upper == "DATA" {
            st.data = Some(String::new());
            "354 go ahead\r\n".into()
        } else if upper == "QUIT" {
            push(json!({"smtp": "quit"}));
            "221 bye\r\n".into()
        } else {
            "502 unknown\r\n".into()
        };
        Some(reply)
    })
}

fn mask_pdu(p: &[u8]) -> Vec<u8> {
    let mut b = p.to_vec();
    if b.len() < 16 || b[4..8] != [0, 0, 0, 4] {
        return b;
    }
    let cstr = |b: &[u8], pos: usize| pos + b[pos..].iter().position(|x| *x == 0).unwrap() + 1;
    let mut pos = cstr(&b, 16);
    pos += 2;
    pos = cstr(&b, pos);
    pos += 2;
    pos = cstr(&b, pos);
    let esm = b[pos];
    pos += 3;
    pos = cstr(&b, pos);
    pos = cstr(&b, pos);
    pos += 4;
    let len = b[pos];
    pos += 1;
    if esm & 0x40 != 0 && len >= 6 && b[pos] == 5 {
        b[pos + 3] = 0;
    }
    b
}

/// A scripted SMPP SMSC recording submitted messages. `fail` selects a failure: `connect`, `bind` or `submit`.
pub fn smsc(fail: Option<String>, events: Events) -> ScriptedConn {
    let mut buf: Vec<u8> = Vec::new();
    let fail = fail.unwrap_or_default();
    ScriptedConn::bytes(Vec::new(), move |data| {
        buf.extend_from_slice(data);
        let mut out = Vec::new();
        while buf.len() >= 16 {
            let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if buf.len() < len {
                break;
            }
            let p: Vec<u8> = buf.drain(..len).collect();
            let hex: String = mask_pdu(&p).iter().map(|x| format!("{x:02x}")).collect();
            events.lock().unwrap().push(json!({"smpp": "pdu", "hex": hex}));
            let cmd = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
            let seq = &p[12..16];
            let (status, body): (u32, &[u8]) = match cmd {
                1 | 2 | 9 => (if fail == "bind" { 0x0E } else { 0 }, b"SMSC\0"),
                4 if fail == "submit" => (0x45, b""),
                4 => (0, b"msg-1\0"),
                _ => (0, b""),
            };
            out.extend_from_slice(&((16 + body.len()) as u32).to_be_bytes());
            out.extend_from_slice(&(cmd | 0x8000_0000).to_be_bytes());
            out.extend_from_slice(&status.to_be_bytes());
            out.extend_from_slice(seq);
            out.extend_from_slice(body);
        }
        out
    })
}

fn failure(case: &Value, key: &str) -> Option<String> {
    case.get("responses")?.as_array()?.iter().find_map(|r| r.get(key)?.as_str().map(str::to_string))
}

fn dedupe(events: Vec<Value>) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for e in events {
        if out.last() != Some(&e) {
            out.push(e);
        }
    }
    out
}

fn setup(s: &mut Session, case: &Value, smpp: bool) {
    let fail = failure(case, if smpp { "smpp_fail" } else { "smtp_fail" });
    if fail.as_deref() != Some("connect") {
        let conn = if smpp { smsc(fail, s.events.clone()) } else { smtp_server(fail, s.events.clone()) };
        s.fake.push_conn(conn);
    }
}

fn events(s: &Session, smpp: bool) -> Vec<Value> {
    let mut got: Vec<Value> = s
        .fake
        .endpoints()
        .iter()
        .map(|ep| {
            if smpp {
                json!({"smpp": "connect", "host": ep.host, "port": ep.port, "tls": ep.tls})
            } else {
                json!({"smtp": "connect", "host": ep.host, "port": ep.port, "ssl": ep.tls})
            }
        })
        .collect();
    got.extend(s.events.lock().unwrap().drain(..));
    dedupe(got)
}

pub(super) const SMTP: Comparator = Comparator {
    services: &["email", "deltachat"],
    setup: |s, case| setup(s, case, false),
    events: |s, _| events(s, false),
    ..Comparator::DEFAULT
};

pub(super) const SMPP: Comparator = Comparator {
    services: &["smpp"],
    setup: |s, case| setup(s, case, true),
    events: |s, _| events(s, true),
    ..Comparator::DEFAULT
};
