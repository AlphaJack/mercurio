//! Desktop and XMPP comparators.
//!
//! The fixtures hold the expected argv, D-Bus calls, HID reports and XMPP client calls. The commands mercurio runs and its socket conversation are mapped back onto the same events.
//!
//! Known, documented divergences handled here:
//! - macosx: `argv[0]` is compared by file name (mercurio falls back to `PATH`). The `-contentImage` value is not compared (mercurio passes the image URL, the fixture a local file path).
//! - Failure cases compare `ok` only: the point where a failing local tool stops differs from where the fixture's binding failed.
//! - macosx off macOS and windows off Windows: every valid case must fail as unsupported.
//! - windows: each toast is recorded with its XML, then each balloon fallback with its decoded script; a `{"toast": "error"}` response fails the next toast.

#![allow(dead_code, reason = "each desktop fixture is used by one optional service")]

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::events::{Comparator, Recorder, Session};
use crate::error::Error;
use crate::testing::{FakeTransport, ScriptedConn};
use crate::transport::{CommandOutput, NativeCall};

fn responses(case: &Value) -> Vec<Value> {
    case.get("responses").and_then(Value::as_array).cloned().unwrap_or_default()
}

/// Map `{"exit", "stdout", "error"}` responses onto queued command outputs.
fn queue_commands(s: &mut Session, case: &Value) {
    for r in responses(case) {
        if r.get("error").and_then(Value::as_bool).unwrap_or(false) {
            s.fake.push_command_output(Err(Error::transport("scripted spawn failure")));
        } else {
            s.fake.push_command_output(Ok(CommandOutput {
                status: r.get("exit").and_then(Value::as_i64).unwrap_or(0) as i32,
                stdout: r.get("stdout").and_then(Value::as_str).unwrap_or("").as_bytes().to_vec(),
                stderr: Vec::new(),
            }));
        }
    }
}

/// Each command's program and arguments, with the temporary directory (where the bundled icon is written) shown as `<tmp>`.
fn argv(fake: &FakeTransport) -> Vec<Vec<String>> {
    let tmp = std::env::temp_dir().to_string_lossy().trim_end_matches(['/', '\\']).to_owned();
    fake.commands()
        .into_iter()
        .map(|c| {
            let mut v = vec![c.program];
            v.extend(c.args.into_iter().map(|a| redact_tmp(&a, &tmp)));
            v
        })
        .collect()
}

/// Replace `tmp` with `<tmp>`, also when backslash-escaped (GVariant literals), and write the icon path below it with `/` so Windows matches.
fn redact_tmp(arg: &str, tmp: &str) -> String {
    let arg = arg.replace(tmp, "<tmp>").replace(&tmp.replace('\\', "\\\\"), "<tmp>");
    arg.replace("<tmp>\\\\mercurio\\\\", "<tmp>/mercurio/").replace("<tmp>\\mercurio\\", "<tmp>/mercurio/")
}

fn macosx_normalise(events: Vec<Value>) -> Vec<Value> {
    events
        .into_iter()
        .map(|mut e| {
            if let Some(cmd) = e.get_mut("cmd").and_then(Value::as_array_mut) {
                if let Some(Value::String(p)) = cmd.first_mut() {
                    *p = p.rsplit('/').next().unwrap_or(p).to_owned();
                }
                for i in 0..cmd.len() {
                    if cmd[i] == "-contentImage" && i + 1 < cmd.len() {
                        cmd[i + 1] = json!("<image>");
                    }
                }
            }
            e
        })
        .collect()
}

pub(super) const MACOSX: Comparator = Comparator {
    services: &["macosx"],
    setup: queue_commands,
    events: |s, _| argv(&s.fake).into_iter().map(|a| json!({ "cmd": a })).collect(),
    normalise: macosx_normalise,
    events_on_failure: false,
};

/// A session bus on the scripted connection: it accepts `AUTH EXTERNAL`, answers `Hello`, records each `Notify` through `record` and answers it (with an error when `fail`).
fn fake_bus(record: impl Fn(Value) + Send + 'static, fail: bool) -> ScriptedConn {
    use crate::services::_dbus::{decode_notify, reply, take_message};
    let tmp = std::env::temp_dir().to_string_lossy().trim_end_matches(['/', '\\']).to_owned();
    let mut rx: Vec<u8> = Vec::new();
    let mut serial = 0;
    ScriptedConn::bytes(Vec::new(), move |data| match data {
        b"\0AUTH EXTERNAL\r\n" => b"DATA\r\n".to_vec(),
        b"DATA\r\n" => b"OK 0123456789abcdef0123456789abcdef\r\n".to_vec(),
        _ => {
            rx.extend_from_slice(data.strip_prefix(b"BEGIN\r\n").unwrap_or(data));
            let mut out = Vec::new();
            while let Some(msg) = take_message(&mut rx).unwrap() {
                serial += 1;
                let error = match msg.member.as_deref() {
                    Some("Notify") => {
                        let n = decode_notify(&msg).expect("Notify arguments");
                        let hints: serde_json::Map<String, Value> =
                            n.hints.into_iter().map(|(k, v)| (k, json!(v))).collect();
                        let icon = redact_tmp(&n.icon, &tmp);
                        record(json!([n.app, n.replaces_id, icon, n.summary, n.body, [], hints, n.timeout]));
                        fail.then_some(("org.freedesktop.DBus.Error.Failed", "scripted failure"))
                    }
                    _ => None,
                };
                out.extend(reply(serial, msg.serial, error));
            }
            out
        }
    })
}

/// A failing case: any response with a non-zero `exit` or an `error`.
fn fails(case: &Value) -> bool {
    responses(case).iter().any(|r| {
        r.get("exit").and_then(Value::as_i64).is_some_and(|c| c != 0)
            || r.get("error").and_then(Value::as_bool) == Some(true)
    })
}

/// Point the session bus at the fake one and queue it.
fn setup_bus(s: &mut Session, case: &Value, event: fn(Value) -> Value) {
    s.fake.set_env(
        crate::testing::FixedEnv::new(1_700_000_000)
            .with_var("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
            .with_var("XDG_RUNTIME_DIR", "/run/user/1000"),
    );
    let rec = s.events.clone();
    s.fake.push_conn(fake_bus(move |args| rec.lock().unwrap().push(event(args)), fails(case)));
}

/// Every connection goes to the session bus.
fn bus_events(s: &Session) -> Vec<Value> {
    for ep in s.fake.endpoints() {
        assert_eq!(ep.unix.as_deref(), Some("/run/user/1000/bus"));
    }
    s.events.lock().unwrap().clone()
}

pub(super) const DBUS: Comparator = Comparator {
    services: &["dbus", "glib"],
    setup: |s, case| setup_bus(s, case, |args| json!({ "notify": args })),
    events: |s, _| bus_events(s),
    events_on_failure: false,
    ..Comparator::DEFAULT
};

/// libnotify's call, shown as the fields gnome sets: app, summary (the merged message), urgency and icon; no body, the daemon's timeout.
fn gnome_event(args: Value) -> Value {
    assert_eq!((&args[1], &args[4], &args[5], &args[7]), (&json!(0), &json!(""), &json!([]), &json!(-1)));
    let icon = args[2].as_str().filter(|i| !i.is_empty()).map(str::to_owned);
    json!({"gnome": {"app": args[0], "body": args[3], "urgency": args[6]["urgency"], "icon": icon}})
}

pub(super) const GNOME: Comparator = Comparator {
    services: &["gnome"],
    setup: |s, case| setup_bus(s, case, gnome_event),
    events: |s, _| bus_events(s),
    events_on_failure: false,
    ..Comparator::DEFAULT
};

fn ps_literal(script: &str, key: &str) -> String {
    // A single-quoted literal may span lines; `''` is an escaped quote.
    let start = script.find(key).unwrap() + key.len() + 1;
    let mut out = String::new();
    let mut chars = script.get(start..).unwrap_or_default().chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            if chars.peek() == Some(&'\'') {
                chars.next();
            } else {
                break;
            }
        }
        out.push(c);
    }
    out
}

/// Queue toast failures (`{"toast": "error"}`) and command outputs.
fn queue_windows(s: &mut Session, case: &Value) {
    for r in responses(case) {
        if r.get("toast").and_then(Value::as_str) == Some("error") {
            s.fake.push_native_result(Err(Error::Service("scripted toast failure".into())));
        } else if r.get("error").and_then(Value::as_bool).unwrap_or(false) {
            s.fake.push_command_output(Err(Error::transport("scripted spawn failure")));
        } else {
            s.fake.push_command_output(Ok(CommandOutput {
                status: r.get("exit").and_then(Value::as_i64).unwrap_or(0) as i32,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }));
        }
    }
}

fn windows_events(case: &Value, fake: &FakeTransport, events: &Recorder) -> Vec<Value> {
    let tmp = std::env::temp_dir().to_string_lossy().trim_end_matches(['/', '\\']).replace('\\', "/");
    let mut out: Vec<Value> = fake
        .natives()
        .into_iter()
        .map(|call| match call {
            NativeCall::Toast(t) => json!({"toast": {"app_id": t.app_id, "xml": t.xml.replace(&tmp, "<tmp>")}}),
        })
        .collect();
    out.extend(balloon_events(case, fake, events));
    out
}

fn balloon_events(_: &Value, fake: &FakeTransport, _: &Recorder) -> Vec<Value> {
    fake.commands()
        .into_iter()
        .map(|c| {
            let raw = crate::crypto::b64_decode(c.args.last().unwrap()).unwrap();
            let units: Vec<u16> = raw.chunks(2).map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
            let script = String::from_utf16(&units).unwrap();
            let duration: u64 =
                script.lines().find_map(|l| l.strip_prefix("Start-Sleep -Seconds ")).unwrap().parse().unwrap();
            json!({"balloon": {
                "title": ps_literal(&script, "$n.BalloonTipTitle = "),
                "body": ps_literal(&script, "$n.BalloonTipText = "),
                "duration": duration,
            }})
        })
        .collect()
}

pub(super) const WINDOWS: Comparator = Comparator {
    services: &["windows"],
    setup: queue_windows,
    events: |s, case| windows_events(case, &s.fake, &s.events),
    events_on_failure: false,
    ..Comparator::DEFAULT
};

fn blink1_events(s: &Session, _: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    let cmds = argv(&s.fake);
    let mut serial = Value::Null;
    let mut reports = Vec::new();
    for a in &cmds {
        assert_eq!(a[0], "blink1-tool");
        let mut i = 1;
        let (mut led, mut fade, mut rgb) = (0u64, 0u64, [0u64; 3]);
        while i < a.len() {
            match a[i].as_str() {
                "--id" => serial = json!(a[i + 1]),
                "--led" => led = a[i + 1].parse().unwrap(),
                "-m" => fade = a[i + 1].parse().unwrap(),
                "--rgb" => {
                    let v: Vec<u64> = a[i + 1].split(',').map(|x| x.parse().unwrap()).collect();
                    rgb = [v[0], v[1], v[2]];
                }
                other => panic!("unexpected blink1-tool argument {other}"),
            }
            i += 2;
        }
        let ticks = fade / 10;
        reports.push(json!({"report": [1, 99, rgb[0], rgb[1], rgb[2], ticks >> 8, ticks & 0xff, led, 0]}));
    }
    out.push(json!({"open": [0x27b8, 0x01ed, serial]}));
    let sleeps = s.fake.sleeps();
    assert_eq!(sleeps.len(), 1);
    out.push(reports[0].clone());
    out.push(json!({"sleep": sleeps[0].as_secs_f64()}));
    out.extend(reports.into_iter().skip(1));
    out.push(json!({"close": true}));
    out
}

pub(super) const BLINK1: Comparator = Comparator {
    services: &["blink1"],
    setup: queue_commands,
    events: blink1_events,
    events_on_failure: false,
    ..Comparator::DEFAULT
};

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&apos;", "'").replace("&quot;", "\"").replace("&amp;", "&")
}

fn attr<'a>(tag: &'a str, key: &str) -> Option<&'a str> {
    let re = crate::re::Regex::new(&format!(r#"\s{key}=['"]([^'"]*)['"]"#)).unwrap();
    re.captures(tag).map(|c| c.get(1).unwrap().as_str())
}

fn inner<'a>(s: &'a str, tag: &str) -> Option<&'a str> {
    let open = s.find(&format!("<{tag}"))?;
    let start = open + s.get(open..)?.find('>')? + 1;
    let end = start + s.get(start..)?.find(&format!("</{tag}>"))?;
    s.get(start..end)
}

/// Scripted XMPP server state for fixture replays (stream setup, SASL, messages).
#[derive(Debug)]
pub struct XmppServer {
    password: String,
    auth_fail: bool,
    mechanisms: Vec<String>,
    tls: bool,
    authed: bool,
    scram: Option<(String, String)>,
    events: Recorder,
}

const SALT: &[u8] = b"mercurio-salt";

/// Derived once per password and process, as every session derives them again.
fn scram_keys(password: &str) -> (Vec<u8>, Vec<u8>) {
    static DERIVED: Mutex<std::collections::BTreeMap<String, (Vec<u8>, Vec<u8>)>> =
        Mutex::new(std::collections::BTreeMap::new());
    if let Some(k) = DERIVED.lock().ok().and_then(|d| d.get(password).cloned()) {
        return k;
    }
    let k = derive_scram_keys(password);
    if let Ok(mut d) = DERIVED.lock() {
        d.insert(password.to_owned(), k.clone());
    }
    k
}

fn derive_scram_keys(password: &str) -> (Vec<u8>, Vec<u8>) {
    let mut salted = [0u8; 20];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA1,
        std::num::NonZeroU32::new(4096).unwrap(),
        SALT,
        password.as_bytes(),
        &mut salted,
    );
    (crate::crypto::hmac_sha1(&salted, b"Client Key"), crate::crypto::hmac_sha1(&salted, b"Server Key"))
}

impl XmppServer {
    fn handle(&mut self, data: &[u8]) -> Vec<u8> {
        let s = String::from_utf8_lossy(data).to_string();
        let mut ev = self.events.lock().unwrap();
        let reply = if s.contains("<stream:stream") {
            let features = if !self.authed {
                let tls =
                    if self.tls { String::new() } else { "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>".into() };
                let mechs: String = self.mechanisms.iter().map(|m| format!("<mechanism>{m}</mechanism>")).collect();
                format!("{tls}<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{mechs}</mechanisms>")
            } else {
                "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>"
                    .into()
            };
            format!(
                "<?xml version='1.0'?><stream:stream xmlns='jabber:client' \
                 xmlns:stream='http://etherx.jabber.org/streams' id='s1' from='example.com' version='1.0'>\
                 <stream:features>{features}</stream:features>"
            )
        } else if s.starts_with("<starttls") {
            self.tls = true;
            ev.push(json!({"_starttls": true}));
            "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>".into()
        } else if s.starts_with("<auth") {
            let mech = attr(&s, "mechanism").unwrap().to_owned();
            let payload = crate::crypto::b64_decode(inner(&s, "auth").unwrap()).unwrap();
            let payload = String::from_utf8(payload).unwrap();
            if mech == "PLAIN" {
                let pw = payload.split('\0').nth(2).unwrap();
                if self.auth_fail || pw != self.password {
                    "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>".into()
                } else {
                    self.authed = true;
                    "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>".into()
                }
            } else {
                assert_eq!(mech, "SCRAM-SHA-1");
                let bare = payload.strip_prefix("n,,").unwrap().to_owned();
                let nonce = bare.split(',').find_map(|p| p.strip_prefix("r=")).unwrap();
                let first = format!("r={nonce}srv,s={},i=4096", crate::crypto::b64(SALT));
                self.scram = Some((bare.clone(), first.clone()));
                format!(
                    "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{}</challenge>",
                    crate::crypto::b64(first.as_bytes())
                )
            }
        } else if s.starts_with("<response") {
            let fin = String::from_utf8(crate::crypto::b64_decode(inner(&s, "response").unwrap()).unwrap()).unwrap();
            let (bare, first) = self.scram.clone().unwrap();
            let (without, proof) = fin.rsplit_once(",p=").unwrap();
            let auth_message = format!("{bare},{first},{without}");
            let (client_key, server_key) = scram_keys(&self.password);
            let stored = crate::crypto::sha1(&client_key);
            let sig = crate::crypto::hmac_sha1(&stored, auth_message.as_bytes());
            let expect: Vec<u8> = client_key.iter().zip(&sig).map(|(a, b)| a ^ b).collect();
            if self.auth_fail || crate::crypto::b64(&expect) != proof {
                "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>".into()
            } else {
                self.authed = true;
                let v = crate::crypto::hmac_sha1(&server_key, auth_message.as_bytes());
                format!(
                    "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{}</success>",
                    crate::crypto::b64(format!("v={}", crate::crypto::b64(&v)).as_bytes())
                )
            }
        } else if s.starts_with("<iq") {
            let id = attr(&s, "id").unwrap();
            if s.contains("jabber:iq:roster") {
                ev.push(json!({"roster": true}));
                format!("<iq type='result' id='{id}'><query xmlns='jabber:iq:roster'/></iq>")
            } else if s.contains("xmpp-bind") {
                let res = inner(&s, "resource").unwrap_or("srv-res");
                format!(
                    "<iq type='result' id='{id}'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>\
                     <jid>user@example.com/{res}</jid></bind></iq>"
                )
            } else {
                format!("<iq type='result' id='{id}'/>")
            }
        } else if s == "<presence/>" {
            ev.push(json!({"presence": true}));
            String::new()
        } else if s.starts_with("<presence") {
            let to = xml_unescape(attr(&s, "to").unwrap());
            let (room, nick) = to.rsplit_once('/').unwrap();
            ev.push(json!({"join": [room, nick]}));
            format!(
                "<presence from='{to}' to='user@example.com'><x xmlns='http://jabber.org/protocol/muc#user'>\
                 <status code='110'/></x></presence>"
            )
        } else if s.starts_with("<message") {
            ev.push(json!({"message": {
                "to": xml_unescape(attr(&s, "to").unwrap()),
                "type": attr(&s, "type").unwrap(),
                "subject": inner(&s, "subject").map(xml_unescape).unwrap_or_default(),
                "body": xml_unescape(inner(&s, "body").unwrap()),
            }}));
            String::new()
        } else if s == "</stream:stream>" {
            ev.push(json!({"disconnect": true}));
            "</stream:stream>".into()
        } else {
            panic!("unexpected client data: {s}");
        };
        reply.into_bytes()
    }
}

fn xmpp_mode(case: &Value) -> String {
    responses(case).first().and_then(|r| r.get("xmpp")).and_then(Value::as_str).unwrap_or("ok").to_owned()
}

/// Recover the password from the case URL (only for the scripted server).
fn url_password(url: &str) -> String {
    let rest = url.split_once("://").unwrap().1;
    let auth = rest.split('@').next().unwrap_or("");
    auth.split_once(':').map(|(_, p)| crate::url::unquote(p)).unwrap_or_default()
}

/// A scripted XMPP connection for `case`, offering `mechanisms`, with its shared server state. The password defaults to the one in the case URL.
pub fn xmpp_conn(
    case: &Value,
    rec: &Recorder,
    mechanisms: &[&str],
    password: Option<&str>,
) -> (ScriptedConn, Arc<Mutex<XmppServer>>) {
    let mode = xmpp_mode(case);
    let server = Arc::new(Mutex::new(XmppServer {
        password: password.map(str::to_owned).unwrap_or_else(|| url_password(case["url"].as_str().unwrap())),
        auth_fail: mode == "auth_fail",
        mechanisms: mechanisms.iter().map(|m| m.to_string()).collect(),
        tls: false,
        authed: false,
        scram: None,
        events: rec.clone(),
    }));
    let s = server.clone();
    (ScriptedConn::bytes(Vec::new(), move |data| s.lock().unwrap().handle(data)), server)
}

fn setup_xmpp(s: &mut Session, case: &Value) {
    if xmpp_mode(case) == "connect_fail" {
        return;
    }
    let (conn, _server) = xmpp_conn(case, &s.events, &["SCRAM-SHA-1", "PLAIN"], None);
    s.fake.push_conn(conn);
}

fn xmpp_events(s: &Session, _: &Value) -> Vec<Value> {
    let mut events = s.events.lock().unwrap().clone();
    let starttls = events.iter().any(|e| e.get("_starttls").is_some());
    events.retain(|e| e.get("_starttls").is_none());
    let eps = s.fake.endpoints();
    let Some(ep) = eps.first() else { return events };
    let plaintext = !ep.tls && !starttls;
    let mut out = vec![json!({"connect": {
        "host": ep.host,
        "port": ep.port,
        "plaintext": plaintext,
        "starttls": starttls,
        "direct_tls": ep.tls,
        "verify": if plaintext { Value::Null } else { json!(ep.verify_tls) },
    }})];
    out.extend(events);
    out
}

pub(super) const XMPP: Comparator = Comparator {
    services: &["xmpp"],
    setup: setup_xmpp,
    events: xmpp_events,
    events_on_failure: false,
    ..Comparator::DEFAULT
};
