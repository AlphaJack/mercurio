//! Desktop and XMPP comparators.
//!
//! The fixtures hold the expected argv, D-Bus calls, HID reports and XMPP client calls. The commands mercurio runs and its socket conversation are mapped back onto the same events.
//!
//! Known, documented divergences handled here:
//! - macosx: `argv[0]` is compared by file name (mercurio falls back to `PATH`). The `-contentImage` value is not compared (mercurio passes the image URL, the fixture a local file path).
//! - Failure cases compare `ok` only: the point where a failing local tool stops differs from where the fixture's binding failed.
//! - macosx off macOS and windows off Windows: every valid case must fail as unsupported (windows still checks its command builder against the expected balloon events).

#![allow(dead_code, reason = "each desktop fixture is used by one optional service")]

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::events::{Comparator, Recorder, Session};
use crate::error::Error;
use crate::testing::{FakeTransport, ScriptedConn};
use crate::transport::CommandOutput;

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
    let tmp = std::env::temp_dir().to_string_lossy().trim_end_matches(['/', '\\']).to_string();
    fake.commands()
        .into_iter()
        .map(|c| {
            let mut v = vec![c.program];
            v.extend(c.args.into_iter().map(|a| a.replace(&tmp, "<tmp>")));
            v
        })
        .collect()
}

fn macosx_normalise(events: Vec<Value>) -> Vec<Value> {
    events
        .into_iter()
        .map(|mut e| {
            if let Some(cmd) = e.get_mut("cmd").and_then(Value::as_array_mut) {
                if let Some(Value::String(p)) = cmd.first_mut() {
                    *p = p.rsplit('/').next().unwrap_or(p).to_string();
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

/// Read back a GVariant text string literal.
fn gv_str(s: &str) -> String {
    let inner = s.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')).unwrap_or_else(|| panic!("not a string: {s}"));
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                out.push(char::from_u32(u32::from_str_radix(&hex, 16).unwrap()).unwrap());
            }
            Some(o) => out.push(o),
            None => {}
        }
    }
    out
}

fn gdbus_events(_: &Value, fake: &FakeTransport, _: &Recorder) -> Vec<Value> {
    argv(fake)
        .into_iter()
        .map(|a| {
            assert_eq!(
                a[..9].join(" "),
                "gdbus call --session --dest org.freedesktop.Notifications --object-path \
                 /org/freedesktop/Notifications --method org.freedesktop.Notifications.Notify"
            );
            assert_eq!(a[14], "@as []");
            let mut hints = serde_json::Map::new();
            let re = regex::Regex::new(r"'(\w+)': <(?:byte|int32) (-?\d+)>").unwrap();
            for c in re.captures_iter(&a[15]) {
                hints.insert(c[1].to_string(), json!(c[2].parse::<i64>().unwrap()));
            }
            json!({"notify": [
                gv_str(&a[9]), a[10].parse::<i64>().unwrap(), gv_str(&a[11]), gv_str(&a[12]), gv_str(&a[13]),
                [], hints, a[16].parse::<i64>().unwrap()
            ]})
        })
        .collect()
}

pub(super) const GDBUS: Comparator = Comparator {
    services: &["dbus", "glib"],
    setup: queue_commands,
    events: |s, case| gdbus_events(case, &s.fake, &s.events),
    events_on_failure: false,
    ..Comparator::DEFAULT
};

fn gnome_events(s: &Session, _: &Value) -> Vec<Value> {
    argv(&s.fake)
        .into_iter()
        .map(|a| {
            assert_eq!(a[0], "notify-send");
            let icon = a[3].strip_prefix("--icon=");
            let rest = if icon.is_some() { &a[4..] } else { &a[3..] };
            assert_eq!(rest[0], "--");
            let urgency = match a[2].strip_prefix("--urgency=").unwrap() {
                "low" => 0,
                "normal" => 1,
                "critical" => 2,
                other => panic!("urgency {other}"),
            };
            json!({"gnome": {"app": a[1].strip_prefix("--app-name=").unwrap(), "body": rest[1], "urgency": urgency, "icon": icon}})
        })
        .collect()
}

pub(super) const GNOME: Comparator = Comparator {
    services: &["gnome"],
    setup: queue_commands,
    events: gnome_events,
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
    setup: queue_commands,
    events: |s, case| balloon_events(case, &s.fake, &s.events),
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
    let re = regex::Regex::new(&format!(r#"\s{key}=['"]([^'"]*)['"]"#)).unwrap();
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

fn scram_keys(password: &str) -> (Vec<u8>, Vec<u8>) {
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
            let mech = attr(&s, "mechanism").unwrap().to_string();
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
                let bare = payload.strip_prefix("n,,").unwrap().to_string();
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
    responses(case).first().and_then(|r| r.get("xmpp")).and_then(Value::as_str).unwrap_or("ok").to_string()
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
        password: password.map(str::to_string).unwrap_or_else(|| url_password(case["url"].as_str().unwrap())),
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
