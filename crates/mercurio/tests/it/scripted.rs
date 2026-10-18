//! Direct checks of socket services against the scripted peers the fixture comparators use (`mercurio::testing::fixtures::{socket, desktop}`): flows a fixture does not cover.

use std::sync::{Arc, Mutex};

use mercurio::Delivery;
use mercurio::testing::fixtures::desktop::xmpp_conn;
use mercurio::testing::fixtures::events::Recorder;
use mercurio::testing::fixtures::socket::smtp_server;
use mercurio::testing::{FakeTransport, ScriptedConn};
use mercurio::{Asset, Message};
use serde_json::{Value, json};

type Events = Recorder;

/// With `?reply=` set, mercurio sends to every target.
#[test]
fn reply_to_with_several_targets() {
    let events: Events = Arc::new(Mutex::new(Vec::new()));
    let fake = Arc::new(FakeTransport::new());
    fake.push_conn(smtp_server(None, events.clone()));
    let t = mercurio::parse("mailtos://user:pass@example.com/a@example.com/b@example.com?reply=noreply@example.com")
        .unwrap();
    assert!(t.send(&Message::new("body").title("t"), fake.as_ref(), &Asset::default()).is_success());
    let sent: Vec<Value> = events.lock().unwrap().iter().filter(|e| e["smtp"] == "sendmail").cloned().collect();
    assert_eq!(sent.len(), 2);
    for (e, to) in sent.iter().zip(["a@example.com", "b@example.com"]) {
        assert_eq!(e["to"], json!([to]));
        let headers = e["message"]["headers"].as_array().unwrap();
        assert!(headers.contains(&json!(["reply-to", "noreply@example.com"])), "{headers:?}");
    }
}

/// AUTH LOGIN is used when the server does not offer PLAIN.
#[test]
fn auth_login_fallback() {
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let l2 = log.clone();
    let mut pending_pw = false;
    let mut in_data = false;
    let conn = ScriptedConn::lines("220 hi\r\n", move |line| {
        l2.lock().unwrap().push(line.to_string());
        if in_data {
            if line == "." {
                in_data = false;
                return Some("250 ok\r\n".into());
            }
            return None;
        }
        if pending_pw {
            pending_pw = false;
            return Some("235 ok\r\n".into());
        }
        Some(
            match line.split(' ').next().unwrap_or("") {
                "EHLO" => "250-x\r\n250 AUTH LOGIN\r\n",
                "AUTH" => {
                    pending_pw = true;
                    "334 UGFzc3dvcmQ6\r\n"
                }
                "DATA" => {
                    in_data = true;
                    "354 go\r\n"
                }
                "QUIT" => "221 bye\r\n",
                _ => "250 ok\r\n",
            }
            .into(),
        )
    });
    let fake = Arc::new(FakeTransport::new());
    fake.push_conn(conn);
    let t = mercurio::parse("mailto://bob:secret@example.com:2525").unwrap();
    let d = t.send(&Message::new("hi"), fake.as_ref(), &Asset::default());
    assert!(d.is_success(), "{d:?}");
    let log = log.lock().unwrap();
    assert!(log.contains(&format!("AUTH LOGIN {}", mercurio::crypto::b64(b"bob"))), "{log:?}");
    assert!(log.contains(&mercurio::crypto::b64(b"secret")));
    assert!(log.iter().any(|l| l.starts_with("MAIL FROM:<bob@example.com>")));
}

/// CRAM-MD5 is tried before PLAIN and LOGIN, like smtplib.
#[test]
fn auth_cram_md5_preferred() {
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let l2 = log.clone();
    let mut pending = false;
    let mut in_data = false;
    let conn = ScriptedConn::lines("220 hi\r\n", move |line| {
        l2.lock().unwrap().push(line.to_string());
        if in_data {
            if line == "." {
                in_data = false;
                return Some("250 ok\r\n".into());
            }
            return None;
        }
        if pending {
            pending = false;
            return Some("235 ok\r\n".into());
        }
        Some(
            match line.split(' ').next().unwrap_or("") {
                "EHLO" => "250-x\r\n250 AUTH LOGIN PLAIN CRAM-MD5\r\n",
                "AUTH" => {
                    pending = true;
                    "334 PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2UucmVzdG9uLm1jaS5uZXQ+\r\n"
                }
                "DATA" => {
                    in_data = true;
                    "354 go\r\n"
                }
                "QUIT" => "221 bye\r\n",
                _ => "250 ok\r\n",
            }
            .into(),
        )
    });
    let fake = Arc::new(FakeTransport::new());
    fake.push_conn(conn);
    let t = mercurio::parse("mailto://tim:tanstaaftanstaaf@example.com:2525").unwrap();
    let d = t.send(&Message::new("hi"), fake.as_ref(), &Asset::default());
    assert!(d.is_success(), "{d:?}");
    let log = log.lock().unwrap();
    assert!(log.contains(&"AUTH CRAM-MD5".to_string()), "{log:?}");
    // RFC 2195's example answer.
    assert!(log.contains(&"dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw".to_string()), "{log:?}");
    assert!(!log.iter().any(|l| l.starts_with("AUTH PLAIN") || l.starts_with("AUTH LOGIN")), "{log:?}");
}

#[test]
fn pgp_is_unsupported() {
    let t = mercurio::parse("mailto://user:pass@example.com?pgp=sign").unwrap();
    let d = t.send(&Message::new("hi"), &FakeTransport::new(), &Asset::default());
    let errs: Vec<_> = d.errors().collect();
    assert!(matches!(errs[0], mercurio::Error::Unsupported(_)), "{errs:?}");
}

/// Send one notification through a scripted server offering `mechanisms`.
fn xmpp_once(url: &str, mechanisms: &[&str], password: &str) -> (Delivery, Vec<Value>, Vec<u8>) {
    let fake = FakeTransport::new();
    let rec: Recorder = Arc::default();
    let case = json!({"url": url});
    let (conn, _server) = xmpp_conn(&case, &rec, mechanisms, Some(password));
    let written = conn.written();
    fake.push_conn(conn);
    let t = mercurio::parse(url).unwrap();
    let d = t.send(&mercurio::Message::new("hi").title("T"), &fake, &Asset::default());
    let mut ev = rec.lock().unwrap().clone();
    ev.retain(|e| e.get("_starttls").is_none());
    let w = written.lock().unwrap().clone();
    (d, ev, w)
}

#[test]
fn xmpp_plain_over_tls() {
    let (d, ev, w) = xmpp_once("xmpps://user:pass@example.com/friend", &["PLAIN"], "pass");
    assert!(d.is_success(), "{:?}", d.errors().collect::<Vec<_>>());
    let w = String::from_utf8_lossy(&w);
    assert!(w.contains("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"));
    assert!(w.contains("mechanism='PLAIN'"));
    assert_eq!(ev.last().unwrap(), &json!({"disconnect": true}));
}

#[test]
fn xmpp_plain_refused_without_tls() {
    let (d, ev, w) = xmpp_once("xmpp://user:pass@example.com/friend", &["PLAIN"], "pass");
    assert!(!d.is_success());
    assert!(ev.is_empty());
    assert!(!String::from_utf8_lossy(&w).contains("<auth"), "PLAIN must never be sent in clear text");
}

#[test]
fn xmpp_wrong_password_fails() {
    let (d, ev, _) = xmpp_once("xmpps://user:wrong@example.com/friend", &["SCRAM-SHA-1"], "pass");
    assert!(!d.is_success());
    assert!(ev.iter().all(|e| e.get("message").is_none()));
}

#[test]
fn xmpp_resource_is_bound() {
    let (d, _, w) = xmpp_once("xmpps://user%2Fbot:pass@example.com", &["SCRAM-SHA-1"], "pass");
    assert!(d.is_success(), "{:?}", d.errors().collect::<Vec<_>>());
    let w = String::from_utf8_lossy(&w);
    assert!(w.contains("<resource>bot</resource>"));
    assert!(w.contains("<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>"));
    assert!(w.contains("<message to='user@example.com/bot' type='chat'><body>T\r\nhi</body></message>"));
}

#[test]
fn xmpp_no_mechanism_fails() {
    let (d, _, _) = xmpp_once("xmpps://user:pass@example.com", &["X-OAUTH2"], "pass");
    assert!(!d.is_success());
}
