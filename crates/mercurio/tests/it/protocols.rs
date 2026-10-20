//! Raw-protocol services against real local servers (no internet needed): MQTT broker, UDP syslog collector and IRC server on 127.0.0.1, driven through `BlockingTransport`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use mercurio::{BlockingTransport, Mercurio, Message};

fn mercurio() -> Mercurio {
    Mercurio::with_transport(Arc::new(BlockingTransport::new()))
}

fn read_packet(s: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut head = [0u8; 1];
    s.read_exact(&mut head).ok()?;
    let (mut len, mut mult) = (0usize, 1usize);
    loop {
        let mut b = [0u8; 1];
        s.read_exact(&mut b).ok()?;
        len += (b[0] as usize & 0x7f) * mult;
        if b[0] & 0x80 == 0 {
            break;
        }
        mult *= 128;
    }
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).ok()?;
    Some((head[0], body))
}

fn mqtt_str(body: &[u8], pos: &mut usize) -> String {
    let len = u16::from_be_bytes([body[*pos], body[*pos + 1]]) as usize;
    let s = String::from_utf8_lossy(&body[*pos + 2..*pos + 2 + len]).to_string();
    *pos += 2 + len;
    s
}

#[test]
fn mqtt_qos1_round_trip() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut seen = Vec::new();
        while let Some((head, body)) = read_packet(&mut s) {
            match head >> 4 {
                1 => {
                    let mut pos = 0;
                    let proto = mqtt_str(&body, &mut pos);
                    let level = body[pos];
                    let flags = body[pos + 1];
                    pos += 4;
                    let client = mqtt_str(&body, &mut pos);
                    let user = mqtt_str(&body, &mut pos);
                    let pass = mqtt_str(&body, &mut pos);
                    seen.push(format!("CONNECT {proto} {level} {flags:#04x} [{client}] {user}:{pass}"));
                    s.write_all(&[0x20, 0x02, 0x00, 0x00]).unwrap();
                }
                3 => {
                    let mut pos = 0;
                    let topic = mqtt_str(&body, &mut pos);
                    let id = [body[pos], body[pos + 1]];
                    let payload = String::from_utf8_lossy(&body[pos + 2..]).to_string();
                    seen.push(format!("PUBLISH {head:#04x} {topic} {payload:?}"));
                    s.write_all(&[0x40, 0x02, id[0], id[1]]).unwrap();
                }
                14 => {
                    seen.push("DISCONNECT".into());
                    break;
                }
                other => seen.push(format!("packet {other}")),
            }
        }
        tx.send(seen).unwrap();
    });
    let mut m = mercurio();
    m.add(&format!("mqtt://user:pass@127.0.0.1:{port}/b/topic,a/topic?qos=1&retain=yes")).unwrap();
    let report = m.notify(&Message::new("Body").title("Title"));
    assert!(report.is_success(), "{report:?}");
    let seen = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        seen,
        vec![
            "CONNECT MQTT 4 0xc2 [] user:pass".to_string(),
            "PUBLISH 0x33 a/topic \"Title\\r\\nBody\"".to_string(),
            "PUBLISH 0x33 b/topic \"Title\\r\\nBody\"".to_string(),
            "DISCONNECT".to_string(),
        ]
    );
}

#[test]
fn mqtt_connack_refusal_fails() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let _ = read_packet(&mut s);
        s.write_all(&[0x20, 0x02, 0x00, 0x05]).unwrap();
        #[expect(clippy::disallowed_methods, reason = "the fake broker keeps the socket open briefly")]
        thread::sleep(Duration::from_millis(200));
    });
    let mut m = mercurio();
    m.add(&format!("mqtt://127.0.0.1:{port}/t")).unwrap();
    assert!(!m.notify(&Message::new("x")).is_success());
}

#[test]
fn rsyslog_udp_datagram() {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let port = sock.local_addr().unwrap().port();
    let mut m = mercurio();
    m.add(&format!("rsyslog://127.0.0.1:{port}/local3")).unwrap();
    assert!(m.notify(&Message::new("Body").title("Title")).is_success());
    let mut buf = [0u8; 2048];
    let (n, _) = sock.recv_from(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    // local3 (152) + info (6)
    assert_eq!(text, format!("<158>- {} Title: Body", std::process::id()));

    let mut m = mercurio();
    m.add(&format!("rsyslog://127.0.0.1:{port}/?logpid=no")).unwrap();
    let mut msg = Message::new("Disk full");
    msg.kind = mercurio::NotifyType::Failure;
    assert!(m.notify(&msg).is_success());
    let (n, _) = sock.recv_from(&mut buf).unwrap();
    assert_eq!(String::from_utf8_lossy(&buf[..n]), "<10>- Disk full");
}

#[test]
fn irc_register_join_privmsg() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut w = s.try_clone().unwrap();
        w.write_all(b":srv NOTICE * :*** hello\r\n").unwrap();
        let mut lines = Vec::new();
        for line in BufReader::new(s).lines() {
            let Ok(line) = line else { break };
            if line.starts_with("USER ") {
                w.write_all(b"PING :tok\r\n").unwrap();
            } else if line == "PONG :tok" {
                w.write_all(b":srv 001 bot :Welcome\r\n:srv 376 bot :End of MOTD\r\n").unwrap();
            } else if line == "JOIN #room" {
                w.write_all(b":bot!u@h JOIN :#room\r\n").unwrap();
            }
            let quit = line.starts_with("QUIT");
            lines.push(line);
            if quit {
                break;
            }
        }
        tx.send(lines).unwrap();
    });
    let mut m = mercurio();
    m.add(&format!("irc://bot:secret@127.0.0.1:{port}/%23room/@alice")).unwrap();
    let report = m.notify(&Message::new("line one\nline two").title("Hi"));
    assert!(report.is_success(), "{report:?}");
    let lines = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        lines,
        vec![
            "PASS secret",
            "NICK bot",
            "USER bot 0 * :Mercurio Notifications",
            "PONG :tok",
            "JOIN #room",
            "PRIVMSG #room :Hi",
            "PRIVMSG #room :line one",
            "PRIVMSG #room :line two",
            "PRIVMSG alice :Hi",
            "PRIVMSG alice :line one",
            "PRIVMSG alice :line two",
            "QUIT :Mercurio Notifications",
        ]
    );
}

use mercurio::Asset;
use mercurio::testing::fixtures::socket::describe;
use serde_json::json;

/// Serve one SMTP session; return every line the client sent.
fn loopback(advertise_starttls: bool, starttls_reply: &'static str) -> (u16, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);
        let mut lines = Vec::new();
        writer.write_all(b"220 loopback ESMTP\r\n").unwrap();
        let mut in_data = false;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let line = line.trim_end_matches(['\r', '\n']).to_string();
            lines.push(line.clone());
            if in_data {
                if line == "." {
                    in_data = false;
                    writer.write_all(b"250 queued\r\n").unwrap();
                }
                continue;
            }
            let cmd = line.split([' ', ':']).next().unwrap_or("").to_ascii_uppercase();
            let reply: &str = match cmd.as_str() {
                "EHLO" if advertise_starttls => "250-loopback\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n",
                "EHLO" => "250-loopback\r\n250 AUTH PLAIN\r\n",
                "STARTTLS" => starttls_reply,
                "AUTH" => "235 ok\r\n",
                "DATA" => {
                    in_data = true;
                    "354 go\r\n"
                }
                "QUIT" => {
                    writer.write_all(b"221 bye\r\n").ok();
                    break;
                }
                _ => "250 ok\r\n",
            };
            if writer.write_all(reply.as_bytes()).is_err() {
                break;
            }
        }
        lines
    });
    (port, handle)
}

#[test]
fn loopback_plain_delivery() {
    let (port, server) = loopback(false, "");
    let url = format!("mailto://bob:pw@127.0.0.1:{port}/alice@example.com?from=bob@example.com&name=Bob");
    let t = mercurio::parse(&url).unwrap();
    let msg = Message::new("Hello ✓\n.dot line").title("Grüße");
    let d = t.send(&msg, &BlockingTransport::new(), &Asset::default());
    assert!(d.is_success(), "{d:?}");
    let lines = server.join().unwrap();
    assert!(lines[0].starts_with("EHLO "));
    assert!(lines.contains(&format!("AUTH PLAIN {}", mercurio::crypto::b64(b"\0bob\0pw"))), "{lines:?}");
    assert!(lines.contains(&"MAIL FROM:<bob@example.com>".to_string()), "{lines:?}");
    assert!(lines.contains(&"RCPT TO:<alice@example.com>".to_string()));
    let start = lines.iter().position(|l| l == "DATA").unwrap() + 1;
    let end = lines.iter().rposition(|l| l == ".").unwrap();
    let raw: String = lines[start..end].iter().map(|l| format!("{}\r\n", l.strip_prefix('.').unwrap_or(l))).collect();
    let m = describe(&raw);
    let headers = m["headers"].as_array().unwrap();
    assert!(headers.contains(&json!(["subject", "Grüße"])), "{headers:?}");
    assert!(headers.contains(&json!(["from", "Bob <bob@example.com>"])));
    assert_eq!(m["body"]["parts"][1]["text"], "Hello ✓\n.dot line");
    assert_eq!(lines.last().unwrap(), "QUIT");
}

#[test]
fn loopback_starttls_not_offered_refuses_plaintext_auth() {
    let (port, server) = loopback(false, "");
    let t = mercurio::parse(&format!("mailtos://bob:pw@127.0.0.1:{port}?from=bob@example.com")).unwrap();
    let d = t.send(&Message::new("hi"), &BlockingTransport::new(), &Asset::default());
    assert!(!d.is_success());
    let lines = server.join().unwrap();
    assert!(lines.iter().all(|l| !l.starts_with("AUTH") && !l.starts_with("MAIL")), "{lines:?}");
}

#[test]
fn loopback_starttls_rejected() {
    let (port, server) = loopback(true, "454 TLS not available\r\n");
    let t = mercurio::parse(&format!("mailtos://bob:pw@127.0.0.1:{port}?from=bob@example.com")).unwrap();
    let d = t.send(&Message::new("hi"), &BlockingTransport::new(), &Asset::default());
    assert!(!d.is_success());
    let lines = server.join().unwrap();
    assert!(lines.contains(&"STARTTLS".to_string()));
    assert!(lines.iter().all(|l| !l.starts_with("AUTH") && !l.starts_with("MAIL")), "{lines:?}");
}

#[test]
fn loopback_starttls_handshake_failure() {
    // The server accepts STARTTLS but never speaks TLS: the handshake fails, no credentials leak.
    let (port, server) = loopback(true, "220 go ahead\r\n");
    let t = mercurio::parse(&format!("mailtos://bob:pw@127.0.0.1:{port}?from=bob@example.com&rto=2&cto=2")).unwrap();
    let d = t.send(&Message::new("hi"), &BlockingTransport::new(), &Asset::default());
    assert!(!d.is_success());
    let lines = server.join().unwrap();
    assert!(lines.iter().all(|l| !l.contains("AUTH")), "{lines:?}");
}
