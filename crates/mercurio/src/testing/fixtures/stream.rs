//! Raw-protocol comparators: IRC, APRS, MQTT, syslog, rsyslog.
//!
//! Stream services get one `ScriptedConn` per connection script in the case `responses` (`greeting` / `replies` / `refuse`), interpreted exactly like a fake server; the bytes mercurio writes are decoded back into the same event shapes. MQTT gets a scripted broker (`{"mqtt": {"connack": n, "ack": bool, "connect_error": bool}}`).

use std::sync::{Arc, Mutex};

use regex::Regex;
use serde_json::{Value, json};

use super::events::{Comparator, Log};
use crate::testing::{FakeTransport, ScriptedConn};

/// Connection scripts (`greeting` / `replies` / `refuse`) in case order.
fn scripts(case: &Value) -> Vec<Value> {
    case.get("responses")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter(|s| s.get("replies").is_some() || s.get("greeting").is_some() || s.get("refuse").is_some())
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn replies(script: &Value) -> Vec<(Regex, String)> {
    script["replies"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|r| (Regex::new(r[0].as_str().unwrap()).unwrap(), r[1].as_str().unwrap_or("").to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn reply_for(rules: &[(Regex, String)], text: &str) -> Option<String> {
    rules.iter().find(|(re, _)| re.is_match(text)).map(|(_, r)| r.clone())
}

/// Push one `ScriptedConn` per script (stopping at the first refusal); returns each connection's send log.
fn push_stream_conns(fake: &FakeTransport, case: &Value) -> Vec<Log> {
    let mut logs = Vec::new();
    for script in scripts(case) {
        if script.get("refuse").and_then(Value::as_bool).unwrap_or(false) {
            break;
        }
        let rules = replies(&script);
        let greeting = script.get("greeting").and_then(Value::as_str).unwrap_or("").to_string();
        let log: Log = Arc::default();
        let l = log.clone();
        let conn = ScriptedConn::lines(greeting, move |line| {
            l.lock().unwrap().push(line.to_string());
            reply_for(&rules, line)
        });
        fake.push_conn(conn);
        logs.push(log);
    }
    logs
}

fn stream_events(fake: &FakeTransport, logs: &[Log]) -> Vec<Value> {
    let mut out = Vec::new();
    for (ep, log) in fake.endpoints().iter().zip(logs) {
        out.push(json!({"connect": {"host": ep.host, "port": ep.port, "tls": ep.tls}}));
        for s in log.lock().unwrap().iter() {
            out.push(json!({"send": s}));
        }
    }
    out
}

/// One decoded MQTT control packet.
#[derive(Debug, Clone)]
struct Packet {
    kind: u8,
    flags: u8,
    body: Vec<u8>,
}

fn decode_varint(data: &[u8]) -> Option<(usize, usize)> {
    let mut value = 0usize;
    let mut mult = 1usize;
    for (i, b) in data.iter().enumerate().take(4) {
        value += (*b as usize & 0x7f) * mult;
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
        mult *= 128;
    }
    None
}

fn split_packets(mut data: &[u8]) -> Vec<Packet> {
    let mut out = Vec::new();
    while data.len() >= 2 {
        let Some((len, n)) = decode_varint(&data[1..]) else { break };
        let start = 1 + n;
        if data.len() < start + len {
            break;
        }
        out.push(Packet { kind: data[0] >> 4, flags: data[0] & 0x0f, body: data[start..start + len].to_vec() });
        data = &data[start + len..];
    }
    out
}

fn read_str(body: &[u8], pos: &mut usize) -> String {
    let len = u16::from_be_bytes([body[*pos], body[*pos + 1]]) as usize;
    let s = String::from_utf8_lossy(&body[*pos + 2..*pos + 2 + len]).to_string();
    *pos += 2 + len;
    s
}

fn skip_props(body: &[u8], pos: &mut usize) {
    let (len, n) = decode_varint(&body[*pos..]).unwrap();
    *pos += n + len;
}

struct Connect {
    level: u8,
    client_id: String,
    clean: bool,
    keepalive: u16,
    username: Option<String>,
    password: Option<String>,
}

fn parse_connect(body: &[u8]) -> Connect {
    let mut pos = 0;
    let _name = read_str(body, &mut pos);
    let level = body[pos];
    let flags = body[pos + 1];
    let keepalive = u16::from_be_bytes([body[pos + 2], body[pos + 3]]);
    pos += 4;
    if level == 5 {
        skip_props(body, &mut pos);
    }
    let client_id = read_str(body, &mut pos);
    let username = (flags & 0x80 != 0).then(|| read_str(body, &mut pos));
    let password = (flags & 0x40 != 0).then(|| read_str(body, &mut pos));
    Connect { level, client_id, clean: flags & 0x02 != 0, keepalive, username, password }
}

fn varint_len(mut n: usize) -> usize {
    let mut len = 1;
    while n >= 128 {
        n /= 128;
        len += 1;
    }
    len
}

struct MqttBroker {
    written: Arc<Mutex<Vec<u8>>>,
}

fn push_mqtt(fake: &FakeTransport, case: &Value) -> Option<MqttBroker> {
    let script = case
        .get("responses")
        .and_then(Value::as_array)
        .and_then(|a| a.iter().find_map(|s| s.get("mqtt").cloned()))
        .unwrap_or_else(|| json!({}));
    if script.get("connect_error").and_then(Value::as_bool).unwrap_or(false) {
        return None;
    }
    let connack = script.get("connack").and_then(Value::as_u64).unwrap_or(0) as u8;
    let ack = script.get("ack").and_then(Value::as_bool).unwrap_or(true);
    let pending = Arc::new(Mutex::new(Vec::<u8>::new()));
    let conn = ScriptedConn::bytes(Vec::new(), move |chunk| {
        let mut buf = pending.lock().unwrap();
        buf.extend_from_slice(chunk);
        let packets = split_packets(&buf);
        let consumed: usize = packets.iter().map(|p| 1 + varint_len(p.body.len()) + p.body.len()).sum();
        buf.drain(..consumed);
        let mut reply = Vec::new();
        for p in packets {
            match p.kind {
                1 => {
                    if parse_connect(&p.body).level == 5 {
                        reply.extend([0x20, 0x03, 0x00, connack, 0x00]);
                    } else {
                        reply.extend([0x20, 0x02, 0x00, connack]);
                    }
                }
                3 => {
                    let qos = (p.flags >> 1) & 0x03;
                    if qos > 0 && ack {
                        let mut pos = 0;
                        let _topic = read_str(&p.body, &mut pos);
                        reply.extend([if qos == 1 { 0x40 } else { 0x50 }, 0x02, p.body[pos], p.body[pos + 1]]);
                    }
                }
                6 => reply.extend([0x70, 0x02, p.body[0], p.body[1]]),
                _ => {}
            }
        }
        reply
    });
    let written = conn.written();
    fake.push_conn(conn);
    Some(MqttBroker { written })
}

fn mqtt_events(fake: &FakeTransport, broker: Option<&MqttBroker>) -> Vec<Value> {
    let mut out = Vec::new();
    let (Some(broker), Some(ep)) = (broker, fake.endpoints().first().cloned()) else {
        return out;
    };
    let data = broker.written.lock().unwrap().clone();
    let mut level = 4;
    for p in split_packets(&data) {
        match p.kind {
            1 => {
                let c = parse_connect(&p.body);
                level = c.level;
                let clean = if c.level == 5 { Value::Null } else { Value::Bool(c.clean) };
                out.push(json!({"client": {"client_id": c.client_id, "clean_session": clean, "protocol": c.level}}));
                if let Some(u) = &c.username {
                    out.push(json!({"username_pw_set": {"username": u, "password": c.password}}));
                }
                if ep.tls {
                    out.push(json!({"tls": {"verify": ep.verify_tls}}));
                }
                out.push(json!({"connect": {"host": ep.host, "port": ep.port, "keepalive": c.keepalive}}));
            }
            3 => {
                let qos = (p.flags >> 1) & 0x03;
                let mut pos = 0;
                let topic = read_str(&p.body, &mut pos);
                if qos > 0 {
                    pos += 2;
                }
                if level == 5 {
                    skip_props(&p.body, &mut pos);
                }
                let payload = String::from_utf8_lossy(&p.body[pos..]).to_string();
                out.push(
                    json!({"publish": {"topic": topic, "payload": payload, "qos": qos, "retain": p.flags & 1 == 1}}),
                );
            }
            _ => {}
        }
    }
    out
}

fn syslog_events(fake: &FakeTransport) -> Vec<Value> {
    let re = Regex::new(r"(?s)^<(\d+)>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d ([^\[:]+)(\[\d+\])?: (.*)$").unwrap();
    fake.datagrams()
        .iter()
        .map(|d| {
            assert!(
                matches!(&d.target, crate::transport::DatagramTarget::Unix(p) if p == "/dev/log" || p == "/var/run/syslog"),
                "unexpected syslog target {:?}",
                d.target
            );
            let text = String::from_utf8_lossy(&d.payload).to_string();
            let c = re.captures(&text).unwrap_or_else(|| panic!("bad syslog line {text:?}"));
            let pri: u64 = c[1].parse().unwrap();
            json!({"syslog": {
                "ident": &c[2],
                "pid": c.get(3).is_some(),
                "facility": pri & !7,
                "priority": pri & 7,
                "message": &c[4],
            }})
        })
        .collect()
}

fn rsyslog_events(fake: &FakeTransport) -> Vec<Value> {
    fake.datagrams()
        .iter()
        .map(|d| {
            let crate::transport::DatagramTarget::Udp { host, port } = &d.target else {
                panic!("rsyslog must use UDP")
            };
            json!({"sendto": {"host": host, "port": port}, "payload": String::from_utf8_lossy(&d.payload)})
        })
        .collect()
}

pub(super) const LINES: Comparator = Comparator {
    services: &["irc", "aprs"],
    setup: |s, case| s.logs = push_stream_conns(&s.fake, case),
    events: |s, _| stream_events(&s.fake, &s.logs),
    ..Comparator::DEFAULT
};

pub(super) const MQTT: Comparator = Comparator {
    services: &["mqtt"],
    setup: |s, case| s.written = push_mqtt(&s.fake, case).map(|b| b.written),
    events: |s, _| mqtt_events(&s.fake, s.written.clone().map(|written| MqttBroker { written }).as_ref()),
    ..Comparator::DEFAULT
};

pub(super) const SYSLOG: Comparator =
    Comparator { services: &["syslog"], events: |s, _| syslog_events(&s.fake), ..Comparator::DEFAULT };

pub(super) const RSYSLOG: Comparator =
    Comparator { services: &["rsyslog"], events: |s, _| rsyslog_events(&s.fake), ..Comparator::DEFAULT };
