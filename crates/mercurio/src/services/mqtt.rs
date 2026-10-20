//! MQTT (`mqtt://`, `mqtts://`): publishes the message to an MQTT broker.
//!
//! The client is built in: MQTT 3.1 / 3.1.1 / 5, with CONNECT (client id, clean session, credentials, keepalive 30) -> CONNACK, then one PUBLISH per topic (QoS 1 waits for PUBACK, QoS 2 runs PUBREC/PUBREL/PUBCOMP), then DISCONNECT.
//!
//! # Differences with Apprise
//!
//! - MQTT 5 works (Apprise passes `clean_session` to paho for every version, which paho rejects for v5). *intentional*
//! - TLS uses the bundled Mozilla roots or the `SSL_CERT_FILE` bundle (Apprise refuses verified `mqtts://` without a CA bundle on disk). *intentional*
//! - Topics of one notification are not throttled against each other (Apprise waits 0.5 s between publishes). *intentional*
//! - CONNACK is awaited before publishing (paho publishes asynchronously). *intentional*

use std::time::Duration;

use super::_sockets::{read_exact, send};
use crate::error::Error;
use crate::parse::parse_list;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::transport::{AsyncConn, Endpoint};
use crate::url::{ParsedUrl, unquote};
use crate::util::parse_int;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "mqtt",
    name: "MQTT Notification",
    schemes: &["mqtt", "mqtts"],
    service_url: "https://mqtt.org/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 268_435_455, body_max_line_count: 0 },
    throttle: Duration::from_millis(500),
    templates: &[
        "{schema}://{user}@{host}/{topic}",
        "{schema}://{user}@{host}:{port}/{topic}",
        "{schema}://{user}:{password}@{host}/{topic}",
        "{schema}://{user}:{password}@{host}:{port}/{topic}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("password", "Password").required().secret(),
        Param::new("port", "Port").port(),
        Param::new("targets", "Targets").list("/").group(&["topic"]),
        Param::new("topic", "Target Queue").required(),
        Param::new("user", "User Name").required(),
    ],
    params: &[
        Param::new("client_id", "Client ID"),
        Param::new("qos", "QOS").int().default("0").range(0, 2),
        Param::new("retain", "Retain Messages").bool(false),
        Param::new("session", "Use Session").bool(false),
        Param::sets("to", &["targets"]),
        Param::new("version", "Version").choice(&["v3.1.1", "v3.1", "v5.0"]).default("v3.1.1"),
    ],
    ..ServiceDef::DEFAULTS
};

const INSECURE_PORT: u16 = 1883;
const SECURE_PORT: u16 = 8883;
const KEEPALIVE: u16 = 30;

/// MQTT protocol levels (3.1, 3.1.1, 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V31 = 3,
    V311 = 4,
    V5 = 5,
}

#[derive(Debug)]
struct Mqtt {
    host: String,
    port: u16,
    secure: bool,
    user: Option<String>,
    password: Option<Secret>,
    topics: Vec<String>,
    version: Version,
    qos: u8,
    client_id: Option<String>,
    session: bool,
    retain: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let mut targets: Vec<String> = match &u.fullpath {
        Some(p) => parse_list([unquote(p.trim_start_matches('/'))]),
        None => Vec::new(),
    };
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }
    let topics = parse_list(targets);

    let version_str = SERVICE.text_or_default(u, "version");
    let digits: String = version_str.chars().filter(char::is_ascii_digit).collect();
    let version = match digits.as_str() {
        "311" => Version::V311,
        "31" => Version::V31,
        "5" | "50" => Version::V5,
        _ => return Err(SERVICE.err(format!("An invalid MQTT Protocol version ({version_str}) was specified."))),
    };

    let client_id = SERVICE.text(u, "client_id");
    let session = client_id.as_ref().is_some_and(|c| !c.is_empty()) && SERVICE.flag(u, "session");
    let retain = SERVICE.flag(u, "retain");
    let q = SERVICE.text_or_default(u, "qos");
    let qos = match parse_int(&q) {
        Some(v @ 0..=2) => v as u8,
        _ => return Err(SERVICE.err(format!("An invalid MQTT QOS ({q}) was specified."))),
    };
    let port = u.port.filter(|p| *p != 0).unwrap_or(if u.secure { SECURE_PORT } else { INSECURE_PORT });
    Ok(Box::new(Mqtt {
        host: u.host(),
        port,
        secure: u.secure,
        user: u.user().filter(|s| !s.is_empty()),
        password: u.password().map(Secret::new),
        topics,
        version,
        qos,
        client_id,
        session,
        retain,
    }))
}

/// MQTT "remaining length" variable byte integer (max 268,435,455).
pub fn encode_varint(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = (n % 128) as u8;
        n /= 128;
        if n > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
}

/// Decode a variable byte integer; returns (value, bytes used).
pub fn decode_varint(data: &[u8]) -> Option<(usize, usize)> {
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

fn put_str(out: &mut Vec<u8>, s: &[u8]) {
    let len = s.len().min(u16::MAX as usize);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(&s[..len]);
}

fn packet(header: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![header];
    encode_varint(body.len(), &mut out);
    out.extend_from_slice(body);
    out
}

/// CONNECT packet.
pub fn connect_packet(
    version: Version,
    client_id: &str,
    clean: bool,
    keepalive: u16,
    user: Option<&str>,
    password: Option<&str>,
) -> Vec<u8> {
    let mut body = Vec::new();
    put_str(&mut body, if version == Version::V31 { b"MQIsdp" } else { b"MQTT" });
    body.push(version as u8);
    let mut flags = 0u8;
    if clean {
        flags |= 0x02;
    }
    if user.is_some() {
        flags |= 0x80;
    }
    if password.is_some() {
        flags |= 0x40;
    }
    body.push(flags);
    body.extend_from_slice(&keepalive.to_be_bytes());
    if version == Version::V5 {
        body.push(0); // no properties
    }
    put_str(&mut body, client_id.as_bytes());
    if let Some(u) = user {
        put_str(&mut body, u.as_bytes());
    }
    if let Some(p) = password {
        put_str(&mut body, p.as_bytes());
    }
    packet(0x10, &body)
}

/// PUBLISH packet (`packet_id` is ignored for QoS 0).
pub fn publish_packet(version: Version, topic: &str, payload: &[u8], qos: u8, retain: bool, packet_id: u16) -> Vec<u8> {
    let mut body = Vec::new();
    put_str(&mut body, topic.as_bytes());
    if qos > 0 {
        body.extend_from_slice(&packet_id.to_be_bytes());
    }
    if version == Version::V5 {
        body.push(0);
    }
    body.extend_from_slice(payload);
    packet(0x30 | (qos << 1) | u8::from(retain), &body)
}

/// A control packet read from the broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub kind: u8,
    pub flags: u8,
    pub body: Vec<u8>,
}

async fn read_packet(conn: &mut dyn AsyncConn) -> Result<Packet> {
    let mut head = [0u8; 1];
    read_exact(conn, &mut head).await?;
    let mut len_bytes = Vec::new();
    loop {
        let mut b = [0u8; 1];
        read_exact(conn, &mut b).await?;
        len_bytes.push(b[0]);
        if b[0] & 0x80 == 0 {
            break;
        }
        if len_bytes.len() == 4 {
            return Err(Error::transport("MQTT: malformed remaining length"));
        }
    }
    let (len, _) = decode_varint(&len_bytes).ok_or_else(|| Error::transport("MQTT: malformed remaining length"))?;
    let mut body = vec![0u8; len];
    read_exact(conn, &mut body).await?;
    Ok(Packet { kind: head[0] >> 4, flags: head[0] & 0x0f, body })
}

/// Read packets until one of `kind` arrives (others, e.g. PINGRESP, are skipped).
async fn expect_packet(conn: &mut dyn AsyncConn, kind: u8, packet_id: Option<u16>) -> Result<Packet> {
    loop {
        let p = read_packet(conn).await?;
        if p.kind != kind {
            continue;
        }
        if let Some(id) = packet_id
            && (p.body.len() < 2 || u16::from_be_bytes([p.body[0], p.body[1]]) != id)
        {
            continue;
        }
        return Ok(p);
    }
}

fn connack_error(version: Version, code: u8) -> String {
    let reason = match (version, code) {
        (Version::V5, _) => "connection refused",
        (_, 1) => "unacceptable protocol version",
        (_, 2) => "identifier rejected",
        (_, 3) => "server unavailable",
        (_, 4) => "bad user name or password",
        (_, 5) => "not authorised",
        _ => "connection refused",
    };
    format!("MQTT broker refused the connection: {reason} (code {code})")
}

/// v5 acks carry a reason code after the packet id (absent = success).
fn ack_failed(version: Version, p: &Packet) -> bool {
    version == Version::V5 && p.body.len() > 2 && p.body[2] >= 0x80
}

/// Random client id for MQTT 3.1 (22 base62 characters).
fn random_client_id() -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut buf = [0u8; 22];
    crate::crypto::random_bytes(&mut buf);
    buf.iter().map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char).collect()
}

struct Session {
    version: Version,
    client_id: String,
    clean: bool,
    user: Option<String>,
    password: Option<String>,
    topics: Vec<String>,
    payload: Vec<u8>,
    qos: u8,
    retain: bool,
}

async fn run_session(s: Session, conn: &mut dyn AsyncConn) -> Result<()> {
    let connect = connect_packet(s.version, &s.client_id, s.clean, KEEPALIVE, s.user.as_deref(), s.password.as_deref());
    send(conn, &connect).await?;
    let ack = expect_packet(conn, 2, None).await?;
    let code_at = 1;
    let code = ack.body.get(code_at).copied().unwrap_or(0xff);
    if code != 0 {
        return Err(Error::Service(connack_error(s.version, code)));
    }
    let mut packet_id: u16 = 0;
    for topic in &s.topics {
        packet_id = packet_id.checked_add(1).unwrap_or(1);
        send(conn, &publish_packet(s.version, topic, &s.payload, s.qos, s.retain, packet_id)).await?;
        match s.qos {
            1 => {
                let p = expect_packet(conn, 4, Some(packet_id)).await?;
                if ack_failed(s.version, &p) {
                    return Err(Error::Service(format!("MQTT broker rejected the message for {topic}")));
                }
            }
            2 => {
                let p = expect_packet(conn, 5, Some(packet_id)).await?;
                if ack_failed(s.version, &p) {
                    return Err(Error::Service(format!("MQTT broker rejected the message for {topic}")));
                }
                send(conn, &packet(0x62, &packet_id.to_be_bytes())).await?;
                expect_packet(conn, 7, Some(packet_id)).await?;
            }
            _ => {}
        }
    }
    // Best effort: the messages are already delivered.
    send(conn, &[0xe0, 0x00]).await.ok();
    Ok(())
}

impl Notify for Mqtt {
    fn plan(&self, msg: &Prepared<'_>, _ctx: &Context<'_>) -> Plan {
        if self.topics.is_empty() {
            return Plan::Fail(Error::Message("there were no MQTT topics to notify".into()));
        }
        let client_id = match &self.client_id {
            Some(c) if !c.is_empty() => c.clone(),
            _ if self.version == Version::V31 => random_client_id(),
            _ => String::new(),
        };
        let topics: Vec<String> = self.topics.clone();
        let session = Session {
            version: self.version,
            client_id,
            clean: !self.session,
            user: self.user.clone(),
            password: if self.user.is_some() { self.password.as_ref().map(|p| p.expose().to_string()) } else { None },
            topics,
            payload: msg.body.as_bytes().to_vec(),
            qos: self.qos,
            retain: self.retain,
        };
        let ep = Endpoint::new(self.host.clone(), self.port, self.secure);
        Plan::socket(ep, move |conn, _| Box::pin(run_session(session, conn)))
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        for (n, bytes) in [
            (0usize, vec![0x00]),
            (127, vec![0x7f]),
            (128, vec![0x80, 0x01]),
            (16_383, vec![0xff, 0x7f]),
            (16_384, vec![0x80, 0x80, 0x01]),
            (2_097_151, vec![0xff, 0xff, 0x7f]),
            (2_097_152, vec![0x80, 0x80, 0x80, 0x01]),
            (268_435_455, vec![0xff, 0xff, 0xff, 0x7f]),
        ] {
            let mut out = Vec::new();
            encode_varint(n, &mut out);
            assert_eq!(out, bytes, "encode {n}");
            assert_eq!(decode_varint(&bytes), Some((n, bytes.len())), "decode {n}");
        }
        assert_eq!(decode_varint(&[0x80, 0x80, 0x80, 0x80, 0x01]), None);
    }

    #[test]
    fn connect_v311_bytes() {
        let p = connect_packet(Version::V311, "id", true, 30, Some("u"), Some("p"));
        assert_eq!(
            p,
            vec![0x10, 20, 0, 4, b'M', b'Q', b'T', b'T', 4, 0xc2, 0, 30, 0, 2, b'i', b'd', 0, 1, b'u', 0, 1, b'p']
        );
        let p = connect_packet(Version::V31, "", false, 30, None, None);
        assert_eq!(&p[2..10], &[0, 6, b'M', b'Q', b'I', b's', b'd', b'p']);
        assert_eq!(p[10], 3);
        assert_eq!(p[11], 0);
    }

    #[test]
    fn connect_v5_has_properties() {
        let p = connect_packet(Version::V5, "", true, 30, None, None);
        assert_eq!(p, vec![0x10, 13, 0, 4, b'M', b'Q', b'T', b'T', 5, 0x02, 0, 30, 0, 0, 0]);
    }

    #[test]
    fn publish_bytes() {
        assert_eq!(
            publish_packet(Version::V311, "a/b", b"hi", 0, false, 7),
            vec![0x30, 7, 0, 3, b'a', b'/', b'b', b'h', b'i']
        );
        assert_eq!(publish_packet(Version::V311, "t", b"x", 1, true, 258), vec![0x33, 6, 0, 1, b't', 1, 2, b'x']);
        assert_eq!(publish_packet(Version::V5, "t", b"x", 2, false, 1), vec![0x34, 7, 0, 1, b't', 0, 1, 0, b'x']);
    }

    #[test]
    fn client_id_shape() {
        let id = random_client_id();
        assert_eq!(id.len(), 22);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
