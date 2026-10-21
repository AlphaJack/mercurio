//! SMPP (`smpp://`, `smpps://`): SMS through an SMPP server, with a built-in SMPP v3.4 client: `bind_transmitter`, one `submit_sm` per segment and target, `unbind`.
//!
//! PDUs: sequence numbers start at 2, `registered_delivery=1`, GSM 7-bit unpacked or UCS-2 with concatenation UDH above 160 / 140 octets, string fields truncated to the SMPP maxima.
//!
//! Divergences: an explicit `:port` is honoured (otherwise 2775 / 3550); `smpps://` uses TLS; `submit_sm_resp` statuses are checked.
//!
//! # Differences with Apprise
//!
//! - An explicit `:port` is honoured (Apprise always uses 2775 / 3550).
//! - `smpps://` uses TLS (Apprise opens a plain socket).
//! - `submit_sm_resp` statuses are checked (Apprise never reads them).

use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::error::{Error, Result};
use crate::machine::{Input, Output, Protocol};
use crate::parse::{is_phone_no, parse_phone_no, parse_phone_no_unquoted};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::transport::Endpoint;
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "smpp",
    name: "SMPP",
    schemes: &["smpp", "smpps"],
    service_url: "https://smpp.org/",
    parse,
    limits: Limits { title_maxlen: 0, ..Limits::DEFAULT },
    templates: &[
        "{schema}://{user}:{password}@{host}/{from_phone}/{targets}",
        "{schema}://{user}:{password}@{host}:{port}/{from_phone}/{targets}",
    ],
    tokens: &[
        Param::new("from_phone", "From Phone No").required().pattern(r"^[0-9\s)(+-]+$"),
        Param::new("host", "Host").required(),
        Param::new("password", "Password").required().secret(),
        Param::new("port", "Port").port(),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").required().group(&["target_phone"]),
        Param::new("user", "Username").required(),
    ],
    params: &[
        Param::sets("from", &["from_phone"]),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const DEFAULT_PORT: u16 = 2775;
const DEFAULT_SECURE_PORT: u16 = 3550;

pub const BIND_TRANSMITTER: u32 = 0x0000_0002;
pub const SUBMIT_SM: u32 = 0x0000_0004;
pub const UNBIND: u32 = 0x0000_0006;
pub const ENQUIRE_LINK: u32 = 0x0000_0015;
pub const GENERIC_NACK: u32 = 0x8000_0000;
const RESP: u32 = 0x8000_0000;

const TON_INTL: u8 = 0x01;
const ENCODING_DEFAULT: u8 = 0x00;
const ENCODING_UCS2: u8 = 0x08;
const ESM_UDHI: u8 = 0x40;

#[derive(Debug)]
struct Smpp {
    host: String,
    port: u16,
    tls: bool,
    system_id: String,
    password: Secret,
    source: String,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_phone_no_unquoted([to], false));
    }
    let source = match u.param_nonempty("from") {
        Some(f) => Some(unquote(f)),
        None if !targets.is_empty() => Some(targets.remove(0)),
        None => None,
    };

    let (Some(user), Some(password)) = (u.user().filter(|s| !s.is_empty()), u.password().filter(|s| !s.is_empty()))
    else {
        return Err(SERVICE.err("no SMPP user/pass combination was provided"));
    };
    let source = source
        .as_deref()
        .and_then(|s| is_phone_no(s, 10))
        .ok_or_else(|| SERVICE.err("the Account (From) Phone # specified is invalid"))?
        .full;
    let targets = parse_phone_no(&targets, true, true)
        .into_iter()
        .filter_map(|t| {
            let p = is_phone_no(&t, 10);
            if p.is_none() {
                log::warn!("SMPP: dropped invalid phone # ({t})");
            }
            p.map(|p| p.full)
        })
        .collect();
    let port = u.port.filter(|p| *p != 0).unwrap_or(if u.secure { DEFAULT_SECURE_PORT } else { DEFAULT_PORT });
    Ok(Box::new(Smpp {
        host: u.host(),
        port,
        tls: u.secure,
        system_id: user,
        password: Secret::new(password),
        source,
        targets,
    }))
}

impl Notify for Smpp {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Message("there were no SMPP targets to notify".into()));
        }
        let (parts, coding, esm) = match make_parts(msg.body, crypto_ref(ctx.env().as_ref())) {
            Ok(p) => p,
            Err(e) => return Plan::Fail(e),
        };
        let job = Job {
            system_id: self.system_id.clone(),
            password: self.password.clone(),
            source: self.source.clone(),
            targets: self.targets.clone(),
            parts,
            coding,
            esm,
        };
        let ep = Endpoint::new(self.host.clone(), self.port, self.tls);
        Plan::socket(ep, move |conn, transport| Box::pin(crate::machine::drive(Session::new(job), conn, transport)))
    }

}

fn crypto_ref(env: &dyn crate::Env) -> u8 {
    let mut b = [0u8; 1];
    env.fill_random(&mut b);
    b[0]
}

/// GSM 03.38 alphabet: index < 0x80 is one octet, the rest are `ESC` + (index - 0x80).
const GSM_TABLE: &str = concat!(
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>",
    "?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ`¿abcdefghijklmnopqrstuvwxyzäöñüà",
    "````````````````````^```````````````````{}`````\\````````````[~]`",
    "|````````````````````````````````````€``````````````````````````",
);

/// GSM 03.38 default alphabet, unpacked (one septet per octet); `None` if a character is not representable.
pub fn gsm_encode(text: &str) -> Option<Vec<u8>> {
    // Each character's first index in `GSM_TABLE`.
    static INDEX: LazyLock<BTreeMap<char, usize>> = LazyLock::new(|| {
        let mut m = BTreeMap::new();
        for (i, t) in GSM_TABLE.chars().enumerate() {
            m.entry(t).or_insert(i);
        }
        m
    });
    let mut out = Vec::with_capacity(text.len());
    for c in text.chars() {
        let idx = *INDEX.get(&c)?;
        if idx < 0x80 {
            out.push(idx as u8);
        } else {
            out.push(0x1b);
            out.push((idx - 0x80) as u8);
        }
    }
    Some(out)
}

/// Split `text` into segments: (segments, data_coding, esm_class).
pub fn make_parts(text: &str, reference: u8) -> Result<(Vec<Vec<u8>>, u8, u8)> {
    let (encoded, coding, split, part_size) = match gsm_encode(text) {
        Some(e) => (e, ENCODING_DEFAULT, 160, 153),
        None => {
            let e: Vec<u8> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
            (e, ENCODING_UCS2, 140, 134)
        }
    };
    if encoded.len() <= split {
        return Ok((vec![encoded], coding, 0));
    }
    let chunks: Vec<&[u8]> = encoded.chunks(part_size).collect();
    if chunks.len() > 255 {
        return Err(Error::Message("message too long for SMPP concatenation (more than 255 parts)".into()));
    }
    let total = chunks.len() as u8;
    let parts = chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            let mut p = vec![0x05, 0x00, 0x03, reference, total, (i + 1) as u8];
            p.extend_from_slice(chunk);
            p
        })
        .collect();
    Ok((parts, coding, ESM_UDHI))
}

/// C-octet string truncated to `max` (which includes the NUL).
fn cstr(out: &mut Vec<u8>, s: &str, max: usize) {
    let chars: Vec<char> = s.chars().filter(|c| *c != '\0').take(max - 1).collect();
    if chars.iter().all(|c| (*c as u32) <= 0xff) {
        out.extend(chars.iter().map(|c| *c as u32 as u8));
    } else {
        let s: String = chars.into_iter().collect();
        let bytes = s.as_bytes();
        out.extend_from_slice(&bytes[..bytes.len().min(max - 1)]);
    }
    out.push(0);
}

/// A full PDU: 16-byte header (length, command, status 0, sequence) + body.
pub fn pdu(command: u32, seq: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&((16 + body.len()) as u32).to_be_bytes());
    out.extend_from_slice(&command.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(body);
    out
}

pub fn bind_transmitter(seq: u32, system_id: &str, password: &str) -> Vec<u8> {
    let mut b = Vec::new();
    cstr(&mut b, system_id, 16);
    cstr(&mut b, password, 9);
    cstr(&mut b, "", 13); // system_type
    b.push(0x34); // interface_version
    b.push(0); // addr_ton
    b.push(0); // addr_npi
    cstr(&mut b, "", 41); // address_range
    pdu(BIND_TRANSMITTER, seq, &b)
}

pub fn submit_sm(seq: u32, source: &str, dest: &str, coding: u8, esm: u8, message: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    cstr(&mut b, "", 6); // service_type
    b.push(TON_INTL);
    b.push(0); // source_addr_npi
    cstr(&mut b, source, 21);
    b.push(TON_INTL);
    b.push(0); // dest_addr_npi
    cstr(&mut b, dest, 21);
    b.push(esm);
    b.push(0); // protocol_id
    b.push(0); // priority_flag
    cstr(&mut b, "", 17); // schedule_delivery_time
    cstr(&mut b, "", 17); // validity_period
    b.push(1); // registered_delivery
    b.push(0); // replace_if_present_flag
    b.push(coding);
    b.push(0); // sm_default_msg_id
    let message = &message[..message.len().min(254)];
    b.push(message.len() as u8);
    b.extend_from_slice(message);
    pdu(SUBMIT_SM, seq, &b)
}

#[derive(Debug)]
struct Job {
    system_id: String,
    password: Secret,
    source: String,
    targets: Vec<String>,
    parts: Vec<Vec<u8>>,
    coding: u8,
    esm: u8,
}

struct Pdu {
    command: u32,
    status: u32,
    seq: u32,
}

/// The next complete PDU in `buf`, removed from it; `Ok(None)` until one has fully arrived.
fn take_pdu(buf: &mut Vec<u8>) -> Result<Option<Pdu>> {
    let Some(head) = buf.get(..16) else { return Ok(None) };
    let word = |i: usize| u32::from_be_bytes([head[i], head[i + 1], head[i + 2], head[i + 3]]);
    let len = word(0) as usize;
    if !(16..=65_536).contains(&len) {
        return Err(Error::transport(format!("invalid SMPP PDU length {len}")));
    }
    if buf.len() < len {
        return Ok(None);
    }
    let p = Pdu { command: word(4), status: word(8), seq: word(12) };
    buf.drain(..len);
    Ok(Some(p))
}

/// PDUs read while waiting for one response before giving up.
const MAX_WAIT_PDUS: usize = 64;

/// The request whose response a session waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Bind,
    /// `submit_sm` of `parts[part]` to `targets[target]`.
    Submit { target: usize, part: usize },
    /// The answer (or a failure to get one) is ignored.
    Unbind,
    Done,
}

/// An SMPP session as a sans-IO state machine.
struct Session {
    job: Job,
    state: State,
    /// Sequence number of the request in flight.
    seq: u32,
    /// PDUs read while waiting for its response.
    seen: usize,
    rx: Vec<u8>,
    out: Vec<u8>,
    failed: Vec<String>,
    result: Option<Result<()>>,
}

impl Session {
    fn new(job: Job) -> Self {
        // The sequence counter starts at 1 and pre-increments (first PDU: 2).
        let mut s = Session { job, state: State::Bind, seq: 1, seen: 0, rx: Vec::new(), out: Vec::new(), failed: Vec::new(), result: None };
        let seq = s.next_seq();
        let bind = bind_transmitter(seq, &s.job.system_id, s.job.password.expose());
        s.request(&bind, State::Bind);
        s
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = if self.seq >= 0x7FFF_FFFF { 1 } else { self.seq + 1 };
        self.seq
    }

    fn request(&mut self, pdu: &[u8], state: State) {
        self.out.extend_from_slice(pdu);
        self.state = state;
        self.seen = 0;
    }

    fn fail(&mut self, err: Error) {
        self.result.get_or_insert(Err(err));
        self.state = State::Done;
    }

    /// A read or write failed: fatal, except while unbinding.
    fn io_failed(&mut self, err: Error) {
        if self.state == State::Unbind {
            self.finish();
        } else {
            self.fail(err);
        }
    }

    /// Submit `parts[part]` to `targets[target]`, moving to the next target after the last part, and unbind after the last target.
    fn submit(&mut self, mut target: usize, mut part: usize) {
        if part >= self.job.parts.len() {
            target += 1;
            part = 0;
        }
        if target >= self.job.targets.len() || self.job.parts.is_empty() {
            let seq = self.next_seq();
            return self.request(&pdu(UNBIND, seq, &[]), State::Unbind);
        }
        let seq = self.next_seq();
        let j = &self.job;
        let p = submit_sm(seq, &j.source, &j.targets[target], j.coding, j.esm, &j.parts[part]);
        self.request(&p, State::Submit { target, part });
    }

    fn on_pdu(&mut self, p: &Pdu) {
        if p.command == ENQUIRE_LINK {
            self.out.extend_from_slice(&pdu(ENQUIRE_LINK | RESP, p.seq, &[]));
        } else if p.seq == self.seq && p.command & RESP != 0 {
            return self.on_response(p);
        }
        self.seen += 1;
        if self.seen >= MAX_WAIT_PDUS {
            self.io_failed(Error::transport("no SMPP response"));
        }
    }

    fn on_response(&mut self, r: &Pdu) {
        let ok = r.status == 0 && r.command != GENERIC_NACK;
        match self.state {
            State::Bind if !ok => {
                self.fail(Error::Service(format!("SMPP bind_transmitter failed: {}", status_text(r.status))));
            }
            State::Bind => self.submit(0, 0),
            State::Submit { target, part } if ok => self.submit(target, part + 1),
            State::Submit { target, .. } => {
                self.failed.push(format!("{}: {}", self.job.targets[target], status_text(r.status)));
                self.submit(target + 1, 0);
            }
            State::Unbind => self.finish(),
            State::Done => {}
        }
    }

    fn finish(&mut self) {
        let res = if self.failed.is_empty() {
            Ok(())
        } else {
            Err(Error::Service(format!("SMPP submit_sm failed for {}", self.failed.join(", "))))
        };
        self.result.get_or_insert(res);
        self.state = State::Done;
    }
}

impl Protocol for Session {
    fn next(&mut self) -> Output {
        if !self.out.is_empty() {
            return Output::Write(std::mem::take(&mut self.out));
        }
        match self.state {
            State::Done => Output::Done(self.result.take().unwrap_or(Ok(()))),
            State::Bind | State::Submit { .. } | State::Unbind => Output::Read,
        }
    }

    fn input(&mut self, input: Input<'_>) {
        match input {
            Input::Data([]) => self.io_failed(Error::transport(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            ))),
            Input::Data(data) => {
                self.rx.extend_from_slice(data);
                while self.state != State::Done {
                    match take_pdu(&mut self.rx) {
                        Ok(Some(p)) => self.on_pdu(&p),
                        Ok(None) => break,
                        Err(e) => self.io_failed(e),
                    }
                }
            }
            Input::ReadError(e) | Input::WriteError(e) => self.io_failed(Error::transport(e)),
            Input::ChannelBinding(_) => {}
            Input::Tls(r) => {
                if let Err(e) = r {
                    self.fail(e);
                }
            }
        }
    }
}

fn status_text(status: u32) -> String {
    let desc = match status {
        0x01 => "Message Length is invalid",
        0x02 => "Command Length is invalid",
        0x03 => "Invalid Command ID",
        0x04 => "Incorrect BIND Status for given command",
        0x05 => "ESME Already in Bound State",
        0x08 => "System Error",
        0x0A => "Invalid Source Address",
        0x0B => "Invalid Dest Addr",
        0x0D => "Bind Failed",
        0x0E => "Invalid Password",
        0x0F => "Invalid System ID",
        0x14 => "Message Queue Full",
        0x45 => "submit_sm or submit_multi failed",
        0x58 => "Throttling error",
        _ => "",
    };
    if desc.is_empty() { format!("status {status:#x}") } else { format!("status {status:#x} ({desc})") }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn bind_pdu_bytes() {
        assert_eq!(hex(&bind_transmitter(2, "user", "pass")), "0000001f000000020000000000000002757365720070617373000034000000");
        // system_id max 16, password max 9 (NUL included).
        assert_eq!(
            hex(&bind_transmitter(2, "averyveryverylongsystemid", "longpassword1")),
            "0000002e000000020000000000000002617665727976657279766572796c6f006c6f6e6770617373000034000000"
        );
    }

    #[test]
    fn submit_pdu_bytes() {
        let (parts, coding, esm) = make_parts("Alert\r\ndisk full", 0).unwrap();
        assert_eq!((parts.len(), coding, esm), (1, 0, 0));
        assert_eq!(
            hex(&submit_sm(3, "1111111111", "2222222222", coding, esm, &parts[0])),
            "0000004500000004000000000000000300010031313131313131313131000100323232323232323232320000000000000100000010416c6572740d0a6469736b2066756c6c"
        );
    }

    #[test]
    fn gsm_and_ucs2() {
        assert_eq!(hex(&gsm_encode("{[x]}~^|€\\ @£$").unwrap()), "1b281b3c781b3e1b291b3d1b141b401b651b2f20000102");
        assert!(gsm_encode("✓").is_none());
        let (p, coding, _) = make_parts("Grüße ✓ 日本", 0).unwrap();
        assert_eq!(coding, ENCODING_UCS2);
        assert_eq!(hex(&p[0]), "0047007200fc00df006500202713002065e5672c");
    }

    #[test]
    fn concatenation() {
        let (p, _, esm) = make_parts(&"0123456789".repeat(20), 7).unwrap();
        assert_eq!(esm, ESM_UDHI);
        assert_eq!(p.len(), 2);
        assert_eq!(&p[0][..6], &[5, 0, 3, 7, 2, 1]);
        assert_eq!(p[0].len(), 6 + 153);
        assert_eq!(&p[1][..6], &[5, 0, 3, 7, 2, 2]);
        let (p, _, esm) = make_parts(&"a".repeat(160), 7).unwrap();
        assert_eq!((p.len(), esm), (1, 0));
        let (p, coding, _) = make_parts(&"✓".repeat(80), 1).unwrap();
        assert_eq!((p.len(), coding, p[0].len()), (2, ENCODING_UCS2, 140));
        assert!(make_parts(&"✓".repeat(20_000), 1).is_err());
    }
}
