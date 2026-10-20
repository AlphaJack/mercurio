//! A small D-Bus client as a hand-written sans-IO state machine for [`crate::Plan::socket`]: SASL `EXTERNAL` authentication, `Hello`, then one method call (`org.freedesktop.Notifications.Notify` for the desktop notifiers).
//!
//! [`Call`] never does I/O. The bus address comes from `DBUS_SESSION_BUS_ADDRESS` (or `$XDG_RUNTIME_DIR/bus`) through the [`Env`]; messages are marshalled little-endian per the D-Bus specification, replies of either byte order are read.

use crate::env::Env;
use crate::error::{Error, Result};
use crate::machine::{Input, LineBuf, Output, Protocol};
use crate::transport::Endpoint;

/// Message types.
const METHOD_CALL: u8 = 1;
const METHOD_RETURN: u8 = 2;
const ERROR: u8 = 3;

/// Header field codes.
const FIELD_PATH: u8 = 1;
const FIELD_INTERFACE: u8 = 2;
const FIELD_MEMBER: u8 = 3;
const FIELD_ERROR_NAME: u8 = 4;
const FIELD_REPLY_SERIAL: u8 = 5;
const FIELD_DESTINATION: u8 = 6;
const FIELD_SIGNATURE: u8 = 8;

/// Replies larger than this are refused (the specification allows 128 MiB; a Notify reply is a few dozen bytes).
const MAX_MESSAGE: usize = 1 << 20;

/// The session bus: the first `unix:path=` or `unix:abstract=` entry of `DBUS_SESSION_BUS_ADDRESS`, else `$XDG_RUNTIME_DIR/bus` (as libdbus and sd-bus fall back).
pub fn session_bus(env: &dyn Env) -> Result<Endpoint> {
    if let Some(addr) = env.var("DBUS_SESSION_BUS_ADDRESS").filter(|a| !a.is_empty()) {
        return parse_address(&addr)
            .map(Endpoint::unix)
            .ok_or_else(|| Error::Unsupported(format!("no unix:path or unix:abstract D-Bus address in {addr:?}")));
    }
    match env.var("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
        Some(dir) => Ok(Endpoint::unix(format!("{}/bus", dir.trim_end_matches('/')))),
        None => Err(Error::Unsupported("no D-Bus session bus (DBUS_SESSION_BUS_ADDRESS and XDG_RUNTIME_DIR are unset)".into())),
    }
}

/// The socket of the first usable entry of a D-Bus address list; abstract names get a leading NUL.
fn parse_address(list: &str) -> Option<String> {
    list.split(';').find_map(|entry| {
        let rest = entry.strip_prefix("unix:")?;
        rest.split(',').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            let v = unescape(v)?;
            match k {
                "path" => Some(v),
                "abstract" => Some(format!("\0{v}")),
                _ => None,
            }
        })
    })
}

/// `%xx` escapes of an address value.
fn unescape(v: &str) -> Option<String> {
    let mut out = Vec::with_capacity(v.len());
    let mut bytes = v.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hex = [bytes.next()?, bytes.next()?];
            out.push(u8::from_str_radix(std::str::from_utf8(&hex).ok()?, 16).ok()?);
        } else {
            out.push(b);
        }
    }
    String::from_utf8(out).ok()
}

/// A little-endian D-Bus marshaller; alignment is relative to the start of the buffer (the header, or the 8-aligned body).
#[derive(Default)]
struct Writer(Vec<u8>);

impl Writer {
    fn align(&mut self, n: usize) {
        while !self.0.len().is_multiple_of(n) {
            self.0.push(0);
        }
    }
    fn byte(&mut self, b: u8) {
        self.0.push(b);
    }
    fn u32(&mut self, v: u32) {
        self.align(4);
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn i32(&mut self, v: i32) {
        self.align(4);
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    /// Strings and object paths.
    fn str(&mut self, s: &str) {
        self.u32(len32(s.len()));
        self.0.extend_from_slice(s.as_bytes());
        self.0.push(0);
    }
    fn sig(&mut self, s: &str) {
        self.byte(u8::try_from(s.len()).unwrap_or(u8::MAX));
        self.0.extend_from_slice(s.as_bytes());
        self.0.push(0);
    }
    /// An array whose elements align to `elem_align`: the length, the padding, then `fill`'s elements.
    fn array(&mut self, elem_align: usize, fill: impl FnOnce(&mut Self)) {
        self.align(4);
        let at = self.0.len();
        self.0.extend_from_slice(&[0; 4]);
        self.align(elem_align);
        let start = self.0.len();
        fill(self);
        let len = len32(self.0.len() - start);
        self.0[at..at + 4].copy_from_slice(&len.to_le_bytes());
    }
}

fn len32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// A method call addressed to `dest`.
#[derive(Debug, Clone)]
pub struct MethodCall<'a> {
    pub dest: &'a str,
    pub path: &'a str,
    pub interface: &'a str,
    pub member: &'a str,
    pub signature: &'a str,
    /// The marshalled arguments.
    pub body: Vec<u8>,
}

/// One whole message for `call` with `serial`.
fn method_call(serial: u32, call: &MethodCall<'_>) -> Vec<u8> {
    let mut w = Writer::default();
    w.0.extend_from_slice(&[b'l', METHOD_CALL, 0, 1]);
    w.u32(len32(call.body.len()));
    w.u32(serial);
    w.array(8, |w| {
        let mut field = |code: u8, sig: &str, put: &dyn Fn(&mut Writer)| {
            w.align(8);
            w.byte(code);
            w.sig(sig);
            put(w);
        };
        field(FIELD_PATH, "o", &|w| w.str(call.path));
        field(FIELD_INTERFACE, "s", &|w| w.str(call.interface));
        field(FIELD_MEMBER, "s", &|w| w.str(call.member));
        field(FIELD_DESTINATION, "s", &|w| w.str(call.dest));
        if !call.signature.is_empty() {
            field(FIELD_SIGNATURE, "g", &|w| w.sig(call.signature));
        }
    });
    w.align(8);
    w.0.extend_from_slice(&call.body);
    w.0
}

/// `org.freedesktop.DBus.Hello`, which every connection sends first.
fn hello() -> MethodCall<'static> {
    MethodCall {
        dest: "org.freedesktop.DBus",
        path: "/org/freedesktop/DBus",
        interface: "org.freedesktop.DBus",
        member: "Hello",
        signature: "",
        body: Vec::new(),
    }
}

/// A notification hint value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hint {
    Byte(u8),
    Int32(i32),
}

/// The arguments of `org.freedesktop.Notifications.Notify` (`susssasa{sv}i`); no actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub app: String,
    pub icon: String,
    pub summary: String,
    pub body: String,
    pub hints: Vec<(&'static str, Hint)>,
    /// Milliseconds; `-1` lets the server decide.
    pub timeout: i32,
}

impl Notification {
    /// The `Notify` call (replaces-id `0`).
    pub fn call(&self) -> MethodCall<'static> {
        let mut w = Writer::default();
        w.str(&self.app);
        w.u32(0);
        w.str(&self.icon);
        w.str(&self.summary);
        w.str(&self.body);
        w.array(4, |_| {});
        w.array(8, |w| {
            for (name, value) in &self.hints {
                w.align(8);
                w.str(name);
                match value {
                    Hint::Byte(b) => {
                        w.sig("y");
                        w.byte(*b);
                    }
                    Hint::Int32(i) => {
                        w.sig("i");
                        w.i32(*i);
                    }
                }
            }
        });
        w.i32(self.timeout);
        MethodCall {
            dest: "org.freedesktop.Notifications",
            path: "/org/freedesktop/Notifications",
            interface: "org.freedesktop.Notifications",
            member: "Notify",
            signature: "susssasa{sv}i",
            body: w.0,
        }
    }
}

/// A reader over one message of either byte order.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    big: bool,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8], big: bool, pos: usize) -> Self {
        Self { buf, pos, big }
    }
    pub(crate) fn align(&mut self, n: usize) {
        self.pos = self.pos.next_multiple_of(n);
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.buf.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(s)
    }
    pub(crate) fn byte(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    pub(crate) fn u32(&mut self) -> Option<u32> {
        self.align(4);
        let b: [u8; 4] = self.take(4)?.try_into().ok()?;
        Some(if self.big { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) })
    }
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn i32(&mut self) -> Option<i32> {
        self.u32().map(|v| i32::from_ne_bytes(v.to_ne_bytes()))
    }
    pub(crate) fn str(&mut self) -> Option<String> {
        let n = usize::try_from(self.u32()?).ok()?;
        let s = String::from_utf8(self.take(n)?.to_vec()).ok()?;
        self.take(1)?;
        Some(s)
    }
    pub(crate) fn sig(&mut self) -> Option<String> {
        let n = usize::from(self.byte()?);
        let s = String::from_utf8(self.take(n)?.to_vec()).ok()?;
        self.take(1)?;
        Some(s)
    }
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }
}

/// A received message: what the client looks at.
#[derive(Debug, Default)]
pub(crate) struct Message {
    pub kind: u8,
    pub big: bool,
    pub serial: u32,
    pub reply_serial: Option<u32>,
    pub member: Option<String>,
    pub error_name: Option<String>,
    pub signature: String,
    /// The body; alignment is relative to its start.
    pub body: Vec<u8>,
}

impl Message {
    /// The first argument when it is a string (an error's message).
    fn first_str(&self) -> Option<String> {
        self.signature.starts_with('s').then(|| Reader::new(&self.body, self.big, 0).str()).flatten()
    }
}

/// Cut the next whole message off `rx`; `Ok(None)` until it has arrived.
pub(crate) fn take_message(rx: &mut Vec<u8>) -> Result<Option<Message>> {
    let Some(head) = rx.get(..16) else { return Ok(None) };
    let big = match head[0] {
        b'l' => false,
        b'B' => true,
        other => return Err(Error::transport(format!("D-Bus: bad byte order {other:#04x}"))),
    };
    let mut r = Reader::new(head, big, 4);
    let (Some(body_len), Some(serial), Some(fields_len)) = (r.u32(), r.u32(), r.u32()) else { return Ok(None) };
    let header_end = (16 + fields_len as usize).next_multiple_of(8);
    let total = header_end + body_len as usize;
    if total > MAX_MESSAGE {
        return Err(Error::transport(format!("D-Bus: message of {total} bytes")));
    }
    if rx.len() < total {
        return Ok(None);
    }
    let bytes: Vec<u8> = rx.drain(..total).collect();
    let mut msg = Message { kind: bytes[1], big, serial, body: bytes[header_end..].to_vec(), ..Message::default() };
    let malformed = || Error::transport("D-Bus: malformed message header");
    let mut r = Reader::new(&bytes[..16 + fields_len as usize], big, 16);
    while r.pos() < 16 + fields_len as usize {
        r.align(8);
        let code = r.byte().ok_or_else(malformed)?;
        let sig = r.sig().ok_or_else(malformed)?;
        match (code, sig.as_str()) {
            (FIELD_REPLY_SERIAL, "u") => msg.reply_serial = r.u32(),
            (FIELD_ERROR_NAME, "s") => msg.error_name = r.str(),
            (FIELD_MEMBER, "s") => msg.member = r.str(),
            (FIELD_SIGNATURE, "g") => msg.signature = r.sig().ok_or_else(malformed)?,
            (_, "s" | "o") => drop(r.str().ok_or_else(malformed)?),
            (_, "g") => drop(r.sig().ok_or_else(malformed)?),
            (_, "u") => drop(r.u32().ok_or_else(malformed)?),
            _ => return Err(malformed()),
        }
    }
    Ok(Some(msg))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// `AUTH EXTERNAL` sent; waiting for `DATA` (or `OK`).
    AuthData,
    /// The empty identity sent; waiting for `OK`.
    AuthOk,
    /// Waiting for the reply to `Hello` (serial 1).
    Hello,
    /// Waiting for the reply to the call (serial 2).
    Call,
    Done,
}

/// One authenticated call on a fresh connection: `AUTH EXTERNAL` with an empty identity (the bus reads the peer credentials), `Hello`, the call, its reply.
pub struct Call {
    call: MethodCall<'static>,
    state: State,
    lines: LineBuf,
    rx: Vec<u8>,
    out: Vec<u8>,
    result: Option<Result<()>>,
}

impl Call {
    pub fn new(call: MethodCall<'static>) -> Self {
        Self {
            call,
            state: State::AuthData,
            lines: LineBuf::default(),
            rx: Vec::new(),
            out: b"\0AUTH EXTERNAL\r\n".to_vec(),
            result: None,
        }
    }

    fn fail(&mut self, e: Error) {
        self.result.get_or_insert(Err(e));
        self.state = State::Done;
    }

    fn on_line(&mut self, line: &str) {
        let word = line.split(' ').next().unwrap_or("");
        match (self.state, word) {
            (State::AuthData, "DATA") => {
                self.out.extend_from_slice(b"DATA\r\n");
                self.state = State::AuthOk;
            }
            (State::AuthData | State::AuthOk, "OK") => {
                self.out.extend_from_slice(b"BEGIN\r\n");
                self.out.extend_from_slice(&method_call(1, &hello()));
                self.state = State::Hello;
                self.rx = self.lines.take();
            }
            _ => self.fail(Error::Service(format!("D-Bus authentication failed: {}", crate::util::truncate_chars(line, 200)))),
        }
    }

    fn on_message(&mut self, msg: &Message) {
        let expected = match self.state {
            State::Hello => 1,
            State::Call => 2,
            State::AuthData | State::AuthOk | State::Done => return,
        };
        // Signals (NameAcquired) and other traffic are not ours.
        if msg.reply_serial != Some(expected) || !matches!(msg.kind, METHOD_RETURN | ERROR) {
            log::trace!("D-Bus: skipped message {} of type {}", msg.serial, msg.kind);
            return;
        }
        if msg.kind == ERROR {
            let member = if expected == 1 { "Hello" } else { self.call.member };
            let name = msg.error_name.as_deref().unwrap_or("unknown error");
            let detail = msg.first_str().map(|m| format!(": {}", crate::util::truncate_chars(&m, 200))).unwrap_or_default();
            return self.fail(Error::Service(format!("D-Bus {member} failed: {name}{detail}")));
        }
        if self.state == State::Hello {
            self.out.extend_from_slice(&method_call(2, &self.call));
            self.state = State::Call;
        } else {
            self.result = Some(Ok(()));
            self.state = State::Done;
        }
    }
}

impl Protocol for Call {
    fn next(&mut self) -> Output {
        if !self.out.is_empty() {
            return Output::Write(std::mem::take(&mut self.out));
        }
        match self.state {
            State::Done => Output::Done(self.result.take().unwrap_or(Ok(()))),
            State::AuthData | State::AuthOk | State::Hello | State::Call => Output::Read,
        }
    }

    fn input(&mut self, input: Input<'_>) {
        match input {
            Input::Data([]) => self.fail(Error::transport("D-Bus: connection closed by the bus")),
            Input::Data(data) => {
                if matches!(self.state, State::AuthData | State::AuthOk) {
                    self.lines.push(data);
                    while matches!(self.state, State::AuthData | State::AuthOk)
                        && let Some(line) = self.lines.next_line()
                    {
                        self.on_line(&line);
                    }
                } else {
                    self.rx.extend_from_slice(data);
                }
                while matches!(self.state, State::Hello | State::Call) {
                    match take_message(&mut self.rx) {
                        Ok(Some(msg)) => self.on_message(&msg),
                        Ok(None) => break,
                        Err(e) => self.fail(e),
                    }
                }
            }
            Input::ReadError(e) | Input::WriteError(e) => self.fail(Error::transport(e)),
            Input::Tls(r) => {
                if let Err(e) = r {
                    self.fail(e);
                }
            }
        }
    }
}

/// The arguments of a received `Notify` call (for the fake bus of the tests).
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Notified {
    pub app: String,
    pub replaces_id: u32,
    pub icon: String,
    pub summary: String,
    pub body: String,
    pub hints: Vec<(String, i64)>,
    pub timeout: i32,
}

/// Decode the arguments of a marshalled `Notify` call (no actions expected).
#[cfg(any(test, feature = "testing"))]
pub(crate) fn decode_notify(msg: &Message) -> Option<Notified> {
    let mut r = Reader::new(&msg.body, msg.big, 0);
    let (app, id, icon, summary, body) = (r.str()?, r.u32()?, r.str()?, r.str()?, r.str()?);
    let actions = r.u32()?;
    if actions != 0 {
        return None;
    }
    let hints_len = r.u32()? as usize;
    r.align(8);
    let end = r.pos() + hints_len;
    let mut hints = Vec::new();
    while r.pos() < end {
        r.align(8);
        let name = r.str()?;
        let value = match r.sig()?.as_str() {
            "y" => i64::from(r.byte()?),
            "i" => i64::from(r.i32()?),
            _ => return None,
        };
        hints.push((name, value));
    }
    Some(Notified { app, replaces_id: id, icon, summary, body, hints, timeout: r.i32()? })
}

/// A message from the bus (for the fake bus of the tests): a method return, or an error with a message, answering `reply_to`.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn reply(serial: u32, reply_to: u32, error: Option<(&str, &str)>) -> Vec<u8> {
    let mut body = Writer::default();
    let sig = match error {
        Some((_, text)) => {
            body.str(text);
            "s"
        }
        None => {
            body.u32(1);
            "u"
        }
    };
    let mut w = Writer::default();
    w.0.extend_from_slice(&[b'l', if error.is_some() { ERROR } else { METHOD_RETURN }, 0, 1]);
    w.u32(len32(body.0.len()));
    w.u32(serial);
    w.array(8, |w| {
        if let Some((name, _)) = error {
            w.align(8);
            w.byte(FIELD_ERROR_NAME);
            w.sig("s");
            w.str(name);
        }
        w.align(8);
        w.byte(FIELD_REPLY_SERIAL);
        w.sig("u");
        w.u32(reply_to);
        w.align(8);
        w.byte(FIELD_SIGNATURE);
        w.sig("g");
        w.sig(sig);
    });
    w.align(8);
    w.0.extend_from_slice(&body.0);
    w.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FixedEnv;

    #[test]
    fn addresses() {
        assert_eq!(parse_address("unix:path=/run/user/1000/bus").as_deref(), Some("/run/user/1000/bus"));
        assert_eq!(parse_address("unix:abstract=/tmp/dbus-x,guid=12").as_deref(), Some("\0/tmp/dbus-x"));
        assert_eq!(parse_address("tcp:host=h,port=1;unix:path=/a%20b").as_deref(), Some("/a b"));
        assert_eq!(parse_address("unix:path=/a%2"), None);
        assert_eq!(parse_address("launchd:env=X"), None);

        let env = FixedEnv::new(0).with_var("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/bus");
        assert_eq!(session_bus(&env).unwrap(), Endpoint::unix("/run/bus"));
        let env = FixedEnv::new(0).with_var("XDG_RUNTIME_DIR", "/run/user/7/");
        assert_eq!(session_bus(&env).unwrap(), Endpoint::unix("/run/user/7/bus"));
        assert!(matches!(session_bus(&FixedEnv::new(0)), Err(Error::Unsupported(_))));
        let env = FixedEnv::new(0).with_var("DBUS_SESSION_BUS_ADDRESS", "tcp:host=h,port=1");
        assert!(matches!(session_bus(&env), Err(Error::Unsupported(_))));
    }

    fn notification() -> Notification {
        Notification {
            app: "Mercurio".into(),
            icon: "/tmp/i.svg".into(),
            summary: "T".into(),
            body: "B".into(),
            hints: vec![("urgency", Hint::Byte(2)), ("x", Hint::Int32(-5)), ("y", Hint::Int32(7))],
            timeout: 13_000,
        }
    }

    #[test]
    fn notify_round_trips() {
        let mut rx = method_call(2, &notification().call());
        let msg = take_message(&mut rx).unwrap().unwrap();
        assert!(rx.is_empty());
        assert_eq!((msg.kind, msg.serial, msg.member.as_deref(), msg.signature.as_str()), (1, 2, Some("Notify"), "susssasa{sv}i"));
        let hints = vec![("urgency".to_string(), 2), ("x".to_string(), -5), ("y".to_string(), 7)];
        let expected = Notified {
            app: "Mercurio".into(),
            replaces_id: 0,
            icon: "/tmp/i.svg".into(),
            summary: "T".into(),
            body: "B".into(),
            hints,
            timeout: 13_000,
        };
        assert_eq!(decode_notify(&msg), Some(expected));
    }

    /// Feed `server` replies to the machine until it is done, returning everything it wrote.
    fn run(mut call: Call, mut server: impl FnMut(&[u8]) -> Vec<u8>) -> (Vec<u8>, Result<()>) {
        let mut written = Vec::new();
        let mut pending = Vec::new();
        loop {
            match call.next() {
                Output::Write(data) => {
                    written.extend_from_slice(&data);
                    pending.extend(server(&data));
                }
                Output::Read => call.input(Input::Data(&std::mem::take(&mut pending))),
                Output::Done(r) => return (written, r),
                other @ (Output::StartTls | Output::Sleep(_)) => panic!("unexpected {other:?}"),
            }
        }
    }

    /// A bus that answers the handshake and `Hello` (with a `NameAcquired`-like signal first), then `notify` to the call.
    fn bus(notify: Option<(&'static str, &'static str)>) -> impl FnMut(&[u8]) -> Vec<u8> {
        move |data: &[u8]| match data {
            b"\0AUTH EXTERNAL\r\n" => b"DATA\r\n".to_vec(),
            b"DATA\r\n" => b"OK 0123456789abcdef0123456789abcdef\r\n".to_vec(),
            d if d.starts_with(b"BEGIN\r\n") => {
                let mut signal = reply(1, 9, None);
                signal[1] = 4;
                [signal, reply(2, 1, None)].concat()
            }
            _ => reply(3, 2, notify),
        }
    }

    #[test]
    fn call_succeeds() {
        let (written, r) = run(Call::new(notification().call()), bus(None));
        r.unwrap();
        assert!(written.starts_with(b"\0AUTH EXTERNAL\r\nDATA\r\nBEGIN\r\nl\x01"), "{written:?}");
    }

    #[test]
    fn call_reports_errors() {
        let (_, r) = run(Call::new(notification().call()), bus(Some(("org.freedesktop.DBus.Error.ServiceUnknown", "no daemon"))));
        assert_eq!(
            r.unwrap_err().to_string(),
            "service error: D-Bus Notify failed: org.freedesktop.DBus.Error.ServiceUnknown: no daemon"
        );
        let (_, r) = run(Call::new(notification().call()), |_| b"REJECTED EXTERNAL\r\n".to_vec());
        assert_eq!(r.unwrap_err().to_string(), "service error: D-Bus authentication failed: REJECTED EXTERNAL");
        let (_, r) = run(Call::new(notification().call()), |_| Vec::new());
        assert!(matches!(r, Err(Error::Transport(_))));
    }

    #[test]
    fn big_endian_replies_are_read() {
        // A big-endian method return to serial 2 with no body.
        let mut rx = vec![b'B', 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 8, 5, 1, b'u', 0, 0, 0, 0, 2];
        let msg = take_message(&mut rx).unwrap().unwrap();
        assert_eq!((msg.kind, msg.serial, msg.reply_serial), (2, 5, Some(2)));
    }
}
