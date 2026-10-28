//! A minimal one-shot XMPP client session (RFC 6120/6121, XEP-0045): stream negotiation, STARTTLS, SASL, resource binding, session, presence, optional roster fetch, MUC join, messages, stream close.

use std::collections::VecDeque;
use std::sync::Arc;

use super::sasl::{Mech, Scram, plain};
use super::xml::{self, Element, Event, Parser};
use crate::env::Env;
use crate::error::{Error, Result};
use crate::machine::{Input, Output, Protocol};
use crate::transport::ChannelBinding;

const NS_TLS: &str = "urn:ietf:params:xml:ns:xmpp-tls";
const NS_SASL: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
const NS_BIND: &str = "urn:ietf:params:xml:ns:xmpp-bind";
const NS_SESSION: &str = "urn:ietf:params:xml:ns:xmpp-session";
const NS_ROSTER: &str = "jabber:iq:roster";
const NS_MUC: &str = "http://jabber.org/protocol/muc";

/// Stream security (`?mode=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    /// Plain TCP; STARTTLS is not attempted.
    None,
    /// Direct TLS from the first byte.
    Tls,
    /// Plain TCP upgraded with STARTTLS (required).
    StartTls,
}

/// What one session delivers.
#[derive(Debug, Clone)]
pub(super) struct Session {
    pub mode: Mode,
    /// Bare or full JID we log in as.
    pub jid: String,
    pub password: String,
    pub roster: bool,
    /// MUC nickname.
    pub nick: String,
    /// `(type, jid)`: `chat` or `groupchat`.
    pub targets: Vec<(String, String)>,
    pub subject: String,
    pub body: String,
    /// Use SCRAM `-PLUS` (channel binding) when the server offers it on a TLS stream (`?scramplus=`).
    pub scramplus: bool,
}

struct Jid<'a> {
    local: &'a str,
    domain: &'a str,
    resource: Option<&'a str>,
}

fn split_jid(jid: &str) -> Jid<'_> {
    let (bare, resource) = match jid.split_once('/') {
        Some((b, r)) => (b, Some(r)),
        None => (jid, None),
    };
    let (local, domain) = bare.split_once('@').unwrap_or(("", bare));
    Jid { local, domain, resource }
}

fn iq_error(what: &str, el: &Element) -> Error {
    let cond = el
        .child("error")
        .and_then(|e| e.children.iter().find(|c| c.local() != "text"))
        .map(|c| c.local().to_owned())
        .unwrap_or_else(|| "unknown".into());
    Error::service(format!("XMPP {what} failed: {cond}"))
}

/// A top-level event as a stanza; stream errors, a new header and the stream end fail.
fn stanza(ev: Event) -> Result<Element> {
    match ev {
        Event::Stanza(el) if el.local() == "error" && el.name.contains(':') => {
            let cond = el.children.first().map(|c| c.local().to_owned()).unwrap_or_default();
            Err(Error::service(format!("XMPP stream error: {cond}")))
        }
        Event::Stanza(el) => Ok(el),
        Event::Open(_) => Err(Error::service("XMPP: unexpected stream header")),
        Event::Close => Err(Error::service("XMPP: server closed the stream")),
    }
}

/// A SASL `<failure>`. One that mentions channel binding gets Apprise's hint about `?scramplus=no`.
fn sasl_failed(el: &Element, scramplus: bool) -> Error {
    let all = flatten(el).to_lowercase();
    if all.contains("channel") && all.contains("binding") {
        return Error::service(if scramplus {
            "XMPP authentication failed: the server rejected SASL SCRAM-PLUS channel binding. Add ?scramplus=no to \
             your URL to disable SCRAM-PLUS mechanism negotiation."
        } else {
            "XMPP authentication failed: the server rejected channel binding despite ?scramplus=no being set."
        });
    }
    let cond = el.children.iter().find(|c| c.local() != "text").map(|c| c.local().to_owned());
    Error::service(format!("XMPP authentication failed: {}", cond.unwrap_or_else(|| "unknown".into())))
}

/// Every name and text inside `el`.
fn flatten(el: &Element) -> String {
    let mut out = format!("{} {}", el.local(), el.text);
    for c in &el.children {
        out.push(' ');
        out.push_str(&flatten(c));
    }
    out
}

/// The channel binding types to try, best first: those the server lists (XEP-0440), else `tls-exporter` (the TLS 1.3 default of RFC 9266).
fn binding_types(features: &Element) -> VecDeque<ChannelBinding> {
    let all = [ChannelBinding::TlsExporter, ChannelBinding::TlsServerEndPoint];
    match features.child("sasl-channel-binding") {
        Some(list) => all
            .into_iter()
            .filter(|k| list.children_named("channel-binding").any(|c| c.attr("type") == Some(k.name())))
            .collect(),
        None => VecDeque::from([ChannelBinding::TlsExporter]),
    }
}

fn sasl_unexpected() -> Error {
    Error::service("XMPP: unexpected SASL answer")
}

fn sasl_data(el: &Element) -> Result<String> {
    let raw = crate::crypto::b64_decode(el.text.trim()).ok_or_else(|| Error::service("XMPP: bad SASL data"))?;
    Ok(String::from_utf8_lossy(&raw).into_owned())
}

/// Which stream (re)start a header and features belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Initial,
    AfterTls,
    AfterAuth,
}

/// Where SASL is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sasl {
    /// `<auth mechanism='PLAIN'>` sent.
    Plain,
    /// SCRAM client-first sent; a challenge is due.
    First,
    /// SCRAM client-final sent; success (or a challenge carrying `v=`) is due.
    Final,
    /// The `v=` challenge is answered; success is due.
    Verified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IqStep {
    Bind,
    Session,
    Roster,
}

/// What the session waits for.
#[derive(Debug)]
enum Wait {
    /// The server's stream header.
    Header(Phase),
    /// Stanzas until `<stream:features>`.
    Features(Phase),
    Proceed,
    Sasl(Sasl),
    /// The answer to the IQ `id`.
    Iq { id: String, step: IqStep },
    /// The room's presence for our occupant JID, before messaging `targets[target]`.
    Muc { occupant: String, target: usize },
    /// The transport's TLS upgrade.
    TlsHandshake,
    /// The connection's channel binding data of `kind` for `mech` (`SCRAM-*-PLUS`); `rest` are the types left to try, `offered` the mechanisms to fall back on.
    Binding { mech: Mech, kind: ChannelBinding, rest: VecDeque<ChannelBinding>, offered: Vec<String> },
    /// `</stream:stream>` is sent: the server's close (or any failure) ends the session.
    Close,
    Done,
}

/// An XMPP session as a sans-IO state machine.
pub(super) struct Client {
    cfg: Session,
    wait: Wait,
    parser: Parser,
    /// One write per stanza, as servers (and the fixture server) see them.
    out: VecDeque<Vec<u8>>,
    tls: bool,
    ids: u32,
    scram: Option<Scram>,
    /// SCRAM `-PLUS` was attempted.
    plus: bool,
    /// The features after authentication (bind, session).
    features: Option<Element>,
    env: Arc<dyn Env>,
    result: Option<Result<()>>,
}

impl Client {
    /// A session for `cfg`; `tls` is whether the stream starts encrypted.
    pub(super) fn new(cfg: Session, tls: bool, env: Arc<dyn Env>) -> Self {
        let mut c = Client {
            cfg,
            wait: Wait::Done,
            parser: Parser::default(),
            out: VecDeque::new(),
            tls,
            ids: 0,
            scram: None,
            plus: false,
            features: None,
            env,
            result: None,
        };
        c.open(Phase::Initial);
        c
    }

    fn send(&mut self, data: &str) {
        self.out.push_back(data.as_bytes().to_vec());
    }

    fn fail(&mut self, err: Error) {
        self.result.get_or_insert(Err(err));
        self.wait = Wait::Done;
    }

    fn finish(&mut self) {
        self.result.get_or_insert(Ok(()));
        self.wait = Wait::Done;
    }

    /// Open (or restart) the stream.
    fn open(&mut self, phase: Phase) {
        let domain = split_jid(&self.cfg.jid).domain.to_owned();
        self.send(&format!(
            "<?xml version='1.0'?><stream:stream to='{}' xmlns='jabber:client' \
             xmlns:stream='http://etherx.jabber.org/streams' xml:lang='en' version='1.0'>",
            xml::attr(&domain)
        ));
        self.wait = Wait::Header(phase);
    }

    fn iq(&mut self, kind: &str, payload: &str, step: IqStep) {
        self.ids += 1;
        let id = format!("mercurio{}", self.ids);
        self.send(&format!("<iq type='{kind}' id='{id}'>{payload}</iq>"));
        self.wait = Wait::Iq { id, step };
    }

    fn on_event(&mut self, ev: Event) {
        match std::mem::replace(&mut self.wait, Wait::Done) {
            Wait::Header(phase) => match ev {
                Event::Open(_) => self.wait = Wait::Features(phase),
                Event::Stanza(_) | Event::Close => self.fail(Error::service("XMPP: server did not open a stream")),
            },
            Wait::Close => {
                if ev == Event::Close {
                    self.finish();
                } else {
                    self.wait = Wait::Close;
                }
            }
            wait @ (Wait::Features(_)
            | Wait::Proceed
            | Wait::Sasl(_)
            | Wait::Iq { .. }
            | Wait::Muc { .. }
            | Wait::TlsHandshake
            | Wait::Binding { .. }
            | Wait::Done) => match stanza(ev) {
                Ok(el) => self.on_stanza(wait, &el),
                Err(e) => self.fail(e),
            },
        }
    }

    fn on_stanza(&mut self, wait: Wait, el: &Element) {
        match wait {
            Wait::Features(phase) if el.local() == "features" => self.on_features(phase, el),
            Wait::Proceed if el.local() != "proceed" => self.fail(Error::service("XMPP: the server refused STARTTLS")),
            // Anything the server sent after `<proceed/>` arrived in plain text and must not be read as part of the encrypted stream.
            Wait::Proceed if self.parser.has_unread() => {
                self.fail(Error::service("XMPP: unexpected data after STARTTLS proceed"));
            }
            Wait::Proceed => {
                self.parser.reset();
                self.wait = Wait::TlsHandshake;
            }
            Wait::Sasl(step) => self.on_sasl(step, el),
            Wait::Iq { id, step } if el.local() == "iq" && el.attr("id") == Some(id.as_str()) => self.on_iq(step, el),
            Wait::Muc { occupant, target }
                if el.local() == "presence" && el.attr("from").is_some_and(|f| f.eq_ignore_ascii_case(&occupant)) =>
            {
                self.message(target);
                self.next_target(target + 1);
            }
            // Unrelated stanzas are skipped.
            wait @ (Wait::Features(_) | Wait::Iq { .. } | Wait::Muc { .. }) => self.wait = wait,
            Wait::Header(_) | Wait::TlsHandshake | Wait::Binding { .. } | Wait::Close | Wait::Done => {}
        }
    }

    fn on_features(&mut self, phase: Phase, features: &Element) {
        match phase {
            Phase::Initial if self.cfg.mode == Mode::StartTls && !self.tls => {
                if features.child("starttls").is_none() {
                    return self.fail(Error::service("XMPP: the server does not offer STARTTLS"));
                }
                self.send(&format!("<starttls xmlns='{NS_TLS}'/>"));
                self.wait = Wait::Proceed;
            }
            Phase::Initial | Phase::AfterTls => self.authenticate(features),
            Phase::AfterAuth => {
                self.features = Some(features.clone());
                self.bind();
            }
        }
    }

    fn authenticate(&mut self, features: &Element) {
        let offered: Vec<String> = features
            .child("mechanisms")
            .map(|m| m.children_named("mechanism").map(|c| c.text.trim().to_owned()).collect())
            .unwrap_or_default();
        if self.cfg.scramplus
            && self.tls
            && let Some(mech) = Mech::choose_plus(offered.iter().map(String::as_str))
        {
            let mut kinds = binding_types(features);
            if let Some(kind) = kinds.pop_front() {
                self.wait = Wait::Binding { mech, kind, rest: kinds, offered };
                return;
            }
        }
        self.authenticate_unbound(&offered);
    }

    /// The connection answered for channel binding: SCRAM `-PLUS` with the data, else the next type, else no binding.
    fn on_binding(&mut self, data: Option<Vec<u8>>) {
        let Wait::Binding { mech, kind, mut rest, offered } = std::mem::replace(&mut self.wait, Wait::Done) else {
            return;
        };
        match (data, rest.pop_front()) {
            (Some(data), _) => {
                self.plus = true;
                let user = split_jid(&self.cfg.jid).local.to_owned();
                let scram = Scram::new(mech, &user, self.env.as_ref()).with_binding(kind.name(), data);
                self.start_scram(&format!("{}-PLUS", mech.name()), scram);
            }
            (None, Some(next)) => self.wait = Wait::Binding { mech, kind: next, rest, offered },
            (None, None) => self.authenticate_unbound(&offered),
        }
    }

    fn authenticate_unbound(&mut self, offered: &[String]) {
        let Some(mech) = Mech::choose(offered.iter().map(String::as_str), self.tls) else {
            return self.fail(Error::service(if offered.iter().any(|m| m.eq_ignore_ascii_case("PLAIN")) && !self.tls {
                "XMPP: the server only offers PLAIN authentication over an unencrypted stream; use TLS".to_owned()
            } else {
                "XMPP: no supported SASL mechanism offered".to_owned()
            }));
        };
        let user = split_jid(&self.cfg.jid).local.to_owned();
        if mech == Mech::Plain {
            let auth = format!("<auth xmlns='{NS_SASL}' mechanism='PLAIN'>{}</auth>", plain(&user, &self.cfg.password));
            self.send(&auth);
            self.wait = Wait::Sasl(Sasl::Plain);
            return;
        }
        let scram = Scram::new(mech, &user, self.env.as_ref());
        self.start_scram(mech.name(), scram);
    }

    fn start_scram(&mut self, mechanism: &str, scram: Scram) {
        log::debug!("XMPP: authenticating with {mechanism} ({})", scram.binding_name());
        let first = crate::crypto::b64(scram.client_first().as_bytes());
        self.send(&format!("<auth xmlns='{NS_SASL}' mechanism='{mechanism}'>{first}</auth>"));
        self.scram = Some(scram);
        self.wait = Wait::Sasl(Sasl::First);
    }

    fn on_sasl(&mut self, step: Sasl, el: &Element) {
        let res = match (step, el.local()) {
            (_, "failure") => Err(sasl_failed(el, self.cfg.scramplus)),
            (Sasl::Plain | Sasl::Verified, "success") => Ok(true),
            (Sasl::First, "challenge") => self.scram_final(el).map(|()| false),
            (Sasl::Final, "challenge") => {
                // Some servers send `v=` in a challenge and an empty success.
                self.scram_verify(el).map(|()| {
                    self.send(&format!("<response xmlns='{NS_SASL}'/>"));
                    self.wait = Wait::Sasl(Sasl::Verified);
                    false
                })
            }
            (Sasl::Final, "success") => self.scram_verify(el).map(|()| true),
            _ => Err(sasl_unexpected()),
        };
        match res {
            Ok(true) => {
                self.parser.reset();
                self.open(Phase::AfterAuth);
            }
            Ok(false) => {}
            Err(e) => self.fail(e),
        }
    }

    fn scram_final(&mut self, el: &Element) -> Result<()> {
        let server_first = sasl_data(el)?;
        let scram = self.scram.as_mut().ok_or_else(sasl_unexpected)?;
        let fin = scram.client_final(&server_first, &self.cfg.password)?;
        self.send(&format!("<response xmlns='{NS_SASL}'>{}</response>", crate::crypto::b64(fin.as_bytes())));
        self.wait = Wait::Sasl(Sasl::Final);
        Ok(())
    }

    fn scram_verify(&self, el: &Element) -> Result<()> {
        self.scram.as_ref().ok_or_else(sasl_unexpected)?.verify(&sasl_data(el)?)
    }

    fn bind(&mut self) {
        if self.features.as_ref().is_some_and(|f| f.child("bind").is_some()) {
            let resource = split_jid(&self.cfg.jid)
                .resource
                .map(|r| format!("<resource>{}</resource>", xml::text(r)))
                .unwrap_or_default();
            return self.iq("set", &format!("<bind xmlns='{NS_BIND}'>{resource}</bind>"), IqStep::Bind);
        }
        self.session();
    }

    fn session(&mut self) {
        let wanted = self.features.as_ref().and_then(|f| f.child("session")).is_some_and(|s| s.child("optional").is_none());
        if wanted {
            return self.iq("set", &format!("<session xmlns='{NS_SESSION}'/>"), IqStep::Session);
        }
        self.presence();
    }

    fn presence(&mut self) {
        self.send("<presence/>");
        if self.cfg.roster {
            // Roster errors are ignored.
            return self.iq("get", &format!("<query xmlns='{NS_ROSTER}'/>"), IqStep::Roster);
        }
        self.next_target(0);
    }

    fn on_iq(&mut self, step: IqStep, el: &Element) {
        let ok = el.attr("type") == Some("result");
        match step {
            IqStep::Bind if !ok => self.fail(iq_error("resource binding", el)),
            IqStep::Bind => self.session(),
            IqStep::Session if !ok => self.fail(iq_error("session", el)),
            IqStep::Session => self.presence(),
            IqStep::Roster => self.next_target(0),
        }
    }

    /// `(type, jid)` of target `i`; the account itself when there are none.
    fn target(&self, i: usize) -> Option<(String, String)> {
        if self.cfg.targets.is_empty() {
            return (i == 0).then(|| ("chat".to_owned(), self.cfg.jid.clone()));
        }
        self.cfg.targets.get(i).cloned()
    }

    /// Message targets from `i` on, stopping to join a room; close the stream after the last.
    fn next_target(&mut self, mut i: usize) {
        while let Some((kind, to)) = self.target(i) {
            if kind == "groupchat" {
                // XEP-0045 join: presence to `room/nick`, then wait for the room's answer about our occupant JID.
                let occupant = format!("{to}/{}", self.cfg.nick);
                self.send(&format!("<presence to='{}'><x xmlns='{NS_MUC}'/></presence>", xml::attr(&occupant)));
                self.wait = Wait::Muc { occupant, target: i };
                return;
            }
            self.message(i);
            i += 1;
        }
        self.send("</stream:stream>");
        self.wait = Wait::Close;
    }

    fn message(&mut self, i: usize) {
        let Some((kind, to)) = self.target(i) else { return };
        let subject = if self.cfg.subject.is_empty() {
            String::new()
        } else {
            format!("<subject>{}</subject>", xml::text(&self.cfg.subject))
        };
        let message = format!(
            "<message to='{}' type='{kind}'>{subject}<body>{}</body></message>",
            xml::attr(&to),
            xml::text(&self.cfg.body)
        );
        self.send(&message);
    }

    fn reading(&self) -> bool {
        !matches!(self.wait, Wait::TlsHandshake | Wait::Binding { .. } | Wait::Done)
    }
}

impl Protocol for Client {
    fn next(&mut self) -> Output {
        if let Some(data) = self.out.pop_front() {
            return Output::Write(data);
        }
        match self.wait {
            Wait::TlsHandshake => Output::StartTls,
            Wait::Binding { kind, .. } => Output::ChannelBinding(kind),
            Wait::Done => Output::Done(self.result.take().unwrap_or(Ok(()))),
            Wait::Header(_)
            | Wait::Features(_)
            | Wait::Proceed
            | Wait::Sasl(_)
            | Wait::Iq { .. }
            | Wait::Muc { .. }
            | Wait::Close => Output::Read,
        }
    }

    fn input(&mut self, input: Input<'_>) {
        let closing = matches!(self.wait, Wait::Close);
        match input {
            // Once the stream is closed on our side, errors no longer matter.
            Input::Data([]) | Input::ReadError(_) if closing => self.finish(),
            Input::Data([]) => self.fail(self.parser.eof_error()),
            Input::Data(data) => {
                self.parser.push(data);
                while self.reading() {
                    match self.parser.next_event() {
                        Ok(Some(ev)) => self.on_event(ev),
                        Ok(None) => break,
                        Err(_) if matches!(self.wait, Wait::Close) => self.finish(),
                        Err(e) => self.fail(e),
                    }
                }
            }
            Input::ReadError(e) => self.fail(Error::transport(e)),
            Input::WriteError(e) => {
                // Nothing goes out after a failed write.
                self.out.clear();
                self.fail(Error::transport(e));
            }
            Input::Tls(Ok(())) => {
                self.tls = true;
                self.open(Phase::AfterTls);
            }
            Input::Tls(Err(e)) => self.fail(e),
            Input::ChannelBinding(data) => self.on_binding(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::ScriptedConn;
    use crate::transport::AsyncConn;

    fn session() -> Session {
        Session {
            mode: Mode::StartTls,
            jid: "user@example.com".into(),
            password: "pw".into(),
            roster: false,
            nick: "n".into(),
            targets: Vec::new(),
            subject: String::new(),
            body: "hi".into(),
            scramplus: true,
        }
    }

    /// Bytes sent in plain text together with `<proceed/>` must not be read as part of the TLS stream.
    #[test]
    fn starttls_injection_fails() {
        let conn = ScriptedConn::bytes(Vec::new(), |w: &[u8]| {
            let w = String::from_utf8_lossy(w);
            if w.contains("<stream:stream") {
                b"<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' \
                  version='1.0'><stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\
                  </stream:features>"
                    .to_vec()
            } else if w.contains("<starttls") {
                b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\
                  <success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>"
                    .to_vec()
            } else {
                Vec::new()
            }
        });
        let mut conn: Box<dyn crate::transport::Conn> = Box::new(conn);
        let err = pollster::block_on(crate::machine::drive(Client::new(session(), false, Arc::new(crate::testing::FixedEnv::new(0))),
            &mut conn,
            &crate::Blocking(crate::testing::FakeTransport::new()),
        )).unwrap_err();
        assert!(err.to_string().contains("after STARTTLS"), "{err}");
        assert!(!AsyncConn::is_tls(&conn));
    }

    /// A server that upgrades with STARTTLS, then offers `mechanisms` and the binding `types` (XEP-0440), records the `<auth>` and rejects it with `reason`.
    fn plus_run(mechanisms: &[&str], types: &[&str], scramplus: bool, reason: &str) -> (String, Error) {
        let auth = Arc::new(std::sync::Mutex::new(String::new()));
        let seen = auth.clone();
        let mut opened = 0;
        let mechs: String = mechanisms.iter().map(|m| format!("<mechanism>{m}</mechanism>")).collect();
        let cb: String = if types.is_empty() {
            String::new()
        } else {
            let list: String = types.iter().map(|t| format!("<channel-binding type='{t}'/>")).collect();
            format!("<sasl-channel-binding xmlns='urn:xmpp:sasl-cb:0'>{list}</sasl-channel-binding>")
        };
        let reason = reason.to_owned();
        let conn = ScriptedConn::bytes(Vec::new(), move |w: &[u8]| {
            let w = String::from_utf8_lossy(w);
            let head = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>";
            if w.contains("<stream:stream") {
                opened += 1;
                if opened == 1 {
                    format!("{head}<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features>")
                } else {
                    format!(
                        "{head}<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>{mechs}</mechanisms>\
                         {cb}</stream:features>"
                    )
                }
                .into_bytes()
            } else if w.contains("<starttls") {
                b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>".to_vec()
            } else if w.contains("<auth") {
                *seen.lock().unwrap() = w.to_string();
                format!("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/><text>{reason}</text></failure>")
                    .into_bytes()
            } else {
                Vec::new()
            }
        });
        let mut conn: Box<dyn crate::transport::Conn> = Box::new(conn);
        let client = Client::new(Session { scramplus, ..session() }, false, Arc::new(crate::testing::FixedEnv::new(0)));
        let err = pollster::block_on(crate::machine::drive(
            client,
            &mut conn,
            &crate::Blocking(crate::testing::FakeTransport::new()),
        ))
        .unwrap_err();
        let auth = auth.lock().unwrap().clone();
        (auth, err)
    }

    /// The first SCRAM message inside a recorded `<auth>`.
    fn first_message(auth: &str) -> String {
        let b64 = auth.split('>').nth(1).unwrap().split('<').next().unwrap();
        String::from_utf8(crate::crypto::b64_decode(b64).unwrap()).unwrap()
    }

    #[test]
    fn scram_plus_uses_the_listed_binding() {
        let mechs = ["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"];
        let (auth, err) = plus_run(&mechs, &["tls-server-end-point"], true, "Invalid channel binding");
        assert!(auth.contains("mechanism='SCRAM-SHA-256-PLUS'"), "{auth}");
        assert!(first_message(&auth).starts_with("p=tls-server-end-point,,n=user,r="), "{auth}");
        assert!(err.to_string().contains("Add ?scramplus=no"), "{err}");
    }

    #[test]
    fn scram_plus_falls_back_without_binding() {
        let mechs = ["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"];
        // Disabled: plain SCRAM.
        let (auth, err) = plus_run(&mechs, &["tls-exporter"], false, "bad password");
        assert!(auth.contains("mechanism='SCRAM-SHA-256'") && first_message(&auth).starts_with("n,,"), "{auth}");
        assert_eq!(err.to_string(), "service error: XMPP authentication failed: not-authorized");
        // Only a type the connection cannot provide: plain SCRAM.
        let (auth, _) = plus_run(&mechs, &["tls-unique"], true, "x");
        assert!(auth.contains("mechanism='SCRAM-SHA-256'"), "{auth}");
        // No list: tls-exporter.
        let (auth, _) = plus_run(&mechs, &[], true, "x");
        assert!(first_message(&auth).starts_with("p=tls-exporter,,"), "{auth}");
    }
}
