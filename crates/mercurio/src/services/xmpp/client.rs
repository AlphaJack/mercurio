//! A minimal one-shot XMPP client session (RFC 6120/6121, XEP-0045): stream negotiation, STARTTLS, SASL, resource binding, session, presence, optional roster fetch, MUC join, messages, stream close.

use super::sasl::{Mech, Scram, plain};
use super::xml::{self, Element, Event, Reader};
use crate::error::{Error, Result};
use crate::transport::Conn;

const NS_TLS: &str = "urn:ietf:params:xml:ns:xmpp-tls";
const NS_SASL: &str = "urn:ietf:params:xml:ns:xmpp-sasl";
const NS_BIND: &str = "urn:ietf:params:xml:ns:xmpp-bind";
const NS_SESSION: &str = "urn:ietf:params:xml:ns:xmpp-session";
const NS_ROSTER: &str = "jabber:iq:roster";
const NS_MUC: &str = "http://jabber.org/protocol/muc";

/// Stream security (`?mode=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Plain TCP; STARTTLS is not attempted.
    None,
    /// Direct TLS from the first byte.
    Tls,
    /// Plain TCP upgraded with STARTTLS (required).
    StartTls,
}

/// What one session delivers.
#[derive(Debug, Clone)]
pub struct Session {
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

struct Stream<'a> {
    /// Owns the connection; writes go through it.
    reader: Reader<&'a mut dyn Conn>,
    ids: u32,
}

impl Stream<'_> {
    fn send(&mut self, data: &str) -> Result<()> {
        let conn = self.reader.get_mut()?;
        conn.write_all(data.as_bytes()).map_err(Error::transport)?;
        conn.flush().map_err(Error::transport)
    }

    fn next(&mut self) -> Result<Event> {
        self.reader.next()
    }

    fn is_tls(&self) -> bool {
        self.reader.get_ref().is_ok_and(|c| c.is_tls())
    }

    /// Next top-level stanza; stream errors and stream end fail.
    fn stanza(&mut self) -> Result<Element> {
        match self.next()? {
            Event::Stanza(el) if el.local() == "error" && el.name.contains(':') => {
                let cond = el.children.first().map(|c| c.local().to_string()).unwrap_or_default();
                Err(Error::service(format!("XMPP stream error: {cond}")))
            }
            Event::Stanza(el) => Ok(el),
            Event::Open(_) => Err(Error::service("XMPP: unexpected stream header")),
            Event::Close => Err(Error::service("XMPP: server closed the stream")),
        }
    }

    /// Open (or restart) the stream and return the server's features.
    fn open(&mut self, domain: &str) -> Result<Element> {
        self.send(&format!(
            "<?xml version='1.0'?><stream:stream to='{}' xmlns='jabber:client' \
             xmlns:stream='http://etherx.jabber.org/streams' xml:lang='en' version='1.0'>",
            xml::attr(domain)
        ))?;
        let Event::Open(_) = self.next()? else {
            return Err(Error::service("XMPP: server did not open a stream"));
        };
        loop {
            let el = self.stanza()?;
            if el.local() == "features" {
                return Ok(el);
            }
        }
    }

    fn next_id(&mut self, prefix: &str) -> String {
        self.ids += 1;
        format!("{prefix}{}", self.ids)
    }

    /// Send an IQ and wait for its answer, skipping unrelated stanzas.
    fn iq(&mut self, kind: &str, payload: &str) -> Result<Element> {
        let id = self.next_id("mercurio");
        self.send(&format!("<iq type='{kind}' id='{id}'>{payload}</iq>"))?;
        loop {
            let el = self.stanza()?;
            if el.local() == "iq" && el.attr("id") == Some(id.as_str()) {
                return Ok(el);
            }
        }
    }
}

fn iq_error(what: &str, el: &Element) -> Error {
    let cond = el
        .child("error")
        .and_then(|e| e.children.iter().find(|c| c.local() != "text"))
        .map(|c| c.local().to_string())
        .unwrap_or_else(|| "unknown".into());
    Error::service(format!("XMPP {what} failed: {cond}"))
}

/// SASL negotiation; `Ok` once the server reports success.
fn authenticate(s: &mut Stream<'_>, features: &Element, user: &str, password: &str) -> Result<()> {
    let offered: Vec<String> = features
        .child("mechanisms")
        .map(|m| m.children_named("mechanism").map(|c| c.text.trim().to_string()).collect())
        .unwrap_or_default();
    let encrypted = s.is_tls();
    let mech = Mech::choose(offered.iter().map(String::as_str), encrypted).ok_or_else(|| {
        Error::service(if offered.iter().any(|m| m.eq_ignore_ascii_case("PLAIN")) && !encrypted {
            "XMPP: the server only offers PLAIN authentication over an unencrypted stream; use TLS".to_string()
        } else {
            "XMPP: no supported SASL mechanism offered".to_string()
        })
    })?;
    let failed = |el: &Element| {
        let cond = el.children.iter().find(|c| c.local() != "text").map(|c| c.local().to_string());
        Error::service(format!("XMPP authentication failed: {}", cond.unwrap_or_else(|| "unknown".into())))
    };
    if mech == Mech::Plain {
        s.send(&format!("<auth xmlns='{NS_SASL}' mechanism='PLAIN'>{}</auth>", plain(user, password)))?;
        let el = s.stanza()?;
        return match el.local() {
            "success" => Ok(()),
            "failure" => Err(failed(&el)),
            _ => Err(Error::service("XMPP: unexpected SASL answer")),
        };
    }
    let mut scram = Scram::new(mech, user);
    s.send(&format!(
        "<auth xmlns='{NS_SASL}' mechanism='{}'>{}</auth>",
        mech.name(),
        crate::crypto::b64(scram.client_first().as_bytes())
    ))?;
    let decode = |el: &Element| -> Result<String> {
        let raw = crate::crypto::b64_decode(el.text.trim()).ok_or_else(|| Error::service("XMPP: bad SASL data"))?;
        Ok(String::from_utf8_lossy(&raw).into_owned())
    };
    let el = s.stanza()?;
    match el.local() {
        "challenge" => {}
        "failure" => return Err(failed(&el)),
        _ => return Err(Error::service("XMPP: unexpected SASL answer")),
    }
    let fin = scram.client_final(&decode(&el)?, password)?;
    s.send(&format!("<response xmlns='{NS_SASL}'>{}</response>", crate::crypto::b64(fin.as_bytes())))?;
    let mut el = s.stanza()?;
    if el.local() == "challenge" {
        // Some servers send `v=` in a challenge and an empty success.
        scram.verify(&decode(&el)?)?;
        s.send(&format!("<response xmlns='{NS_SASL}'/>"))?;
        el = s.stanza()?;
        return match el.local() {
            "success" => Ok(()),
            "failure" => Err(failed(&el)),
            _ => Err(Error::service("XMPP: unexpected SASL answer")),
        };
    }
    match el.local() {
        "success" => scram.verify(&decode(&el)?),
        "failure" => Err(failed(&el)),
        _ => Err(Error::service("XMPP: unexpected SASL answer")),
    }
}

/// Run the whole session on `conn`.
pub fn run(conn: &mut dyn Conn, cfg: &Session) -> Result<()> {
    let jid = split_jid(&cfg.jid);
    let mut s = Stream { reader: Reader::new(conn), ids: 0 };

    let mut features = s.open(jid.domain)?;
    if cfg.mode == Mode::StartTls && !s.is_tls() {
        if features.child("starttls").is_none() {
            return Err(Error::service("XMPP: the server does not offer STARTTLS"));
        }
        s.send(&format!("<starttls xmlns='{NS_TLS}'/>"))?;
        let el = s.stanza()?;
        if el.local() != "proceed" {
            return Err(Error::service("XMPP: the server refused STARTTLS"));
        }
        // Anything the server sent after `<proceed/>` arrived in plain text and must not be read as part of the encrypted stream.
        if s.reader.has_unread() {
            return Err(Error::service("XMPP: unexpected data after STARTTLS proceed"));
        }
        s.reader.reset();
        s.reader.get_mut()?.start_tls()?;
        features = s.open(jid.domain)?;
    }

    authenticate(&mut s, &features, jid.local, &cfg.password)?;
    s.reader.reset();
    let features = s.open(jid.domain)?;

    if features.child("bind").is_some() {
        let resource = jid.resource.map(|r| format!("<resource>{}</resource>", xml::text(r))).unwrap_or_default();
        let res = s.iq("set", &format!("<bind xmlns='{NS_BIND}'>{resource}</bind>"))?;
        if res.attr("type") != Some("result") {
            return Err(iq_error("resource binding", &res));
        }
    }
    if let Some(sess) = features.child("session")
        && sess.child("optional").is_none()
    {
        let res = s.iq("set", &format!("<session xmlns='{NS_SESSION}'/>"))?;
        if res.attr("type") != Some("result") {
            return Err(iq_error("session", &res));
        }
    }

    s.send("<presence/>")?;

    if cfg.roster {
        // Roster errors are ignored.
        s.iq("get", &format!("<query xmlns='{NS_ROSTER}'/>"))?;
    }

    let default = [("chat".to_string(), cfg.jid.clone())];
    let targets = if cfg.targets.is_empty() { &default[..] } else { &cfg.targets[..] };
    for (kind, to) in targets {
        if kind == "groupchat" {
            join_muc(&mut s, to, &cfg.nick)?;
        }
        let subject =
            if cfg.subject.is_empty() { String::new() } else { format!("<subject>{}</subject>", xml::text(&cfg.subject)) };
        s.send(&format!(
            "<message to='{}' type='{kind}'>{subject}<body>{}</body></message>",
            xml::attr(to),
            xml::text(&cfg.body)
        ))?;
    }

    s.send("</stream:stream>")?;
    // Wait for the server to close its side; errors no longer matter.
    while let Ok(ev) = s.next() {
        if ev == Event::Close {
            break;
        }
    }
    Ok(())
}

/// XEP-0045 join: presence to `room/nick`, then wait for the room's answer about our occupant JID.
fn join_muc(s: &mut Stream<'_>, room: &str, nick: &str) -> Result<()> {
    let occupant = format!("{room}/{nick}");
    s.send(&format!("<presence to='{}'><x xmlns='{NS_MUC}'/></presence>", xml::attr(&occupant)))?;
    loop {
        let el = s.stanza()?;
        if el.local() == "presence" && el.attr("from").is_some_and(|f| f.eq_ignore_ascii_case(&occupant)) {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::ScriptedConn;

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
        }
    }

    /// Bytes sent in plain text together with `<proceed/>` must not be read as part of the TLS stream.
    #[test]
    fn starttls_injection_fails() {
        let mut conn = ScriptedConn::bytes(Vec::new(), |w: &[u8]| {
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
        let err = run(&mut conn, &session()).unwrap_err();
        assert!(err.to_string().contains("after STARTTLS"), "{err}");
        assert!(!conn.is_tls());
    }
}
