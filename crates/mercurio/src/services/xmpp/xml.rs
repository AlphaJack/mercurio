//! XML for the XMPP client: escaping for the stanzas we write and a streaming reader (quick-xml over the bytes received so far). The reader yields the stream header, each complete top-level stanza and the stream end.

use quick_xml::events::{BytesRef, BytesStart, Event as XmlEvent};

use crate::error::{Error, Result};
use crate::transport::AsyncConn;

/// Escape character data.
pub fn text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c if is_xml_char(c) => out.push(c),
            _ => out.push('\u{FFFD}'),
        }
    }
    out
}

/// Escape an attribute value (for either quote style).
pub fn attr(s: &str) -> String {
    text(s).replace('\'', "&apos;").replace('"', "&quot;")
}

/// Characters XML 1.0 allows in a document.
fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

/// A parsed element.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Element {
    /// Qualified name as written (`stream:features`, `iq`, ...).
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Element>,
    /// Concatenated character data directly inside this element.
    pub text: String,
}

impl Element {
    /// Name without its namespace prefix.
    pub fn local(&self) -> &str {
        self.name.rsplit(':').next().unwrap_or(&self.name)
    }

    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// First child with this local name.
    pub fn child(&self, local: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.local() == local)
    }

    pub fn children_named<'a>(&'a self, local: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.local() == local)
    }
}

/// One item read from the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// `<stream:stream ...>` (attributes only; it stays open).
    Open(Element),
    /// A complete top-level stanza.
    Stanza(Element),
    /// `</stream:stream>`.
    Close,
}

/// Upper bound for one stanza; a server sending more is broken.
const MAX_STANZA: u64 = 1 << 20;
/// Nesting limit for one stanza.
const MAX_DEPTH: usize = 64;

/// Streaming reader over the server half of an XMPP stream. Received bytes are buffered and parsed one complete event at a time; more are read only when the event is incomplete. It owns the connection; write through [`Reader::conn`].
pub struct Reader<'c> {
    conn: &'c mut dyn AsyncConn,
    pending: Vec<u8>,
    /// The stream header's name, once read.
    open: Option<String>,
}

impl std::fmt::Debug for Reader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reader").field("open", &self.open.is_some()).finish_non_exhaustive()
    }
}

fn closed() -> Error {
    Error::transport("XMPP connection closed")
}

fn xml_error(e: quick_xml::Error) -> Error {
    if let quick_xml::Error::Io(io) = e {
        return Error::transport(io);
    }
    Error::service(format!("XMPP: malformed XML: {e}"))
}

/// A start tag as an [`Element`] without children.
fn element(start: &BytesStart<'_>) -> Result<Element> {
    let mut el = Element { name: start.name().as_ref().to_string(), ..Element::default() };
    for a in start.attributes() {
        let a = a.map_err(|e| xml_error(e.into()))?;
        let value = a.normalized_value(quick_xml::XmlVersion::Implicit1_0).map_err(xml_error)?;
        el.attrs.push((a.key.as_ref().to_string(), value.into_owned()));
    }
    Ok(el)
}

/// `&name;` or `&#n;` as text.
fn reference(r: &BytesRef<'_>) -> Result<String> {
    if let Some(c) = r.resolve_char_ref().map_err(xml_error)? {
        return Ok(c.to_string());
    }
    let raw = format!("&{};", r.clone().into_inner());
    quick_xml::escape::unescape(&raw)
        .map(|s| s.into_owned())
        .map_err(|e| Error::service(format!("XMPP: malformed XML: {e}")))
}

/// What [`parse`] found at the start of the buffered bytes.
enum Parsed {
    /// A complete event and the bytes it used.
    Event(Event, usize),
    /// The input ends inside an event; the syntax error it would be if no more bytes came.
    More(Option<quick_xml::Error>),
}

/// The next complete event in `input`; `stream` names the open stream header, if any. End tags are matched here: each parse starts mid-stream, where quick-xml would see the stream's end tag as unmatched.
fn parse(input: &[u8], stream: Option<&str>) -> Result<Parsed> {
    let mut xml = quick_xml::Reader::from_reader(input);
    xml.config_mut().check_end_names = false;
    xml.config_mut().allow_unmatched_ends = true;
    let mut stack: Vec<Element> = Vec::new();
    let mut start = 0;
    loop {
        let ev = match xml.read_event() {
            Ok(ev) => ev,
            Err(e @ quick_xml::Error::Syntax(_)) => return Ok(Parsed::More(Some(e))),
            Err(e) => return Err(xml_error(e)),
        };
        let used = xml.buffer_position() as usize;
        if stack.is_empty() {
            start = used;
        } else if used.saturating_sub(start) as u64 > MAX_STANZA {
            return Err(Error::service("XMPP stanza too large"));
        }
        let done = |ev| Ok(Parsed::Event(ev, used));
        match ev {
            XmlEvent::Eof => return Ok(Parsed::More(None)),
            XmlEvent::Start(s) if stream.is_none() => return done(Event::Open(element(&s)?)),
            XmlEvent::Start(s) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(Error::service("XMPP: stanza nested too deeply"));
                }
                stack.push(element(&s)?);
            }
            XmlEvent::Empty(s) if stream.is_some() => {
                let el = element(&s)?;
                match stack.last_mut() {
                    Some(parent) => parent.children.push(el),
                    None => return done(Event::Stanza(el)),
                }
            }
            XmlEvent::End(e) => {
                let found = e.name().as_ref().to_string();
                let expected = stack.last().map(|el| el.name.as_str()).or(stream);
                if let Some(expected) = expected.filter(|x| *x != found) {
                    let ill = quick_xml::errors::IllFormedError::MismatchedEndTag { expected: expected.into(), found };
                    return Err(xml_error(ill.into()));
                }
                let Some(el) = stack.pop() else { return done(Event::Close) };
                match stack.last_mut() {
                    Some(parent) => parent.children.push(el),
                    None => return done(Event::Stanza(el)),
                }
            }
            XmlEvent::Text(t) => match stack.last_mut() {
                Some(el) => el.text.push_str(&t.xml10_content()),
                None if t.xml10_content().trim().is_empty() => {}
                None => return Err(Error::service("XMPP: unexpected text at stream level")),
            },
            XmlEvent::GeneralRef(r) => match stack.last_mut() {
                Some(el) => el.text.push_str(&reference(&r)?),
                None => return Err(Error::service("XMPP: unexpected text at stream level")),
            },
            XmlEvent::CData(c) => match stack.last_mut() {
                Some(el) => el.text.push_str(&c.into_inner()),
                None => return Err(Error::service("XMPP: unexpected text at stream level")),
            },
            XmlEvent::Empty(_) | XmlEvent::DocType(_) => {
                return Err(Error::service("XMPP: unexpected markup"));
            }
            XmlEvent::Comment(_) | XmlEvent::Decl(_) | XmlEvent::PI(_) => {}
        }
    }
}

impl<'c> Reader<'c> {
    pub fn new(conn: &'c mut dyn AsyncConn) -> Self {
        Self { conn, pending: Vec::new(), open: None }
    }

    /// The connection, for writing.
    pub fn conn(&mut self) -> &mut dyn AsyncConn {
        &mut *self.conn
    }

    /// Whether bytes were received but not read yet.
    pub fn has_unread(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Start over on the same connection and expect a new stream header (after STARTTLS or SASL success). Unread bytes are dropped.
    pub fn reset(&mut self) {
        self.pending.clear();
        self.open = None;
    }

    /// Read until one complete event is available. EOF is an error.
    pub async fn next(&mut self) -> Result<Event> {
        loop {
            let eof = match parse(&self.pending, self.open.as_deref())? {
                Parsed::Event(ev, used) => {
                    if let Event::Open(el) = &ev {
                        self.open = Some(el.name.clone());
                    }
                    self.pending.drain(..used);
                    return Ok(ev);
                }
                Parsed::More(eof) => eof,
            };
            let mut chunk = [0u8; crate::net::READ_CHUNK];
            let n = self.conn.read(&mut chunk).await.map_err(Error::transport)?;
            if n == 0 {
                return Err(eof.map_or_else(closed, xml_error));
            }
            self.pending.extend_from_slice(&chunk[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hands out at most `chunk` bytes per `read` call.
    struct Feed {
        data: Vec<u8>,
        chunk: usize,
    }

    impl AsyncConn for Feed {
        fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> crate::BoxFuture<'a, std::io::Result<usize>> {
            let n = self.chunk.min(buf.len()).min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data.drain(..n);
            Box::pin(std::future::ready(Ok(n)))
        }
        fn write_all<'a>(&'a mut self, _: &'a [u8]) -> crate::BoxFuture<'a, std::io::Result<()>> {
            Box::pin(std::future::ready(Ok(())))
        }
        fn flush(&mut self) -> crate::BoxFuture<'_, std::io::Result<()>> {
            Box::pin(std::future::ready(Ok(())))
        }
        fn start_tls(&mut self) -> crate::BoxFuture<'_, Result<()>> {
            Box::pin(std::future::ready(Ok(())))
        }
        fn is_tls(&self) -> bool {
            false
        }
    }

    fn feed(data: &[u8], chunk: usize) -> Feed {
        Feed { data: data.to_vec(), chunk }
    }

    fn next(r: &mut Reader<'_>) -> Result<Event> {
        pollster::block_on(r.next())
    }

    fn events(input: &str) -> Vec<Event> {
        let mut conn = feed(input.as_bytes(), 64);
        let mut r = Reader::new(&mut conn);
        let mut out = Vec::new();
        while let Ok(ev) = next(&mut r) {
            out.push(ev);
        }
        out
    }

    #[test]
    fn reads_header_stanzas_and_close() {
        let evs = events(
            "<?xml version='1.0'?><stream:stream xmlns='jabber:client' id=\"abc\" version='1.0'>\
             <stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>\
             <mechanism>PLAIN</mechanism><mechanism>SCRAM-SHA-1</mechanism></mechanisms></stream:features>\
             <message from='a@b' type='chat'><body>x &amp; &lt;y&gt; &#x2603; <![CDATA[<z>]]></body></message>\
             <!-- c --><presence/></stream:stream>",
        );
        assert_eq!(evs.len(), 5);
        let Event::Open(h) = &evs[0] else { panic!() };
        assert_eq!(h.attr("id"), Some("abc"));
        let Event::Stanza(f) = &evs[1] else { panic!() };
        let mechs: Vec<_> = f.child("mechanisms").unwrap().children_named("mechanism").map(|m| m.text.clone()).collect();
        assert_eq!(mechs, ["PLAIN", "SCRAM-SHA-1"]);
        let Event::Stanza(m) = &evs[2] else { panic!() };
        assert_eq!(m.child("body").unwrap().text, "x & <y> \u{2603} <z>");
        assert_eq!(evs[3], Event::Stanza(Element { name: "presence".into(), ..Element::default() }));
        assert_eq!(evs[4], Event::Close);
    }

    #[test]
    fn waits_for_partial_input() {
        let input = b"<stream:stream a='1'><iq type='result' id='x'><bind><jid>a@b</jid></bind></iq>";
        let mut conn = feed(input, 1);
        let mut r = Reader::new(&mut conn);
        assert!(matches!(next(&mut r).unwrap(), Event::Open(_)));
        let Event::Stanza(iq) = next(&mut r).unwrap() else { panic!() };
        assert_eq!(iq.child("bind").unwrap().child("jid").unwrap().text, "a@b");
        // A stanza cut short by the connection closing is a transport error.
        let mut conn = feed(b"<s><iq><bind>", 1);
        let mut r = Reader::new(&mut conn);
        next(&mut r).unwrap();
        assert!(matches!(next(&mut r), Err(Error::Transport(_))));
    }

    #[test]
    fn rejects_mismatched_tags() {
        let mut conn = feed(b"<s><a><b></a>", 64);
        let mut r = Reader::new(&mut conn);
        next(&mut r).unwrap();
        assert!(matches!(next(&mut r), Err(Error::Service(_))));
    }

    #[test]
    fn limits_depth() {
        let deep = format!("<s>{}", "<a>".repeat(MAX_DEPTH + 1));
        let mut conn = feed(deep.as_bytes(), 64);
        let mut r = Reader::new(&mut conn);
        next(&mut r).unwrap();
        assert!(matches!(next(&mut r), Err(Error::Service(m)) if m.contains("deeply")));
    }

    #[test]
    fn reset_reports_unread_bytes() {
        let mut conn = feed(b"<s><proceed/><injected/>", 64);
        let mut r = Reader::new(&mut conn);
        next(&mut r).unwrap();
        next(&mut r).unwrap();
        assert!(r.has_unread());
        r.reset();
        assert!(!r.has_unread());
        // The rest is read again as a new stream.
        assert!(matches!(next(&mut r), Err(Error::Transport(_)) | Ok(Event::Open(_))));
    }

    #[test]
    fn random_input_never_panics() {
        let seeds: &[&[u8]] = &[
            b"<stream:stream a='1'><x y=\"2\"><z/>t&amp;&#65;&#x42;<![CDATA[c]]><!--n--></x></stream:stream>",
            b"<?xml?><s><iq type='result' id='a'><bind><jid>a@b/c</jid></bind></iq>",
        ];
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut rnd = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for i in 0..20_000 {
            let mut data = seeds[i % seeds.len()].to_vec();
            for _ in 0..(rnd() % 6) {
                let pos = (rnd() as usize) % (data.len() + 1);
                match rnd() % 3 {
                    0 if pos < data.len() => {
                        data.remove(pos);
                    }
                    1 => {
                        let alphabet = b"<>/&;'\"=!?[]-#x\x00\xff a";
                        data.insert(pos, alphabet[(rnd() as usize) % alphabet.len()]);
                    }
                    _ if pos < data.len() => data[pos] = rnd() as u8,
                    _ => {}
                }
            }
            let mut conn = feed(&data, 7);
            let mut r = Reader::new(&mut conn);
            for _ in 0..16 {
                if next(&mut r).is_err() {
                    break;
                }
            }
        }
    }

    #[test]
    fn escapes() {
        assert_eq!(text("<a & b>"), "&lt;a &amp; b&gt;");
        assert_eq!(attr("it's \"x\""), "it&apos;s &quot;x&quot;");
        assert_eq!(text("a\u{1}b"), "a\u{FFFD}b");
    }
}
