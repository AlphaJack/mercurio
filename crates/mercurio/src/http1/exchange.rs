//! One HTTP/1.1 exchange as sans-IO [`Protocol`] machines: [`SendRequest`] writes the request and reads the response head, [`ReadBody`] reads the body the head frames. [`crate::machine::run`] drives them on a connection; a test feeds bytes directly.
//!
//! The machines report what happened ([`Trip`]); whether a failure means "retry on a new connection" is the caller's decision.

use std::collections::VecDeque;
use std::io;

use crate::error::Error;
use crate::http::{Method, body_too_large};
use crate::http1::wire::{COALESCE, Framing, Head, MAX_HEAD, digits, parse_head};
use crate::machine::{Input, Output, Protocol};

/// Why [`SendRequest`] produced no response head.
#[derive(Debug)]
pub(crate) enum Trip {
    /// Writing the request failed.
    WriteFailed(io::Error),
    /// The connection ended before the first byte of a response.
    NoResponse,
    /// Any other failure.
    Fail(Error),
}

/// Write a request, then read the response head (1xx heads other than 101 are skipped).
pub(crate) struct SendRequest {
    writes: VecDeque<Vec<u8>>,
    buf: Vec<u8>,
    method: Method,
    outcome: Option<Result<Head, Trip>>,
}

impl SendRequest {
    /// `wire` is the request head; a body up to [`COALESCE`] bytes goes out in the same write. `buf` holds bytes already received on the connection.
    pub(crate) fn new(wire: Vec<u8>, body: &[u8], method: Method, buf: Vec<u8>) -> Self {
        let mut writes = VecDeque::new();
        if body.len() <= COALESCE {
            let mut all = wire;
            all.extend_from_slice(body);
            writes.push_back(all);
        } else {
            writes.push_back(wire);
            writes.push_back(body.to_vec());
        }
        Self { writes, buf, method, outcome: None }
    }

    /// The response head, or why there is none, and the bytes received after the head.
    pub(crate) fn finish(self) -> (Result<Head, Trip>, Vec<u8>) {
        (self.outcome.unwrap_or(Err(Trip::NoResponse)), self.buf)
    }

    /// A complete head in the buffer: parsed and removed; `None` while it is incomplete.
    fn head(&mut self) -> Option<Result<Head, Trip>> {
        loop {
            let end = self.buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)?;
            let head = parse_head(self.buf.get(..end).unwrap_or_default(), self.method);
            self.buf.drain(..end);
            match head {
                Ok(h) if (100..200).contains(&h.status) && h.status != 101 => {}
                Ok(h) => return Some(Ok(h)),
                Err(e) => return Some(Err(Trip::Fail(e))),
            }
        }
    }
}

impl Protocol for SendRequest {
    fn next(&mut self) -> Output {
        if self.outcome.is_some() {
            return Output::Done(Ok(()));
        }
        if let Some(w) = self.writes.pop_front() {
            return Output::Write(w);
        }
        if let Some(head) = self.head() {
            self.outcome = Some(head);
            return Output::Done(Ok(()));
        }
        if self.buf.len() > MAX_HEAD {
            self.outcome = Some(Err(Trip::Fail(Error::Unconfirmed("the response head is too large".into()))));
            return Output::Done(Ok(()));
        }
        Output::Read
    }

    fn input(&mut self, input: Input<'_>) {
        let started = !self.buf.is_empty();
        let outcome = match input {
            Input::Data([]) if started => Err(Trip::Fail(Error::Unconfirmed("connection closed mid-response".into()))),
            Input::Data([]) => Err(Trip::NoResponse),
            Input::Data(d) => {
                self.buf.extend_from_slice(d);
                return;
            }
            Input::ReadError(e) if !started && is_reset(&e) => Err(Trip::NoResponse),
            Input::ReadError(e) => Err(Trip::Fail(unconfirmed(&e, "receive response"))),
            Input::WriteError(e) => {
                self.writes.clear();
                Err(Trip::WriteFailed(e))
            }
            Input::Tls(_) | Input::ChannelBinding(_) => return,
        };
        self.outcome = Some(outcome);
    }
}

/// Where [`ReadBody`] is in the body.
#[derive(Debug)]
enum Body {
    /// This many bytes left of a `Content-Length` body.
    Length(u64),
    /// A chunk-size line is next.
    Size,
    /// This many bytes left of a chunk.
    Chunk(u64),
    /// The `\r\n` after a chunk is next.
    ChunkEnd,
    /// Trailer lines, up to an empty one.
    Trailers,
    /// Everything until the server closes the connection.
    Close,
    Done,
}

/// Read the body of a response, at most `limit` bytes (`max_body` names the limit in the error).
pub(crate) struct ReadBody {
    state: Body,
    limit: u64,
    max_body: u64,
    buf: Vec<u8>,
    body: Vec<u8>,
    error: Option<Error>,
}

impl ReadBody {
    /// `buf` holds the bytes received after the head.
    pub(crate) fn new(framing: &Framing, limit: u64, max_body: u64, buf: Vec<u8>) -> Self {
        let mut body = Vec::new();
        let (state, error) = match framing {
            Framing::None => (Body::Done, None),
            Framing::Length(n) if *n > limit => (Body::Done, Some(too_large(limit, max_body))),
            Framing::Length(n) => {
                body.reserve(usize::try_from(*n).unwrap_or(0).min(1 << 20));
                (Body::Length(*n), None)
            }
            Framing::Chunked => (Body::Size, None),
            Framing::Close => (Body::Close, None),
        };
        Self { state, limit, max_body, buf, body, error }
    }

    /// The body, and the bytes received after it (none, on a connection worth reusing).
    pub(crate) fn finish(self) -> (crate::error::Result<Vec<u8>>, Vec<u8>) {
        match self.error {
            Some(e) => (Err(e), self.buf),
            None => (Ok(self.body), self.buf),
        }
    }

    /// Move up to `n` buffered bytes into the body; how many moved.
    fn take(&mut self, n: u64) -> u64 {
        let k = usize::try_from(n).unwrap_or(usize::MAX).min(self.buf.len());
        // A slice copy is a `memcpy`; extending from the `Drain` iterator goes byte by byte.
        self.body.extend_from_slice(self.buf.get(..k).unwrap_or_default());
        self.buf.drain(..k);
        k as u64
    }

    /// The next line of chunked framing without its `\r\n`; `None` until it has arrived.
    fn line(&mut self) -> Result<Option<String>, Error> {
        let Some(end) = self.buf.windows(2).position(|w| w == b"\r\n") else {
            if self.buf.len() > MAX_HEAD {
                return Err(Error::Unconfirmed("bad chunk framing".into()));
            }
            return Ok(None);
        };
        let line = String::from_utf8_lossy(self.buf.get(..end).unwrap_or_default()).into_owned();
        self.buf.drain(..end + 2);
        Ok(Some(line))
    }

    /// One step with what is buffered; `false` when more bytes are needed.
    fn step(&mut self) -> Result<bool, Error> {
        match self.state {
            Body::Done => Ok(true),
            Body::Length(0) => {
                self.state = Body::Done;
                Ok(true)
            }
            Body::Length(n) => {
                let k = self.take(n);
                self.state = Body::Length(n - k);
                Ok(k > 0)
            }
            Body::Chunk(0) => {
                self.state = Body::ChunkEnd;
                Ok(true)
            }
            Body::Chunk(n) => {
                let k = self.take(n);
                self.state = Body::Chunk(n - k);
                Ok(k > 0)
            }
            Body::Size => {
                let Some(line) = self.line()? else { return Ok(false) };
                let size = line.split(';').next().unwrap_or_default().trim();
                let size = digits(size, 16).ok_or_else(|| Error::Unconfirmed("bad chunk size".into()))?;
                self.state = if size == 0 {
                    Body::Trailers
                } else if self.body.len() as u64 + size > self.limit {
                    return Err(too_large(self.limit, self.max_body));
                } else {
                    Body::Chunk(size)
                };
                Ok(true)
            }
            Body::ChunkEnd => {
                let Some(line) = self.line()? else { return Ok(false) };
                if !line.is_empty() {
                    return Err(Error::Unconfirmed("bad chunk".into()));
                }
                self.state = Body::Size;
                Ok(true)
            }
            Body::Trailers => {
                let Some(line) = self.line()? else { return Ok(false) };
                if line.is_empty() {
                    self.state = Body::Done;
                }
                Ok(true)
            }
            Body::Close => {
                if self.buf.is_empty() {
                    return Ok(false);
                }
                if (self.body.len() + self.buf.len()) as u64 > self.limit {
                    return Err(too_large(self.limit, self.max_body));
                }
                self.body.append(&mut self.buf);
                Ok(false)
            }
        }
    }
}

impl Protocol for ReadBody {
    fn next(&mut self) -> Output {
        loop {
            if self.error.is_some() || matches!(self.state, Body::Done) {
                return Output::Done(Ok(()));
            }
            match self.step() {
                Ok(true) => {}
                Ok(false) => return Output::Read,
                Err(e) => self.error = Some(e),
            }
        }
    }

    fn input(&mut self, input: Input<'_>) {
        match input {
            Input::Data([]) if matches!(self.state, Body::Close) => self.state = Body::Done,
            Input::Data([]) => self.error = Some(Error::Unconfirmed("connection closed before the body ended".into())),
            Input::Data(d) => self.buf.extend_from_slice(d),
            Input::ReadError(e) => self.error = Some(unconfirmed(&e, "receive body")),
            Input::WriteError(_) | Input::Tls(_) | Input::ChannelBinding(_) => {}
        }
    }
}

fn too_large(limit: u64, max_body: u64) -> Error {
    if max_body == 0 { body_too_large(limit) } else { body_too_large(max_body) }
}

/// The peer reset or dropped the connection.
pub(crate) fn is_reset(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    )
}

/// An I/O failure after the request may have arrived.
pub(crate) fn unconfirmed(e: &io::Error, what: &str) -> Error {
    if e.kind() == io::ErrorKind::TimedOut {
        Error::Unconfirmed(format!("timed out ({what})"))
    } else {
        Error::Unconfirmed(format!("{what}: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run `machine` on `incoming`, handed over `step` bytes per read and then end of stream; what it wrote.
    fn feed(machine: &mut impl Protocol, incoming: &[u8], step: usize) -> Vec<u8> {
        let (mut written, mut rest) = (Vec::new(), incoming);
        loop {
            match machine.next() {
                Output::Write(w) => written.extend(w),
                Output::Read => {
                    let (now, later) = rest.split_at(step.min(rest.len()));
                    machine.input(Input::Data(now));
                    rest = later;
                }
                Output::Done(r) => {
                    r.unwrap();
                    return written;
                }
                other @ (Output::StartTls | Output::ChannelBinding(_) | Output::Sleep(_)) => {
                    panic!("unexpected {other:?}")
                }
            }
        }
    }

    /// The same bytes, whole and split at every size up to 9.
    fn steps(incoming: &[u8]) -> impl Iterator<Item = usize> {
        (1..10).chain([incoming.len().max(1)])
    }

    fn head(incoming: &[u8], step: usize, method: Method) -> (Result<Head, Trip>, Vec<u8>) {
        let mut m = SendRequest::new(b"GET / HTTP/1.1\r\n\r\n".to_vec(), b"", method, Vec::new());
        assert_eq!(feed(&mut m, incoming, step), b"GET / HTTP/1.1\r\n\r\n");
        m.finish()
    }

    fn body(framing: Framing, limit: u64, incoming: &[u8], step: usize) -> (crate::error::Result<Vec<u8>>, Vec<u8>) {
        let mut m = ReadBody::new(&framing, limit, 0, Vec::new());
        feed(&mut m, incoming, step);
        m.finish()
    }

    #[test]
    fn request_and_body_go_out_together_when_small() {
        let mut m = SendRequest::new(b"H".to_vec(), b"body", Method::Post, Vec::new());
        assert!(matches!(m.next(), Output::Write(w) if w == b"Hbody"));
        let big = vec![b'x'; COALESCE + 1];
        let mut m = SendRequest::new(b"H".to_vec(), &big, Method::Post, Vec::new());
        assert!(matches!(m.next(), Output::Write(w) if w == b"H"));
        assert!(matches!(m.next(), Output::Write(w) if w.len() == COALESCE + 1));
    }

    #[test]
    fn heads_parse_whatever_the_reads() {
        let incoming = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-A: b\r\n\r\nhi";
        for step in steps(incoming) {
            let (h, rest) = head(incoming, step, Method::Get);
            let h = h.unwrap();
            assert_eq!((h.status, h.header("x-a"), &h.framing), (200, Some("b"), &Framing::Length(2)), "step {step}");
            // What arrived after the head is kept for the body.
            assert!(b"hi".starts_with(&rest), "step {step}: {rest:?}");
        }
    }

    #[test]
    fn content_length_is_digits_only() {
        let framing = |value: &str| {
            let raw = format!("HTTP/1.1 200 OK\r\nContent-Length: {value}\r\n\r\n");
            head(raw.as_bytes(), 64, Method::Get).0.map(|h| h.framing)
        };
        for good in ["5", " 5 ", "5, 5", "005"] {
            assert!(matches!(framing(good), Ok(Framing::Length(5))), "{good:?}");
        }
        for bad in ["+5", "-5", "0x5", "5 5", "", "5, 6", "99999999999999999999"] {
            assert!(matches!(framing(bad), Err(Trip::Fail(Error::Unconfirmed(_)))), "{bad:?}");
        }
    }

    #[test]
    fn heads_report_how_they_failed() {
        assert!(matches!(head(b"", 4, Method::Get).0, Err(Trip::NoResponse)));
        let mid = head(b"HTTP/1.1 200", 4, Method::Get).0;
        assert!(matches!(mid, Err(Trip::Fail(Error::Unconfirmed(m))) if m == "connection closed mid-response"));
        assert!(matches!(head(b"SMTP 220\r\n\r\n", 4, Method::Get).0, Err(Trip::Fail(_))));

        let mut m = SendRequest::new(b"H".to_vec(), b"", Method::Get, Vec::new());
        assert!(matches!(m.next(), Output::Write(_)));
        m.input(Input::WriteError(io::ErrorKind::BrokenPipe.into()));
        assert!(matches!(m.next(), Output::Done(Ok(()))));
        assert!(matches!(m.finish().0, Err(Trip::WriteFailed(e)) if e.kind() == io::ErrorKind::BrokenPipe));

        let mut m = SendRequest::new(b"H".to_vec(), b"", Method::Get, Vec::new());
        m.next();
        assert!(matches!(m.next(), Output::Read));
        m.input(Input::ReadError(io::ErrorKind::ConnectionReset.into()));
        assert!(matches!(m.finish().0, Err(Trip::NoResponse)), "a reset before any byte is no response");

        let mut m = SendRequest::new(b"H".to_vec(), b"", Method::Get, Vec::new());
        m.next();
        m.next();
        m.input(Input::Data(&vec![b'a'; MAX_HEAD + 1]));
        assert!(matches!(m.next(), Output::Done(Ok(()))));
        assert!(matches!(m.finish().0, Err(Trip::Fail(Error::Unconfirmed(m))) if m.contains("too large")));
    }

    #[test]
    fn bodies_decode_whatever_the_reads() {
        let chunked = b"4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nTrailer: x\r\n\r\nNEXT";
        for step in steps(chunked) {
            let (b, rest) = body(Framing::Chunked, 100, chunked, step);
            assert_eq!(b.unwrap(), b"Wikipedia", "step {step}");
            assert!(b"NEXT".starts_with(&rest), "step {step}: the bytes after the body are left over");
        }
        for step in steps(b"helloNEXT") {
            let (b, rest) = body(Framing::Length(5), 100, b"helloNEXT", step);
            assert_eq!(b.unwrap(), b"hello", "step {step}");
            assert!(b"NEXT".starts_with(&rest), "step {step}");
        }
        for step in steps(b"until close") {
            assert_eq!(body(Framing::Close, 100, b"until close", step).0.unwrap(), b"until close", "step {step}");
        }
        assert_eq!(body(Framing::None, 100, b"ignored", 4).0.unwrap(), b"");
        assert_eq!(body(Framing::Length(0), 100, b"", 4).0.unwrap(), b"");
    }

    #[test]
    fn bodies_keep_their_limit_and_framing() {
        let too_large =
            |r: crate::error::Result<Vec<u8>>| matches!(r, Err(Error::Transport(m)) if m.contains("larger than"));
        assert!(too_large(body(Framing::Length(11), 10, b"", 4).0), "refused before reading");
        assert!(too_large(body(Framing::Chunked, 10, b"b\r\nhello world\r\n0\r\n\r\n", 4).0));
        assert!(too_large(body(Framing::Close, 10, b"hello world", 4).0));
        assert_eq!(body(Framing::Close, 11, b"hello world", 4).0.unwrap(), b"hello world");

        let unconfirmed =
            |r: crate::error::Result<Vec<u8>>, want: &str| matches!(r, Err(Error::Unconfirmed(m)) if m == want);
        for size in ["zz", "+a", "-1", "", "1 0", "0x5", "ffffffffffffffffff"] {
            let chunked = format!("{size}\r\nx\r\n0\r\n\r\n");
            assert!(unconfirmed(body(Framing::Chunked, 100, chunked.as_bytes(), 4).0, "bad chunk size"), "{size:?}");
        }
        assert_eq!(body(Framing::Chunked, 100, b" A ;x\r\n0123456789\r\n0\r\n\r\n", 4).0.unwrap(), b"0123456789");
        assert!(unconfirmed(body(Framing::Chunked, 100, b"2\r\nabX\r\n", 4).0, "bad chunk"));
        assert!(unconfirmed(body(Framing::Chunked, 100, &vec![b'1'; MAX_HEAD + 1], 4096).0, "bad chunk framing"));
        assert!(unconfirmed(body(Framing::Length(5), 100, b"abc", 4).0, "connection closed before the body ended"));
        assert!(unconfirmed(body(Framing::Chunked, 100, b"5\r\nab", 4).0, "connection closed before the body ended"));

        let mut m = ReadBody::new(&Framing::Length(5), 100, 0, Vec::new());
        assert!(matches!(m.next(), Output::Read));
        m.input(Input::ReadError(io::ErrorKind::TimedOut.into()));
        assert!(unconfirmed(m.finish().0, "timed out (receive body)"));
    }
}
