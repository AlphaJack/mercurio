//! A small SMTP client (RFC 5321) as a hand-written sans-IO state machine for [`crate::Plan::socket`]: EHLO/HELO, STARTTLS (RFC 3207), AUTH CRAM-MD5 (RFC 2195) / PLAIN / LOGIN (RFC 4954), MAIL/RCPT/DATA with dot-stuffing, QUIT.
//!
//! [`Smtp`] never does I/O: every command it writes moves it to the [`State`] that reads the reply, and each reply decides the next command.

use md5::{Digest, Md5};

use crate::crypto;
use crate::error::{Error, Result};
use crate::machine::{Input, LineBuf, Output, Protocol};
use crate::service::Secret;

/// Transport security of the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    /// Plain text from start to end.
    Insecure,
    /// TLS from the first byte (the endpoint is opened with `tls: true`).
    Ssl,
    /// Plain connection upgraded with STARTTLS; refuses to continue without it.
    StartTls,
}

/// One message to submit.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub from: String,
    pub recipients: Vec<String>,
    /// The full RFC 5322 message (CRLF line endings, not dot-stuffed).
    pub data: String,
}

/// Everything a session needs.
#[derive(Debug)]
pub struct Job {
    pub security: Security,
    /// Name announced in EHLO/HELO.
    pub helo: String,
    pub user: Option<String>,
    pub password: Option<Secret>,
    pub messages: Vec<Envelope>,
}

#[derive(Debug)]
struct Reply {
    code: u16,
    lines: Vec<String>,
}

impl Reply {
    fn text(&self) -> String {
        self.lines.join(" ")
    }
}

fn smtp_error(what: &str, r: &Reply) -> Error {
    Error::Service(format!("SMTP {what} failed: {} {}", r.code, crate::util::truncate_chars(&r.text(), 200)))
}

/// Advertised EHLO extensions (upper-cased keyword -> parameters).
#[derive(Debug, Default)]
struct Extensions(Vec<(String, String)>);

impl Extensions {
    fn has(&self, key: &str) -> bool {
        self.0.iter().any(|(k, _)| k == key)
    }
    fn params(&self, key: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
    /// The extensions of a 250 EHLO reply (its first line is the greeting).
    fn from_ehlo(r: &Reply) -> Self {
        let mut ext = Extensions::default();
        for line in r.lines.iter().skip(1) {
            // "AUTH=PLAIN LOGIN" is an old form of "AUTH PLAIN LOGIN".
            let (k, v) = match line.split_once([' ', '=']) {
                Some((k, v)) => (k, v),
                None => (line.as_str(), ""),
            };
            ext.0.push((k.to_ascii_uppercase(), v.trim().to_string()));
        }
        ext
    }
}

/// HMAC-MD5 (RFC 2104).
fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        block[..16].copy_from_slice(&Md5::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |byte: u8| block.map(|b| b ^ byte);
    let inner = Md5::new().chain_update(pad(0x36)).chain_update(data).finalize();
    Md5::new().chain_update(pad(0x5c)).chain_update(inner).finalize().into()
}

/// The CRAM-MD5 answer to a base64 `challenge`, like smtplib's `auth_cram_md5`.
fn cram_md5_response(challenge: &str, user: &str, password: &str) -> Result<String> {
    if !password.is_ascii() {
        return Err(Error::Message("CRAM-MD5 needs an ASCII password".into()));
    }
    let challenge = crypto::b64_decode(challenge.trim()).unwrap_or_default();
    let digest = crypto::hex(&hmac_md5(password.as_bytes(), &challenge));
    Ok(crypto::b64(format!("{user} {digest}").as_bytes()))
}

/// The mechanisms smtplib's `login()` tries, in order.
const MECHS: [&str; 3] = ["CRAM-MD5", "PLAIN", "LOGIN"];

/// Where a session is: each state but [`State::TlsHandshake`] and [`State::Closing`] waits for the reply to the command it just wrote.
#[derive(Debug)]
enum State {
    Greeting,
    Ehlo { after_tls: bool },
    Helo { after_tls: bool },
    StartTls,
    /// Waiting for the transport's TLS upgrade.
    TlsHandshake,
    /// The first step of `mech` (`MECHS[mech]`), or the second (CRAM-MD5 answer, LOGIN password) when `answered`.
    Auth { mechs: Vec<String>, mech: usize, answered: bool, last: Option<Error> },
    Mail { msg: usize },
    Rcpt { msg: usize, rcpt: usize, refused: Vec<(String, u16)> },
    Data { msg: usize, refused: Vec<(String, u16)> },
    Dot { msg: usize, refused: Vec<(String, u16)> },
    /// After a failed MAIL, RCPT or DATA; the reply (or a failure to get one) is ignored.
    Rset { msg: usize },
    /// The last command; the reply (or a failure to get one) is ignored.
    Quit,
    /// Writing the best-effort QUIT after a fatal error.
    Closing,
    Done,
}

/// An SMTP session as a sans-IO state machine.
#[derive(Debug)]
pub struct Smtp {
    job: Job,
    state: State,
    ext: Extensions,
    /// Received bytes not yet split into lines.
    rx: LineBuf,
    /// The lines of a multi-line reply so far.
    reply: Vec<String>,
    out: Vec<u8>,
    failures: Vec<Error>,
    /// QUIT went out as the last command; a later failure needs no best-effort QUIT.
    quit_sent: bool,
    result: Option<Result<()>>,
}

/// A whole SMTP session; `tls` is whether the stream starts encrypted (the session does not need it).
pub fn session(job: Job, _tls: bool) -> Smtp {
    Smtp {
        job,
        state: State::Greeting,
        ext: Extensions::default(),
        rx: LineBuf::default(),
        reply: Vec::new(),
        out: Vec::new(),
        failures: Vec::new(),
        quit_sent: false,
        result: None,
    }
}

impl Smtp {
    fn send(&mut self, line: &str, next: State) {
        self.out.extend_from_slice(line.as_bytes());
        self.out.extend_from_slice(b"\r\n");
        self.state = next;
    }

    /// End with `err`, writing a best-effort QUIT first unless QUIT was already sent.
    fn fail(&mut self, err: Error) {
        self.result = Some(Err(err));
        if self.quit_sent {
            self.state = State::Done;
        } else {
            self.quit_sent = true;
            self.send("QUIT", State::Closing);
        }
    }

    /// A failure to read or write in the current state: fatal, except where the reply is ignored.
    fn io_failed(&mut self, err: Error) {
        match self.state {
            State::Rset { msg } => self.next_message(msg + 1),
            State::Quit => self.finish(),
            State::Closing => self.state = State::Done,
            State::Greeting
            | State::Ehlo { .. }
            | State::Helo { .. }
            | State::StartTls
            | State::TlsHandshake
            | State::Auth { .. }
            | State::Mail { .. }
            | State::Rcpt { .. }
            | State::Data { .. }
            | State::Dot { .. }
            | State::Done => self.fail(err),
        }
    }

    /// Split received bytes into lines and replies, acting on each complete reply.
    fn received(&mut self, data: &[u8]) {
        self.rx.push(data);
        while self.reading() {
            let Some(line) = self.rx.next_line() else { return };
            let Some(code) = line.get(..3).and_then(|s| s.parse::<u16>().ok()) else {
                self.io_failed(Error::transport(format!("malformed SMTP reply: {:.80}", line)));
                continue;
            };
            let more = line.as_bytes().get(3) == Some(&b'-');
            self.reply.push(line.get(4..).unwrap_or("").to_string());
            if more {
                if self.reply.len() > 1000 {
                    self.reply.clear();
                    self.io_failed(Error::transport("SMTP reply too long"));
                }
                continue;
            }
            let reply = Reply { code, lines: std::mem::take(&mut self.reply) };
            self.on_reply(&reply);
        }
    }

    /// Whether the state waits for a reply.
    fn reading(&self) -> bool {
        !matches!(self.state, State::TlsHandshake | State::Closing | State::Done)
    }

    fn on_reply(&mut self, r: &Reply) {
        match std::mem::replace(&mut self.state, State::Done) {
            State::Greeting if r.code != 220 => self.fail(smtp_error("greeting", r)),
            State::Greeting => self.hello(false),
            State::Ehlo { after_tls } if r.code == 250 => {
                self.ext = Extensions::from_ehlo(r);
                self.after_hello(after_tls);
            }
            State::Ehlo { after_tls } => {
                let line = format!("HELO {}", self.job.helo);
                self.send(&line, State::Helo { after_tls });
            }
            State::Helo { .. } if r.code != 250 => self.fail(smtp_error("HELO", r)),
            State::Helo { after_tls } => {
                self.ext = Extensions::default();
                self.after_hello(after_tls);
            }
            State::StartTls if r.code != 220 => self.fail(smtp_error("STARTTLS", r)),
            State::StartTls => self.state = State::TlsHandshake,
            State::Auth { mechs, mech, answered, last } => self.auth_reply(r, mechs, mech, answered, last),
            State::Mail { msg } if r.code != 250 => self.rset(msg, smtp_error("MAIL FROM", r)),
            State::Mail { msg } => self.rcpt(msg, 0, Vec::new()),
            State::Rcpt { msg, rcpt, mut refused } => {
                if r.code != 250 && r.code != 251 {
                    refused.push((self.job.messages[msg].recipients[rcpt].clone(), r.code));
                }
                self.rcpt(msg, rcpt + 1, refused);
            }
            State::Data { msg, .. } if r.code != 354 => self.rset(msg, smtp_error("DATA", r)),
            State::Data { msg, refused } => {
                let data = super::mime::dot_stuff(&self.job.messages[msg].data);
                self.out.extend_from_slice(&data);
                self.send(".", State::Dot { msg, refused });
            }
            State::Dot { msg, refused } => {
                if r.code != 250 {
                    self.failures.push(smtp_error("message submission", r));
                } else if !refused.is_empty() {
                    let codes: Vec<String> = refused.iter().map(|(a, code)| format!("{a} ({code})")).collect();
                    self.failures.push(Error::Service(format!("SMTP recipients refused: {}", codes.join(", "))));
                }
                self.next_message(msg + 1);
            }
            State::Rset { msg } => self.next_message(msg + 1),
            State::Quit => self.finish(),
            state @ (State::TlsHandshake | State::Closing | State::Done) => self.state = state,
        }
    }

    fn hello(&mut self, after_tls: bool) {
        let line = format!("EHLO {}", self.job.helo);
        self.send(&line, State::Ehlo { after_tls });
    }

    fn after_hello(&mut self, after_tls: bool) {
        if !after_tls && self.job.security == Security::StartTls {
            if !self.ext.has("STARTTLS") {
                return self.fail(Error::Service("STARTTLS extension not supported by server".into()));
            }
            return self.send("STARTTLS", State::StartTls);
        }
        let has_login = matches!((&self.job.user, &self.job.password), (Some(u), Some(p)) if !u.is_empty() && !p.is_empty());
        if !has_login {
            return self.next_message(0);
        }
        let Some(mechs) = self.ext.params("AUTH") else {
            return self.fail(Error::Service("SMTP AUTH extension not supported by server".into()));
        };
        let mechs = mechs.split_whitespace().map(str::to_ascii_uppercase).collect();
        self.try_mech(mechs, 0, None);
    }

    /// Start the first offered mechanism at or after `MECHS[from]`.
    fn try_mech(&mut self, mechs: Vec<String>, from: usize, last: Option<Error>) {
        let Some(mech) = (from..MECHS.len()).find(|i| mechs.iter().any(|m| m == MECHS[*i])) else {
            let err = last.unwrap_or_else(|| {
                Error::Unsupported(format!("no supported SMTP authentication method (server offers {})", mechs.join(" ")))
            });
            return self.fail(err);
        };
        let (user, password) = self.credentials();
        let line = match MECHS[mech] {
            "CRAM-MD5" => "AUTH CRAM-MD5".to_string(),
            "PLAIN" => format!("AUTH PLAIN {}", crypto::b64(format!("\0{user}\0{password}").as_bytes())),
            _ => format!("AUTH LOGIN {}", crypto::b64(user.as_bytes())),
        };
        self.send(&line, State::Auth { mechs, mech, answered: false, last });
    }

    fn credentials(&self) -> (String, String) {
        let user = self.job.user.clone().unwrap_or_default();
        let password = self.job.password.as_ref().map(|p| p.expose().to_string()).unwrap_or_default();
        (user, password)
    }

    fn auth_reply(&mut self, r: &Reply, mechs: Vec<String>, mech: usize, answered: bool, last: Option<Error>) {
        if !answered && r.code == 334 && MECHS[mech] != "PLAIN" {
            let (user, password) = self.credentials();
            let answer = if MECHS[mech] == "CRAM-MD5" {
                match cram_md5_response(&r.text(), &user, &password) {
                    Ok(a) => a,
                    Err(e) => return self.fail(e),
                }
            } else {
                crypto::b64(password.as_bytes())
            };
            return self.send(&answer, State::Auth { mechs, mech, answered: true, last });
        }
        if r.code == 235 || r.code == 503 {
            return self.next_message(0);
        }
        self.try_mech(mechs, mech + 1, Some(smtp_error("authentication", r)));
    }

    fn next_message(&mut self, msg: usize) {
        let Some(m) = self.job.messages.get(msg) else {
            self.quit_sent = true;
            return self.send("QUIT", State::Quit);
        };
        let mut mail = format!("MAIL FROM:<{}>", m.from);
        if self.ext.has("SIZE") {
            mail.push_str(&format!(" SIZE={}", m.data.len()));
        }
        self.send(&mail, State::Mail { msg });
    }

    fn rcpt(&mut self, msg: usize, rcpt: usize, refused: Vec<(String, u16)>) {
        let m = &self.job.messages[msg];
        if let Some(to) = m.recipients.get(rcpt) {
            let line = format!("RCPT TO:<{to}>");
            return self.send(&line, State::Rcpt { msg, rcpt, refused });
        }
        if refused.len() == m.recipients.len() {
            let n = refused.len();
            return self.rset(msg, Error::Service(format!("SMTP server refused all {n} recipient(s)")));
        }
        self.send("DATA", State::Data { msg, refused });
    }

    /// A per-message failure: record it and reset the transaction.
    fn rset(&mut self, msg: usize, err: Error) {
        self.failures.push(err);
        self.send("RSET", State::Rset { msg });
    }

    /// QUIT is answered: report the per-message failures.
    fn finish(&mut self) {
        let total = self.job.messages.len();
        let res = match self.failures.len() {
            0 => Ok(()),
            1 => Err(self.failures.remove(0)),
            n => Err(Error::Service(format!("{n} of {total} messages failed; first: {}", self.failures[0]))),
        };
        self.result = Some(res);
        self.state = State::Done;
    }
}

impl Protocol for Smtp {
    fn next(&mut self) -> Output {
        if !self.out.is_empty() {
            return Output::Write(std::mem::take(&mut self.out));
        }
        match self.state {
            State::TlsHandshake => Output::StartTls,
            State::Closing | State::Done => {
                self.state = State::Done;
                Output::Done(self.result.take().unwrap_or(Ok(())))
            }
            State::Greeting
            | State::Ehlo { .. }
            | State::Helo { .. }
            | State::StartTls
            | State::Auth { .. }
            | State::Mail { .. }
            | State::Rcpt { .. }
            | State::Data { .. }
            | State::Dot { .. }
            | State::Rset { .. }
            | State::Quit => Output::Read,
        }
    }

    fn input(&mut self, input: Input<'_>) {
        match input {
            Input::Data([]) => self.io_failed(Error::unconfirmed("connection closed")),
            Input::Data(data) => self.received(data),
            Input::ReadError(e) | Input::WriteError(e) => self.io_failed(Error::unconfirmed(e)),
            Input::ChannelBinding(_) => {}
            Input::Tls(Ok(())) => {
                // Plaintext buffered before the upgrade is discarded (it must be empty per RFC 3207).
                self.rx.clear();
                self.hello(true);
            }
            Input::Tls(Err(e)) => self.fail(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_md5_rfc2202() {
        assert_eq!(crypto::hex(&hmac_md5(&[0x0b; 16], b"Hi There")), "9294727a3638bb1c13f48ef8158bfc9d");
        assert_eq!(crypto::hex(&hmac_md5(b"Jefe", b"what do ya want for nothing?")), "750c783e6ab0b503eaa86e310a5db738");
        assert_eq!(
            crypto::hex(&hmac_md5(&[0xaa; 80], b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"
        );
    }

    /// Plays the server: feeds `reply` for every command the session writes, collects the commands.
    fn converse(mut m: impl Protocol, reply: impl Fn(&str) -> &'static str) -> (Vec<String>, Result<()>) {
        let mut sent = Vec::new();
        let mut pending = String::from("220 hi\r\n");
        loop {
            match m.next() {
                Output::Write(data) => {
                    for line in String::from_utf8(data).unwrap().split_inclusive("\r\n") {
                        let line = line.trim_end().to_string();
                        if !line.is_empty() {
                            pending.push_str(reply(&line));
                            sent.push(line);
                        }
                    }
                }
                Output::Read => m.input(Input::Data(std::mem::take(&mut pending).as_bytes())),
                Output::StartTls => m.input(Input::Tls(Ok(()))),
                Output::ChannelBinding(_) => m.input(Input::ChannelBinding(None)),
                Output::Sleep(_) => {}
                Output::Done(r) => return (sent, r),
            }
        }
    }

    #[test]
    fn session_is_driven_by_bytes_alone() {
        let job = Job {
            security: Security::StartTls,
            helo: "me".into(),
            user: Some("u".into()),
            password: Some(Secret::new("p")),
            messages: vec![Envelope { from: "a@x".into(), recipients: vec!["b@x".into()], data: "Subject: s\r\n\r\nhi\r\n".into() }],
        };
        let (sent, res) = converse(session(job, false), |line| match line.split(' ').next().unwrap() {
            "EHLO" => "250-x\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n",
            "STARTTLS" => "220 go\r\n",
            "AUTH" => "235 ok\r\n",
            "DATA" => "354 go\r\n",
            "QUIT" => "221 bye\r\n",
            "Subject:" | "hi" => "",
            _ => "250 ok\r\n",
        });
        res.unwrap();
        let verbs: Vec<&str> = sent.iter().map(|l| l.split([' ', ':']).next().unwrap()).collect();
        assert_eq!(verbs, ["EHLO", "STARTTLS", "EHLO", "AUTH", "MAIL", "RCPT", "DATA", "Subject", "hi", ".", "QUIT"]);
    }

    #[test]
    fn cram_md5_rfc2195() {
        let challenge = crypto::b64(b"<1896.697170952@postoffice.reston.mci.net>");
        let answer = cram_md5_response(&challenge, "tim", "tanstaaftanstaaf").unwrap();
        assert_eq!(answer, "dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw");
        assert!(cram_md5_response(&challenge, "tim", "pässword").is_err());
    }
}
