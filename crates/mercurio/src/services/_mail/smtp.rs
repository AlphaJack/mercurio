//! A small blocking SMTP client (RFC 5321) for [`crate::Plan::socket`]: EHLO/HELO, STARTTLS (RFC 3207), AUTH CRAM-MD5 (RFC 2195) / PLAIN / LOGIN (RFC 4954), MAIL/RCPT/DATA with dot-stuffing, QUIT.

use md5::{Digest, Md5};

use crate::crypto;
use crate::error::{Error, Result};
use crate::net::LineConn;
use crate::service::Secret;
use crate::transport::Conn;

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

struct Reply {
    code: u16,
    lines: Vec<String>,
}

impl Reply {
    fn text(&self) -> String {
        self.lines.join(" ")
    }
}

fn read_reply(c: &mut LineConn<'_>) -> Result<Reply> {
    let mut lines = Vec::new();
    loop {
        let line = c.read_line()?;
        let code = line.get(..3).and_then(|s| s.parse::<u16>().ok());
        let Some(code) = code else {
            return Err(Error::transport(format!("malformed SMTP reply: {:.80}", line)));
        };
        let more = line.as_bytes().get(3) == Some(&b'-');
        lines.push(line.get(4..).unwrap_or("").to_string());
        if !more {
            return Ok(Reply { code, lines });
        }
        if lines.len() > 1000 {
            return Err(Error::transport("SMTP reply too long"));
        }
    }
}

fn command(c: &mut LineConn<'_>, line: &str) -> Result<Reply> {
    c.write_line(line)?;
    read_reply(c)
}

fn smtp_error(what: &str, r: &Reply) -> Error {
    Error::Service(format!("SMTP {what} failed: {} {}", r.code, crate::util::truncate_chars(&r.text(), 200)))
}

/// Advertised EHLO extensions (upper-cased keyword -> parameters).
#[derive(Default)]
struct Extensions(Vec<(String, String)>);

impl Extensions {
    fn has(&self, key: &str) -> bool {
        self.0.iter().any(|(k, _)| k == key)
    }
    fn params(&self, key: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
}

fn hello(c: &mut LineConn<'_>, name: &str) -> Result<Extensions> {
    let r = command(c, &format!("EHLO {name}"))?;
    if r.code == 250 {
        let mut ext = Extensions::default();
        for line in r.lines.iter().skip(1) {
            // "AUTH=PLAIN LOGIN" is an old form of "AUTH PLAIN LOGIN".
            let (k, v) = match line.split_once([' ', '=']) {
                Some((k, v)) => (k, v),
                None => (line.as_str(), ""),
            };
            ext.0.push((k.to_ascii_uppercase(), v.trim().to_string()));
        }
        return Ok(ext);
    }
    let r = command(c, &format!("HELO {name}"))?;
    if r.code != 250 {
        return Err(smtp_error("HELO", &r));
    }
    Ok(Extensions::default())
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

/// smtplib's `login()`: CRAM-MD5, PLAIN, then LOGIN, as far as the server offers them.
fn login(c: &mut LineConn<'_>, ext: &Extensions, user: &str, password: &str) -> Result<()> {
    let Some(mechs) = ext.params("AUTH") else {
        return Err(Error::Service("SMTP AUTH extension not supported by server".into()));
    };
    let mechs: Vec<String> = mechs.split_whitespace().map(str::to_ascii_uppercase).collect();
    let mut last: Option<Error> = None;
    for mech in ["CRAM-MD5", "PLAIN", "LOGIN"] {
        if !mechs.iter().any(|m| m == mech) {
            continue;
        }
        let r = match mech {
            "CRAM-MD5" => {
                let r = command(c, "AUTH CRAM-MD5")?;
                if r.code == 334 { command(c, &cram_md5_response(&r.text(), user, password)?)? } else { r }
            }
            "PLAIN" => command(c, &format!("AUTH PLAIN {}", crypto::b64(format!("\0{user}\0{password}").as_bytes())))?,
            _ => {
                let r = command(c, &format!("AUTH LOGIN {}", crypto::b64(user.as_bytes())))?;
                if r.code == 334 { command(c, &crypto::b64(password.as_bytes()))? } else { r }
            }
        };
        if r.code == 235 || r.code == 503 {
            return Ok(());
        }
        last = Some(smtp_error("authentication", &r));
    }
    Err(last.unwrap_or_else(|| {
        Error::Unsupported(format!("no supported SMTP authentication method (server offers {})", mechs.join(" ")))
    }))
}

/// Submit one message; `Ok(Err(..))` is a per-message failure (session still usable).
fn send_one(c: &mut LineConn<'_>, ext: &Extensions, msg: &Envelope) -> Result<std::result::Result<(), Error>> {
    let mut mail = format!("MAIL FROM:<{}>", msg.from);
    if ext.has("SIZE") {
        mail.push_str(&format!(" SIZE={}", msg.data.len()));
    }
    let r = command(c, &mail)?;
    if r.code != 250 {
        command(c, "RSET").ok();
        return Ok(Err(smtp_error("MAIL FROM", &r)));
    }
    let mut refused = Vec::new();
    for rcpt in &msg.recipients {
        let r = command(c, &format!("RCPT TO:<{rcpt}>"))?;
        if r.code != 250 && r.code != 251 {
            refused.push((rcpt.clone(), r.code));
        }
    }
    if refused.len() == msg.recipients.len() {
        command(c, "RSET").ok();
        return Ok(Err(Error::Service(format!("SMTP server refused all {} recipient(s)", refused.len()))));
    }
    let r = command(c, "DATA")?;
    if r.code != 354 {
        command(c, "RSET").ok();
        return Ok(Err(smtp_error("DATA", &r)));
    }
    c.write_all(&super::mime::dot_stuff(&msg.data))?;
    let r = command(c, ".")?;
    if r.code != 250 {
        return Ok(Err(smtp_error("message submission", &r)));
    }
    if !refused.is_empty() {
        let codes: Vec<String> = refused.iter().map(|(a, code)| format!("{a} ({code})")).collect();
        return Ok(Err(Error::Service(format!("SMTP recipients refused: {}", codes.join(", ")))));
    }
    Ok(Ok(()))
}

fn run(c: &mut LineConn<'_>, job: &Job, quit_sent: &mut bool) -> Result<()> {
    let greeting = read_reply(c)?;
    if greeting.code != 220 {
        return Err(smtp_error("greeting", &greeting));
    }
    let mut ext = hello(c, &job.helo)?;
    if job.security == Security::StartTls {
        if !ext.has("STARTTLS") {
            return Err(Error::Service("STARTTLS extension not supported by server".into()));
        }
        let r = command(c, "STARTTLS")?;
        if r.code != 220 {
            return Err(smtp_error("STARTTLS", &r));
        }
        c.start_tls()?;
        ext = hello(c, &job.helo)?;
    }
    if let (Some(user), Some(pw)) = (&job.user, &job.password)
        && !user.is_empty()
        && !pw.is_empty()
    {
        login(c, &ext, user, pw.expose())?;
    }
    let mut failures = Vec::new();
    for msg in &job.messages {
        if let Err(e) = send_one(c, &ext, msg)? {
            failures.push(e);
        }
    }
    *quit_sent = true;
    command(c, "QUIT").ok();
    match failures.len() {
        0 => Ok(()),
        1 => Err(failures.remove(0)),
        n => Err(Error::Service(format!("{n} of {} messages failed; first: {}", job.messages.len(), failures[0]))),
    }
}

/// Run a whole SMTP session on `conn`.
pub fn session(conn: &mut dyn Conn, job: &Job) -> Result<()> {
    let mut c = LineConn::new(conn);
    let mut quit_sent = false;
    let res = run(&mut c, job, &mut quit_sent);
    if res.is_err() && !quit_sent {
        // Best effort, like smtplib's quit() after a failed STARTTLS/login.
        c.write_line("QUIT").ok();
    }
    res
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

    #[test]
    fn cram_md5_rfc2195() {
        let challenge = crypto::b64(b"<1896.697170952@postoffice.reston.mci.net>");
        let answer = cram_md5_response(&challenge, "tim", "tanstaaftanstaaf").unwrap();
        assert_eq!(answer, "dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw");
        assert!(cram_md5_response(&challenge, "tim", "pässword").is_err());
    }
}
