//! IRC (`irc://`, `ircs://`): messages to IRC channels and users.
//!
//! One connection per notification: optional `PASS`, `NICK` + `USER`, wait for the `001` welcome (answering `PING`s, retrying taken nicknames up to 3 times), optional ZNC liveness `PING`, then per channel `JOIN` (waiting for the server's confirmation) and one `PRIVMSG` per non-blank body line, `PRIVMSG` to each user, `QUIT`.
//!
//! Auth modes (`?mode=`): `server` (default, `PASS`), `nickserv` (`PRIVMSG NickServ :IDENTIFY` after registration), `znc` (`PASS user:password`), `none`. Known networks (Libera.Chat, SynIRC, EFnet) get TLS / port / mode defaults when no port is given.
//!
//! # Differences with Apprise
//!
//! - NickServ identification is sent (Apprise clears the password first, so its `nickserv` mode never identifies). *intentional*
//! - After the welcome mercurio continues at once instead of draining the MOTD for a quiet period. *intentional*
//! - A missing JOIN confirmation is waited for up to the read timeout (30 s) and then ignored, like Apprise after its 6 s join timeout. *intentional*

mod protocol;

use std::sync::Arc;
use std::time::Duration;

use self::protocol::{IrcMessage, join_error, normalise_channel, parse_line, register_error};
use crate::env::Env;
use crate::error::Error;
use crate::machine::{Input, LineBuf, Output, Protocol};
use crate::parse::{parse_list, parse_list_unquoted};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::transport::Endpoint;
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "irc",
    name: "IRC",
    schemes: &["irc", "ircs"],
    service_url: "https://ircv3.net/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 380, body_max_line_count: 0 },
    throttle: Duration::from_millis(20),
    templates: &[
        "{schema}://{host}/{targets}",
        "{schema}://{host}:{port}/{targets}",
        "{schema}://{user}@{host}/{targets}",
        "{schema}://{user}@{host}:{port}/{targets}",
        "{schema}://{user}:{password}@{host}/{targets}",
        "{schema}://{user}:{password}@{host}:{port}/{targets}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("password", "Password").secret(),
        Param::new("port", "Port").port(),
        Param::new("target_channel", "Target Channel").prefix("#"),
        Param::new("target_user", "Target User").prefix("@"),
        Param::new("targets", "Targets").list("/").required().group(&["target_channel", "target_user"]),
        Param::new("user", "User"),
    ],
    params: &[
        Param::new("join", "Join Channels").bool(true),
        Param::new("mode", "Auth Mode").choice(&["znc", "server", "nickserv", "none"]).default("server").inferred(),
        Param::new("name", "Real Name"),
        Param::new("nick", "Nickname"),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const INSECURE_PORT: u16 = 6667;
const SECURE_PORT: u16 = 6697;
const NICK_MAX_LENGTH: usize = 9;
const NICK_COLLISION_MAX: u32 = 3;
const REGISTER_TIMEOUT: Duration = Duration::from_secs(30);

/// Authentication mode, in prefix-lookup order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthMode {
    Znc,
    Server,
    NickServ,
    None,
}

const AUTH_MODES: &[(&str, AuthMode)] =
    &[("znc", AuthMode::Znc), ("server", AuthMode::Server), ("nickserv", AuthMode::NickServ), ("none", AuthMode::None)];

/// Known networks: host suffix -> (secure, port, mode).
const TEMPLATES: &[(&str, bool, u16, AuthMode)] = &[
    (".synirc.net", true, 6697, AuthMode::NickServ),
    (".libera.chat", true, 6697, AuthMode::NickServ),
    (".efnet.org", false, 6667, AuthMode::Server),
];

#[derive(Debug)]
struct Irc {
    host: String,
    port: u16,
    secure: bool,
    user: Option<String>,
    password: Option<Secret>,
    nickname: String,
    fullname: Option<String>,
    mode: AuthMode,
    join: bool,
    /// Channel (without `#`) -> optional key, in target order.
    channels: Vec<(String, Option<String>)>,
    users: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = Vec::new();
    if u.param_nonempty("host").is_some() {
        targets.push(u.host());
    }
    targets.extend(u.path_segments());
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list_unquoted([unquote(to)]));
    }
    let join = SERVICE.flag(u, "join");
    let name = SERVICE.text(u, "name");
    let nick = SERVICE.text(u, "nick");
    let user = u.user();
    let nickname = nick.as_deref().unwrap_or("").trim().to_string();
    let nickname = if nickname.is_empty() { user.as_deref().unwrap_or("").trim().to_string() } else { nickname };

    let host = u.host();
    let mut secure = u.secure;
    let mut port = u.port.filter(|p| *p != 0);
    let mut mode = AuthMode::Server;
    if port.is_none() {
        let lower = host.to_lowercase();
        if let Some((_, s, p, m)) =
            TEMPLATES.iter().find(|(suffix, ..)| lower.ends_with(suffix) && lower.len() > suffix.len())
        {
            secure = *s;
            port = Some(*p);
            mode = *m;
        }
    }
    if let Some(m) = SERVICE.text(u, "mode") {
        let m = m.trim().to_lowercase();
        if !m.is_empty() {
            mode = AUTH_MODES
                .iter()
                .find(|(name, _)| name.starts_with(&m))
                .map(|(_, v)| *v)
                .ok_or_else(|| SERVICE.err(format!("The IRC auth mode specified ({m}) is invalid.")))?;
        }
    }

    let channel_re = crate::regex!(r"^\s*(?:#|%23)(?P<channel>[^ \t\r\n@#:]+)(?::(?P<key>[^ \t\r\n]+))?\s*$");
    let user_re = crate::regex!(r"^\s*(?:@|%40)?(?P<user>[^ \t\r\n@#]+)\n?$");
    let mut channels: Vec<(String, Option<String>)> = Vec::new();
    let mut users = Vec::new();
    for target in parse_list(&targets) {
        if let Some(c) = channel_re.captures(&target) {
            let chan = c["channel"].to_string();
            let key = c.name("key").map(|k| k.as_str().to_string());
            match channels.iter_mut().find(|(n, _)| *n == chan) {
                Some(entry) => entry.1 = key,
                None => channels.push((chan, key)),
            }
            continue;
        }
        if let Some(c) = user_re.captures(&target) {
            users.push(c["user"].to_string());
            continue;
        }
        log::warn!("Dropped invalid IRC target ({target}).");
    }

    Ok(Box::new(Irc {
        port: port.unwrap_or(if secure { SECURE_PORT } else { INSECURE_PORT }),
        host,
        secure,
        user,
        password: u.password().map(Secret::new),
        nickname,
        fullname: name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty()),
        mode,
        join,
        channels,
        users,
    }))
}

/// Random nickname from `prefix`; after a collision the last character is the collision count.
fn nick_generation(prefix: &str, length: usize, collision: u32, env: &dyn Env) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
    let base: String = prefix.chars().take(length.saturating_sub(3)).collect::<String>().trim().to_lowercase();
    let mut raw = vec![0u8; length.max(1)];
    env.fill_random(&mut raw);
    let suffix: String = raw.iter().map(|b| CHARSET[*b as usize % CHARSET.len()] as char).collect();
    let mut nick = format!("{base}{suffix}");
    if collision > 0 {
        nick = format!("{}{}", nick.chars().take(length.saturating_sub(1)).collect::<String>(), collision % 10);
    }
    nick.chars().take(length).collect()
}

struct Session {
    pass: Option<String>,
    nickname: String,
    fullname: String,
    prefix: String,
    identify: Option<String>,
    znc: bool,
    joins: Vec<(String, Option<String>, bool)>,
    users: Vec<String>,
    lines: Vec<String>,
    quit: String,
}

/// Where a session is; every state but [`State::Quitting`] and [`State::Done`] reads.
#[derive(Debug)]
enum State {
    /// Waiting for the `001` welcome.
    Register,
    /// Waiting for the `PONG` of the ZNC liveness `PING`.
    ZncCheck,
    /// Waiting for the server to confirm the JOIN of `joins[idx]`.
    Join { idx: usize },
    /// `QUIT` is queued; the session ends once it is sent.
    Quitting,
    Done,
}

/// An IRC session as a sans-IO state machine.
struct Client {
    s: Session,
    state: State,
    rx: LineBuf,
    out: Vec<u8>,
    collisions: u32,
    env: Arc<dyn Env>,
    result: Option<Result<()>>,
}

impl Client {
    fn new(s: Session, env: Arc<dyn Env>) -> Self {
        let mut c =
            Client { s, state: State::Register, rx: LineBuf::default(), out: Vec::new(), collisions: 0, env, result: None };
        if let Some(p) = c.s.pass.clone() {
            c.send(&format!("PASS {p}"));
        }
        let nick = c.s.nickname.clone();
        c.send(&format!("NICK {nick}"));
        let user = format!("USER {nick} 0 * :{}", c.s.fullname);
        c.send(&user);
        c
    }

    fn send(&mut self, line: &str) {
        self.out.extend_from_slice(line.as_bytes());
        self.out.extend_from_slice(b"\r\n");
    }

    fn fail(&mut self, err: Error) {
        self.result.get_or_insert(Err(err));
        self.state = State::Done;
    }

    /// PING and nickname-collision handling shared by every wait. Returns `Ok(true)` when the message was consumed.
    fn common(&mut self, msg: &IrcMessage) -> Result<bool> {
        if msg.is("PING") {
            let payload = msg.ping_payload().to_string();
            self.send(&format!("PONG :{payload}"));
            return Ok(true);
        }
        if matches!(msg.numeric(), Some(432 | 433)) {
            if self.collisions >= NICK_COLLISION_MAX {
                return Err(Error::Service("IRC nickname is already in use".into()));
            }
            self.collisions += 1;
            let nick = nick_generation(&self.s.prefix, NICK_MAX_LENGTH, self.collisions, self.env.as_ref());
            self.send(&format!("NICK {nick}"));
            return Ok(true);
        }
        Ok(false)
    }

    fn on_line(&mut self, msg: &IrcMessage) {
        match self.state {
            State::Register => match self.common(msg) {
                Err(e) => self.fail(e),
                Ok(true) => {}
                Ok(false) => match msg.numeric() {
                    Some(n) if register_error(n).is_some() => {
                        let reason = register_error(n).unwrap_or_default();
                        self.fail(Error::Service(format!("{reason}: {}", msg.error_text())));
                    }
                    Some(1) => self.registered(),
                    _ => {}
                },
            },
            State::ZncCheck => {
                if msg.is("PONG") {
                    self.next_target(0);
                }
            }
            State::Join { idx } => match self.common(msg) {
                Err(e) => self.fail(e),
                Ok(true) => {}
                Ok(false) => {
                    let n = msg.numeric();
                    if let Some(reason) = n.and_then(join_error) {
                        return self.fail(Error::Service(format!("{reason}: {}", msg.error_text())));
                    }
                    let chan = self.s.joins[idx].0.as_str();
                    let confirmed = match n {
                        Some(443 | 366) => msg.params.get(1).map(String::as_str) == Some(chan),
                        _ if msg.is("JOIN") => {
                            msg.trailing.as_deref().or(msg.params.first().map(String::as_str)) == Some(chan)
                        }
                        _ => false,
                    };
                    if confirmed {
                        self.joined(idx);
                    }
                }
            },
            State::Quitting | State::Done => {}
        }
    }

    /// The server went quiet or closed the stream while the session waited.
    fn on_quiet(&mut self) {
        match self.state {
            State::Register => self.fail(Error::transport("IRC registration timeout")),
            State::ZncCheck => self.fail(Error::Service("ZNC connection check failed".into())),
            State::Join { idx } => {
                log::debug!("IRC join confirmation not observed for {}", self.s.joins[idx].0);
                self.joined(idx);
            }
            State::Quitting | State::Done => {}
        }
    }

    fn registered(&mut self) {
        if let Some(pw) = self.s.identify.clone() {
            self.send(&format!("PRIVMSG NickServ :IDENTIFY {pw}"));
        }
        if self.s.znc {
            self.send("PING :mercurio");
            self.state = State::ZncCheck;
        } else {
            self.next_target(0);
        }
    }

    fn privmsg(&mut self, target: &str) {
        for i in 0..self.s.lines.len() {
            let line = format!("PRIVMSG {target} :{}", self.s.lines[i]);
            self.send(&line);
        }
    }

    /// `joins[idx]` is joined (or its confirmation never came): message it, then go on.
    fn joined(&mut self, idx: usize) {
        let chan = self.s.joins[idx].0.clone();
        self.privmsg(&chan);
        self.next_target(idx + 1);
    }

    /// Message the channels from `joins[idx]` on (stopping at the next one to JOIN), then the users, then QUIT.
    fn next_target(&mut self, idx: usize) {
        for i in idx..self.s.joins.len() {
            let (chan, key, join) = self.s.joins[i].clone();
            if join {
                match key {
                    Some(k) => self.send(&format!("JOIN {chan} {k}")),
                    None => self.send(&format!("JOIN {chan}")),
                }
                self.state = State::Join { idx: i };
                return;
            }
            self.privmsg(&chan);
        }
        for user in self.s.users.clone() {
            self.privmsg(user.trim_start_matches('@'));
        }
        let quit = format!("QUIT :{}", self.s.quit);
        self.send(&quit);
        self.state = State::Quitting;
    }

    fn reading(&self) -> bool {
        matches!(self.state, State::Register | State::ZncCheck | State::Join { .. })
    }
}

impl Protocol for Client {
    fn next(&mut self) -> Output {
        if !self.out.is_empty() {
            return Output::Write(std::mem::take(&mut self.out));
        }
        match self.state {
            State::Quitting | State::Done => {
                self.state = State::Done;
                Output::Done(self.result.take().unwrap_or(Ok(())))
            }
            State::Register | State::ZncCheck | State::Join { .. } => Output::Read,
        }
    }

    fn input(&mut self, input: Input<'_>) {
        match input {
            Input::Data([]) | Input::ReadError(_) => self.on_quiet(),
            Input::Data(data) => {
                self.rx.push(data);
                while self.reading() {
                    let Some(line) = self.rx.next_line() else { break };
                    self.on_line(&parse_line(&line));
                }
            }
            Input::WriteError(e) => self.fail(Error::unconfirmed(e)),
            Input::Tls(r) => {
                if let Err(e) = r {
                    self.fail(e);
                }
            }
        }
    }
}

impl Notify for Irc {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.channels.is_empty() && self.users.is_empty() {
            return Plan::Fail(Error::Message("no IRC targets specified".into()));
        }
        let nickname = if self.nickname.is_empty() {
            nick_generation(ctx.app_id(), NICK_MAX_LENGTH, 0, ctx.env().as_ref())
        } else {
            self.nickname.clone()
        };
        let password = self.password.as_ref().map(|p| p.expose().to_string());
        let pass = match self.mode {
            AuthMode::Server => password.clone().filter(|p| !p.is_empty()),
            AuthMode::Znc => Some(format!(
                "{}:{}",
                self.user.as_deref().unwrap_or_default(),
                password.as_deref().unwrap_or_default()
            )),
            AuthMode::NickServ | AuthMode::None => None,
        };
        let identify = if self.mode == AuthMode::NickServ { password.filter(|p| !p.is_empty()) } else { None };
        let message = if msg.title.is_empty() {
            msg.body.to_string()
        } else {
            format!("{} {}", msg.title, msg.body).trim().to_string()
        };
        let lines: Vec<String> =
            message.split(['\r', '\n']).filter(|l| !l.trim().is_empty()).map(str::to_string).collect();
        let session = Session {
            pass,
            nickname,
            fullname: self.fullname.clone().unwrap_or_else(|| ctx.app_desc().to_string()),
            prefix: ctx.app_id().to_string(),
            identify,
            znc: self.mode == AuthMode::Znc,
            joins: self
                .channels
                .iter()
                .map(|(c, k)| (normalise_channel(c), k.clone(), self.join || k.is_some()))
                .collect(),
            users: self.users.clone(),
            lines,
            quit: ctx.app_desc().to_string(),
        };
        let mut ep = Endpoint::new(self.host.clone(), self.port, self.secure);
        ep.read_timeout = REGISTER_TIMEOUT;
        Plan::socket(ep, move |conn, transport| Box::pin(crate::machine::drive(Client::new(session, transport.env()), conn)))
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    /// The PING buffered behind the welcome is answered while waiting for the JOIN, as before: registration ends at `001`.
    #[test]
    fn session_is_driven_by_bytes_alone() {
        let s = Session {
            pass: None,
            nickname: "me".into(),
            fullname: "Me".into(),
            prefix: "m".into(),
            identify: None,
            znc: false,
            joins: vec![("#c".into(), None, true)],
            users: vec!["@bob".into()],
            lines: vec!["hi".into()],
            quit: "bye".into(),
        };
        let mut c = Client::new(s, Arc::new(crate::testing::FixedEnv::new(0)));
        let mut sent = String::new();
        let mut replies = [":s 001 me :Welcome\r\nPING :x\r\n", ":me JOIN :#c\r\n"].into_iter();
        let res = loop {
            match c.next() {
                Output::Write(data) => sent.push_str(&String::from_utf8(data).unwrap()),
                Output::Read => c.input(Input::Data(replies.next().unwrap_or("").as_bytes())),
                Output::StartTls => c.input(Input::Tls(Ok(()))),
                Output::Done(r) => break r,
            }
        };
        res.unwrap();
        assert_eq!(
            sent,
            "NICK me\r\nUSER me 0 * :Me\r\nJOIN #c\r\nPONG :x\r\nPRIVMSG #c :hi\r\nPRIVMSG bob :hi\r\nQUIT :bye\r\n"
        );
    }

    #[test]
    fn generated_nicks() {
        let n = nick_generation("Mercurio", 9, 0, crate::testing::test_env());
        assert_eq!(n.len(), 9);
        assert!(n.starts_with("mercur"));
        let c = nick_generation("Mercurio", 9, 2, crate::testing::test_env());
        assert_eq!(c.len(), 9);
        assert!(c.ends_with('2'));
    }
}
