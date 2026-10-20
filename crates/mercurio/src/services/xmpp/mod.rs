//! XMPP (`xmpp://`, `xmpps://`): chat and group-chat messages through a built-in XMPP client.
//!
//! `xmpp[s]://user:password@host[:port]/target1/#room@conference.host?...`
//!
//! Mercurio speaks XMPP itself over a [`Plan::socket`] session: stream negotiation, STARTTLS (`?mode=starttls`, the `xmpps://` default) or direct TLS (`?mode=tls`, port 5223), SASL SCRAM-SHA-512/256/1 or PLAIN, resource binding, session establishment, initial presence, optional roster fetch (`?roster=yes`), XEP-0045 room join for `#room` targets, then one `<message type="chat|groupchat">` per target (the account itself when there are none) and a clean stream close.
//!
//! # Differences with Apprise
//!
//! - SCRAM `-PLUS` channel binding is not implemented; `?scramplus=` has no effect. *todo*
//! - `?keepalive=yes` is accepted, but every notification opens its own connection. *intentional*
//! - `?mode=none`: slixmpp refuses every password mechanism on an unencrypted stream and Apprise then reports success without sending -> mercurio authenticates with SCRAM, refuses PLAIN and fails when nothing usable is offered. *intentional*
//! - A server without STARTTLS under `?mode=starttls` is a failure (slixmpp reports silent success). *intentional*

mod client;
mod sasl;
mod xml;

use crate::parse::{parse_bool, parse_list, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::transport::Endpoint;
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};
use client::{Mode, Session};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "xmpp",
    name: "XMPP",
    schemes: &["xmpp", "xmpps"],
    service_url: "https://xmpp.org/",
    parse,
    templates: &[
        "{schema}://{user}:{password}@{host}",
        "{schema}://{user}:{password}@{host}:{port}",
        "{schema}://{user}:{password}@{host}/{targets}",
        "{schema}://{user}:{password}@{host}:{port}/{targets}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("password", "Password").required().secret(),
        Param::new("port", "Port").port(),
        Param::new("target_channels", "Target Channel").prefix("#"),
        Param::new("target_user", "Target User"),
        Param::new("targets", "Targets").list("/").group(&["target_channels", "target_user"]),
        Param::new("user", "User").required(),
    ],
    params: &[
        Param::new("mode", "Secure Mode").choice(&["starttls", "tls", "none"]).default("starttls").inferred(),
        Param::new("name", "MUC Nickname"),
        Param::new("roster", "Get Roster").bool(false),
        Param::new("subject", "Use Subject").bool(false),
        Param::sets("to", &["targets"]),
        Param::new("xmpp", "XMPP Server"),
    ],
    ..ServiceDef::DEFAULTS
};

/// `?mode=` values, in prefix-matching order.
const MODES: &[(&str, Mode)] = &[("starttls", Mode::StartTls), ("tls", Mode::Tls), ("none", Mode::None)];

#[derive(Debug)]
struct Xmpp {
    jid: String,
    password: Secret,
    /// Where to connect (`?xmpp=` or the URL host).
    host: String,
    port: u16,
    mode: Mode,
    verify: bool,
    targets: Vec<(String, String)>,
    roster: bool,
    subject: bool,
    /// MUC nickname; `None` means the app id.
    nick: Option<String>,
}

/// `IS_JID` + `normalize_jid`: `(jid, is_muc)`.
fn normalize_jid(value: &str, default_host: &str) -> Option<(String, bool)> {
    let re = crate::regex!(
        r"^\s*(?P<is_room>#|%23)?(?P<local>[^@\s/]+)((@|%40)(?P<domain>[^@\s/]+))?(?:(/|%2F)(?P<resource>[^%/\s]+)((/|%2F).*)?)?\s*$"
    );
    let c = re.captures(value.trim())?;
    let is_muc = c.name("is_room").is_some();
    let host = c.name("domain").map(|m| m.as_str()).unwrap_or(default_host);
    let mut jid = format!("{}@{host}", &c["local"]);
    if let Some(r) = c.name("resource") {
        jid.push('/');
        jid.push_str(r.as_str());
    }
    Some((jid, is_muc))
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let host = u.host();
    let user = u.user().unwrap_or_default();
    let (jid, _) = normalize_jid(&user, &host).ok_or_else(|| SERVICE.err("an invalid XMPP JID was specified"))?;

    let mut raw: Vec<String> = u.path_segments().iter().map(|t| unquote(t)).collect();
    if let Some(to) = u.param_nonempty("to") {
        raw.extend(parse_list([unquote(to)]));
    }
    let mut targets = Vec::new();
    for t in parse_list(&raw) {
        match normalize_jid(&t, &host) {
            Some((jid, muc)) => targets.push((if muc { "groupchat" } else { "chat" }.to_string(), jid)),
            None => log::warn!("dropped invalid XMPP target"),
        }
    }

    let mode = match SERVICE.raw(u, "mode").map(|m| m.trim().to_lowercase()).filter(|m| !m.is_empty()) {
        Some(m) => MODES
            .iter()
            .find(|(k, _)| k.starts_with(m.as_str()))
            .map(|(_, v)| *v)
            .ok_or_else(|| SERVICE.err("the XMPP secure mode specified is invalid"))?,
        None => Mode::None,
    };
    // `xmpps://` with no (or `none`) mode means STARTTLS; any TLS mode on `xmpp://` wins over the scheme.
    let mode = if u.secure && mode == Mode::None { Mode::StartTls } else { mode };

    let flag = |key: &str| u.param_nonempty(key).map(|v| parse_bool(v, false)).unwrap_or(false);
    let nick = u
        .param_nonempty("name")
        .map(unquote)
        .and_then(|n| validate_regex(&n, r"^[a-zA-Z0-9_]+$", "i", true))
        .or_else(|| Some(user.clone()).filter(|s| !s.is_empty()));

    let xmpp_host = u.param_nonempty("xmpp").map(|v| unquote(v).trim().to_string()).filter(|v| !v.is_empty());
    let default_port = if mode == Mode::Tls { 5223 } else { 5222 };
    Ok(Box::new(Xmpp {
        jid,
        password: Secret::new(u.password().unwrap_or_default()),
        host: xmpp_host.unwrap_or(host),
        port: u.port.filter(|p| *p != 0).unwrap_or(default_port),
        mode,
        verify: u.verify,
        targets,
        roster: flag("roster"),
        subject: flag("subject"),
        nick,
    }))
}

impl Notify for Xmpp {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let session = Session {
            mode: self.mode,
            jid: self.jid.clone(),
            password: self.password.expose().to_string(),
            roster: self.roster,
            nick: self.nick.clone().unwrap_or_else(|| ctx.app_id().to_string()),
            targets: self.targets.clone(),
            subject: if self.subject { msg.title.to_string() } else { String::new() },
            body: msg.body.to_string(),
        };
        let mut ep = Endpoint::new(self.host.clone(), self.port, self.mode == Mode::Tls);
        ep.verify_tls = self.verify;
        Plan::socket(ep, move |conn, transport| {
            let client = client::Client::new(session, conn.is_tls(), transport.env());
            Box::pin(crate::machine::drive(client, conn, transport))
        })
    }

    fn limits(&self, _title: &str, _body: &str, _format: crate::NotifyFormat, _ctx: &Context<'_>) -> Option<Limits> {
        // The title only has a place of its own with `?subject=yes`.
        Some(Limits { title_maxlen: if self.subject { 250 } else { 0 }, ..Limits::DEFAULT })
    }

}

#[cfg(test)]
mod tests {
    use super::normalize_jid;

    #[test]
    fn jids_normalise() {
        assert_eq!(normalize_jid("user", "h"), Some(("user@h".into(), false)));
        assert_eq!(normalize_jid("user@x.org/res", "h"), Some(("user@x.org/res".into(), false)));
        assert_eq!(normalize_jid("user/res", "h"), Some(("user@h/res".into(), false)));
        assert_eq!(normalize_jid("#room@conf.h", "h"), Some(("room@conf.h".into(), true)));
        assert_eq!(normalize_jid("%23room", "h"), Some(("room@h".into(), true)));
        assert_eq!(normalize_jid(" a b ", "h"), None);
        assert_eq!(normalize_jid("@x", "h"), None);
        assert_eq!(normalize_jid("", "h"), None);
    }
}
