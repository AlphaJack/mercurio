//! APRS (`aprs://`): text messages to amateur radio call signs through APRS-IS.
//!
//! One TCP connection to the regional APRS-IS server (port 10152): the `user ... pass ... vers ...` login, the server's `# logresp` check, then one message packet per call sign: `FROMCALL>APPRIS::TOCALL   :text` (text cleaned and cut to 67 chars).
//!
//! # Differences with Apprise
//!
//! - The login names the software `mercurio <version>` (Apprise: `apprise <version>`). *intentional*
//! - When the first read holds only the server banner, mercurio reads once more for the `# logresp` line (Apprise fails). *intentional*
//! - The 0.8 s (+ `delay`) wait applies between the message packets of one notification, not between login and the first packet. *intentional*

use std::time::Duration;

use crate::error::Error;
use crate::parse::{is_call_sign, parse_call_sign, parse_list};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use super::_sockets::send;
use crate::transport::Endpoint;
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "aprs",
    name: "Aprs",
    schemes: &["aprs"],
    service_url: "https://www.aprs2.net/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: MAX_TEXT, body_max_line_count: 0 },
    throttle: PACKET_GAP,
    templates: &[
        "{schema}://{user}:{password}@{targets}",
    ],
    tokens: &[
        Param::new("password", "Password").required().secret(),
        Param::new("target_callsign", "Target Callsign").pattern("^[a-z0-9]{2,5}(-[a-z0-9]{1,2})?$"),
        Param::new("targets", "Targets").list("/").required().group(&["target_callsign"]),
        Param::new("user", "User Name").required(),
    ],
    params: &[
        Param::new("delay", "Resend Delay").float().default("0.0").range(0, 5),
        Param::new("locale", "Locale").choice(&["NOAM", "SOAM", "EURO", "ASIA", "AUNZ", "ROTA"]).default("EURO"),
        Param::new("to", "Target Callsign"),
    ],
    ..ServiceDef::DEFAULTS
};

const PORT: u16 = 10152;
const DEVICE_ID: &str = "APPRIS";
/// Characters of message text in one packet.
const MAX_TEXT: usize = 67;
/// The gap between two packets of one connection (APRS-IS rate limit).
const PACKET_GAP: Duration = Duration::from_millis(800);

const LOCALES: &[(&str, &str)] = &[
    ("NOAM", "noam.aprs2.net"),
    ("SOAM", "soam.aprs2.net"),
    ("EURO", "euro.aprs2.net"),
    ("ASIA", "asia.aprs2.net"),
    ("AUNZ", "aunz.aprs2.net"),
    ("ROTA", "rotate.aprs2.net"),
];

#[derive(Debug)]
struct Aprs {
    user: String,
    password: Secret,
    server: &'static str,
    delay: f64,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let user = u.user().unwrap_or_default();
    let password = u.password().unwrap_or_default();
    if user.is_empty() || password.is_empty() {
        return Err(SERVICE.err("An APRS user/pass was not provided."));
    }
    if password == "-1" {
        return Err(SERVICE.err("APRS read-only passwords are not supported."));
    }
    if !password.chars().all(char::is_numeric) {
        return Err(SERVICE.err("Invalid APRS-IS password"));
    }
    let locale = SERVICE.text_or_default(u, "locale").to_uppercase();
    let server = LOCALES
        .iter()
        .find(|(k, _)| *k == locale)
        .map(|(_, v)| *v)
        .ok_or_else(|| SERVICE.err(format!("Unsupported APRS-IS server locale. Received: {locale}.")))?;
    let d = SERVICE.text_or_default(u, "delay");
    let delay = match d.trim().parse::<f64>().ok() {
        Some(v) if (0.0..5.0).contains(&v) => v,
        _ => return Err(SERVICE.err(format!("Unsupported APRS-IS delay ({d}) specified."))),
    };
    let mut entries = vec![u.host()];
    entries.extend(u.path_segments());
    if let Some(to) = u.param_nonempty("to") {
        entries.extend(parse_list([to]));
    }
    let targets = parse_call_sign(&entries, true)
        .into_iter()
        .filter(|t| {
            let ok = is_call_sign(t).is_some();
            if !ok {
                log::warn!("Dropping invalid Amateur radio call sign ({t}).");
            }
            ok
        })
        .map(|t| t.to_uppercase())
        .collect();
    Ok(Box::new(Aprs { user: user.to_uppercase(), password: Secret::new(password), server, delay, targets }))
}

/// Message cleanup: drop `{}|~`, transliterate German umlauts, fold line breaks into single spaces, cut to 67 characters, end in CRLF.
pub fn clean_payload(body: &str) -> String {
    let mut s: String = body.chars().filter(|c| !matches!(c, '{' | '}' | '|' | '~')).collect();
    for (from, to) in [("Ä", "Ae"), ("Ö", "Oe"), ("Ü", "Ue"), ("ä", "ae"), ("ö", "oe"), ("ü", "ue"), ("ß", "ss")]
    {
        s = s.replace(from, to);
    }
    let s = s.trim_matches(['\r', '\n']);
    let s = crate::regex!(r"[ \t]*[\r\n]+[ \t]*").replace_all(s, " ");
    let s: String = s.chars().take(MAX_TEXT).collect();
    format!("{}\r\n", s.trim_end_matches(['\r', '\n']))
}

/// Check the server's answer to the login line.
fn check_login(rx: &str, user: &str) -> Result<()> {
    let rx = rx.trim_end();
    let lines: Vec<&str> = rx.lines().collect();
    if lines.len() < 2 {
        return Err(Error::Service("APRS-IS login response is too short".into()));
    }
    let parts: Vec<&str> = lines[1].splitn(5, ' ').collect();
    if parts.len() != 5 {
        return Err(Error::Service("received an invalid login response from APRS-IS".into()));
    }
    if parts[2] != user {
        return Err(Error::Service(format!("APRS-IS call signs differ: {}", parts[2])));
    }
    if parts[3].starts_with("unverified") {
        return Err(Error::Service("invalid APRS-IS password for the given call sign".into()));
    }
    Ok(())
}

fn latin1(data: &[u8]) -> String {
    data.iter().map(|b| *b as char).collect()
}

impl Notify for Aprs {
    fn plan(&self, msg: &Prepared<'_>, _ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Message("there are no amateur radio call signs to notify".into()));
        }
        let login = format!(
            "user {} pass {} vers mercurio {}\r\n",
            self.user,
            self.password.expose(),
            env!("CARGO_PKG_VERSION")
        );
        let user = self.user.clone();
        let payload = clean_payload(msg.body);
        let packets: Vec<String> =
            self.targets.iter().map(|t| format!("{user}>{DEVICE_ID}::{t:<9}:{payload}")).collect();
        let pause = Duration::try_from_secs_f64(PACKET_GAP.as_secs_f64() + self.delay).unwrap_or(PACKET_GAP);
        let ep = Endpoint::new(self.server, PORT, false);
        Plan::socket(ep, move |conn, transport| {
            Box::pin(async move {
            send(conn, login.as_bytes()).await?;
            let limit = login.len() + 100;
            let mut rx = Vec::new();
            for _ in 0..2 {
                let mut buf = vec![0u8; limit];
                let n = conn.read(&mut buf).await.map_err(Error::transport)?;
                if n == 0 {
                    break;
                }
                rx.extend_from_slice(&buf[..n]);
                if latin1(&rx).trim_end().lines().count() >= 2 {
                    break;
                }
            }
            check_login(&latin1(&rx), &user)?;
            for (i, p) in packets.iter().enumerate() {
                if i > 0 {
                    transport.sleep(pause).await;
                }
                send(conn, p.as_bytes()).await?;
            }
            Ok(())
            })
        })
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_cleanup() {
        assert_eq!(clean_payload("a\r\nb"), "a b\r\n");
        assert_eq!(clean_payload("Grüße {x}|~"), "Gruesse x\r\n");
        assert_eq!(clean_payload("x  \n\n  y\n"), "x y\r\n");
        assert_eq!(clean_payload(&"z".repeat(80)).len(), 69);
    }

    #[test]
    fn login_response() {
        let ok = "# aprsc 2.1\r\n# logresp CALL verified, server T2";
        assert!(check_login(ok, "CALL").is_ok());
        assert!(check_login(ok, "OTHER").is_err());
        assert!(check_login("# aprsc\r\n# logresp CALL unverified, server T2", "CALL").is_err());
        assert!(check_login("# aprsc", "CALL").is_err());
        assert!(check_login("# aprsc\r\n# logresp", "CALL").is_err());
    }

    #[test]
    fn packet_padding() {
        assert_eq!(format!("{:<9}|", "DF1ABC"), "DF1ABC   |");
        assert_eq!(format!("{:<9}|", "DF1ABC-15"), "DF1ABC-15|");
    }
}
