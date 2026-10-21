//! SFR (`sfr://`): SMS through SFR.

use serde_json::{Value, json};

use super::_telephony::{json_object, has_value, valid_phones};
use crate::error::Error;
use crate::http::Request;
use crate::parse::parse_phone_no_unquoted;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::util::parse_int;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "sfr",
    name: "Société Française du Radiotéléphone",
    schemes: &["sfr"],
    service_url: "https://www.sfr.fr/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    templates: &[
        "{schema}://{user}:{password}@{space_id}/{targets}",
    ],
    tokens: &[
        Param::new("password", "Service Password").required().secret(),
        Param::new("space_id", "Space ID").required().secret(),
        Param::new("target", "Recipient Phone Number").pattern(r"^\+?[0-9\s)(+-]+$"),
        Param::new("targets", "Targets").list("/").required().group(&["target"]),
        Param::new("user", "Service ID").required(),
    ],
    params: &[
        Param::new("lang", "Language").default("fr_FR").required(),
        Param::new("media", "Media Type").values(&["SMS", "SMSLong", "SMSUnicode", "SMSUnicodeLong"]).default("SMSUnicode").required(),
        Param::new("sender", "Sender Name").required().aliases(&["from"]),
        Param::new("timeout", "Timeout").int().default("2880"),
        Param::sets("to", &["targets"]),
        Param::new("voice", "TTS Voice").values(&["claire08s", "laura8k"]).default("claire08s"),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://www.dmc.sfr-sh.fr/DmcWS/1.5.8/JsonService/MessagesUnitairesWS/addSingleCall";

#[derive(Debug)]
struct Sfr {
    user: String,
    password: Secret,
    space_id: Secret,
    lang: String,
    sender: String,
    media: String,
    timeout: i64,
    voice: String,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let space_id = u.host.clone();
    let mut targets = u.path_segments();
    let sender = SERVICE.raw(u, "sender").map(unquote).unwrap_or_default();
    let timeout = SERVICE.text_or_default(u, "timeout");
    let voice = SERVICE.text_or_default(u, "voice");
    let lang = SERVICE.text_or_default(u, "lang");
    let media = SERVICE.text_or_default(u, "media");
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_phone_no_unquoted([to], false));
    }

    let user = u.user().unwrap_or_default();
    let password = u.password().unwrap_or_default();
    if user.is_empty() || password.is_empty() {
        return Err(SERVICE.err("a SFR user (serviceId) and password (servicePassword) combination was not provided"));
    }
    if space_id.is_empty() {
        return Err(SERVICE.err("a SFR Space ID is required"));
    }
    let targets = valid_phones(&targets, 10);
    if targets.is_empty() {
        return Err(SERVICE.err("no receiver phone number has been provided"));
    }
    Ok(Box::new(Sfr {
        user,
        password: Secret::new(password),
        space_id: Secret::new(space_id),
        voice,
        lang,
        media,
        sender,
        timeout: parse_int(&timeout).or_else(|| parse_int(SERVICE.default_of("timeout"))).unwrap_or_default(),
        targets,
    }))
}

impl Notify for Sfr {
    fn plan(&self, msg: &Prepared<'_>, _ctx: &Context<'_>) -> Plan {
        let auth = json!({
            "serviceId": self.user,
            "servicePassword": self.password.expose(),
            "spaceId": self.space_id.expose(),
            "lang": self.lang,
        })
        .to_string();
        Plan::all(self.targets.iter().map(|t| {
            let message = json!({
                "media": self.media,
                "textMsg": crate::http::TEXT,
                "to": t,
                "from": self.sender,
                "timeout": self.timeout,
                "ttsVoice": self.voice,
            });
            let message = String::from_utf8(crate::http::json_with_text(&message, msg.body)).unwrap_or_default();
            let req =
                Request::post(NOTIFY_URL).query(&[("authenticate", auth.as_str()), ("messageUnitaire", &message)]);
            Plan::http(req, |res| match res {
                Err(e) => Plan::Fail(e),
                Ok(r) if r.status != 200 && r.status != 204 => Plan::Fail(r.http_error()),
                Ok(r) => {
                    let ok = json_object(&r).and_then(|m| m.get("success").cloned()).is_some_and(|v| has_value(&v));
                    if ok {
                        Plan::Done
                    } else {
                        let code = json_object(&r)
                            .and_then(|m| m.get("errorCode").cloned())
                            .unwrap_or(Value::String("UNKNOWN".into()));
                        Plan::Fail(Error::Service(format!("SFR notification was not sent: server_error={code}")))
                    }
                }
            })
            .target(t.clone())
        }))
    }

}
