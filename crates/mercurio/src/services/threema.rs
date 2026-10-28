//! Threema Gateway (`threema://`): messages through the Threema Gateway API.

use crate::error::Error;
use crate::parse::{is_email, is_phone_no, parse_list_keep_spaces, validate_nonblank};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "threema",
    name: "Threema Gateway",
    schemes: &["threema"],
    service_url: "https://gateway.threema.ch/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 3500, body_max_line_count: 0 },
    templates: &[
        "{schema}://{gateway_id}@{secret}/{targets}",
    ],
    tokens: &[
        Param::new("gateway_id", "Gateway ID").required().secret(),
        Param::new("secret", "API Secret").required().secret(),
        Param::new("target_email", "Target Email").email(),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("target_threema_id", "Target Threema ID"),
        Param::new("targets", "Targets").list("/").required().group(&["target_email", "target_phone", "target_threema_id"]),
    ],
    params: &[
        Param::sets("from", &["gateway_id"]),
        Param::sets("gwid", &["gateway_id"]),
        Param::sets("secret", &["secret"]),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Threema {
    gateway_id: String,
    secret: Secret,
    /// `(query key, value)`: `to` (Threema ID), `email` or `phone`.
    targets: Vec<(&'static str, String)>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let secret = SERVICE.text(u, "secret").unwrap_or_else(|| u.host());
    let mut targets = u.path_segments();
    // The sender is unquoted once more.
    let user = match (u.param_nonempty("from"), u.param_nonempty("gwid")) {
        (Some(f), _) | (None, Some(f)) => Some(unquote(&unquote(f))),
        _ => u.user(),
    };
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list_keep_spaces([to]));
    }

    let user = user.filter(|s| !s.is_empty()).ok_or_else(|| SERVICE.err("Threema Gateway ID must be specified"))?;
    if user.chars().count() != 8 {
        return Err(SERVICE.err("Threema Gateway ID must be 8 characters in length"));
    }
    let secret =
        validate_nonblank(&secret).ok_or_else(|| SERVICE.err("an invalid Threema API Secret was specified"))?;

    let mut out = Vec::new();
    for target in parse_list_keep_spaces(targets) {
        if target.chars().count() == 8 {
            out.push(("to", target));
        } else if let Some(e) = is_email(&target) {
            out.push(("email", e.full_email));
        } else if let Some(p) = is_phone_no(&target, 11) {
            out.push(("phone", p.full));
        } else {
            crate::warning!("Threema: dropped invalid user/email/phone specified");
        }
    }
    Ok(Box::new(Threema { gateway_id: user, secret: Secret::new(secret), targets: out }))
}

impl Notify for Threema {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Service("there were no Threema Gateway targets to notify".into()));
        }
        Plan::all(self.targets.iter().map(|(key, target)| {
            let req = ctx.post("https://msgapi.threema.ch/send_simple")
                .header("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                .query(&[
                    ("secret", self.secret.expose()),
                    ("from", self.gateway_id.as_str()),
                    ("text", msg.body),
                    (key, target.as_str()),
                ]);
            Plan::send_expect(req, &[200]).target(target.clone())
        }))
    }

}
