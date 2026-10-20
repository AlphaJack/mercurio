//! SMSC (`smsc://`): SMS through the SMSC API.

use super::_telephony::{Form, http_err, json_object, param_unquoted, valid_phones};
use crate::error::Error;
use crate::http::{Request, Response};
use crate::parse::{parse_phone_no_unquoted, validate_nonblank};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "smsc",
    name: "SMSC",
    schemes: &["smsc"],
    service_url: "https://smsc.ru/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    attachments: true,
    templates: &[
        "{schema}://{user}:{password}@{targets}",
    ],
    tokens: &[
        Param::new("password", "Password").required().secret(),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").required().group(&["target_phone"]),
        Param::new("user", "Login").required(),
    ],
    params: &[
        Param::new("sender", "Sender ID"),
        Param::sets("to", &["targets"]),
        Param::new("translit", "Transliterate").bool(false),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://smsc.ru/sys/send.php";

#[derive(Debug)]
struct Smsc {
    user: String,
    password: Secret,
    sender: Option<String>,
    translit: bool,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = vec![u.host()];
    targets.extend(u.path_segments());
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_phone_no_unquoted([to], false));
    }
    let sender = param_unquoted(u, "sender");
    let translit = SERVICE.flag(u, "translit");

    let user = u.user().unwrap_or_default();
    if user.is_empty() {
        return Err(SERVICE.err("an SMSC login must be specified"));
    }
    let password = u.password().unwrap_or_default();
    if password.is_empty() {
        return Err(SERVICE.err("an SMSC password must be specified"));
    }
    let sender = match sender {
        Some(s) => Some(validate_nonblank(&s).ok_or_else(|| SERVICE.err("the SMSC sender ID specified is invalid"))?),
        None => None,
    };
    Ok(Box::new(Smsc { user, password: Secret::new(password), sender, translit, targets: valid_phones(&targets, 10) }))
}

fn check(r: &Response) -> Result<()> {
    if r.status != 200 {
        return Err(http_err(r));
    }
    if let Some(m) = json_object(r)
        && m.contains_key("error_code")
    {
        let err = m.get("error").map(|v| v.to_string()).unwrap_or_else(|| "Unknown error.".into());
        return Err(Error::Service(format!("SMSC error {}: {err}", m["error_code"])));
    }
    Ok(())
}

impl Notify for Smsc {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(SERVICE.err("there are no valid SMSC targets to notify"));
        }
        let mut params: Vec<(&str, String)> = vec![
            ("login", self.user.clone()),
            ("psw", self.password.expose().to_string()),
            ("phones", self.targets.join(",")),
            ("fmt", "3".into()),
        ];
        if let Some(s) = &self.sender {
            params.push(("sender", s.clone()));
        }
        if self.translit {
            params.push(("translit", "1".into()));
        }
        params.push(("mes", msg.body.to_string()));
        let req = Request::post(NOTIFY_URL);
        let req = if msg.attachments.is_empty() {
            req.form(&params)
        } else {
            params.push(("mms", "1".into()));
            let mut form = Form::new(ctx.env().as_ref());
            for (k, v) in &params {
                form = form.text(k, v);
            }
            for (i, a) in msg.attachments.iter().enumerate() {
                let name = if a.name.is_empty() { "attachment.dat" } else { a.name.as_str() };
                form = form.part(&format!("mes{i}"), Some(name), Some(&a.mime), a.data.clone());
            }
            form.apply(req)
        };
        Plan::send_check(req, check)
    }

}
