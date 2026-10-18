//! Seven (`seven://`): SMS through the seven API.

use serde_json::json;

use super::_telephony::{param_unquoted, unquote_or_empty, valid_phones};
use crate::http::Request;
use crate::parse::parse_phone_no_unquoted;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "seven",
    name: "seven",
    schemes: &["seven"],
    service_url: "https://www.seven.io",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    templates: &[
        "{schema}://{apikey}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret(),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").required().group(&["target_phone"]),
    ],
    params: &[
        Param::new("flash", "Flash").bool(false),
        Param::new("label", "Label"),
        Param::new("source", "Originating Address").aliases(&["from"]),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://gateway.seven.io/api/sms";

#[derive(Debug)]
struct Seven {
    apikey: Secret,
    source: Option<String>,
    flash: bool,
    label: Option<String>,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let apikey = unquote_or_empty(Some(&u.host));
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_phone_no_unquoted([to], false));
    }
    let source = param_unquoted(u, "from").or_else(|| param_unquoted(u, "source"));
    let flash = SERVICE.flag(u, "flash");
    let label = u.param("label").map(str::to_string);
    if apikey.is_empty() {
        return Err(SERVICE.err("an invalid seven API Key was specified"));
    }
    Ok(Box::new(Seven {
        apikey: Secret::new(apikey),
        source: source.map(|s| s.trim().to_string()),
        flash,
        label: label.map(|s| s.trim().to_string()),
        targets: valid_phones(&targets, 10),
    }))
}

impl Notify for Seven {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(SERVICE.err("there were no seven targets to notify"));
        }
        let mut payload = json!({"to": null, "text": msg.body});
        if let Some(s) = self.source.as_deref().filter(|s| !s.is_empty()) {
            payload["from"] = json!(s);
        }
        if self.flash {
            payload["flash"] = json!(true);
        }
        if let Some(l) = self.label.as_deref().filter(|s| !s.is_empty()) {
            payload["label"] = json!(l);
        }
        Plan::all(self.targets.iter().map(|t| {
            let mut p = payload.clone();
            p["to"] = json!(format!("+{t}"));
            let req = Request::post(NOTIFY_URL)
                .header("Accept", "application/json")
                .header("SentWith", ctx.app_id())
                .header("X-Api-Key", self.apikey.expose())
                .json(&p);
            Plan::send_expect(req, &[200, 201]).target(t.clone())
        }))
    }

}
