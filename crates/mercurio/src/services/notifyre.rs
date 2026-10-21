//! Notifyre (`notifyre://`): SMS and fax through the Notifyre API.

use serde_json::{Value, json};

use super::_telephony::{http_err, json_object, param_unquoted, has_value, unquote_or_empty, valid_phones};
use crate::crypto::b64;
use crate::error::Error;
use crate::http::Response;
use crate::parse::{is_phone_no, parse_bool, parse_phone_no_unquoted};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "notifyre",
    name: "Notifyre",
    schemes: &["notifyre"],
    service_url: "https://notifyre.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 160, body_max_line_count: 0 },
    attachments: true,
    templates: &[
        "{schema}://{apikey}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret(),
        Param::new("target_phone", "Target Phone No").pattern(r"^[0-9\s)(+-]+$").prefix("+"),
        Param::new("targets", "Targets").list("/").group(&["target_phone"]),
    ],
    params: &[
        Param::new("campaign", "Campaign Name"),
        Param::new("from", "Source Phone No"),
        Param::new("header", "Fax Header"),
        Param::new("hq", "High Quality").bool(true),
        Param::new("mode", "Mode").choice(&["sms", "fax"]).default("sms"),
        Param::new("ref", "Client Reference"),
        Param::new("template", "Template Name"),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const SMS_URL: &str = "https://api.notifyre.com/20220711/sms/send";
const FAX_URL: &str = "https://api.notifyre.com/20220711/fax/send";
const MODES: &[&str] = &["sms", "fax"];

#[derive(Debug)]
struct Notifyre {
    apikey: Secret,
    fax: bool,
    source: Option<String>,
    /// `None` -> the app id at send time.
    campaign: Option<String>,
    template: String,
    reference: String,
    hq: bool,
    header: String,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let apikey = unquote_or_empty(Some(&u.host));
    let mut targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_phone_no_unquoted([to], false));
    }
    if apikey.is_empty() {
        return Err(SERVICE.err("a Notifyre API key must be specified"));
    }
    let fax = match param_unquoted(u, "mode") {
        None => false,
        Some(m) => {
            let m = m.trim().to_lowercase();
            match MODES.iter().find(|x| x.starts_with(&m)) {
                Some(&"fax") => true,
                Some(_) => false,
                None => return Err(SERVICE.err("the Notifyre mode specified is invalid")),
            }
        }
    };
    let source = match param_unquoted(u, "from") {
        None => None,
        Some(s) => Some(format!(
            "+{}",
            is_phone_no(&s, 10).ok_or_else(|| SERVICE.err("the Notifyre source (From) phone # is invalid"))?.full
        )),
    };
    let campaign = param_unquoted(u, "campaign").map(|c| c.trim().to_string()).filter(|c| !c.is_empty());
    let trimmed = |k: &str| param_unquoted(u, k).map(|v| v.trim().to_string()).unwrap_or_default();
    let hq = u.param_nonempty("hq").map(|v| parse_bool(v, false)).unwrap_or(true);
    Ok(Box::new(Notifyre {
        apikey: Secret::new(apikey),
        fax,
        source,
        campaign,
        template: trimmed("template"),
        reference: trimmed("ref"),
        hq,
        header: trimmed("header"),
        targets: valid_phones(&targets, 10).into_iter().map(|t| format!("+{t}")).collect(),
    }))
}

fn check(r: &Response) -> Result<()> {
    if r.status != 200 {
        return Err(http_err(r));
    }
    let content = json_object(r).unwrap_or_default();
    match content.get("success") {
        Some(v) if !has_value(v) => Err(Error::Service(format!(
            "Notifyre reported failure: {}",
            content.get("message").map(Value::to_string).unwrap_or_default()
        ))),
        _ => Ok(()),
    }
}

impl Notify for Notifyre {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(SERVICE.err("there are no valid Notifyre targets to notify"));
        }
        let campaign = self.campaign.clone().unwrap_or_else(|| ctx.app_id().to_string());
        let source = self.source.clone().unwrap_or_default();
        let req = ctx.post(if self.fax { FAX_URL } else { SMS_URL })
            .header("Content-Type", "application/json")
            .header("x-api-token", self.apikey.expose());
        let payload = if self.fax {
            let mut documents = Vec::new();
            if !msg.body.is_empty() {
                documents.push(json!({"base64Str": b64(msg.body.as_bytes()), "contentType": "text/plain"}));
            }
            for a in msg.attachments {
                documents.push(json!({"base64Str": b64(&a.data), "contentType": a.mime}));
            }
            if documents.is_empty() {
                return Plan::Fail(Error::Message("there is no content to fax".into()));
            }
            json!({
                "templateName": self.template,
                "recipients": self.targets.iter().map(|t| json!({"type": "fax_number", "value": t})).collect::<Vec<_>>(),
                "sendFrom": source,
                "isHighQuality": self.hq,
                "clientReference": self.reference,
                "documents": documents,
                "header": self.header,
                "subject": crate::http::TEXT,
                "campaignName": campaign,
                "scheduledDate": null,
            })
        } else {
            json!({
                "body": crate::http::TEXT,
                "recipients": self.targets.iter().map(|t| json!({"type": "mobile_number", "value": t})).collect::<Vec<_>>(),
                "from": source,
                "campaignName": campaign,
            })
        };
        Plan::send_check(req.json_text(&payload, msg.body), check)
    }

    fn limits(&self, _title: &str, _body: &str, _format: crate::NotifyFormat, _ctx: &Context<'_>) -> Option<Limits> {
        Some(Limits { title_maxlen: 0, body_maxlen: if self.fax { 32768 } else { 160 }, body_max_line_count: 0 })
    }

}
