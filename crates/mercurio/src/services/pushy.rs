//! Pushy (`pushy://`): push notifications through Pushy.

use serde_json::{Value, json};

use crate::error::Error;
use crate::parse::{parse_list, validate_nonblank};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::util::{json_has_value, parse_int};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "pushy",
    name: "Pushy",
    schemes: &["pushy"],
    service_url: "https://pushy.me/",
    parse,
    limits: Limits { title_maxlen: 250, body_maxlen: 4096, body_max_line_count: 0 },
    templates: &[
        "{schema}://{apikey}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "Secret API Key").required().secret(),
        Param::new("target_device", "Target Device").prefix("@"),
        Param::new("target_topic", "Target Topic").prefix("#"),
        Param::new("targets", "Targets").list("/").required().group(&["target_device", "target_topic"]),
    ],
    params: &[
        Param::new("badge", "Badge").int().min(0),
        Param::sets("key", &["apikey"]),
        Param::new("sound", "Sound"),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Pushy {
    apikey: Secret,
    topics: Vec<String>,
    devices: Vec<String>,
    sound: Option<String>,
    badge: Option<i64>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut apikey = u.host();
    let mut targets = u.path_segments();
    let sound = SERVICE.text(u, "sound");
    let badge = u.param_nonempty("badge").map(|b| unquote(b.trim()));
    if let Some(k) = u.param_nonempty("key") {
        apikey = k.to_string();
    }
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }
    let apikey =
        validate_nonblank(&apikey).ok_or_else(|| SERVICE.err("an invalid Pushy Secret API Key was specified"))?;

    let topic_re = crate::regex!(r"(?i)^[#]?(?P<topic>[a-z0-9]+)$");
    let device_re = crate::regex!(r"(?i)^@(?P<device>[a-z0-9]+)$");
    let mut topics = Vec::new();
    let mut devices = Vec::new();
    for t in parse_list(targets) {
        if let Some(c) = topic_re.captures(&t) {
            topics.push(c["topic"].to_string());
        } else if let Some(c) = device_re.captures(&t) {
            devices.push(c["device"].to_string());
        } else {
            log::warn!("Pushy: dropped invalid topic/device specified");
        }
    }
    let badge = badge.and_then(|b| parse_int(&b)).filter(|b| *b >= 0);
    Ok(Box::new(Pushy { apikey: Secret::new(apikey), topics, devices, sound, badge }))
}

impl Notify for Pushy {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.topics.is_empty() && self.devices.is_empty() {
            return Plan::Fail(Error::Service("there are no Pushy targets to notify".into()));
        }
        let url = format!("https://api.pushy.me/push?api_key={}", self.apikey.expose());
        let targets =
            self.topics.iter().map(|t| (format!("#{t}"), t)).chain(self.devices.iter().map(|d| (format!("@{d}"), d)));
        Plan::all(
            targets
                .map(|(label, target)| {
                    let mut notification = json!({"body": msg.body});
                    if !msg.title.is_empty() {
                        notification["title"] = json!(msg.title);
                    }
                    if let Some(s) = &self.sound {
                        notification["sound"] = json!(s);
                    }
                    if let Some(b) = self.badge {
                        notification["badge"] = json!(b);
                    }
                    let payload = json!({
                        "to": target,
                        "data": {"message": msg.body},
                        "notification": notification,
                    });
                    let req = ctx.post(&url).header("Accepts", "application/json").json(&payload);
                    Plan::send_check(req, |r| {
                        let success = match r.json() {
                            Some(Value::Object(m)) => m.get("success").is_some_and(json_has_value),
                            Some(_) => false,
                            None => false,
                        };
                        if r.status != 200 || !success {
                            return Err(r.http_error());
                        }
                        Ok(())
                    })
                    .target(label)
                })
                .collect::<Vec<_>>(),
        )
    }

}
