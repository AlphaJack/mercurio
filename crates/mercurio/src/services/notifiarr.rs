//! Notifiarr (`notifiarr://`): notifications through the Notifiarr API.

use std::time::Duration;

use serde_json::json;

use crate::asset::ImageSize;
use crate::parse::{parse_list, validate_nonblank};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::util::parse_int;
use crate::{Plan, Prepared, Result};

use super::_discord::find_mentions;

pub static SERVICE: ServiceDef = ServiceDef {
    id: "notifiarr",
    name: "Notifiarr",
    schemes: &["notifiarr"],
    service_url: "https://notifiarr.com/",
    parse,
    throttle: Duration::from_millis(40),
    templates: &[
        "{schema}://{apikey}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "Token").required().secret(),
        Param::new("target_channel", "Target Channel").prefix("#"),
        Param::new("targets", "Targets").list("/").required().group(&["target_channel"]),
    ],
    params: &[
        Param::sets("apikey", &["apikey"]).aliases(&["key"]),
        Param::new("event", "Discord Event ID").int(),
        Param::new("image", "Include Image").bool(false),
        Param::new("source", "Source").aliases(&["from"]),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://notifiarr.com/api/v1/notification/apprise";

#[derive(Debug)]
struct Notifiarr {
    apikey: Secret,
    include_image: bool,
    source: Option<String>,
    event: i64,
    channels: Vec<u64>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let event = SERVICE.text(u, "event");
    let source = u.param_nonempty("source").or_else(|| u.param_nonempty("from")).map(unquote);

    let (apikey, host_is_target) = if let Some(k) = u.param_nonempty("apikey").or_else(|| u.param_nonempty("key")) {
        (unquote(k), true)
    } else {
        (u.host(), false)
    };
    if host_is_target && !u.host.is_empty() {
        targets.push(u.host());
    }
    if let Some(to) = u.param_nonempty("to") {
        let re = crate::regex!(r"[ \t\r\n,#\\/]+");
        targets.extend(re.split(&unquote(to)).filter(|s| !s.is_empty()).map(str::to_string));
    }

    if apikey.is_empty() {
        return Err(SERVICE.err("an invalid Notifiarr APIKey was specified"));
    }
    let event = match event {
        None => 0,
        Some(e) => parse_int(&e).ok_or_else(|| SERVICE.err("an invalid Notifiarr Discord Event ID was specified"))?,
    };

    let mut channels = Vec::new();
    let re = crate::regex!(r"(?i)^\s*(?:#|%35)?([0-9]+)");
    for t in parse_list(targets) {
        match re.captures(&t).and_then(|c| c[1].parse::<u64>().ok()) {
            Some(ch) => channels.push(ch),
            None => {
                log::warn!("Notifiarr: dropped invalid channel ({t}) specified");
            }
        }
    }

    Ok(Box::new(Notifiarr {
        apikey: Secret::new(apikey),
        include_image: SERVICE.flag(u, "image"),
        source: source.and_then(|s| validate_nonblank(&s)),
        event,
        channels,
    }))
}

impl Notify for Notifiarr {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.channels.is_empty() {
            return Plan::Fail(crate::Error::Message("there were no Notifiarr channels to notify".into()));
        }
        let image_url = ctx.asset.image_url(msg.kind, ImageSize::Xy256);
        let mut ping_user: Vec<String> = Vec::new();
        let mut ping_role: Vec<String> = Vec::new();
        let mut content: Vec<String> = Vec::new();
        for (is_role, no, value) in find_mentions(msg.body) {
            if !value.is_empty() {
                content.push(format!("@{value}"));
            } else if is_role {
                content.push(format!("<@&{no}>"));
                ping_role.push(no);
            } else {
                content.push(format!("<@{no}>"));
                ping_user.push(no);
            }
        }

        Plan::all(self.channels.iter().map(|ch| {
            let mut payload = json!({
                "source": self.source.clone().unwrap_or_else(|| ctx.app_id().to_string()),
                "type": msg.kind.as_str(),
                "notification": {
                    "update": self.event != 0,
                    "name": ctx.app_id(),
                    "event": if self.event != 0 { self.event.to_string() } else { String::new() },
                },
                "discord": {
                    "color": ctx.asset.color(msg.kind),
                    "ping": {
                        "pingUser": ping_user.first().map(|s| json!(s)).unwrap_or(json!(0)),
                        "pingRole": ping_role.first().map(|s| json!(s)).unwrap_or(json!(0)),
                    },
                    "text": {
                        "title": msg.title,
                        "content": if content.is_empty() { String::new() } else { format!("👉 {}", content.join(" ")) },
                        "description": msg.body,
                        "footer": ctx.app_desc(),
                    },
                    "ids": {"channel": ch},
                },
            });
            if self.include_image
                && let Some(img) = &image_url
            {
                payload["discord"]["text"]["icon"] = json!(img);
                payload["discord"]["images"] = json!({"thumbnail": img});
            }
            let req = ctx
                .post(NOTIFY_URL)
                .header("Accept", "text/plain")
                .header("X-api-Key", self.apikey.expose())
                .json(&payload);
            Plan::send(req).target(format!("#{ch}"))
        }))
    }

}
