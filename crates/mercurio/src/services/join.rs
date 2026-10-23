//! Join (`join://`): push notifications to Join devices or device groups.

use crate::asset::ImageSize;
use crate::parse::{parse_list, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "join",
    name: "Join",
    schemes: &["join"],
    service_url: "https://joaoapps.com/join/",
    parse,
    limits: Limits { title_maxlen: 250, body_maxlen: 1000, body_max_line_count: 0 },
    templates: &[
        "{schema}://{apikey}/{targets}",
    ],
    tokens: &[
        Param::new("apikey", "API Key").required().secret().pattern("^[a-z0-9]{32}$"),
        Param::new("device", "Device ID").pattern("^[a-z0-9]{32}$"),
        Param::new("device_name", "Device Name"),
        Param::new("group", "Group").choice(&["all", "android", "chrome", "windows10", "phone", "tablet", "pc"]),
        Param::new("targets", "Targets").list("/").required().group(&["device", "device_name", "group"]),
    ],
    params: &[
        Param::new("image", "Include Image").bool(true),
        Param::new("priority", "Priority").choice(&["-2", "-1", "0", "1", "2"]).default("0"),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://joinjoaomgcd.appspot.com/_ah/api/messaging/v1/sendPush";
const DEFAULT_GROUP: &str = "group.all";

/// Prefix -> priority, in lookup order.
const PRIORITY_MAP: &[(&str, i64)] =
    &[("l", -2), ("m", -1), ("n", 0), ("h", 1), ("e", 2), ("-2", -2), ("-1", -1), ("0", 0), ("1", 1), ("2", 2)];

fn group_re() -> &'static crate::re::Regex {
    crate::regex!(r"(?i)^(group\.)?(?P<name>(all|android|chrome|windows10|phone|tablet|pc))")
}

#[derive(Debug)]
struct Join {
    apikey: Secret,
    targets: Vec<String>,
    include_image: bool,
    priority: i64,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let raw_key = match &u.user {
        Some(user) if !user.is_empty() => user.clone(),
        _ => u.host.clone(),
    };
    let raw_key = unquote(&raw_key);
    let apikey = validate_regex(&raw_key, r"^[a-z0-9]{32}$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid Join API Key was specified"))?;

    let priority = match u.param_nonempty("priority") {
        None => 0,
        Some(p) => {
            let p = unquote(p).to_lowercase();
            PRIORITY_MAP.iter().find(|(k, _)| p.starts_with(k)).map(|(_, v)| *v).unwrap_or(0)
        }
    };

    let mut raw_targets = Vec::new();
    if u.user.as_deref().is_some_and(|s| !s.is_empty()) {
        raw_targets.push(u.host());
    }
    raw_targets.extend(u.path_segments());
    if let Some(to) = u.param_nonempty("to") {
        raw_targets.extend(parse_list([to]));
    }
    let raw_targets = parse_list(raw_targets);

    let mut targets = Vec::new();
    if raw_targets.is_empty() {
        targets.push(DEFAULT_GROUP.to_string());
    }
    for t in raw_targets {
        match group_re().captures(&t) {
            Some(c) => targets.push(format!("group.{}", c["name"].to_lowercase())),
            None => targets.push(t),
        }
    }

    Ok(Box::new(Join { apikey: Secret::new(apikey), targets, include_image: SERVICE.flag(u, "image"), priority }))
}

impl Notify for Join {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let device_re = crate::regex!(r"(?i)^[a-z0-9]{32}$");
        let icon = if self.include_image { ctx.asset.image_url(msg.kind, ImageSize::Xy72) } else { None };
        Plan::all(self.targets.iter().map(|target| {
            let mut args: Vec<(&str, String)> = vec![
                ("apikey", self.apikey.expose().to_string()),
                ("priority", self.priority.to_string()),
                ("title", msg.title.to_string()),
                ("text", msg.body.to_string()),
            ];
            if group_re().is_match(target) || device_re.is_match(target) {
                args.push(("deviceId", target.clone()));
            } else {
                args.push(("deviceNames", target.clone()));
            }
            if let Some(icon) = &icon {
                args.push(("icon", icon.clone()));
            }
            let req = ctx.post(NOTIFY_URL)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .query(&args);
            Plan::send_expect(req, &[200]).target(target.clone())
        }))
    }

}
