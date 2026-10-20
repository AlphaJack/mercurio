//! LaMetric (`lametric://`, `lametrics://`): notifications on LaMetric Time devices.
//!
//! Two modes: `cloud` (developer widget push, `{token}@{app_id}[/{ver}]`) and `device` (local API, `[user:]{apikey}@{host}[:port]`).

use std::time::Duration;

use serde_json::json;

use crate::parse::{is_hostname, is_ipaddr, validate_nonblank, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{NotifyType, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "lametric",
    name: "LaMetric",
    schemes: &["lametric", "lametrics"],
    service_url: "https://lametric.com",
    parse,
    parse_native: Some(parse_native),
    limits: Limits { title_maxlen: 0, body_maxlen: 32768, body_max_line_count: 0 },
    throttle: Duration::from_millis(200),
    templates: &[
        "{schema}://{app_token}@{app_id}",
        "{schema}://{app_token}@{app_id}/{app_ver}",
        "{schema}://{apikey}@{host}",
        "{schema}://{user}:{apikey}@{host}",
        "{schema}://{apikey}@{host}:{port}",
        "{schema}://{user}:{apikey}@{host}:{port}",
    ],
    tokens: &[
        Param::new("apikey", "Device API Key").secret(),
        Param::new("app_id", "App ID").secret(),
        Param::new("app_token", "App Access Token").pattern("^[A-Z0-9]{80,}==$"),
        Param::new("app_ver", "App Version").default("1").pattern("^[1-9][0-9]*$"),
        Param::new("host", "Hostname"),
        Param::new("port", "Port").port().default("8080"),
        Param::new("user", "Username"),
    ],
    params: &[
        Param::sets("apikey", &["apikey"]),
        Param::sets("app_id", &["app_id"]),
        Param::sets("app_ver", &["app_ver"]),
        Param::new("cycles", "Cycles").int().default("1").min(0),
        Param::new("icon", "Custom Icon"),
        Param::new("icon_type", "Icon Type").choice(&["info", "alert", "none"]).default("none"),
        Param::new("mode", "Mode").choice(&["cloud", "device"]).default("device").inferred(),
        Param::new("priority", "Priority").choice(&["info", "warning", "critical"]).default("info"),
        Param::new("sound", "Sound"),
    ],
    ..ServiceDef::DEFAULTS
};

const PRIORITIES: &[&str] = &["info", "warning", "critical"];
const ICON_TYPES: &[&str] = &["info", "alert", "none"];
const DEFAULT_PORT: u16 = 8080;

/// `(category, aliases)` in lookup order; the first alias is the sound id.
const SOUNDS: &[(&str, &[&str])] = &[
    ("alarms", &["alarm13", "a13"]),
    ("alarms", &["alarm12", "a12"]),
    ("alarms", &["alarm11", "a11"]),
    ("alarms", &["alarm10", "a10"]),
    ("alarms", &["alarm9", "a9", "a09"]),
    ("alarms", &["alarm8", "a8", "a08"]),
    ("alarms", &["alarm7", "a7", "a07"]),
    ("alarms", &["alarm6", "a6", "a06"]),
    ("alarms", &["alarm5", "a5", "a05"]),
    ("alarms", &["alarm4", "a4", "a04"]),
    ("alarms", &["alarm3", "a3", "a03"]),
    ("alarms", &["alarm2", "a2", "a02"]),
    ("alarms", &["alarm1", "a1", "a01"]),
    ("notifications", &["bicycle", "bike"]),
    ("notifications", &["car"]),
    ("notifications", &["cash"]),
    ("notifications", &["cat"]),
    ("notifications", &["dog2", "dog02"]),
    ("notifications", &["dog", "dog1", "dog01"]),
    ("notifications", &["energy"]),
    ("notifications", &["knock-knock", "knock"]),
    ("notifications", &["letter_email", "letter", "email"]),
    ("notifications", &["lose2", "lose02"]),
    ("notifications", &["lose1", "lose01", "lose"]),
    ("notifications", &["negative1", "negative01", "neg01", "neg1", "-"]),
    ("notifications", &["negative2", "negative02", "neg02", "neg2", "--"]),
    ("notifications", &["negative3", "negative03", "neg03", "neg3", "---"]),
    ("notifications", &["negative4", "negative04", "neg04", "neg4", "----"]),
    ("notifications", &["negative5", "negative05", "neg05", "neg5", "-----"]),
    ("notifications", &["notification4", "notification04", "not04", "not4"]),
    ("notifications", &["notification3", "notification03", "not03", "not3"]),
    ("notifications", &["notification2", "notification02", "not02", "not2"]),
    ("notifications", &["notification", "notification1", "notification01", "not01", "not1"]),
    ("notifications", &["open_door", "open", "door"]),
    ("notifications", &["positive1", "positive01", "pos01", "p1", "+"]),
    ("notifications", &["positive2", "positive02", "pos02", "p2", "++"]),
    ("notifications", &["positive3", "positive03", "pos03", "p3", "+++"]),
    ("notifications", &["positive4", "positive04", "pos04", "p4", "++++"]),
    ("notifications", &["positive5", "positive05", "pos05", "p5", "+++++"]),
    ("notifications", &["positive1", "positive01", "pos01", "p1", "+"]),
    ("notifications", &["statistic", "stat"]),
    ("notifications", &["thunder"]),
    ("notifications", &["water2", "water02"]),
    ("notifications", &["water1", "water01"]),
    ("notifications", &["wind"]),
    ("notifications", &["wind_short"]),
    ("notifications", &["win", "win01", "win1"]),
    ("notifications", &["win2", "win02"]),
];

fn sound_lookup(lookup: &str) -> Option<(&'static str, &'static str)> {
    SOUNDS.iter().find(|(_, aliases)| aliases.iter().any(|a| a.starts_with(lookup))).map(|(c, a)| (*c, a[0]))
}

#[derive(Debug)]
enum Mode {
    Cloud { app_id: String, app_ver: String, token: Secret },
    Device { url: String, user: String, password: Option<Secret> },
}

#[derive(Debug)]
struct Lametric {
    mode: Mode,
    priority: String,
    icon: Option<String>,
    icon_type: String,
    cycles: i64,
    sound: Option<(&'static str, &'static str)>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let (user, password) = match (u.user.as_deref().filter(|s| !s.is_empty()), u.password.as_deref()) {
        (Some(user), None | Some("")) => (None, Some(user.to_string())),
        (user, pw) => (user.map(str::to_string), pw.map(str::to_string)),
    };
    let password = password.filter(|p| !p.is_empty());
    let mut entries = u.path_segments();
    let lower = |k: &str| u.param_nonempty(k).map(|v| unquote(&v.trim().to_lowercase()));
    let raw = |k: &str| u.param_nonempty(k).map(unquote);

    let priority = lower("priority");
    let icon = lower("icon");
    let icon_type = lower("icon_type");
    let sound = lower("sound");
    let apikey = raw("apikey");
    let app_id = raw("app");
    let app_ver = raw("app_ver").or_else(|| if entries.is_empty() { None } else { Some(entries.remove(0)) });
    let app_token = raw("token");

    let mode = match u.param_nonempty("mode") {
        Some(m) => unquote(&m.trim().to_lowercase()),
        None => {
            let host_ok = is_hostname(&u.host, true, true, true).is_some() || is_ipaddr(&u.host, true, true).is_some();
            let pw_ok = password
                .as_deref()
                .is_some_and(|p| !crate::regex!(r"(?i)^[a-z0-9]{80,}==$").is_match(p));
            let has_app = app_ver.is_some() || app_id.is_some() || app_token.is_some();
            if host_ok && pw_ok && !has_app { "device".into() } else { "cloud".into() }
        }
    };
    let pw_unquoted = password.as_deref().map(unquote).unwrap_or_default();

    let mode = match mode.trim() {
        "cloud" => {
            let app_id = app_id.unwrap_or_else(|| u.host());
            let token = app_token.unwrap_or_else(|| pw_unquoted.clone());
            let caps = crate::regex!(r"(?i)^(com\.lametric\.)?(?P<app_id>[0-9a-z.-]{1,64})(/(?P<app_ver>[1-9][0-9]*))?")
                .captures(&app_id);
            let token = validate_regex(&token, r"^[A-Z0-9]{80,}==$", "i", true)
                .ok_or_else(|| SERVICE.err("an invalid LaMetric Application Access Token was specified"))?;
            let caps = caps.ok_or_else(|| SERVICE.err("an invalid LaMetric Application ID was specified"))?;
            let app_ver = match app_ver.filter(|v| !v.is_empty()) {
                Some(v) => validate_regex(&v, r"^[1-9][0-9]*$", "", true)
                    .ok_or_else(|| SERVICE.err("an invalid LaMetric Application Version was specified"))?,
                None => caps.name("app_ver").map(|m| m.as_str().to_string()).unwrap_or_else(|| SERVICE.default_of("app_ver").into()),
            };
            Mode::Cloud { app_id: caps["app_id"].to_string(), app_ver, token: Secret::new(token) }
        }
        "device" => {
            let apikey = apikey.unwrap_or_else(|| pw_unquoted.clone());
            validate_nonblank(&apikey).ok_or_else(|| SERVICE.err("an invalid LaMetric Device API Key was specified"))?;
            let url = format!(
                "{}://{}:{}/api/v2/device/notifications",
                u.http_scheme(),
                u.host(),
                u.port.filter(|p| *p != 0).unwrap_or(DEFAULT_PORT)
            );
            Mode::Device {
                url,
                user: user.map(|s| unquote(&s)).filter(|s| !s.is_empty()).unwrap_or_else(|| "dev".into()),
                password: password.map(|p| Secret::new(unquote(&p))),
            }
        }
        _ => return Err(SERVICE.err("an invalid LaMetric Mode was specified")),
    };

    let icon = icon.and_then(|i| {
        crate::regex!(r"[#\s]*(?P<value>.+?)\s*$").captures(&i).map(|c| c["value"].to_string())
    });
    let cycles = u.int("cycles").map(|c| c.saturating_abs()).filter(|c| *c > 0).unwrap_or(1);
    Ok(Box::new(Lametric {
        mode,
        priority: priority.filter(|p| PRIORITIES.contains(&p.as_str())).unwrap_or_else(|| SERVICE.default_of("priority").into()),
        icon,
        icon_type: icon_type.filter(|t| ICON_TYPES.contains(&t.as_str())).unwrap_or_else(|| SERVICE.default_of("icon_type").into()),
        cycles,
        sound: sound.and_then(|s| sound_lookup(s.trim())),
    }))
}

/// `https://developer.lametric.com/api/v1/dev/widget/update/com.lametric.{id}[/{ver}]` -> `lametric(s)://{id}[/{ver}]/{params}`.
fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(
        r"(?i)^http(?P<secure>s)?://(?P<host>[^/]+)/api/(?P<api_ver>v[1-9]*[0-9]+)/dev/widget/update/com\.lametric\.(?P<app_id>[0-9a-z.-]{1,64})(/(?P<app_ver>[1-9][0-9]*))?/?(?P<params>\?.+)?$"
    );
    let c = re.captures(url)?;
    let schema = if c.name("secure").is_some() { "lametrics" } else { "lametric" };
    let ver = c.name("app_ver").map(|m| format!("/{}", m.as_str())).unwrap_or_default();
    Some(format!("{schema}://{}{ver}/{}", &c["app_id"], c.name("params").map(|m| m.as_str()).unwrap_or("")))
}

impl Notify for Lametric {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let icon = self.icon.clone().unwrap_or_else(|| {
            match msg.kind {
                NotifyType::Info => "i620",
                NotifyType::Success => "i9182",
                NotifyType::Warning => "i9183",
                NotifyType::Failure => "i9184",
            }
            .to_string()
        });
        let req = match &self.mode {
            Mode::Cloud { app_id, app_ver, token } => {
                let payload = json!({"frames": [{"icon": icon, "text": msg.body, "index": 0}]});
                ctx.post(format!(
                    "https://developer.lametric.com/api/v1/dev/widget/update/com.lametric.{app_id}/{app_ver}"
                ))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("Cache-Control", "no-cache")
                .header("X-Access-Token", token.expose())
                .json(&payload)
            }
            Mode::Device { url, user, password } => {
                let mut payload = json!({
                    "priority": self.priority,
                    "icon_type": self.icon_type,
                    "lifetime": 120000,
                    "model": {"cycles": self.cycles, "frames": [{"icon": icon, "text": msg.body}]},
                });
                if let Some((category, id)) = self.sound {
                    payload["model"]["sound"] = json!({"category": category, "id": id, "repeat": 1});
                }
                ctx.post(url)
                    .header("Accept", "application/json")
                    .header("Cache-Control", "no-cache")
                    .basic_auth(user, password.as_ref().map(Secret::expose))
                    .json(&payload)
            }
        };
        Plan::send_expect(req, &[200, 201])
    }
}
