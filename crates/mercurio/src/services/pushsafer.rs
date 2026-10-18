//! Pushsafer (`psafer://`, `psafers://`): push notifications through Pushsafer.

use std::time::Duration;

use crate::crypto::b64;
use crate::error::Error;
use crate::http::{Request, Response};
use crate::parse::{parse_list, validate_nonblank};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::util::parse_int;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "pushsafer",
    name: "Pushsafer",
    schemes: &["psafer", "psafers"],
    service_url: "https://www.pushsafer.com/",
    parse,
    attachments: true,
    throttle: Duration::from_millis(1200),
    templates: &[
        "{schema}://{privatekey}",
        "{schema}://{privatekey}/{targets}",
    ],
    tokens: &[
        Param::new("privatekey", "Private Key").required().secret(),
        Param::new("target_device", "Target Device"),
        Param::new("target_email", "Target Email"),
        Param::new("targets", "Targets").list("/").group(&["target_device", "target_email"]),
    ],
    params: &[
        Param::new("priority", "Priority").choice(&["-2", "-1", "0", "1", "2"]),
        Param::new("sound", "Sound").choice(&["silent", "ahem", "applause", "arrow", "baby", "bell", "bicycle", "bike", "boing", "buzzer", "camera", "carhorn", "horn", "cashregister", "chime", "creakydoor", "cuckooclock", "cuckoo", "disconnect", "dog", "doorbell", "fanfare", "gunshot", "honk", "jawharp", "morse", "electric", "radiotuner", "sirens", "militarytrumpets", "military", "trumpets", "ufo", "whahwhah", "whah", "goodye", "hello", "no", "okay", "ok", "ooohhhweee", "warn", "warning", "welcome", "yeah", "yes", "beep", "beep1", "weee", "wee", "cutinout", "flickglass", "laser", "windchime", "echo", "zipper", "hihat", "beep2", "beep3", "beep4", "alarmarmed", "armed", "alarmdisarmed", "disarmed", "backupready", "dooropen", "dopen", "doorclosed", "dclosed", "windowopen", "wopen", "windowclosed", "wclosed", "lighton", "lon", "lightoff", "loff", "doorbellrang"]),
        Param::sets("to", &["targets"]),
        Param::new("vibration", "Vibration").choice(&["1", "2", "3"]),
    ],
    ..ServiceDef::DEFAULTS
};

const DEFAULT_ICON: i64 = 25;
const SEND_TO_ALL: &str = "a";
const PICTURE_PARAMETER: [&str; 3] = ["p", "p2", "p3"];

const PRIORITY_MAP: &[(&str, i64)] = &[("low", -2), ("medium", -1), ("normal", 0), ("high", 1), ("emergency", 2)];
const VIBRATIONS: &[i64] = &[1, 2, 3];

const SOUNDS: &[(&str, i64)] = &[
    ("silent", 0),
    ("ahem", 1),
    ("applause", 2),
    ("arrow", 3),
    ("baby", 4),
    ("bell", 5),
    ("bicycle", 6),
    ("bike", 6),
    ("boing", 7),
    ("buzzer", 8),
    ("camera", 9),
    ("carhorn", 10),
    ("horn", 10),
    ("cashregister", 11),
    ("chime", 12),
    ("creakydoor", 13),
    ("cuckooclock", 14),
    ("cuckoo", 14),
    ("disconnect", 15),
    ("dog", 16),
    ("doorbell", 17),
    ("fanfare", 18),
    ("gunshot", 19),
    ("honk", 20),
    ("jawharp", 21),
    ("morse", 22),
    ("electric", 23),
    ("radiotuner", 24),
    ("sirens", 25),
    ("militarytrumpets", 26),
    ("military", 26),
    ("trumpets", 26),
    ("ufo", 27),
    ("whahwhah", 28),
    ("whah", 42),
    ("goodye", 29),
    ("hello", 30),
    ("no", 31),
    ("okay", 32),
    ("ok", 32),
    ("ooohhhweee", 33),
    ("warn", 34),
    ("warning", 34),
    ("welcome", 35),
    ("yeah", 36),
    ("yes", 37),
    ("beep", 38),
    ("beep1", 38),
    ("weee", 39),
    ("wee", 39),
    ("cutinout", 40),
    ("flickglass", 41),
    ("laser", 43),
    ("windchime", 44),
    ("echo", 45),
    ("zipper", 46),
    ("hihat", 47),
    ("beep2", 48),
    ("beep3", 49),
    ("beep4", 50),
    ("alarmarmed", 51),
    ("armed", 51),
    ("alarmdisarmed", 52),
    ("disarmed", 52),
    ("backupready", 53),
    ("dooropen", 55),
    ("dopen", 55),
    ("doorclosed", 54),
    ("dclosed", 54),
    ("windowopen", 57),
    ("wopen", 57),
    ("windowclosed", 56),
    ("wclosed", 56),
    ("lighton", 58),
    ("lon", 58),
    ("lightoff", 59),
    ("loff", 59),
    ("doorbellrang", 60),
];

#[derive(Debug)]
struct PushSafer {
    secure: bool,
    privatekey: Secret,
    targets: Vec<String>,
    sound: Option<i64>,
    vibration: Option<i64>,
}

/// `value` as an integer, else the first map key starting with `value`; `None` -> error.
fn choice(value: Option<&str>, map: &[(&str, i64)]) -> Result<Option<i64>, ()> {
    let Some(v) = value else { return Ok(None) };
    let n = match parse_int(v) {
        Some(n) => n,
        None => {
            let v = v.to_lowercase();
            let v = v.trim();
            if v.is_empty() {
                return Err(());
            }
            map.iter().find(|(k, _)| k.starts_with(v)).map(|(_, n)| *n).ok_or(())?
        }
    };
    if map.iter().any(|(_, x)| *x == n) { Ok(Some(n)) } else { Err(()) }
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }
    let privatekey = u.host();
    let get = |k: &str| SERVICE.text(u, k);

    // Priority is validated but (as upstream) never sent.
    choice(get("priority").as_deref(), PRIORITY_MAP)
        .map_err(|_| SERVICE.err("an invalid PushSafer priority was specified"))?;
    let sound =
        choice(get("sound").as_deref(), SOUNDS).map_err(|_| SERVICE.err("an invalid PushSafer sound was specified"))?;
    let vibration = match get("vibration") {
        None => None,
        Some(v) => {
            let n = parse_int(&v).ok_or_else(|| SERVICE.err("an invalid PushSafer vibration was specified"))?;
            if n != 0 && !VIBRATIONS.contains(&n) {
                return Err(SERVICE.err("an invalid PushSafer vibration was specified"));
            }
            Some(n)
        }
    };
    let privatekey =
        validate_nonblank(&privatekey).ok_or_else(|| SERVICE.err("an invalid PushSafer Private Key was specified"))?;
    let mut targets = parse_list(targets);
    if targets.is_empty() {
        targets.push(SEND_TO_ALL.to_string());
    }
    Ok(Box::new(PushSafer { secure: u.secure, privatekey: Secret::new(privatekey), targets, sound, vibration }))
}

type Payload = Vec<(&'static str, String)>;

fn set(p: &mut Payload, k: &'static str, v: String) {
    match p.iter_mut().find(|(key, _)| *key == k) {
        Some(e) => e.1 = v,
        None => p.push((k, v)),
    }
}

fn check(r: &Response) -> Result<()> {
    let json = r.json();
    let code = json.as_ref().and_then(|j| j.get("status")).cloned();
    if r.status != 200 && r.status != 204 {
        return Err(r.http_error());
    }
    let ok = matches!(&code, Some(serde_json::Value::Number(n)) if n.as_f64() == Some(1.0))
        || matches!(&code, Some(serde_json::Value::Bool(true)));
    if !ok {
        let err = json
            .as_ref()
            .and_then(|j| j.get("error"))
            .and_then(|e| e.as_str().map(str::to_string))
            .unwrap_or_else(|| "Unknown".into());
        return Err(Error::Service(format!("Pushsafer: {err}")));
    }
    Ok(())
}

#[derive(Clone)]
struct Sender {
    url: String,
    key: String,
    app_id: String,
}

impl Sender {
    fn request(&self, mut payload: Payload) -> Request {
        set(&mut payload, "k", self.key.clone());
        Request::post(&self.url).header("User-Agent", &self.app_id).form(&payload)
    }
}

/// Send the attachment batches from `idx`, mirroring upstream's loop: a successful batch resets `payload_` (title cleared, body "..."); a failed one leaves it as is, so the next batch also carries its pictures.
fn batches(s: Sender, base: Payload, mut current: Payload, pictures: Vec<String>, idx: usize) -> Plan {
    if idx >= pictures.len() {
        return Plan::Done;
    }
    let end = (idx + PICTURE_PARAMETER.len()).min(pictures.len());
    for (c, data) in pictures[idx..end].iter().enumerate() {
        set(&mut current, PICTURE_PARAMETER[c], data.clone());
    }
    let req = s.request(current.clone());
    Plan::http(req, move |res| {
        let outcome = res.and_then(|r| check(&r));
        let next_payload = if outcome.is_ok() {
            let mut p = base.clone();
            set(&mut p, "t", String::new());
            set(&mut p, "m", "...".into());
            p
        } else {
            current
        };
        let next = batches(s, base, next_payload, pictures, end);
        match outcome {
            Ok(()) => next,
            Err(e) => Plan::all([Plan::Fail(e), next]),
        }
    })
}

impl Notify for PushSafer {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let pictures: Vec<String> = msg
            .attachments
            .iter()
            .filter(|a| a.mime.starts_with("image/"))
            .map(|a| format!("data:{};base64,{}", a.mime, b64(&a.data)))
            .collect();
        let sender = Sender {
            url: format!("{}://www.pushsafer.com/api", if self.secure { "https" } else { "http" }),
            key: self.privatekey.expose().to_string(),
            app_id: ctx.app_id().to_string(),
        };
        let plans = self.targets.iter().map(|recipient| {
            let mut payload: Payload = vec![
                ("t", msg.title.to_string()),
                ("m", msg.body.to_string()),
                ("i", DEFAULT_ICON.to_string()),
                ("c", ctx.asset.color(msg.kind).to_string()),
                ("d", recipient.clone()),
            ];
            if let Some(s) = self.sound {
                payload.push(("s", s.to_string()));
            }
            if let Some(v) = self.vibration {
                payload.push(("v", v.to_string()));
            }
            let plan = if pictures.is_empty() {
                Plan::send_check(sender.request(payload), check)
            } else {
                batches(sender.clone(), payload.clone(), payload, pictures.clone(), 0)
            };
            plan.target(recipient.clone())
        });
        Plan::all(plans.collect::<Vec<_>>())
    }

}
