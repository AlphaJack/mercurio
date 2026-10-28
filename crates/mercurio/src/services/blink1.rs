//! blink(1) (`blink1://`, `blink1://<serial>/`): lights a blink(1) USB LED in the notification type's colour.
//!
//! Sequence: fade to the colour over `fade` ms, wait `fade + duration` ms, then switch the LED off instantly. Mercurio has no HID dependency and drives the sequence through ThingM's `blink1-tool`, which must be installed and on `PATH`:
//!
//! ```text
//! blink1-tool [--id <serial>] --led <n> -m <fade> --rgb <r>,<g>,<b>
//! (sleep fade + duration)
//! blink1-tool [--id <serial>] --led <n> -m 0 --rgb 0,0,0
//! ```
//!
//! The fade is passed rounded down to 10 ms, the device's resolution.

use std::time::Duration;

use super::_desktop::check_exit;
use crate::service::{Context, Limits, Notify, Param, ServiceDef};
use crate::transport::Command;
use crate::url::{ParsedUrl, unquote};
use crate::util::parse_int;
use crate::{Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "blink1",
    name: "blink(1)",
    schemes: &["blink1"],
    service_url: "https://blink1.thingm.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 32768, body_max_line_count: 0 },
    templates: &[
        "{schema}://",
        "{schema}://{serial}/",
    ],
    tokens: &[
        Param::new("serial", "Serial Number"),
    ],
    params: &[
        Param::new("duration", "Duration (ms)").int().default("5000").range(0, 300000),
        Param::new("fade", "Fade Time (ms)").int().default("0").range(0, 10000),
        Param::new("ledn", "LED Number").choice(&["0", "1", "2"]).default("0"),
    ],
    ..ServiceDef::DEFAULTS
};

const MAX_DURATION_MS: i64 = 300_000;
const MAX_FADE_MS: i64 = 10_000;

#[derive(Debug)]
struct Blink1 {
    serial: Option<String>,
    duration_ms: u64,
    fade_ms: u64,
    ledn: u8,
}

fn ranged(u: &ParsedUrl, key: &str, max: i64) -> Result<u64> {
    let v = match SERVICE.raw(u, key).filter(|v| !v.is_empty()) {
        None => parse_int(SERVICE.default_of(key)).unwrap_or(0),
        Some(raw) => {
            parse_int(&unquote(raw)).ok_or_else(|| SERVICE.err(format!("blink(1) {key} must be an integer")))?
        }
    };
    if !(0..=max).contains(&v) {
        return Err(SERVICE.err(format!("blink(1) {key} must be between 0 and {max} ms")));
    }
    Ok(v as u64)
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    // The host, unquoted, is the device serial; `_` (or nothing) means "first device".
    let serial = if !u.host.is_empty() && u.host != "_" { Some(u.host()) } else { None };
    let serial = serial.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty() && s != "_");
    let duration_ms = ranged(u, "duration", MAX_DURATION_MS)?;
    let fade_ms = ranged(u, "fade", MAX_FADE_MS)?;
    let ledn = match u.param_nonempty("ledn").map(|v| unquote(v).to_lowercase()).as_deref() {
        Some("1") => 1,
        Some("2") => 2,
        _ => 0,
    };
    Ok(Box::new(Blink1 { serial, duration_ms, fade_ms, ledn }))
}

impl Blink1 {
    fn fade(&self, (r, g, b): (u8, u8, u8), fade_ms: u64) -> Command {
        let mut cmd = Command::new("blink1-tool");
        if let Some(s) = &self.serial {
            cmd = cmd.args(["--id", s.as_str()]);
        }
        cmd.args([
            "--led".to_owned(),
            self.ledn.to_string(),
            "-m".into(),
            (fade_ms / 10 * 10).to_string(),
            "--rgb".into(),
            format!("{r},{g},{b}"),
        ])
    }
}

impl Notify for Blink1 {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let rgb = ctx.asset.color_rgb(msg.kind);
        Plan::chain([
            Plan::command(self.fade(rgb, self.fade_ms), |res| check_exit("blink1-tool", res)),
            Plan::Sleep(Duration::from_millis(self.fade_ms + self.duration_ms)),
            Plan::command(self.fade((0, 0, 0), 0), |res| check_exit("blink1-tool", res)),
        ])
    }
}
