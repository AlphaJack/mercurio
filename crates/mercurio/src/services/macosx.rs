//! macOS Notification Center (`macosx://`): banners through `terminal-notifier`.
//!
//! mercurio runs `terminal-notifier` (`brew install terminal-notifier`), looked up in the same places: `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin`, `/bin`, `/opt/local/bin`. Without `?version=`, the installed major version is probed once per URL with `terminal-notifier -version` (falling back to 3); version 2 gets `-sender` and `-appIcon`, version 3 `-contentImage`. Every value is prefixed with `\` so terminal-notifier reads it as plain text.
//!
//! There is no `osascript` fallback.
//!
//! # Differences with Apprise
//!
//! - When no known path holds `terminal-notifier`, mercurio still runs it through `PATH` (Apprise gives up). *intentional*
//! - On other platforms delivery fails with `Unsupported` (Apprise does not load the plugin there). *intentional*

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::error::Error;
use crate::service::{Context, Limits, Notify, Param, ServiceDef};
use crate::transport::{Command, CommandOutput, FileOp};
use crate::url::ParsedUrl;
use crate::util::parse_int;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "macosx",
    name: "MacOSX Notification",
    schemes: &["macosx"],
    service_url: "https://github.com/julienXX/terminal-notifier",
    parse,
    limits: Limits { title_maxlen: 250, body_maxlen: 32768, body_max_line_count: 10 },
    templates: &[
        "{schema}://",
    ],
    params: &[
        Param::new("click", "Open/Click URL"),
        Param::new("image", "Include Image").bool(true),
        Param::new("sender", "Sender"),
        Param::new("sound", "Sound"),
        Param::new("version", "Terminal-Notifier Version").choice(&["2", "3"]),
    ],
    ..ServiceDef::DEFAULTS
};

/// Where `terminal-notifier` is looked for, in order.
const NOTIFY_PATHS: &[&str] = &[
    "/opt/homebrew/bin/terminal-notifier",
    "/usr/local/bin/terminal-notifier",
    "/usr/bin/terminal-notifier",
    "/bin/terminal-notifier",
    "/opt/local/bin/terminal-notifier",
];

/// Used when detection fails.
const DEFAULT_VERSION: u8 = 3;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct MacOSX {
    include_image: bool,
    sound: Option<String>,
    click: Option<String>,
    sender: Option<String>,
    version: Option<u8>,
    /// Detected version, cached for later notifications.
    detected: Arc<OnceLock<u8>>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let version = match SERVICE.text(u, "version") {
        None => None,
        Some(v) => match parse_int(&v) {
            Some(2) => Some(2),
            Some(3) => Some(3),
            _ => return Err(SERVICE.err("the terminal-notifier version specified is invalid")),
        },
    };
    Ok(Box::new(MacOSX {
        include_image: SERVICE.flag_strict(u, "image"),
        sound: SERVICE.text(u, "sound"),
        click: SERVICE.text(u, "click"),
        sender: SERVICE.text(u, "sender"),
        version,
        detected: Arc::new(OnceLock::new()),
    }))
}

/// First executable `terminal-notifier` among the known paths.
fn notifier_path(ctx: &Context<'_>) -> String {
    NOTIFY_PATHS
        .iter()
        .find(|p| ctx.stat(p).is_some_and(|m| m.executable))
        .map(|p| p.to_string())
        .unwrap_or_else(|| "terminal-notifier".to_string())
}

/// `-version` output -> major version (2 for anything before 3).
fn probed_version(res: &Result<CommandOutput>) -> u8 {
    let Ok(out) = res else { return DEFAULT_VERSION };
    if out.status != 0 {
        return DEFAULT_VERSION;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    match crate::regex!(r"(\d+)\.\d+").captures(&text) {
        Some(c) => match c[1].parse::<u64>() {
            Ok(major) if major < 3 => 2,
            _ => 3,
        },
        None => DEFAULT_VERSION,
    }
}

/// Exit codes documented by terminal-notifier.
fn exit_reason(code: i32) -> String {
    match code {
        1 => "No message was provided.".into(),
        2 => "An argument could not be read.".into(),
        3 => {
            "Notifications are not authorized for terminal-notifier. Run 'terminal-notifier -diagnose' to find out why."
                .into()
        }
        4 => "Could not reach the notification service; is a user logged in?".into(),
        5 => "The notification service refused the request.".into(),
        6 => "Timed out waiting for a response.".into(),
        other => format!("terminal-notifier returned {other}."),
    }
}

fn esc(v: &str) -> String {
    format!("\\{v}")
}

/// What one send needs, owned so it can wait for the version probe.
struct Send {
    path: String,
    title: String,
    body: String,
    click: Option<String>,
    sound: Option<String>,
    sender: String,
    image: Option<crate::IconFile>,
}

impl Send {
    fn command(&self, version: u8) -> Command {
        let mut cmd = Command::new(self.path.clone()).args(["-message".to_string(), esc(&self.body)]);
        if !self.title.is_empty() {
            cmd = cmd.args(["-title".to_string(), esc(&self.title)]);
        }
        if let Some(c) = &self.click {
            cmd = cmd.args(["-open".to_string(), esc(c)]);
        }
        if let Some(s) = &self.sound {
            cmd = cmd.args(["-sound".to_string(), esc(s)]);
        }
        if version == 2 && !self.sender.is_empty() {
            cmd = cmd.args(["-sender".to_string(), esc(&self.sender)]);
        }
        if let Some(img) = &self.image {
            let flag = if version == 2 { "-appIcon" } else { "-contentImage" };
            cmd = super::_desktop::with_icon(cmd.args([flag.to_string(), esc(&img.path)]), Some(img));
        }
        cmd.timeout = SEND_TIMEOUT;
        cmd
    }

    fn plan(self, version: u8) -> Plan {
        Plan::command(self.command(version), |res| match res {
            Ok(out) if out.status == 0 => Plan::Done,
            Ok(out) => {
                Plan::Fail(Error::Service(format!("failed to send macOS notification: {}", exit_reason(out.status))))
            }
            Err(e) => Plan::Fail(e),
        })
    }
}

impl Notify for MacOSX {
    fn files(&self, _: &Context<'_>) -> Vec<FileOp> {
        NOTIFY_PATHS.iter().map(|p| FileOp::Stat { path: p.into() }).collect()
    }

    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if !cfg!(target_os = "macos") {
            return Plan::Fail(Error::Unsupported("macOS notifications are only available on macOS".into()));
        }
        let path = notifier_path(ctx);
        let send = Send {
            path: path.clone(),
            title: msg.title.to_string(),
            body: msg.body.to_string(),
            click: self.click.clone(),
            sound: self.sound.clone(),
            sender: self.sender.clone().unwrap_or_else(|| ctx.app_id().to_string()),
            image: if self.include_image { ctx.asset.icon_file(msg.kind, "png") } else { None },
        };
        if let Some(v) = self.version.or_else(|| self.detected.get().copied()) {
            return send.plan(v);
        }
        let mut probe = Command::new(path).arg("-version");
        probe.timeout = PROBE_TIMEOUT;
        let detected = self.detected.clone();
        Plan::command(probe, move |res| {
            let v = *detected.get_or_init(|| probed_version(&res));
            send.plan(v)
        })
    }
}
