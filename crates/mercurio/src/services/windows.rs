//! Windows notifications (`windows://`): a toast with the title, body and the notification type's image, falling back to a tray-icon balloon.
//!
//! The toast goes through WinRT (`ToastNotificationManager`) in-process, with no `windows` crate and no program to run. It is shown under PowerShell's AppUserModelID, which every Windows 10 and 11 registers, so mercurio needs no app ID of its own; Windows labels the toast "Windows PowerShell". The image is the app's icon (`image_path_mask` or `image_bytes`), else the bundled one, shown as the app logo; `?image=no` leaves it out. `?duration=` above 7 seconds asks for a long toast (about 25 seconds), otherwise a short one (about 7 seconds).
//!
//! When the toast fails, mercurio shows a balloon instead: the sequence (tray icon, balloon tip, sleep, tear-down) runs through `powershell.exe` and `System.Windows.Forms.NotifyIcon` (`ShowBalloonTip`, `Start-Sleep`, `Dispose`) for `duration` seconds. The script travels as `-EncodedCommand` so no quoting of user text reaches the command line.
//!
//! Only Windows can display these: on other platforms delivery fails with [`Error::Unsupported`].
//!
//! # Differences with Apprise
//!
//! - Apprise shows a tray balloon through the Win32 API, while mercurio shows a toast through WinRT and falls back to a balloon through `powershell.exe` (`System.Windows.Forms.NotifyIcon`).
//! - Apprise keeps the balloon up for `?duration=` seconds, while the toast is short (about 7 seconds) up to 7 and long (about 25 seconds) above.
//! - The balloon fallback shows the stock application icon.
//! - On other platforms delivery fails with `Unsupported`.

#[cfg(windows)]
use super::_desktop::{check_exit, write_icon};
use crate::Error;
use crate::service::{Context, Limits, Notify, Param, ServiceDef};
use crate::transport::{Command, NativeCall, Toast};
use crate::util::xml_escape;
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "windows",
    name: "Windows Notification",
    schemes: &["windows"],
    service_url: "",
    parse,
    limits: Limits { title_maxlen: 250, body_maxlen: 32768, body_max_line_count: 2 },
    templates: &[
        "{schema}://",
    ],
    params: &[
        Param::new("duration", "Duration").int().default("12").min(1),
        Param::new("image", "Include Image").bool(true),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Windows {
    duration: u64,
    include_image: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    // `?duration=` as an integer, ignored when invalid or not > 0.
    let duration = SERVICE
        .int(u, "duration")
        .filter(|d| *d > 0)
        .or_else(|| crate::util::parse_int(SERVICE.default_of("duration")))
        .unwrap_or_default();
    Ok(Box::new(Windows { duration: duration.unsigned_abs(), include_image: SERVICE.flag_strict(u, "image") }))
}

/// PowerShell's AppUserModelID: registered on every Windows 10 and 11, so the toast shows without registering one of our own.
pub const POWERSHELL_APP_ID: &str = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe";

/// `?duration=` up to this many seconds gives a `short` toast (about 7 s on screen), above it a `long` one (about 25 s).
const SHORT_TOAST_SECS: u64 = 7;

/// `file:///` URI for a local path, as toast images take them.
fn file_uri(path: &str) -> String {
    let mut out = String::from("file:///");
    for c in path.trim_start_matches(['/', '\\']).chars() {
        match c {
            '\\' => out.push('/'),
            ' ' => out.push_str("%20"),
            '#' => out.push_str("%23"),
            '%' => out.push_str("%25"),
            c => out.push(c),
        }
    }
    out
}

/// The toast payload: title (when set) and body as `ToastGeneric` text, `icon` as the app logo.
pub fn toast_xml(title: &str, body: &str, icon: Option<&str>, duration: u64) -> String {
    let mut xml = String::from("<toast");
    if duration > SHORT_TOAST_SECS {
        xml.push_str(" duration=\"long\"");
    }
    xml.push_str("><visual><binding template=\"ToastGeneric\">");
    if !title.is_empty() {
        xml.push_str(&format!("<text>{}</text>", xml_escape(title)));
    }
    xml.push_str(&format!("<text>{}</text>", xml_escape(body)));
    if let Some(path) = icon {
        xml.push_str(&format!("<image placement=\"appLogoOverride\" src=\"{}\"/>", xml_escape(&file_uri(path))));
    }
    xml.push_str("</binding></visual></toast>");
    xml
}

/// PowerShell single-quoted literal.
fn ps_str(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// The balloon script for `title`, `body` and `duration` seconds.
pub fn balloon_script(title: &str, body: &str, duration: u64) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         Add-Type -AssemblyName System.Windows.Forms\n\
         Add-Type -AssemblyName System.Drawing\n\
         $n = New-Object System.Windows.Forms.NotifyIcon\n\
         $n.Icon = [System.Drawing.SystemIcons]::Application\n\
         $n.Text = 'Tooltip'\n\
         $n.BalloonTipTitle = {}\n\
         $n.BalloonTipText = {}\n\
         $n.Visible = $true\n\
         $n.ShowBalloonTip({})\n\
         Start-Sleep -Seconds {}\n\
         $n.Dispose()\n",
        ps_str(title),
        ps_str(body),
        duration.saturating_mul(1000).min(i32::MAX as u64),
        duration,
    )
}

/// `powershell.exe -EncodedCommand <UTF-16LE base64 script>`.
pub fn balloon_command(title: &str, body: &str, duration: u64) -> Command {
    let script = balloon_script(title, body, duration);
    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut cmd = Command::new("powershell.exe").args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
    ]);
    cmd = cmd.arg(crate::crypto::b64(&utf16));
    cmd.timeout = std::time::Duration::from_secs(duration.saturating_add(30));
    cmd
}

impl Notify for Windows {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if !cfg!(windows) {
            return Plan::Fail(Error::Unsupported("Windows notifications are only available on Windows".into()));
        }
        let icon = if self.include_image { ctx.asset.icon_file(msg.kind, "png") } else { None };
        let toast = NativeCall::Toast(Toast {
            app_id: POWERSHELL_APP_ID.into(),
            xml: toast_xml(msg.title, msg.body, icon.as_ref().map(|i| i.path.as_str()), self.duration),
        });
        let balloon = balloon_command(msg.title, msg.body, self.duration);
        #[cfg(windows)]
        {
            Plan::chain([
                write_icon(icon.as_ref()),
                Plan::native(toast, move |res| match res {
                    Ok(()) => Plan::Done,
                    Err(toast_err) => Plan::command(balloon, move |res| {
                        let plan = check_exit("powershell", res);
                        if let Plan::Fail(e) = plan {
                            Plan::Fail(Error::Service(format!("toast: {toast_err}; balloon: {e}")))
                        } else {
                            plan
                        }
                    }),
                }),
            ])
        }
        #[cfg(not(windows))]
        {
            let _ = (toast, balloon);
            Plan::Done
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_quotes_user_text() {
        let s = balloon_script("it's", "a 'b' $c", 7);
        assert!(s.contains("$n.BalloonTipTitle = 'it''s'\n"));
        assert!(s.contains("$n.BalloonTipText = 'a ''b'' $c'\n"));
        assert!(s.contains("ShowBalloonTip(7000)"));
        assert!(s.contains("Start-Sleep -Seconds 7"));
    }

    #[test]
    fn command_is_encoded() {
        let c = balloon_command("t", "b", 12);
        assert_eq!(c.program, "powershell.exe");
        let enc = c.args.last().unwrap();
        let raw = crate::crypto::b64_decode(enc).unwrap();
        let units: Vec<u16> = raw.chunks(2).map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
        assert_eq!(String::from_utf16(&units).unwrap(), balloon_script("t", "b", 12));
    }
}
