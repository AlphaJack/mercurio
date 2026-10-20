//! Windows balloon notifications (`windows://`): a tray-icon balloon tip with the title and body, shown for `duration` seconds.
//!
//! There is no Win32 dependency: the sequence (tray icon, balloon tip, sleep, tear-down) runs through `powershell.exe` and `System.Windows.Forms.NotifyIcon` (`ShowBalloonTip`, `Start-Sleep`, `Dispose`). The script travels as `-EncodedCommand` so no quoting of user text reaches the command line.
//!
//! Only Windows can display these: on other platforms delivery fails with [`Error::Unsupported`].
//!
//! # Differences with Apprise
//!
//! - Apprise uses the Win32 API -> mercurio runs `powershell.exe` (`System.Windows.Forms.NotifyIcon`). *intentional*
//! - The tray icon is the stock application icon; `?image=` is accepted and ignored. *intentional*
//! - On other platforms delivery fails with `Unsupported`. *intentional*

#[cfg(windows)]
use super::_desktop::check_exit;
#[cfg(not(windows))]
use crate::Error;
use crate::service::{Context, Limits, Notify, Param, ServiceDef};
use crate::transport::Command;
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
        Param::new("image", "Include Image").bool(true).ignored(),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Windows {
    duration: u64,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    // `?duration=` as an integer, ignored when invalid or not > 0.
    let duration = SERVICE
        .int(u, "duration")
        .filter(|d| *d > 0)
        .or_else(|| crate::util::parse_int(SERVICE.default_of("duration")))
        .unwrap_or_default();
    Ok(Box::new(Windows { duration: duration.unsigned_abs() }))
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
    fn plan(&self, msg: &Prepared<'_>, _ctx: &Context<'_>) -> Plan {
        let cmd = balloon_command(msg.title, msg.body, self.duration);
        #[cfg(windows)]
        {
            Plan::command(cmd, |res| check_exit("powershell", res))
        }
        #[cfg(not(windows))]
        {
            let _ = cmd;
            Plan::Fail(Error::Unsupported("Windows notifications are only available on Windows".into()))
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
