//! File (`file://`): appends each notification to a local file as one JSON line (JSON Lines).
//!
//! Each line is exactly the body `json://` would post (attachments included, `:key=value` payload entries applied). `file:///var/log/alerts.jsonl` is an absolute path, `file:///C:/logs/alerts.jsonl` a Windows one, `file://alerts.jsonl` a path relative to the working directory. The file is created when missing; its directory must exist. Each line is written in one append, so concurrent writers do not interleave lines.
//!

use crate::service::{Context, Notify, Param, ServiceDef};
use crate::transport::{Datagram, DatagramTarget};
use crate::services::_webhook::double_unquoted;
use crate::url::{ParsedUrl, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "file",
    name: "File",
    schemes: &["file"],
    parse,
    formats: &[NotifyFormat::Text, NotifyFormat::Html, NotifyFormat::Markdown],
    attachments: true,
    templates: &["{schema}://{path}"],
    tokens: &[Param::new("path", "File Path").required()],
    params: &[Param::new("payload", "Payload Extras").prefix(":")],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct File {
    path: String,
    payload: Vec<(String, String)>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    // Read the path from the input: the generic parser treats the first segment as a host and drops the leading `/` of an absolute path.
    let rest = u.original.split_once("://").map_or("", |(_, rest)| rest);
    let mut path = unquote(rest.split_once('?').map_or(rest, |(path, _)| path));
    // `file:///C:/logs/x` names `C:/logs/x`, as in browsers.
    if let [b'/', drive, b':', ..] = path.as_bytes()
        && drive.is_ascii_alphabetic()
    {
        path.remove(0);
    }
    if path.is_empty() || path.ends_with('/') {
        return Err(SERVICE.err("a file path is required, e.g. file:///var/log/alerts.jsonl"));
    }
    Ok(Box::new(File { path, payload: double_unquoted(&u.query_colon) }))
}

impl Notify for File {
    fn plan(&self, msg: &Prepared<'_>, _: &Context<'_>) -> Plan {
        let mut payload = super::_json::encode(super::_json::object(msg), &self.payload);
        payload.push(b'\n');
        Plan::Datagram(Datagram { target: DatagramTarget::File(self.path.clone()), payload })
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::FakeTransport;
    use crate::transport::DatagramTarget;
    use crate::{Asset, DefaultTransport, Message, NotifyType};

    fn lines(path: &std::path::Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    #[test]
    fn paths() {
        let path_of = |url: &str| {
            let fake = FakeTransport::new();
            assert!(crate::parse(url).unwrap().send(&Message::new("b"), &fake, &Asset::default()).is_success());
            let DatagramTarget::File(path) = &fake.datagrams()[0].target else { panic!("not a file target") };
            path.clone()
        };
        assert_eq!(path_of("file:///var/log/alerts.jsonl"), "/var/log/alerts.jsonl");
        assert_eq!(path_of("file://alerts.jsonl"), "alerts.jsonl");
        assert_eq!(path_of("file://logs/my%20alerts.jsonl"), "logs/my alerts.jsonl");
        assert_eq!(path_of("file:///C:/logs/alerts.jsonl"), "C:/logs/alerts.jsonl");
        assert_eq!(path_of("file:///tmp/a.jsonl?:type=level"), "/tmp/a.jsonl");
        for bad in ["file://", "file:///", "file:///var/log/"] {
            assert!(crate::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn appends_one_json_line_per_message() {
        let dir = std::env::temp_dir().join(format!("mercurio-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("alerts.jsonl");
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }
        let target = crate::parse(&format!("file://{}", path.display())).unwrap();
        let transport = DefaultTransport::new();
        let asset = Asset::default();
        assert!(target.send(&Message::new("disk full").title("server-1").kind(NotifyType::Warning), &transport, &asset).is_success());
        assert!(target.send(&Message::new("line one\nline two"), &transport, &asset).is_success());

        let got = lines(&path);
        assert_eq!(got.len(), 2);
        assert_eq!((got[0]["title"].as_str(), got[0]["message"].as_str()), (Some("server-1"), Some("disk full")));
        assert_eq!(got[0]["type"], "warning");
        assert_eq!(got[1]["message"], "line one\nline two");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn line_is_the_json_service_body() {
        let msg = Message::new("disk full").title("server-1").attach(crate::Attachment::new("a.txt", "text/plain", b"hi".to_vec()));
        let extras = "?:type=level&:version=";
        let fake = FakeTransport::new();
        fake.respond(200, "");
        let asset = Asset::default();
        assert!(crate::parse(&format!("json://localhost/hook{extras}")).unwrap().send(&msg, &fake, &asset).is_success());
        assert!(crate::parse(&format!("file:///tmp/a.jsonl{extras}")).unwrap().send(&msg, &fake, &asset).is_success());

        let body = fake.last_request().unwrap().body;
        assert_eq!(fake.datagrams()[0].payload, [body.as_slice(), b"\n"].concat());
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!((json["level"].as_str(), json.get("version")), (Some("info"), None));
        assert_eq!(json["attachments"][0]["base64"], "aGk=");
    }

    #[cfg(unix)]
    #[test]
    fn follows_symlinks() {
        let dir = std::env::temp_dir().join(format!("mercurio-file-link-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (real, link) = (dir.join("real.jsonl"), dir.join("link.jsonl"));
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let target = crate::parse(&format!("file://{}", link.display())).unwrap();
        assert!(target.send(&Message::new("via link"), &DefaultTransport::new(), &Asset::default()).is_success());
        assert_eq!(lines(&real)[0]["message"], "via link");
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_directory_fails() {
        let target = crate::parse("file:///nonexistent-mercurio-dir/alerts.jsonl").unwrap();
        let delivery = target.send(&Message::new("b"), &DefaultTransport::new(), &Asset::default());
        assert!(!delivery.is_success());
    }
}
