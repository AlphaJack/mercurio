//! Pushbullet (`pbul://`): pushes through the Pushbullet API.

use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::error::Error;
use crate::http::{Multipart, Request, Response};
use crate::parse::{is_email, parse_list, validate_nonblank};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "pushbullet",
    name: "Pushbullet",
    schemes: &["pbul"],
    service_url: "https://www.pushbullet.com/",
    parse,
    attachments: true,
    throttle: Duration::from_millis(1200),
    templates: &[
        "{schema}://{accesstoken}",
        "{schema}://{accesstoken}/{targets}",
    ],
    tokens: &[
        Param::new("accesstoken", "Access Token").required().secret(),
        Param::new("target_channel", "Target Channel").prefix("#"),
        Param::new("target_device", "Target Device"),
        Param::new("target_email", "Target Email").email(),
        Param::new("targets", "Targets").list("/").group(&["target_channel", "target_device", "target_email"]),
    ],
    params: &[
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.pushbullet.com/v2/";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Recipient {
    /// No target given: push to every device of the account.
    All,
    Target(String),
}

#[derive(Debug)]
struct PushBullet {
    token: Secret,
    targets: Vec<Recipient>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }
    let token =
        validate_nonblank(&u.host()).ok_or_else(|| SERVICE.err("an invalid PushBullet Access Token was specified"))?;
    let mut targets: Vec<Recipient> = parse_list(targets).into_iter().map(Recipient::Target).collect();
    if targets.is_empty() {
        targets.push(Recipient::All);
    }
    Ok(Box::new(PushBullet { token: Secret::new(token), targets }))
}

/// Everything a deferred continuation needs to build further requests.
#[derive(Clone)]
struct Api {
    token: String,
    app_id: String,
}

impl Api {
    fn json(&self, url: &str, payload: &Value) -> Request {
        let empty = payload.as_object().is_some_and(Map::is_empty);
        let req = Request::post(url)
            .header("User-Agent", &self.app_id)
            .header("Content-Type", "application/json")
            .basic_auth(&self.token, Some(""));
        if empty { req } else { req.body(serde_json::to_vec(payload).unwrap_or_default(), None) }
    }

    fn upload(&self, url: &str, name: &str, data: &[u8]) -> Request {
        Request::post(url)
            .header("User-Agent", &self.app_id)
            .basic_auth(&self.token, Some(""))
            .multipart(Multipart::new().file("file", name, "", data.to_vec()))
    }
}

fn status_ok(r: &Response) -> Result<()> {
    if r.status == 200 || r.status == 204 { Ok(()) } else { Err(r.http_error()) }
}

/// Send `req`; on 200/204 continue with the parsed JSON (or `Null`).
fn send_then(req: Request, next: impl FnOnce(Value) -> Plan + Send + 'static) -> Plan {
    Plan::http(req, move |res| match res.and_then(|r| status_ok(&r).map(|_| r)) {
        Ok(r) => next(r.json().unwrap_or(Value::Null)),
        Err(e) => Plan::Fail(e),
    })
}

type Finish = Box<dyn FnOnce(Vec<Value>) -> Plan + Send>;

struct Upload {
    file_name: String,
    mime: String,
    name: String,
    data: Vec<u8>,
}

/// Upload attachments one by one (upload-request, then upload), collecting the file pushes; any failure aborts the whole notification.
fn upload_all(api: Api, mut pending: Vec<Upload>, mut done: Vec<Value>, finish: Finish) -> Plan {
    if pending.is_empty() {
        return finish(done);
    }
    let up = pending.remove(0);
    let req =
        api.json(&format!("{NOTIFY_URL}upload-request"), &json!({"file_name": up.file_name, "file_type": up.mime}));
    send_then(req, move |resp| {
        let parsed = (|| {
            let file_name = resp.get("file_name")?.clone();
            let file_type = resp.get("file_type")?.clone();
            let file_url = resp.get("file_url")?.clone();
            let is_image = file_type.as_str()?.starts_with("image/");
            let mut payload = json!({
                "type": "file",
                "file_name": file_name,
                "file_type": file_type,
                "file_url": file_url,
            });
            if is_image {
                payload["image_url"] = file_url;
            }
            let upload_url = resp.get("upload_url")?.as_str()?.to_string();
            Some((payload, upload_url))
        })();
        let Some((payload, upload_url)) = parsed else {
            return Plan::Fail(Error::Service("Pushbullet: unexpected upload-request response".into()));
        };
        let req = api.upload(&upload_url, &up.name, &up.data);
        send_then(req, move |_| {
            done.push(payload);
            upload_all(api, pending, done, finish)
        })
        .context("upload")
    })
    .context("upload request")
}

impl Notify for PushBullet {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let api = Api { token: self.token.expose().to_string(), app_id: ctx.app_id().to_string() };
        let uploads: Vec<Upload> = msg
            .attachments
            .iter()
            .enumerate()
            .map(|(i, a)| Upload {
                file_name: if a.name.is_empty() { format!("file{:03}.dat", i + 1) } else { a.name.clone() },
                mime: a.mime.clone(),
                name: a.name.clone(),
                data: a.data.clone(),
            })
            .collect();
        let title = msg.title.to_string();
        let body = msg.body.to_string();
        let targets = self.targets.clone();
        let push_api = api.clone();
        let finish: Finish = Box::new(move |files: Vec<Value>| {
            Plan::all(targets.into_iter().map(|recipient| {
                let mut payload = json!({"type": "note", "title": title, "body": body});
                let label = match &recipient {
                    Recipient::All => "ALL_DEVICES".to_string(),
                    Recipient::Target(t) => t.clone(),
                };
                if let Recipient::Target(t) = &recipient {
                    if let Some(m) = is_email(t) {
                        payload["email"] = json!(m.full_email);
                    } else if let Some(tag) = t.strip_prefix('#') {
                        payload["channel_tag"] = json!(tag);
                    } else {
                        payload["device_iden"] = json!(t);
                    }
                }
                let url = format!("{NOTIFY_URL}pushes");
                // After uploads, a failed push names its step.
                let step = |p: Plan| if files.is_empty() { p } else { p.context("push") };
                let file_pushes: Vec<Plan> =
                    files.iter().map(|f| step(Plan::send_check(push_api.json(&url, f), status_ok))).collect();
                let plan = if body.is_empty() {
                    Plan::all(file_pushes)
                } else {
                    step(Plan::http(push_api.json(&url, &payload), move |res| match res.and_then(|r| status_ok(&r)) {
                        Ok(()) => Plan::all(file_pushes),
                        Err(e) => Plan::Fail(e),
                    }))
                };
                plan.target(label)
            }))
        });
        if uploads.is_empty() { finish(Vec::new()) } else { upload_all(api, uploads, Vec::new(), finish) }
    }

}
