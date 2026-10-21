//! HumHub (`humhub://`, `humhubs://`): posts to HumHub spaces or user streams.
//!
//! One post per container; attachments are uploaded to the post id the server returns. On `?retry=`, containers already posted to are not posted again and only their missing attachments are uploaded to the remembered post id.

use serde_json::{Value, json};

use crate::http::{Multipart, Request, Response};
use crate::message::Attachment;
use crate::parse::parse_list;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::store::Memo;
use crate::url::ParsedUrl;
use crate::util::{json_text, json_has_value, parse_int};
use crate::{Error, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "humhub",
    name: "HumHub",
    schemes: &["humhub", "humhubs"],
    service_url: "https://www.humhub.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 4000, body_max_line_count: 0 },
    attachments: true,
    throttle: std::time::Duration::from_millis(20),
    templates: &[
        "{schema}://{user}@{host}/{targets}",
        "{schema}://{user}@{host}:{port}/{targets}",
        "{schema}://{user}:{password}@{host}/{targets}",
        "{schema}://{user}:{password}@{host}:{port}/{targets}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("password", "Password").secret(),
        Param::new("port", "Port").port(),
        Param::new("targets", "Targets").list("/"),
        Param::new("user", "Token or Username").required().secret(),
    ],
    params: &[
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct HumHub {
    base: String,
    user: Secret,
    password: Option<Secret>,
    targets: Vec<String>,
}

/// A positive decimal integer, normalised, else `None`.
fn positive_int(s: &str) -> Option<String> {
    parse_int(s).filter(|n| *n > 0).map(|n| n.to_string())
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let mut targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }
    let user = u
        .user()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| SERVICE.err("a HumHub bearer token or username must be specified"))?;
    let mut ids = Vec::new();
    for t in parse_list(&targets) {
        match positive_int(&t) {
            Some(id) => ids.push(id),
            None => log::warn!("HumHub: dropping an invalid container id"),
        }
    }
    if ids.is_empty() {
        return Err(SERVICE.err("no valid HumHub container ID(s) were specified"));
    }
    let mut base = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = u.port {
        base.push_str(&format!(":{p}"));
    }
    Ok(Box::new(HumHub {
        base,
        user: Secret::new(user),
        password: u.password().filter(|p| !p.is_empty()).map(Secret::new),
        targets: ids,
    }))
}

/// The JSON `id` value as text, when it holds a value.
fn post_id(r: &Response) -> Option<String> {
    let v = r.json()?;
    let id = v.as_object()?.get("id")?;
    json_has_value(id).then(|| json_text(id))
}

fn expect_200(r: &Response) -> Result<()> {
    if r.status == 200 { Ok(()) } else { Err(r.http_error()) }
}

impl HumHub {
    fn auth(&self, req: Request) -> Request {
        match &self.password {
            Some(p) => req.basic_auth(self.user.expose(), Some(p.expose())),
            None => req.header("Authorization", format!("Bearer {}", self.user.expose())),
        }
    }

    fn plan_container(&self, id: &str, payload: &Value, text: &str, attachments: &[Attachment], ctx: &Context<'_>) -> Plan {
        let message_key = format!("message:{id}");
        let req = self.auth(ctx.post(format!("{}/api/v1/post/container/{id}", self.base))).json_text(payload, text);
        let base = self.base.clone();
        let no_attachments = attachments.is_empty();
        let attachments = attachments.to_vec();
        let upload = self.auth(ctx.post(String::new()));
        let memo = ctx.memo.clone();
        let container = id.to_string();
        let env = ctx.env().clone();
        // Upload the attachments the post has not received yet.
        let uploads = move |memo: Memo, pid: Option<String>| {
            let Some(pid) = pid else {
                return Plan::Fail(Error::Service("failed to parse the HumHub post id; attachments not sent".into()));
            };
            let url = format!("{base}/api/v1/post/{pid}/upload-files");
            Plan::all(attachments.into_iter().enumerate().filter_map(|(i, a)| {
                let key = format!("attachment:{container}:{}", i + 1);
                if memo.is_delivered(&key) {
                    return None;
                }
                let mut req = upload.clone();
                req.url = url.clone();
                let req = req.multipart(Multipart::with_env(env.as_ref()).file("files[]", a.name.clone(), "", a.data));
                let memo = memo.clone();
                Some(Plan::send_then(req, move |r| match expect_200(&r) {
                    Ok(()) => {
                        memo.mark_delivered(&key);
                        Plan::Done
                    }
                    Err(e) => Plan::Fail(e),
                }))
            }))
            .context("upload")
        };
        if memo.is_delivered(&message_key) {
            if no_attachments {
                return Plan::Done;
            }
            let pid = memo.recall(&message_key).and_then(|v| v.as_str().map(str::to_string));
            return uploads(memo, pid);
        }
        Plan::http(req, move |res| {
            let r = match res.and_then(|r| expect_200(&r).map(|()| r)) {
                Ok(r) => r,
                Err(e) if no_attachments => return Plan::Fail(e),
                Err(e) => return Plan::Fail(e.context("post")),
            };
            if no_attachments {
                memo.mark_delivered(&message_key);
                return Plan::Done;
            }
            let pid = post_id(&r);
            memo.remember(&message_key, pid.clone().map_or(Value::Null, Value::String));
            memo.mark_delivered(&message_key);
            uploads(memo, pid)
        })
    }
}

impl Notify for HumHub {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let payload = json!({"data": {"message": crate::http::TEXT}});
        Plan::all(
            self.targets.iter().map(|id| self.plan_container(id, &payload, msg.body, msg.attachments, ctx).target(id.clone())),
        )
    }

}
