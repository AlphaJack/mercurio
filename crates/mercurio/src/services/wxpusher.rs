//! WxPusher (`wxpusher://`): messages through WxPusher.

use serde_json::{Value, json};

use crate::error::Error;
use crate::http::Response;
use crate::parse::{parse_list, validate_regex};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, split_path, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "wxpusher",
    name: "WxPusher",
    schemes: &["wxpusher"],
    service_url: "https://wxpusher.zjiecode.com/",
    parse,
    templates: &[
        "{schema}://{token}/{targets}",
    ],
    tokens: &[
        Param::new("target_topic", "Target Topic").int(),
        Param::new("target_user", "Target User ID").pattern(r"^UID_[^\s]+$"),
        Param::new("targets", "Targets").list("/").required().group(&["target_topic", "target_user"]),
        Param::new("token", "App Token").required().secret().pattern(r"^AT_[^\s]+$"),
    ],
    params: &[
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct WxPusher {
    token: Secret,
    users: Vec<String>,
    topics: Vec<u64>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let token = match u.param_nonempty("token") {
        Some(t) => {
            if !u.host.is_empty() {
                targets.extend(split_path(&u.host, true));
            }
            unquote(t)
        }
        None => u.host(),
    };
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }
    let token = validate_regex(&token, r"^AT_[^\s]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid WxPusher App Token was specified"))?;

    let user_re = crate::regex!(r"(?i)^\s*(?P<full>UID_[^\s]+)\s*$");
    let topic_re = crate::regex!(r"^\s*(?P<topic>[1-9][0-9]{0,20})\s*$");
    let mut users = Vec::new();
    let mut topics = Vec::new();
    for target in parse_list(targets) {
        if let Some(c) = user_re.captures(&target) {
            users.push(c["full"].to_string());
        } else if let Some(t) = topic_re.captures(&target).and_then(|c| c["topic"].parse::<u64>().ok()) {
            topics.push(t);
        } else {
            crate::warning!("WxPusher: dropped invalid user/topic specified");
        }
    }
    Ok(Box::new(WxPusher { token: Secret::new(token), users, topics }))
}

fn check(r: &Response) -> Result<()> {
    let content = r.json().filter(|c| c.as_object().is_some_and(|o| !o.is_empty()));
    let code = content.as_ref().and_then(|c| c.get("code")).and_then(Value::as_i64);
    if r.status == 200 && code == Some(1000) {
        return Ok(());
    }
    match content.as_ref().and_then(|c| c.get("msg")).and_then(Value::as_str) {
        Some(m) if !m.is_empty() => Err(Error::Service(format!("WxPusher code={code:?}: {m}"))),
        _ => Err(r.http_error()),
    }
}

impl Notify for WxPusher {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.users.is_empty() && self.topics.is_empty() {
            return Plan::Fail(Error::Service("WxPusher: there are no valid users or topics to notify".into()));
        }
        let content_type = match msg.format {
            NotifyFormat::Text => 1,
            NotifyFormat::Html => 2,
            NotifyFormat::Markdown => 3,
        };
        let payload = json!({
            "appToken": self.token.expose(),
            "content": crate::http::TEXT,
            "summary": msg.title,
            "contentType": content_type,
            "topicIds": self.topics,
            "uids": self.users,
            "url": null,
        });
        let req = ctx.post("https://wxpusher.zjiecode.com/api/send/message")
            .header("Accept", "application/json")
            .json_text(&payload, msg.body);
        Plan::send_check(req, check)
    }

}
