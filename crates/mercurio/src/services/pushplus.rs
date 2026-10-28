//! PushPlus (`pushplus://`, `wecom://`): messages through PushPlus.

use serde_json::{Value, json};

use crate::error::Error;
use crate::parse::{parse_list, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "pushplus",
    name: "Pushplus",
    schemes: &["pushplus", "wecom"],
    service_url: "https://www.pushplus.plus/",
    parse,
    parse_native: Some(parse_native),
    limits: Limits { title_maxlen: 200, body_maxlen: 20000, body_max_line_count: 0 },
    formats: &[NotifyFormat::Html],
    templates: &[
        "{schema}://{token}",
        "{schema}://{token}/{targets}",
    ],
    tokens: &[
        Param::new("targets", "Group Topics").list("/"),
        Param::new("token", "User Token").required().secret().pattern("^[a-z0-9_-]{32,64}$"),
    ],
    params: &[
        Param::new("channel", "Channel").choice(&["wechat", "webhook", "cp", "mail", "sms"]).default("wechat").aliases(&["mode"]).inferred(),
        Param::new("name", "Webhook Name"),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
        Param::sets("topic", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const CHANNELS: &[&str] = &["wechat", "webhook", "cp", "mail", "sms"];

#[derive(Debug)]
struct Pushplus {
    token: Secret,
    channel: &'static str,
    topics: Vec<String>,
    webhook: Option<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let token = SERVICE.text(u, "token").unwrap_or_else(|| u.host());
    let mut targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }
    if let Some(topic) = u.param_nonempty("topic") {
        targets.extend(parse_list([topic]));
    }
    let mut channel = u.text("mode");
    if let Some(c) = u.param_nonempty("channel") {
        channel = Some(unquote(c));
    }
    let mut webhook = SERVICE.text(u, "name");
    if u.user.as_deref().is_some_and(|s| !s.is_empty()) {
        if webhook.is_none() {
            webhook = u.user();
        }
        if channel.is_none() {
            channel = Some("webhook".into());
        }
    }

    let token = validate_regex(&token, r"^[a-z0-9_-]{32,64}$", "i", true)
        .ok_or_else(|| SERVICE.err("the Pushplus token is invalid"))?;

    let channel = match channel.filter(|c| !c.is_empty()) {
        Some(c) => {
            let c = c.to_lowercase();
            let c = if c == "wecom" { "cp".to_owned() } else { c };
            CHANNELS
                .iter()
                .copied()
                .find(|x| *x == c)
                .ok_or_else(|| SERVICE.err("the Pushplus channel is not valid"))?
        }
        None if u.scheme == "wecom" => "cp",
        None => "wechat",
    };

    let topic_re = crate::regex!(r"(?i)^([a-z0-9_-]{1,50})$");
    let topics = parse_list(targets).into_iter().filter(|t| topic_re.is_match(t)).collect();
    Ok(Box::new(Pushplus { token: Secret::new(token), channel, topics, webhook: webhook.filter(|w| !w.is_empty()) }))
}

fn parse_native(url: &str) -> Option<String> {
    let caps = crate::regex!(r"(?i)^https?://www\.pushplus\.plus/send(?:\?(?P<params>[^#]+))?$").captures(url)?;
    let params = caps.name("params").map(|m| m.as_str()).unwrap_or("");
    let tok = crate::regex!(r"(?i)(?:^|&)token=(?P<token>[a-z0-9_-]+)").captures(params)?;
    Some(format!("pushplus://{}/?{params}", &tok["token"]))
}

fn check(r: &crate::http::Response) -> Result<()> {
    if r.status != 200 {
        return Err(r.http_error());
    }
    let content = r.json();
    let code = content.as_ref().and_then(|c| c.get("code")).and_then(Value::as_i64);
    if code == Some(200) && content.as_ref().is_some_and(Value::is_object) {
        return Ok(());
    }
    let msg = content.as_ref().and_then(|c| c.get("msg")).and_then(Value::as_str).unwrap_or("Unknown error");
    Err(Error::Service(format!("PushPlus code={code:?}: {msg}")))
}

impl Notify for Pushplus {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let template = match msg.format {
            NotifyFormat::Html => "html",
            NotifyFormat::Markdown => "markdown",
            NotifyFormat::Text => "txt",
        };
        let topics: Vec<Option<&String>> =
            if self.topics.is_empty() { vec![None] } else { self.topics.iter().map(Some).collect() };
        Plan::all(topics.into_iter().map(|topic| {
            let mut payload = json!({
                "token": self.token.expose(),
                "title": if msg.title.is_empty() { msg.body } else { msg.title },
                "content": crate::http::TEXT,
                "template": template,
                "channel": self.channel,
            });
            if let Some(t) = topic {
                payload["topic"] = json!(t);
            }
            if self.channel == "webhook"
                && let Some(w) = &self.webhook
            {
                payload["webhook"] = json!(w);
            }
            let req = ctx.post("https://www.pushplus.plus/send")
                .json_text(&payload, msg.body);
            let plan = Plan::send_check(req, check);
            match topic {
                Some(t) => plan.target(t.clone()),
                None => plan,
            }
        }))
    }

}
