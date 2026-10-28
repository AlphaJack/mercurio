//! Google Chat (`gchat://`): messages to a Google Chat space through a webhook.

use serde_json::json;

use crate::http::Request;
use crate::parse::validate_nonblank;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "googlechat",
    name: "Google Chat",
    schemes: &["gchat"],
    service_url: "https://chat.google.com/",
    parse,
    parse_native: Some(parse_native),
    limits: Limits { title_maxlen: 0, body_maxlen: 4000, body_max_line_count: 0 },
    formats: &[NotifyFormat::Markdown],
    templates: &[
        "{schema}://{workspace}/{webhook_key}/{webhook_token}",
        "{schema}://{workspace}/{webhook_key}/{webhook_token}/{thread_key}",
    ],
    tokens: &[
        Param::new("thread_key", "Thread Key").secret(),
        Param::new("webhook_key", "Webhook Key").required().secret(),
        Param::new("webhook_token", "Webhook Token").required().secret(),
        Param::new("workspace", "Workspace").required().secret(),
    ],
    params: &[
        Param::sets("key", &["webhook_key"]),
        Param::sets("thread", &["thread_key"]).aliases(&["threadkey"]),
        Param::sets("token", &["webhook_token"]),
        Param::sets("workspace", &["workspace"]),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct GoogleChat {
    workspace: Secret,
    key: Secret,
    token: Secret,
    thread_key: Option<Secret>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut workspace = Some(u.host());
    let mut tokens = u.path_segments().into_iter();
    let mut key = tokens.next();
    let mut token = tokens.next();
    let mut thread = tokens.next();
    if let Some(v) = SERVICE.raw(u, "workspace") {
        workspace = Some(unquote(v));
    }
    if let Some(v) = SERVICE.raw(u, "key") {
        key = Some(unquote(v));
    }
    if let Some(v) = SERVICE.raw(u, "token") {
        token = Some(unquote(v));
    }
    if let Some(v) = u.param("thread").or_else(|| u.param("threadkey")) {
        thread = Some(unquote(v));
    }
    let check = |v: Option<String>, what: &str| {
        v.as_deref()
            .and_then(validate_nonblank)
            .map(Secret::new)
            .ok_or_else(|| SERVICE.err(format!("an invalid Google Chat {what} was specified")))
    };
    let workspace = check(workspace, "Workspace")?;
    let key = check(key, "Webhook Key")?;
    let token = check(token, "Webhook Token")?;
    let thread_key = match thread.filter(|t| !t.is_empty()) {
        Some(t) => Some(check(Some(t), "Thread Key")?),
        None => None,
    };
    Ok(Box::new(GoogleChat { workspace, key, token, thread_key }))
}

fn parse_native(url: &str) -> Option<String> {
    let re = crate::regex!(
        r"(?i)^https://chat\.googleapis\.com/v1/spaces/(?P<workspace>[A-Z0-9_-]+)/messages/*(?P<params>.+)\n?\z"
    );
    let c = re.captures(url)?;
    Some(format!("gchat://{}/{}", &c["workspace"], &c["params"]))
}

/// Markdown as Google Chat markup (lists nest by four spaces).
pub(crate) fn commonmark_to_google_chat(body: &str) -> String {
    use super::_chat_markup::{ANCHOR, render};
    render(body, &crate::convert::markup::Markup { list_indent: "    ", ..ANCHOR })
}

impl Notify for GoogleChat {
    fn convert(&self, body: &str, format: NotifyFormat) -> Option<String> {
        (format == NotifyFormat::Markdown).then(|| commonmark_to_google_chat(body))
    }

    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut params = vec![("token", self.token.expose()), ("key", self.key.expose())];
        let mut payload = json!({"text": crate::http::TEXT});
        if let Some(t) = &self.thread_key {
            params.push(("messageReplyOption", "REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"));
            payload["thread"] = json!({"thread_key": t.expose()});
        }
        let req = Request::post(format!("https://chat.googleapis.com/v1/spaces/{}/messages", self.workspace.expose()))
            .query(&params)
            .header("User-Agent", ctx.app_id())
            .header("Content-Type", "application/json; charset=utf-8")
            .json_text(&payload, msg.body);
        Plan::send_expect(req, &[200, 204])
    }
}
