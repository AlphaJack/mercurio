//! WeChat / WeCom (`wechat://`): messages through the WeCom application API.
//!
//! The access token is kept in the persistent store for `expires_in` minus five minutes (at least a minute) and dropped when the API reports it expired (errcode 40001, 40014, 42001).

use serde_json::{Map, Value, json};

use crate::error::Error;
use crate::http::{Request, Response};
use crate::parse::{parse_list, validate_nonblank, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef, UrlIdentifier};
use crate::url::{ParsedUrl, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "wechat",
    name: "WeChat (WeCom)",
    schemes: &["wechat"],
    service_url: "https://work.weixin.qq.com/",
    parse,
    limits: Limits { title_maxlen: 0, body_maxlen: 2048, body_max_line_count: 0 },
    templates: &[
        "{schema}://{user}:{password}@{host}",
        "{schema}://{user}:{password}@{host}/{targets}",
    ],
    tokens: &[
        Param::new("host", "Agent ID").required().pattern("^[0-9]+$"),
        Param::new("password", "App Secret").required().secret(),
        Param::new("target_department", "Target Department").prefix("#"),
        Param::new("target_tag", "Target Tag").prefix("+"),
        Param::new("target_user", "Target User").prefix("@"),
        Param::new("targets", "Targets").list("/").group(&["target_department", "target_tag", "target_user"]),
        Param::new("user", "Corp ID").required(),
    ],
    params: &[
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const TOKEN_URL: &str = "https://qyapi.weixin.qq.com/cgi-bin/gettoken";
const NOTIFY_URL: &str = "https://qyapi.weixin.qq.com/cgi-bin/message/send";
/// Error codes meaning the cached token is no longer valid.
const TOKEN_ERROR_CODES: &[i64] = &[40001, 40014, 42001];

#[derive(Debug)]
struct WeChat {
    corpid: String,
    corpsecret: Secret,
    agentid: u64,
    users: Vec<String>,
    departments: Vec<String>,
    tags: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let corpid = u.user.as_deref().map(unquote).unwrap_or_default();
    let corpsecret = u.password.as_deref().map(unquote).unwrap_or_default();
    let agentid = u.host();
    let mut targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }

    let corpid = validate_nonblank(&corpid).ok_or_else(|| SERVICE.err("a WeChat (WeCom) Corp ID must be specified"))?;
    let corpsecret =
        validate_nonblank(&corpsecret).ok_or_else(|| SERVICE.err("a WeChat (WeCom) App Secret must be specified"))?;
    let agentid = validate_regex(&agentid, r"^[0-9]+$", "", true)
        .and_then(|a| a.parse::<u64>().ok())
        .ok_or_else(|| SERVICE.err("the WeChat (WeCom) Agent ID is invalid; it must be a non-negative integer"))?;

    let dept_re = crate::regex!(r"^#(?P<dept>[0-9]+)$");
    let tag_re = crate::regex!(r"^\+(?P<tag>[0-9]+)$");
    let user_re = crate::regex!(r"^@?(?P<user>[A-Za-z0-9][A-Za-z0-9_@.\-]*)$");
    let (mut users, mut departments, mut tags) = (Vec::new(), Vec::new(), Vec::new());
    for target in parse_list(targets) {
        if let Some(c) = dept_re.captures(&target) {
            departments.push(c["dept"].to_string());
        } else if let Some(c) = tag_re.captures(&target) {
            tags.push(c["tag"].to_string());
        } else if let Some(c) = user_re.captures(&target) {
            let user = &c["user"];
            users.push(if user == "all" { "@all".to_string() } else { user.to_string() });
        } else {
            crate::warning!("WeChat (WeCom): ignoring unrecognized target");
        }
    }
    Ok(Box::new(WeChat { corpid, corpsecret: Secret::new(corpsecret), agentid, users, departments, tags }))
}

/// Error text when the body is empty/not an object or `errcode` is non-zero.
fn api_error(r: &Response) -> Option<String> {
    let content = r.json();
    let obj = match content.as_ref() {
        Some(Value::Object(o)) if !o.is_empty() => o,
        _ => return Some("unexpected response".into()),
    };
    match obj.get("errcode") {
        None => None,
        Some(Value::Number(n)) if n.as_f64() == Some(0.0) => None,
        Some(Value::Bool(false)) => None,
        Some(code) => {
            let msg = obj.get("errmsg").and_then(Value::as_str).unwrap_or("Unknown error");
            Some(format!("errcode={code}: {msg}"))
        }
    }
}

/// The token and how long to cache it (`expires_in` minus 300 s, at least 60 s).
fn token_of(r: &Response) -> Result<(String, std::time::Duration)> {
    if r.status != 200 {
        return Err(r.http_error());
    }
    if let Some(e) = api_error(r) {
        return Err(Error::Service(format!("WeChat access token request failed: {e}")));
    }
    let json = r.json();
    let token = match json.as_ref().and_then(|c| c.get("access_token")) {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        Some(Value::Number(n)) if n.as_f64() != Some(0.0) => n.to_string(),
        _ => return Err(Error::Service("WeChat access token response contained no token".into())),
    };
    let expires_in = json.as_ref().and_then(|c| c.get("expires_in")).and_then(Value::as_f64).unwrap_or(7200.0);
    Ok((token, std::time::Duration::from_secs_f64((expires_in - 300.0).max(60.0))))
}

fn errcode(r: &Response) -> Option<i64> {
    r.json().as_ref()?.get("errcode")?.as_i64()
}

fn check_send(r: &Response) -> Result<()> {
    if r.status != 200 {
        return Err(r.http_error());
    }
    match api_error(r) {
        None => Ok(()),
        Some(e) => Err(Error::Service(format!("failed to send WeChat (WeCom) notification: {e}"))),
    }
}

impl Notify for WeChat {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.users.is_empty() && self.departments.is_empty() && self.tags.is_empty() {
            return Plan::Fail(Error::Service("no WeChat (WeCom) recipients configured".into()));
        }
        let msgtype = if msg.format == NotifyFormat::Markdown { "markdown" } else { "text" };
        let mut payload = Map::new();
        payload.insert("agentid".into(), json!(self.agentid));
        payload.insert("msgtype".into(), json!(msgtype));
        payload.insert(msgtype.into(), json!({"content": crate::http::TEXT}));
        if !self.users.is_empty() {
            payload.insert("touser".into(), json!(self.users.join("|")));
        }
        if !self.departments.is_empty() {
            payload.insert("toparty".into(), json!(self.departments.join("|")));
        }
        if !self.tags.is_empty() {
            payload.insert("totag".into(), json!(self.tags.join("|")));
        }
        // Serialized once: the token continuation keeps these bytes, not a copy of the text.
        let payload = bytes::Bytes::from(crate::http::json_with_text(&Value::Object(payload), msg.body));
        let user_agent = ctx.app_id().to_string();

        let store = ctx.store();
        let send = move |token: String| {
            let req = Request::post(format!("{NOTIFY_URL}?access_token={token}"))
                .header("User-Agent", user_agent)
                .body(payload, Some("application/json"));
            Plan::send_check(req, move |r| {
                let res = check_send(r);
                if res.is_err() && errcode(r).is_some_and(|c| TOKEN_ERROR_CODES.contains(&c)) {
                    // Expired token: the next send fetches a fresh one.
                    store.clear(&["access_token"]);
                }
                res
            })
            .context("send")
        };
        if let Some(token) = ctx.store.get_str("access_token").filter(|t| !t.is_empty()) {
            return send(token);
        }
        let store = ctx.store();
        let token_req = Request::get(TOKEN_URL)
            .query(&[("corpid", self.corpid.as_str()), ("corpsecret", self.corpsecret.expose())]);
        Plan::http(token_req, move |res| match res.and_then(|r| token_of(&r)) {
            Ok((token, ttl)) => {
                store.set("access_token", json!(token), Some(ttl));
                send(token)
            }
            Err(e) => Plan::Fail(e.context("token")),
        })
    }

    fn url_identifier(&self) -> UrlIdentifier {
        UrlIdentifier::Parts(vec![
            "wechat".into(),
            self.corpid.clone(),
            self.corpsecret.expose().to_string(),
            self.agentid.to_string(),
        ])
    }
}
