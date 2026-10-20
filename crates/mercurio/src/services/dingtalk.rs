//! DingTalk (`dingtalk://`): messages to a DingTalk group robot webhook.

use serde_json::json;

use crate::crypto::{b64, hmac_sha256};
use crate::parse::{parse_list, validate_regex};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, quote, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "dingtalk",
    name: "DingTalk",
    schemes: &["dingtalk"],
    service_url: "https://www.dingtalk.com/",
    parse,
    formats: &[NotifyFormat::Text, NotifyFormat::Markdown],
    templates: &[
        "{schema}://{token}/",
        "{schema}://{token}/{targets}/",
        "{schema}://{secret}@{token}/",
        "{schema}://{secret}@{token}/{targets}/",
    ],
    tokens: &[
        Param::new("secret", "Secret").secret().pattern("^[a-z0-9]+$"),
        Param::new("target_phone_no", "Target Phone No"),
        Param::new("targets", "Targets").list("/").group(&["target_phone_no"]),
        Param::new("token", "Token").required().secret().pattern("^[a-z0-9]+$"),
    ],
    params: &[
        Param::sets("secret", &["secret"]),
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct DingTalk {
    token: Secret,
    secret: Option<Secret>,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut token = u.host();
    let mut secret = u.user.clone().filter(|s| !s.is_empty());
    let mut targets = u.path_segments();
    if let Some(t) = u.param_nonempty("token") {
        token = unquote(t);
    }
    if let Some(s) = u.param_nonempty("secret") {
        secret = Some(unquote(s));
    }
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }

    let token = validate_regex(&token, r"^[a-z0-9]+$", "i", true)
        .ok_or_else(|| SERVICE.err("an invalid DingTalk API Token was specified"))?;
    let secret = match secret.filter(|s| !s.is_empty()) {
        None => None,
        Some(s) => Some(Secret::new(
            validate_regex(&s, r"^[a-z0-9]+$", "i", true)
                .ok_or_else(|| SERVICE.err("an invalid DingTalk Secret was specified"))?,
        )),
    };

    let phone_re = crate::regex!(r"^\+?(?P<phone>[0-9\s)(+-]+)\s*$");
    let mut phones = Vec::new();
    for target in parse_list(targets) {
        let Some(caps) = phone_re.captures(&target) else {
            log::warn!("DingTalk: dropped invalid phone # specified");
            continue;
        };
        let digits: String = caps["phone"].chars().filter(char::is_ascii_digit).collect();
        if !(11..=14).contains(&digits.len()) {
            log::warn!("DingTalk: dropped invalid phone # specified");
            continue;
        }
        phones.push(digits);
    }
    Ok(Box::new(DingTalk { token: Secret::new(token), secret, targets: phones }))
}

/// `quote(b64(HMAC-SHA256(secret, "{timestamp}\n{secret}")), safe="")`. The query string then encodes it a second time.
fn signature(secret: &str, timestamp: &str) -> String {
    let mac = hmac_sha256(secret.as_bytes(), format!("{timestamp}\n{secret}").as_bytes());
    quote(&b64(&mac), "")
}

/// Whitespace runs collapsed to single spaces, ends trimmed.
fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl Notify for DingTalk {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let mut payload = json!({
            "msgtype": "text",
            "at": {"atMobiles": self.targets, "isAtAll": false},
        });
        if msg.format == NotifyFormat::Markdown {
            let title = collapse_ws(msg.title);
            let title = title.trim_start_matches(['#', '-', ' ']);
            payload["markdown"] = json!({
                "title": if title.is_empty() { ctx.app_desc() } else { title },
                "text": if title.is_empty() { msg.body.to_string() } else { format!("# {title}\n{}", msg.body) },
            });
            payload["msgtype"] = json!("markdown");
        } else {
            let content =
                if msg.title.is_empty() { msg.body.to_string() } else { format!("{}\r\n{}", msg.title, msg.body) };
            payload["text"] = json!({"content": content});
        }

        let mut req = ctx
            .post(format!("https://oapi.dingtalk.com/robot/send?access_token={}", self.token.expose()))
            .json(&payload);
        if let Some(secret) = &self.secret {
            let timestamp = ctx.env().unix_time_ms().to_string();
            let signature = signature(secret.expose(), &timestamp);
            req = req.query(&[("timestamp", timestamp.as_str()), ("sign", signature.as_str())]);
        }
        Plan::send_expect(req, &[200])
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Request;

    #[test]
    fn signature_matches_reference() {
        assert_eq!(signature("abc123", "1700000000000"), "ChNzxo8gXVVs%2Flr61VrC3ZPLPrpkm%2Bu4EJCgVIi87zs%3D");
        let req = Request::post("https://x/?a=1").query(&[("sign", signature("abc123", "1700000000000").as_str())]);
        assert!(req.url.ends_with("sign=ChNzxo8gXVVs%252Flr61VrC3ZPLPrpkm%252Bu4EJCgVIi87zs%253D"));
    }
}
