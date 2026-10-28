//! Nextcloud Talk (`nctalk://`, `nctalks://`): messages to Nextcloud Talk rooms.
//!
//! Either user/password (chat API) or `?secret=` (bot API, HMAC-SHA256 signed).

use serde_json::json;

use crate::crypto::{hex, hmac_sha256};
use crate::parse::parse_list;
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Error, Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "nextcloudtalk",
    name: "Nextcloud Talk",
    schemes: &["nctalk", "nctalks"],
    service_url: "https://nextcloud.com/talk",
    parse,
    // Title and body share one 32000-character field.
    limits: Limits { title_maxlen: 255, body_maxlen: 31745, body_max_line_count: 0 },
    templates: &[
        "{schema}://{user}:{password}@{host}/{targets}",
        "{schema}://{user}:{password}@{host}:{port}/{targets}",
        "{schema}://{host}/{targets}?secret={secret}",
        "{schema}://{host}:{port}/{targets}?secret={secret}",
    ],
    tokens: &[
        Param::new("host", "Hostname").required(),
        Param::new("password", "Password").required().secret(),
        Param::new("port", "Port").port(),
        Param::new("secret", "Secret").required().secret(),
        Param::new("target_room_id", "Room ID"),
        Param::new("targets", "Targets").list("/").required().group(&["target_room_id"]),
        Param::new("user", "Username").required(),
    ],
    params: &[
        Param::sets("secret", &["secret"]),
        Param::new("silent", "Silent Notification").bool(false),
        Param::new("url_prefix", "URL Prefix"),
        Param::new("headers", "HTTP Header").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct NextcloudTalk {
    base: String,
    user: String,
    password: Secret,
    secret: Option<Secret>,
    targets: Vec<String>,
    silent: bool,
    headers: Vec<(String, String)>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    crate::parse::require_host(u, &SERVICE)?;
    let targets = parse_list(u.path_segments());
    let secret = u.param("secret").filter(|s| !s.is_empty()).map(Secret::new);
    let silent = SERVICE.flag(u, "silent");
    let url_prefix = SERVICE.text(u, "url_prefix");
    let headers = u.query_plus.iter().map(|(k, v)| (unquote(k), unquote(v))).collect();

    if secret.is_none() && (u.user.is_none() || u.password.is_none()) {
        return Err(SERVICE.err("specify a Nextcloud Talk user and password or bot secret"));
    }

    let mut base = format!("{}://{}", u.http_scheme(), u.host());
    if let Some(p) = u.port {
        base.push_str(&format!(":{p}"));
    }
    if let Some(p) = url_prefix.as_deref().map(|p| p.trim_matches('/')).filter(|p| !p.is_empty()) {
        base.push('/');
        base.push_str(p);
    }
    Ok(Box::new(NextcloudTalk {
        base,
        user: u.user().unwrap_or_default(),
        password: Secret::new(u.password().unwrap_or_default()),
        secret,
        targets,
        silent,
        headers,
    }))
}

impl Notify for NextcloudTalk {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Service("there were no Nextcloud Talk targets to notify".into()));
        }
        let head = if msg.title.is_empty() { ctx.app_desc() } else { msg.title };
        let message = if msg.body.is_empty() { head.to_owned() } else { format!("{head}\r\n{}", msg.body) };
        let mut payload = json!({"message": message});
        if self.silent {
            payload["silent"] = json!(true);
        }
        Plan::all(self.targets.iter().map(|target| {
            let endpoint =
                if self.secret.is_some() { format!("bot/{target}/message") } else { format!("chat/{target}") };
            let mut req = ctx
                .post(format!("{}/ocs/v2.php/apps/spreed/api/v1/{endpoint}", self.base))
                .header("OCS-APIRequest", "true")
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .headers(self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())));
            match &self.secret {
                Some(secret) => {
                    let random = ctx.env().random_hex(32);
                    let sig = hex(&hmac_sha256(secret.expose().as_bytes(), format!("{random}{message}").as_bytes()));
                    req = req
                        .set_header("X-Nextcloud-Talk-Bot-Random", random)
                        .set_header("X-Nextcloud-Talk-Bot-Signature", sig);
                }
                None => req = req.basic_auth(&self.user, Some(self.password.expose())),
            }
            Plan::send_expect(req.json(&payload), &[200, 201]).target(target.clone())
        }))
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_hmac_sha256_hex() {
        // HMAC-SHA256 with key "secret" over "abc" + "hello", hex-encoded.
        let sig = hex(&hmac_sha256(b"secret", b"abchello"));
        assert_eq!(sig, "6b845e7932547a86c42b79e9c3e42fdad359332333973361704ced054df7e539");
    }
}
