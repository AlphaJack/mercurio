//! Zulip (`zulip://`): messages to Zulip streams and users through a bot.

use crate::parse::{is_email, parse_list, validate_regex};
use crate::service::{Context, Limits, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "zulip",
    name: "Zulip",
    schemes: &["zulip"],
    service_url: "https://zulipchat.com/",
    parse,
    limits: Limits { title_maxlen: 60, body_maxlen: 10000, body_max_line_count: 0 },
    templates: &[
        "{schema}://{botname}@{organization}/{token}",
        "{schema}://{botname}@{organization}/{token}/{targets}",
    ],
    tokens: &[
        Param::new("botname", "Bot Name").required().pattern("^[A-Z0-9_-]{1,32}$"),
        Param::new("organization", "Organization").required().pattern("^[A-Z0-9_-]{1,32}$"),
        Param::new("target_stream", "Target Stream"),
        Param::new("target_user", "Target User").email(),
        Param::new("targets", "Targets").list("/").group(&["target_stream", "target_user"]),
        Param::new("token", "Token").required().secret().pattern("^[A-Z0-9]{32}$"),
    ],
    params: &[
        Param::sets("to", &["targets"]),
        Param::sets("token", &["token"]),
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Zulip {
    botname: String,
    organization: String,
    hostname: String,
    token: Secret,
    targets: Vec<String>,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    let token = if let Some(t) = u.param_nonempty("token") {
        Some(unquote(t))
    } else if !targets.is_empty() {
        Some(targets.remove(0))
    } else {
        None
    };
    if let Some(to) = u.param_nonempty("to") {
        let delim = crate::regex!(r"[ \t\r\n,#\\/]+");
        targets.extend(delim.split(&unquote(to)).filter(|s| !s.is_empty()).map(str::to_string));
    }

    let botname = u.user().unwrap_or_default();
    let bot_re = crate::regex!(r"(?i)^[A-Z0-9_-]{1,32}");
    let mut botname = bot_re
        .find(botname.trim())
        .map(|m| m.as_str().to_string())
        .ok_or_else(|| SERVICE.err("the Zulip botname specified is invalid"))?;
    if let Some(b) = botname.strip_suffix("-bot") {
        botname = b.to_string();
    }

    let org_re = crate::regex!(r"(?i)^(?P<org>[A-Z0-9_-]{1,32})(\.(?P<hostname>[^\s]+))?");
    let host = u.host();
    let c = org_re.captures(host.trim()).ok_or_else(|| SERVICE.err("the Zulip organization specified is invalid"))?;
    let organization = c["org"].to_string();
    let hostname = c.name("hostname").map_or("zulipchat.com", |m| m.as_str()).to_string();

    let token = token
        .as_deref()
        .and_then(|t| validate_regex(t, r"^[A-Z0-9]{32}$", "i", true))
        .ok_or_else(|| SERVICE.err("the Zulip token specified is invalid"))?;

    let mut targets = parse_list(targets);
    if targets.is_empty() {
        targets.push("general".into());
    }
    Ok(Box::new(Zulip { botname, organization, hostname, token: Secret::new(token), targets }))
}

impl Notify for Zulip {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let url = format!("https://{}.{}/api/v1/messages", self.organization, self.hostname);
        let user = format!("{}-bot@{}.{}", self.botname, self.organization, self.hostname);
        Plan::all(self.targets.iter().map(|target| {
            let (kind, to) = match is_email(target) {
                Some(e) => ("private", e.full_email),
                None => ("stream", target.clone()),
            };
            let req = ctx
                .post(&url)
                .header("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                .basic_auth(&user, Some(self.token.expose()))
                .form(&[("subject", msg.title), ("content", msg.body), ("type", kind), ("to", &to)]);
            Plan::send_expect(req, &[200]).target(target.clone())
        }))
    }

}
