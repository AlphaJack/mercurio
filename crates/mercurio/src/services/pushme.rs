//! PushMe (`pushme://`): push notifications through PushMe.

use crate::parse::validate_nonblank;
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::{ParsedUrl, unquote};
use crate::{NotifyFormat, Plan, Prepared, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "pushme",
    name: "PushMe",
    schemes: &["pushme"],
    service_url: "https://push.i-i.me/",
    parse,
    templates: &[
        "{schema}://{token}",
    ],
    tokens: &[
        Param::new("token", "Token").required().secret(),
    ],
    params: &[
        Param::new("status", "Show Status").bool(true),
        Param::sets("token", &["token"]).aliases(&["push_key"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://push.i-i.me/";

#[derive(Debug)]
struct PushMe {
    token: Secret,
    status: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let token = if let Some(t) = u.param_nonempty("token") {
        unquote(t)
    } else if let Some(t) = u.param_nonempty("push_key") {
        unquote(t)
    } else {
        u.host()
    };
    let token = validate_nonblank(&token).ok_or_else(|| SERVICE.err("an invalid PushMe Token was specified"))?;
    Ok(Box::new(PushMe { token: Secret::new(token), status: SERVICE.flag(u, "status") }))
}

impl Notify for PushMe {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let title =
            if self.status { format!("{} {}", ctx.asset.ascii(msg.kind), msg.title) } else { msg.title.to_owned() };
        let kind = if msg.format == NotifyFormat::Markdown { "markdown" } else { "text" };
        let params = [("push_key", self.token.expose()), ("title", &title), ("content", msg.body), ("type", kind)];
        let req = ctx.post(NOTIFY_URL).query(&params);
        Plan::send_expect(req, &[200])
    }
}
