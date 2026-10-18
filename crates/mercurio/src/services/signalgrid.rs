//! Signalgrid (`signalgrid://`): push notifications through Signalgrid.

use crate::parse::{parse_list, validate_nonblank};
use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Error, NotifyType, Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "signalgrid",
    name: "Signalgrid",
    schemes: &["signalgrid"],
    service_url: "https://signalgrid.co/",
    parse,
    templates: &[
        "{schema}://{client_key}/{targets}",
    ],
    tokens: &[
        Param::new("client_key", "Client Key").required().secret(),
        Param::new("targets", "Channels").list("/"),
    ],
    params: &[
        Param::sets("client_key", &["client_key"]),
        Param::new("critical", "Critical Notification").bool(false),
        Param::sets("to", &["targets"]),
    ],
    ..ServiceDef::DEFAULTS
};

const NOTIFY_URL: &str = "https://api.signalgrid.co/v1/push";

#[derive(Debug)]
struct Signalgrid {
    client_key: Secret,
    targets: Vec<String>,
    critical: bool,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let mut targets = u.path_segments();
    if let Some(to) = u.param_nonempty("to") {
        targets.extend(parse_list([to]));
    }
    let client_key = SERVICE.text(u, "client_key").unwrap_or_else(|| u.host());
    let client_key =
        validate_nonblank(&client_key).ok_or_else(|| SERVICE.err("an invalid Signalgrid Client Key was specified"))?;
    Ok(Box::new(Signalgrid {
        client_key: Secret::new(client_key),
        targets: parse_list(targets),
        critical: SERVICE.flag(u, "critical"),
    }))
}

impl Notify for Signalgrid {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Service("there are no Signalgrid channels to notify".into()));
        }
        let kind = match msg.kind {
            NotifyType::Info => "INFO",
            NotifyType::Success => "SUCCESS",
            NotifyType::Warning => "WARN",
            NotifyType::Failure => "CRIT",
        };
        Plan::all(self.targets.iter().map(|channel| {
            let form = [
                ("client_key", self.client_key.expose()),
                ("channel", channel.as_str()),
                ("title", msg.title),
                ("body", msg.body),
                ("type", kind),
                ("critical", if self.critical { "true" } else { "false" }),
            ];
            let req = ctx.post(NOTIFY_URL).form(&form);
            Plan::send_expect(req, &[200]).target(channel.clone())
        }))
    }

}
