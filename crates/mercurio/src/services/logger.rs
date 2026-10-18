//! Logger (`logger://`): writes the notification to the `log` facade at info level.

use crate::service::{Context, Limits, Notify, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "logger",
    name: "Logger",
    schemes: &["logger"],
    service_url: "",
    parse,
    limits: Limits { title_maxlen: 250, body_maxlen: 32768, body_max_line_count: 0 },
    templates: &[
        "logger://",
    ],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct Logger;

fn parse(_: &ParsedUrl) -> Result<Box<dyn Notify>> {
    Ok(Box::new(Logger))
}

impl Notify for Logger {
    fn plan(&self, msg: &Prepared<'_>, _: &Context<'_>) -> Plan {
        if msg.title.is_empty() {
            log::info!(target: "mercurio::logger", "{}", msg.body);
        } else {
            log::info!(target: "mercurio::logger", "{}: {}", msg.title, msg.body);
        }
        Plan::Done
    }
}
