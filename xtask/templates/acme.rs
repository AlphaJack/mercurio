//! Acme (`acme://`): TODO one line on what it sends where.

use serde_json::json;

use crate::service::{Context, Notify, Param, Secret, ServiceDef};
use crate::url::ParsedUrl;
use crate::{Plan, Prepared, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "acme",
    name: "Acme",
    schemes: &["acme"],
    service_url: "https://example.com",
    parse,
    templates: &["{schema}://{token}"],
    tokens: &[Param::new("token", "Token").required().secret()],
    params: &[],
    ..ServiceDef::DEFAULTS
};

#[derive(Debug)]
struct AcmeService {
    token: Secret,
}

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let token = u.host().to_string();
    if token.is_empty() {
        return Err(SERVICE.err("no token was specified"));
    }
    Ok(Box::new(AcmeService { token: Secret::new(token) }))
}

impl Notify for AcmeService {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        let req = ctx
            .post("https://example.com/api/send")
            .header("Authorization", format!("Bearer {}", self.token.expose()))
            .json(&json!({"title": msg.title, "message": msg.body}));
        Plan::send_expect(req, &[200])
    }
}
