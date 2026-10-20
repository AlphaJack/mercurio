//! E-Mail (`mailto://`, `mailtos://`): sends the notification as e-mail over SMTP.
//!
//! SMTP with STARTTLS or implicit TLS, AUTH CRAM-MD5/PLAIN/LOGIN, the provider template table (Gmail, Outlook, Yahoo, ...), To/Cc/Bcc/Reply-To, HTML + text `multipart/alternative`, attachments (inline with `?inline=yes`) and `?+X-Header=value`.
//!
//! # Differences with Apprise
//!
//! - PGP (`?pgp=sign|encrypt`, `?wkd=yes`) is validated like Apprise, but delivery fails with `Unsupported` before connecting (Apprise without PGPy fails after logging in). *todo*
//! - `?reply=` with several targets raised on the second target in Apprise -> mercurio sends it. *intentional*

use crate::service::{Notify, Param, ServiceDef};
use crate::services::_mail::email::{Email, Flavor};
use crate::url::ParsedUrl;
use crate::{NotifyFormat, Result};

pub static SERVICE: ServiceDef = ServiceDef {
    id: "email",
    name: "E-Mail",
    schemes: &["mailto", "mailtos"],
    service_url: "",
    parse,
    formats: &[NotifyFormat::Html, NotifyFormat::Text],
    attachments: true,
    templates: &[
        "{schema}://{host}",
        "{schema}://{host}:{port}",
        "{schema}://{host}:{port}/{targets}",
        "{schema}://{host}/{targets}",
        "{schema}://{user}@{host}",
        "{schema}://{user}@{host}/{targets}",
        "{schema}://{user}@{host}:{port}",
        "{schema}://{user}@{host}/{targets}",
        "{schema}://{user}@{host}:{port}/{targets}",
        "{schema}://{user}:{password}@{host}",
        "{schema}://{user}:{password}@{host}/{targets}",
        "{schema}://{user}:{password}@{host}:{port}",
        "{schema}://{user}:{password}@{host}:{port}/{targets}",
    ],
    tokens: &[
        Param::new("host", "Domain").required(),
        Param::new("password", "Password").secret(),
        Param::new("port", "Port").port(),
        Param::new("target_email", "Target Email"),
        Param::new("targets", "Targets").list("/").group(&["target_email"]),
        Param::new("user", "User Name"),
    ],
    params: &[
        Param::new("bcc", "Blind Carbon Copy").list(", "),
        Param::new("cc", "Carbon Copy").list(", "),
        Param::new("from", "From Email"),
        Param::new("inline", "Inline Attachments").bool(false),
        Param::new("mode", "Secure Mode").choice(&["starttls", "ssl", "insecure"]).default("starttls").inferred(),
        Param::new("name", "From Name"),
        Param::new("pgp", "PGP Security Mode").choice(&["no", "sign", "encrypt"]).default("no").note("validated, but a URL with a PGP mode fails at send time with `Unsupported` (mercurio has no OpenPGP)").inferred(),
        Param::new("reply", "Reply To").list(", "),
        Param::new("smtp", "SMTP Server"),
        Param::new("to", "To Email"),
        Param::new("wkd", "Web Key Directory").bool(false),
        Param::new("headers", "Email Header").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    Ok(Box::new(Email::from_url(u, &SERVICE, Flavor::Email)?))
}
