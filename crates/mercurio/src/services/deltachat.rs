//! Delta Chat (`deltachat://`, `deltachats://`): messages to Delta Chat users as e-mail, delivered with a `Chat-Version: 1.0` header, plain-text bodies and a `Chat: <excerpt>` subject built from the body (the title is merged into the body).
//!
//! # Differences with Apprise
//!
//! - PGP works as for `email` (feature `service-deltachat-pgp`), with the subject `Chat:` when signing and `Chat: Encrypted message` when encrypting, the Autocrypt header and key generation included.

use crate::service::{Limits, Notify, Param, ServiceDef};
use crate::services::_mail::email::{Email, Flavor};
use crate::url::ParsedUrl;
use crate::{NotifyFormat, Result};

pub(crate) static SERVICE: ServiceDef = ServiceDef {
    id: "deltachat",
    name: "Delta Chat",
    schemes: &["deltachat", "deltachats"],
    service_url: "https://delta.chat/",
    parse,
    limits: Limits { title_maxlen: 0, ..Limits::DEFAULT },
    formats: &[NotifyFormat::Text],
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
        Param::new("pgp", "PGP Security Mode").choice(&["no", "sign", "encrypt"]).default("no").note("`sign`: Ed25519 or RSA (2048 to 8192 bits) private key; `encrypt`: cv25519 or RSA public key; without the `service-deltachat-pgp` feature a PGP mode fails with `Unsupported`"),
        Param::new("pgpprv", "PGP Private Key Path").secret().note("path, `file://` or `http(s)://`; default: the storage folder"),
        Param::new("pgppub", "PGP Public Key Path").secret().note("path, `file://` or `http(s)://`; default: the storage folder"),
        Param::new("reply", "Reply To").list(", "),
        Param::new("smtp", "SMTP Server"),
        Param::new("to", "To Email"),
        Param::new("wkd", "Web Key Directory").bool(false),
        Param::new("headers", "Email Header").prefix("+"),
    ],
    ..ServiceDef::DEFAULTS
};

fn parse(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    Ok(Box::new(Email::from_url(u, &SERVICE, Flavor::DeltaChat)?))
}
