//! E-Mail (`mailto://`, `mailtos://`): sends the notification as e-mail over SMTP.
//!
//! SMTP with STARTTLS or implicit TLS, AUTH CRAM-MD5/PLAIN/LOGIN, the provider template table (Gmail, Outlook, Yahoo, ...), To/Cc/Bcc/Reply-To, HTML + text `multipart/alternative`, attachments (inline with `?inline=yes`) and `?+X-Header=value`.
//!
//! # Differences with Apprise
//!
//! - `?pgp=sign` (feature `service-email-pgp`) signs with Ed25519 keys (GnuPG's encoding) and RSA keys of 2048 to 8192 bits, while Apprise also accepts DSA, ECDSA and smaller RSA keys: mercurio's OpenPGP is its own, built on `ring`, and covers those two.
//! - `?pgp=encrypt` (and `?pgp=sign` when the recipient's key is at hand) encrypts to Curve25519 (`cv25519`) and RSA keys, without compression, while Apprise compresses the message (ZIP) and also encrypts to ECDH keys on the NIST, Brainpool and secp256k1 curves.
//! - `?wkd=yes` asks a recipient's Web Key Directory (RFC 9080) only when no key is in `?pgppub=` or the storage folder, as in Apprise, but asks both URLs at once, where Apprise tries the direct URL only after the `openpgpkey.` one fails; the `openpgpkey.` answer still wins.
//! - When encryption needs a key pair and none exists (a message to oneself, or the Autocrypt header advertising ours), mercurio generates an Ed25519 key with a Curve25519 encryption subkey, while Apprise generates RSA 2048 keys; both write `<local>-pub.asc` and `<local>-prv.asc` to the storage folder (`asset: pgp_autogen: no` turns it off).
//! - `?reply=` with several targets raised on the second target in Apprise, while mercurio sends it.

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
        Param::new("pgp", "PGP Security Mode").choice(&["no", "sign", "encrypt"]).default("no").note("`sign`: Ed25519 or RSA (2048 to 8192 bits) private key; `encrypt`: cv25519 or RSA public key; without the `service-email-pgp` feature a PGP mode fails with `Unsupported`").inferred(),
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
    Ok(Box::new(Email::from_url(u, &SERVICE, Flavor::Email)?))
}
