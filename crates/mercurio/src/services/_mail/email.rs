//! The e-mail engine shared by `email` and `deltachat`: URL parsing, provider templates, message building and SMTP delivery.

use std::sync::LazyLock;
use std::time::Duration;

use crate::re::Regex;

use super::mime::{Part, formataddr, header_value, render_owned};
use super::super::_keys::{local_file_ops, read_local_file, remote_fetches};
use super::smtp::{Envelope, Job, Security, session};
use crate::convert::html_to_text;
use crate::error::{Error, Result};
use crate::message::{NotifyFormat, Prepared};
use crate::parse::{is_email, is_hostname, is_ipaddr, parse_emails};
use crate::plan::Plan;
use crate::service::{Context, Notify, Secret, ServiceDef};
use crate::transport::{Endpoint, FileOp};
use crate::url::{ParsedUrl, unquote};

/// SMTP without TLS.
const SMTP_PORT: u16 = 25;
/// SMTP over TLS from the first byte.
const SMTPS_PORT: u16 = 465;
/// SMTP submission with STARTTLS.
const SUBMISSION_PORT: u16 = 587;

const SMTP_TIMEOUT: Duration = Duration::from_secs(15);

/// Which service this instance serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Email,
    DeltaChat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Insecure,
    Ssl,
    StartTls,
}

impl Mode {
    fn parse(s: &str) -> Option<Mode> {
        match s {
            "insecure" => Some(Mode::Insecure),
            "ssl" => Some(Mode::Ssl),
            "starttls" => Some(Mode::StartTls),
            _ => None,
        }
    }
    fn default_port(self) -> u16 {
        match self {
            Mode::Insecure => SMTP_PORT,
            Mode::Ssl => SMTPS_PORT,
            Mode::StartTls => SUBMISSION_PORT,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pgp {
    None,
    Sign,
    Encrypt,
}

const PGP_MODES: &[(&str, Pgp)] = &[("no", Pgp::None), ("sign", Pgp::Sign), ("encrypt", Pgp::Encrypt)];

/// Display name of an address: none, the asset `app_id` or text.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Name {
    None,
    AppId,
    Text(String),
}

impl Name {
    fn of(name: &str) -> Name {
        if name.is_empty() { Name::None } else { Name::Text(name.to_string()) }
    }
    fn resolve<'a>(&'a self, ctx: &'a Context<'_>) -> Option<&'a str> {
        match self {
            Name::None => None,
            Name::AppId => Some(ctx.app_id()),
            Name::Text(t) => Some(t),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Login {
    Email,
    UserId,
}

struct Template {
    pattern: &'static str,
    port: Option<u16>,
    smtp_host: Option<&'static str>,
    mode: Option<Mode>,
    login: &'static [Login],
    from_user: Option<&'static str>,
}

const fn provider(
    pattern: &'static str,
    port: u16,
    host: &'static str,
    mode: Mode,
    login: &'static [Login],
) -> Template {
    Template { pattern, port: Some(port), smtp_host: Some(host), mode: Some(mode), login, from_user: None }
}

const EMAIL: &[Login] = &[Login::Email];
const USERID: &[Login] = &[Login::UserId];

/// Provider templates, matched in order.
const TEMPLATES: &[Template] = &[
    provider(
        r"^((?P<label>[^+]+)\+)?(?P<id>[^@]+)@(?P<domain>gmail\.com)$",
        SUBMISSION_PORT,
        "smtp.gmail.com",
        Mode::StartTls,
        EMAIL,
    ),
    provider(
        r"^((?P<label>[^+]+)\+)?(?P<id>[^@]+)@(?P<domain>yandex\.(com|ru|ua|by|kz|uz|tr|fr))$",
        SMTPS_PORT,
        "smtp.yandex.ru",
        Mode::Ssl,
        USERID,
    ),
    provider(
        r"^((?P<label>[^+]+)\+)?(?P<id>[^@]+)@(?P<domain>(hotmail|live)\.com(\.au)?)$",
        SUBMISSION_PORT,
        "smtp-mail.outlook.com",
        Mode::StartTls,
        EMAIL,
    ),
    provider(
        r"^((?P<label>[^+]+)\+)?(?P<id>[^@]+)@(?P<domain>(smtp\.)?outlook\.com(\.au)?)$",
        SUBMISSION_PORT,
        "smtp.outlook.com",
        Mode::StartTls,
        EMAIL,
    ),
    provider(r"^[^@]+@(?P<domain>(smtp\.)?office365\.com)$", SUBMISSION_PORT, "smtp.office365.com", Mode::StartTls, &[]),
    provider(
        r"^((?P<label>[^+]+)\+)?(?P<id>[^@]+)@(?P<domain>yahoo\.(ca|com))$",
        SMTPS_PORT,
        "smtp.mail.yahoo.com",
        Mode::Ssl,
        EMAIL,
    ),
    provider(
        r"^((?P<label>[^+]+)\+)?(?P<id>[^@]+)@(?P<domain>gmx\.(com|net|de|at|ch|fr))$",
        SUBMISSION_PORT,
        "mail.gmx.com",
        Mode::StartTls,
        EMAIL,
    ),
    provider(
        r"^((?P<label>[^+]+)\+)?(?P<id>[^@]+)@(?P<domain>fastmail\.(com|cn|co\.uk|com\.au|de|es|fm|fr|im|in|jp|mx|net|nl|org|se|to|tw|uk|us))$",
        SMTPS_PORT,
        "smtp.fastmail.com",
        Mode::Ssl,
        EMAIL,
    ),
    provider(
        concat!(
            r"^((?P<label>[^+]+)\+)?(?P<id>[^@]+)@",
            r"(?P<domain>123mail\.org|airpost\.net|eml\.cc|fmail\.co\.uk|",
            r"fmgirl\.com|fmguy\.com|mailbolt\.com|mailcan\.com|",
            r"mailhaven\.com|mailmight\.com|ml1\.net|mm\.st|myfastmail\.com|",
            r"proinbox\.com|promessage\.com|rushpost\.com|sent\.(as|at|com)|",
            r"speedymail\.org|warpmail\.net|xsmail\.com|150mail\.com|",
            r"150ml\.com|16mail\.com|2-mail\.com|4email\.net|50mail\.com|",
            r"allmail\.net|bestmail\.us|cluemail\.com|elitemail\.org|",
            r"emailcorner\.net|emailengine\.(net|org)|emailgroups\.net|",
            r"emailplus\.org|emailuser\.net|f-m\.fm|fast-email\.com|",
            r"fast-mail\.org|fastem\.com|fastemail\.us|fastemailer\.com|",
            r"fastest\.cc|fastimap\.com|fastmailbox\.net|fastmessaging\.com|",
            r"fea\.st|fmailbox\.com|ftml\.net|h-mail\.us|hailmail\.net|",
            r"imap-mail\.com|imap\.cc|imapmail\.org|inoutbox\.com|",
            r"internet-e-mail\.com|internet-mail\.org|internetemails\.net|",
            r"internetmailing\.net|jetemail\.net|justemail\.net|",
            r"letterboxes\.org|mail-central\.com|mail-page\.com|",
            r"mailandftp\.com|mailas\.com|mailc\.net|mailforce\.net|",
            r"mailftp\.com|mailingaddress\.org|mailite\.com|mailnew\.com|",
            r"mailsent\.net|mailservice\.ms|mailup\.net|mailworks\.org|",
            r"mymacmail\.com|nospammail\.net|ownmail\.net|petml\.com|",
            r"postinbox\.com|postpro\.net|realemail\.net|reallyfast\.biz|",
            r"reallyfast\.info|speedpost\.net|ssl-mail\.com|swift-mail\.com|",
            r"the-fastest\.net|the-quickest\.com|theinternetemail\.com|",
            r"veryfast\.biz|veryspeedy\.net|yepmail\.net)$"
        ),
        SMTPS_PORT,
        "smtp.fastmail.com",
        Mode::Ssl,
        EMAIL,
    ),
    provider(
        r"^((?P<label>[^+]+)\+)?(?P<id>[^@]+)@(?P<domain>zoho(mail)?\.com)$",
        SUBMISSION_PORT,
        "smtp.zoho.com",
        Mode::StartTls,
        EMAIL,
    ),
    provider(
        r"^((?P<label>[^+]+)\+)?(?P<id>[^@]+)@(?P<domain>(\.smtp)?sendgrid\.(com|net))$",
        SMTPS_PORT,
        "smtp.sendgrid.net",
        Mode::Ssl,
        USERID,
    ),
    provider(r"^((?P<label>[^+]+)\+)?(?P<id>[^@]+)@(?P<domain>163\.com)$", SMTPS_PORT, "smtp.163.com", Mode::Ssl, EMAIL),
    provider(
        r"^((?P<label>[^+]+)\+)?(?P<id>[^@]+)@(?P<domain>(foxmail|qq)\.com)$",
        SUBMISSION_PORT,
        "smtp.qq.com",
        Mode::StartTls,
        EMAIL,
    ),
    provider(
        r"^((?P<label>[^+]+)\+)?(?P<id>[^@]+)@(?P<domain>(comcast)\.net)$",
        SMTPS_PORT,
        "smtp.comcast.net",
        Mode::Ssl,
        EMAIL,
    ),
    // Local mail server
    Template {
        pattern: r"^(((?P<label>[^+]+)\+)?(?P<id>[^@]+)@)?(?P<domain>localhost(\.localdomain)?)$",
        port: None,
        smtp_host: None,
        mode: None,
        login: &[],
        from_user: Some("root"),
    },
    // Catch all
    Template {
        pattern: r"^((?P<label>[^+]+)\+)?(?P<id>[^@]+)@(?P<domain>.+)$",
        port: None,
        smtp_host: None,
        mode: None,
        login: &[],
        from_user: None,
    },
];

/// One entry per `TEMPLATES` row; `None` would mark an invalid pattern (tests compile them all).
fn template_regexes() -> &'static [Option<Regex>] {
    static RES: LazyLock<Vec<Option<Regex>>> =
        LazyLock::new(|| TEMPLATES.iter().map(|t| Regex::new(&format!("(?i){}", t.pattern)).ok()).collect());
    &RES
}

/// A configured e-mail (or Delta Chat) target.
#[derive(Debug)]
pub struct Email {
    flavor: Flavor,
    user: Option<String>,
    password: Option<Secret>,
    smtp_host: String,
    port: u16,
    mode: Mode,
    from_name: Name,
    from_addr: String,
    targets: Vec<(Name, String)>,
    cc: Vec<String>,
    bcc: Vec<String>,
    reply_to: Vec<String>,
    names: Vec<(String, Name)>,
    headers: Vec<(String, String)>,
    pgp: Pgp,
    /// `?pgpprv=`: the private key's path or URL.
    pgp_prv: Option<String>,
    /// `?pgppub=`: the recipients' public key's path or URL.
    pgp_pub: Option<String>,
    /// `?wkd=yes`: look keys up in the recipient's Web Key Directory.
    use_wkd: bool,
    inline: bool,
}

/// Why signing failed, as Apprise words it.
const SIGN_FAILED: &str =
    "Unable to sign email via PGP; supply a private key via pgpprv= or place one in the cache directory";

/// Largest private key read (Apprise's `max_pgp_private_key_size`).
const MAX_PRIVATE_KEY: u64 = 32_000;

/// A key pair generated during a send, armored, to be written to the storage folder.
struct NewKey {
    email: String,
    public: String,
    secret: String,
}

/// Why encryption failed, as Apprise words it.
const ENCRYPT_FAILED: &str =
    "Unable to encrypt email via PGP; supply a public key via pgppub= or place one in the cache directory";

/// Largest public key read (Apprise's `max_pgp_public_key_size`).
const MAX_PUBLIC_KEY: u64 = 8_000;

/// How long a Web Key Directory answer is reused.
const WKD_CACHE: Duration = Duration::from_secs(86_400);

/// `re.split(r"[\s@]+", user)[0]`.
fn user_prefix(user: &str) -> &str {
    user.split(|c: char| c.is_whitespace() || c == '@').next().unwrap_or("")
}

fn insert_unique(v: &mut Vec<String>, s: String) {
    if !v.contains(&s) {
        v.push(s);
    }
}

fn set_name(names: &mut Vec<(String, Name)>, addr: &str, name: Name) {
    match names.iter_mut().find(|(a, _)| a == addr) {
        Some(entry) => entry.1 = name,
        None => names.push((addr.to_string(), name)),
    }
}

/// Public key file names in the storage folder for `to`, best first (Apprise's `_pub_key_candidates`).
fn public_key_names(to: &str) -> Vec<String> {
    let mut names = vec![
        format!("{}-pub.asc", to.to_lowercase()),
        format!("{}-pub.asc", to.split('@').next().unwrap_or("").to_lowercase()),
    ];
    names.extend(["pgp-public.asc", "pgp-pub.asc", "public.asc", "pub.asc"].map(String::from));
    names
}

/// Private key file names in the storage folder, best first (Apprise's `_prv_key_candidates`).
fn private_key_names(from: &str) -> Vec<String> {
    let mut names = Vec::new();
    if !from.is_empty() {
        names.push(format!("{}-prv.asc", from.to_lowercase()));
        names.push(format!("{}-prv.asc", from.split('@').next().unwrap_or("").to_lowercase()));
    }
    names.extend(["pgp-private.asc", "pgp-prv.asc", "private.asc", "prv.asc"].map(String::from));
    names
}

/// `prefix match` over `PGP_MODES` ("e", "en", ... are accepted).
fn pgp_prefix(s: &str) -> Option<Pgp> {
    let s = s.to_lowercase();
    PGP_MODES.iter().find(|(m, _)| m.starts_with(&s)).map(|(_, p)| *p)
}

impl Email {
    /// Parse and validate an email URL.
    pub fn from_url(u: &ParsedUrl, def: &'static ServiceDef, flavor: Flavor) -> Result<Email> {
        let mut targets_raw: Vec<String> = Vec::new();
        let mut host_raw = u.host.clone();
        if is_ipaddr(&host_raw, true, true).is_some() {
        } else if is_hostname(&host_raw, false, false, false).is_none() {
            let h = unquote(&host_raw);
            if is_email(&h).is_some() {
                targets_raw.push(h);
            }
            host_raw.clear();
        }

        let mut pgp_arg: Option<String> = None;
        if let Some(raw) = u.param_nonempty("pgp") {
            pgp_arg = Some(match pgp_prefix(raw) {
                Some(Pgp::None) => "no".into(),
                Some(Pgp::Sign) => "sign".into(),
                Some(Pgp::Encrypt) => "encrypt".into(),
                None => raw.to_string(),
            });
        }
        let use_wkd = def.flag_strict(u, "wkd");
        if use_wkd && pgp_arg.is_none() {
            pgp_arg = Some("encrypt".into());
        }
        let inline = def.flag_strict(u, "inline");

        targets_raw.extend(u.path_segments());
        if let Some(to) = u.param_nonempty("to") {
            targets_raw.push(to.to_string());
        }
        let mut from_arg = String::new();
        if let Some(from) = u.param_nonempty("from") {
            from_arg = unquote(from);
            if let Some(name) = u.param_nonempty("name") {
                from_arg = formataddr(&unquote(name), &from_arg);
            }
        } else if let Some(name) = u.param_nonempty("name") {
            from_arg = unquote(name);
        }
        let mut smtp_host = def.text(u, "smtp").unwrap_or_default();
        let mode_arg = u.param_nonempty("mode").map(str::to_lowercase);
        let cc_raw = u.param_nonempty("cc");
        let bcc_raw = u.param_nonempty("bcc");
        let reply_raw = u.param_nonempty("reply");
        let headers: Vec<(String, String)> = u.query_plus.iter().map(|(k, v)| (unquote(k), unquote(v))).collect();

        let mut user = u.user();
        let password = u.password();
        let mut host = unquote(&host_raw);
        let port_arg = u.port.filter(|p| *p != 0);
        let mut port = port_arg;
        let mut mode = match &mode_arg {
            Some(m) => Mode::parse(m),
            None if u.secure => Some(Mode::StartTls),
            None => Some(Mode::Insecure),
        }
        .ok_or_else(|| {
            def.err(format!("the secure mode specified ({}) is invalid", mode_arg.as_deref().unwrap_or("")))
        })?;

        let mut names: Vec<(String, Name)> = Vec::new();
        let mut collect = |raw: Option<&str>, out: &mut Vec<String>| {
            for r in parse_emails(raw, true) {
                if let Some(e) = is_email(&r) {
                    insert_unique(out, e.full_email.clone());
                    set_name(&mut names, &e.full_email, Name::of(&e.name));
                }
            }
        };
        let (mut cc, mut bcc, mut reply_to) = (Vec::new(), Vec::new(), Vec::new());
        collect(cc_raw, &mut cc);
        collect(bcc_raw, &mut bcc);
        collect(reply_raw, &mut reply_to);

        let mut from_name = Name::None;
        let mut from_addr = String::new();
        if smtp_host.is_empty() {
            let probe = match user.as_deref().filter(|u| !u.is_empty()) {
                Some(u) => format!("{}@{}", user_prefix(u), host),
                None => host.clone(),
            };
            for (t, re) in TEMPLATES.iter().zip(template_regexes()) {
                let Some(caps) = re.as_ref().and_then(|re| re.captures(&probe)) else { continue };
                if let Some(h) = t.smtp_host {
                    smtp_host = h.to_string();
                }
                if port_arg.is_none()
                    && let Some(p) = t.port
                {
                    port = Some(p);
                }
                if mode_arg.is_none()
                    && let Some(m) = t.mode
                {
                    mode = m;
                }
                if !t.login.is_empty() {
                    let current = user.clone().unwrap_or_default();
                    if user.as_deref().is_some_and(|u| is_email(u).is_some()) {
                        if !t.login.contains(&Login::Email) {
                            user = caps.name("id").map(|m| m.as_str().to_string());
                        } else if let Some((_, domain)) = current.split_once('@') {
                            host = domain.split('@').next().unwrap_or("").to_string();
                        }
                    } else if !t.login.contains(&Login::UserId) {
                        let name = user.clone().unwrap_or_default();
                        user = Some(format!("{name}@{host}"));
                    }
                }
                if let Some(fu) = t.from_user {
                    from_addr = format!("{fu}@{host}");
                }
                break;
            }
        }

        if let Some(u) = user.as_deref().filter(|u| !u.is_empty()) {
            if !host.is_empty() {
                from_name = Name::AppId;
                from_addr = format!("{}@{}", user_prefix(u), host);
            } else if let Some(r) = is_email(u) {
                host = r.domain;
                from_name = Name::AppId;
                from_addr = u.to_string();
            }
        }
        if !from_arg.is_empty() {
            match is_email(&from_arg) {
                Some(r) => {
                    from_name = Name::of(&r.name);
                    from_addr = r.full_email;
                }
                None => from_name = Name::Text(from_arg.clone()),
            }
        }
        if is_email(&from_addr).is_none() {
            return Err(def.err("an invalid ~From~ email was specified"));
        }
        set_name(&mut names, &from_addr, from_name.clone());

        let mut targets = Vec::new();
        if !targets_raw.is_empty() {
            for r in parse_emails(&targets_raw, true) {
                if let Some(e) = is_email(&r) {
                    targets.push((Name::of(&e.name), e.full_email));
                }
            }
        } else {
            targets.push((Name::None, from_addr.clone()));
        }

        let port = port.unwrap_or_else(|| mode.default_port());
        if smtp_host.is_empty() {
            smtp_host = host;
        }

        let pgp = match pgp_arg.as_deref() {
            None | Some("") => Pgp::None,
            Some(s) if s.eq_ignore_ascii_case("none") => Pgp::None,
            Some(s) => {
                pgp_prefix(s).ok_or_else(|| def.err(format!("the Email PGP mode specified ({s}) is invalid")))?
            }
        };

        Ok(Email {
            flavor,
            user,
            password: password.map(Secret::new),
            smtp_host,
            port,
            mode,
            from_name,
            from_addr,
            targets,
            cc,
            bcc,
            reply_to,
            names,
            headers,
            pgp,
            pgp_prv: def.text(u, "pgpprv"),
            pgp_pub: def.text(u, "pgppub"),
            use_wkd,
            inline,
        })
    }

    fn name_of(&self, addr: &str) -> &Name {
        self.names.iter().find(|(a, _)| a == addr).map(|(_, n)| n).unwrap_or(&Name::None)
    }

    /// Delta Chat `_chat_subject` (PGP modes never reach delivery here).
    fn chat_subject(body: &str) -> String {
        let excerpt: Vec<&str> = body.split_whitespace().collect();
        let excerpt = excerpt.join(" ");
        let excerpt = if excerpt.chars().count() > 50 {
            format!("{}...", excerpt.chars().take(50).collect::<String>())
        } else {
            excerpt
        };
        if excerpt.is_empty() { "Chat:".into() } else { format!("Chat: {excerpt}") }
    }

    /// Whether this build signs and encrypts for this flavor.
    fn pgp_built(&self) -> bool {
        match self.flavor {
            Flavor::Email => cfg!(feature = "service-email-pgp"),
            Flavor::DeltaChat => cfg!(feature = "service-deltachat-pgp"),
        }
    }

    /// Private key files to look at: `?pgpprv=`, else Apprise's names in the storage folder.
    fn private_key_specs(&self, ctx: &Context<'_>) -> Vec<String> {
        if let Some(spec) = &self.pgp_prv {
            return vec![spec.clone()];
        }
        let Some(dir) = ctx.store.path() else { return Vec::new() };
        private_key_names(&self.from_addr).iter().map(|n| dir.join(n).display().to_string()).collect()
    }

    /// Public key files to look at for `to`: `?pgppub=`, else Apprise's names in the storage folder.
    fn public_key_specs(&self, ctx: &Context<'_>, to: &str) -> Vec<String> {
        if let Some(spec) = &self.pgp_pub {
            return vec![spec.clone()];
        }
        let Some(dir) = ctx.store.path() else { return Vec::new() };
        public_key_names(to).iter().map(|n| dir.join(n).display().to_string()).collect()
    }

    /// The first public key for `to` that could be read.
    fn public_key<'a>(&self, ctx: &Context<'a>, to: &str) -> Option<std::borrow::Cow<'a, [u8]>> {
        if let Some(key) = self.local_public_key(ctx, to) {
            return Some(std::borrow::Cow::Borrowed(key));
        }
        self.wkd_key(ctx, to).map(std::borrow::Cow::Owned)
    }

    /// The public key for `to` from `?pgppub=` or the storage folder.
    fn local_public_key<'a>(&self, ctx: &Context<'a>, to: &str) -> Option<&'a [u8]> {
        self.public_key_specs(ctx, to).iter().find_map(|spec| read_local_file(ctx, spec, MAX_PUBLIC_KEY))
    }

    /// The store entry keeping `to`'s Web Key Directory answer for a day (Apprise's `default_cache_expiry_sec`).
    fn wkd_cache_key(to: &str) -> String {
        format!("wkd_{}", to.trim().to_lowercase())
    }

    /// `to`'s key from its Web Key Directory: the cached answer, else the advanced URL's, else the direct URL's (HTTP 200, not empty, at most 64 KiB).
    #[cfg(any(feature = "service-email-pgp", feature = "service-deltachat-pgp"))]
    fn wkd_key(&self, ctx: &Context<'_>, to: &str) -> Option<Vec<u8>> {
        if !self.use_wkd {
            return None;
        }
        let cache = Self::wkd_cache_key(to);
        if let Some(b64) = ctx.store.get_str(&cache) {
            return crate::crypto::b64_decode(&b64);
        }
        let (advanced, direct) = super::pgp::wkd::urls(to)?;
        let key = [advanced, direct]
            .iter()
            .find_map(|url| ctx.fetched(url).ok().filter(|b| !b.is_empty() && b.len() <= super::pgp::wkd::MAX_RESPONSE))?
            .to_vec();
        ctx.store.remember(&cache, serde_json::json!(crate::crypto::b64(&key)), Some(WKD_CACHE));
        Some(key)
    }

    #[cfg(not(any(feature = "service-email-pgp", feature = "service-deltachat-pgp")))]
    fn wkd_key(&self, _: &Context<'_>, _: &str) -> Option<Vec<u8>> {
        None
    }

    /// The first private key that could be read, without a warning when there is none (the Autocrypt header is optional).
    fn private_key_quiet<'a>(&self, ctx: &Context<'a>) -> Option<&'a [u8]> {
        self.private_key_specs(ctx).iter().find_map(|spec| read_local_file(ctx, spec, MAX_PRIVATE_KEY))
    }

    /// The first private key that could be read.
    fn private_key<'a>(&self, ctx: &Context<'a>) -> Option<&'a [u8]> {
        let key = self.private_key_quiet(ctx);
        if key.is_none() {
            crate::warning!("{}", if self.pgp_prv.is_some() { "PGP Private Key could not be accessed" } else { "No PGP private key found" });
        }
        key
    }

    /// `prepare_emails`: one message per `To` target.
    fn prepare(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Result<(Vec<Envelope>, Option<NewKey>)> {
        let mut new_key: Option<NewKey> = None;
        let format = if self.flavor == Flavor::DeltaChat { NotifyFormat::Text } else { msg.format };
        let subject = match (self.flavor, self.pgp) {
            // A signed message must not show its content in the subject either.
            (Flavor::DeltaChat, Pgp::Sign) => "Chat:".to_string(),
            // Delta Chat's placeholder when the subject is not carried inside the encryption.
            (Flavor::DeltaChat, Pgp::Encrypt) => "Chat: Encrypted message".to_string(),
            (Flavor::DeltaChat, Pgp::None) => Self::chat_subject(msg.body),
            (Flavor::Email, _) => msg.title.to_string(),
        };
        let subject: String = subject.split_whitespace().collect::<Vec<_>>().join(" ");
        let msgid_host = if self.smtp_host.is_empty() {
            self.from_addr.split('@').nth(1).unwrap_or("localhost").to_string()
        } else {
            self.smtp_host.clone()
        };
        // headers map: X-Application, user headers, protocol headers (later keys replace values).
        let mut extra: Vec<(String, String)> = vec![("X-Application".into(), ctx.app_id().to_string())];
        let mut put = |k: &str, v: &str| match extra.iter_mut().find(|(ek, _)| ek == k) {
            Some(e) => e.1 = v.to_string(),
            None => extra.push((k.to_string(), v.to_string())),
        };
        for (k, v) in &self.headers {
            put(k, v);
        }
        if self.flavor == Flavor::DeltaChat {
            put("Chat-Version", "1.0");
        }
        let from_hdr = formataddr(self.from_name.resolve(ctx).unwrap_or(""), &self.from_addr);
        let fmt_addr = |a: &String| formataddr(self.name_of(a).resolve(ctx).unwrap_or(""), a);

        let mut out = Vec::new();
        for (to_name, to_addr) in &self.targets {
            let cc: Vec<&String> = self.cc.iter().filter(|a| !self.bcc.contains(a) && *a != to_addr).collect();
            let bcc: Vec<&String> = self.bcc.iter().filter(|a| *a != to_addr).collect();
            let reply: Vec<&String> = self.reply_to.iter().filter(|a| *a != to_addr).collect();

            // Borrowed until the inline-image handling below has to add to it: the body can be megabytes.
            let mut body: std::borrow::Cow<'_, str> = std::borrow::Cow::Borrowed(msg.body);
            let mut cid_refs: Vec<String> = Vec::new();
            let att_name =
                |i: usize, n: &str| if n.is_empty() { format!("file{:03}.dat", i + 1) } else { n.to_string() };
            if self.inline && !msg.attachments.is_empty() {
                if format == NotifyFormat::Html {
                    let re = crate::regex!(r#"cid:([^\s"'>\)]+)"#);
                    let names: Vec<String> =
                        msg.attachments.iter().enumerate().map(|(i, a)| att_name(i, &a.name)).collect();
                    for m in re.captures_iter(&body) {
                        let r = m[1].replace("%20", " ");
                        if names.contains(&r) && !cid_refs.contains(&r) {
                            cid_refs.push(r);
                        }
                    }
                    let mut appends = Vec::new();
                    for (i, a) in msg.attachments.iter().enumerate() {
                        let n = att_name(i, &a.name);
                        if a.mime.to_lowercase().starts_with("image/") && !cid_refs.contains(&n) {
                            appends.push(n.clone());
                            cid_refs.push(n);
                        }
                    }
                    for n in appends {
                        body.to_mut().push_str(&format!("<br/><img src=\"cid:{}\">", n.replace(' ', "%20")));
                    }
                } else {
                    let imgs: Vec<String> = msg
                        .attachments
                        .iter()
                        .enumerate()
                        .filter(|(_, a)| a.mime.to_lowercase().starts_with("image/"))
                        .map(|(i, a)| format!("[Image: {}]", att_name(i, &a.name)))
                        .collect();
                    if !imgs.is_empty() {
                        body = std::borrow::Cow::Owned(format!("{body}\n{}", imgs.join("\n")));
                    }
                }
            }

            let mut base = if format == NotifyFormat::Html {
                Part::multi("alternative", vec![Part::text("plain", html_to_text(&body)), Part::text("html", &*body)])
            } else {
                Part::text("plain", &*body)
            };
            if !msg.attachments.is_empty() {
                let mut parts = vec![base];
                for (i, a) in msg.attachments.iter().enumerate() {
                    let n = att_name(i, &a.name);
                    let part = if cid_refs.contains(&n) {
                        Part::file(&a.mime, &a.data, "inline", &n, Some(n.replace(' ', "%20")))
                    } else {
                        Part::file(&a.mime, &a.data, "attachment", &n, None)
                    };
                    parts.push(part);
                }
                base = Part::multi(if cid_refs.is_empty() { "mixed" } else { "related" }, parts);
            }

            let (protected, autocrypt) = self.protect(base, ctx, to_addr, &subject, &mut new_key)?;
            base = protected;

            let mut headers: Vec<(String, String)> = Vec::new();
            // Our own Autocrypt header comes first and replaces one from `?+Autocrypt=`.
            let mut autocrypt_seen = autocrypt.is_some();
            if let Some(value) = autocrypt {
                headers.push(("Autocrypt".into(), value));
            }
            for (k, v) in &extra {
                let name: String = k.chars().filter(|c| c.is_ascii_graphic() && *c != ':').collect();
                if name.is_empty() {
                    continue;
                }
                if name.eq_ignore_ascii_case("autocrypt") {
                    if autocrypt_seen {
                        continue;
                    }
                    autocrypt_seen = true;
                }
                headers.push((name, header_value(v)));
            }
            headers.push(("Subject".into(), header_value(&subject)));
            headers.push(("From".into(), from_hdr.clone()));
            headers.push(("To".into(), formataddr(to_name.resolve(ctx).unwrap_or(""), to_addr)));
            headers.push(("Message-ID".into(), format!("<{}@{}>", ctx.env().random_hex(16), msgid_host)));
            headers.push(("Date".into(), crate::time::rfc2822_in(ctx.env().unix_time(), &ctx.time_zone())));
            if !self.cc.is_empty() {
                headers.push(("Cc".into(), cc.iter().map(|a| fmt_addr(a)).collect::<Vec<_>>().join(",")));
            }
            if !reply.is_empty() {
                headers.push(("Reply-To".into(), reply.iter().map(|a| fmt_addr(a)).collect::<Vec<_>>().join(",")));
            }

            let mut recipients = vec![to_addr.clone()];
            recipients.extend(cc.iter().map(|a| (*a).clone()));
            recipients.extend(bcc.iter().map(|a| (*a).clone()));
            out.push(Envelope { from: self.from_addr.clone(), recipients, data: render_owned(&headers, base, ctx.env().as_ref()) });
        }
        Ok((out, new_key))
    }

    /// PGP for one recipient: `base` signed and/or encrypted as `?pgp=` says, and the Autocrypt header advertising our key. A key pair is generated (into `new_key`, once) when encrypting to oneself or advertising needs one and `pgp_autogen` allows it.
    #[cfg(any(feature = "service-email-pgp", feature = "service-deltachat-pgp"))]
    fn protect<'a>(
        &self,
        base: Part<'a>,
        ctx: &Context<'_>,
        to_addr: &str,
        subject: &str,
        new_key: &mut Option<NewKey>,
    ) -> Result<(Part<'a>, Option<String>)> {
        use std::borrow::Cow;
        // Apprise generates keys only into its storage folder and never next to an explicit `?pgppub=`.
        let autogen = ctx.asset.pgp_autogen && self.pgp_pub.is_none() && ctx.store.path().is_some();
        let base = match self.pgp {
            Pgp::None => return Ok((base, None)),
            Pgp::Sign => {
                // Signed, then encrypted too when the recipient's key is at hand.
                let signed = self.signed(base, ctx)?;
                match self.public_key(ctx, to_addr) {
                    Some(key) => {
                        let content = super::mime::render_part_alone(&signed, ctx.env().as_ref());
                        self.encrypted(&key, &content, ctx).unwrap_or(signed)
                    }
                    None => signed,
                }
            }
            Pgp::Encrypt => {
                // The From, To and Subject travel inside the encryption too.
                let inner = super::mime::render_part_alone(&base, ctx.env().as_ref());
                let protected =
                    format!("From: {}\r\nTo: {}\r\nSubject: {}\r\n", self.from_addr, to_addr, header_value(subject));
                let content = match inner.split_once("\r\n\r\n") {
                    Some((head, body)) => format!("{head}\r\n{protected}\r\n{body}"),
                    None => inner,
                };
                let key = match self.public_key(ctx, to_addr) {
                    Some(key) => key,
                    // A message to oneself may use a new key.
                    None if autogen && to_addr.eq_ignore_ascii_case(&self.from_addr) => {
                        let generated = self.generate(ctx, new_key).ok_or_else(|| Error::Service(ENCRYPT_FAILED.into()))?;
                        Cow::Owned(generated.public.clone().into_bytes())
                    }
                    None => {
                        crate::warning!("{}", if self.pgp_pub.is_some() { "PGP Public Key could not be accessed" } else { "No PGP public key found" });
                        return Err(Error::Service(ENCRYPT_FAILED.into()));
                    }
                };
                self.encrypted(&key, &content, ctx)?
            }
        };
        let secret = match self.private_key_quiet(ctx) {
            Some(key) => Some(Cow::Borrowed(key)),
            None if autogen => self.generate(ctx, new_key).map(|g| Cow::Owned(g.secret.clone().into_bytes())),
            None => None,
        };
        let autocrypt = secret.and_then(|key| super::pgp::autocrypt_header(&self.from_addr, &key));
        Ok((base, autocrypt))
    }

    /// The key pair generated for this send (Ed25519 and Curve25519, named after the app id and the sender), made once.
    #[cfg(any(feature = "service-email-pgp", feature = "service-deltachat-pgp"))]
    fn generate<'k>(&self, ctx: &Context<'_>, new_key: &'k mut Option<NewKey>) -> Option<&'k NewKey> {
        if new_key.is_none() {
            let g = super::pgp::generate(ctx.app_id(), &self.from_addr, ctx.env().as_ref())?;
            *new_key = Some(NewKey { email: self.from_addr.clone(), public: g.public, secret: g.secret.to_string() });
        }
        new_key.as_ref()
    }

    #[cfg(not(any(feature = "service-email-pgp", feature = "service-deltachat-pgp")))]
    fn protect<'a>(
        &self,
        base: Part<'a>,
        _: &Context<'_>,
        _: &str,
        _: &str,
        _: &mut Option<NewKey>,
    ) -> Result<(Part<'a>, Option<String>)> {
        match self.pgp {
            Pgp::None => Ok((base, None)),
            Pgp::Sign | Pgp::Encrypt => Err(Error::Unsupported("PGP is not compiled in".into())),
        }
    }

    /// Write a generated key pair as Apprise names it, `<local>-pub.asc` and `<local>-prv.asc` in the storage folder; a failure is only logged.
    fn write_new_key(key: NewKey, ctx: &Context<'_>) -> Plan {
        let Some(dir) = ctx.store.path() else { return Plan::Done };
        let prefix = key.email.split('@').next().unwrap_or("").to_lowercase();
        let write = |name: String, data: String, private: bool| {
            let path = dir.join(name);
            Plan::file(FileOp::WriteAtomic { path: path.clone(), data: data.into_bytes(), private }, move |res| {
                match res {
                    Ok(_) => log::info!("Wrote PGP Key {}", path.display()),
                    Err(e) => crate::warning!("Error writing PGP file {}: {e}", path.display()),
                }
                Plan::Done
            })
        };
        Plan::chain([write(format!("{prefix}-pub.asc"), key.public, false), write(format!("{prefix}-prv.asc"), key.secret, true)])
    }

    /// RFC 3156 `multipart/signed`: `base` as rendered, then its detached signature.
    #[cfg(any(feature = "service-email-pgp", feature = "service-deltachat-pgp"))]
    fn signed<'a>(&self, base: Part<'a>, ctx: &Context<'_>) -> Result<Part<'a>> {
        let failed = || Error::Service(SIGN_FAILED.into());
        let key = self.private_key(ctx).ok_or_else(failed)?;
        let content = super::mime::render_part_alone(&base, ctx.env().as_ref());
        let (signature, micalg) = super::pgp::sign(key, content.as_bytes(), ctx.env().as_ref()).map_err(|e| {
            crate::warning!("{}", e.warning());
            failed()
        })?;
        let sig_part = Part::Leaf {
            headers: vec![
                ("Content-Type".into(), "application/pgp-signature".into()),
                ("Content-Disposition".into(), "attachment; filename=\"signature.asc\"".into()),
            ],
            content: super::mime::Content::Encoded(signature),
        };
        Ok(Part::Multi {
            subtype: "signed",
            params: format!("; micalg=\"{micalg}\"; protocol=\"application/pgp-signature\""),
            parts: vec![Part::Raw(content), sig_part],
        })
    }

    /// RFC 3156 `multipart/encrypted`: the version part, then `content` encrypted to `key`.
    #[cfg(any(feature = "service-email-pgp", feature = "service-deltachat-pgp"))]
    fn encrypted<'a>(&self, key: &[u8], content: &str, ctx: &Context<'_>) -> Result<Part<'a>> {
        let armored = super::pgp::encrypt(key, content.as_bytes(), ctx.env().as_ref()).map_err(|e| {
            crate::warning!("{}", e.warning());
            Error::Service(ENCRYPT_FAILED.into())
        })?;
        let version = Part::Leaf {
            headers: vec![
                ("Content-Type".into(), "application/pgp-encrypted; charset=\"us-ascii\"".into()),
                ("Content-Transfer-Encoding".into(), "7bit".into()),
            ],
            content: super::mime::Content::Encoded("Version: 1".into()),
        };
        let data = Part::Leaf {
            headers: vec![("Content-Type".into(), "application/octet-stream".into())],
            content: super::mime::Content::Encoded(armored),
        };
        Ok(Part::Multi {
            subtype: "encrypted",
            params: "; protocol=\"application/pgp-encrypted\"".into(),
            parts: vec![version, data],
        })
    }

    #[cfg(not(any(feature = "service-email-pgp", feature = "service-deltachat-pgp")))]
    fn encrypted<'a>(&self, _: &[u8], _: &str, _: &Context<'_>) -> Result<Part<'a>> {
        Err(Error::Unsupported("PGP encryption of e-mail is not compiled in".into()))
    }

    #[cfg(not(any(feature = "service-email-pgp", feature = "service-deltachat-pgp")))]
    fn signed<'a>(&self, _: Part<'a>, _: &Context<'_>) -> Result<Part<'a>> {
        Err(Error::Unsupported("PGP signing of e-mail is not compiled in".into()))
    }
}

impl Notify for Email {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        if self.targets.is_empty() {
            return Plan::Fail(Error::Message("there are no Email recipients to notify".into()));
        }
        match self.pgp {
            Pgp::None => {}
            Pgp::Sign | Pgp::Encrypt if !self.pgp_built() => {
                let feature = if self.flavor == Flavor::Email { "service-email-pgp" } else { "service-deltachat-pgp" };
                return Plan::Fail(Error::Unsupported(format!("PGP needs the `{feature}` feature")));
            }
            Pgp::Sign | Pgp::Encrypt => {}
        }
        let (messages, new_key) = match self.prepare(msg, ctx) {
            Ok(m) => m,
            Err(e) => return Plan::Fail(e),
        };
        let keygen = new_key.map_or(Plan::Done, |k| Self::write_new_key(k, ctx));
        let security = match self.mode {
            Mode::Insecure => Security::Insecure,
            Mode::Ssl => Security::Ssl,
            Mode::StartTls => Security::StartTls,
        };
        let job = Job {
            security,
            helo: "localhost".into(),
            user: self.user.clone(),
            password: self.password.clone(),
            messages,
        };
        let mut ep = Endpoint::new(self.smtp_host.clone(), self.port, self.mode == Mode::Ssl);
        ep.connect_timeout = SMTP_TIMEOUT;
        ep.read_timeout = SMTP_TIMEOUT;
        let send = Plan::socket(ep, move |conn, transport| {
            let machine = session(job, conn.is_tls());
            Box::pin(crate::machine::drive(machine, conn, transport))
        });
        Plan::chain([keygen, send])
    }

    fn files(&self, ctx: &Context<'_>) -> Vec<FileOp> {
        let mut specs = Vec::new();
        if self.pgp != Pgp::None {
            // Encryption reads our key too, for the Autocrypt header.
            specs.extend(self.private_key_specs(ctx));
        }
        if self.pgp != Pgp::None {
            for (_, to) in &self.targets {
                for spec in self.public_key_specs(ctx, to) {
                    if !specs.contains(&spec) {
                        specs.push(spec);
                    }
                }
            }
        }
        specs.iter().flat_map(|s| local_file_ops(s)).collect()
    }

    fn fetches(&self, ctx: &Context<'_>) -> Vec<crate::http::Request> {
        let mut out = Vec::new();
        if let (Some(spec), Pgp::Sign | Pgp::Encrypt) = (&self.pgp_prv, self.pgp) {
            out.extend(remote_fetches(ctx, spec, MAX_PRIVATE_KEY));
        }
        if let (Some(spec), Pgp::Sign | Pgp::Encrypt) = (&self.pgp_pub, self.pgp) {
            out.extend(remote_fetches(ctx, spec, MAX_PUBLIC_KEY));
        }
        out.extend(self.wkd_fetches(ctx));
        out
    }
}

impl Email {
    /// Web Key Directory lookups for the recipients with no key of their own and no answer cached (both URLs; the advanced one wins).
    #[cfg(any(feature = "service-email-pgp", feature = "service-deltachat-pgp"))]
    fn wkd_fetches(&self, ctx: &Context<'_>) -> Vec<crate::http::Request> {
        if !self.use_wkd || self.pgp == Pgp::None || self.pgp_pub.is_some() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for (_, to) in &self.targets {
            if self.local_public_key(ctx, to).is_some() || ctx.store.get(&Self::wkd_cache_key(to)).is_some() {
                continue;
            }
            for url in super::pgp::wkd::urls(to).into_iter().flat_map(|(a, d)| [a, d]) {
                out.push(crate::http::Request::get(url).header("User-Agent", ctx.app_id()));
            }
        }
        out
    }

    #[cfg(not(any(feature = "service-email-pgp", feature = "service-deltachat-pgp")))]
    fn wkd_fetches(&self, _: &Context<'_>) -> Vec<crate::http::Request> {
        Vec::new()
    }

}
