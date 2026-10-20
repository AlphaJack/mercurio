//! The contract every service implements.

use std::fmt;
use std::path::Path;
use std::time::Duration;

use crate::asset::Asset;
use crate::error::{Error, Result};
use crate::http::{Method, Request};
use crate::message::{NotifyFormat, Prepared};
use crate::plan::Plan;
use crate::store::{Memo, StoreRef};
use crate::transport::{FileMeta, FileOp, FileOutput};
use crate::url::ParsedUrl;

/// Message size limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// `0` means the service has no title; it is merged into the body.
    pub title_maxlen: usize,
    /// Longest body in characters.
    pub body_maxlen: usize,
    /// `0` means unlimited.
    pub body_max_line_count: usize,
}

impl Limits {
    /// Defaults: title 250, body 32768, no line limit.
    pub const DEFAULT: Limits = Limits { title_maxlen: 250, body_maxlen: 32768, body_max_line_count: 0 };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Static description of a service; one `pub static SERVICE` per module.
#[derive(Clone, Copy)]
pub struct ServiceDef {
    /// Module name, lowercase letters and digits (the Cargo feature is `service-<id>`), e.g. `"googlechat"`.
    pub id: &'static str,
    /// Human name, e.g. `"Google Chat"`.
    pub name: &'static str,
    /// URL schemes (lower case). Insecure first, then secure.
    pub schemes: &'static [&'static str],
    /// Vendor homepage.
    pub service_url: &'static str,
    /// Build the service from a parsed URL.
    pub parse: fn(&ParsedUrl) -> Result<Box<dyn Notify>>,
    /// Map a vendor URL (e.g. a Discord webhook URL) to an equivalent mercurio URL.
    pub parse_native: Option<fn(&str) -> Option<String>>,
    /// Default message limits.
    pub limits: Limits,
    /// Supported body formats; the first is the default (`notify_format`).
    pub formats: &'static [NotifyFormat],
    /// The service can send attachments.
    pub attachments: bool,
    /// Minimum gap between consecutive requests.
    pub throttle: Duration,
    /// URL shapes, e.g. `{schema}://{token}@{host}/{targets}`.
    pub templates: &'static [&'static str],
    /// The `{tokens}` of [`ServiceDef::templates`].
    pub tokens: &'static [Param],
    /// Query parameters, besides the common ones every URL accepts.
    pub params: &'static [Param],
}

impl ServiceDef {
    /// Base values for `..ServiceDef::DEFAULTS` in service statics.
    pub const DEFAULTS: ServiceDef = ServiceDef {
        id: "",
        name: "",
        schemes: &[],
        service_url: "",
        parse: unimplemented_parse,
        parse_native: None,
        limits: Limits::DEFAULT,
        formats: &[NotifyFormat::Text],
        attachments: false,
        throttle: Duration::ZERO,
        templates: &[],
        tokens: &[],
        params: &[],
    };

    /// `true` when `scheme` (any case) is one of [`ServiceDef::schemes`].
    pub fn handles(&self, scheme: &str) -> bool {
        self.schemes.iter().any(|s| s.eq_ignore_ascii_case(scheme))
    }

    /// The declared default of token or query parameter `key`; empty when it has none. Parsers read defaults from here so that the declaration is the only place that states them.
    pub fn default_of(&self, key: &str) -> &'static str {
        self.tokens.iter().chain(self.params).find(|p| p.key == key).map_or("", |p| p.default)
    }

    fn param_def(&self, key: &str) -> Option<&'static Param> {
        self.params.iter().find(|p| p.key == key)
    }

    /// The raw value of declared query parameter `key`, or of the first of its aliases that is present; `None` when none is.
    pub fn raw<'u>(&self, u: &'u ParsedUrl, key: &str) -> Option<&'u str> {
        let aliases = self.param_def(key).map_or(&[][..], |p| p.aliases);
        std::iter::once(key).chain(aliases.iter().copied()).find_map(|k| u.param(k))
    }

    /// [`ServiceDef::raw`], percent-decoded, `None` when empty.
    pub fn text(&self, u: &ParsedUrl, key: &str) -> Option<String> {
        self.raw(u, key).filter(|v| !v.is_empty()).map(crate::url::unquote)
    }

    /// [`ServiceDef::text`], or the declared default.
    pub fn text_or_default(&self, u: &ParsedUrl, key: &str) -> String {
        self.text(u, key).unwrap_or_else(|| self.default_of(key).to_string())
    }

    /// A yes/no parameter: its value read with [`crate::parse::parse_bool`], falling back to the declared default (`Param::bool`).
    pub fn flag(&self, u: &ParsedUrl, key: &str) -> bool {
        let default = crate::parse::parse_bool(self.default_of(key), false);
        self.raw(u, key).map_or(default, |v| crate::parse::parse_bool(v, default))
    }

    /// A yes/no parameter where only a yes word turns it on: the declared default when absent, `false` for any other value (also empty).
    pub fn flag_strict(&self, u: &ParsedUrl, key: &str) -> bool {
        self.raw(u, key).map_or_else(
            || crate::parse::parse_bool(self.default_of(key), false),
            |v| crate::parse::parse_bool(v, false),
        )
    }

    /// A whole-number parameter; `None` when absent or not a number.
    pub fn int(&self, u: &ParsedUrl, key: &str) -> Option<i64> {
        self.raw(u, key).filter(|v| !v.is_empty()).and_then(crate::util::parse_int)
    }

    /// [`ServiceDef::int`], or the declared default (0 when it has none).
    pub fn int_or_default(&self, u: &ParsedUrl, key: &str) -> i64 {
        self.int(u, key).or_else(|| crate::util::parse_int(self.default_of(key))).unwrap_or(0)
    }

    /// Shorthand for a configuration error from this service.
    pub fn err(&'static self, reason: impl Into<String>) -> Error {
        Error::config(self.name, reason)
    }
}

/// Value type of a [`Param`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kind {
    /// Free text.
    String,
    /// Whole number.
    Int,
    /// Decimal number.
    Float,
    /// `yes` / `no` (also `true`, `1`, `on`, ...).
    Bool,
    /// Email address.
    Email,
    /// One of [`Param::values`].
    Choice,
    /// Several values, separated by [`Param::delim`].
    List,
}

impl Kind {
    /// Lower-case name, e.g. `"choice"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::String => "string",
            Kind::Int => "int",
            Kind::Float => "float",
            Kind::Bool => "bool",
            Kind::Email => "email",
            Kind::Choice => "choice",
            Kind::List => "list",
        }
    }
}

/// A URL path token (`{host}`) or query parameter a service reads. Declared in [`ServiceDef::tokens`] and [`ServiceDef::params`] with the `const` builder methods; `mercurio services --json` and the book pages show them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Param {
    /// Token name without braces or query key. For a prefixed parameter (`+name=value`) the name of the group.
    pub key: &'static str,
    /// What it is, e.g. `"Hostname"`.
    pub name: &'static str,
    /// Value type.
    pub kind: Kind,
    /// Default as written in a URL; empty when there is none.
    pub default: &'static str,
    /// Accepted values.
    pub values: &'static [&'static str],
    /// Smallest accepted number.
    pub min: Option<i64>,
    /// Largest accepted number.
    pub max: Option<i64>,
    /// The URL is rejected without it.
    pub required: bool,
    /// A credential; never logged.
    pub secret: bool,
    /// Other query keys read for the same value.
    pub aliases: &'static [&'static str],
    /// Tokens this query parameter fills instead (`?to=` sets `{targets}`).
    pub sets: &'static [&'static str],
    /// List separators, one character each (`", "`: comma or space).
    pub delim: &'static str,
    /// Regular expression the value must match.
    pub pattern: &'static str,
    /// Marks the token (`#` for a channel) or the prefixed parameter (`+` in `+name=value`).
    pub prefix: &'static str,
    /// For a list token: the tokens it can hold.
    pub group: &'static [&'static str],
    /// How the value is read, when that needs saying.
    pub note: &'static str,
    /// Without the key the service picks the value from the rest of the URL (or leaves it to the server); `default` is the usual outcome.
    pub inferred: bool,
    /// Accepted for compatibility, without effect.
    pub ignored: bool,
}

impl Param {
    /// A string parameter.
    pub const fn new(key: &'static str, name: &'static str) -> Self {
        Self {
            key,
            name,
            kind: Kind::String,
            default: "",
            values: &[],
            min: None,
            max: None,
            required: false,
            secret: false,
            aliases: &[],
            sets: &[],
            delim: "",
            pattern: "",
            prefix: "",
            group: &[],
            note: "",
            inferred: false,
            ignored: false,
        }
    }
    /// A query key that fills `tokens` (`?to=` for `{targets}`).
    pub const fn sets(key: &'static str, tokens: &'static [&'static str]) -> Self {
        let mut p = Self::new(key, "");
        p.sets = tokens;
        p
    }
    /// Set the value type.
    pub const fn kind(mut self, kind: Kind) -> Self {
        self.kind = kind;
        self
    }
    /// [`Kind::Int`].
    pub const fn int(self) -> Self {
        self.kind(Kind::Int)
    }
    /// A TCP or UDP port: an integer from 1 to 65535.
    pub const fn port(self) -> Self {
        self.int().range(1, u16::MAX as i64)
    }
    /// [`Kind::Float`].
    pub const fn float(self) -> Self {
        self.kind(Kind::Float)
    }
    /// [`Kind::Bool`] with its default.
    pub const fn bool(self, default: bool) -> Self {
        self.kind(Kind::Bool).default(if default { "yes" } else { "no" })
    }
    /// [`Kind::Email`].
    pub const fn email(self) -> Self {
        self.kind(Kind::Email)
    }
    /// [`Kind::List`] separated by any character of `delim`.
    pub const fn list(mut self, delim: &'static str) -> Self {
        self.delim = delim;
        self.kind(Kind::List)
    }
    /// [`Kind::Choice`] among `values`.
    pub const fn choice(mut self, values: &'static [&'static str]) -> Self {
        self.values = values;
        self.kind(Kind::Choice)
    }
    /// [`Param::values`] without changing the kind.
    pub const fn values(mut self, values: &'static [&'static str]) -> Self {
        self.values = values;
        self
    }
    /// [`Param::default`].
    pub const fn default(mut self, value: &'static str) -> Self {
        self.default = value;
        self
    }
    /// [`Param::min`] and [`Param::max`].
    pub const fn range(self, min: i64, max: i64) -> Self {
        self.min(min).max(max)
    }
    /// [`Param::min`].
    pub const fn min(mut self, min: i64) -> Self {
        self.min = Some(min);
        self
    }
    /// [`Param::max`].
    pub const fn max(mut self, max: i64) -> Self {
        self.max = Some(max);
        self
    }
    /// [`Param::required`].
    pub const fn required(mut self) -> Self {
        self.required = true;
        self
    }
    /// [`Param::secret`].
    pub const fn secret(mut self) -> Self {
        self.secret = true;
        self
    }
    /// [`Param::aliases`].
    pub const fn aliases(mut self, keys: &'static [&'static str]) -> Self {
        self.aliases = keys;
        self
    }
    /// [`Param::pattern`].
    pub const fn pattern(mut self, regex: &'static str) -> Self {
        self.pattern = regex;
        self
    }
    /// [`Param::prefix`].
    pub const fn prefix(mut self, prefix: &'static str) -> Self {
        self.prefix = prefix;
        self
    }
    /// [`Param::group`].
    pub const fn group(mut self, tokens: &'static [&'static str]) -> Self {
        self.group = tokens;
        self
    }
    /// [`Param::note`].
    pub const fn note(mut self, note: &'static str) -> Self {
        self.note = note;
        self
    }
    /// [`Param::inferred`].
    pub const fn inferred(mut self) -> Self {
        self.inferred = true;
        self
    }
    /// [`Param::ignored`].
    pub const fn ignored(mut self) -> Self {
        self.ignored = true;
        self
    }

    /// The parameter as a JSON object; empty fields are left out.
    pub fn to_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        let mut put = |k: &str, v: serde_json::Value| {
            let empty = match &v {
                serde_json::Value::Null => true,
                serde_json::Value::Bool(b) => !b,
                serde_json::Value::String(s) => s.is_empty(),
                serde_json::Value::Array(a) => a.is_empty(),
                serde_json::Value::Number(_) | serde_json::Value::Object(_) => false,
            };
            if !empty {
                m.insert(k.to_string(), v);
            }
        };
        put("key", self.key.into());
        put("name", self.name.into());
        put("type", self.kind.as_str().into());
        put("default", self.default.into());
        put("values", self.values.into());
        put("min", self.min.into());
        put("max", self.max.into());
        put("required", self.required.into());
        put("secret", self.secret.into());
        put("aliases", self.aliases.into());
        put("sets", self.sets.into());
        put("delim", self.delim.into());
        put("pattern", self.pattern.into());
        put("prefix", self.prefix.into());
        put("group", self.group.into());
        put("note", self.note.into());
        put("inferred", self.inferred.into());
        put("ignored", self.ignored.into());
        serde_json::Value::Object(m)
    }
}

impl fmt::Debug for ServiceDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceDef").field("id", &self.id).field("schemes", &self.schemes).finish()
    }
}

fn unimplemented_parse(_: &ParsedUrl) -> Result<Box<dyn Notify>> {
    Err(Error::Unsupported("service has no parser".into()))
}

/// Per-send context handed to services.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    /// Branding and pipeline defaults of the notifier.
    pub asset: &'a Asset,
    /// The target's persistent store namespace. Clone it into continuations that read or write after a response.
    pub store: &'a StoreRef,
    /// Scratch space shared by the retry attempts of this notification.
    pub memo: &'a Memo,
    /// The results of [`Notify::files`].
    files: &'a [(FileOp, Result<FileOutput>)],
}

impl<'a> Context<'a> {
    /// A context over `asset`, `store` and `memo`.
    pub fn new(asset: &'a Asset, store: &'a StoreRef, memo: &'a Memo) -> Self {
        Self { asset, store, memo, files: &[] }
    }

    /// This context with the results of [`Notify::files`].
    pub fn with_files(self, files: &'a [(FileOp, Result<FileOutput>)]) -> Self {
        Self { files, ..self }
    }

    /// What the [`FileOp::Stat`] of `path` requested by [`Notify::files`] found; `None` when the file is missing or could not be accessed.
    pub fn stat(&self, path: impl AsRef<Path>) -> Option<FileMeta> {
        self.files.iter().find_map(|(op, res)| match (op, res) {
            (FileOp::Stat { path: p }, Ok(FileOutput::Meta(meta))) if p == path.as_ref() => *meta,
            _ => None,
        })
    }

    /// The bytes the [`FileOp::Read`] of `path` (with `max`) requested by [`Notify::files`] returned; `None` when it failed.
    pub fn read(&self, path: impl AsRef<Path>, max: u64) -> Option<&'a [u8]> {
        self.files.iter().find_map(|(op, res)| match (op, res) {
            (FileOp::Read { path: p, max: m }, Ok(FileOutput::Bytes(b))) if p == path.as_ref() && *m == max => {
                Some(b.as_slice())
            }
            _ => None,
        })
    }

    /// A regular file of at most `max` bytes (`0`: any size), read by the [`FileOp::local_file`] steps of [`Notify::files`]. `Err("could not be accessed")` when it is missing, not a file or too large, `Err("could not be read")` when reading it failed.
    pub fn local_file(&self, path: impl AsRef<Path>, max: u64) -> std::result::Result<&'a [u8], &'static str> {
        let path = path.as_ref();
        match self.stat(path) {
            Some(m) if m.is_file && (max == 0 || m.len <= max) => self.read(path, 0).ok_or("could not be read"),
            _ => Err("could not be accessed"),
        }
    }

    /// A clone of the store handle, for `'static` continuations.
    pub fn store(&self) -> StoreRef {
        self.store.clone()
    }

    /// [`Asset::app_id`].
    pub fn app_id(&self) -> &str {
        &self.asset.app_id
    }
    /// [`Asset::app_desc`].
    pub fn app_desc(&self) -> &str {
        &self.asset.app_desc
    }
    /// [`Asset::app_url`].
    pub fn app_url(&self) -> &str {
        &self.asset.app_url
    }

    /// A request with `User-Agent` set to the app id.
    pub fn request(&self, method: Method, url: impl Into<String>) -> Request {
        Request::new(method, url).header("User-Agent", self.app_id())
    }
    /// A `GET` request with `User-Agent` set to the app id.
    pub fn get(&self, url: impl Into<String>) -> Request {
        self.request(Method::Get, url)
    }
    /// A `POST` request with `User-Agent` set to the app id.
    pub fn post(&self, url: impl Into<String>) -> Request {
        self.request(Method::Post, url)
    }
}

/// A configured service instance (one parsed URL).
///
/// `Debug` implementations must not print secrets; wrap them in [`crate::Secret`].
pub trait Notify: Send + Sync + fmt::Debug {
    /// Plan the delivery of one message piece.
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan;

    /// Limits for this message when they differ from [`ServiceDef::limits`] (they may depend on the instance or on the converted title and body).
    fn limits(&self, _title: &str, _body: &str, _format: NotifyFormat, _ctx: &Context<'_>) -> Option<Limits> {
        None
    }

    /// Convert a body piece to the service's own markup; `None` to send `format` as is. Converted pieces are re-fitted to the limits, so this must be deterministic.
    fn convert(&self, _body: &str, _format: NotifyFormat) -> Option<String> {
        None
    }

    /// `true` when [`Notify::convert`] yields well-nested HTML that may be converted once per chunk and then split between tags, instead of converting every candidate piece of the source until one fits.
    fn split_converted(&self) -> bool {
        false
    }

    /// What identifies this URL for its persistent store namespace. The default hashes scheme, credentials, host, port and path.
    fn url_identifier(&self) -> UrlIdentifier {
        UrlIdentifier::Default
    }

    /// Files [`Notify::plan`] reads ([`FileOp::Stat`], [`FileOp::Read`]). They run on the transport right before each `plan` call; `plan` finds the results with [`Context::stat`] and [`Context::read`]. Services never touch the file system themselves: writes are [`Plan::file`] steps.
    fn files(&self, _ctx: &Context<'_>) -> Vec<FileOp> {
        Vec::new()
    }

    /// Stores this service opens besides the target's own (e.g. a key store under a configured directory). They are loaded before a send and flushed with the target's.
    fn stores(&self, _ctx: &Context<'_>) -> Vec<StoreRef> {
        Vec::new()
    }

    /// Clean-up when the target goes away: log out or revoke a session kept in `ctx.store`. Called by [`crate::Target::close`] (and when a [`crate::Mercurio`] is dropped) for targets that sent something; failures are ignored.
    fn close(&self, _ctx: &Context<'_>) -> Option<Plan> {
        None
    }
}

/// How a target identifies its URL for its persistent store namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UrlIdentifier {
    /// Hash the generic URL parts.
    Default,
    /// No URL id; the store stays in memory.
    Disabled,
    /// Hash these parts, concatenated; a missing part is an empty string.
    Parts(Vec<String>),
}

impl UrlIdentifier {
    /// Build [`UrlIdentifier::Parts`] from string-like values.
    pub fn parts<I: IntoIterator<Item = S>, S: Into<String>>(items: I) -> Self {
        UrlIdentifier::Parts(items.into_iter().map(Into::into).collect())
    }
}

/// A string that never shows up in `Debug` or `Display` output.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Secret(String);

impl Secret {
    /// Wrap a secret value.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// The wrapped value. Use only when building requests.
    pub fn expose(&self) -> &str {
        &self.0
    }
    /// `true` for an empty value.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"***\"")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}
