//! The URL tokens and query options a service declares, for documentation and validation.

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

/// A URL path token (`{host}`) or query parameter a service reads. Declared in [`ServiceDef::tokens`](crate::service::ServiceDef::tokens) and [`ServiceDef::params`](crate::service::ServiceDef::params) with the `const` builder methods; `mercurio services --json` and the book pages show them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
    #[must_use]
    pub const fn kind(mut self, kind: Kind) -> Self {
        self.kind = kind;
        self
    }
    /// [`Kind::Int`].
    #[must_use]
    pub const fn int(self) -> Self {
        self.kind(Kind::Int)
    }
    /// A TCP or UDP port: an integer from 1 to 65535.
    #[must_use]
    pub const fn port(self) -> Self {
        self.int().range(1, u16::MAX as i64)
    }
    /// [`Kind::Float`].
    #[must_use]
    pub const fn float(self) -> Self {
        self.kind(Kind::Float)
    }
    /// [`Kind::Bool`] with its default.
    #[must_use]
    pub const fn bool(self, default: bool) -> Self {
        self.kind(Kind::Bool).default(if default { "yes" } else { "no" })
    }
    /// [`Kind::Email`].
    #[must_use]
    pub const fn email(self) -> Self {
        self.kind(Kind::Email)
    }
    /// [`Kind::List`] separated by any character of `delim`.
    #[must_use]
    pub const fn list(mut self, delim: &'static str) -> Self {
        self.delim = delim;
        self.kind(Kind::List)
    }
    /// [`Kind::Choice`] among `values`.
    #[must_use]
    pub const fn choice(mut self, values: &'static [&'static str]) -> Self {
        self.values = values;
        self.kind(Kind::Choice)
    }
    /// [`Param::values`] without changing the kind.
    #[must_use]
    pub const fn values(mut self, values: &'static [&'static str]) -> Self {
        self.values = values;
        self
    }
    /// [`Param::default`].
    #[must_use]
    pub const fn default(mut self, value: &'static str) -> Self {
        self.default = value;
        self
    }
    /// [`Param::min`] and [`Param::max`].
    #[must_use]
    pub const fn range(self, min: i64, max: i64) -> Self {
        self.min(min).max(max)
    }
    /// [`Param::min`].
    #[must_use]
    pub const fn min(mut self, min: i64) -> Self {
        self.min = Some(min);
        self
    }
    /// [`Param::max`].
    #[must_use]
    pub const fn max(mut self, max: i64) -> Self {
        self.max = Some(max);
        self
    }
    /// [`Param::required`].
    #[must_use]
    pub const fn required(mut self) -> Self {
        self.required = true;
        self
    }
    /// [`Param::secret`].
    #[must_use]
    pub const fn secret(mut self) -> Self {
        self.secret = true;
        self
    }
    /// [`Param::aliases`].
    #[must_use]
    pub const fn aliases(mut self, keys: &'static [&'static str]) -> Self {
        self.aliases = keys;
        self
    }
    /// A required secret matching `regex`: an API key or token.
    #[must_use]
    pub(crate) const fn secret_key(self, regex: &'static str) -> Self {
        self.required().secret().pattern(regex)
    }
    /// [`Param::pattern`].
    #[must_use]
    pub const fn pattern(mut self, regex: &'static str) -> Self {
        self.pattern = regex;
        self
    }
    /// [`Param::prefix`].
    #[must_use]
    pub const fn prefix(mut self, prefix: &'static str) -> Self {
        self.prefix = prefix;
        self
    }
    /// [`Param::group`].
    #[must_use]
    pub const fn group(mut self, tokens: &'static [&'static str]) -> Self {
        self.group = tokens;
        self
    }
    /// [`Param::note`].
    #[must_use]
    pub const fn note(mut self, note: &'static str) -> Self {
        self.note = note;
        self
    }
    /// [`Param::inferred`].
    #[must_use]
    pub const fn inferred(mut self) -> Self {
        self.inferred = true;
        self
    }
    /// [`Param::ignored`].
    #[must_use]
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
                m.insert(k.to_owned(), v);
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
