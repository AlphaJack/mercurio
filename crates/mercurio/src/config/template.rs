//! YAML `template:` variables (`${NAME}`).
//!
//! Declared variables in a URL are swapped for parse-safe placeholders and the URL is parsed. The entry stays pending until values are known. Values then go straight into the parsed fields, so a value lands in the field it was written in (a host value can not add a path).

use std::collections::BTreeMap;
use std::fmt;

use super::yaml::Yaml;
use crate::url::ParsedUrl;

/// Environment prefix: variable `target` reads `APPRISE_TEMPLATE_TARGET`.
pub const ENV_PREFIX: &str = "APPRISE_TEMPLATE_";
/// Longest variable name.
pub const NAME_MAXLEN: usize = 32;
/// Longest variable value in characters.
pub const MAX_VALUE_LEN: usize = 1024;
/// Longest URL after substitution.
pub const MAX_RESOLVED_URL_LEN: usize = 8192;

/// A template problem (bad declaration, missing or invalid value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateError {
    /// Human-readable description.
    pub message: String,
    /// The variable concerned, when there is one.
    pub variable: Option<String>,
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for TemplateError {}

fn terr(message: String, variable: Option<&str>) -> TemplateError {
    TemplateError { message, variable: variable.map(str::to_string) }
}

/// `TEMPLATE_VAR_RE`.
pub(crate) fn var_re() -> &'static crate::re::Regex {
    crate::regex!(r"\$\{(?P<name>[A-Za-z0-9_]{1,32})\}")
}

/// `TEMPLATE_NAME_RE` (whole string).
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= NAME_MAXLEN && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Canonical (lower-case) form of a variable name; names are case-insensitive.
pub fn normalize_name(name: &str) -> String {
    name.to_lowercase()
}

/// `validate_value`: text, numbers and booleans (`yes`/`no`) only; no control characters; at most 1024 characters.
pub fn validate_value(name: &str, value: &Yaml) -> Result<String, TemplateError> {
    let v = match value {
        Yaml::Bool(b) => if *b { "yes" } else { "no" }.to_string(),
        Yaml::Int(_) | Yaml::Float(_) => value.to_text(),
        Yaml::Str(s) => s.clone(),
        Yaml::Null | Yaml::Seq(_) | Yaml::Map(_) => {
            return Err(terr(format!("Template variable '{name}' must be text."), Some(name)));
        }
    };
    validate_text(name, v)
}

fn validate_text(name: &str, v: String) -> Result<String, TemplateError> {
    if v.chars().count() > MAX_VALUE_LEN {
        return Err(terr(format!("Template variable '{name}' exceeds {MAX_VALUE_LEN} characters."), Some(name)));
    }
    if v.chars().any(|c| (c as u32) < 0x20 || c == '\x7f' || c == '\u{2028}' || c == '\u{2029}') {
        return Err(terr(format!("Template variable '{name}' contains a control character."), Some(name)));
    }
    Ok(v)
}

/// The variables a configuration declares (`template:` section).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TemplateSchema {
    /// Normalized name and default (`None` = required), in declaration order.
    pub variables: Vec<(String, Option<String>)>,
}

impl TemplateSchema {
    /// `TemplateSchema.parse`: a list of `- name` / `- name: default` entries or a `name: default` mapping.
    pub fn parse(entries: &Yaml) -> Result<Self, TemplateError> {
        let mut items: Vec<(&Yaml, &Yaml)> = Vec::new();
        let null = Yaml::Null;
        match entries {
            Yaml::Map(m) => items.extend(m.iter().map(|(k, v)| (k, v))),
            Yaml::Seq(list) => {
                for e in list {
                    match e {
                        Yaml::Str(_) => items.push((e, &null)),
                        Yaml::Map(m) => items.extend(m.iter().map(|(k, v)| (k, v))),
                        Yaml::Null | Yaml::Bool(_) | Yaml::Int(_) | Yaml::Float(_) | Yaml::Seq(_) => {
                            return Err(terr("Invalid template declaration entry.".into(), None));
                        }
                    }
                }
            }
            Yaml::Null | Yaml::Bool(_) | Yaml::Int(_) | Yaml::Float(_) | Yaml::Str(_) => {
                return Err(terr("The template section must be a list or a mapping.".into(), None));
            }
        }
        let mut variables: Vec<(String, Option<String>)> = Vec::new();
        for (name, default) in items {
            let Some(n) = name.as_str().filter(|n| valid_name(n)) else {
                return Err(terr(format!("Invalid template variable name {}.", name), None));
            };
            let key = normalize_name(n);
            if variables.iter().any(|(k, _)| *k == key) {
                return Err(terr(format!("Template variable '{key}' is declared more than once."), Some(&key)));
            }
            let default = if default.is_null() { None } else { Some(validate_value(&key, default)?) };
            variables.push((key, default));
        }
        Ok(TemplateSchema { variables })
    }

    /// Declared variable names (normalised), in declaration order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.variables.iter().map(|(n, _)| n.as_str())
    }

    /// `true` when `name` (any case) is declared.
    pub fn contains(&self, name: &str) -> bool {
        let n = normalize_name(name);
        self.variables.iter().any(|(k, _)| *k == n)
    }

    /// Configuration default of `name`, if it has one. `name` must be normalised.
    pub fn default_of(&self, name: &str) -> Option<&str> {
        self.variables.iter().find(|(k, _)| k == name).and_then(|(_, d)| d.as_deref())
    }

    /// `true` when `name` is declared without a default.
    pub fn is_required(&self, name: &str) -> bool {
        self.variables.iter().any(|(k, d)| k == name && d.is_none())
    }

    /// `true` when no variable is declared.
    pub fn is_empty(&self) -> bool {
        self.variables.is_empty()
    }
}

/// Values supplied for one call (CLI `-tv`, API `template=`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TemplateVars {
    values: Vec<(String, String)>,
    /// Read `APPRISE_TEMPLATE_*` from the process environment (default on).
    use_env: bool,
    env: Option<BTreeMap<String, String>>,
}

impl TemplateVars {
    /// Empty set that reads the process environment.
    pub fn new() -> Self {
        TemplateVars { values: Vec::new(), use_env: true, env: None }
    }

    /// Add a value; names are case-insensitive. Errors on an invalid or repeated name (`validate_overrides`).
    pub fn set(&mut self, name: &str, value: impl Into<String>) -> Result<&mut Self, TemplateError> {
        if !valid_name(name) {
            return Err(terr(format!("Invalid template variable name '{name}'."), None));
        }
        let n = normalize_name(name);
        if self.values.iter().any(|(k, _)| normalize_name(k) == n) {
            return Err(terr(format!("Template variable '{n}' was supplied more than once."), Some(&n)));
        }
        self.values.push((name.to_string(), value.into()));
        Ok(self)
    }

    /// Builder form of [`TemplateVars::set`].
    ///
    /// # Panics
    ///
    /// On an invalid or repeated name; use [`TemplateVars::set`] to get the error instead.
    #[expect(clippy::expect_used, reason = "documented public builder contract: the fallible form is `set`")]
    #[must_use]
    pub fn with(mut self, name: &str, value: impl Into<String>) -> Self {
        self.set(name, value).expect("valid template variable name");
        self
    }

    /// Replace the process environment with `env` (`{}` disables lookups).
    #[must_use]
    pub fn environment(mut self, env: BTreeMap<String, String>) -> Self {
        self.env = Some(env);
        self.use_env = true;
        self
    }

    /// Do not consult the environment.
    #[must_use]
    pub fn no_environment(mut self) -> Self {
        self.use_env = false;
        self
    }

    /// `true` when no value is set.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// The values set, as `(name, value)` in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.values.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    fn env_get(&self, name: &str) -> Option<String> {
        if !self.use_env {
            return None;
        }
        let key = format!("{ENV_PREFIX}{}", name.to_uppercase());
        let v = match &self.env {
            Some(map) => map.get(&key).cloned(),
            None => std::env::var(&key).ok(),
        };
        v.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
    }

    /// `resolve_values`: call value, then configuration default, then environment. Blank call/environment values read as unsupplied.
    pub fn resolve(
        &self,
        schema: &TemplateSchema,
        names: Option<&[String]>,
    ) -> Result<BTreeMap<String, String>, TemplateError> {
        let mut supplied: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in &self.values {
            let n = normalize_name(k);
            if !schema.contains(&n) {
                continue;
            }
            let v = v.trim();
            if v.is_empty() {
                continue;
            }
            supplied.insert(n.clone(), validate_text(&n, v.to_string())?);
        }
        let mut out = BTreeMap::new();
        for (name, default) in &schema.variables {
            if let Some(names) = names
                && !names.iter().any(|n| n == name)
            {
                continue;
            }
            if let Some(v) = supplied.get(name) {
                out.insert(name.clone(), v.clone());
                continue;
            }
            if let Some(d) = default {
                out.insert(name.clone(), d.clone());
                continue;
            }
            if let Some(v) = self.env_get(name) {
                out.insert(name.clone(), validate_text(name, v)?);
                continue;
            }
            return Err(terr(format!("No value available for template variable '{name}'."), Some(name)));
        }
        Ok(out)
    }
}

/// `TemplatePlaceholderMap`: placeholders are `a<nonce>t<index>z`.
#[derive(Debug, Clone)]
pub struct Placeholders {
    nonce: String,
    names: Vec<String>,
    schema: TemplateSchema,
    /// Placeholder regex, compiled on first use (it depends only on `nonce`).
    pattern: std::sync::OnceLock<Option<crate::re::Regex>>,
}

impl Placeholders {
    /// Placeholder map for `schema`, with a nonce that does not occur in `content`.
    #[expect(clippy::disallowed_methods, reason = "an internal marker that never reaches a request")]
    pub fn new(schema: TemplateSchema, content: &str) -> Result<Self, TemplateError> {
        for _ in 0..8 {
            let nonce = crate::env::system().random_hex(8);
            if !content.contains(&format!("a{nonce}")) {
                return Ok(Placeholders { nonce, names: Vec::new(), schema, pattern: std::sync::OnceLock::new() });
            }
        }
        Err(terr("Could not prepare template variable placeholders.".into(), None))
    }

    /// The variables this map was built from.
    pub fn schema(&self) -> &TemplateSchema {
        &self.schema
    }

    fn token(&mut self, name: &str) -> String {
        let idx = match self.names.iter().position(|n| n == name) {
            Some(i) => i,
            None => {
                self.names.push(name.to_string());
                self.names.len() - 1
            }
        };
        format!("a{}t{}z", self.nonce, idx)
    }

    /// Replace declared `${NAME}` markers; undeclared ones stay as written.
    pub fn encode(&mut self, text: &str) -> String {
        if !text.contains("${") {
            return text.to_string();
        }
        crate::util::replace_all(var_re(), text, |c| {
            let name = normalize_name(&c["name"]);
            Some(if self.schema.contains(&name) { self.token(&name) } else { c[0].to_string() })
        })
        .unwrap_or_else(|| text.to_string())
    }

    /// Encode only after the `://` separator so the schema stays literal.
    pub fn encode_url(&mut self, url: &str) -> String {
        match url.split_once("://") {
            Some((schema, rest)) => format!("{schema}://{}", self.encode(rest)),
            None => url.to_string(),
        }
    }

    /// Encode every string value (never mapping keys).
    pub fn encode_value(&mut self, v: &Yaml) -> Yaml {
        match v {
            Yaml::Str(s) => Yaml::Str(self.encode(s)),
            Yaml::Seq(items) => Yaml::Seq(items.iter().map(|i| self.encode_value(i)).collect()),
            Yaml::Map(m) => Yaml::Map(m.iter().map(|(k, v)| (k.clone(), self.encode_value(v))).collect()),
            other @ (Yaml::Null | Yaml::Bool(_) | Yaml::Int(_) | Yaml::Float(_)) => other.clone(),
        }
    }

    /// `None` only if the pattern failed to compile, which an escaped nonce cannot cause.
    fn pattern(&self) -> Option<&crate::re::Regex> {
        self.pattern
            .get_or_init(|| crate::re::Regex::new(&format!("a{}t[0-9]{{1,10}}z", crate::re::escape(&self.nonce))).ok())
            .as_ref()
    }

    fn name_of(&self, token: &str) -> Option<&str> {
        let idx: usize = token.strip_prefix(&format!("a{}t", self.nonce))?.strip_suffix('z')?.parse().ok()?;
        self.names.get(idx).map(String::as_str)
    }

    /// Names whose placeholders occur in `text`.
    pub fn used_in(&self, text: &str, out: &mut Vec<String>) {
        if self.names.is_empty() {
            return;
        }
        let Some(pattern) = self.pattern() else { return };
        for m in pattern.find_iter(text) {
            if let Some(n) = self.name_of(m.as_str())
                && !out.iter().any(|x| x == n)
            {
                out.push(n.to_string());
            }
        }
    }

    /// Names still needed by a parsed URL (`used(results)`).
    pub fn used_by(&self, u: &ParsedUrl) -> Vec<String> {
        let mut out = Vec::new();
        for text in parsed_texts(u) {
            self.used_in(text, &mut out);
        }
        out.sort();
        out
    }

    /// `${NAME}` back in place of placeholders (for display).
    pub fn display(&self, text: &str) -> String {
        let Some(pattern) = self.pattern().filter(|_| !self.names.is_empty()) else {
            return text.to_string();
        };
        pattern
            .replace_all(text, |c: &crate::re::Captures| match self.name_of(&c[0]) {
                Some(n) => format!("${{{}}}", n.to_uppercase()),
                None => c[0].to_string(),
            })
            .into_owned()
    }

    fn fill(&self, text: &str, values: &BTreeMap<String, String>) -> String {
        let Some(pattern) = self.pattern().filter(|_| !self.names.is_empty()) else {
            return text.to_string();
        };
        pattern
            .replace_all(text, |c: &crate::re::Captures| {
                self.name_of(&c[0]).and_then(|n| values.get(n)).cloned().unwrap_or_else(|| c[0].to_string())
            })
            .into_owned()
    }

    /// `substitute(results, values)`: fill every parsed field, then the whole-authority (`user@host`) and whole-user (`user:pass`) forms.
    pub fn substitute(&self, u: &ParsedUrl, values: &BTreeMap<String, String>) -> ParsedUrl {
        let mut r = u.clone();
        let f = |s: &str| self.fill(s, values);
        let fo = |s: &Option<String>| s.as_deref().map(f);
        r.user = fo(&u.user);
        r.password = fo(&u.password);
        r.host = f(&u.host);
        // A filled-in host may carry its port (`${HOST}` = `example.com:8080`).
        if r.port.is_none()
            && let Some((host, port)) = r.host.rsplit_once(':')
            && !host.contains(':')
            && let Ok(port) = port.parse::<u16>()
        {
            r.port = Some(port);
            r.host = host.to_string();
        }
        r.port_raw = fo(&u.port_raw);
        r.fullpath = fo(&u.fullpath);
        r.path = fo(&u.path);
        r.last_segment = fo(&u.last_segment);
        r.url = f(&u.url);
        r.original = f(&u.original);
        for (src, dst) in [
            (&u.query, &mut r.query),
            (&u.query_plus, &mut r.query_plus),
            (&u.query_minus, &mut r.query_minus),
            (&u.query_colon, &mut r.query_colon),
        ] {
            *dst = src.iter().map(|(k, v)| (f(k), f(v))).collect();
        }
        if let Some(v) = r.query.get("tz") {
            r.tz = Some(v.to_string());
        }
        let pat = self.pattern();
        let whole = |s: &str| pat.and_then(|p| p.find(s)).is_some_and(|m| m.start() == 0 && m.end() == s.len());
        let empty = |s: &Option<String>| s.as_deref().is_none_or(str::is_empty);
        if whole(&u.host) && empty(&u.user) && empty(&u.password) {
            let authority = f(&u.host);
            if let Some((cred, host)) = authority.rsplit_once('@')
                && !cred.is_empty()
                && !host.is_empty()
            {
                match cred.split_once(':') {
                    Some((user, pw)) => {
                        r.user = Some(user.to_string());
                        r.password = Some(pw.to_string());
                    }
                    None => r.user = Some(cred.to_string()),
                }
                r.host = host.to_string();
            }
        }
        if let Some(user) = &u.user
            && whole(user)
            && empty(&u.password)
        {
            let cred = f(user);
            if let Some((user, pw)) = cred.split_once(':') {
                r.user = Some(user.to_string());
                r.password = Some(pw.to_string());
            }
        }
        r
    }
}

/// Every text field of a parsed URL that may hold a placeholder.
fn parsed_texts(u: &ParsedUrl) -> Vec<&str> {
    let mut out: Vec<&str> = vec![u.host.as_str()];
    for s in [&u.user, &u.password, &u.port_raw, &u.fullpath].into_iter().flatten() {
        out.push(s);
    }
    for p in [&u.query, &u.query_plus, &u.query_minus, &u.query_colon] {
        for (k, v) in p.iter() {
            out.push(k);
            out.push(v);
        }
    }
    out
}

/// `template_in_schema`: a declared marker before the first `://`.
pub fn in_schema(url: &str, schema: &TemplateSchema) -> Option<String> {
    let sep = url.find("://");
    for c in var_re().captures_iter(url) {
        let name = normalize_name(&c["name"]);
        let Some(start) = c.get(0).map(|m| m.start()) else { continue };
        if schema.contains(&name) && sep.is_none_or(|s| start < s) {
            return Some(name);
        }
    }
    None
}

/// Normalized `${NAME}` references in a YAML value (URL-shaped keys included).
pub fn references(v: &Yaml, out: &mut Vec<String>) {
    match v {
        Yaml::Str(s) => {
            for c in var_re().captures_iter(s) {
                let n = normalize_name(&c["name"]);
                if !out.contains(&n) {
                    out.push(n);
                }
            }
        }
        Yaml::Seq(items) => {
            for i in items {
                references(i, out);
            }
        }
        Yaml::Map(m) => {
            for (k, v) in m {
                if let Yaml::Str(ks) = k
                    && ks.contains("://")
                {
                    references(k, out);
                }
                references(v, out);
            }
        }
        Yaml::Null | Yaml::Bool(_) | Yaml::Int(_) | Yaml::Float(_) => {}
    }
}

#[cfg(test)]
#[cfg(feature = "config-yaml")]
mod tests {
    use super::*;

    fn schema(src: &str) -> TemplateSchema {
        TemplateSchema::parse(&super::super::yaml::parse(src).unwrap()).unwrap()
    }

    #[test]
    fn schema_forms() {
        let s = schema("- Target\n- host: localhost\n- port: 8080\n- flag: yes\n");
        assert_eq!(s.variables[0], ("target".into(), None));
        assert_eq!(s.default_of("host"), Some("localhost"));
        assert_eq!(s.default_of("port"), Some("8080"));
        assert_eq!(s.default_of("flag"), Some("yes"));
        assert!(TemplateSchema::parse(&super::super::yaml::parse("- a\n- A\n").unwrap()).is_err());
        assert!(TemplateSchema::parse(&super::super::yaml::parse("- bad-name\n").unwrap()).is_err());
    }

    #[test]
    fn resolution_order() {
        let s = schema("a:\nb: dflt\nc:\n");
        let env: BTreeMap<String, String> = [("APPRISE_TEMPLATE_C".to_string(), " envc ".to_string())].into();
        let vars = TemplateVars::new().with("A", "va").with("b", "  ").environment(env);
        let v = vars.resolve(&s, None).unwrap();
        assert_eq!(v["a"], "va");
        assert_eq!(v["b"], "dflt");
        assert_eq!(v["c"], "envc");
        let err = TemplateVars::new().no_environment().resolve(&s, None).unwrap_err();
        assert_eq!(err.variable.as_deref(), Some("a"));
    }

    #[test]
    fn placeholders_round_trip() {
        let s = schema("- host\n- path\n");
        let mut p = Placeholders::new(s, "").unwrap();
        let enc = p.encode_url("json://${HOST}/${path}/${OTHER}");
        assert!(!enc.contains("${HOST}") && enc.contains("${OTHER}"));
        let u = crate::url::parse_url(&enc).unwrap();
        assert_eq!(p.used_by(&u), vec!["host".to_string(), "path".to_string()]);
        let vals: BTreeMap<String, String> =
            [("host".to_string(), "me:pw@example.com".to_string()), ("path".to_string(), "x".to_string())].into();
        let r = p.substitute(&u, &vals);
        assert_eq!(r.host, "example.com");
        assert_eq!(r.user.as_deref(), Some("me"));
        assert_eq!(r.password.as_deref(), Some("pw"));
        assert_eq!(p.display(&enc), "json://${HOST}/${PATH}/${OTHER}");
    }
}
