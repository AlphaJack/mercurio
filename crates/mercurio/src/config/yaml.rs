//! YAML loading for configuration documents.
//!
//! `saphyr_parser` does the syntax (feature `config-yaml`; without it [`parse`] always fails); this module composes its events with the YAML 1.1 resolvers: plain scalars resolve to `yes`/`no`/`on`/`off` booleans, octal / hex / binary / sexagesimal integers, floats that need a dot, `~`/`null` (timestamps stay strings); the core `!!` tags; anchors, aliases and merge keys (`<<`, merged keys before a mapping's own).
//!
//! Rejected: multiple documents, custom `!tag`s, complex (collection) keys, self-referencing anchors.

use std::fmt;

/// A parsed YAML value.
#[derive(Debug, Clone, PartialEq)]
pub enum Yaml {
    /// `~`, `null` or an empty value.
    Null,
    /// A YAML 1.1 boolean (`true`, `yes`, `on`, ...).
    Bool(bool),
    /// An integer (decimal, octal, hex, binary or sexagesimal).
    Int(i128),
    /// A float (also `.inf` and `.nan`).
    Float(f64),
    /// A string (also timestamps).
    Str(String),
    /// A sequence.
    Seq(Vec<Yaml>),
    /// Insertion-ordered; a repeated key keeps its first position and the last value.
    Map(Vec<(Yaml, Yaml)>),
}

impl Yaml {
    /// The string, when this is [`Yaml::Str`].
    pub fn as_str(&self) -> Option<&str> {
        if let Yaml::Str(s) = self { Some(s) } else { None }
    }

    /// The entries, when this is [`Yaml::Map`].
    pub fn as_map(&self) -> Option<&[(Yaml, Yaml)]> {
        if let Yaml::Map(m) = self { Some(m) } else { None }
    }

    /// The items, when this is [`Yaml::Seq`].
    pub fn as_seq(&self) -> Option<&[Yaml]> {
        if let Yaml::Seq(s) = self { Some(s) } else { None }
    }

    /// Value of a string key in a mapping.
    pub fn get(&self, key: &str) -> Option<&Yaml> {
        self.as_map()?.iter().find(|(k, _)| k.as_str() == Some(key)).map(|(_, v)| v)
    }

    /// `true` for [`Yaml::Null`].
    pub fn is_null(&self) -> bool {
        matches!(self, Yaml::Null)
    }

    /// Whether the node holds a value: false for null, `false`, zero, empty strings and empty collections.
    pub fn has_value(&self) -> bool {
        match self {
            Yaml::Null => false,
            Yaml::Bool(b) => *b,
            Yaml::Int(i) => *i != 0,
            Yaml::Float(f) => *f != 0.0,
            Yaml::Str(s) => !s.is_empty(),
            Yaml::Seq(s) => !s.is_empty(),
            Yaml::Map(m) => !m.is_empty(),
        }
    }

    /// Plain text of a scalar (null is empty, `true`, `1.5`, ...).
    pub fn to_text(&self) -> String {
        match self {
            Yaml::Null => String::new(),
            Yaml::Bool(b) => b.to_string(),
            Yaml::Int(i) => i.to_string(),
            Yaml::Float(f) => f.to_string(),
            Yaml::Str(s) => s.clone(),
            Yaml::Seq(_) | Yaml::Map(_) => format!("{self}"),
        }
    }
}

impl fmt::Display for Yaml {
    /// Diagnostic rendering: strings quoted, collections inline.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Yaml::Null => f.write_str("null"),
            Yaml::Str(s) => write!(f, "'{s}'"),
            Yaml::Seq(items) => {
                f.write_str("[")?;
                for (i, v) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{v}")?;
                }
                f.write_str("]")
            }
            Yaml::Map(items) => {
                f.write_str("{")?;
                for (i, (k, v)) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{k}: {v}")?;
                }
                f.write_str("}")
            }
            other @ (Yaml::Bool(_) | Yaml::Int(_) | Yaml::Float(_)) => f.write_str(&other.to_text()),
        }
    }
}

/// Parse failure with a 1-based line number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlError {
    /// 1-based line of the problem.
    pub line: usize,
    /// What went wrong.
    pub message: String,
}

impl fmt::Display for YamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for YamlError {}

type R<T> = std::result::Result<T, YamlError>;

#[cfg(feature = "config-yaml")]
mod parser;
#[cfg(feature = "config-yaml")]
pub use parser::parse;

/// Parse one YAML document: always an error, as this build lacks the `config-yaml` feature.
#[cfg(not(feature = "config-yaml"))]
pub fn parse(_src: &str) -> R<Yaml> {
    Err(YamlError { line: 1, message: "YAML support is not compiled in (Cargo feature `config-yaml`)".into() })
}
