//! YAML loading for configuration documents.
//!
//! `saphyr_parser` does the syntax; this module composes its events with the YAML 1.1 resolvers: plain scalars resolve to `yes`/`no`/`on`/`off` booleans, octal / hex / binary / sexagesimal integers, floats that need a dot, `~`/`null` (timestamps stay strings); the core `!!` tags; anchors, aliases and merge keys (`<<`, merged keys before a mapping's own).
//!
//! Rejected: multiple documents, custom `!tag`s, complex (collection) keys, self-referencing anchors.

use std::collections::BTreeMap;
use std::fmt;

use saphyr_parser::{Event, Parser, ScalarStyle, StrInput, Tag};

/// A parsed YAML value.
#[derive(Debug, Clone, PartialEq)]
pub enum Yaml {
    /// `~`, `null` or an empty value.
    Null,
    /// A YAML 1.1 boolean (`true`, `yes`, `on`, ...).
    Bool(bool),
    /// An integer (decimal, octal, hex, binary or sexagesimal).
    Int(i128),
    Float(f64),
    /// A string (also timestamps).
    Str(String),
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

/// Parse one YAML document. An empty document is `Null`.
pub fn parse(src: &str) -> R<Yaml> {
    let mut c = Composer { events: Parser::new_from_str(src), anchors: BTreeMap::new(), depth: 0, line: 1 };
    let mut doc = None;
    loop {
        let ev = c.next()?;
        if matches!(ev, Event::StreamEnd) {
            return Ok(doc.unwrap_or(Yaml::Null));
        }
        if matches!(ev, Event::DocumentStart(_)) {
            if doc.is_some() {
                return c.err("expected a single document in the stream");
            }
            doc = Some(c.node()?);
        }
    }
}

const MAX_DEPTH: usize = 200;

/// Builds `Yaml` values from `saphyr_parser` events.
struct Composer<'a> {
    events: Parser<'a, StrInput<'a>>,
    anchors: BTreeMap<usize, Yaml>,
    depth: usize,
    line: usize,
}

impl<'a> Composer<'a> {
    fn err<T>(&self, msg: impl Into<String>) -> R<T> {
        Err(YamlError { line: self.line, message: msg.into() })
    }

    fn next(&mut self) -> R<Event<'a>> {
        match self.events.next_event() {
            None => Ok(Event::StreamEnd),
            Some(Ok((ev, span))) => {
                self.line = span.start.line();
                Ok(ev)
            }
            Some(Err(e)) => Err(YamlError { line: e.marker().line(), message: e.info().into() }),
        }
    }

    /// Next node; `None` at the end of the enclosing collection.
    fn item(&mut self) -> R<Option<Yaml>> {
        let ev = self.next()?;
        if matches!(ev, Event::SequenceEnd | Event::MappingEnd) {
            return Ok(None);
        }
        self.compose(ev).map(Some)
    }

    fn node(&mut self) -> R<Yaml> {
        let ev = self.next()?;
        self.compose(ev)
    }

    fn compose(&mut self, ev: Event<'a>) -> R<Yaml> {
        let (anchor, value) = match ev {
            Event::Alias(id) => {
                return match self.anchors.get(&id) {
                    Some(v) => Ok(v.clone()),
                    None => self.err("found undefined alias"),
                };
            }
            Event::Scalar(text, style, anchor, tag) => {
                let v = match tag {
                    Some(t) => self.tagged_scalar(&tag_name(&t), &text)?,
                    None if style == ScalarStyle::Plain => resolve_scalar(&text),
                    None => Yaml::Str(text.into_owned()),
                };
                (anchor, v)
            }
            Event::SequenceStart(anchor, tag) => {
                self.enter()?;
                let mut items = Vec::new();
                while let Some(v) = self.item()? {
                    items.push(v);
                }
                self.depth -= 1;
                (anchor, self.tagged_collection(tag.map(|t| tag_name(&t)), "seq", Yaml::Seq(items))?)
            }
            Event::MappingStart(anchor, tag) => {
                self.enter()?;
                let mut map = MapBuilder::default();
                while let Some(k) = self.item()? {
                    let v = self.node()?;
                    map.insert(k, v, self)?;
                }
                self.depth -= 1;
                (anchor, self.tagged_collection(tag.map(|t| tag_name(&t)), "map", map.finish())?)
            }
            Event::Nothing
            | Event::StreamStart
            | Event::StreamEnd
            | Event::DocumentStart(_)
            | Event::DocumentEnd
            | Event::SequenceEnd
            | Event::MappingEnd => return self.err("unexpected event"),
        };
        if anchor != 0 {
            self.anchors.insert(anchor, value.clone());
        }
        Ok(value)
    }

    fn enter(&mut self) -> R<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH { self.err("nesting too deep") } else { Ok(()) }
    }

    /// Value of an explicitly tagged scalar.
    fn tagged_scalar(&self, tag: &str, text: &str) -> R<Yaml> {
        match tag {
            "tag:yaml.org,2002:str" => Ok(Yaml::Str(text.into())),
            "tag:yaml.org,2002:int" => resolve_int(text).map_or_else(|| self.err("invalid integer"), Ok),
            "tag:yaml.org,2002:float" => resolve_float(text)
                .or_else(|| text.parse().ok().map(Yaml::Float))
                .map_or_else(|| self.err("invalid float"), Ok),
            "tag:yaml.org,2002:bool" => match text.to_lowercase().as_str() {
                "yes" | "true" | "on" => Ok(Yaml::Bool(true)),
                "no" | "false" | "off" => Ok(Yaml::Bool(false)),
                _ => self.err("invalid boolean"),
            },
            "tag:yaml.org,2002:null" => Ok(Yaml::Null),
            "tag:yaml.org,2002:seq" => self.err("expected a sequence node"),
            "tag:yaml.org,2002:map" => self.err("expected a mapping node"),
            other => self.err(format!("could not determine a constructor for the tag '{other}'")),
        }
    }

    fn tagged_collection(&self, tag: Option<String>, kind: &str, value: Yaml) -> R<Yaml> {
        let Some(tag) = tag else { return Ok(value) };
        match tag.strip_prefix("tag:yaml.org,2002:") {
            Some(k) if k == kind => Ok(value),
            Some("str" | "int" | "float" | "bool" | "null") => self.err("expected a scalar node"),
            Some("seq") => self.err("expected a sequence node"),
            Some("map") => self.err("expected a mapping node"),
            _ => self.err(format!("could not determine a constructor for the tag '{tag}'")),
        }
    }
}

fn tag_name(t: &Tag) -> String {
    format!("{}{}", t.handle, t.suffix)
}

/// Mapping under construction: merge-key (`<<`) sources and own entries, combined when finished: merged keys first, own keys override their values.
#[derive(Default)]
struct MapBuilder {
    merge: Vec<(Yaml, Yaml)>,
    own: Vec<(Yaml, Yaml)>,
}

impl MapBuilder {
    fn insert(&mut self, key: Yaml, value: Yaml, p: &Composer) -> R<()> {
        if matches!(key, Yaml::Seq(_) | Yaml::Map(_)) {
            return p.err("collection keys are not supported");
        }
        if key.as_str() == Some("<<") {
            match value {
                Yaml::Map(entries) => self.merge.extend(entries),
                Yaml::Seq(items) => {
                    let mut sub = Vec::new();
                    for src in items {
                        let Yaml::Map(entries) = src else { return p.err("expected a mapping for merging") };
                        sub.push(entries);
                    }
                    for entries in sub.into_iter().rev() {
                        self.merge.extend(entries);
                    }
                }
                Yaml::Null | Yaml::Bool(_) | Yaml::Int(_) | Yaml::Float(_) | Yaml::Str(_) => {
                    return p.err("expected a mapping or list of mappings for merging");
                }
            }
            return Ok(());
        }
        self.own.push((key, value));
        Ok(())
    }

    fn finish(self) -> Yaml {
        let mut map = Vec::new();
        for (k, v) in self.merge.into_iter().chain(self.own) {
            set(&mut map, k, v);
        }
        Yaml::Map(map)
    }
}

fn set(map: &mut Vec<(Yaml, Yaml)>, key: Yaml, value: Yaml) {
    if let Some(slot) = map.iter_mut().find(|(k, _)| *k == key) {
        slot.1 = value;
    } else {
        map.push((key, value));
    }
}

/// YAML 1.1 implicit resolvers for a plain scalar.
fn resolve_scalar(text: &str) -> Yaml {
    match text {
        "" | "~" | "null" | "Null" | "NULL" => return Yaml::Null,
        "yes" | "Yes" | "YES" | "true" | "True" | "TRUE" | "on" | "On" | "ON" => return Yaml::Bool(true),
        "no" | "No" | "NO" | "false" | "False" | "FALSE" | "off" | "Off" | "OFF" => return Yaml::Bool(false),
        _ => {}
    }
    if let Some(i) = resolve_int(text) {
        return i;
    }
    if let Some(f) = resolve_float(text) {
        return f;
    }
    Yaml::Str(text.to_string())
}

fn resolve_int(text: &str) -> Option<Yaml> {
    let re = crate::regex!(
        r"^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$"
    );
    if !re.is_match(text) {
        return None;
    }
    let v = text.replace('_', "");
    let (sign, v) = match v.strip_prefix('-') {
        Some(rest) => (-1i128, rest.to_string()),
        None => (1, v.strip_prefix('+').unwrap_or(&v).to_string()),
    };
    let n = if v == "0" {
        0
    } else if let Some(b) = v.strip_prefix("0b") {
        i128::from_str_radix(b, 2).ok()?
    } else if let Some(h) = v.strip_prefix("0x") {
        i128::from_str_radix(h, 16).ok()?
    } else if let Some(o) = v.strip_prefix('0') {
        i128::from_str_radix(o, 8).ok()?
    } else if v.contains(':') {
        let mut total: i128 = 0;
        for part in v.split(':') {
            total = total.checked_mul(60)?.checked_add(part.parse::<i128>().ok()?)?;
        }
        total
    } else {
        v.parse::<i128>().ok()?
    };
    Some(Yaml::Int(sign * n))
}

fn resolve_float(text: &str) -> Option<Yaml> {
    let re = crate::regex!(
        r"^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$"
    );
    if !re.is_match(text) {
        return None;
    }
    let v = text.replace('_', "").to_lowercase();
    let (sign, v) = match v.strip_prefix('-') {
        Some(rest) => (-1.0, rest.to_string()),
        None => (1.0, v.strip_prefix('+').unwrap_or(&v).to_string()),
    };
    let f = if v == ".inf" {
        f64::INFINITY
    } else if v == ".nan" {
        f64::NAN
    } else if v.contains(':') {
        let mut total = 0.0;
        for part in v.split(':') {
            total = total * 60.0 + part.parse::<f64>().ok()?;
        }
        total
    } else {
        v.parse::<f64>().ok()?
    };
    Some(Yaml::Float(sign * f))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Yaml {
        Yaml::Str(v.into())
    }

    #[test]
    fn common_document_shapes() {
        let doc =
            "version: 1\nurls:\n  - json://localhost:\n      tag: a, b\n      +X-Head: v\n  - mailto://u:p@x.com\n";
        let y = parse(doc).unwrap();
        assert_eq!(y.get("version"), Some(&Yaml::Int(1)));
        let urls = y.get("urls").unwrap().as_seq().unwrap();
        assert_eq!(urls.len(), 2);
        let first = urls[0].as_map().unwrap();
        assert_eq!(first[0].0, s("json://localhost"));
        assert_eq!(first[0].1.get("tag"), Some(&s("a, b")));
        assert_eq!(first[0].1.get("+X-Head"), Some(&s("v")));
        assert_eq!(urls[1], s("mailto://u:p@x.com"));
    }

    #[test]
    fn indentless_and_lists() {
        let y = parse("urls:\n- a\n- b: 1\n  c: [x, 'y', \"z\"]\ntag: t\n").unwrap();
        let urls = y.get("urls").unwrap().as_seq().unwrap();
        assert_eq!(urls[0], s("a"));
        assert_eq!(urls[1].get("c").unwrap().as_seq().unwrap().len(), 3);
        assert_eq!(y.get("tag"), Some(&s("t")));
    }

    #[test]
    fn scalars() {
        let y = parse("a: yes\nb: off\nc: 012\nd: 0x1f\ne: 1.5\nf: ~\ng: 1:30\nh: 1e5\ni: '1'\nj: .inf\n").unwrap();
        assert_eq!(y.get("a"), Some(&Yaml::Bool(true)));
        assert_eq!(y.get("b"), Some(&Yaml::Bool(false)));
        assert_eq!(y.get("c"), Some(&Yaml::Int(10)));
        assert_eq!(y.get("d"), Some(&Yaml::Int(31)));
        assert_eq!(y.get("e"), Some(&Yaml::Float(1.5)));
        assert_eq!(y.get("f"), Some(&Yaml::Null));
        assert_eq!(y.get("g"), Some(&Yaml::Int(90)));
        assert_eq!(y.get("h"), Some(&s("1e5")));
        assert_eq!(y.get("i"), Some(&s("1")));
        assert_eq!(y.get("j"), Some(&Yaml::Float(f64::INFINITY)));
    }

    #[test]
    fn block_scalars() {
        let y = parse("a: |\n  l1\n  l2\n\nb: >-\n  f1\n  f2\n\n  f3\nc: |+\n  k\n\n").unwrap();
        assert_eq!(y.get("a"), Some(&s("l1\nl2\n")));
        assert_eq!(y.get("b"), Some(&s("f1 f2\nf3")));
        assert_eq!(y.get("c"), Some(&s("k\n\n")));
    }

    #[test]
    fn anchors_and_merge() {
        let y = parse("base: &b {x: 1, y: 2}\nother:\n  <<: *b\n  y: 3\nref: *b\n").unwrap();
        assert_eq!(y.get("other").unwrap().get("x"), Some(&Yaml::Int(1)));
        assert_eq!(y.get("other").unwrap().get("y"), Some(&Yaml::Int(3)));
        assert_eq!(y.get("ref").unwrap().get("y"), Some(&Yaml::Int(2)));
    }

    #[test]
    fn errors() {
        assert!(parse("a: b: c\n").is_err());
        assert!(parse("a: 1\n---\nb: 2\n").is_err());
        assert!(parse("a: [1, 2\n").is_err());
        assert!(parse("a: 'x\n").is_err());
        assert!(parse("a: !custom x\n").is_err());
        assert!(parse("a: &x [*x]\n").is_err());
    }

    #[test]
    fn tabs_in_text_and_comments() {
        let y = parse("a: \"x\ty\"\nb: |\n  \tz\nc: d # \te\ne: 'q\tr' #\t\n").unwrap();
        assert_eq!(y.get("a"), Some(&s("x\ty")));
        assert_eq!(y.get("b"), Some(&s("\tz\n")));
        assert_eq!(y.get("c"), Some(&s("d")));
        assert_eq!(y.get("e"), Some(&s("q\tr")));
    }

    #[test]
    fn scalar_text() {
        assert_eq!(Yaml::Null.to_text(), "");
        assert_eq!(Yaml::Bool(true).to_text(), "true");
        assert_eq!(Yaml::Float(1.5).to_text(), "1.5");
        assert_eq!(Yaml::Int(-3).to_text(), "-3");
    }
}
