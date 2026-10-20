//! `GET /details`: the service schemas in the shape of Apprise's `details()`.

use mercurio::{Kind, Param, ServiceDef};
use serde_json::{Map, Value, json};

/// One `schemas` entry; `enabled` is only given with `?all=yes`, as in Apprise.
pub fn schema(d: &ServiceDef, enabled: Option<bool>) -> Value {
    let secure = |s: &&&str| s.ends_with('s') && d.schemes.len() > 1;
    let mut out = json!({
        "service_name": d.name,
        "service_url": d.service_url,
        "setup_url": format!("{}/services/{}.html", mercurio::PAGES_URL, d.id),
        "details": details(d),
        "attachment_support": d.attachments,
        "category": "native",
        "protocols": d.schemes.iter().filter(|s| !secure(s)).collect::<Vec<_>>(),
        "secure_protocols": d.schemes.iter().filter(secure).collect::<Vec<_>>(),
    });
    if let Some(e) = enabled {
        out["enabled"] = Value::Bool(e);
    }
    out
}

/// The asset block of the response.
pub fn asset(a: &mercurio::Asset) -> Value {
    json!({
        "app_id": a.app_id,
        "app_desc": a.app_desc,
        "default_extension": a.default_extension,
        "theme": a.theme,
        "image_path_mask": a.image_path_mask,
        "image_url_mask": a.image_url_mask,
        "image_url_logo": a.image_url_logo,
    })
}

/// `templates`, `tokens`, `args` and `kwargs`, like Apprise's `plugins.details()`.
fn details(d: &ServiceDef) -> Value {
    let mut tokens = Map::new();
    for p in d.tokens {
        tokens.insert(p.key.into(), param(p, &["/"]));
    }
    tokens.insert(
        "schema".into(),
        json!({"name": "Schema", "type": "choice:string", "required": true, "values": d.schemes, "private": false, "map_to": "schema"}),
    );
    let (mut args, mut kwargs) = (Map::new(), Map::new());
    let usable = |p: &&Param| !p.ignored;
    for p in d.params.iter().chain(mercurio::COMMON_PARAMS).filter(usable) {
        if ["+", "-", ":"].contains(&p.prefix) {
            kwargs.entry(p.key).or_insert_with(|| param(p, &[",", " "]));
            continue;
        }
        if args.contains_key(p.key) {
            continue;
        }
        match p.sets.first() {
            Some(token) if p.name.is_empty() => {
                args.insert(p.key.into(), json!({"alias_of": token}));
            }
            _ => {
                args.insert(p.key.into(), param(p, &[",", " "]));
            }
        }
        for alias in p.aliases {
            args.entry(*alias).or_insert_with(|| json!({"alias_of": p.key}));
        }
    }
    json!({"templates": d.templates, "tokens": tokens, "args": args, "kwargs": kwargs})
}

/// One token or argument; `delim` applies to lists that declare none.
fn param(p: &Param, delim: &[&str]) -> Value {
    let kind = match p.kind {
        Kind::Choice => "choice:string",
        Kind::List => "list:string",
        Kind::String | Kind::Int | Kind::Float | Kind::Bool | Kind::Email => p.kind.as_str(),
        _ => p.kind.as_str(),
    };
    let mut m = Map::new();
    m.insert("name".into(), Value::from(if p.name.is_empty() { p.key } else { p.name }));
    m.insert("type".into(), Value::from(kind));
    m.insert("required".into(), Value::Bool(p.required));
    m.insert("private".into(), Value::Bool(p.secret));
    m.insert("map_to".into(), Value::from(p.key));
    if !p.default.is_empty() {
        m.insert("default".into(), default(p));
    }
    if !p.values.is_empty() {
        m.insert("values".into(), Value::from(p.values));
    }
    if let Some(v) = p.min {
        m.insert("min".into(), Value::from(v));
    }
    if let Some(v) = p.max {
        m.insert("max".into(), Value::from(v));
    }
    if p.kind == Kind::List {
        let own: Vec<String> = p.delim.chars().map(String::from).collect();
        m.insert("delim".into(), if own.is_empty() { Value::from(delim) } else { Value::from(own) });
        m.insert("group".into(), Value::from(p.group));
    }
    if !p.pattern.is_empty() {
        m.insert("regex".into(), json!([p.pattern, null]));
    }
    if !p.prefix.is_empty() {
        m.insert("prefix".into(), Value::from(p.prefix));
    }
    Value::Object(m)
}

/// The declared default as a JSON value of the parameter's type.
fn default(p: &Param) -> Value {
    match p.kind {
        Kind::Bool => Value::Bool(mercurio::parse::parse_bool(p.default, false)),
        Kind::Int => p.default.parse::<i64>().map(Value::from).unwrap_or_else(|_| p.default.into()),
        Kind::Float => p.default.parse::<f64>().map(Value::from).unwrap_or_else(|_| p.default.into()),
        Kind::String | Kind::Email | Kind::Choice | Kind::List => p.default.into(),
        _ => p.default.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(id: &str) -> &'static ServiceDef {
        mercurio::services().iter().copied().find(|d| d.id == id).expect("service")
    }

    #[test]
    fn schema_has_apprise_shape() {
        let s = schema(def("gotify"), None);
        assert!(s["setup_url"].as_str().is_some_and(|u| u.ends_with("/services/gotify.html")), "{s}");
        assert_eq!(s["category"], "native");
        assert!(s.get("enabled").is_none());
        let details = &s["details"];
        assert!(details["templates"].as_array().is_some_and(|t| !t.is_empty()));
        assert_eq!(details["tokens"]["schema"]["values"], json!(["gotify", "gotifys"]));
        assert_eq!(details["tokens"]["token"]["private"], true);
        assert_eq!(
            details["args"]["verify"],
            json!({"name": "Verify TLS certificates", "type": "bool", "required": false, "private": false, "map_to": "verify", "default": true})
        );
        assert_eq!(details["args"]["retry"]["max"], 10);
        assert_eq!(details["args"]["pass"], json!({"alias_of": "password"}));
        assert!(details["args"].get("emojis").is_none(), "ignored keys are left out");
        assert_eq!(schema(def("gotify"), Some(false))["enabled"], false);
    }

    #[test]
    fn aliases_lists_and_prefixed_keys() {
        let details = &schema(def("nextcloud"), None)["details"];
        assert_eq!(details["kwargs"]["headers"]["prefix"], "+");
        assert!(details["args"].get("headers").is_none());
        assert_eq!(details["args"]["to"], json!({"alias_of": "targets"}));
        let email = &schema(def("email"), None)["details"];
        assert_eq!(email["tokens"]["targets"]["type"], "list:string");
        assert_eq!(email["tokens"]["targets"]["delim"], json!(["/"]));
        assert_eq!(email["tokens"]["targets"]["group"], json!(["target_email"]));
    }
}
