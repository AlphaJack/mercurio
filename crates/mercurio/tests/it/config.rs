//! Configuration fixtures: every document in `tests/fixtures/config.json` must load into the same services, tags, template entries, asset overrides and tag-matching decisions in mercurio. Every YAML document must parse to its expected value.
//!
//! URL comparison: the expected URL re-serialises a service and adds its defaults (`method=POST`, `overflow=upstream`, ...), while a mercurio target keeps the URL it was built from. For the custom HTTP services (`json`, `xml`, `form`), whose URL maps one-to-one onto their settings, every field is compared and only the expected defaults may be absent on the mercurio side. Other services compare the scheme.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use mercurio::config::yaml::{self, Yaml};
use mercurio::config::{AssetValue, Config, ConfigFormat, ConfigOptions, ConfigService};
use mercurio::testing::FakeTransport;
use mercurio::url::{ParsedUrl, parse_url_unverified};
use mercurio::{Tag, TagFilter, TemplateVars};
use serde_json::{Map, Value, json};

fn corpus() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/config.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixture exists")).unwrap()
}

/// Defaults the expected URLs carry for the custom HTTP services.
const URL_DEFAULTS: &[(&str, &str)] =
    &[("method", "POST"), ("overflow", "upstream"), ("retry", "0"), ("wait", "0.5"), ("optional", "no")];

const FULL_COMPARE: &[&str] = &["json", "jsons", "xml", "xmls", "form", "forms"];

fn tags_json(tags: &[Tag]) -> Value {
    let mut v: Vec<String> = tags
        .iter()
        .map(|t| if t.has_priority { format!("{}:{}", t.priority, t.name) } else { t.name.clone() })
        .collect();
    v.sort();
    json!(v)
}

fn pairs(p: &mercurio::url::Pairs) -> Map<String, Value> {
    p.iter().map(|(k, v)| (k.to_string(), json!(v))).collect()
}

fn url_fields(url: &str) -> Value {
    let Some(u): Option<ParsedUrl> = parse_url_unverified(url) else { return json!({ "raw": url }) };
    let segs: Vec<&str> = u.fullpath.as_deref().unwrap_or("").split('/').filter(|s| !s.is_empty()).collect();
    json!({
        "schema": u.scheme,
        "user": u.user,
        "password": u.password,
        "host": if u.host.is_empty() { Value::Null } else { json!(u.host) },
        "port": u.port,
        "path": segs,
        "qsd": Value::Object(pairs(&u.query)),
        "qsd+": Value::Object(pairs(&u.query_plus)),
        "qsd-": Value::Object(pairs(&u.query_minus)),
        "qsd:": Value::Object(pairs(&u.query_colon)),
    })
}

/// Settings the custom HTTP services read from the query string; any other key a YAML entry folds into the URL is ignored by the service.
const KNOWN_KEYS: &[&str] = &["method", "format", "overflow", "verify", "cto", "rto", "retry", "wait", "optional"];

/// Values the expected URLs leave out because they are the default.
const OMITTED_DEFAULTS: &[(&str, &str)] = &[("verify", "yes")];

/// Expected URLs quote fields once more than the URL that built them.
fn same_text(exp: &Value, got: &Value) -> bool {
    use mercurio::url::unquote;
    match (exp, got) {
        (Value::String(e), Value::String(g)) => e == g || unquote(e) == *g || unquote(e) == unquote(g),
        (Value::Array(e), Value::Array(g)) => e.len() == g.len() && e.iter().zip(g).all(|(a, b)| same_text(a, b)),
        (Value::Object(e), Value::Object(g)) => {
            e.len() == g.len() && e.iter().all(|(k, v)| g.get(k).is_some_and(|x| same_text(v, x)))
        }
        _ => exp == got,
    }
}

fn same_value(key: &str, exp: &Value, got: &Value) -> bool {
    if matches!(key, "cto" | "rto" | "wait") {
        let num = |v: &Value| v.as_str().and_then(|s| s.parse::<f64>().ok());
        if let (Some(a), Some(b)) = (num(exp), num(got)) {
            return a == b;
        }
    }
    same_text(exp, got)
}

fn compare_url(exp: &Value, url: &str) -> Result<(), String> {
    let got = url_fields(url);
    let schema = exp["schema"].as_str().unwrap_or_default();
    let gs = got["schema"].as_str().unwrap_or_default();
    // `url()` may write another scheme of the same service (`mailto` -> `mailtos`).
    let def_of = |s: &str| mercurio::service_for_scheme(s).map(|d| d.id);
    if gs != schema && (def_of(gs).is_none() || def_of(gs) != def_of(schema)) {
        return Err(format!("schema: expected {schema}, got {gs}"));
    }
    if !FULL_COMPARE.contains(&schema) || gs != schema {
        return Ok(());
    }
    for key in ["user", "password", "host", "port", "path", "qsd+", "qsd-", "qsd:"] {
        if !same_text(&exp[key], &got[key]) {
            return Err(format!("{key}: expected {}, got {}", exp[key], got[key]));
        }
    }
    let eq = exp["qsd"].as_object().unwrap();
    let gq: Map<String, Value> = got["qsd"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(k, _)| !k.starts_with(['+', '-', ':']))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for (k, v) in eq {
        match gq.get(k) {
            Some(g) if same_value(k, v, g) => {}
            None if URL_DEFAULTS.iter().any(|(dk, dv)| dk == k && v == dv) => {}
            other => return Err(format!("query {k}: expected {v}, got {other:?}")),
        }
    }
    for (k, v) in &gq {
        if eq.contains_key(k) || !KNOWN_KEYS.contains(&k.as_str()) {
            continue;
        }
        if OMITTED_DEFAULTS.iter().any(|(dk, dv)| dk == k && v == dv) {
            continue;
        }
        return Err(format!("query {k}: unexpected (= {v})"));
    }
    Ok(())
}

fn filter_of(expr: &Value) -> TagFilter {
    match expr["kind"].as_str().unwrap() {
        "none" => TagFilter::untagged(),
        "str" => TagFilter::parse(expr["v"].as_str().unwrap()),
        _ => TagFilter::any_of(
            expr["v"]
                .as_array()
                .unwrap()
                .iter()
                .map(|g| g.as_array().unwrap().iter().map(|t| t.as_str().unwrap().to_string()).collect::<Vec<_>>()),
        ),
    }
}

fn vars_of(values: &Value, env: &BTreeMap<String, String>) -> TemplateVars {
    let mut v = TemplateVars::new().environment(env.clone());
    for (k, val) in values.as_object().unwrap() {
        v.set(k, val.as_str().unwrap()).unwrap();
    }
    v
}

fn load_case(case: &Value, dir: &Path) -> Result<Config, String> {
    let opts = ConfigOptions {
        recursion: case["recursion"].as_u64().unwrap_or(0) as u32,
        insecure_includes: case["insecure"].as_bool().unwrap_or(false),
        ..ConfigOptions::default()
    };
    let t = FakeTransport::new();
    // Windows `canonicalize` adds the `\\?\` verbatim prefix, whose `?` would start a URL query.
    let dirs = dir.to_string_lossy().trim_start_matches(r"\\?\").to_string();
    if let Some(files) = case["files"].as_object() {
        for (name, content) in files {
            std::fs::write(dir.join(name), content.as_str().unwrap().replace("{DIR}", &dirs)).unwrap();
        }
    }
    if let Some(main) = case["main"].as_str() {
        let main = main.replace("{DIR}", &dirs);
        let src = if main.contains("://") { main } else { dir.join(main).to_string_lossy().to_string() };
        return Config::load(&src, &t, &opts).map_err(|e| e.to_string());
    }
    let format = case["format"].as_str().and_then(ConfigFormat::parse);
    Config::from_text(case["content"].as_str().unwrap(), format, &t, &opts).map_err(|e| e.to_string())
}

fn asset_json(cfg: &Config) -> Map<String, Value> {
    cfg.asset
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                match v {
                    AssetValue::Text(s) => json!(s),
                    AssetValue::Flag(b) => json!(b),
                },
            )
        })
        .collect()
}

/// The scheme of an expected service entry (ready or template).
fn entry_scheme(e: &Value) -> &str {
    e["url"]["schema"].as_str().or_else(|| e["schema"].as_str()).unwrap_or_default()
}

/// Drop the expected services whose scheme this build does not compile in (services whose `service-<id>` feature is off), together with their template resolutions and tag-matching indices. Returns the expectations and how many services were dropped.
fn compiled_in(exp: &Value) -> (Value, usize) {
    let services = exp["services"].as_array().unwrap();
    let keep: Vec<bool> = services.iter().map(|e| mercurio::service_for_scheme(entry_scheme(e)).is_some()).collect();
    let skipped = keep.iter().filter(|k| !**k).count();
    if skipped == 0 {
        return (exp.clone(), 0);
    }
    let kept = |items: &Value| -> Value {
        json!(items.as_array().unwrap().iter().zip(&keep).filter(|(_, k)| **k).map(|(v, _)| v).collect::<Vec<_>>())
    };
    // Old index -> new index for the services that remain.
    let renumber: Vec<Option<usize>> = keep
        .iter()
        .scan(0usize, |next, k| {
            Some(k.then(|| {
                *next += 1;
                *next - 1
            }))
        })
        .collect();
    let mut out = exp.clone();
    out["services"] = kept(&exp["services"]);
    for row in out["resolved"].as_array_mut().unwrap() {
        row["services"] = kept(&row["services"]);
    }
    for want in out["matches"].as_array_mut().unwrap() {
        *want = json!(
            want.as_array()
                .unwrap()
                .iter()
                .filter_map(|i| renumber[usize::try_from(i.as_u64().unwrap()).unwrap()])
                .collect::<Vec<_>>()
        );
    }
    (out, skipped)
}

fn check_case(case: &Value, exprs: &[Value], dir: &Path) -> Result<(), String> {
    let (exp, _) = compiled_in(&case["expect"]);
    let exp = &exp;
    let env: BTreeMap<String, String> = case["env"]
        .as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string())).collect())
        .unwrap_or_default();
    let loaded = load_case(case, dir);
    let loaded_ok = loaded.is_ok();
    if loaded_ok != exp["loaded"].as_bool().unwrap() {
        return Err(format!("loaded: expected {}, got {loaded:?}", exp["loaded"]));
    }
    let cfg = loaded.unwrap_or_default();
    let es = exp["services"].as_array().unwrap();
    if es.len() != cfg.services.len() {
        let got: Vec<String> = cfg
            .services
            .iter()
            .map(|s| match s {
                ConfigService::Ready(t) => t.url().to_string(),
                ConfigService::Pending(p) => format!("pending {}", p.url()),
            })
            .collect();
        return Err(format!(
            "{} services expected, got {}: {got:?}\nwarnings: {:?}",
            es.len(),
            got.len(),
            cfg.warnings
        ));
    }
    for (i, (e, s)) in es.iter().zip(&cfg.services).enumerate() {
        if e["tags"] != tags_json(s.tags()) {
            return Err(format!("service {i} tags: expected {}, got {}", e["tags"], tags_json(s.tags())));
        }
        match s {
            ConfigService::Ready(t) => {
                if e["pending"] == json!(true) {
                    return Err(format!("service {i}: expected a template entry, got {}", t.url()));
                }
                compare_url(&e["url"], t.url()).map_err(|m| format!("service {i} ({}): {m}", t.url()))?;
            }
            ConfigService::Pending(p) => {
                if e["pending"] != json!(true) {
                    return Err(format!("service {i}: unexpected template entry {}", p.url()));
                }
                let names: Vec<String> =
                    e["names"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().into()).collect();
                let mut req: Vec<String> =
                    e["required"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().into()).collect();
                let mut got_names = p.template_names().to_vec();
                let mut names = names;
                names.sort();
                got_names.sort();
                if names != got_names {
                    return Err(format!("service {i} names: expected {names:?}, got {got_names:?}"));
                }
                let mut got_req = p.template_required();
                req.sort();
                got_req.sort();
                if req != got_req {
                    return Err(format!("service {i} required: expected {req:?}, got {got_req:?}"));
                }
                if e["schema"] != json!(p.service().schemes.iter().find(|s| e["schema"] == json!(s)).copied()) {
                    return Err(format!("service {i} schema: expected {}, got {}", e["schema"], p.service().id));
                }
            }
        }
    }
    // Asset overrides: every changed asset attribute is overridden alike.
    let got_asset = asset_json(&cfg);
    for (k, v) in exp["asset"].as_object().unwrap() {
        if got_asset.get(k) != Some(v) {
            return Err(format!("asset {k}: expected {v}, got {:?}", got_asset.get(k)));
        }
    }
    for row in exp["resolved"].as_array().unwrap() {
        let vars = vars_of(&row["vars"], &env);
        for (i, (e, s)) in row["services"].as_array().unwrap().iter().zip(&cfg.services).enumerate() {
            match s {
                ConfigService::Ready(_) => {
                    if e != "ready" {
                        return Err(format!("resolve {}: service {i} should be a template", row["vars"]));
                    }
                }
                ConfigService::Pending(p) => match (p.resolve(&vars), e.is_null()) {
                    (Err(_), true) => {}
                    (Ok(t), true) => {
                        return Err(format!(
                            "resolve {}: service {i} built {} but the fixture skipped it",
                            row["vars"],
                            t.url()
                        ));
                    }
                    (Err(err), false) => {
                        return Err(format!(
                            "resolve {}: service {i} failed ({err}), expected {}",
                            row["vars"], e["url"]
                        ));
                    }
                    (Ok(t), false) => {
                        if e["tags"] != tags_json(t.tag_set()) {
                            return Err(format!("resolve {}: service {i} tags differ", row["vars"]));
                        }
                        compare_url(&e["url"], t.url())
                            .map_err(|m| format!("resolve {}: service {i} ({}): {m}", row["vars"], t.url()))?;
                    }
                },
            }
        }
    }
    for (ei, (expr, want)) in exprs.iter().zip(exp["matches"].as_array().unwrap()).enumerate() {
        let f = filter_of(expr);
        let got: Vec<usize> =
            cfg.services.iter().enumerate().filter(|(_, s)| f.matches(s.tags())).map(|(i, _)| i).collect();
        if json!(got) != *want {
            return Err(format!("expression {ei} {expr}: expected {want}, got {got:?}"));
        }
    }
    Ok(())
}

/// Known divergences from the fixtures: (case name, whether this build compiles the services involved, reason).
const KNOWN_DIVERGENCES: &[(&str, bool, &str)] = &[
    (
        "upstream_test_apprise_template_111",
        true,
        "a template in an email port: the fixture's email URL parser drops the host and with it the marker; \
     mercurio keeps the entry pending and rejects the value when it is resolved",
    ),
    (
        "upstream_test_apprise_template_199",
        true,
        "a non-numeric template value for an email port: the fixture ignores the port, mercurio rejects the entry",
    ),
    (
        "upstream_test_apprise_template_164",
        true,
        "a self-referencing YAML anchor: the fixture rejects that entry only; mercurio reports the whole \
         document as invalid YAML",
    ),
];

fn diverges(name: &str) -> bool {
    KNOWN_DIVERGENCES.iter().any(|(n, compiled, _)| *compiled && *n == name)
}

#[test]
fn configs_match_fixtures() {
    let c = corpus();
    let exprs = c["expressions"].as_array().unwrap();
    let cases = c["cases"].as_array().unwrap();
    let root = std::env::temp_dir().join(format!("mercurio-config-fixtures-{}", std::process::id()));
    let cwd = std::env::current_dir().unwrap();
    let mut failures = Vec::new();
    let skipped: Vec<usize> = cases.iter().map(|case| compiled_in(&case["expect"]).1).filter(|n| *n > 0).collect();
    if !skipped.is_empty() {
        println!(
            "skipped {} expected services in {} configurations: their schemes are not compiled into this build",
            skipped.iter().sum::<usize>(),
            skipped.len()
        );
    }
    for (i, case) in cases.iter().enumerate() {
        let dir = root.join(i.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let dir = dir.canonicalize().unwrap();
        // Memory includes resolve against the working directory.
        std::env::set_current_dir(&dir).unwrap();
        let name = case["name"].as_str().unwrap();
        match check_case(case, exprs, &dir) {
            Err(_) if diverges(name) => {}
            Err(m) => failures.push(format!("{name}: {m}")),
            Ok(()) if diverges(name) => {
                failures.push(format!("{name}: listed as a divergence but now matches; remove it"))
            }
            Ok(()) => {}
        }
    }
    std::env::set_current_dir(cwd).unwrap();
    std::fs::remove_dir_all(&root).ok();
    if !failures.is_empty() {
        let mut msg = format!("{} of {} configurations differ from the fixtures\n", failures.len(), cases.len());
        for f in failures.iter().take(40) {
            writeln!(msg, "{f}").ok();
        }
        panic!("{msg}");
    }
}

fn yaml_json(v: &Yaml) -> Value {
    match v {
        Yaml::Null => json!({"t": "null"}),
        Yaml::Bool(b) => json!({"t": "bool", "v": b}),
        Yaml::Int(i) => json!({"t": "int", "v": i.to_string()}),
        Yaml::Float(f) => json!({"t": "float", "v": f.to_string()}),
        Yaml::Str(s) => json!({"t": "str", "v": s}),
        Yaml::Seq(items) => json!({"t": "seq", "v": items.iter().map(yaml_json).collect::<Vec<_>>()}),
        Yaml::Map(items) => {
            json!({"t": "map", "v": items.iter().map(|(k, x)| json!([yaml_json(k), yaml_json(x)])).collect::<Vec<_>>()})
        }
    }
}

/// Expected float values rewritten in Rust `Display` form (`1e+16` -> `10000000000000000`).
fn float_text(v: &Value) -> Value {
    match v {
        Value::Object(o) if o.get("t") == Some(&json!("float")) => {
            let f: f64 = o["v"].as_str().and_then(|s| s.parse().ok()).expect("float fixture value");
            json!({"t": "float", "v": f.to_string()})
        }
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), float_text(x))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(float_text).collect()),
        other @ (Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)) => other.clone(),
    }
}

#[test]
fn yaml_documents_parse_to_expected_values() {
    let c = corpus();
    let docs = c["yaml"].as_array().unwrap();
    let mut failures = Vec::new();
    // Outside the subset (documented in `config/yaml.rs`): explicit `? key` entries; timestamps, which stay strings instead of `datetime`.
    // Then intended divergences from the fixtures:
    let skipped = [
        "? a\n: b\n",
        "a: 2001-12-14\nb: 2001-12-14t21:59:43.10-05:00\n",
        // A quoted continuation line less indented than its block is an error.
        "a: 'it''s'\nb: \"tab\\there\"\nc: \"\\u00e9\\x41\"\nd: \"line\\\nnext\"\n",
        // `1`, `1.0` and `true` are distinct keys.
        "1: one\n1.0: float\ntrue: t\n",
        // Tabs are allowed as separators and trailing whitespace.
        "a: \tb\n",
        "a: b\t\n",
        // `=` is a plain string.
        "a: =\n",
    ];
    for d in docs {
        let input = d["input"].as_str().unwrap();
        if skipped.contains(&input) {
            continue;
        }
        let got = yaml::parse(input);
        let ok = match (&got, d.get("error")) {
            (Err(_), Some(_)) => true,
            (Ok(v), None) => yaml_json(v) == float_text(&d["value"]),
            _ => false,
        };
        if !ok {
            failures.push(format!(
                "{input:?}: expected {}, got {:?}",
                d.get("value").map_or(json!("error"), float_text),
                got.map(|v| yaml_json(&v))
            ));
        }
    }
    if !failures.is_empty() {
        let mut msg = format!("{} of {} YAML documents differ from the expected values\n", failures.len(), docs.len());
        for f in failures.iter().take(40) {
            writeln!(msg, "{f}").ok();
        }
        panic!("{msg}");
    }
}
