use super::fold::fold_url;
use super::template::TemplateVars;
use super::yaml::Yaml;
use super::*;
use crate::testing::FakeTransport;

fn load(text: &str) -> Config {
    Config::from_text(text, None, &FakeTransport::new(), &ConfigOptions::default()).unwrap()
}

fn ready(cfg: &Config) -> Vec<(&str, Vec<String>)> {
    cfg.services
        .iter()
        .filter_map(|s| match s {
            ConfigService::Ready(t) => Some((t.url(), t.tags().to_vec())),
            _ => None,
        })
        .collect()
}

#[test]
fn detect() {
    assert_eq!(detect_format("# c\njson://x\n"), Some(ConfigFormat::Text));
    assert_eq!(detect_format("version: 1\nurls:\n"), Some(ConfigFormat::Yaml));
    assert_eq!(detect_format("a,b=c\n"), Some(ConfigFormat::Text));
    assert_eq!(detect_format("# only\n"), Some(ConfigFormat::Text));
    assert_eq!(detect_format("- json://x\n"), None);
}

#[test]
fn text_tags_and_groups() {
    let c = load("dev, ops=json://localhost/a\nteam=dev\njson://localhost/b\nhello\n");
    let r = ready(&c);
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].1, vec!["dev", "ops", "team"]);
    assert!(r[1].1.is_empty());
}

#[test]
fn yaml_basic() {
    let c = load(
        "version: 1\ntag: g\nurls:\n  - json://localhost/a\n  - json://localhost/b:\n      - tag: x\n        method: GET\n      - tag: y\n",
    );
    let r = ready(&c);
    assert_eq!(r.len(), 3);
    assert_eq!(r[0].1, vec!["g"]);
    assert_eq!(r[1].0, "json://localhost/b?method=GET");
    assert_eq!(r[1].1, vec!["g", "x"]);
    assert_eq!(r[2].1, vec!["g", "y"]);
}

#[test]
fn yaml_template() {
    let c = load("template:\n  - target\n  - host: localhost\nurls:\n  - json://${HOST}/${TARGET}:\n      tag: t\n");
    let ConfigService::Pending(p) = &c.services[0] else { panic!("expected pending") };
    assert_eq!(p.template_names(), ["host", "target"]);
    assert_eq!(p.template_required(), vec!["target".to_string()]);
    assert_eq!(p.url(), "json://${HOST}/${TARGET}");
    let t = p.resolve(&TemplateVars::new().no_environment().with("target", "xyz")).unwrap();
    assert_eq!(t.tags(), ["t"]);
    assert!(p.resolve(&TemplateVars::new().no_environment()).is_err());
}

#[test]
fn fold() {
    let mut w = Vec::new();
    let t = vec![
        ("user".to_string(), Yaml::Str("me".into())),
        ("+X-H".to_string(), Yaml::Str("a b".into())),
        ("verify".to_string(), Yaml::Bool(false)),
        ("x-bad".to_string(), Yaml::Int(1)),
    ];
    let u = fold_url(Some("json://old@localhost:8080/p?a=1"), "json", &t, &mut w);
    assert_eq!(u, "json://me@localhost:8080/p?a=1&+X-H=a%20b&verify=no");
    assert_eq!(w.len(), 1);
}
