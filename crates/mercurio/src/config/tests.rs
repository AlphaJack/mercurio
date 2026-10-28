use super::fold::fold_url;
#[cfg(feature = "config-yaml")]
use super::template::TemplateVars;
use super::yaml::Yaml;
use super::*;
#[cfg(feature = "config-yaml")]
use crate::Asset;
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

#[cfg(feature = "service-json")]
#[test]
fn text_tags_and_groups() {
    let c = load("dev, ops=json://localhost/a\nteam=dev\njson://localhost/b\nhello\n");
    let r = ready(&c);
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].1, vec!["dev", "ops", "team"]);
    assert!(r[1].1.is_empty());
}

#[cfg(feature = "config-yaml")]
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

#[cfg(feature = "config-yaml")]
#[test]
fn yaml_template() {
    let c = load("template:\n  - target\n  - host: localhost\nurls:\n  - json://${HOST}/${TARGET}:\n      tag: t\n");
    let ConfigService::Pending(p) = &c.services[0] else { panic!("expected pending") };
    assert_eq!(p.template_names(), ["host", "target"]);
    assert_eq!(p.template_required(), vec!["target".to_owned()]);
    assert_eq!(p.url(), "json://${HOST}/${TARGET}");
    let t = p.resolve(&TemplateVars::new().no_environment().with("target", "xyz")).unwrap();
    assert_eq!(t.tags(), ["t"]);
    assert!(p.resolve(&TemplateVars::new().no_environment()).is_err());
}

#[test]
fn fold() {
    let mut w = Vec::new();
    let t = vec![
        ("user".to_owned(), Yaml::Str("me".into())),
        ("+X-H".to_owned(), Yaml::Str("a b".into())),
        ("verify".to_owned(), Yaml::Bool(false)),
        ("x-bad".to_owned(), Yaml::Int(1)),
    ];
    let u = fold_url(Some("json://old@localhost:8080/p?a=1"), "json", &t, &mut w);
    assert_eq!(u, "json://me@localhost:8080/p?a=1&+X-H=a%20b&verify=no");
    assert_eq!(w.len(), 1);
}

#[cfg(feature = "config-yaml")]
#[cfg(feature = "timezones")]
#[test]
fn asset_timezone() {
    let load = |yaml: &str| Config::from_text(yaml, None, &FakeTransport::new(), &ConfigOptions::default()).unwrap();
    let zone = |cfg: &Config| cfg.asset_for(&Asset::default()).timezone;
    // A location alone, cleaned of other characters, as Apprise.
    let cfg = load("version: 1\nasset:\n  timezone: ' paris!'\nurls:\n  - json://localhost\n");
    assert_eq!(zone(&cfg).as_deref(), Some("Europe/Paris"));
    let cfg = load("version: 1\nasset:\n  tz: UTC\nurls:\n  - json://localhost\n");
    assert_eq!(zone(&cfg).as_deref(), Some("UTC"));
    let cfg = load("version: 1\nasset:\n  timezone: Mars/Olympus\nurls:\n  - json://localhost\n");
    assert_eq!(zone(&cfg), None);
    assert!(cfg.warnings.iter().any(|w| w == "Ignored invalid timezone \"Mars/Olympus\""), "{:?}", cfg.warnings);

    // The URL's ?tz= wins over the asset's, which wins over the machine's.
    let (store, memo) = (crate::store::PersistentStore::memory().shared(), crate::store::Memo::disabled());
    let paris = Asset { timezone: Some("Europe/Paris".into()), ..Asset::default() };
    let ctx = crate::Context::new(&paris, &store, &memo);
    assert_eq!(ctx.time_zone().iana_name(), Some("Europe/Paris"));
    let tokyo = crate::time::zone("Asia/Tokyo").unwrap();
    assert_eq!(ctx.with_tz(Some(&tokyo)).time_zone().iana_name(), Some("Asia/Tokyo"));
}
