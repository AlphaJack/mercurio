//! Services registered at runtime.
//!
//! A [`Registry`] holds the services one notifier knows besides the compiled-in ones, which are always consulted first; a runtime service can only claim schemes nobody handles yet. Two ways to add one:
//!
//! - [`Registry::register`] a full [`ServiceDef`] (your own [`Notify`] type, URL parser and limits), exactly like a built-in service module;
//! - [`Registry::register_scheme`] a closure that turns each prepared message into a [`Plan`]. [`CustomScheme`] sets a display name or the accepted formats.
//!
//! Each [`crate::Mercurio`] and [`crate::AsyncMercurio`] has its own registry ([`crate::Mercurio::registry_mut`]), so two notifiers in one process can use the same scheme for different handlers. [`ConfigOptions::registry`](crate::ConfigOptions::registry) carries it into [`crate::Config`] loading.
//!
//! ```
//! use std::sync::{Arc, Mutex};
//! use mercurio::{Mercurio, Message, service::Plan};
//!
//! let seen = Arc::new(Mutex::new(Vec::new()));
//! let log = seen.clone();
//! let mut m = Mercurio::new();
//! m.registry_mut()
//!     .register_scheme("docexample", move |msg, hook| {
//!         log.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(format!("{} -> {}: {}", hook.url.host(), msg.title, msg.body));
//!         Plan::Done
//!     })
//!     .unwrap();
//! m.add("docexample://ops").unwrap();
//! assert!(m.notify(&Message::new("disk full").title("alert")).is_success());
//! assert_eq!(seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner)[0], "ops -> alert: disk full");
//! ```

use std::fmt;
use std::sync::{Arc, Mutex};

use crate::asset::Asset;
use crate::error::{Error, Result};
use crate::message::{NotifyFormat, Prepared};
use crate::plan::Plan;
use crate::service::{Context, Notify, ServiceDef};
use crate::store::{Memo, StoreRef};
use crate::target::Target;
use crate::url::ParsedUrl;

/// A closure-based notifier: one call per message piece.
pub type Handler = dyn Fn(&Prepared<'_>, &Hook<'_>) -> Plan + Send + Sync;

/// What a [`Handler`] gets besides the message.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Hook<'a> {
    /// The URL this target was built from.
    pub url: &'a ParsedUrl,
    /// Branding of the notifier sending the message.
    pub asset: &'a Asset,
    /// The target's persistent store (see [`crate::store`]).
    pub store: &'a StoreRef,
    /// Scratch space shared by the retry attempts of this notification.
    pub memo: &'a Memo,
}

impl Hook<'_> {
    /// The usual service context (`app_id`, images, colours).
    pub fn context(&self) -> Context<'_> {
        Context::new(self.asset, self.store, self.memo)
    }
}

/// Services added at runtime, on top of the compiled-in ones. Cheap to clone: the handlers are shared.
#[derive(Clone, Default)]
pub struct Registry {
    entries: Vec<Entry>,
}

#[derive(Clone)]
struct Entry {
    def: &'static ServiceDef,
    /// The closure of a [`CustomScheme`]; `None` for a full [`ServiceDef`].
    handler: Option<Arc<Handler>>,
}

impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.entries.iter().map(|e| e.def.id)).finish()
    }
}

/// Valid custom scheme: 1 to 32 ASCII letters or digits.
fn valid_scheme(scheme: &str) -> bool {
    (1..=32).contains(&scheme.len()) && scheme.bytes().all(|b| b.is_ascii_alphanumeric())
}

impl Registry {
    /// An empty registry: only the compiled-in services.
    pub fn new() -> Self {
        Self::default()
    }

    fn taken(&self, scheme: &str) -> bool {
        crate::services::ALL.iter().any(|d| d.handles(scheme)) || self.entries.iter().any(|e| e.def.handles(scheme))
    }

    fn check(&self, def: &ServiceDef) -> Result<()> {
        if def.schemes.is_empty() {
            return Err(Error::Message(format!("service {:?} declares no schemes", def.id)));
        }
        for s in def.schemes {
            if !valid_scheme(s) {
                return Err(Error::Message(format!("invalid scheme {s:?}")));
            }
            if self.taken(s) {
                return Err(Error::Message(format!("the scheme {s}:// is already handled by another service")));
            }
        }
        Ok(())
    }

    /// Add a full service definition. Fails when one of its schemes is invalid or already handled (compiled-in services always win).
    pub fn register(&mut self, def: &'static ServiceDef) -> Result<()> {
        self.check(def)?;
        self.entries.push(Entry { def, handler: None });
        Ok(())
    }

    /// Register a closure as the notifier for `scheme://` URLs. The host of such a URL is not validated.
    ///
    /// Shorthand for `CustomScheme::new(scheme, handler).register(registry)`.
    pub fn register_scheme<F>(&mut self, scheme: &str, handler: F) -> Result<&'static ServiceDef>
    where
        F: Fn(&Prepared<'_>, &Hook<'_>) -> Plan + Send + Sync + 'static,
    {
        CustomScheme::new(scheme, handler).register(self)
    }

    /// Remove the runtime service handling `scheme` (all of its schemes). Returns `false` when no runtime service handles it; compiled-in services can not be removed. Targets already built keep working.
    pub fn unregister(&mut self, scheme: &str) -> bool {
        let Some(i) = self.entries.iter().position(|e| e.def.handles(scheme)) else { return false };
        self.entries.remove(i);
        true
    }

    /// Runtime services, in registration order.
    pub fn registered(&self) -> impl Iterator<Item = &'static ServiceDef> + '_ {
        self.entries.iter().map(|e| e.def)
    }

    /// The service handling `scheme`: compiled-in services first ([`crate::service_for_scheme`]), then this registry's.
    pub fn service_for_scheme(&self, scheme: &str) -> Option<&'static ServiceDef> {
        crate::target::service_for_scheme(scheme).or_else(|| self.lookup(scheme))
    }

    /// [`crate::parse`] with this registry's services too.
    pub fn parse(&self, url: &str) -> Result<Target> {
        crate::target::parse_with(url, self)
    }

    /// The runtime service handling `scheme`.
    pub(crate) fn lookup(&self, scheme: &str) -> Option<&'static ServiceDef> {
        self.entries.iter().map(|e| e.def).find(|d| d.handles(scheme))
    }

    /// The closure behind `def`, when it is one of this registry's [`CustomScheme`]s.
    pub(crate) fn handler(&self, def: &ServiceDef) -> Option<Arc<Handler>> {
        self.entries.iter().find(|e| std::ptr::eq(e.def, def)).and_then(|e| e.handler.clone())
    }

    /// Build `def`'s service from `parsed`: its closure when it has one, its URL parser otherwise.
    pub(crate) fn build(&self, def: &'static ServiceDef, parsed: &ParsedUrl) -> Result<Box<dyn Notify>> {
        match self.handler(def) {
            Some(handler) => Ok(custom_notify(parsed, handler)),
            None => (def.parse)(parsed),
        }
    }
}

/// A [`CustomScheme`] target's service.
pub(crate) fn custom_notify(parsed: &ParsedUrl, handler: Arc<Handler>) -> Box<dyn Notify> {
    Box::new(CustomNotify { url: parsed.clone(), handler })
}

/// Closure definitions, shared by every registry that registers the same scheme with the same settings. A [`ServiceDef`] must be `'static`, so each one is leaked once and reused, which bounds the leak by the distinct schemes, not by the number of notifiers.
static DEFS: Mutex<Vec<&'static ServiceDef>> = Mutex::new(Vec::new());

fn closure_def(scheme: &str, name: &str, formats: &'static [NotifyFormat], attachments: bool) -> &'static ServiceDef {
    let mut defs = DEFS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let same = |d: &&&'static ServiceDef| {
        d.schemes == [scheme] && d.name == name && d.formats == formats && d.attachments == attachments
    };
    if let Some(def) = defs.iter().find(same) {
        return def;
    }
    let scheme: &'static str = Box::leak(scheme.to_string().into_boxed_str());
    let def: &'static ServiceDef = Box::leak(Box::new(ServiceDef {
        id: Box::leak(format!("custom_{scheme}").into_boxed_str()),
        name: Box::leak(name.to_string().into_boxed_str()),
        schemes: Box::leak(vec![scheme].into_boxed_slice()),
        parse: parse_custom,
        formats,
        attachments,
        ..ServiceDef::DEFAULTS
    }));
    defs.push(def);
    def
}

/// The URL parser of a closure definition. Its targets are built from the registry holding the closure ([`Registry::build`]), never from here.
fn parse_custom(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    Err(Error::UnknownScheme(u.scheme.clone()))
}

/// Builder for a closure-based service.
pub struct CustomScheme {
    scheme: String,
    name: Option<String>,
    formats: &'static [NotifyFormat],
    attachments: bool,
    handler: Arc<Handler>,
}

impl fmt::Debug for CustomScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomScheme").field("scheme", &self.scheme).field("name", &self.name).finish()
    }
}

/// Closure services accept every format unconverted unless told otherwise.
const ALL_FORMATS: &[NotifyFormat] = &[NotifyFormat::Text, NotifyFormat::Html, NotifyFormat::Markdown];

impl CustomScheme {
    /// A closure-based service for `scheme://` URLs. The scheme is lower-cased and a trailing `://` is dropped. Defaults: every format passed through unconverted, attachments on, name `Custom - <scheme>`.
    pub fn new<F>(scheme: &str, handler: F) -> Self
    where
        F: Fn(&Prepared<'_>, &Hook<'_>) -> Plan + Send + Sync + 'static,
    {
        Self {
            scheme: scheme.trim().trim_end_matches("://").to_ascii_lowercase(),
            name: None,
            formats: ALL_FORMATS,
            attachments: true,
            handler: Arc::new(handler),
        }
    }

    /// Display name (default `Custom - <scheme>`).
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Formats the handler accepts; the first is the default and other inputs are converted to it. Default: text, HTML and Markdown, all passed through unconverted.
    #[must_use]
    pub fn formats(mut self, formats: &'static [NotifyFormat]) -> Self {
        if !formats.is_empty() {
            self.formats = formats;
        }
        self
    }

    /// Whether attachments reach the handler (default `true`).
    #[must_use]
    pub fn attachments(mut self, yes: bool) -> Self {
        self.attachments = yes;
        self
    }

    /// Add it to `registry`.
    pub fn register(self, registry: &mut Registry) -> Result<&'static ServiceDef> {
        if !valid_scheme(&self.scheme) {
            return Err(Error::Message(format!("invalid scheme {:?}", self.scheme)));
        }
        // Validate before leaking anything.
        if registry.taken(&self.scheme) {
            return Err(Error::Message(format!("the scheme {}:// is already handled by another service", self.scheme)));
        }
        let name = self.name.unwrap_or_else(|| format!("Custom - {}", self.scheme));
        let def = closure_def(&self.scheme, &name, self.formats, self.attachments);
        registry.entries.push(Entry { def, handler: Some(self.handler) });
        Ok(def)
    }
}

struct CustomNotify {
    url: ParsedUrl,
    handler: Arc<Handler>,
}

impl fmt::Debug for CustomNotify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomNotify").field("scheme", &self.url.scheme).finish_non_exhaustive()
    }
}

impl Notify for CustomNotify {
    fn plan(&self, msg: &Prepared<'_>, ctx: &Context<'_>) -> Plan {
        (self.handler)(msg, &Hook { url: &self.url, asset: ctx.asset, store: ctx.store, memo: ctx.memo })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::http::Request;
    use crate::testing::FakeTransport;
    use crate::{Mercurio, Message, NotifyFormat};

    #[test]
    fn closure_service_receives_message_and_url() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let mut m = Mercurio::new();
        m.registry_mut()
            .register_scheme("tclosure", move |msg, hook| {
                log.lock().unwrap().push((
                    msg.title.to_string(),
                    msg.body.to_string(),
                    msg.kind.as_str().to_string(),
                    hook.url.host(),
                    hook.url.param("x").map(str::to_string),
                    msg.attachments.len(),
                ));
                Plan::Done
            })
            .unwrap();
        m.add("tclosure://box?x=1").unwrap();
        let mut msg = Message::new("body").title("title");
        msg.kind = crate::NotifyType::Warning;
        msg.attachments.push(crate::Attachment::new("a.txt", "text/plain", b"x".to_vec()));
        let report = m.notify(&msg);
        assert!(report.is_success());
        assert_eq!(report.entries[0].service, "custom_tclosure");
        assert_eq!(
            seen.lock().unwrap()[0],
            ("title".into(), "body".into(), "warning".into(), "box".into(), Some("1".into()), 1)
        );
    }

    #[test]
    fn closure_plan_goes_through_the_transport() {
        let fake = Arc::new(FakeTransport::new());
        let mut m = Mercurio::with_transport(fake.clone());
        m.registry_mut()
            .register_scheme("thttp", |msg, hook| {
                let req = Request::post(format!("https://{}/hook", hook.url.host()))
                    .header("User-Agent", hook.context().app_id().to_string())
                    .text(msg.body.to_string());
                Plan::send(req)
            })
            .unwrap();
        m.add("thttp://example.com").unwrap();
        assert!(m.notify(&Message::new("hi")).is_success());
        let reqs = fake.requests();
        assert_eq!(reqs[0].url, "https://example.com/hook");
        assert_eq!(reqs[0].body_text(), "hi");
    }

    #[test]
    fn failures_are_reported() {
        let mut m = Mercurio::new();
        m.registry_mut().register_scheme("tfail", |_, _| Plan::fail(Error::Message("failed".into()))).unwrap();
        m.add("tfail://").unwrap();
        assert!(!m.notify(&Message::new("x")).is_success());
    }

    #[test]
    fn compiled_in_and_duplicate_schemes_are_rejected() {
        let mut reg = Registry::new();
        if let Some(def) = crate::services().first() {
            assert!(reg.register_scheme(def.schemes[0], |_, _| Plan::Done).is_err());
        }
        reg.register_scheme("tdup", |_, _| Plan::Done).unwrap();
        assert!(reg.register_scheme("TDUP", |_, _| Plan::Done).is_err());
        assert!(reg.register_scheme("", |_, _| Plan::Done).is_err());
        assert!(reg.register_scheme("a-b", |_, _| Plan::Done).is_err());
        assert!(reg.register_scheme(&"x".repeat(33), |_, _| Plan::Done).is_err());
        assert!(reg.register_scheme("a b", |_, _| Plan::Done).is_err());
    }

    #[test]
    fn unregister_then_register_again() {
        let mut reg = Registry::new();
        reg.register_scheme("tcycle", |_, _| Plan::Done).unwrap();
        assert!(reg.parse("tcycle://x").is_ok());
        assert!(reg.unregister("tcycle"));
        assert!(!reg.unregister("tcycle"));
        assert!(matches!(reg.parse("tcycle://x"), Err(Error::UnknownScheme(_))));
        reg.register_scheme("tcycle", |_, _| Plan::Done).unwrap();
        assert!(reg.parse("tcycle://x").is_ok());
        assert!(reg.registered().any(|d| d.handles("tcycle")));
    }

    #[test]
    fn registries_are_independent() {
        let (mut a, mut b) = (Registry::new(), Registry::new());
        let first = a.register_scheme("tsplit", |_, _| Plan::Done).unwrap();
        let second = b.register_scheme("tsplit", |_, _| Plan::fail(Error::Message("b".into()))).unwrap();
        // Same settings: one leaked definition, two handlers.
        assert!(std::ptr::eq(first, second));
        assert!(matches!(crate::parse("tsplit://x"), Err(Error::UnknownScheme(_))));
        let fake = FakeTransport::new();
        let send = |r: &Registry| r.parse("tsplit://x").unwrap().send(&Message::new("m"), &fake, &Asset::default());
        assert!(send(&a).is_success());
        assert!(!send(&b).is_success());
    }

    #[test]
    fn config_entries_use_the_registry() {
        let mut m = Mercurio::new();
        m.registry_mut().register_scheme("tcfg", |_, _| Plan::Done).unwrap();
        let yaml = "template:\n  - host: box\nurls:\n  - tcfg://plain\n  - tcfg://${HOST}\n";
        assert_eq!(m.add_config_text(yaml, None).unwrap(), 2);
        assert_eq!(m.pending().len(), 1);
        assert_eq!(m.notify(&Message::new("x")).status(), crate::Status::Success);
        // Another notifier does not know the scheme.
        assert_eq!(Mercurio::new().add_config_text("tcfg://plain", None).unwrap_or(0), 0);
    }

    #[test]
    fn declared_format_converts_input() {
        let seen = Arc::new(Mutex::new(String::new()));
        let log = seen.clone();
        let mut reg = Registry::new();
        CustomScheme::new("thtml", move |msg, _| {
            *log.lock().unwrap() = format!("{:?}:{}", msg.format, msg.body);
            Plan::Done
        })
        .name("HTML hook")
        .formats(&[NotifyFormat::Html])
        .register(&mut reg)
        .unwrap();
        let t = reg.parse("thtml://").unwrap();
        assert_eq!(t.service().name, "HTML hook");
        let mut msg = Message::new("**hi**");
        msg.format = Some(NotifyFormat::Markdown);
        assert!(t.send(&msg, &FakeTransport::new(), &Asset::default()).is_success());
        assert_eq!(*seen.lock().unwrap(), "Html:<p><strong>hi</strong></p>");
    }

    #[derive(Debug)]
    struct Echo;
    impl Notify for Echo {
        fn plan(&self, msg: &Prepared<'_>, _: &Context<'_>) -> Plan {
            Plan::send(Request::post("https://echo.test/").text(msg.body.to_string()))
        }
    }

    fn parse_echo(_: &ParsedUrl) -> Result<Box<dyn Notify>> {
        Ok(Box::new(Echo))
    }

    static ECHO: ServiceDef = ServiceDef {
        id: "echo",
        name: "Echo",
        schemes: &["techo", "techos"],
        parse: parse_echo,
        limits: crate::Limits { title_maxlen: 0, body_maxlen: 5, body_max_line_count: 0 },
        ..ServiceDef::DEFAULTS
    };

    #[test]
    fn full_service_definitions() {
        let mut reg = Registry::new();
        reg.register(&ECHO).unwrap();
        assert!(reg.register(&ECHO).is_err());
        let t = reg.parse("techos://anything?overflow=truncate").unwrap();
        assert_eq!(t.service().id, "echo");
        assert!(std::ptr::eq(reg.service_for_scheme("techo").unwrap(), &ECHO));
        assert!(crate::service_for_scheme("techo").is_none());
        let fake = FakeTransport::new();
        // `?overflow=truncate` cuts the body to the 5 characters the limits allow.
        assert!(t.send(&Message::new("123456789"), &fake, &Asset::default()).is_success());
        assert_eq!(fake.requests()[0].body_text(), "12345");
    }
}
