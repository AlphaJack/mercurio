//! Services registered at runtime.
//!
//! Compiled-in services are always consulted first; a runtime service can only claim schemes nobody handles yet. Two ways to add one:
//!
//! - [`register`] a full [`ServiceDef`] (your own [`Notify`] type, URL parser and limits), exactly like a built-in service module;
//! - [`register_scheme`] a closure that turns each prepared message into a [`Plan`]. [`CustomScheme`] sets a display name or the accepted formats.
//!
//! The registry is process-wide and thread-safe; registered definitions live for the rest of the process.
//!
//! ```
//! use std::sync::{Arc, Mutex};
//! use mercurio::{Mercurio, Message, Plan};
//!
//! let seen = Arc::new(Mutex::new(Vec::new()));
//! let log = seen.clone();
//! Mercurio::register_scheme("docexample", move |msg, hook| {
//!     log.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(format!("{} -> {}: {}", hook.url.host(), msg.title, msg.body));
//!     Plan::Done
//! })
//! .unwrap();
//!
//! let mut m = Mercurio::new();
//! m.add("docexample://ops").unwrap();
//! assert!(m.notify(&Message::new("disk full").title("alert")).is_success());
//! assert_eq!(seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner)[0], "ops -> alert: disk full");
//! ```

use std::fmt;
use std::sync::{Arc, RwLock};

use crate::asset::Asset;
use crate::error::{Error, Result};
use crate::message::{NotifyFormat, Prepared};
use crate::plan::Plan;
use crate::service::{Context, Notify, ServiceDef};
use crate::store::{Memo, StoreRef};
use crate::url::ParsedUrl;

/// A closure-based notifier: one call per message piece.
pub type Handler = dyn Fn(&Prepared<'_>, &Hook<'_>) -> Plan + Send + Sync;

/// What a [`Handler`] gets besides the message.
#[derive(Debug, Clone, Copy)]
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

struct Registry {
    defs: Vec<&'static ServiceDef>,
    handlers: Vec<(&'static str, Arc<Handler>)>,
}

static REGISTRY: RwLock<Registry> = RwLock::new(Registry { defs: Vec::new(), handlers: Vec::new() });

fn read() -> std::sync::RwLockReadGuard<'static, Registry> {
    REGISTRY.read().unwrap_or_else(|p| p.into_inner())
}

fn write() -> std::sync::RwLockWriteGuard<'static, Registry> {
    REGISTRY.write().unwrap_or_else(|p| p.into_inner())
}

/// Valid custom scheme: 1 to 32 ASCII letters or digits.
fn valid_scheme(scheme: &str) -> bool {
    (1..=32).contains(&scheme.len()) && scheme.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn check(reg: &Registry, def: &ServiceDef) -> Result<()> {
    if def.schemes.is_empty() {
        return Err(Error::Message(format!("service {:?} declares no schemes", def.id)));
    }
    for s in def.schemes {
        if !valid_scheme(s) {
            return Err(Error::Message(format!("invalid scheme {s:?}")));
        }
        let taken = crate::services::ALL.iter().chain(reg.defs.iter()).any(|d| d.handles(s));
        if taken {
            return Err(Error::Message(format!("the scheme {s}:// is already handled by another service")));
        }
    }
    Ok(())
}

/// Add a service at runtime. Fails when one of its schemes is invalid or already handled (compiled-in services always win).
pub fn register(def: &'static ServiceDef) -> Result<()> {
    let mut reg = write();
    check(&reg, def)?;
    reg.defs.push(def);
    Ok(())
}

/// Remove the runtime service handling `scheme` (all of its schemes). Returns `false` when no runtime service handles it; compiled-in services can not be removed. Targets already built keep working.
pub fn unregister(scheme: &str) -> bool {
    let mut reg = write();
    let Some(i) = reg.defs.iter().position(|d| d.handles(scheme)) else { return false };
    let def = reg.defs.remove(i);
    reg.handlers.retain(|(s, _)| !def.handles(s));
    true
}

/// Runtime-registered services, in registration order.
pub fn registered() -> Vec<&'static ServiceDef> {
    read().defs.clone()
}

/// The runtime service handling `scheme`.
pub(crate) fn lookup(scheme: &str) -> Option<&'static ServiceDef> {
    read().defs.iter().copied().find(|d| d.handles(scheme))
}

/// Register a closure as the notifier for `scheme://` URLs. The host of such a URL is not validated.
///
/// Shorthand for `CustomScheme::new(scheme, handler).register()`.
pub fn register_scheme<F>(scheme: &str, handler: F) -> Result<&'static ServiceDef>
where
    F: Fn(&Prepared<'_>, &Hook<'_>) -> Plan + Send + Sync + 'static,
{
    CustomScheme::new(scheme, handler).register()
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
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Formats the handler accepts; the first is the default and other inputs are converted to it. Default: text, HTML and Markdown, all passed through unconverted.
    pub fn formats(mut self, formats: &'static [NotifyFormat]) -> Self {
        if !formats.is_empty() {
            self.formats = formats;
        }
        self
    }

    /// Whether attachments reach the handler (default `true`).
    pub fn attachments(mut self, yes: bool) -> Self {
        self.attachments = yes;
        self
    }

    /// Add it to the registry.
    pub fn register(self) -> Result<&'static ServiceDef> {
        if !valid_scheme(&self.scheme) {
            return Err(Error::Message(format!("invalid scheme {:?}", self.scheme)));
        }
        let mut reg = write();
        // Validate before leaking anything.
        if crate::services::ALL.iter().chain(reg.defs.iter()).any(|d| d.handles(&self.scheme)) {
            return Err(Error::Message(format!("the scheme {}:// is already handled by another service", self.scheme)));
        }
        let scheme: &'static str = Box::leak(self.scheme.clone().into_boxed_str());
        let name = self.name.unwrap_or_else(|| format!("Custom - {scheme}"));
        let def: &'static ServiceDef = Box::leak(Box::new(ServiceDef {
            id: Box::leak(format!("custom_{scheme}").into_boxed_str()),
            name: Box::leak(name.into_boxed_str()),
            schemes: Box::leak(vec![scheme].into_boxed_slice()),
            parse: parse_custom,
            formats: self.formats,
            attachments: self.attachments,
            ..ServiceDef::DEFAULTS
        }));
        check(&reg, def)?;
        reg.defs.push(def);
        reg.handlers.push((scheme, self.handler));
        Ok(def)
    }
}

fn parse_custom(u: &ParsedUrl) -> Result<Box<dyn Notify>> {
    let handler = read()
        .handlers
        .iter()
        .find(|(s, _)| s.eq_ignore_ascii_case(&u.scheme))
        .map(|(_, h)| h.clone())
        .ok_or_else(|| Error::UnknownScheme(u.scheme.clone()))?;
    Ok(Box::new(CustomNotify { url: u.clone(), handler }))
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
        crate::register_scheme("tclosure", move |msg, hook| {
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
        let mut m = Mercurio::new();
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
        crate::register_scheme("thttp", |msg, hook| {
            let req = Request::post(format!("https://{}/hook", hook.url.host()))
                .header("User-Agent", hook.context().app_id().to_string())
                .text(msg.body.to_string());
            Plan::send(req)
        })
        .unwrap();
        let fake = Arc::new(FakeTransport::new());
        let mut m = Mercurio::with_transport(fake.clone());
        m.add("thttp://example.com").unwrap();
        assert!(m.notify(&Message::new("hi")).is_success());
        let reqs = fake.requests();
        assert_eq!(reqs[0].url, "https://example.com/hook");
        assert_eq!(reqs[0].body_text(), "hi");
    }

    #[test]
    fn failures_are_reported() {
        crate::register_scheme("tfail", |_, _| Plan::fail(Error::Message("failed".into()))).unwrap();
        let mut m = Mercurio::new();
        m.add("tfail://").unwrap();
        assert!(!m.notify(&Message::new("x")).is_success());
    }

    #[test]
    fn compiled_in_and_duplicate_schemes_are_rejected() {
        if let Some(def) = crate::services().first() {
            assert!(crate::register_scheme(def.schemes[0], |_, _| Plan::Done).is_err());
        }
        crate::register_scheme("tdup", |_, _| Plan::Done).unwrap();
        assert!(crate::register_scheme("TDUP", |_, _| Plan::Done).is_err());
        assert!(crate::register_scheme("", |_, _| Plan::Done).is_err());
        assert!(crate::register_scheme("a-b", |_, _| Plan::Done).is_err());
        assert!(crate::register_scheme(&"x".repeat(33), |_, _| Plan::Done).is_err());
        assert!(crate::register_scheme("a b", |_, _| Plan::Done).is_err());
    }

    #[test]
    fn unregister_then_register_again() {
        crate::register_scheme("tcycle", |_, _| Plan::Done).unwrap();
        assert!(crate::parse("tcycle://x").is_ok());
        assert!(unregister("tcycle"));
        assert!(!unregister("tcycle"));
        assert!(matches!(crate::parse("tcycle://x"), Err(Error::UnknownScheme(_))));
        crate::register_scheme("tcycle", |_, _| Plan::Done).unwrap();
        assert!(crate::parse("tcycle://x").is_ok());
        assert!(registered().iter().any(|d| d.handles("tcycle")));
    }

    #[test]
    fn declared_format_converts_input() {
        let seen = Arc::new(Mutex::new(String::new()));
        let log = seen.clone();
        CustomScheme::new("thtml", move |msg, _| {
            *log.lock().unwrap() = format!("{:?}:{}", msg.format, msg.body);
            Plan::Done
        })
        .name("HTML hook")
        .formats(&[NotifyFormat::Html])
        .register()
        .unwrap();
        let t = crate::parse("thtml://").unwrap();
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
        register(&ECHO).unwrap();
        assert!(register(&ECHO).is_err());
        let t = crate::parse("techos://anything?overflow=truncate").unwrap();
        assert_eq!(t.service().id, "echo");
        assert!(std::ptr::eq(crate::service_for_scheme("techo").unwrap(), &ECHO));
        let fake = FakeTransport::new();
        // `?overflow=truncate` cuts the body to the 5 characters the limits allow.
        assert!(t.send(&Message::new("123456789"), &fake, &Asset::default()).is_success());
        assert_eq!(fake.requests()[0].body_text(), "12345");
    }
}
