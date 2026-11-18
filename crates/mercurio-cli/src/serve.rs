//! `mercurio serve`: the notification HTTP API.
//!
//! Endpoints, payloads, settings and status codes are documented in the user guide: `docs/book/src/server.md`.

mod alerts;
#[expect(clippy::allow_attributes, reason = "honig's generated code allows lints that a binary may or may not trigger")]
mod api;
mod auth;
mod call;
mod codec;
mod details;
mod filters;
mod handlers;
mod key;
mod metrics;
mod notify;
mod notify_json;
mod payload;
mod router;
mod settings;
mod store;
mod text;

use std::sync::Arc;
use std::time::Duration;

use mercurio::transport::{AsyncTransport, TokioTransport};
use mercurio::{Config, ConfigFormat, ConfigOptions, config::ConfigService};

use auth::{KeyState, Role};
use call::{Call, Fault};
use store::ConfigStore;

use router::app;
pub(crate) use router::help_tables;
pub(crate) use settings::ServeArgs;
use settings::Settings;

struct Server {
    transport: Arc<dyn AsyncTransport>,
    s: Settings,
    store: ConfigStore,
    metrics: Arc<metrics::Metrics>,
    verifier: auth::Verifier,
    streams: Arc<tokio::sync::Semaphore>,
    /// `/details` without and with `?all=yes`, built on first use.
    details_cache: [std::sync::OnceLock<api::types::Details>; 2],
}
/// `mercurio serve --healthcheck`: `GET /status` of the server listening at `bind` (a wildcard address is reached
/// through loopback), with 5 s to connect and 5 s to answer. `Ok` on `200`. The container image's `HEALTHCHECK` runs
/// it; the image has no curl.
pub(crate) fn healthcheck(bind: &str) -> Result<(), String> {
    use mercurio::transport::{Method, Request};
    use std::net::{SocketAddr, ToSocketAddrs};
    let mut addr: SocketAddr =
        bind.to_socket_addrs().map_err(|e| format!("{bind}: {e}"))?.next().ok_or(format!("{bind}: no address"))?;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() { [127, 0, 0, 1].into() } else { std::net::Ipv6Addr::LOCALHOST.into() });
    }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
    let mut request = Request::new(Method::Get, format!("http://{addr}/status"));
    request.connect_timeout = Duration::from_secs(5);
    request.read_timeout = Duration::from_secs(5);
    let answer = runtime.block_on(TokioTransport::new().http(&request)).map_err(|e| format!("{addr}: {e}"))?;
    match answer.status {
        200 => Ok(()),
        code => Err(format!("{addr}: /status answered {code}")),
    }
}

pub(crate) async fn run(bind: &str, args: &ServeArgs) -> Result<(), String> {
    let s = Settings::from_args(args)?;
    let listener = tokio::net::TcpListener::bind(bind).await.map_err(|e| format!("bind {bind}: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let mut stop = std::pin::pin!(shutdown());
    outln!("listening on http://{addr}");
    if let Some(p) = s.prune {
        let store = ConfigStore::new(s.config_dir.clone(), s.stateful, s.secret.clone());
        tokio::spawn(prune_loop(p, store, s.storage.clone()));
    }
    let io_timeout = s.io_timeout;
    let app = app(s);
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    loop {
        let (tcp, remote) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(a) => a,
                Err(e) => {
                    log::debug!("accept: {e}");
                    continue;
                }
            },
            () = &mut stop => break,
        };
        let service = router::Connection::serve(&app, remote);
        // `half_close`: a client that shut its writing side still gets its answer.
        let conn = hyper::server::conn::http1::Builder::new()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(io_timeout)
            .half_close(true)
            .serve_connection(hyper_util::rt::TokioIo::new(tcp), service);
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                log::debug!("connection: {e}");
            }
        });
    }
    drop(listener);
    graceful.shutdown().await;
    Ok(())
}
/// Ctrl-C, or SIGTERM / SIGHUP on Unix (a container stop).
/// apprise-api's container clean-up: one run at start-up, then one every interval, each stopped after the timeout. It ends with the server.
async fn prune_loop(p: settings::Prune, store: ConfigStore, storage: Option<std::path::PathBuf>) {
    loop {
        match tokio::time::timeout(p.timeout, prune_once(&p, &store, storage.as_deref())).await {
            Ok((files, logins)) => log::info!("pruned {files} persistent storage file(s) and {logins} unused login(s)"),
            Err(_) => log::warn!("pruning did not complete within {}s", p.timeout.as_secs()),
        }
        tokio::time::sleep(p.interval).await;
    }
}

/// Persistent storage older than `p.storage`, then logins without a configuration older than `p.logins`: the counts removed.
async fn prune_once(p: &settings::Prune, store: &ConfigStore, storage: Option<&std::path::Path>) -> (usize, usize) {
    let mut files = 0;
    if let Some(dir) = storage {
        let pruned = crate::storage::prune(dir, &[], p.storage, true).await;
        files = pruned.values().flatten().filter(|f| f.removed).count();
    }
    (files, store.prune_unused_locks(p.logins).await)
}

/// Resolves on SIGINT, SIGTERM or SIGHUP (Ctrl-C or Ctrl-Break on Windows, Ctrl-C elsewhere). The handlers are installed when this is called, not when it is first awaited, so a signal sent right after the listener is announced is never lost to the default action.
fn shutdown() -> impl Future<Output = ()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let signals = [SignalKind::interrupt(), SignalKind::terminate(), SignalKind::hangup()].map(signal);
        async move {
            let mut streams: Vec<_> =
                signals.into_iter().filter_map(|s| s.map_err(|e| log::warn!("signal: {e}")).ok()).collect();
            if streams.is_empty() {
                std::future::pending::<()>().await;
            }
            futures_util::future::select_all(streams.iter_mut().map(|s| Box::pin(s.recv()))).await;
        }
    }
    // Ctrl-Break too, which unlike Ctrl-C can be sent to one process group, as a supervisor would.
    #[cfg(windows)]
    {
        let ctrl_break = tokio::signal::windows::ctrl_break();
        async move {
            match ctrl_break {
                Ok(mut ctrl_break) => tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = ctrl_break.recv() => {}
                },
                Err(_) => _ = tokio::signal::ctrl_c().await,
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    async {
        tokio::signal::ctrl_c().await.ok();
    }
}
const DENIED: &str = "The site has been configured to deny this request";

impl Server {
    async fn key_state(&self, key: &str) -> KeyState {
        self.s.auth.key_state(&self.store, key, self.s.config_lock).await
    }

    /// May this request use `key`? Sets the caller's role on success.
    async fn key_ok(&self, call: &Call<'_>, key: &str, allow_public: bool) -> bool {
        call.note("key", key);
        match call.caller.role.get() {
            Role::Admin | Role::Open => return true,
            Role::User | Role::Anonymous => {}
        }
        let state = self.key_state(key).await;
        if allow_public && state.public() {
            return true;
        }
        let Some(digest) = state.digest.as_deref() else { return false };
        let Some((user, pass)) = call.caller.credentials.as_ref() else { return false };
        if !self.verifier.verify(key, user, pass, state.username.as_deref(), digest) {
            return false;
        }
        if state.disabled() {
            call.caller.disabled_key.set(Some(key.to_owned()));
            return false;
        }
        call.caller.role.set(Role::User);
        true
    }

    /// The answer when [`Server::key_ok`] said no.
    fn key_denied(&self, call: &Call<'_>, key: &str) -> Fault {
        if call.caller.disabled_key.get().as_deref() == Some(key) {
            return call.fail(Fault::new(403, "This configuration has been disabled by an administrator"));
        }
        call.fail(Fault::unauthorized(&format!("{}: {key}", self.s.auth.realm)))
    }

    /// May this request use `key`? The answer to give when it may not.
    async fn require_key(&self, call: &Call<'_>, key: &str, allow_public: bool) -> Result<(), Fault> {
        if self.key_ok(call, key, allow_public).await { Ok(()) } else { Err(self.key_denied(call, key)) }
    }

    /// Either the global lock or the key's own access mode hides configuration content.
    async fn configuration_is_locked(&self, key: Option<&str>) -> bool {
        if !self.store.enabled() {
            return false;
        }
        if self.s.config_lock {
            return true;
        }
        match key {
            Some(k) if self.s.auth.required => self.key_state(k).await.config_locked(),
            _ => false,
        }
    }

    /// `403` when persistent storage is off.
    fn require_stateful(&self, call: &Call<'_>) -> Result<(), Fault> {
        if self.store.enabled() {
            Ok(())
        } else {
            Err(call.fail(Fault::new(403, "Persistent configuration storage is disabled")))
        }
    }

    /// Whether this caller may see or change configuration content.
    async fn config_lock_allows(&self, call: &Call<'_>, key: Option<&str>) -> bool {
        call.caller.role.get() == Role::Admin || !self.configuration_is_locked(key).await
    }

    fn config_options(&self) -> ConfigOptions {
        ConfigOptions {
            recursion: self.s.recursion_max,
            allow_templates: self.s.allow_templates,
            ..ConfigOptions::default()
        }
    }

    /// Parse configuration text held by the server (a memory source, so includes can not read local files).
    async fn load(&self, content: &str, format: Option<ConfigFormat>) -> Result<Config, String> {
        let mut cfg = Config::from_text_async(content, format, self.transport.as_ref(), &self.config_options())
            .await
            .map_err(|e| e.to_string())?;
        cfg.services.retain(|s| {
            let id = match s {
                ConfigService::Ready(t) => t.service().id,
                ConfigService::Pending(p) => p.service().id,
            };
            self.s.services.enabled(id)
        });
        Ok(cfg)
    }

    /// The asset for a send, with persistent storage when enabled.
    fn asset(&self, persistent: bool) -> mercurio::Asset {
        let asset = mercurio::Asset {
            http_redirects: self.s.http_redirects,
            storage_idlen: self.s.storage_idlen,
            storage_mode: self.s.storage_mode,
            interpret_emojis: self.s.interpret_emojis,
            ..mercurio::Asset::default()
        };
        match (&self.s.storage, persistent) {
            (Some(dir), true) => asset.with_storage(dir.clone()),
            (Some(_) | None, _) => asset,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::{Request, StatusCode};

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        serve: ServeArgs,
    }

    type Body = Full<Bytes>;

    /// The app with `settings` (as `mercurio serve` flags) and a fresh configuration directory.
    fn test_app(name: &str, settings: &[&str]) -> router::App {
        let dir = std::env::temp_dir().join(format!("mercurio-app-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let dir = dir.to_string_lossy().to_string();
        let args = Cli::parse_from(["serve", "--config-dir", &dir].iter().chain(settings));
        app(Settings::from_args(&args.serve).unwrap())
    }

    fn empty() -> Body {
        Full::new(Bytes::new())
    }

    /// Send one request; status, headers and body.
    async fn send(app: &router::App, request: Request<Body>) -> (StatusCode, hyper::HeaderMap, String) {
        let res = app.call(request, std::net::SocketAddr::from(([127, 0, 0, 1], 9))).await.unwrap();
        let (parts, body) = res.into_parts();
        let body = body.collect().await.unwrap();
        (parts.status, parts.headers, String::from_utf8_lossy(&body).into_owned())
    }

    fn form(path: &str, body: &str) -> Request<Body> {
        Request::post(path)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Full::new(Bytes::from(body.to_owned())))
            .unwrap()
    }
    #[tokio::test]
    async fn unknown_paths_and_methods() {
        let app = test_app("routes", &[]);
        let (status, _, body) = send(&app, Request::get("/invalid").body(empty()).unwrap()).await;
        assert_eq!((status, body.as_str()), (StatusCode::NOT_FOUND, ""));
        let (status, headers, _) = send(&app, Request::get("/notify").body(empty()).unwrap()).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(headers["allow"], "POST");
        let (status, _, _) = send(&app, form("/add/bad!", "urls=json://localhost")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, body) = send(&app, Request::get("/status/").body(empty()).unwrap()).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "OK"));
    }

    /// apprise-api's web UI is not served (differences.md).
    #[tokio::test]
    async fn web_ui_paths_are_not_found() {
        let app = test_app("web-ui", &[]);
        for (method, path) in [("GET", "/login"), ("POST", "/login"), ("GET", "/logout"), ("POST", "/logout")]
            .into_iter()
            .chain([("GET", "/qr/@"), ("GET", "/qr/k1")])
        {
            let (status, _, _) = send(&app, Request::builder().method(method).uri(path).body(empty()).unwrap()).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
        }
    }

    fn with_header(mut request: Request<Body>, name: &'static str, value: &str) -> Request<Body> {
        request.headers_mut().insert(name, value.parse().unwrap());
        request
    }

    /// A Config ID in the path that is not 1 to 128 letters, digits, `_` or `-` is no route: `404` with no body, as
    /// an unknown path. Letters and digits of any script are valid.
    #[tokio::test]
    async fn an_invalid_key_in_the_path_is_no_route() {
        let app = test_app("path-key", &[]);
        let long = "k".repeat(129);
        for path in ["/get/bad!", "/add/bad!", "/notify/bad!", "/move/bad!", "/cfg/bad!"]
            .into_iter()
            .map(str::to_owned)
            .chain([format!("/get/{long}")])
        {
            let (status, _, body) = send(&app, form(&path, "body=x")).await;
            assert_eq!((status, body.as_str()), (StatusCode::NOT_FOUND, ""), "{path}");
        }
        for path in ["/status/bad!", "/json/urls/bad!", "/auth/bad!"] {
            let (status, _, body) = send(&app, Request::get(path).body(empty()).unwrap()).await;
            assert_eq!((status, body.as_str()), (StatusCode::NOT_FOUND, ""), "{path}");
        }
        for key in ["k".repeat(128), "ключ_1-ä".to_owned()] {
            let path = format!("/get/{}", key.replace('ч', "%D1%87").replace('к', "%D0%BA"));
            let path = path.replace('л', "%D0%BB").replace('ю', "%D1%8E").replace('ä', "%C3%A4");
            assert_eq!(send(&app, form(&path, "")).await.0, StatusCode::NO_CONTENT, "{key}");
        }
    }

    /// An invalid `X-Apprise-Config-ID` is `400`; an empty one falls back to the path.
    #[tokio::test]
    async fn an_invalid_key_header_is_a_bad_request() {
        let app = test_app("header-key", &[]);
        let expected = (StatusCode::BAD_REQUEST, "The X-Apprise-Config-ID header provided is invalid".to_owned());
        for path in ["/get", "/get/k1", "/notify", "/notify/k1"] {
            let (status, _, body) = send(&app, with_header(form(path, "body=x"), "x-apprise-config-id", "bad!")).await;
            assert_eq!((status, body), expected, "{path}");
        }
        for path in ["/status", "/details", "/json/urls", "/json/urls/k1"] {
            let request = with_header(Request::get(path).body(empty()).unwrap(), "x-apprise-config-id", "bad!");
            let (status, _, body) = send(&app, request).await;
            assert_eq!((status, body), expected, "{path}");
        }
        assert_eq!(send(&app, form("/add/k1", "urls=json://localhost")).await.0, StatusCode::OK);
        let (status, _, body) = send(&app, with_header(form("/get/k1", ""), "x-apprise-config-id", " ")).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "json://localhost"));
    }

    #[tokio::test]
    async fn add_get_and_delete_a_configuration() {
        let app = test_app("store", &[]);
        assert_eq!(send(&app, form("/add/k1", "urls=json://localhost")).await.0, StatusCode::OK);
        let (status, _, body) = send(&app, form("/get/k1", "")).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "json://localhost"));
        assert_eq!(send(&app, form("/del/k1", "")).await.0, StatusCode::OK);
        assert_eq!(send(&app, form("/get/k1", "")).await.0, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn errors_follow_the_client() {
        let app = test_app("errors", &[]);
        let json = Request::post("/notify")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(r#"{"urls": "json://localhost"}"#)))
            .unwrap();
        let (status, _, body) = send(&app, json).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, r#"{"error":"Payload lacks minimum requirements"}"#);
        let (status, _, body) = send(&app, form("/notify", "urls=json://localhost")).await;
        assert_eq!((status, body.as_str()), (StatusCode::BAD_REQUEST, "Payload lacks minimum requirements"));
        // A field of the wrong type is named, though the body is one of two schemas (a notification or an alert).
        let wrong_type = Request::post("/notify")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(r#"{"urls": 5, "body": "x"}"#)))
            .unwrap();
        let (status, _, body) = send(&app, wrong_type).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, r#"{"error":"The urls field must be a string or list of strings","field":"urls"}"#);
        // Not JSON, and JSON that is not an object.
        for (sent, error) in
            [("not json", "Invalid JSON Payload provided"), ("[1]", "The JSON payload must be an object")]
        {
            let request = Request::post("/notify")
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(sent)))
                .unwrap();
            let (status, _, body) = send(&app, request).await;
            assert_eq!((status, body), (StatusCode::BAD_REQUEST, format!(r#"{{"error":"{error}"}}"#)));
        }
    }

    #[tokio::test]
    async fn the_gate_admits_keys_and_the_administrator() {
        let app = test_app("gate", &["--auth-required", "yes", "--password", "pw"]);
        let (status, headers, _) = send(&app, Request::get("/metrics").body(empty()).unwrap()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(headers["www-authenticate"], "Basic realm=\"Mercurio API\"");
        let admin = Request::get("/metrics").header("authorization", "Basic OnB3").body(empty()).unwrap();
        assert_eq!(send(&app, admin).await.0, StatusCode::OK);
        // A key in the path passes the gate; the key's own check answers.
        let (status, headers, _) = send(&app, form("/notify/abc", "body=x")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(headers["www-authenticate"], "Basic realm=\"Mercurio API: abc\"");
    }

    #[tokio::test]
    async fn basic_auth_is_utf8_or_latin1() {
        let app = test_app("latin1", &["--auth-required", "yes", "--password", "p\u{e4}"]);
        // `:pä` in UTF-8, then in Latin-1.
        for creds in ["OnDDpA==", "OnDk"] {
            let request =
                Request::get("/metrics").header("authorization", format!("Basic {creds}")).body(empty()).unwrap();
            assert_eq!(send(&app, request).await.0, StatusCode::OK, "{creds}");
        }
    }
}
