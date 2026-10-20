//! `mercurio serve`: the notification HTTP API.
//!
//! Endpoints, payloads, settings and status codes are documented in the user guide: `docs/book/src/server.md`.

mod api;
mod auth;
mod codec;
mod details;
mod filters;
mod http;
mod metrics;
mod notify;
mod payload;
mod router;
mod settings;
mod store;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ConnectInfo;
use mercurio::AsyncTransport;
use mercurio::{Config, ConfigFormat, ConfigOptions, ConfigService};
use tower::ServiceExt;

use auth::{KeyState, Role};
use http::{Reply, Req};
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
    streams: Arc<notify::StreamSlots>,
}
/// `mercurio serve --healthcheck`: `GET /status` on the server listening at `bind` (a wildcard address is reached through loopback). `Ok` on `200`. The container image's `HEALTHCHECK` runs it; the image has no curl.
pub fn healthcheck(bind: &str) -> Result<(), String> {
    use std::io::{Read as _, Write as _};
    use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
    let mut addr: SocketAddr =
        bind.to_socket_addrs().map_err(|e| format!("{bind}: {e}"))?.next().ok_or(format!("{bind}: no address"))?;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() { [127, 0, 0, 1].into() } else { std::net::Ipv6Addr::LOCALHOST.into() });
    }
    let mut conn = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(|e| format!("{addr}: {e}"))?;
    conn.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
    write!(conn, "GET /status HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").map_err(|e| e.to_string())?;
    let mut head = [0u8; 64];
    let n = conn.read(&mut head).map_err(|e| format!("{addr}: {e}"))?;
    let line = String::from_utf8_lossy(&head[..n]);
    match line.split_whitespace().nth(1) {
        Some("200") => Ok(()),
        Some(code) => Err(format!("{addr}: /status answered {code}")),
        None => Err(format!("{addr}: no HTTP answer")),
    }
}
pub async fn run(bind: &str, args: &ServeArgs) -> Result<(), String> {
    let s = Settings::from_args(args)?;
    let listener = tokio::net::TcpListener::bind(bind).await.map_err(|e| format!("bind {bind}: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let mut stop = std::pin::pin!(shutdown());
    outln!("listening on http://{addr}");
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
        let app = app.clone();
        let service = hyper::service::service_fn(move |mut request: hyper::Request<hyper::body::Incoming>| {
            request.extensions_mut().insert(ConnectInfo(remote));
            app.clone().oneshot(request.map(axum::body::Body::new))
        });
        // `half_close`: a client that shut its writing side still gets its answer.
        let conn = hyper::server::conn::http1::Builder::new()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(http::IO_TIMEOUT)
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
/// Resolves on SIGINT, SIGTERM or SIGHUP (Ctrl-C elsewhere). The handlers are installed when this is called, not when it is first awaited, so a signal sent right after the listener is announced is never lost to the default action.
fn shutdown() -> impl std::future::Future<Output = ()> {
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
    #[cfg(not(unix))]
    async {
        tokio::signal::ctrl_c().await.ok();
    }
}
/// Config IDs: 1 to 128 letters, digits, `_` or `-`.
pub(crate) fn valid_key(key: &str) -> bool {
    let n = key.chars().count();
    (1..=128).contains(&n) && key.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-')
}
const MISSING_KEY: &str = "A configuration ID is required (URL path or X-Apprise-Config-ID header)";
const INVALID_KEY_HEADER: &str = "The X-Apprise-Config-ID header provided is invalid";
const DENIED: &str = "The site has been configured to deny this request";
/// The effective Config ID: a valid `Config-ID` header wins over the path.
fn resolve_key(req: &Req, path_key: Option<&str>) -> Result<String, Reply> {
    match req.x_header("Config-ID") {
        Some(h) if valid_key(h) => Ok(h.to_string()),
        Some(_) => Err(Reply::error(req, 400, INVALID_KEY_HEADER)),
        None => path_key.map(str::to_string).ok_or_else(|| Reply::error(req, 400, MISSING_KEY)),
    }
}

impl Server {
    async fn key_state(&self, key: &str) -> KeyState {
        self.s.auth.key_state(&self.store, key, self.s.config_lock).await
    }

    /// May this request use `key`? Sets the caller's role on success.
    async fn key_ok(&self, req: &Req, key: &str, allow_public: bool) -> bool {
        req.note(|ev| ev.key = Some(key.to_string()));
        match req.role.get() {
            Role::Admin | Role::Open => return true,
            Role::User | Role::Anonymous => {}
        }
        let state = self.key_state(key).await;
        if allow_public && state.public() {
            return true;
        }
        let Some(digest) = state.digest.as_deref() else { return false };
        let Some((user, pass)) = req.basic_auth() else { return false };
        if !self.verifier.verify(key, &user, &pass, state.username.as_deref(), digest) {
            return false;
        }
        if state.disabled() {
            req.disabled_key.set(Some(key.to_string()));
            return false;
        }
        req.role.set(Role::User);
        true
    }

    /// The answer when [`Server::key_ok`] said no.
    fn key_denied(&self, req: &Req, key: &str) -> Reply {
        if req.disabled_key.get().as_deref() == Some(key) {
            return Reply::error(req, 403, "This configuration has been disabled by an administrator");
        }
        let realm = format!("Basic realm=\"{}: {key}\"", self.s.auth.realm);
        Reply::error(req, 401, "Access Denied").header("WWW-Authenticate", &realm)
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

    fn stateful_disabled(&self, req: &Req) -> Option<Reply> {
        (!self.store.enabled()).then(|| Reply::error(req, 403, "Persistent configuration storage is disabled"))
    }

    /// Whether this caller may see or change configuration content.
    async fn config_lock_allows(&self, req: &Req, key: Option<&str>) -> bool {
        req.role.get() == Role::Admin || !self.configuration_is_locked(key).await
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
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use clap::Parser;
    use tower::ServiceExt;

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        serve: ServeArgs,
    }

    /// The app with `settings` (as `mercurio serve` flags) and a fresh configuration directory.
    fn test_app(name: &str, settings: &[&str]) -> tower_http::normalize_path::NormalizePath<axum::Router> {
        let dir = std::env::temp_dir().join(format!("mercurio-app-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        let dir = dir.to_string_lossy().to_string();
        let args = Cli::parse_from(["serve", "--config-dir", &dir].iter().chain(settings));
        app(Settings::from_args(&args.serve).unwrap())
    }

    /// Send one request; status, headers and body.
    async fn send(
        app: &tower_http::normalize_path::NormalizePath<axum::Router>,
        request: Request<Body>,
    ) -> (StatusCode, axum::http::HeaderMap, String) {
        let mut request = request;
        request.extensions_mut().insert(ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 9))));
        let res = app.clone().oneshot(request).await.unwrap();
        let (parts, body) = res.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        (parts.status, parts.headers, String::from_utf8_lossy(&body).into_owned())
    }

    fn form(path: &str, body: &str) -> Request<Body> {
        Request::post(path)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn unknown_paths_and_methods() {
        let app = test_app("routes", &[]);
        let (status, _, body) = send(&app, Request::get("/invalid").body(Body::empty()).unwrap()).await;
        assert_eq!((status, body.as_str()), (StatusCode::NOT_FOUND, ""));
        let (status, headers, _) = send(&app, Request::get("/notify").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(headers["allow"], "POST");
        let (status, _, _) = send(&app, form("/add/bad!", "urls=json://localhost")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, body) = send(&app, Request::get("/status/").body(Body::empty()).unwrap()).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "OK"));
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
            .body(Body::from(r#"{"urls": "json://localhost"}"#))
            .unwrap();
        let (status, _, body) = send(&app, json).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, r#"{"error":"Payload lacks minimum requirements"}"#);
        let (status, _, body) = send(&app, form("/notify", "urls=json://localhost")).await;
        assert_eq!((status, body.as_str()), (StatusCode::BAD_REQUEST, "Payload lacks minimum requirements"));
    }

    #[tokio::test]
    async fn the_gate_admits_keys_and_the_administrator() {
        let app = test_app("gate", &["--auth-required", "yes", "--password", "pw"]);
        let (status, headers, _) = send(&app, Request::get("/metrics").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(headers["www-authenticate"], "Basic realm=\"Mercurio API\"");
        let admin = Request::get("/metrics").header("authorization", "Basic OnB3").body(Body::empty()).unwrap();
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
                Request::get("/metrics").header("authorization", format!("Basic {creds}")).body(Body::empty()).unwrap();
            assert_eq!(send(&app, request).await.0, StatusCode::OK, "{creds}");
        }
    }
}
