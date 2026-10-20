//! `mercurio serve`: the notification HTTP API.
//!
//! Endpoints, payloads, settings and status codes are documented in the user guide: `docs/book/src/server.md`.

mod auth;
mod codec;
mod details;
mod filters;
mod http;
mod metrics;
mod notify;
mod payload;
mod store;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use axum::extract::{ConnectInfo, State};
use mercurio::config::{Config, ConfigFormat, ConfigOptions, ConfigService};
use mercurio::{
    AsyncMercurio, AsyncTransport, BoxFuture, Message, NotifyFormat, NotifyType, TagFilter, TokioTransport,
};
use serde_json::{Map, Value, json};
use tower::ServiceExt;

use auth::{AuthSettings, KeyState, Role};
use http::{Reply, Req, parse_bool};
use payload::Content;
use store::{Cleared, ConfigStore, Mode, Moved};

/// Requests in progress at once; more get 503 + `Retry-After`.
const MAX_CONNECTIONS: usize = 64;

/// A route handler, run after the authentication gate: an answer computed now, or one that waits for I/O.
enum Handler<'a> {
    Now(Box<dyn FnOnce() -> Reply + Send + 'a>),
    Later(BoxFuture<'a, Reply>),
}

fn now<'a>(f: impl FnOnce() -> Reply + Send + 'a) -> Handler<'a> {
    Handler::Now(Box::new(f))
}

fn later<'a>(f: impl Future<Output = Reply> + Send + 'a) -> Handler<'a> {
    Handler::Later(Box::pin(f))
}
/// Django's built-in default `SECRET_KEY`, the hash-mode salt when none is set.
const DEFAULT_SECRET_KEY: &str = "+reua88v8rs4j!bcfdtinb-f0edxazf!$x_q1g7jtgckxd7gi=";

/// The HTTP API: paths, methods, purpose. `route` implements it; the `routes_match_the_router` test checks every row against it.
pub(crate) const ROUTES: &[(&str, &str, &str)] = &[
    ("/status, /status/{key}", "GET", "health check: OK or the problems found (JSON with Accept: application/json)"),
    ("/details", "GET", "supported services as JSON; ?all=yes includes disabled ones"),
    ("/metrics", "GET", "request counters in the Prometheus text format"),
    ("/notify", "POST", "stateless: send to the URLs in the request"),
    ("/notify/{key}", "POST", "send through the stored configuration"),
    ("/add/{key}", "POST", "store a configuration"),
    ("/get/{key}, /cfg/{key}", "POST", "return the stored configuration"),
    ("/del/{key}", "POST", "delete the stored configuration (and its login)"),
    ("/move/{key}", "POST", "move a configuration and its login to the free key `to`"),
    ("/json/urls/{key}", "GET", "the stored URLs, their tags and template names"),
    ("/cfg", "GET", "the stored keys (simple mode)"),
    ("/auth/{key}", "GET, POST, DELETE", "read, set or remove the key's login"),
];

/// Request fields: names, the endpoints that read them, meaning.
pub(crate) const FIELDS: &[(&str, &str, &str)] = &[
    ("urls", "/notify, /add", "URLs separated by commas or whitespace; a JSON list works too"),
    ("body", "notify", "message body; required unless there is an attachment"),
    ("title", "notify", "message title"),
    ("type", "notify", "info (default), success, warning, failure"),
    ("format", "notify", "input format: text, html, markdown"),
    ("tag, tags", "notify", "tag expression"),
    ("template", "notify", "${NAME} values: a JSON object, template[name]=value fields or NAME=VALUE strings"),
    (
        "attach, attachment, attachments",
        "notify",
        "http(s):// URLs to download; in JSON also {url, filename} or {base64, filename} objects",
    ),
    ("config", "/add", "TEXT or YAML configuration"),
    ("format", "/add", "text, yaml, or empty / auto to detect"),
    ("to (JSON), from + to (form)", "/move", "destination key (form: also the source)"),
];

/// Request headers and what they set.
pub(crate) const HEADERS: &[(&str, &str)] = &[
    ("X-Apprise-Title", "the title"),
    ("X-Apprise-Type", "the type"),
    ("X-Apprise-Tag", "the tag expression"),
    ("X-Apprise-Template", "template values as URL-encoded pairs (api_key=abc&room=ops)"),
    ("X-Apprise-Config-ID", "the key, instead of the path (kept out of access logs)"),
    ("X-Apprise-Log-Level", "detail of the returned logs: trace, debug, info, warning, error, critical"),
    ("X-Apprise-Recursion-Count", "servers this call already went through; above --recursion-max is 406"),
    ("X-Apprise-ID", "id of the call chain, passed on by apprise:// targets"),
];

/// The tables above as `mercurio serve --help` shows them.
pub(crate) fn help_tables() -> String {
    let mut out = String::from("Endpoints:\n");
    for (path, methods, purpose) in ROUTES {
        out.push_str(&format!("  {path:<24} {methods:<18} {purpose}\n"));
    }
    out.push_str("\nRequest fields:\n");
    for (fields, used_by, meaning) in FIELDS {
        out.push_str(&format!("  {fields:<33} {used_by:<14} {meaning}\n"));
    }
    out.push_str("\nHeaders:\n");
    for (name, sets) in HEADERS {
        out.push_str(&format!("  {name:<26} {sets}\n"));
    }
    out
}

/// Server settings: each is a flag of `mercurio serve` and an environment variable. `mercurio serve --help` lists them; the book includes that output.
#[derive(Debug, Clone, clap::Args)]
#[command(next_help_heading = "Server settings")]
pub(crate) struct ServeArgs {
    /// Where stored configurations are kept (relative to the working directory)
    #[arg(long, env = "APPRISE_CONFIG_DIR", default_value = "mercurio-config", value_name = "DIR")]
    config_dir: String,
    /// `hash`, `simple` or `disabled`: layout of stored configurations
    #[arg(long, env = "APPRISE_STATEFUL_MODE", default_value = "hash", value_name = "MODE")]
    stateful_mode: String,
    /// Salt of `hash` file names [default: built-in]
    #[arg(long, env = "SECRET_KEY", hide_env_values = true, value_name = "KEY")]
    secret_key: Option<String>,
    /// `no` refuses stateless `POST /notify`
    #[arg(long, env = "APPRISE_STATELESS_MODE", default_value = "yes", value_name = "YES|NO")]
    stateless_mode: String,
    /// URLs used by `POST /notify` when the request gives none
    #[arg(long, env = "APPRISE_STATELESS_URLS", hide_env_values = true, value_name = "URLS")]
    stateless_urls: Option<String>,
    /// Hide configuration content and management from everyone but the administrator
    #[arg(long, env = "APPRISE_CONFIG_LOCK", default_value = "no", value_name = "YES|NO")]
    config_lock: String,
    /// Offer the `GET /cfg` key list (`simple` mode only)
    #[arg(long, env = "APPRISE_ADMIN", default_value = "yes", value_name = "YES|NO")]
    admin: String,
    /// Largest `config` accepted by `/add`, in KiB
    #[arg(long, env = "APPRISE_CONFIG_MAX_LENGTH", default_value = "512", value_name = "KIB")]
    config_max_length: String,
    /// Upper bound of `--config-max-length`, in MiB
    #[arg(long, env = "APPRISE_UPLOAD_MAX_MEMORY_SIZE", default_value = "3", value_name = "MIB")]
    upload_max_memory_size: String,
    /// `include` levels followed, and the highest `X-Apprise-Recursion-Count` accepted
    #[arg(long, env = "APPRISE_RECURSION_MAX", default_value = "1", value_name = "N")]
    recursion_max: String,
    /// Honour `template:` sections and `${NAME}` markers
    #[arg(long, env = "APPRISE_ALLOW_TEMPLATES", default_value = "yes", value_name = "YES|NO")]
    allow_templates: String,
    /// `text`, `html` or `markdown` for requests without `format`
    #[arg(long, env = "APPRISE_DEFAULT_FORMAT", value_name = "FORMAT")]
    default_format: Option<String>,
    /// Services that can not be used (one scheme names the whole service)
    #[arg(
        long,
        env = "APPRISE_DENY_SERVICES",
        default_value = "windows,dbus,gnome,macosx,syslog",
        value_name = "LIST"
    )]
    deny_services: String,
    /// When set, the only services that can be used (the deny list is ignored)
    #[arg(long, env = "APPRISE_ALLOW_SERVICES", value_name = "LIST")]
    allow_services: Option<String>,
    /// Largest attachment in MiB; `0` turns attachments off
    #[arg(long, env = "APPRISE_ATTACH_SIZE", default_value = "200", value_name = "MIB")]
    attach_size: String,
    /// Attachments per request; `0` means no limit
    #[arg(long, env = "APPRISE_MAX_ATTACHMENTS", default_value = "6", value_name = "N")]
    max_attachments: String,
    /// Attachment URLs that may be downloaded
    #[arg(long, env = "APPRISE_ATTACH_ALLOW_URL", default_value = "*", value_name = "PATTERNS")]
    attach_allow_url: String,
    /// Attachment URLs that are always refused (checked first)
    #[arg(long, env = "APPRISE_ATTACH_REJECT_URL", default_value = "127.0.* localhost*", value_name = "PATTERNS")]
    attach_reject_url: String,
    /// Deepest nested path a `?:a.b=dest` mapping rule may read
    #[arg(long, env = "APPRISE_WEBHOOK_MAPPING_MAX_DEPTH", default_value = "5", value_name = "N")]
    webhook_mapping_max_depth: String,
    /// `http(s)://` URL that receives the result of every notification
    #[arg(long, env = "APPRISE_WEBHOOK_URL", hide_env_values = true, value_name = "URL")]
    webhook_url: Option<String>,
    /// Persistent storage for services (tokens, sessions) [default: <config dir>/store]
    #[arg(long, env = "APPRISE_STORAGE_DIR", value_name = "DIR")]
    storage_dir: Option<String>,
    /// `auto` or `flush` write to the storage directory; `memory` keeps nothing
    #[arg(long, env = "APPRISE_STORAGE_MODE", default_value = "auto", value_name = "MODE")]
    storage_mode: String,
    /// Stateless sends use persistent storage too
    #[arg(long, env = "APPRISE_STATELESS_STORAGE", default_value = "no", value_name = "YES|NO")]
    stateless_storage: String,
    /// Default detail of returned logs
    #[arg(long, env = "LOG_LEVEL", default_value = "INFO", value_name = "LEVEL")]
    log_level: String,
    /// `no` stops following HTTP redirects for URLs without `?redirect=`
    #[arg(long, env = "APPRISE_HTTP_REDIRECTS", default_value = "yes", value_name = "YES|NO")]
    http_redirects: String,
    /// Live streams sending at the same time
    #[arg(long, env = "APPRISE_STREAM_WORKER_COUNT", default_value = "4", value_name = "N")]
    stream_worker_count: String,
    /// Further live streams admitted; more get `503`
    #[arg(long, env = "APPRISE_STREAM_QUEUE_SIZE", default_value = "8", value_name = "N")]
    stream_queue_size: String,
    /// Turn on Basic Auth
    #[arg(long, env = "APPRISE_AUTH_REQUIRED", default_value = "no", value_name = "YES|NO")]
    auth_required: String,
    /// Administrator user name (may be empty)
    #[arg(long, env = "APPRISE_USER", value_name = "NAME")]
    user: Option<String>,
    /// Administrator password; enables the administrator login
    #[arg(long, env = "APPRISE_PASSWORD", hide_env_values = true, value_name = "PASSWORD")]
    password: Option<String>,
    /// Realm shown in login prompts
    #[arg(long, env = "APPRISE_BASIC_AUTH_REALM", default_value = "Mercurio API", value_name = "REALM")]
    basic_auth_realm: String,
}

fn int(name: &str, raw: &str, min: i64, max: i64) -> Result<i64, String> {
    let v: i64 = raw.trim().parse().map_err(|_| format!("{name} must be a whole number"))?;
    if v < min || v > max {
        return Err(format!("{name} must be between {min} and {max}"));
    }
    Ok(v)
}

/// Server settings, read once at start-up.
pub(crate) struct Settings {
    config_dir: PathBuf,
    stateful: Mode,
    secret: String,
    stateless_enabled: bool,
    stateless_urls: Option<String>,
    recursion_max: u32,
    config_lock: bool,
    /// `GET /cfg` key listing (`APPRISE_ADMIN`).
    admin_list: bool,
    config_max_len: usize,
    default_format: Option<NotifyFormat>,
    allow_templates: bool,
    attach_size: u64,
    max_attachments: usize,
    /// Deepest `?:a.b.c=` mapping path (`APPRISE_WEBHOOK_MAPPING_MAX_DEPTH`).
    mapping_depth: usize,
    auth: AuthSettings,
    /// Persistent storage for services (`None`: in memory).
    storage: Option<PathBuf>,
    stateless_storage: bool,
    http_redirects: bool,
    log_level: u8,
    stream_slots: usize,
    services: filters::ServiceFilter,
    attach_urls: filters::UrlFilter,
    webhook: Option<String>,
}

impl Settings {
    fn from_args(a: &ServeArgs) -> Result<Settings, String> {
        let flag = |v: &str, default: bool| parse_bool(Some(v), default);
        let config_dir = PathBuf::from(if a.config_dir.is_empty() { "mercurio-config" } else { &a.config_dir });
        let stateful =
            Mode::parse(&a.stateful_mode).ok_or("APPRISE_STATEFUL_MODE must be one of: hash, simple, disabled")?;
        let secret = a.secret_key.clone().unwrap_or_else(|| DEFAULT_SECRET_KEY.to_string());
        let upload_max = int("APPRISE_UPLOAD_MAX_MEMORY_SIZE", &a.upload_max_memory_size, i64::MIN, i64::MAX)?
            .unsigned_abs() as usize
            * 1_048_576;
        let config_max = (int("APPRISE_CONFIG_MAX_LENGTH", &a.config_max_length, i64::MIN, i64::MAX)?.unsigned_abs()
            as usize
            * 1024)
            .min(upload_max);
        let default_format = a.default_format.as_deref().and_then(|f| {
            let f = f.trim().to_lowercase();
            if ["text", "html", "markdown"].contains(&f.as_str()) { NotifyFormat::parse(&f) } else { None }
        });
        let required = flag(&a.auth_required, false);
        let user = a.user.as_deref().map(|u| u.trim().to_string()).unwrap_or_default();
        let admin = match a.password.clone().filter(|p| !p.is_empty()) {
            Some(_) if user.contains(':') => return Err("APPRISE_USER cannot contain ':'".into()),
            Some(p) if required => Some((user, p)),
            _ => {
                if required && !user.is_empty() {
                    log::warn!(
                        "APPRISE_USER was set without APPRISE_PASSWORD; the administration account is disabled."
                    );
                }
                None
            }
        };
        let auth = AuthSettings { required, admin, realm: a.basic_auth_realm.clone() };
        let services = filters::ServiceFilter::new(a.allow_services.as_deref(), Some(&a.deny_services));
        let attach_urls = filters::UrlFilter::new(&a.attach_allow_url, &a.attach_reject_url);
        let storage = match a.storage_mode.trim().to_lowercase().as_bytes().first() {
            Some(b'm') => None,
            Some(b'a' | b'f') => Some(
                a.storage_dir
                    .as_deref()
                    .filter(|d| !d.trim().is_empty())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| config_dir.join("store")),
            ),
            _ => return Err("APPRISE_STORAGE_MODE must be one of: auto, flush, memory".into()),
        };
        let log_level = notify::level_value(&a.log_level).unwrap_or(20);
        let stream_slots = (int("APPRISE_STREAM_WORKER_COUNT", &a.stream_worker_count, 1, i64::MAX)?
            + int("APPRISE_STREAM_QUEUE_SIZE", &a.stream_queue_size, 0, i64::MAX)?) as usize;
        Ok(Settings {
            storage,
            stateless_storage: flag(&a.stateless_storage, false),
            http_redirects: flag(&a.http_redirects, true),
            log_level,
            stream_slots,
            services,
            attach_urls,
            webhook: a.webhook_url.clone().filter(|u| !u.trim().is_empty()),
            auth,
            config_dir,
            stateful,
            secret,
            stateless_enabled: flag(&a.stateless_mode, true),
            stateless_urls: a.stateless_urls.clone().filter(|v| !v.trim().is_empty()),
            recursion_max: int("APPRISE_RECURSION_MAX", &a.recursion_max, 0, i64::from(u32::MAX))? as u32,
            config_lock: flag(&a.config_lock, false),
            admin_list: flag(&a.admin, true),
            config_max_len: config_max,
            default_format,
            allow_templates: flag(&a.allow_templates, true),
            attach_size: int("APPRISE_ATTACH_SIZE", &a.attach_size, i64::MIN, i64::MAX)?.max(0) as u64 * 1_048_576,
            max_attachments: int("APPRISE_MAX_ATTACHMENTS", &a.max_attachments, 0, i64::MAX)? as usize,
            // Negative values count as positive, as in apprise-api.
            mapping_depth: int("APPRISE_WEBHOOK_MAPPING_MAX_DEPTH", &a.webhook_mapping_max_depth, i64::MIN, i64::MAX)?
                .unsigned_abs() as usize,
        })
    }
}

struct Server {
    transport: Arc<dyn AsyncTransport>,
    /// Requests in progress.
    active: AtomicUsize,
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
    let store = ConfigStore::new(s.config_dir.clone(), s.stateful, s.secret.clone());
    let s_slots = s.stream_slots;
    let server = Arc::new(Server {
        transport: Arc::new(TokioTransport::new()),
        active: AtomicUsize::new(0),
        s,
        store,
        metrics: Arc::new(metrics::Metrics::default()),
        verifier: auth::Verifier::default(),
        streams: notify::StreamSlots::new(s_slots),
    });
    outln!("listening on http://{addr}");
    let app = axum::Router::new().fallback(answer).with_state(server);
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let mut stop = std::pin::pin!(shutdown());
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
            .title_case_headers(true)
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
async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let (Ok(mut term), Ok(mut hup)) = (signal(SignalKind::terminate()), signal(SignalKind::hangup())) else {
            tokio::signal::ctrl_c().await.ok();
            return;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
            _ = hup.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await.ok();
}

/// Gives back a request's place in [`Server::active`].
struct InFlight<'a>(&'a AtomicUsize);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Every request: at most [`MAX_CONNECTIONS`] in progress (503 + `Retry-After` beyond), then [`Server::handle`].
async fn answer(
    State(server): State<Arc<Server>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let req = match http::read(request, remote).await {
        Ok(req) => req,
        Err(reply) => {
            log::info!("bad request -> {}", reply.status);
            return reply.header("Connection", "close").into_response();
        }
    };
    let _in_flight = InFlight(&server.active);
    if server.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
        return Reply::text(503, "busy").header("Retry-After", "1").header("Connection", "close").into_response();
    }
    server.handle(&req).await.into_response()
}

/// Config IDs: 1 to 128 letters, digits, `_` or `-`.
fn valid_key(key: &str) -> bool {
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
    /// Answer one request.
    async fn handle(&self, req: &Req) -> Reply {
        let started = Instant::now();
        let role = if !self.s.auth.required {
            Role::Open
        } else if self.s.auth.is_admin(req.basic_auth().as_ref()) {
            Role::Admin
        } else {
            Role::Anonymous
        };
        req.role.set(role);
        let (handler, view) = self.route(req);
        let reply = match handler {
            Handler::Now(f) => f(),
            Handler::Later(f) => f.await,
        };
        log::info!("{} {} -> {}", req.method, req.path, reply.status);
        self.metrics.record(&req.method, view, reply.status, started.elapsed());
        reply
    }

    fn route<'a>(&'a self, req: &'a Req) -> (Handler<'a>, &'static str) {
        let path = req.path.trim_matches('/');
        let segs: Vec<&str> = if path.is_empty() { Vec::new() } else { path.split('/').collect() };
        let get = matches!(req.method.as_str(), "GET" | "HEAD");
        let post = req.method == "POST";
        let delete = req.method == "DELETE";
        let any = get || post || delete;
        let not_allowed =
            |allow: &'static str| -> Handler<'a> { now(move || Reply::empty(405).header("Allow", allow)) };
        let key = |k: &str| valid_key(k);
        let missing = || -> Handler<'a> { now(|| Reply::error(req, 400, MISSING_KEY)) };
        let (view, handler): (&'static str, Handler<'a>) = match segs[..] {
            ["status"] if get => ("health", now(|| self.status(req, None))),
            ["status", "@"] if get => ("health_current", missing()),
            ["status", k] if get && key(k) => ("health_key", now(move || self.status(req, Some(k)))),
            ["details"] if get => ("details", now(|| self.details(req))),
            ["metrics"] if get => ("prometheus-django-metrics", now(|| self.metrics_page(req))),
            ["cfg"] if get => ("config_list", now(|| self.list(req))),
            ["cfg", "@"] if get || post => ("config_current", missing()),
            ["cfg", k] if post && key(k) => ("config", now(move || self.get_config(req, Some(k)))),
            ["get"] if post => ("get_by_header", now(|| self.get_config(req, None))),
            ["get", k] if post && key(k) => ("get", now(move || self.get_config(req, Some(k)))),
            ["add"] if post => ("add_by_header", later(self.add(req, None))),
            ["add", k] if post && key(k) => ("add", later(self.add(req, Some(k)))),
            ["del"] if post => ("del_by_header", now(|| self.del(req, None))),
            ["del", k] if post && key(k) => ("del", now(move || self.del(req, Some(k)))),
            ["move"] if post => ("move_by_header", now(|| self.move_config(req, None))),
            ["move", k] if post && key(k) => ("move", now(move || self.move_config(req, Some(k)))),
            ["auth", "@"] if any => ("auth_current", missing()),
            ["auth"] if any => ("auth_by_header", now(|| self.auth_view(req, None))),
            ["auth", k] if any && key(k) => ("auth", now(move || self.auth_view(req, Some(k)))),
            ["notify"] if post => ("s_notify", later(self.notify_stateless(req))),
            ["notify", k] if post && key(k) => ("notify", later(self.notify_route(req, k))),
            ["json", "urls"] if get => ("json_urls_by_header", later(self.json_urls(req, None))),
            ["json", "urls", k] if get && key(k) => ("json_urls", later(self.json_urls(req, Some(k)))),
            ["status" | "details" | "metrics" | "cfg"] | ["json", "urls"] => {
                ("<405>", not_allowed("GET, HEAD, OPTIONS"))
            }
            ["status", k] | ["json", "urls", k] if key(k) || k == "@" => ("<405>", not_allowed("GET, HEAD, OPTIONS")),
            ["auth"] => ("<405>", not_allowed("GET, POST, DELETE, HEAD, OPTIONS")),
            ["auth", k] if key(k) || k == "@" => ("<405>", not_allowed("GET, POST, DELETE, HEAD, OPTIONS")),
            ["get" | "add" | "del" | "move" | "notify"] => ("<405>", not_allowed("POST, OPTIONS")),
            ["cfg" | "get" | "add" | "del" | "move" | "notify", k] if key(k) || k == "@" => {
                ("<405>", not_allowed("POST, OPTIONS"))
            }
            _ => ("<unnamed view>", now(|| Reply::error(req, 404, "Not Found"))),
        };
        if req.role.get() == Role::Anonymous && view != "<405>" {
            const KEYED: &[&str] =
                &["config", "add", "del", "get", "move", "notify", "json_urls", "auth", "health_key"];
            const BY_HEADER: &[&str] = &[
                "add_by_header",
                "del_by_header",
                "get_by_header",
                "move_by_header",
                "s_notify",
                "json_urls_by_header",
                "auth_by_header",
                "health",
                "details",
            ];
            let keyed = KEYED.contains(&view) || (BY_HEADER.contains(&view) && req.x_header("Config-ID").is_some());
            if !keyed {
                let realm = format!("Basic realm=\"{}\"", self.s.auth.realm);
                return (now(move || Reply::error(req, 401, "Access Denied").header("WWW-Authenticate", &realm)), view);
            }
        }
        (handler, if view == "<405>" { "<unnamed view>" } else { view })
    }

    fn key_state(&self, key: &str) -> KeyState {
        self.s.auth.key_state(&self.store, key, self.s.config_lock)
    }

    /// May this request use `key`? Sets the caller's role on success.
    fn key_ok(&self, req: &Req, key: &str, allow_public: bool) -> bool {
        match req.role.get() {
            Role::Admin | Role::Open => return true,
            Role::User | Role::Anonymous => {}
        }
        let state = self.key_state(key);
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
        log::warn!("AUTH - {} - Per-key Authentication Failed - Request Denied for KEY: {key}", req.remote);
        let realm = format!("Basic realm=\"{}: {key}\"", self.s.auth.realm);
        Reply::error(req, 401, "Access Denied").header("WWW-Authenticate", &realm)
    }

    /// Either the global lock or the key's own access mode hides configuration content.
    fn configuration_is_locked(&self, key: Option<&str>) -> bool {
        if !self.store.enabled() {
            return false;
        }
        if self.s.config_lock {
            return true;
        }
        match key {
            Some(k) if self.s.auth.required => self.key_state(k).config_locked(),
            _ => false,
        }
    }

    fn auth_view(&self, req: &Req, key: Option<&str>) -> Reply {
        if let Some(r) = self.stateful_disabled(req) {
            return r;
        }
        if req.method == "POST" && req.content_type() != "application/json" {
            return Reply::error(req, 400, "Content-Type must be application/json");
        }
        if !self.s.auth.required {
            return Reply::error(req, 403, "Authentication mode is disabled (set APPRISE_AUTH_REQUIRED to enable it)");
        }
        let key = match resolve_key(req, key) {
            Ok(k) => k,
            Err(r) => return r,
        };
        let state = self.key_state(&key);
        match req.method.as_str() {
            "POST" => {
                let allowed =
                    if state.configured() { self.key_ok(req, &key, false) } else { req.role.get() == Role::Admin };
                if !allowed {
                    return self.key_denied(req, &key);
                }
                self.auth_set(req, &key, &state)
            }
            "DELETE" => {
                if !self.key_ok(req, &key, false) {
                    return self.key_denied(req, &key);
                }
                if req.role.get() != Role::Admin {
                    let msg = "Global administrator credentials are required to remove authentication";
                    return Reply::error(req, 403, msg);
                }
                match self.store.clear_auth(&key) {
                    Cleared::Failed => Reply::error(req, 500, "The authentication could not be removed"),
                    Cleared::Removed | Cleared::Nothing if req.wants_json() => {
                        Reply::json(200, &json!({"error": null, "auth_state": "admin"}))
                    }
                    Cleared::Removed | Cleared::Nothing => Reply::text(200, "Successfully removed authentication"),
                }
            }
            _ => {
                if !self.key_ok(req, &key, false) {
                    return self.key_denied(req, &key);
                }
                let username =
                    if state.assigned() { state.username.clone().unwrap_or_default() } else { String::new() };
                let access = state.saved_access.clone().unwrap_or(state.access.clone());
                Reply::json(200, &json!({"mode": state.mode, "access": access, "username": username}))
            }
        }
    }

    /// `POST /auth/{key}`: set credentials and access.
    fn auth_set(&self, req: &Req, key: &str, state: &KeyState) -> Reply {
        let content = match payload::json_object(req) {
            Ok(m) => m,
            Err(r) => return r,
        };
        let shared = req.role.get() == Role::User;
        let current_user = state.username.clone().unwrap_or_default();
        let current_access = state.saved_access.clone().unwrap_or(state.access.clone());
        if shared && content.contains_key("access") {
            return Reply::field_error(req, 403, "Only an administrator may set configuration access", "access");
        }
        let field = |k: &str, default: Option<Value>| content.get(k).cloned().or(default);
        let default_user = Value::String(if shared { String::new() } else { current_user.clone() });
        let username = match field("username", Some(default_user)) {
            Some(Value::Null) => Some(String::new()),
            Some(Value::String(s)) => Some(s),
            _ => None,
        };
        let access = field("access", Some(Value::String(current_access.clone())));
        let password = field("password", if shared { None } else { Some(Value::String(String::new())) });
        let confirm = content.get("password_confirm");
        let (Some(username), Some(Value::String(access)), Some(Value::String(password))) = (username, access, password)
        else {
            return Reply::error(req, 400, "Valid username and password fields are required");
        };
        if shared && confirm.is_some_and(|c| !c.is_string()) {
            return Reply::error(req, 400, "Valid username and password fields are required");
        }
        let username = username.trim().to_string();
        if shared && username != current_user {
            return Reply::field_error(req, 403, "The username cannot be changed by a configuration user", "username");
        }
        let access = if access.is_empty() { current_access.clone() } else { access };
        if username.contains(':') {
            return Reply::field_error(req, 400, "Username cannot contain ':'", "username");
        }
        for (name, v) in [("username", &username), ("password", &password)] {
            if v.chars().count() > 255 {
                return Reply::field_error(req, 400, "Ensure this value has at most 255 characters.", name);
            }
        }
        if !store::ACCESS_CHOICES.contains(&access.as_str()) {
            let msg = format!("Select a valid choice. {access} is not one of the available choices.");
            return Reply::field_error(req, 400, &msg, "access");
        }
        let open = access == store::ACCESS_PUBLIC || access == store::ACCESS_DISABLED;
        if shared {
            if password.is_empty() {
                return Reply::field_error(req, 400, "A new password is required", "password");
            }
            if confirm.and_then(Value::as_str).is_some_and(|c| c != password) {
                return Reply::field_error(req, 400, "The passwords do not match", "password_confirm");
            }
            if state.digest.as_deref().is_some_and(|d| codec::password_check(&format!("{username}:{password}"), d)) {
                let msg = "The new password must differ from the current password";
                return Reply::field_error(req, 400, msg, "password");
            }
        } else if password.is_empty() {
            if !state.assigned() && !open {
                return Reply::field_error(req, 400, "A password is required for this access mode", "password");
            } else if username != current_user {
                return Reply::field_error(req, 400, "Set a password when changing the username", "username");
            }
        }
        let saved = if !password.is_empty() {
            let digest = codec::password_hash(&format!("{username}:{password}"));
            let rec = store::AuthRecord { access: access.clone(), username: Some(username), digest: Some(digest) };
            self.store.write_auth(key, &rec)
        } else {
            match self.store.auth(key) {
                Ok(None) if open => {
                    let rec = store::AuthRecord { access: access.clone(), username: None, digest: None };
                    self.store.write_auth(key, &rec)
                }
                Ok(Some(rec)) if rec.digest.is_some() || open => {
                    self.store.write_auth(key, &store::AuthRecord { access: access.clone(), ..rec })
                }
                _ => false,
            }
        };
        if !saved {
            return Reply::error(req, 500, "The authentication could not be saved");
        }
        log::info!("AUTH - {} - Authentication set for KEY: {key}", req.remote);
        let effective =
            if self.s.config_lock && access == store::ACCESS_USER { store::ACCESS_LOCKED } else { access.as_str() };
        if req.wants_json() {
            Reply::json(200, &json!({"error": null, "auth_state": effective}))
        } else {
            Reply::text(200, "Successfully set authentication")
        }
    }

    fn status(&self, req: &Req, key: Option<&str>) -> Reply {
        let key = match (req.x_header("Config-ID"), key) {
            (Some(h), _) if !valid_key(h) => return Reply::error(req, 400, INVALID_KEY_HEADER),
            (Some(h), _) => Some(h.to_string()),
            (None, k) => k.map(str::to_string),
        };
        if let Some(k) = key.as_deref()
            && !self.key_ok(req, k, false)
        {
            return self.key_denied(req, k);
        }
        let stateful = self.store.enabled();
        let mut details = Vec::new();
        let mut can_write_config = false;
        if stateful && !self.s.config_lock {
            can_write_config = self.store.writable();
            if !can_write_config {
                details.push("CONFIG_PERMISSION_ISSUE");
            }
        }
        let mut persistent = false;
        if let Some(dir) = &self.s.storage {
            persistent = std::fs::create_dir_all(dir).is_ok() && std::fs::write(dir.join(".tmp_hc"), b"").is_ok();
            if !persistent {
                details.push("STORE_PERMISSION_ISSUE");
            }
        }
        if details.is_empty() {
            details.push("OK");
        }
        let status = if details.contains(&"OK") { 200 } else { 417 };
        if !req.wants_json() {
            return Reply::text(status, &details.join(","));
        }
        Reply::json(
            status,
            &json!({
                "config_lock": !self.config_lock_allows(req, key.as_deref()),
                "attach_lock": self.s.attach_size == 0,
                "stateful_enabled": stateful,
                "stateless_enabled": self.s.stateless_enabled,
                "degraded": !stateful && !self.s.stateless_enabled,
                "max_attachments": self.s.max_attachments,
                "attach_size": self.s.attach_size,
                "status": {
                    "persistent_storage": persistent,
                    "can_write_config": can_write_config,
                    "can_write_attach": self.s.attach_size > 0,
                    "details": details,
                },
                "privilege": req.role.get().label(),
            }),
        )
    }

    fn details(&self, req: &Req) -> Reply {
        if let Some(h) = req.x_header("Config-ID") {
            if !valid_key(h) {
                return Reply::error(req, 400, INVALID_KEY_HEADER);
            }
            if !self.key_ok(req, h, false) {
                return self.key_denied(req, h);
            }
        }
        let show_all = parse_bool(req.query("all"), false);
        let mut schemas: Vec<Value> = mercurio::services()
            .iter()
            .filter(|d| show_all || self.s.services.enabled(d.id))
            .map(|d| details::schema(d, show_all.then(|| self.s.services.enabled(d.id))))
            .collect();
        schemas.sort_by_key(|s| s["service_name"].as_str().unwrap_or("").to_uppercase());
        let asset = details::asset(&self.asset(false));
        Reply::json(200, &json!({"version": env!("CARGO_PKG_VERSION"), "schemas": schemas, "asset": asset}))
    }

    fn metrics_page(&self, _req: &Req) -> Reply {
        Reply::new(200, "text/plain; version=0.0.4; charset=utf-8", self.metrics.render().into_bytes())
    }

    fn stateful_disabled(&self, req: &Req) -> Option<Reply> {
        (!self.store.enabled()).then(|| Reply::error(req, 403, "Persistent configuration storage is disabled"))
    }

    /// Whether this caller may see or change configuration content.
    fn config_lock_allows(&self, req: &Req, key: Option<&str>) -> bool {
        req.role.get() == Role::Admin || !self.configuration_is_locked(key)
    }

    fn list(&self, req: &Req) -> Reply {
        let allowed = if self.s.auth.required { req.role.get() == Role::Admin } else { !self.s.config_lock };
        if !self.s.admin_list || self.store.mode != Mode::Simple || !allowed {
            return Reply::error(req, 403, DENIED);
        }
        let keys = self.store.keys();
        if !req.wants_json() {
            return Reply::text(200, &keys.join("\n"));
        }
        if !self.s.auth.required {
            return Reply::json(200, &json!(keys));
        }
        let entries: Vec<Value> = keys
            .iter()
            .map(|k| {
                let st = self.key_state(k);
                json!({"key": k, "user": st.username, "access": st.access})
            })
            .collect();
        Reply::json(200, &Value::Array(entries))
    }

    fn get_config(&self, req: &Req, key: Option<&str>) -> Reply {
        if let Some(r) = self.stateful_disabled(req) {
            return r;
        }
        let key = match resolve_key(req, key) {
            Ok(k) => k,
            Err(r) => return r,
        };
        if !self.key_ok(req, &key, false) {
            return self.key_denied(req, &key);
        }
        if !self.config_lock_allows(req, Some(&key)) {
            return Reply::error(req, 403, DENIED);
        }
        match self.store.get(&key) {
            Err(()) => Reply::error(req, 500, "An error occurred accessing configuration"),
            Ok(None) => Reply::empty(204),
            Ok(Some((config, format))) if req.wants_json() => {
                Reply::json(200, &json!({"format": format.as_str(), "config": config}))
            }
            Ok(Some((config, ConfigFormat::Yaml))) => Reply::new(200, "text/yaml; charset=utf-8", config.into_bytes()),
            Ok(Some((config, _))) => Reply::new(200, "text/plain; charset=utf-8", config.into_bytes()),
        }
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

    async fn add(&self, req: &Req, key: Option<&str>) -> Reply {
        if let Some(r) = self.stateful_disabled(req) {
            return r;
        }
        let key = match resolve_key(req, key) {
            Ok(k) => k,
            Err(r) => return r,
        };
        if !self.key_ok(req, &key, false) {
            return self.key_denied(req, &key);
        }
        if !self.config_lock_allows(req, Some(&key)) {
            return Reply::error(req, 403, DENIED);
        }
        let fields: Map<String, Value> = if req.json_payload() {
            let m = match payload::json_object(req) {
                Ok(m) => m,
                Err(r) => return r,
            };
            let str_list = |v: &Value| v.is_string() || v.as_array().is_some_and(|a| a.iter().all(Value::is_string));
            if m.get("urls").is_some_and(|v| !str_list(v)) {
                return Reply::field_error(req, 400, "The urls field must be a string or list of strings", "urls");
            }
            for f in ["config", "format"] {
                if m.get(f).is_some_and(|v| !v.is_string()) {
                    return Reply::field_error(req, 400, &format!("The {f} field must be a string"), f);
                }
            }
            m
        } else {
            let (mut m, _, _) = payload::form_fields(req);
            if m.get("urls").and_then(Value::as_str).is_some_and(str::is_empty) {
                m.remove("urls");
            }
            m
        };
        if fields.contains_key("urls") {
            let raw: Vec<String> = match fields.get("urls") {
                Some(Value::String(s)) => vec![s.clone()],
                Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
                _ => Vec::new(),
            };
            let urls: Vec<String> = mercurio::parse::parse_urls(raw.iter().map(String::as_str), true)
                .into_iter()
                .filter(|u| mercurio::parse(u).is_ok_and(|t| self.s.services.enabled(t.service().id)))
                .collect();
            if urls.is_empty() {
                log::warn!("ADD - {} - No valid URLs defined using KEY: {key}", req.remote);
                return Reply::error(req, 400, "No valid URLs defined");
            }
            if !self.store.put(&key, &urls.join("\r\n"), ConfigFormat::Text) {
                return Reply::error(req, 500, "The configuration could not be saved");
            }
        } else if let Some(config) = fields.get("config").and_then(Value::as_str) {
            if config.len() > self.s.config_max_len {
                return Reply::error(req, 400, "The configuration payload is too large");
            }
            let fmt = fields.get("format").and_then(Value::as_str).unwrap_or("").trim().to_lowercase();
            let format = match fmt.as_str() {
                "" | "auto" => None,
                f => match ConfigFormat::parse(f) {
                    Some(f) => Some(f),
                    None => return Reply::error(req, 400, "Invalid configuration format specified"),
                },
            };
            let mut stored = format.unwrap_or(ConfigFormat::Text);
            if !config.trim().is_empty() {
                let Some(detected) = format.or_else(|| mercurio::config::detect_format(config)) else {
                    return Reply::error(req, 400, "The configuration format could not be auto-detected");
                };
                stored = detected;
                let Ok(cfg) = self.load(config, Some(detected)).await else {
                    return Reply::error(req, 400, "The configuration could not be parsed");
                };
                if cfg.services.is_empty() && detected == ConfigFormat::Yaml && yaml_refused(config) {
                    log::warn!("ADD - {} - The YAML configuration could not be parsed using KEY: {key}", req.remote);
                    return Reply::error(req, 400, "The configuration could not be parsed");
                }
            }
            if !self.store.put(&key, config, stored) {
                return Reply::error(req, 500, "An error occurred saving configuration");
            }
        } else if fields.is_empty() {
            return Reply::error(req, 400, "Invalid payload structure provided");
        } else {
            return Reply::error(req, 400, "No configuration provided");
        }
        log::info!("ADD - {} - Configuration saved using KEY: {key}", req.remote);
        let mut reply = Reply::ok(req, "Successfully saved configuration");
        if let Some((created, modified)) = self.store.file_times(&key) {
            reply = reply
                .header("X-Apprise-Config-Created", &iso_seconds(created))
                .header("X-Apprise-Config-MTime", &iso_seconds(modified));
        }
        reply.header("X-Apprise-Timezone", "Etc/UTC")
    }

    fn del(&self, req: &Req, key: Option<&str>) -> Reply {
        if let Some(r) = self.stateful_disabled(req) {
            return r;
        }
        let key = match resolve_key(req, key) {
            Ok(k) => k,
            Err(r) => return r,
        };
        if !self.key_ok(req, &key, false) {
            return self.key_denied(req, &key);
        }
        if !self.config_lock_allows(req, Some(&key)) {
            return Reply::error(req, 403, DENIED);
        }
        let shared = req.role.get() == Role::User;
        let result = self.store.clear(&key);
        if result == Cleared::Failed {
            return Reply::error(req, 500, "The configuration could not be removed");
        }
        if shared {
            // A configuration user keeps their login to save a replacement.
            self.store.touch_auth(&key);
        } else if self.store.clear_auth(&key) == Cleared::Failed {
            let msg = "The configuration was removed, but its authentication could not be removed";
            return Reply::error(req, 500, msg);
        }
        match result {
            Cleared::Nothing | Cleared::Failed => Reply::empty(204),
            Cleared::Removed => Reply::ok(req, "Successfully removed configuration"),
        }
    }

    fn move_config(&self, req: &Req, key: Option<&str>) -> Reply {
        if let Some(r) = self.stateful_disabled(req) {
            return r;
        }
        let key = match resolve_key(req, key) {
            Ok(k) => k,
            Err(r) => return r,
        };
        if !self.key_ok(req, &key, false) {
            return self.key_denied(req, &key);
        }
        if !self.config_lock_allows(req, None) {
            return Reply::error(req, 403, DENIED);
        }
        let (from, to) = if req.json_payload() {
            let m = match payload::json_object(req) {
                Ok(m) => m,
                Err(r) => return r,
            };
            match m.get("to").and_then(Value::as_str) {
                Some(to) if valid_key(to) && to != key => (key.clone(), to.to_string()),
                _ => {
                    let msg = "A valid destination (to), different from the source, is required";
                    return Reply::field_error(req, 400, msg, "to");
                }
            }
        } else {
            let (m, _, _) = payload::form_fields(req);
            let field = |f: &str| m.get(f).and_then(Value::as_str).map(str::trim).unwrap_or("").to_string();
            let (from, to) = (field("from"), field("to"));
            for (name, v) in [("from", &from), ("to", &to)] {
                if v.is_empty() {
                    return Reply::field_error(req, 400, "This field is required.", name);
                }
                if !valid_key(v) {
                    return Reply::field_error(req, 400, "Enter a valid value.", name);
                }
            }
            if from == to {
                return Reply::error(req, 400, "The destination configuration ID must differ from the source");
            }
            (from, to)
        };
        if from != key && !self.key_ok(req, &from, false) {
            return self.key_denied(req, &from);
        }
        if !self.s.config_lock && !self.store.writable() {
            return Reply::error(req, 424, "The configuration store is not currently writable");
        }
        match self.store.move_key(&from, &to) {
            Moved::NotFound => Reply::error(req, 404, "There was no configuration to move"),
            Moved::Conflict => Reply::field_error(req, 409, "A configuration already exists at the destination", "to"),
            Moved::Failed => Reply::error(req, 500, "The configuration could not be moved"),
            Moved::Done => Reply::ok(req, "Successfully moved configuration"),
        }
    }

    async fn json_urls(&self, req: &Req, key: Option<&str>) -> Reply {
        if let Some(r) = self.stateful_disabled(req) {
            return r;
        }
        let key = match resolve_key(req, key) {
            Ok(k) => k,
            Err(r) => return r,
        };
        if !self.key_ok(req, &key, false) {
            return self.key_denied(req, &key);
        }
        if !self.config_lock_allows(req, Some(&key)) {
            return Reply::error(req, 403, DENIED);
        }
        let privacy = parse_bool(req.query("privacy"), false);
        let show_defaults = self.s.allow_templates && !privacy && !self.s.config_lock;
        let (content, format) = match self.store.get(&key) {
            Err(()) => {
                return Reply::json(500, &json!({"tags": [], "urls": [], "error": "There was no configuration found"}));
            }
            Ok(None) => return Reply::empty(204),
            Ok(Some(c)) => c,
        };
        let cfg = Config::from_text_async(&content, Some(format), self.transport.as_ref(), &self.config_options())
            .await
            .unwrap_or_default();
        let defaults = if show_defaults { template_defaults(&content, format) } else { Default::default() };
        let filter = TagFilter::parse(req.query("tag").filter(|t| !t.trim().is_empty()).unwrap_or("all"));
        let mut all_tags = std::collections::BTreeSet::new();
        let mut urls = Vec::new();
        for s in cfg.services.iter().filter(|s| filter.matches(s.tags())) {
            let (url, def, id, template_names) = match s {
                ConfigService::Ready(t) => {
                    (t.url().to_string(), t.service(), t.url_id(&mercurio::Asset::default()), Vec::new())
                }
                ConfigService::Pending(p) => (p.url(), p.service(), None, p.template_names().to_vec()),
            };
            let (name, service_id) = (def.name, def.id);
            let mut names: Vec<String> = s.tags().iter().map(|t| t.name.clone()).collect();
            names.sort();
            names.dedup();
            all_tags.extend(names.iter().cloned());
            let mut tags: Vec<&mercurio::Tag> = s.tags().iter().collect();
            tags.sort_by(|a, b| (&a.name, a.priority).cmp(&(&b.name, b.priority)));
            let details: Vec<Value> = tags
                .iter()
                .map(|t| {
                    let token =
                        if t.has_priority || t.priority > 0 { format!("{}:{}", t.priority, t.name) } else { t.name.clone() };
                    json!({"name": t.name, "priority": t.priority, "token": token, "exact": format!("{}:{}", t.priority, t.name)})
                })
                .collect();
            let query = url_query(&url);
            let retry: u64 = query.iter().find(|(k, _)| k == "retry").and_then(|(_, v)| v.parse().ok()).unwrap_or(0);
            let optional = query.iter().any(|(k, v)| k == "optional" && parse_bool(Some(v), false));
            let template: Map<String, Value> = if self.s.allow_templates {
                template_names
                    .iter()
                    .map(|n| (n.clone(), defaults.get(n).map(|d| Value::String(d.clone())).unwrap_or(Value::Null)))
                    .collect()
            } else {
                Map::new()
            };
            urls.push(json!({
                "id": id,
                "service_name": name,
                "enabled": self.s.services.enabled(service_id),
                "url": if privacy { mercurio::plan::redact_url(&url) } else { url.clone() },
                "retry": retry,
                "optional": optional,
                "tags": names,
                "tag_details": details,
                "template": template,
            }));
        }
        Reply::json(200, &json!({"tags": all_tags, "urls": urls}))
    }

    async fn notify_route(&self, req: &Req, key: &str) -> Reply {
        if let Some(r) = self.stateful_disabled(req) {
            return r;
        }
        let key = match req.x_header("Config-ID") {
            Some(h) if valid_key(h) => h.to_string(),
            Some(_) => return Reply::error(req, 400, INVALID_KEY_HEADER),
            None => key.to_string(),
        };
        let content = match payload::load_notify(req, false, Some(&key), self.s.mapping_depth) {
            Ok(c) => c,
            Err(r) => return r,
        };
        self.notify_stored(req, &key, content).await
    }

    async fn notify_stored(&self, req: &Req, key: &str, mut content: Content) -> Reply {
        if !self.key_ok(req, key, true) {
            return self.key_denied(req, key);
        }
        // Public and locked callers may only send to a tag they know.
        let tag_only = req.role.get() != Role::Admin && self.configuration_is_locked(Some(key));
        let tag = payload::notify_tag(req, &content);
        if tag_only && !tag.as_ref().is_ok_and(payload::tag_is_specific) {
            return Reply::error(req, 400, "A specific tag other than 'all' is required for this configuration");
        }
        let Ok(tag) = tag else {
            return Reply::error(req, 400, "Unsupported characters found in tag definition");
        };
        let attachments = match self.attachments(req, &mut content).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        query_overrides(req, &mut content);
        let message = match self.message(req, &content, attachments) {
            Ok(m) => m,
            Err(r) => return r,
        };
        let (config, format) = match self.store.get(key) {
            Ok(Some(c)) => c,
            Ok(None) => return Reply::error(req, 404, "There was no configuration found"),
            Err(()) => return Reply::error(req, 500, "An error occurred accessing configuration"),
        };
        let recursion = match self.recursion(req) {
            Ok(n) => n,
            Err(r) => return r,
        };
        let asset = self.request_asset(req, true, recursion);
        let mut m = AsyncMercurio::with_transport(self.transport.clone())
            .config_options(self.config_options())
            .asset(asset.clone());
        match self.load(&config, Some(format)).await {
            Ok(cfg) => {
                m.add_loaded(cfg);
            }
            Err(e) => log::warn!("NOTIFY - {} - could not load the configuration of KEY {key}: {e}", req.remote),
        }
        // Without a tag only untagged entries are notified.
        let filter = tag.as_ref().map(payload::tag_filter).unwrap_or_else(TagFilter::untagged);
        let vars = content.template.take().unwrap_or_default();
        let transport = self.transport.clone();
        let job = notify::Job { notifier: m, message, filter, vars, key: Some(key.to_string()), transport, asset };
        self.deliver(req, job).await
    }

    async fn notify_stateless(&self, req: &Req) -> Reply {
        let key = match req.x_header("Config-ID") {
            Some(h) if valid_key(h) => Some(h.to_string()),
            Some(_) => return Reply::error(req, 400, INVALID_KEY_HEADER),
            None => None,
        };
        let mut content = match payload::load_notify(req, true, None, self.s.mapping_depth) {
            Ok(c) => c,
            Err(r) => return r,
        };
        let has_urls = content.fields.get("urls").is_some_and(|v| match v {
            Value::String(s) => !s.is_empty(),
            Value::Array(a) => !a.is_empty(),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_) => false,
        });
        if let Some(key) = key.as_deref().filter(|_| !has_urls) {
            if let Some(r) = self.stateful_disabled(req) {
                return r;
            }
            return self.notify_stored(req, key, content).await;
        }
        if !self.s.stateless_enabled {
            log::warn!("STATELESS NOTIFY - {} - Stateless Mode Disabled - Request Denied", req.remote);
            return Reply::error(req, 403, DENIED);
        }
        if self.s.auth.required && req.role.get() != Role::Admin {
            let scope = key.as_deref().unwrap_or("stateless");
            if key.is_none() || !self.key_ok(req, scope, false) {
                return self.key_denied(req, scope);
            }
            if self.key_state(scope).access != store::ACCESS_USER {
                return Reply::error(req, 403, "This configuration does not permit stateless notifications");
            }
        }
        let urls: Vec<String> = match content.fields.get("urls") {
            Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
            Some(Value::Array(a)) if !a.is_empty() => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
            _ => self.s.stateless_urls.iter().cloned().collect(),
        };
        let Ok(tag) = payload::notify_tag(req, &content) else {
            return Reply::error(req, 400, "Unsupported characters found in tag definition");
        };
        query_overrides(req, &mut content);
        let attachments = match self.attachments(req, &mut content).await {
            Ok(a) => a,
            Err(r) => return r,
        };
        let message = match self.message(req, &content, attachments) {
            Ok(m) => m,
            Err(r) => return r,
        };
        let recursion = match self.recursion(req) {
            Ok(n) => n,
            Err(r) => return r,
        };
        let asset = self.request_asset(req, self.s.stateless_storage, recursion);
        let mut m = AsyncMercurio::with_transport(self.transport.clone()).asset(asset.clone());
        for u in mercurio::parse::parse_urls(urls.iter().map(String::as_str), true) {
            match mercurio::parse(&u) {
                Ok(t) if self.s.services.enabled(t.service().id) => {
                    m.push(t);
                }
                Ok(t) => log::warn!(
                    "skipping {}: the {} service is disabled",
                    mercurio::plan::redact_url(&u),
                    t.service().name
                ),
                Err(e) => log::warn!("skipping {}: {e}", mercurio::plan::redact_url(&u)),
            }
        }
        if m.is_empty() {
            log::warn!("NOTIFY - {} - No valid URLs provided", req.remote);
            return Reply::error(req, 400, "There was no valid URLs provided to notify");
        }
        let filter = tag.as_ref().map(payload::tag_filter).unwrap_or_else(TagFilter::all);
        let vars = content.template.take().unwrap_or_default();
        let transport = self.transport.clone();
        let job = notify::Job { notifier: m, message, filter, vars, key: None, transport, asset };
        self.deliver(req, job).await
    }

    /// The asset for a send, with persistent storage when enabled.
    fn asset(&self, persistent: bool) -> mercurio::Asset {
        let asset = mercurio::Asset { http_redirects: self.s.http_redirects, ..mercurio::Asset::default() };
        match (&self.s.storage, persistent) {
            (Some(dir), true) => asset.with_storage(dir.clone()),
            (Some(_) | None, _) => asset,
        }
    }

    /// The asset for a send, carrying the caller's `X-Apprise-ID` and recursion count.
    fn request_asset(&self, req: &Req, persistent: bool, recursion: u32) -> mercurio::Asset {
        let uid = req.x_header("ID").map(str::trim).filter(|u| !u.is_empty()).map(str::to_string);
        mercurio::Asset { uid, recursion, ..self.asset(persistent) }
    }

    /// The requested log detail; stored configurations limit it to `INFO` unless the caller is the administrator or has `user` access.
    fn log_level(&self, req: &Req, key: Option<&str>) -> u8 {
        let level = req.x_header("Log-Level").and_then(notify::level_value).unwrap_or(self.s.log_level);
        let Some(key) = key else { return level };
        if level >= 20 || !self.s.auth.required {
            return level;
        }
        match req.role.get() {
            Role::Admin | Role::Open => level,
            Role::User if self.key_state(key).access == store::ACCESS_USER => level,
            Role::User | Role::Anonymous => 20,
        }
    }

    async fn deliver(&self, req: &Req, job: notify::Job) -> Reply {
        let level = self.log_level(req, job.key.as_deref());
        let wants_stream = req.header("accept").is_some_and(|a| {
            a.split(',').any(|m| m.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("text/event-stream"))
        }) || parse_bool(req.query("stream"), false);
        if wants_stream {
            let Some(slot) = self.streams.try_admit() else {
                log::warn!("NOTIFY - {} - Live notification stream rejected; capacity reached", req.remote);
                let msg = "The server is temporarily unable to start a new live notification stream";
                return Reply::error(req, 503, msg).header("Retry-After", "15");
            };
            let (metrics, webhook, transport, remote) =
                (self.metrics.clone(), self.s.webhook.clone(), self.transport.clone(), req.remote.clone());
            let done: notify::OnDone = Box::new(move |report, logs| {
                Box::pin(async move {
                    metrics.notified(report.status().as_str());
                    if let Some(url) = webhook {
                        filters::send_webhook(transport.as_ref(), &url, &remote, report.is_success(), &logs).await;
                    }
                })
            });
            return notify::stream(job, level, slot, Duration::from_secs(15), done);
        }
        let (reply, report, logs) = notify::deliver(req, &job, level).await;
        self.metrics.notified(report.status().as_str());
        if let Some(url) = &self.s.webhook {
            filters::send_webhook(self.transport.as_ref(), url, &req.remote, report.is_success(), &logs).await;
        }
        reply
    }

    async fn attachments(&self, req: &Req, content: &mut Content) -> Result<Vec<mercurio::Attachment>, Reply> {
        let allowed = |u: &str| self.s.attach_urls.allowed(u);
        let rules = payload::AttachRules { size: self.s.attach_size, max: self.s.max_attachments, allowed: &allowed };
        payload::attachments(content, &rules, self.transport.as_ref()).await.map_err(|e| {
            log::warn!("NOTIFY - {} - Bad attachment: {e}", req.remote);
            Reply::error(req, 400, "Bad Attachment")
        })
    }

    /// Body, title, type and format checks; the message to send.
    fn message(&self, req: &Req, c: &Content, attachments: Vec<mercurio::Attachment>) -> Result<Message, Reply> {
        let body = c.str("body").unwrap_or_default();
        let kind = c.str("type").unwrap_or("info");
        if (body.is_empty() && attachments.is_empty()) || !["info", "success", "warning", "failure"].contains(&kind) {
            log::warn!("NOTIFY - {} - Payload lacks minimum requirements", req.remote);
            return Err(Reply::error(req, 400, "Payload lacks minimum requirements"));
        }
        let format = if c.fields.contains_key("format") {
            match c.fields.get("format").and_then(Value::as_str).map(str::trim).filter(|f| !f.is_empty()) {
                None => None,
                Some(f) => match ["text", "markdown", "html"].contains(&f).then(|| NotifyFormat::parse(f)).flatten() {
                    Some(f) => Some(f),
                    None => return Err(Reply::error(req, 400, "An invalid body input format was specified")),
                },
            }
        } else {
            self.s.default_format
        };
        let mut msg = Message::new(body).title(c.str("title").unwrap_or_default());
        msg.kind = NotifyType::parse(kind).unwrap_or_default();
        msg.format = format;
        msg.attachments = attachments;
        Ok(msg)
    }

    /// The `Recursion-Count` header against `APPRISE_RECURSION_MAX`.
    fn recursion(&self, req: &Req) -> Result<u32, Reply> {
        let Some(raw) = req.x_header("Recursion-Count") else { return Ok(0) };
        match raw.parse::<i64>() {
            Ok(n) if n >= 0 && n <= i64::from(self.s.recursion_max) => Ok(n as u32),
            Ok(n) if n >= 0 => {
                log::warn!("NOTIFY - {} - Recursion limit reached ({n} > {})", req.remote, self.s.recursion_max);
                Err(Reply::error(req, 406, "The recursion limit has been reached"))
            }
            _ => Err(Reply::error(req, 400, "An invalid recursion value was specified")),
        }
    }
}

/// `?format=`, `?type=` and `?title=` fill fields the payload left empty.
fn query_overrides(req: &Req, c: &mut Content) {
    for name in ["format", "type", "title"] {
        if c.str(name).is_none()
            && let Some(v) = req.query(name)
        {
            c.fields.insert(name.into(), Value::String(v.to_string()));
        }
    }
}

/// A YAML document that would be discarded as a whole (syntax error, not a mapping or a broken `template:` section).
fn yaml_refused(content: &str) -> bool {
    use mercurio::config::yaml::{Yaml, parse};
    match parse(content) {
        Err(_) => true,
        Ok(Yaml::Null) => false,
        Ok(doc) => {
            doc.as_map().is_none()
                || doc.get("template").is_some_and(|t| mercurio::config::template::TemplateSchema::parse(t).is_err())
        }
    }
}

/// Template defaults declared in a YAML configuration.
fn template_defaults(content: &str, format: ConfigFormat) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    if format != ConfigFormat::Yaml {
        return out;
    }
    let Ok(doc) = mercurio::config::yaml::parse(content) else { return out };
    if let Some(Ok(schema)) = doc.get("template").map(mercurio::config::template::TemplateSchema::parse) {
        for (name, default) in schema.variables {
            if let Some(d) = default {
                out.insert(name, d);
            }
        }
    }
    out
}

fn url_query(url: &str) -> Vec<(String, String)> {
    url.split_once('?').map(|(_, q)| http::form_pairs(q)).unwrap_or_default()
}

/// `YYYY-MM-DDTHH:MM:SS` (UTC).
fn iso_seconds(t: SystemTime) -> String {
    let secs = t.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (y, mo, d, h, mi, s) = mercurio::crypto::utc_parts(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}")
}
