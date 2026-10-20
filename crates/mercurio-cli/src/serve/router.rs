//! The HTTP API as an axum app: the route table (with its `--help` tables), the auth gate, logging and metrics, and the load, timeout and body limits around them.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, State};
use axum::response::IntoResponse;
use mercurio::TokioTransport;

use super::auth::Role;
use super::http::{self, Reply, Req};
use super::settings::Settings;
use super::store::ConfigStore;
use super::{MISSING_KEY, Server, auth, metrics, notify, valid_key};

/// Requests in progress at once; more get 503 + `Retry-After`. Above the library's 128 sends at once, so a burst queues for a send slot instead of being refused.
const MAX_CONNECTIONS: usize = 512;
/// The HTTP API: paths, methods, purpose. [`router`] implements it; the `routes_match_the_router` test checks every row against it.
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
/// The HTTP API as one service: [`router`] behind the panic, load, timeout and body limits, with [`observe`] logging each request.
pub(super) fn app(s: Settings) -> tower_http::normalize_path::NormalizePath<axum::Router> {
    let store = ConfigStore::new(s.config_dir.clone(), s.stateful, s.secret.clone());
    let streams = notify::StreamSlots::new(s.stream_slots);
    let server = Arc::new(Server {
        transport: Arc::new(TokioTransport::new()),
        s,
        store,
        metrics: Arc::new(metrics::Metrics::default()),
        verifier: auth::Verifier::default(),
        streams,
    });
    let limit = http::body_limit(server.s.attach_size);
    let bodies = Arc::new(tokio::sync::Semaphore::new(BODY_BUDGET.max(limit) / BUDGET_UNIT));
    let layers = tower::ServiceBuilder::new()
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        .layer(axum::error_handling::HandleErrorLayer::new(busy))
        .load_shed()
        .layer(tower::limit::GlobalConcurrencyLimitLayer::new(MAX_CONNECTIONS))
        .layer(axum::middleware::from_fn_with_state(server.clone(), observe))
        .layer(axum::middleware::from_fn_with_state((bodies, limit), body_budget))
        .layer(tower_http::timeout::RequestBodyTimeoutLayer::new(http::IO_TIMEOUT))
        .layer(axum::extract::DefaultBodyLimit::max(limit));
    let app = router(&server).layer(layers).with_state(server);
    // `/notify/` is `/notify`.
    tower_http::normalize_path::NormalizePath::trim_trailing_slash(app)
}
/// Bytes of request bodies read at once; a request that does not fit gets `503` instead of more memory.
const BODY_BUDGET: usize = 256 * 1024 * 1024;
/// What a body without a `Content-Length` (chunked) is charged.
const UNSIZED_BODY: usize = 1024 * 1024;
/// The budget's unit, so that it fits the semaphore's `u32` permits.
const BUDGET_UNIT: usize = 1024;

/// Charges the request's `Content-Length` (or [`UNSIZED_BODY`]) to the budget before its body is read, and keeps the charge until the answer is built.
async fn body_budget(
    State((bodies, limit)): State<(Arc<tokio::sync::Semaphore>, usize)>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let length = request.headers().get("content-length").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok());
    let units = u32::try_from(length.unwrap_or(UNSIZED_BODY).min(limit).div_ceil(BUDGET_UNIT)).unwrap_or(u32::MAX);
    let Ok(_charge) = bodies.try_acquire_many_owned(units) else { return busy_reply().into_response() };
    next.run(request).await
}

/// A request beyond [`MAX_CONNECTIONS`] in progress.
async fn busy(_: tower::BoxError) -> Reply {
    busy_reply()
}

fn busy_reply() -> Reply {
    Reply::text(503, "busy").header("Retry-After", "1").header("Connection", "close")
}
/// Who may reach a route before its handler checks the key, when Basic Auth is required.
#[derive(Clone, Copy)]
enum Gate {
    /// The key is in the path; the handler checks it.
    Key,
    /// The key is in the `X-Apprise-Config-ID` header, else only the administrator.
    Header,
    /// Only the administrator.
    Admin,
}
/// The view that answered: the `view` label of the metrics (apprise-api's Django view names).
#[derive(Clone, Copy)]
struct View(&'static str);
type St = State<Arc<Server>>;
/// A valid Config ID from the path; `404` otherwise.
struct Key(String);
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Key {
    type Rejection = Reply;

    async fn from_request_parts(parts: &mut axum::http::request::Parts, state: &S) -> Result<Key, Reply> {
        match axum::extract::Path::<String>::from_request_parts(parts, state).await {
            Ok(axum::extract::Path(k)) if valid_key(&k) => Ok(Key(k)),
            _ => Err(Reply::error_as(json_client(&parts.headers), 404, "Not Found")),
        }
    }
}
/// [`http::wants_json`] for a request not read yet.
fn json_client(headers: &axum::http::HeaderMap) -> bool {
    let header = |name| headers.get(name).and_then(|v| v.to_str().ok());
    http::wants_json(header("accept"), header("content-type").unwrap_or(""))
}
/// The HTTP API (the [`ROUTES`] table): each route with its view name and [`Gate`].
fn router(server: &Arc<Server>) -> axum::Router<Arc<Server>> {
    use axum::routing::{MethodRouter, get, post};
    let at = |view: &'static str, gate: Gate, route: MethodRouter<Arc<Server>>| {
        let server = server.clone();
        route.route_layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                authorize(server.clone(), view, gate, request, next)
            },
        ))
    };
    let missing = |req: Req| async move { Reply::error(&req, 400, MISSING_KEY) };
    let auth = |State(s): St, req: Req| async move { s.auth_view(&req, None).await };
    let auth_key = |State(s): St, Key(k): Key, req: Req| async move { s.auth_view(&req, Some(&k)).await };
    axum::Router::new()
        .route(
            "/status",
            at("health", Gate::Header, get(|State(s): St, req: Req| async move { s.status(&req, None).await })),
        )
        .route("/status/@", at("health_current", Gate::Admin, get(missing)))
        .route(
            "/status/{key}",
            at(
                "health_key",
                Gate::Key,
                get(|State(s): St, Key(k): Key, req: Req| async move { s.status(&req, Some(&k)).await }),
            ),
        )
        .route(
            "/details",
            at("details", Gate::Header, get(|State(s): St, req: Req| async move { s.details(&req).await })),
        )
        .route(
            "/metrics",
            at("prometheus-django-metrics", Gate::Admin, get(|State(s): St| async move { s.metrics_page() })),
        )
        .route("/cfg", at("config_list", Gate::Admin, get(|State(s): St, req: Req| async move { s.list(&req).await })))
        .route("/cfg/@", at("config_current", Gate::Admin, get(missing).post(missing)))
        .route(
            "/cfg/{key}",
            at(
                "config",
                Gate::Key,
                post(|State(s): St, Key(k): Key, req: Req| async move { s.get_config(&req, Some(&k)).await }),
            ),
        )
        .route(
            "/get",
            at(
                "get_by_header",
                Gate::Header,
                post(|State(s): St, req: Req| async move { s.get_config(&req, None).await }),
            ),
        )
        .route(
            "/get/{key}",
            at(
                "get",
                Gate::Key,
                post(|State(s): St, Key(k): Key, req: Req| async move { s.get_config(&req, Some(&k)).await }),
            ),
        )
        .route(
            "/add",
            at("add_by_header", Gate::Header, post(|State(s): St, req: Req| async move { s.add(&req, None).await })),
        )
        .route(
            "/add/{key}",
            at(
                "add",
                Gate::Key,
                post(|State(s): St, Key(k): Key, req: Req| async move { s.add(&req, Some(&k)).await }),
            ),
        )
        .route(
            "/del",
            at("del_by_header", Gate::Header, post(|State(s): St, req: Req| async move { s.del(&req, None).await })),
        )
        .route(
            "/del/{key}",
            at(
                "del",
                Gate::Key,
                post(|State(s): St, Key(k): Key, req: Req| async move { s.del(&req, Some(&k)).await }),
            ),
        )
        .route(
            "/move",
            at(
                "move_by_header",
                Gate::Header,
                post(|State(s): St, req: Req| async move { s.move_config(&req, None).await }),
            ),
        )
        .route(
            "/move/{key}",
            at(
                "move",
                Gate::Key,
                post(|State(s): St, Key(k): Key, req: Req| async move { s.move_config(&req, Some(&k)).await }),
            ),
        )
        .route("/auth", at("auth_by_header", Gate::Header, get(auth).post(auth).delete(auth)))
        .route("/auth/@", at("auth_current", Gate::Admin, get(missing).post(missing).delete(missing)))
        .route("/auth/{key}", at("auth", Gate::Key, get(auth_key).post(auth_key).delete(auth_key)))
        .route(
            "/notify",
            at("s_notify", Gate::Header, post(|State(s): St, req: Req| async move { s.notify_stateless(&req).await })),
        )
        .route(
            "/notify/{key}",
            at(
                "notify",
                Gate::Key,
                post(|State(s): St, Key(k): Key, req: Req| async move { s.notify_route(&req, &k).await }),
            ),
        )
        .route(
            "/json/urls",
            at(
                "json_urls_by_header",
                Gate::Header,
                get(|State(s): St, req: Req| async move { s.json_urls(&req, None).await }),
            ),
        )
        .route(
            "/json/urls/{key}",
            at(
                "json_urls",
                Gate::Key,
                get(|State(s): St, Key(k): Key, req: Req| async move { s.json_urls(&req, Some(&k)).await }),
            ),
        )
}
/// Proves who is calling (Basic Auth), for [`Req::role`], and answers `401` to anonymous callers the route's [`Gate`] does not admit.
async fn authorize(
    server: Arc<Server>,
    view: &'static str,
    gate: Gate,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let auth = &server.s.auth;
    let (role, admitted) = {
        // `Request` is not `Sync`: no reference to it may live across the `await` below.
        let header = |name| request.headers().get(name).map(|v| http::decode_header(v.as_bytes()).trim().to_string());
        let role = if !auth.required {
            Role::Open
        } else if auth.is_admin(header("authorization").and_then(|h| http::basic_auth(&h)).as_ref()) {
            Role::Admin
        } else {
            Role::Anonymous
        };
        let admitted = match gate {
            Gate::Key => true,
            Gate::Header => header("x-apprise-config-id").is_some_and(|h| !h.is_empty()),
            Gate::Admin => false,
        };
        (role, admitted)
    };
    let mut response = if role == Role::Anonymous && !admitted {
        let realm = format!("Basic realm=\"{}\"", auth.realm);
        Reply::error_as(json_client(request.headers()), 401, "Access Denied")
            .header("WWW-Authenticate", &realm)
            .into_response()
    } else {
        request.extensions_mut().insert(role);
        next.run(request).await
    };
    response.extensions_mut().insert(View(view));
    response
}
/// Counts every request and logs it as one event (see `docs/book/src/server.md`); a `404` or `405` counts as `<unnamed view>`.
async fn observe(
    State(server): St,
    ConnectInfo(remote): ConnectInfo<std::net::SocketAddr>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let started = Instant::now();
    let event = http::RequestEvent::shared();
    request.extensions_mut().insert(event.clone());
    let method = request.method().as_str().to_ascii_uppercase();
    let route = request.extensions().get::<axum::extract::MatchedPath>().map(|p| p.as_str().to_string());
    let (apprise_id, recursion, bytes_in) = {
        let header = |name| request.headers().get(name).map(|v| http::decode_header(v.as_bytes()).trim().to_string());
        let bytes_in = header("content-length").and_then(|v| v.parse::<u64>().ok());
        (header("x-apprise-id"), header("x-apprise-recursion-count"), bytes_in)
    };
    let response = next.run(request).await;
    let view = response.extensions().get::<View>().map_or("<unnamed view>", |v| v.0);
    let status = response.status().as_u16();
    let elapsed = started.elapsed();
    let bytes_out = axum::body::HttpBody::size_hint(response.body()).exact();
    server.metrics.record(&method, view, status, elapsed, bytes_in.unwrap_or(0), bytes_out);
    // As apprise-api's nginx: a passing health check or metrics scrape is not logged (the container checks `/status` every 30 s).
    let routine = status < 400 && route.as_deref().is_some_and(|r| r.starts_with("/status") || r == "/metrics");
    if !routine {
        let e = event.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        tracing::info!(
            target: "request",
            method,
            route,
            status,
            duration_ms = %format_args!("{:.3}", elapsed.as_secs_f64() * 1000.0),
            remote = %remote.ip(),
            key = e.key,
            apprise_id,
            recursion,
            bytes_in,
            services = e.services,
            failed = e.failed,
            stream = e.stream.then_some(true),
            error = e.error,
            detail = (!e.detail.is_empty()).then(|| e.detail.join("; ")),
        );
    }
    response
}
