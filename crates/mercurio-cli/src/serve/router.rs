//! The HTTP API: the route table (with its `--help` tables), the hyper service with its load, body and time limits,
//! and the generated server's hooks: who is calling, error answers, logs and metrics. The handlers are in `api`.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use futures_util::FutureExt as _;
use hyper::body::{Bytes, Frame};
use mercurio::transport::TokioTransport;

use super::api;
use super::auth::Role;
use super::call::{Caller, Fault, media_type, wants_json};
use super::settings::Settings;
use super::store::ConfigStore;
use super::{Server, auth, metrics};
use api::Message as _;

/// The HTTP API: paths, methods, purpose. `openapi.yaml` describes it; the `routes_match_the_router` test checks every row against it.
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

/// A request body of any kind, as the generated server reads it.
type AnyBody = http_body_util::combinators::BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;
/// The generated server, with the hooks below, as one function.
type Handle = dyn Fn(hyper::Request<AnyBody>) -> futures_util::future::BoxFuture<'static, api::Response> + Send + Sync;

/// The HTTP API with its shared limits: [`App::call`] answers one request.
#[derive(Clone)]
pub(crate) struct App {
    api: Arc<Api>,
    handle: Arc<Handle>,
    /// Requests in progress (`max_requests`); one more gets `503`.
    requests: Arc<tokio::sync::Semaphore>,
    /// [`BODY_BUDGET`] in [`BUDGET_UNIT`]s.
    bodies: Arc<tokio::sync::Semaphore>,
}

/// The generated server's implementation: the business is [`Server`]'s.
pub(crate) struct Api(pub(super) Arc<Server>);

pub(super) fn app(s: Settings) -> App {
    let store = ConfigStore::new(s.config_dir.clone(), s.stateful, s.secret.clone());
    // Live streams admitted at once (`APPRISE_STREAM_WORKER_COUNT` + `APPRISE_STREAM_QUEUE_SIZE`).
    let streams = Arc::new(tokio::sync::Semaphore::new(s.stream_slots.min(tokio::sync::Semaphore::MAX_PERMITS)));
    let requests = Arc::new(tokio::sync::Semaphore::new(s.max_requests.min(tokio::sync::Semaphore::MAX_PERMITS)));
    let limit = body_limit(s.attach_size);
    let server = Arc::new(Server {
        transport: Arc::new(TokioTransport::new()),
        s,
        store,
        metrics: Arc::new(metrics::Metrics::default()),
        verifier: auth::Verifier::default(),
        streams,
        details_cache: Default::default(),
    });
    let bodies = Arc::new(tokio::sync::Semaphore::new(BODY_BUDGET.max(limit) / BUDGET_UNIT));
    let api = Arc::new(Api(Arc::clone(&server)));
    let (find, errors, events) = (Arc::clone(&server), Arc::clone(&server), server);
    let service = api::server::Server::new(Arc::clone(&api))
        .max_body_bytes(limit)
        .authenticate(move |req: &api::Request| std::future::ready(authorize(&find, req)))
        .error_response(move |rejection| error_response(&errors, rejection))
        .on_event(move |event| on_event(&events, event))
        .into_service();
    // `ApiService` is always ready: no `poll_ready` before `call`.
    let handle: Arc<Handle> = Arc::new(move |request| {
        let answer = api::Service::call(&mut service.clone(), request);
        Box::pin(async move { answer.await.unwrap_or_else(|never| match never {}) })
    });
    App { api, handle, requests, bodies }
}

/// Largest request body read: one attachment of `attach_size` bytes plus the other fields, and never less than
/// [`MIN_BODY`].
pub(super) fn body_limit(attach_size: u64) -> usize {
    usize::try_from(attach_size).unwrap_or(usize::MAX).saturating_add(FIELDS_ALLOWANCE).max(MIN_BODY)
}
/// Room a request body keeps for its fields beside an upload.
const FIELDS_ALLOWANCE: usize = 1024 * 1024;
/// The body limit when attachments are off or small.
const MIN_BODY: usize = 8 * 1024 * 1024;
/// Bytes of request bodies read at once; a request that does not fit gets `503` instead of more memory.
const BODY_BUDGET: usize = 256 * 1024 * 1024;
/// What a body without a `Content-Length` (chunked) is charged.
const UNSIZED_BODY: usize = 1024 * 1024;
/// The budget's unit, so that it fits the semaphore's `u32` permits.
const BUDGET_UNIT: usize = 1024;

impl App {
    /// Answer one request from `remote`: within the request and body budgets, `/notify/` as `/notify`, the body read
    /// within the I/O timeout.
    pub(crate) async fn call<B>(
        &self,
        request: hyper::Request<B>,
        remote: SocketAddr,
    ) -> Result<hyper::Response<api::Body>, Infallible>
    where
        B: hyper::body::Body<Data = Bytes> + Send + Sync + Unpin + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let Ok(_slot) = self.requests.clone().try_acquire_owned() else { return Ok(busy()) };
        let length = request.headers().get("content-length").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok());
        let units = u32::try_from(
            length.unwrap_or(UNSIZED_BODY).min(body_limit(self.api.0.s.attach_size)).div_ceil(BUDGET_UNIT),
        )
        .unwrap_or(u32::MAX);
        let Ok(_charge) = self.bodies.clone().try_acquire_many_owned(units) else { return Ok(busy()) };
        let (mut parts, body) = request.into_parts();
        parts.uri = without_trailing_slash(&parts.uri);
        parts.extensions.insert(remote);
        let body = ReadTimeout { body, timeout: Box::pin(tokio::time::sleep(self.api.0.s.io_timeout)) };
        let request = hyper::Request::from_parts(parts, AnyBody::new(body));
        let answer = std::panic::AssertUnwindSafe((self.handle)(request)).catch_unwind().await;
        Ok(answer.unwrap_or_else(|_| status(500)))
    }
}

/// apprise-api's routes end in `/?`: `/notify/` is `/notify`.
fn without_trailing_slash(uri: &hyper::Uri) -> hyper::Uri {
    let path = uri.path();
    if path.len() < 2 || !path.ends_with('/') {
        return uri.clone();
    }
    let trimmed = path.trim_end_matches('/');
    let target = match uri.query() {
        Some(q) => format!("{trimmed}?{q}"),
        None => trimmed.to_owned(),
    };
    target.parse().unwrap_or_else(|_| uri.clone())
}

/// An empty answer.
fn status(code: u16) -> api::Response {
    let mut r = new_response(code);
    set_header(&mut r, "Connection", "close");
    r
}

/// A request beyond `max_requests` or the body budget.
fn busy() -> api::Response {
    let mut r = new_response(503);
    r.set_body("text/plain; charset=utf-8", b"busy".to_vec());
    set_header(&mut r, "Retry-After", "1");
    set_header(&mut r, "Connection", "close");
    r
}

/// An empty answer with this status.
fn new_response(code: u16) -> api::Response {
    let mut r = api::Response::new(api::Body::default());
    *r.status_mut() = api::http::StatusCode::from_u16(code).unwrap_or(api::http::StatusCode::INTERNAL_SERVER_ERROR);
    r
}

/// Sets a header whose name and value are valid by construction.
fn set_header(r: &mut api::Response, name: &str, value: impl Into<std::borrow::Cow<'static, str>>) {
    if let Err(e) = r.set_header(name, value) {
        log::debug!("header {name}: {e}");
    }
}

/// A request body that fails once the I/O timeout passes before it is read.
struct ReadTimeout<B> {
    body: B,
    timeout: Pin<Box<tokio::time::Sleep>>,
}

impl<B> hyper::body::Body for ReadTimeout<B>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if this.timeout.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err("the request body was not read in time".into())));
        }
        Pin::new(&mut this.body).poll_frame(cx).map_err(Into::into)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}

/// Who may reach an operation before its handler checks the key, when Basic Auth is required.
#[derive(Clone, Copy)]
enum Gate {
    /// The key is in the path; the handler checks it.
    Key,
    /// The key is in the `X-Apprise-Config-ID` header, else only the administrator.
    Header,
    /// Only the administrator.
    Admin,
}

/// An operation's view name in the metrics (apprise-api's Django view names) and its [`Gate`].
fn operation(name: &str) -> (&'static str, Gate) {
    match name {
        "status" => ("health", Gate::Header),
        "status_key" => ("health_key", Gate::Key),
        "status_current" => ("health_current", Gate::Admin),
        "details" => ("details", Gate::Header),
        "metrics" => ("prometheus-django-metrics", Gate::Admin),
        "notify_stateless" => ("s_notify", Gate::Header),
        "notify" => ("notify", Gate::Key),
        "list_configs" => ("config_list", Gate::Admin),
        "config_current" | "config_current_post" => ("config_current", Gate::Admin),
        "config_alias" => ("config", Gate::Key),
        "get_config_by_header" => ("get_by_header", Gate::Header),
        "get_config" => ("get", Gate::Key),
        "add_config_by_header" => ("add_by_header", Gate::Header),
        "add_config" => ("add", Gate::Key),
        "delete_config_by_header" => ("del_by_header", Gate::Header),
        "delete_config" => ("del", Gate::Key),
        "move_config_by_header" => ("move_by_header", Gate::Header),
        "move_config" => ("move", Gate::Key),
        "get_auth_by_header" | "set_auth_by_header" | "delete_auth_by_header" => ("auth_by_header", Gate::Header),
        "auth_current" | "auth_current_post" | "auth_current_delete" => ("auth_current", Gate::Admin),
        "get_auth" | "set_auth" | "delete_auth" => ("auth", Gate::Key),
        "json_urls_by_header" => ("json_urls_by_header", Gate::Header),
        "json_urls" => ("json_urls", Gate::Key),
        _ => ("<unnamed view>", Gate::Key),
    }
}

/// The key that holds the client's address in the request's event.
const REMOTE: api::EventKey = api::EventKey::new("remote");

/// Who is calling (Basic Auth), and `401` to an anonymous caller the operation's [`Gate`] does not admit.
fn authorize(server: &Server, req: &api::Request) -> Result<Option<Arc<Caller>>, api::ApiError> {
    if let Some(event) = req.extensions().get::<api::server::RequestEvent>() {
        event.set(REMOTE, api::peer(req.extensions()).map(|p| p.ip().to_string()));
    }
    let auth = &server.s.auth;
    let credentials = api::server::credentials(req).into_iter().next().map(|c| match c {
        api::server::Credential::BasicAuth { user, password } => (user.trim().to_owned(), password.to_owned()),
    });
    let role = if !auth.required {
        Role::Open
    } else if auth.is_admin(credentials.as_ref()) {
        Role::Admin
    } else {
        Role::Anonymous
    };
    let name = req.extensions().get::<api::MatchedOperation>().map_or("", api::MatchedOperation::name);
    let admitted = match operation(name).1 {
        Gate::Key => true,
        Gate::Header => req
            .headers()
            .get("x-apprise-config-id")
            .and_then(|h| h.to_str().ok())
            .is_some_and(|h| super::text::non_blank(&h)),
        Gate::Admin => false,
    };
    if role == Role::Anonymous && !admitted {
        let realm = format!("Basic realm=\"{}\"", auth.realm);
        let mut e = api::ApiError::new(api::http::StatusCode::UNAUTHORIZED, "Access Denied");
        if let Ok(v) = api::http::HeaderValue::from_str(&realm) {
            e = e.with_header(api::http::header::WWW_AUTHENTICATE, v);
        }
        return Err(e);
    }
    Ok(Some(Arc::new(Caller { role: super::call::Slot::new(role), credentials, ..Caller::default() })))
}

/// apprise-api's answers: an empty `404` for no route, `405` with `Allow`, `413` and closing for a body too
/// large, and the message of each other failure as text or `{"error": ...}` for JSON clients.
fn error_response(server: &Server, rejection: api::server::Rejection) -> api::Response {
    let header = |name: &str| rejection.headers.get(name).and_then(|v| v.to_str().ok());
    let json = wants_json(header("accept"), &media_type(header("content-type").unwrap_or("")));
    let operation = rejection.operation.map(honig::Operation::name);
    let fault = match rejection.reason {
        api::Reason::NotFound => return new_response(404),
        api::Reason::MethodNotAllowed(methods) => {
            let mut r = new_response(405);
            set_header(&mut r, "Allow", methods.join(", "));
            return r;
        }
        api::Reason::PayloadTooLarge(_) => {
            let mut r = new_response(413);
            r.set_body(
                "text/plain; charset=utf-8",
                b"Failed to buffer the request body: length limit exceeded".to_vec(),
            );
            set_header(&mut r, "Connection", "close");
            return r;
        }
        api::Reason::Body(_) => Fault::new(400, "Invalid JSON Payload provided"),
        // The connection broke or the I/O timeout passed while the body was read: plain text, as for a body too
        // large, and the connection is not reused.
        api::Reason::Unreadable(_) => {
            let mut r = error_body(false, 400, "Failed to buffer the request body: failed to read the body", None);
            set_header(&mut r, "Connection", "close");
            return r;
        }
        api::Reason::Invalid(violations) => violations.first().map_or_else(
            || Fault::new(400, "Invalid payload structure provided"),
            |v| violation_fault(operation, &v.path, &v.message),
        ),
        api::Reason::Unauthorized => Fault::unauthorized(&server.s.auth.realm),
        api::Reason::Denied(e) | api::Reason::Handler(e) => {
            let mut r = error_body(json, e.status.as_u16(), &e.message, None);
            r.headers_mut().extend(*e.headers);
            return r;
        }
        api::Reason::Encode(e) => Fault::new(500, e),
        // `Reason` is non-exhaustive: a reason that honig adds later answers with its own status and detail too.
        other @ (api::Reason::NotAcceptable(_) | api::Reason::UnsupportedMediaType(..) | _) => {
            Fault::new(other.status().as_u16(), other.detail().unwrap_or_default())
        }
    };
    let mut r = error_body(json, fault.status, &fault.message, fault.field);
    if fault.status == 401 {
        set_header(&mut r, "WWW-Authenticate", fault.challenge);
    }
    r
}

/// apprise-api's message for the first thing wrong in a request: a body field of the wrong type, a value outside its
/// allowed set, or a parameter that does not decode.
fn violation_fault(operation: Option<&str>, pointer: &str, message: &str) -> Fault {
    // A value of the wrong type: serde's decode error, or the schema check of a field that is a union.
    let wrong_type = message.starts_with("invalid type")
        || message.starts_with("must be of type")
        || message.contains("of `oneOf`")
        || message.contains("of `anyOf`");
    // A body that is not JSON at all: serde's syntax error, at the body itself.
    if pointer == "/body" && !wrong_type {
        return Fault::new(400, "Invalid JSON Payload provided");
    }
    if pointer == "/body" || (pointer.starts_with("/body/") && wrong_type) {
        return decode_fault(operation, pointer);
    }
    if pointer.starts_with("/body") || pointer.contains("X-Apprise-Log-Level") {
        return invalid_fault(operation, pointer);
    }
    let name = pointer.rsplit('/').next().unwrap_or(pointer);
    Fault::new(400, format!("The {name} value is invalid"))
}

/// Counts every request and logs it as one event (see `docs/book/src/server.md`).
fn on_event(server: &Server, event: &api::server::RequestEvent) {
    let e = event.snapshot();
    let view = operation(e.operation.map_or("", honig::Operation::name)).0;
    let elapsed = Duration::from_micros(e.duration_us);
    let streamed = e.extra.get("stream").is_some_and(|v| v == true);
    let bytes_out = (!streamed).then_some(e.response_bytes as u64);
    server.metrics.record(e.method, view, e.status, elapsed, e.request_bytes as u64, bytes_out);
    // As apprise-api's nginx: a passing health check or metrics scrape is not logged (the container checks
    // `/status` every 30 s).
    if e.status < 400 && (e.route.starts_with("/status") || e.route == "/metrics") {
        return;
    }
    let field = |k: &str| e.extra.get(k).filter(|v| !v.is_null()).map(super::text::value_text);
    let route = (!e.route.is_empty()).then_some(e.route);
    tracing::info!(
        target: "request",
        method = e.method,
        route,
        status = e.status,
        duration_ms = %format_args!("{:.3}", elapsed.as_secs_f64() * 1000.0),
        remote = field("remote"),
        key = field("key"),
        apprise_id = field("apprise_id"),
        recursion = field("recursion"),
        bytes_in = e.request_bytes,
        services = field("services"),
        failed = field("failed"),
        stream = streamed.then_some(true),
        error = field("fault").or_else(|| e.error.map(|f| f.name().to_owned())),
        detail = field("detail"),
    );
}

/// An error answer as text, or `{"error": ..., "field": ...}` for JSON clients.
fn error_body(json: bool, status: u16, message: &str, field: Option<&str>) -> api::Response {
    let mut r = new_response(status);
    if json {
        let body = api::types::Error { error: message.to_owned(), field: field.map(str::to_owned) };
        r.set_body("application/json", serde_json::to_vec(&body).unwrap_or_default());
    } else {
        r.set_body("text/plain; charset=utf-8", message.as_bytes().to_vec());
    }
    r
}

/// The field a pointer into the body names: `/body/urls/0` is `urls`.
fn body_field(pointer: &str) -> &str {
    let rest = pointer.strip_prefix("/body").unwrap_or(pointer);
    rest.trim_start_matches('/').split('/').next().unwrap_or("")
}

/// apprise-api's message for a body field of the wrong type.
fn decode_fault(operation: Option<&str>, pointer: &str) -> Fault {
    let field = body_field(pointer);
    let (message, name): (&str, &'static str) = match field {
        "urls" => ("The urls field must be a string or list of strings", "urls"),
        "format" if !operation.is_some_and(|o| o.contains("config")) => {
            ("The format field must be a string or null", "format")
        }
        "template" => ("The template field must be an object of name/value pairs", "template"),
        "to" => ("A valid destination (to), different from the source, is required", "to"),
        "body" => ("The body field must be a string", "body"),
        "title" => ("The title field must be a string", "title"),
        "type" => ("The type field must be a string", "type"),
        "config" => ("The config field must be a string", "config"),
        "format" => ("The format field must be a string", "format"),
        "" => return Fault::new(400, "The JSON payload must be an object"),
        _ => return Fault::new(400, "Invalid payload structure provided"),
    };
    Fault::new(400, message).field(name)
}

/// apprise-api's message for a value outside its allowed set.
fn invalid_fault(operation: Option<&str>, pointer: &str) -> Fault {
    match (operation.unwrap_or(""), body_field(pointer)) {
        (_, "type") => Fault::new(400, "Payload lacks minimum requirements"),
        (_, "format") => Fault::new(400, "An invalid body input format was specified"),
        (_, "access") => Fault::new(400, "Select a valid choice: user, locked, public or disabled").field("access"),
        _ if pointer.contains("X-Apprise-Log-Level") => Fault::new(400, "An invalid log level was specified"),
        _ => Fault::new(400, "Invalid payload structure provided"),
    }
}
