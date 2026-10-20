//! Server settings: the flags of `mercurio serve`, each also an environment variable, read once at start-up.

use std::path::PathBuf;
use std::time::Duration;

use mercurio::NotifyFormat;

use super::auth::AuthSettings;
use super::http::parse_bool;
use super::store::Mode;
use super::{filters, notify};

/// Django's built-in default `SECRET_KEY`, the hash-mode salt when none is set.
const DEFAULT_SECRET_KEY: &str = "+reua88v8rs4j!bcfdtinb-f0edxazf!$x_q1g7jtgckxd7gi=";
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
    /// Persistent storage for services (tokens, sessions) [default: CONFIG_DIR/store]
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
    /// Server log on stderr: `text`, or `json` for one JSON object per line
    #[arg(long, env = "LOG_FORMAT", default_value = "text", value_name = "FORMAT", value_parser = ["text", "json"])]
    log_format: String,
    /// `no` stops following HTTP redirects for URLs without `?redirect=`
    #[arg(long, env = "APPRISE_HTTP_REDIRECTS", default_value = "yes", value_name = "YES|NO")]
    http_redirects: String,
    /// `no` turns off the daily clean-up of old persistent storage and unused logins
    #[arg(long, env = "APPRISE_PRUNE_ENABLED", default_value = "yes", value_name = "YES|NO")]
    prune_enabled: String,
    /// Seconds between clean-ups (at least 2; the first runs at start-up)
    #[arg(long, env = "APPRISE_PRUNE_INTERVAL_SECONDS", default_value = "86400", value_name = "N")]
    prune_interval_seconds: String,
    /// Longest a clean-up may run, in seconds (kept below the interval)
    #[arg(long, env = "APPRISE_PRUNE_TIMEOUT_SECONDS", default_value = "28800", value_name = "N")]
    prune_timeout_seconds: String,
    /// Age in seconds after which a login without a configuration is removed
    #[arg(long, env = "APPRISE_AUTH_PRUNE_SECONDS", default_value = "2592000", value_name = "N")]
    auth_prune_seconds: String,
    /// `--storage-prune-days` / `APPRISE_STORAGE_PRUNE_DAYS`, an option every command shares (set by `main`).
    #[arg(skip = 30)]
    pub(crate) storage_prune_days: i64,
    /// `--storage-uid-length` / `APPRISE_STORAGE_UID_LENGTH`, an option every command shares (set by `main`).
    #[arg(skip = mercurio::DEFAULT_STORAGE_IDLEN)]
    pub(crate) storage_uid_length: usize,
    /// `yes` replaces `:shortcode:` emoji unless a URL says `?emojis=no` (also `-j`); `no` never does; unset lets each URL decide
    #[arg(long, env = "APPRISE_INTERPRET_EMOJIS", value_name = "YES|NO")]
    pub(crate) emojis: Option<String>,
    /// Live streams sending at the same time
    #[arg(long, env = "APPRISE_STREAM_WORKER_COUNT", default_value = "4", value_name = "N")]
    stream_worker_count: String,
    /// Workers: each takes 128 requests in progress at once, more get `503`
    #[arg(long, env = "APPRISE_WORKER_COUNT", default_value = "4", value_name = "N")]
    worker_count: String,
    /// Seconds a request head, and each piece of its body, may take to arrive
    #[arg(long, env = "APPRISE_WORKER_TIMEOUT", default_value = "30", value_name = "SECONDS")]
    worker_timeout: String,
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

impl ServeArgs {
    /// `--log-format json`.
    pub(crate) fn json_logs(&self) -> bool {
        self.log_format == "json"
    }
}
/// Requests one worker of `APPRISE_WORKER_COUNT` stands for: the library's 128 sends at once.
const REQUESTS_PER_WORKER: usize = 128;

fn int(name: &str, raw: &str, min: i64, max: i64) -> Result<i64, String> {
    let v: i64 = raw.trim().parse().map_err(|_| format!("{name} must be a whole number"))?;
    if v < min || v > max {
        return Err(format!("{name} must be between {min} and {max}"));
    }
    Ok(v)
}

/// The periodic clean-up of apprise-api's container: persistent storage older than `storage` and logins without a configuration older than `logins`, every `interval`, each run stopped after `timeout`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Prune {
    pub(super) interval: Duration,
    pub(super) timeout: Duration,
    pub(super) storage: Duration,
    pub(super) logins: Duration,
}

impl Prune {
    fn from_args(a: &ServeArgs) -> Result<Prune, String> {
        // As apprise-api's pruner loop: a bad interval or timeout falls back to its default.
        let positive = |name: &str, raw: &str, min: u64, default: u64| match raw.trim().parse::<u64>() {
            Ok(n) if n >= min => n,
            _ => {
                log::warn!("{name}={raw:?} must be a whole number of at least {min}; using {default}");
                default
            }
        };
        let interval = positive("APPRISE_PRUNE_INTERVAL_SECONDS", &a.prune_interval_seconds, 2, 86_400);
        let timeout = positive("APPRISE_PRUNE_TIMEOUT_SECONDS", &a.prune_timeout_seconds, 1, 28_800).min(interval - 1);
        if a.storage_prune_days < 0 {
            return Err("APPRISE_STORAGE_PRUNE_DAYS must not be negative".into());
        }
        let logins = int("APPRISE_AUTH_PRUNE_SECONDS", &a.auth_prune_seconds, 0, i64::MAX)?;
        Ok(Prune {
            interval: Duration::from_secs(interval),
            timeout: Duration::from_secs(timeout),
            storage: Duration::from_secs(a.storage_prune_days.unsigned_abs() * 86_400),
            logins: Duration::from_secs(logins.unsigned_abs()),
        })
    }
}

/// Server settings, read once at start-up.
pub(crate) struct Settings {
    pub(super) config_dir: PathBuf,
    pub(super) stateful: Mode,
    pub(super) secret: String,
    pub(super) stateless_enabled: bool,
    pub(super) stateless_urls: Option<String>,
    pub(super) recursion_max: u32,
    pub(super) config_lock: bool,
    /// `GET /cfg` key listing (`APPRISE_ADMIN`).
    pub(super) admin_list: bool,
    pub(super) config_max_len: usize,
    pub(super) default_format: Option<NotifyFormat>,
    pub(super) allow_templates: bool,
    pub(super) attach_size: u64,
    pub(super) max_attachments: usize,
    /// Deepest `?:a.b.c=` mapping path (`APPRISE_WEBHOOK_MAPPING_MAX_DEPTH`).
    pub(super) mapping_depth: usize,
    pub(super) auth: AuthSettings,
    /// Persistent storage for services (`None`: in memory).
    pub(super) storage: Option<PathBuf>,
    pub(super) stateless_storage: bool,
    pub(super) http_redirects: bool,
    pub(super) interpret_emojis: Option<bool>,
    pub(super) log_level: u8,
    pub(super) stream_slots: usize,
    /// Requests in progress at once (`APPRISE_WORKER_COUNT` workers of [`REQUESTS_PER_WORKER`]).
    pub(super) max_requests: usize,
    /// How long a request head, and each piece of its body, may take (`APPRISE_WORKER_TIMEOUT`).
    pub(super) io_timeout: Duration,
    pub(super) storage_idlen: usize,
    pub(super) storage_mode: mercurio::StorageMode,
    /// The periodic clean-up; `None` when `APPRISE_PRUNE_ENABLED=no`.
    pub(super) prune: Option<Prune>,
    pub(super) services: filters::ServiceFilter,
    pub(super) attach_urls: filters::UrlFilter,
    pub(super) webhook: Option<String>,
}

impl Settings {
    pub(super) fn from_args(a: &ServeArgs) -> Result<Settings, String> {
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
        // apprise-api reads the first letter only.
        let storage_mode = match a.storage_mode.trim().to_lowercase().as_bytes().first() {
            Some(b'm') => mercurio::StorageMode::Memory,
            Some(b'f') => mercurio::StorageMode::Flush,
            Some(b'a') => mercurio::StorageMode::Auto,
            _ => return Err("APPRISE_STORAGE_MODE must be one of: auto, flush, memory".into()),
        };
        let storage = (storage_mode != mercurio::StorageMode::Memory).then(|| {
            a.storage_dir
                .as_deref()
                .filter(|d| !d.trim().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| config_dir.join("store"))
        });
        let log_level = notify::level_value(&a.log_level).unwrap_or(20);
        let stream_slots = (int("APPRISE_STREAM_WORKER_COUNT", &a.stream_worker_count, 1, i64::MAX)?
            + int("APPRISE_STREAM_QUEUE_SIZE", &a.stream_queue_size, 0, i64::MAX)?) as usize;
        Ok(Settings {
            storage,
            stateless_storage: flag(&a.stateless_storage, false),
            http_redirects: flag(&a.http_redirects, true),
            interpret_emojis: a.emojis.as_deref().map(|v| flag(v, false)),
            log_level,
            stream_slots,
            max_requests: int("APPRISE_WORKER_COUNT", &a.worker_count, 1, 1 << 20)? as usize * REQUESTS_PER_WORKER,
            io_timeout: Duration::from_secs(
                int("APPRISE_WORKER_TIMEOUT", &a.worker_timeout, 1, 86_400)?.unsigned_abs(),
            ),
            storage_idlen: match a.storage_uid_length {
                n @ 2..=64 => n,
                _ => return Err("APPRISE_STORAGE_UID_LENGTH must be between 2 and 64".into()),
            },
            storage_mode,
            prune: flag(&a.prune_enabled, true).then(|| Prune::from_args(a)).transpose()?,
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
