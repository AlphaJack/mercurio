//! `mercurio`: send notifications from the command line.
//!
//! `mercurio -t title -b body URL...`, body from stdin when `-b` is absent, configuration files (`-c` or the default locations), `--tag`, `--template-var` and the same exit codes (0 ok, 1 failure, 2 usage, 3 nothing matched, 4 partial).
//!
//! Sources, first match wins: URLs on the command line, `--config`, `$APPRISE_URLS`, the default configuration files.

#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]

/// `println!` that never panics: a closed stdout (`mercurio services | head`) ends the program quietly instead.
macro_rules! outln {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        if let Err(e) = writeln!(std::io::stdout().lock(), $($arg)*) {
            $crate::stdout_failed(e);
        }
    }};
}

/// `eprintln!` that never panics (a closed stderr drops the message).
macro_rules! errln {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        writeln!(std::io::stderr().lock(), $($arg)*).ok();
    }};
}

mod logging;
mod serve;
mod storage;

use std::io::Read;
use std::process::ExitCode;
use std::sync::Arc;

use mercurio::__private::{default_paths, expand_path};
use mercurio::ConfigOptions;
use mercurio::{
    Asset, AsyncMercurio, AsyncTransport, Attachment, Message, NotifyFormat, NotifyType, StorageMode, TagFilter,
    TemplateVars, TokioTransport,
};

/// stdout went away: exit 0 when the reader closed the pipe (as `head` does), 1 otherwise.
fn stdout_failed(e: std::io::Error) -> ! {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        std::process::exit(0);
    }
    errln!("error: writing to stdout: {e}");
    std::process::exit(1);
}

/// Default levels of configuration `include` to follow.
const DEFAULT_RECURSION: u32 = 1;
/// Default age, in days, after which `storage prune` removes files.
const DEFAULT_PRUNE_DAYS: i64 = 30;

#[derive(Debug, clap::Parser)]
#[command(name = "mercurio", version, about, disable_help_subcommand = true, max_term_width = 100)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
    /// Notification URLs
    #[arg(value_name = "URL")]
    urls: Vec<String>,
    #[command(flatten)]
    opts: Opts,
}

#[derive(Debug, clap::Subcommand)]
enum Cmd {
    /// List the supported services
    Services,
    /// Validate URLs or configuration; send nothing
    Check {
        #[arg(value_name = "URL")]
        urls: Vec<String>,
    },
    /// Run the HTTP notification server
    #[command(after_help = serve::help_tables())]
    Serve {
        /// Check the server at `--bind` instead of starting one: exit 0 when `GET /status` answers 200
        #[arg(long)]
        healthcheck: bool,
        #[command(flatten)]
        settings: Box<serve::ServeArgs>,
    },
    /// Show (`list`) or clean (`prune`, `clear`) the persistent storage
    Storage {
        #[arg(value_name = "ACTION|UID|URL")]
        args: Vec<String>,
    },
    /// Same as giving the URLs directly
    #[command(hide = true)]
    Send {
        #[arg(value_name = "URL")]
        urls: Vec<String>,
    },
}

/// Options accepted before or after the command word.
#[derive(Debug, clap::Args)]
struct Opts {
    /// Message body [default: read stdin]
    #[arg(short, long, global = true, value_name = "TEXT")]
    body: Option<String>,
    /// Message title
    #[arg(short, long, global = true, value_name = "TEXT")]
    title: Option<String>,
    /// `info`, `success`, `warning` or `failure`
    #[arg(short = 'n', long, global = true, value_name = "TYPE", default_value = "info", value_parser = parse_type)]
    notification_type: NotifyType,
    /// Markup of the body: `text`, `html` or `markdown`
    #[arg(short, long, global = true, value_name = "FORMAT", value_parser = parse_format)]
    input_format: Option<NotifyFormat>,
    /// Attach a file: path, `file://`, `http(s)://` or `memory://` (repeatable)
    #[arg(short, long, global = true, value_name = "PATH|URL")]
    attach: Vec<String>,
    /// Load a TEXT or YAML configuration (repeatable)
    #[arg(short, long, global = true, value_name = "PATH|URL")]
    config: Vec<String>,
    /// Notify services tagged TAG; `a,b` needs both, repeat for either, `all` notifies everything
    #[arg(short = 'g', long, global = true, value_name = "TAG")]
    tag: Vec<String>,
    /// Value for `${NAME}` in a YAML configuration (`-tv`, repeatable)
    #[arg(long, global = true, value_name = "NAME=VALUE")]
    template_var: Vec<String>,
    /// Configuration `include` levels to follow
    #[arg(short = 'R', long, global = true, value_name = "N", default_value_t = DEFAULT_RECURSION)]
    recursion_depth: u32,
    /// Turn `\n`, `\r`, `\t` and `\\` in the title and body into the characters
    #[arg(short = 'e', long, global = true)]
    interpret_escapes: bool,
    /// Image theme, the `{THEME}` of image URLs
    #[arg(short = 'T', long, global = true, value_name = "THEME", default_value = "default")]
    theme: String,
    /// Replace `:shortcode:` emoji in the title and body (a URL's `?emojis=no` still wins)
    #[arg(short = 'j', long, global = true)]
    interpret_emojis: bool,
    /// Show what would be notified; send nothing
    #[arg(short, long, global = true)]
    dry_run: bool,
    /// Notify services one after another (`-Da`)
    #[arg(long, global = true)]
    disable_async: bool,
    /// Persistent storage directory
    #[arg(short = 'S', long, global = true, value_name = "PATH", env = "APPRISE_STORAGE_PATH", default_value = DEFAULT_STORAGE_PATH)]
    storage_path: String,
    /// `storage prune` removes files older than N days (`-SPD`)
    #[arg(long, global = true, value_name = "N", env = "APPRISE_STORAGE_PRUNE_DAYS", default_value_t = DEFAULT_PRUNE_DAYS, allow_negative_numbers = true, value_parser = parse_days)]
    storage_prune_days: i64,
    /// Characters of the URL ids naming persistent storage, at least 2 (`-SUL`)
    #[arg(long, global = true, value_name = "N", env = "APPRISE_STORAGE_UID_LENGTH", default_value_t = mercurio::DEFAULT_STORAGE_IDLEN)]
    storage_uid_length: usize,
    /// When persistent storage is written: `auto` (after each send), `flush` (also before each step) or `memory` (never) (`-SM`)
    #[arg(long, global = true, value_name = "MODE", default_value = "auto")]
    storage_mode: String,
    /// Same as `mercurio services`
    #[arg(short = 'l', long, global = true)]
    details: bool,
    /// With `services`: print JSON
    #[arg(long, global = true)]
    json: bool,
    /// With `serve`: address to listen on
    #[arg(long, global = true, value_name = "ADDR", default_value = "127.0.0.1:8000")]
    bind: String,
    /// More log output on stderr (repeat for more)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
}

const DEFAULT_STORAGE_PATH: &str =
    if cfg!(windows) { "%APPDATA%/Mercurio/cache" } else { "~/.local/share/mercurio/cache" };

/// Exit codes; `--help` lists them with their meaning.
mod exit {
    pub const OK: u8 = 0;
    pub const FAILURE: u8 = 1;
    pub const USAGE: u8 = 2;
    pub const NO_MATCH: u8 = 3;
    pub const PARTIAL: u8 = 4;

    /// Each code with its meaning, for `--help`.
    pub const ALL: &[(u8, &str)] = &[
        (OK, "every selected service was notified (or -d, check, services, storage succeeded)"),
        (FAILURE, "every selected service failed, or a source, attachment or stdin could not be read"),
        (USAGE, "usage error, or no URLs given or configured"),
        (NO_MATCH, "services were loaded but none matched the tags (-g)"),
        (PARTIAL, "some services were notified and some failed"),
    ];
}

/// Environment variables read outside clap (shown under `--help`).
const ENVIRONMENT: &[(&str, &str)] = &[
    ("APPRISE_URLS", "URLs to notify when none are given and there is no -c"),
    ("APPRISE_CONFIG_PATH", "configuration files instead of the defaults (separated by ; or newlines)"),
    ("APPRISE_TEMPLATE_<NAME>", "value for ${NAME} when -tv and the configuration give none"),
];

/// `-SPD` / `$APPRISE_STORAGE_PRUNE_DAYS`; empty means the default.
fn parse_days(v: &str) -> Result<i64, String> {
    if v.trim().is_empty() {
        return Ok(DEFAULT_PRUNE_DAYS);
    }
    v.trim().parse().map_err(|_| format!("{v:?} is not a number"))
}

fn parse_type(v: &str) -> Result<NotifyType, String> {
    NotifyType::parse(v).ok_or(format!("invalid notification type {v:?}"))
}

fn parse_format(v: &str) -> Result<NotifyFormat, String> {
    NotifyFormat::parse(v).ok_or(format!("invalid input format {v:?}"))
}

/// The text after the options in `--help`: environment and default files, both from the code that reads them.
fn after_help() -> String {
    let mut out = String::from("Environment:\n");
    for (name, meaning) in ENVIRONMENT {
        out.push_str(&format!("  {name:<26} {meaning}\n"));
    }
    out.push_str("\nExit codes:\n");
    for (code, meaning) in exit::ALL {
        out.push_str(&format!("  {code}  {meaning}\n"));
    }
    // The locations current Apprise documents; the older ones in `default_paths` are still read, and the book lists them all.
    let (user, system) = if cfg!(windows) {
        (r"%APPDATA%\Apprise\apprise.conf", r"%ALLUSERSPROFILE%\Apprise\apprise.conf")
    } else {
        ("~/.config/apprise/apprise.conf", "/etc/apprise/apprise.conf")
    };
    out.push_str("\nDefault configuration files (.yaml instead of .conf for YAML):\n");
    out.push_str(&format!("  {user}\n  {system}\n"));
    out
}

/// What to run, from the command word, with what only that command uses.
enum Command {
    /// Send a notification (no command word, or `send`).
    Notify {
        urls: Vec<String>,
    },
    Services,
    Check {
        urls: Vec<String>,
    },
    Serve(Box<serve::ServeArgs>),
    Healthcheck,
    /// `storage [ACTION] [UID|URL...]`.
    Storage {
        args: Vec<String>,
    },
}

/// The command and the options every command shares.
fn parse_args() -> (Command, Opts) {
    use clap::{CommandFactory, FromArgMatches};
    // Multi-letter short options are rewritten to their long forms.
    let raw = std::env::args().map(|s| match s.as_str() {
        "-Da" => "--disable-async".into(),
        "-tv" => "--template-var".into(),
        "-SPD" => "--storage-prune-days".into(),
        "-SUL" => "--storage-uid-length".into(),
        "-SM" => "--storage-mode".into(),
        _ => s,
    });
    let matches = Cli::command().after_help(after_help()).get_matches_from(raw);
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    // URLs may come before the command word, after it, or both.
    let mut urls = cli.urls;
    let command = match cli.command {
        _ if cli.opts.details => Command::Services,
        Some(Cmd::Services) => Command::Services,
        Some(Cmd::Check { urls: more }) => {
            urls.extend(more);
            Command::Check { urls }
        }
        Some(Cmd::Serve { healthcheck: true, .. }) => Command::Healthcheck,
        Some(Cmd::Serve { healthcheck: false, settings }) => Command::Serve(settings),
        Some(Cmd::Storage { args }) => {
            urls.extend(args);
            Command::Storage { args: urls }
        }
        Some(Cmd::Send { urls: more }) => {
            urls.extend(more);
            Command::Notify { urls }
        }
        None => Command::Notify { urls },
    };
    (command, cli.opts)
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            Some(o) => {
                out.push('\\');
                out.push(o);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// A path, `file://`, `http(s)://` or `memory://` attachment (`mercurio::attachment`).
async fn load_attachment(spec: &str, transport: &dyn AsyncTransport) -> Result<Attachment, String> {
    let source = mercurio::AttachSource::parse(spec).map_err(|e| format!("{}: {e}", mercurio::redact_url(spec)))?;
    source.load_async(transport, &mercurio::Asset::default()).await.map_err(|e| e.to_string())
}

fn cmd_services(json: bool) -> ExitCode {
    let mut defs: Vec<_> = mercurio::services().to_vec();
    defs.sort_by_key(|d| d.name.to_lowercase());
    if json {
        let list: Vec<serde_json::Value> = defs
            .iter()
            .map(|d| {
                serde_json::json!({
                    "id": d.id,
                    "name": d.name,
                    "schemes": d.schemes,
                    "service_url": d.service_url,
                    "attachments": d.attachments,
                    "formats": d.formats.iter().map(|f| f.as_str()).collect::<Vec<_>>(),
                    "title_maxlen": d.limits.title_maxlen,
                    "body_maxlen": d.limits.body_maxlen,
                    "body_max_line_count": d.limits.body_max_line_count,
                    "throttle_ms": d.throttle.as_millis() as u64,
                    "native_url": d.parse_native.is_some(),
                    "templates": d.templates,
                    "tokens": d.tokens.iter().map(mercurio::Param::to_json).collect::<Vec<_>>(),
                    "params": d.params.iter().map(mercurio::Param::to_json).collect::<Vec<_>>(),
                })
            })
            .collect();
        match serde_json::to_string_pretty(&list) {
            Ok(text) => outln!("{text}"),
            Err(e) => {
                errln!("error: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        for d in &defs {
            outln!("{:<34} {}", d.name, d.schemes.iter().map(|s| format!("{s}://")).collect::<Vec<_>>().join(" "));
        }
        outln!("\n{} services", defs.len());
    }
    ExitCode::SUCCESS
}

fn env_urls() -> Vec<String> {
    match std::env::var("APPRISE_URLS") {
        Ok(v) if !v.trim().is_empty() => mercurio::__private::parse_urls([v.as_str()], true),
        _ => Vec::new(),
    }
}

/// `$APPRISE_CONFIG_PATH` / `$APPRISE_CONFIG` (`;` or newline separated), else the default locations.
fn config_search_paths() -> Vec<String> {
    for var in ["APPRISE_CONFIG_PATH", "APPRISE_CONFIG"] {
        if let Ok(v) = std::env::var(var) {
            return v.trim().split(['\r', '\n', ';']).filter(|p| !p.is_empty()).map(str::to_string).collect();
        }
    }
    default_paths()
}

/// Where the services come from, in priority order.
enum Source {
    Urls(Vec<String>),
    Configs(Vec<String>),
}

fn source(urls: &[String], o: &Opts) -> Source {
    if !urls.is_empty() {
        if !o.config.is_empty() {
            log::warn!("You defined both URLs and a --config (-c) entry; Only the URLs will be referenced.");
        }
        return Source::Urls(urls.to_vec());
    }
    if !o.config.is_empty() {
        return Source::Configs(o.config.clone());
    }
    let env = env_urls();
    if !env.is_empty() {
        return Source::Urls(env);
    }
    Source::Configs(config_search_paths().into_iter().filter(|p| expand_path(p).is_file()).collect())
}

/// Load every service; returns the notifier, the number of sources that failed and the tag filter to apply.
async fn build(
    urls: &[String],
    o: &Opts,
    transport: Arc<dyn AsyncTransport>,
) -> Result<(AsyncMercurio, usize, TagFilter), u8> {
    let opts = ConfigOptions { recursion: o.recursion_depth, ..ConfigOptions::default() };
    let mut m = AsyncMercurio::with_transport(transport).config_options(opts).asset(storage_asset(o).0);
    if o.disable_async {
        m = m.sequential();
    }
    let mut bad = 0;
    let filter = match source(urls, o) {
        Source::Urls(urls) => {
            for url in &urls {
                if let Err(e) = m.add(url) {
                    errln!("error: {}: {e}", mercurio::redact_url(url));
                    bad += 1;
                }
            }
            // --tag also applies to URLs given directly, through their `?tag=` values.
            if o.tag.is_empty() { TagFilter::all() } else { TagFilter::from_cli(&o.tag) }
        }
        Source::Configs(paths) => {
            for path in &paths {
                match m.add_config(path).await {
                    Ok(0) => log::warn!("no services loaded from {}", mercurio::redact_url(path)),
                    Ok(_) => {}
                    Err(e) => {
                        errln!("error: {}: {e}", mercurio::redact_url(path));
                        bad += 1;
                    }
                }
            }
            // Without --tag only untagged services are notified.
            TagFilter::from_cli(&o.tag)
        }
    };
    if m.is_empty() {
        if bad == 0 {
            errln!(
                "error: no URLs given (pass them as arguments, use --config, set APPRISE_URLS, \
                 or create ~/.config/apprise/apprise.yml)"
            );
            return Err(exit::USAGE);
        }
        return Err(exit::FAILURE);
    }
    Ok((m, bad, filter))
}

/// `-tv NAME=VALUE` entries (exit 2 on a malformed or repeated name).
fn template_vars(o: &Opts) -> Result<TemplateVars, u8> {
    let mut vars = TemplateVars::new();
    for entry in &o.template_var {
        let (name, value) = match entry.split_once('=') {
            Some((n, v)) if mercurio::__private::valid_name(n.trim()) => (n.trim(), v),
            other => {
                // Only the name is echoed: the value may be a secret.
                let name = other.map(|(n, _)| n).unwrap_or(entry).trim();
                errln!("error: the --template-var (-tv) name '{name}' is not in the expected NAME=VALUE format.");
                return Err(exit::USAGE);
            }
        };
        if vars.set(name, value).is_err() {
            errln!("error: the --template-var (-tv) name '{name}' was provided more than once.");
            return Err(exit::USAGE);
        }
    }
    Ok(vars)
}

fn print_tags(tags: &[mercurio::Tag]) {
    if !tags.is_empty() {
        let mut t: Vec<&str> = tags.iter().map(|t| t.name.as_str()).collect();
        t.sort();
        outln!("{:>10}: {}", "tags", t.join(", "));
    }
}

/// `--dry-run`: what would be notified, with tags and template needs.
fn print_dry_run(m: &AsyncMercurio, filter: &TagFilter, vars: &TemplateVars) {
    let sel = m.select(filter, vars);
    let mut n = 0;
    for t in sel.iter() {
        n += 1;
        outln!("{n:4}. {}", mercurio::redact_url(t.url()));
        print_tags(t.tag_set());
    }
    for (p, _) in &sel.unresolved {
        n += 1;
        outln!("{n:4}. {}", mercurio::redact_url(&p.url()));
        outln!("{:>10}: - template; unresolved, would not send -", "uid");
        print_tags(&p.tags);
        let required = p.template_required();
        let names: Vec<String> = p
            .template_names()
            .iter()
            .map(|n| format!("{n} ({})", if required.contains(n) { "required" } else { "has default" }))
            .collect();
        outln!("{:>10}: {}", "template", names.join(", "));
    }
    if !sel.unresolved.is_empty() {
        outln!("\n{} of {n} matched entries could not be resolved and would not be sent.", sel.unresolved.len());
    }
}

/// The asset carrying the storage options, plus the prune age in days.
fn storage_asset(o: &Opts) -> (Asset, i64) {
    let path = if o.storage_path.trim().is_empty() { DEFAULT_STORAGE_PATH } else { &o.storage_path };
    let asset = Asset {
        storage_idlen: o.storage_uid_length,
        // `run` has checked the mode.
        storage_mode: StorageMode::parse(&o.storage_mode).unwrap_or_default(),
        interpret_emojis: o.interpret_emojis.then_some(true),
        theme: o.theme.clone(),
        ..Asset::default()
    };
    (asset.with_storage(expand_path(path.trim())), o.storage_prune_days)
}

/// Human-readable size: `1.50KB`, `2.00MB`, ...
fn bytes_to_str(n: u64) -> String {
    let mut v = n as f64;
    let mut unit = "B";
    for u in ["KB", "MB", "GB", "TB"] {
        if v < 1024.0 {
            break;
        }
        v /= 1024.0;
        unit = u;
    }
    format!("{v:.2}{unit}")
}

/// `mercurio storage [list|prune|clear] [UID-prefix...|URL...]`: URL ids of the configured services next to what is on disk (list); removal of old (prune) or all (clear) cached files.
async fn cmd_storage(args: &[String], o: &Opts) -> Result<u8, u8> {
    const ACTIONS: [&str; 3] = ["list", "prune", "clear"];
    let transport: Arc<dyn AsyncTransport> = Arc::new(TokioTransport::new());
    let (asset, mut days) = storage_asset(o);
    if days < 0 {
        errln!("error: the --storage-prune-days (-SPD) value can not be lower than zero (0).");
        return Err(exit::USAGE);
    }
    let mut rest = args.to_vec();
    let mut action = "list";
    if let Some(first) = rest.first() {
        let found = if first == "clean" {
            Some("clear")
        } else {
            ACTIONS.iter().copied().find(|a| a.starts_with(first.as_str()))
        };
        if let Some(a) = found {
            action = a;
            rest.remove(0);
        }
    }
    let (url_filters, uid_filters): (Vec<String>, Vec<String>) = rest.into_iter().partition(|f| f.contains("://"));
    let uid_filters: Vec<String> = uid_filters.into_iter().map(|u| u.to_lowercase()).collect();
    let had_url_filters = !url_filters.is_empty();

    // The services whose URL ids are cross-referenced.
    let has_source = match source(&url_filters, o) {
        Source::Urls(u) => !u.is_empty(),
        Source::Configs(c) => !c.is_empty(),
    };
    let mut uids: Vec<(String, Vec<&mercurio::Target>)> = Vec::new();
    let loaded = if has_source { build(&url_filters, o, transport).await.ok() } else { None };
    let vars = TemplateVars::new();
    let selection = loaded.as_ref().map(|(m, _, filter)| m.select(filter, &vars));
    for t in selection.iter().flat_map(|s| s.targets.iter().copied()) {
        let Some(id) = t.url_id(&asset) else { continue };
        if !uid_filters.is_empty() && !uid_filters.iter().any(|u| id.starts_with(u.as_str())) {
            continue;
        }
        match uids.iter_mut().find(|(u, _)| *u == id) {
            Some((_, list)) => list.push(t),
            None => uids.push((id, vec![t])),
        }
    }
    let Some(base) = asset.storage_path.clone() else { return Ok(exit::OK) };

    if action == "list" {
        let ns: Vec<String> = if had_url_filters {
            uids.iter().map(|(u, _)| u.clone()).chain(uid_filters.iter().cloned()).collect()
        } else {
            uid_filters.clone()
        };
        let on_disk = if had_url_filters && ns.is_empty() { Vec::new() } else { storage::scan(&base, &ns).await };
        let mut rows: Vec<(String, u64, &str, Vec<&mercurio::Target>)> =
            uids.into_iter().map(|(u, t)| (u, 0, "unused", t)).collect();
        for id in on_disk {
            let size = storage::dir_size(&base.join(&id)).await;
            match rows.iter_mut().find(|r| r.0 == id) {
                Some(r) => {
                    r.1 = size;
                    r.2 = "active";
                }
                None if o.tag.is_empty() => rows.push((id, size, "stale", Vec::new())),
                None => {}
            }
        }
        for (idx, (uid, size, state, targets)) in rows.iter().enumerate() {
            if idx > 0 {
                outln!("");
            }
            outln!("{:4}. {uid:<52} {:<8} {state}", idx + 1, bytes_to_str(*size));
            for t in targets {
                outln!("{:>7} {}", "-", mercurio::redact_url(t.url()));
                print_tags(t.tag_set());
            }
        }
        return Ok(exit::OK);
    }

    if action == "clear" {
        days = 0;
    }
    let ns: Vec<String> = if had_url_filters || !o.tag.is_empty() {
        let ns: Vec<String> = uids.iter().map(|(u, _)| u.clone()).chain(uid_filters.iter().cloned()).collect();
        if ns.is_empty() {
            return Ok(exit::OK);
        }
        ns
    } else {
        uid_filters
    };
    let age = std::time::Duration::from_secs(days as u64 * 86400);
    let results = storage::prune(&base, &ns, age, !o.dry_run).await;
    for (uid, files) in results {
        for f in files {
            let what = if o.dry_run {
                "would remove"
            } else if f.removed {
                "removed"
            } else {
                "kept"
            };
            outln!("{uid}: {what} {}", f.path.display());
        }
    }
    Ok(exit::OK)
}

/// Run the command; the exit code.
fn run() -> u8 {
    let (command, o) = parse_args();
    if o.storage_uid_length < 2 {
        errln!("error: the --storage-uid-length (-SUL) value can not be lower than two (2).");
        return exit::USAGE;
    }
    if StorageMode::parse(&o.storage_mode).is_none() {
        errln!("error: the --storage-mode (-SM) value of {} is not supported.", o.storage_mode.trim());
        return exit::USAGE;
    }
    let style = match &command {
        Command::Serve(settings) if settings.json_logs() => logging::Style::Json,
        Command::Serve(_) => logging::Style::Server,
        Command::Notify { .. }
        | Command::Services
        | Command::Check { .. }
        | Command::Healthcheck
        | Command::Storage { .. } => logging::Style::Cli,
    };
    logging::init(o.verbose, style);
    let code = match command {
        Command::Services => Ok(if cmd_services(o.json) == ExitCode::SUCCESS { exit::OK } else { exit::FAILURE }),
        Command::Serve(mut settings) => {
            settings.storage_uid_length = o.storage_uid_length;
            settings.storage_prune_days = o.storage_prune_days;
            if o.interpret_emojis {
                settings.emojis = Some("yes".into());
            }
            cmd_serve(&o.bind, &settings)
        }
        Command::Healthcheck => serve::healthcheck(&o.bind).map(|()| exit::OK).map_err(|e| {
            errln!("unhealthy: {e}");
            exit::FAILURE
        }),
        Command::Check { urls } => on_current_thread(cmd_check(&urls, &o)),
        Command::Storage { args } => on_current_thread(cmd_storage(&args, &o)),
        Command::Notify { urls } => on_current_thread(cmd_notify(&urls, &o)),
    };
    // `Err` is an early exit; its code is the result all the same.
    code.unwrap_or_else(|c| c)
}

fn cmd_serve(bind: &str, settings: &serve::ServeArgs) -> Result<u8, u8> {
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| {
        errln!("error: {e}");
        exit::FAILURE
    })?;
    runtime.block_on(serve::run(bind, settings)).map(|()| exit::OK).map_err(|e| {
        errln!("error: {e}");
        exit::FAILURE
    })
}

/// Run a command on a single-threaded runtime.
fn on_current_thread(command: impl std::future::Future<Output = Result<u8, u8>>) -> Result<u8, u8> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| {
        errln!("error: {e}");
        exit::FAILURE
    })?;
    runtime.block_on(command)
}

/// `check`: load every URL and configuration, send nothing.
async fn cmd_check(urls: &[String], o: &Opts) -> Result<u8, u8> {
    let (mercurio, bad, _) = build(urls, o, Arc::new(TokioTransport::new())).await?;
    for t in mercurio.targets() {
        outln!("ok   {}", t.label());
    }
    for p in mercurio.pending() {
        outln!("ok   {} (template: {})", p.label(), p.template_names().join(", "));
    }
    Ok(if bad == 0 { exit::OK } else { exit::FAILURE })
}

/// Send the notification (or show it with `-d`).
async fn cmd_notify(urls: &[String], o: &Opts) -> Result<u8, u8> {
    let transport: Arc<dyn AsyncTransport> = Arc::new(TokioTransport::new());
    let vars = template_vars(o)?;
    let (mut selected, bad, filter) = build(urls, o, transport.clone()).await?;
    if bad > 0 {
        errln!("error: {bad} invalid URL or configuration source; nothing was sent");
        return Err(exit::USAGE);
    }
    if selected.select(&filter, &vars).is_empty() {
        errln!("no URLs matched the given tags");
        return Err(exit::NO_MATCH);
    }

    if o.dry_run {
        print_dry_run(&selected, &filter, &vars);
        return Ok(exit::OK);
    }

    let mut body = match &o.body {
        Some(b) => b.clone(),
        None => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).map_err(|e| {
                errln!("error: reading stdin: {e}");
                exit::FAILURE
            })?;
            s
        }
    };
    let mut title = o.title.clone().unwrap_or_default();
    if o.interpret_escapes {
        body = unescape(&body);
        title = unescape(&title);
    }
    let mut msg = Message::new(body).title(title).kind(o.notification_type);
    msg.format = o.input_format;
    for spec in &o.attach {
        match load_attachment(spec, transport.as_ref()).await {
            Ok(a) => msg.attachments.push(a),
            Err(e) => {
                errln!("error: attachment {e}");
                return Err(exit::FAILURE);
            }
        }
    }

    let report = selected.notify_with(&msg, &filter, &vars).await;
    selected.close().await;
    let total = report.entries.len();
    let ok = report.entries.iter().filter(|e| e.delivery.is_success()).count();
    for (entry, outcome) in report.failures() {
        let target = outcome.target.as_deref().map(|t| format!(" [{t}]")).unwrap_or_default();
        if let Err(e) = &outcome.result {
            errln!("failed: {}{target}: {e}", entry.label);
        }
    }
    log::info!("{ok} of {total} services notified");
    Ok(match (ok, total) {
        (o, t) if o == t => exit::OK,
        (0, _) => exit::FAILURE,
        _ => exit::PARTIAL,
    })
}

fn main() -> ExitCode {
    ExitCode::from(run())
}
