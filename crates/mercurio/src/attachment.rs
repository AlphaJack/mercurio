//! Attachment sources.
//!
//! An [`AttachSource`] says where an attachment comes from: a local file (`/path`, `file:///path`), a web resource (`http(s)://...`, downloaded through a [`Transport`] so tests run on [`FakeTransport`](crate::testing::FakeTransport)) or memory. Loading one yields the in-memory [`Attachment`] payload services receive. [`AttachmentSet`] is the list form.
//!
//! URL options:
//!
//! | option | meaning |
//! |---|---|
//! | `?name=report.pdf` | forced file name (base name only) |
//! | `?mime=image/png` | forced MIME type; must be a known type |
//! | `?cache=yes\|no\|<seconds>` | reuse a loaded copy (default 600 s); `no`/`0` reloads every time |
//! | `?verify=no` | (http) skip TLS verification |
//! | `?+Header=value`, `?-Header=value` | (http) extra request headers |
//! | anything else | (http) forwarded as query parameters |
//!
//! ```
//! use mercurio::AttachmentSet;
//! use mercurio::testing::FakeTransport;
//! use mercurio::{Asset, Message, transport::Response};
//!
//! let fake = FakeTransport::new();
//! fake.respond_with(Response::new(200, "a,b\n1,2\n").with_header("Content-Type", "text/csv"));
//! let mut set = AttachmentSet::new();
//! set.add("https://example.com/export?id=7&name=report.csv").unwrap();
//! let mut msg = Message::new("Nightly export");
//! msg.attachments.extend(set.load(&fake, &Asset::default()).unwrap());
//! assert_eq!(msg.attachments[0].name, "report.csv");
//! assert_eq!(msg.attachments[0].mime, "text/csv");
//! assert_eq!(fake.requests()[0].url, "https://example.com/export?id=7");
//! ```

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::asset::Asset;
use crate::error::{Error, Result};
use crate::http::Request;
use crate::message::Attachment;
use crate::service::Secret;
use crate::transport::{AsyncTransport, Blocking, FileOp, FileOutput, Transport};

/// Largest attachment by default (1000 MiB); the [`Asset::attachment_max_size`] default.
pub const DEFAULT_MAX_SIZE: u64 = 1_048_576_000;
/// Default `cache` age in seconds.
pub const DEFAULT_CACHE_SECS: u64 = 600;

const UNKNOWN_MIME: &str = "application/octet-stream";
const UNKNOWN_NAME: &str = "mercurio-attachment";
const UNKNOWN_EXTENSION: &str = ".obj";

/// Where content may come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Location {
    /// Local files and hosted content.
    Local,
    /// Only hosted (`http(s)://`) content: what a server accepting attachment URLs from clients should use.
    Hosted,
    /// Attachments disabled.
    Inaccessible,
}

impl Location {
    /// Parse `local`, `hosted` or `inaccessible` (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "local" => Some(Self::Local),
            "hosted" => Some(Self::Hosted),
            "inaccessible" => Some(Self::Inaccessible),
            _ => None,
        }
    }
}

/// How long a loaded copy stays valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cache {
    /// Reload on every use (`cache=no`, `cache=0`).
    Off,
    /// Load once (`cache=yes`).
    Forever,
    /// Reload when older than this many seconds.
    Seconds(u64),
}

impl Cache {
    /// An integer is an age (0 = off, negative = error), anything else is a boolean.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if let Ok(n) = s.parse::<i64>() {
            return match n {
                n if n < 0 => Err(Error::Message(format!("a negative cache value ({n}) was specified"))),
                0 => Ok(Self::Off),
                n => Ok(Self::Seconds(n as u64)),
            };
        }
        Ok(if crate::parse::parse_bool(s, false) { Self::Forever } else { Self::Off })
    }

    fn fresh(self, loaded_at: Instant) -> bool {
        match self {
            Self::Off => false,
            Self::Forever => true,
            Self::Seconds(s) => loaded_at.elapsed() <= Duration::from_secs(s),
        }
    }
}

#[derive(Clone)]
struct HttpSource {
    secure: bool,
    host: String,
    port: Option<u16>,
    user: Option<String>,
    password: Option<Secret>,
    /// Still percent-encoded, starts with `/`.
    fullpath: String,
    headers: Vec<(String, String)>,
    query: Vec<(String, String)>,
    verify: bool,
    redirects: bool,
    connect_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
}

impl HttpSource {
    fn url(&self) -> String {
        let scheme = if self.secure { "https" } else { "http" };
        let port = self.port.map(|p| format!(":{p}")).unwrap_or_default();
        format!("{scheme}://{}{port}{}", self.host, self.fullpath)
    }
}

#[derive(Clone)]
enum Kind {
    File(PathBuf),
    Http(Box<HttpSource>),
    Memory(Vec<u8>),
}

/// One attachment source.
pub struct AttachSource {
    kind: Kind,
    name: Option<String>,
    mime: Option<String>,
    cache: Option<Cache>,
    loaded: Mutex<Option<(Instant, Attachment)>>,
}

impl Clone for AttachSource {
    fn clone(&self) -> Self {
        Self {
            kind: self.kind.clone(),
            name: self.name.clone(),
            mime: self.mime.clone(),
            cache: self.cache,
            loaded: Mutex::new(self.loaded.lock().unwrap_or_else(|p| p.into_inner()).clone()),
        }
    }
}

impl fmt::Debug for AttachSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachSource")
            .field("source", &self.label())
            .field("name", &self.name)
            .field("mime", &self.mime)
            .field("cache", &self.cache)
            .finish()
    }
}

impl AttachSource {
    /// Parse an attachment URL or plain path.
    pub fn parse(spec: &str) -> Result<Self> {
        let Some(scheme) = crate::url::scheme_of(spec) else {
            return Ok(Self::file(spec));
        };
        match scheme.as_str() {
            "file" => Self::parse_file(spec),
            "http" | "https" => Self::parse_http(spec),
            "memory" => Self::parse_memory(spec),
            _ => Err(Error::UnknownScheme(scheme)),
        }
    }

    /// A local file.
    pub fn file(path: impl AsRef<Path>) -> Self {
        Self::build(Kind::File(path.as_ref().to_path_buf()))
    }

    /// In-memory bytes; name defaults to `<uuid>.dat`, MIME type to `application/octet-stream`.
    #[expect(clippy::disallowed_methods, reason = "a caller-side constructor, before any send")]
    pub fn memory(data: impl Into<Vec<u8>>, name: Option<&str>, mime: Option<&str>) -> Self {
        let mut s = Self::build(Kind::Memory(data.into()));
        s.name = Some(
            name.filter(|n| !n.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| format!("{}.dat", crate::env::system().uuid4())),
        );
        s.mime = Some(mime.unwrap_or(UNKNOWN_MIME).to_string());
        s
    }

    /// In-memory text; name defaults to `<uuid>.txt`, MIME type to `text/plain`.
    #[expect(clippy::disallowed_methods, reason = "a caller-side constructor, before any send")]
    pub fn text(text: &str, name: Option<&str>) -> Self {
        let name = name
            .filter(|n| !n.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("{}.txt", crate::env::system().uuid4()));
        Self::memory(text.as_bytes(), Some(&name), Some("text/plain"))
    }

    fn build(kind: Kind) -> Self {
        Self { kind, name: None, mime: None, cache: None, loaded: Mutex::new(None) }
    }

    /// Force the file name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Force the MIME type (must be a known type).
    pub fn with_mime(mut self, mime: &str) -> Result<Self> {
        self.mime = Some(validate_mime(mime)?);
        Ok(self)
    }

    /// Override the cache policy.
    #[must_use]
    pub fn with_cache(mut self, cache: Cache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Where this source reads from.
    pub fn location(&self) -> Location {
        match self.kind {
            Kind::File(_) | Kind::Memory(_) => Location::Local,
            Kind::Http(_) => Location::Hosted,
        }
    }

    /// A description safe to log (no credentials, no query).
    pub fn label(&self) -> String {
        match &self.kind {
            Kind::File(p) => format!("file://{}", p.display()),
            Kind::Http(h) => crate::plan::redact_url(&h.url()),
            Kind::Memory(_) => format!("memory://{}", self.name.as_deref().unwrap_or("")),
        }
    }

    /// Common `?name=`, `?mime=`, `?cache=` handling.
    fn apply_options(mut self, query: &crate::url::Pairs) -> Result<Self> {
        if let Some(m) = query.get("mime") {
            let m = m.trim().to_lowercase();
            if !m.is_empty() {
                self.mime = Some(validate_mime(&m)?);
            }
        }
        if let Some(n) = query.get("name") {
            let base = n.rsplit(['/', '\\']).next().unwrap_or("").trim();
            if !base.is_empty() {
                self.name = Some(base.to_string());
            }
        }
        if let Some(c) = query.get("cache") {
            self.cache = Some(Cache::parse(c)?);
        }
        Ok(self)
    }

    fn parse_file(spec: &str) -> Result<Self> {
        let re = crate::regex!(r"(?i)^\s*file://(?P<path>[^?]+)(\?.*)?$");
        let caps = re.captures(spec).ok_or_else(|| Error::InvalidUrl("file://...".into()))?;
        let path = crate::url::unquote(&caps["path"]);
        let query = query_pairs(caps.get(2).and_then(|m| m.as_str().strip_prefix('?')).unwrap_or(""));
        Self::file(path).apply_options(&query)
    }

    fn parse_memory(spec: &str) -> Result<Self> {
        let re = crate::regex!(r"(?i)^\s*memory://(?P<path>[^?]*)(\?.*)?$");
        let caps = re.captures(spec).ok_or_else(|| Error::InvalidUrl("memory://...".into()))?;
        let query = query_pairs(caps.get(2).and_then(|m| m.as_str().strip_prefix('?')).unwrap_or(""));
        let path = crate::url::unquote(&caps["path"]);
        let name = path.rsplit('/').next().unwrap_or("").to_string();
        let s = Self::build(Kind::Memory(Vec::new()));
        let mut s = s.apply_options(&query)?;
        if s.name.is_none() && !name.is_empty() {
            s.name = Some(name);
        }
        Ok(s)
    }

    fn parse_http(spec: &str) -> Result<Self> {
        let opts = crate::url::ParseOptions { sanitize: false, ..Default::default() };
        let u =
            crate::url::parse_url_with(spec, opts).ok_or_else(|| Error::InvalidUrl(crate::plan::redact_url(spec)))?;
        // `?-x=` and `?+x=` both become request headers.
        let mut headers: Vec<(String, String)> =
            u.query_minus.iter().chain(u.query_plus.iter()).map(|(k, v)| (k.to_string(), v.to_string())).collect();
        headers.dedup_by(|a, b| a.0 == b.0);
        let query = u
            .query
            .iter()
            .filter(|(k, _)| !["cache", "mime", "name", "verify"].contains(k) && !k.starts_with(['+', '-', ':']))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let http = HttpSource {
            secure: u.secure,
            host: u.host(),
            port: u.port,
            user: u.user(),
            password: u.password().map(Secret::new),
            fullpath: u.fullpath.clone().unwrap_or_else(|| "/".into()),
            headers,
            query,
            verify: u.verify,
            redirects: u.redirect,
            connect_timeout: u.cto.filter(|v| *v > 0.0).map(Duration::from_secs_f64),
            read_timeout: u.rto.filter(|v| *v > 0.0).map(Duration::from_secs_f64),
        };
        Self::build(Kind::Http(Box::new(http))).apply_options(&u.query)
    }

    /// Load the content (or reuse a cached copy), enforcing `max_size` bytes (0 = unlimited).
    pub fn load(&self, transport: &dyn Transport, asset: &Asset) -> Result<Attachment> {
        pollster::block_on(self.load_async(&Blocking(transport), asset))
    }

    /// [`AttachSource::load`] on an [`AsyncTransport`].
    pub async fn load_async(&self, transport: &dyn AsyncTransport, asset: &Asset) -> Result<Attachment> {
        let cache = self.cache.unwrap_or(Cache::Seconds(DEFAULT_CACHE_SECS));
        {
            let mut slot = self.loaded.lock().unwrap_or_else(|p| p.into_inner());
            if let Some((at, a)) = slot.as_ref()
                && cache.fresh(*at)
            {
                return Ok(a.clone());
            }
            *slot = None;
        }
        let a = self.fetch(transport, asset).await?;
        if cache != Cache::Off {
            *self.loaded.lock().unwrap_or_else(|p| p.into_inner()) = Some((Instant::now(), a.clone()));
        }
        Ok(a)
    }

    fn too_large(&self, max: u64) -> Error {
        Error::Message(format!("attachment {} exceeds the maximum size ({}KB)", self.label(), max / 1024))
    }

    async fn fetch(&self, transport: &dyn AsyncTransport, asset: &Asset) -> Result<Attachment> {
        let max = asset.attachment_max_size;
        let (data, detected_name, detected_mime) = match &self.kind {
            Kind::File(path) => {
                let meta = match transport.file(&FileOp::Stat { path: path.clone() }).await {
                    Ok(FileOutput::Meta(Some(m))) if m.is_file => m,
                    _ => return Err(Error::Message(format!("attachment {} is not a readable file", self.label()))),
                };
                if max > 0 && meta.len > max {
                    return Err(self.too_large(max));
                }
                let data = match transport.file(&FileOp::Read { path: path.clone(), max: 0 }).await {
                    Ok(FileOutput::Bytes(b)) => b,
                    Ok(_) => return Err(Error::Message(format!("attachment {} is not a readable file", self.label()))),
                    Err(e) => return Err(Error::Message(format!("attachment {}: {e}", self.label()))),
                };
                let name = path.file_name().map(|n| n.to_string_lossy().to_string());
                (data, name, None)
            }
            Kind::Memory(data) => {
                if data.is_empty() {
                    return Err(Error::Message(format!("attachment {} is empty", self.label())));
                }
                if max > 0 && data.len() as u64 > max {
                    return Err(self.too_large(max));
                }
                (data.clone(), None, None)
            }
            Kind::Http(h) => self.download(h, transport, asset, max).await?,
        };
        let name = self.name.clone().or(detected_name.filter(|n| !n.is_empty())).unwrap_or_else(|| {
            let mime = self.resolve_mime(detected_mime.as_deref(), None);
            format!("{UNKNOWN_NAME}{}", extension_for(&mime).unwrap_or(UNKNOWN_EXTENSION))
        });
        let mime = self.resolve_mime(detected_mime.as_deref(), Some(&name));
        Ok(Attachment::new(name, mime, data))
    }

    /// Forced MIME, then the server's `Content-Type`, then a guess from the name.
    fn resolve_mime(&self, detected: Option<&str>, name: Option<&str>) -> String {
        if let Some(m) = &self.mime {
            return m.clone();
        }
        if let Some(d) = detected.filter(|d| !d.trim().is_empty()) {
            return d.to_string();
        }
        name.and_then(guess_mime).unwrap_or(UNKNOWN_MIME).to_string()
    }

    async fn download(
        &self,
        h: &HttpSource,
        transport: &dyn AsyncTransport,
        asset: &Asset,
        max: u64,
    ) -> Result<(Vec<u8>, Option<String>, Option<String>)> {
        let mut req = Request::get(h.url())
            .header("User-Agent", asset.app_id.clone())
            .headers(h.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .verify(h.verify)
            .redirects(h.redirects);
        if !h.query.is_empty() {
            req = req.query(&h.query);
        }
        if let Some(user) = &h.user {
            req = req.basic_auth(user, h.password.as_ref().map(Secret::expose));
        }
        if h.connect_timeout.is_some() || h.read_timeout.is_some() {
            let (connect, read) = (req.connect_timeout, req.read_timeout);
            req = req.timeouts(h.connect_timeout.unwrap_or(connect), h.read_timeout.unwrap_or(read));
        }
        // Stop reading once the body passes the limit (Apprise streams to a file and stops early too).
        let req = req.max_body(max);
        let res = transport.http(&req).await.map_err(|e| {
            if max > 0 && e == crate::http::body_too_large(max) {
                return self.too_large(max);
            }
            if let Error::Transport(m) = e { Error::Transport(format!("attachment {}: {m}", self.label())) } else { e }
        })?;
        if res.status >= 400 {
            return Err(Error::Http { status: res.status, reason: format!("attachment {}", self.label()) });
        }
        if (300..400).contains(&res.status) {
            return Err(Error::Message(format!(
                "attachment {}: redirect encountered but redirects are disabled",
                self.label()
            )));
        }
        let declared: u64 = res.header("content-length").and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        if max > 0 && (declared > max || res.body.len() as u64 > max) {
            return Err(self.too_large(max));
        }
        let disposition = res.header("content-disposition").unwrap_or("");
        let re = crate::regex!(r#"(?i)filename=['"]?([^'"]+)['"]?"#);
        let name = re.captures(disposition).map(|c| c[1].trim().to_string()).filter(|n| !n.is_empty()).or_else(|| {
            // Fall back to the basename of the (still quoted) URL path.
            Some(h.fullpath.rsplit('/').next().unwrap_or("").to_string())
        });
        let mime = res.header("content-type").map(str::to_string);
        Ok((res.body, name, mime))
    }

    /// Drop any cached copy.
    pub fn invalidate(&self) {
        *self.loaded.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}

/// `?k=v&...` (lower-cased keys, unquoted values).
fn query_pairs(q: &str) -> crate::url::Pairs {
    let mut out = crate::url::Pairs::new();
    for part in q.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        let k = crate::url::unquote_plus(k).trim().to_lowercase();
        if k.starts_with(['+', '-', ':']) {
            continue;
        }
        out.insert(k, crate::url::unquote_plus(v).trim().to_string());
    }
    out
}

/// A list of attachment sources.
///
/// Sources are checked when added and read by [`AttachmentSet::load`]; `http(s)://` sources are downloaded through the given transport.
///
/// ```
/// use mercurio::testing::FakeTransport;
/// use mercurio::{attachment::AttachSource, AttachmentSet, Asset, transport::Response};
///
/// let mut set = AttachmentSet::new();
/// set.add("https://example.com/report?name=report.csv")?;
/// set.push(AttachSource::text("hello", Some("note.txt")))?;
///
/// let fake = FakeTransport::new();
/// fake.respond_with(Response::new(200, "a,b\n1,2\n").with_header("Content-Type", "text/csv"));
/// let files = set.load(&fake, &Asset::default())?;
/// assert_eq!(files[0].name, "report.csv");
/// assert_eq!(files[1].data, &b"hello"[..]);
/// # Ok::<(), mercurio::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct AttachmentSet {
    items: Vec<AttachSource>,
    location: Option<Location>,
    cache: Option<Cache>,
}

impl Default for AttachmentSet {
    fn default() -> Self {
        Self::new()
    }
}

impl AttachmentSet {
    /// An empty set. The size limit is read from the [`Asset`] passed to [`load`](Self::load) (`attachment_max_size`).
    pub fn new() -> Self {
        Self { items: Vec::new(), location: None, cache: None }
    }

    /// Restrict what may be added. `None` (default) allows everything.
    #[must_use]
    pub fn location(mut self, location: Location) -> Self {
        self.location = Some(location);
        self
    }

    /// Cache policy for sources added from now on, overriding their `?cache=`.
    #[must_use]
    pub fn cache(mut self, cache: Cache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Parse and add one URL or path.
    pub fn add(&mut self, spec: &str) -> Result<&mut Self> {
        let source = AttachSource::parse(spec)?;
        self.push(source)
    }

    /// Add several; returns the error of every spec that was rejected.
    pub fn add_all<I: IntoIterator<Item = S>, S: AsRef<str>>(&mut self, specs: I) -> Vec<Error> {
        specs.into_iter().filter_map(|s| self.add(s.as_ref()).err()).collect()
    }

    /// Add a prepared source, honouring the location restriction.
    pub fn push(&mut self, mut source: AttachSource) -> Result<&mut Self> {
        let disallowed = match self.location {
            Some(Location::Inaccessible) => true,
            Some(Location::Hosted) => source.location() != Location::Hosted,
            _ => false,
        };
        if disallowed {
            return Err(Error::Message(format!(
                "attachment {} is not allowed here ({:?} content only)",
                source.label(),
                self.location.unwrap_or(Location::Local)
            )));
        }
        if let Some(c) = self.cache {
            source.cache = Some(c);
        }
        self.items.push(source);
        Ok(self)
    }

    /// Number of attachment sources.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// `true` when no source was added.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The sources in the order they were added.
    pub fn iter(&self) -> impl Iterator<Item = &AttachSource> {
        self.items.iter()
    }

    /// Remove every source.
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// Load every attachment; the first failure aborts.
    pub fn load(&self, transport: &dyn Transport, asset: &Asset) -> Result<Vec<Attachment>> {
        pollster::block_on(self.load_async(&Blocking(transport), asset))
    }

    /// [`AttachmentSet::load`] on an [`AsyncTransport`].
    pub async fn load_async(&self, transport: &dyn AsyncTransport, asset: &Asset) -> Result<Vec<Attachment>> {
        let mut out = Vec::with_capacity(self.items.len());
        for s in &self.items {
            out.push(s.load_async(transport, asset).await?);
        }
        Ok(out)
    }
}

/// `true` for MIME types in the built-in table.
pub fn is_known_mime(mime: &str) -> bool {
    MIME_TYPES.iter().any(|(_, m)| *m == mime)
}

fn validate_mime(mime: &str) -> Result<String> {
    let m = mime.trim().to_lowercase();
    if is_known_mime(&m) { Ok(m) } else { Err(Error::Message(format!("an invalid mime-type ({mime}) was specified"))) }
}

/// MIME type for a file name's extension (case-insensitive).
pub fn guess_mime(name: &str) -> Option<&'static str> {
    let (_, ext) = name.rsplit_once('.')?;
    let ext = ext.to_ascii_lowercase();
    MIME_TYPES.iter().find(|(e, _)| *e == ext).map(|(_, m)| *m)
}

/// Preferred extension (with the dot) for a MIME type.
pub fn extension_for(mime: &str) -> Option<&'static str> {
    let mime = mime.to_ascii_lowercase();
    let ext = PREFERRED_EXTENSIONS
        .iter()
        .find(|(m, _)| *m == mime)
        .map(|(_, e)| *e)
        .or_else(|| MIME_TYPES.iter().find(|(_, m)| *m == mime).map(|(e, _)| *e))?;
    DOTTED.iter().copied().find(|d| d.strip_prefix('.') == Some(ext))
}

/// Preferred extension where several extensions share a type.
const PREFERRED_EXTENSIONS: &[(&str, &str)] = &[
    ("application/octet-stream", "bin"),
    ("text/plain", "txt"),
    ("image/jpeg", "jpg"),
    ("text/html", "html"),
    ("audio/mpeg", "mp3"),
    ("video/mpeg", "mpeg"),
    ("image/tiff", "tiff"),
];

macro_rules! mime_table {
    ($(($ext:literal, $mime:literal)),* $(,)?) => {
        const MIME_TYPES: &[(&str, &str)] = &[$(($ext, $mime)),*];
        const DOTTED: &[&str] = &[$(concat!(".", $ext)),*];
    };
}

mime_table![
    ("bin", "application/octet-stream"),
    ("obj", "application/octet-stream"),
    ("dat", "application/octet-stream"),
    ("txt", "text/plain"),
    ("log", "text/plain"),
    ("text", "text/plain"),
    ("conf", "text/plain"),
    ("html", "text/html"),
    ("htm", "text/html"),
    ("css", "text/css"),
    ("csv", "text/csv"),
    ("md", "text/markdown"),
    ("markdown", "text/markdown"),
    ("xml", "text/xml"),
    ("ics", "text/calendar"),
    ("vcf", "text/vcard"),
    ("js", "text/javascript"),
    ("rtf", "application/rtf"),
    ("json", "application/json"),
    ("pdf", "application/pdf"),
    ("zip", "application/zip"),
    ("gz", "application/gzip"),
    ("tar", "application/x-tar"),
    ("tgz", "application/x-gtar"),
    ("bz2", "application/x-bzip2"),
    ("xz", "application/x-xz"),
    ("7z", "application/x-7z-compressed"),
    ("rar", "application/vnd.rar"),
    ("doc", "application/msword"),
    ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    ("xls", "application/vnd.ms-excel"),
    ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    ("ppt", "application/vnd.ms-powerpoint"),
    ("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
    ("odt", "application/vnd.oasis.opendocument.text"),
    ("ods", "application/vnd.oasis.opendocument.spreadsheet"),
    ("yaml", "application/yaml"),
    ("yml", "application/yaml"),
    ("wasm", "application/wasm"),
    ("sh", "application/x-sh"),
    ("py", "text/x-python"),
    ("eml", "message/rfc822"),
    ("png", "image/png"),
    ("jpg", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("jpe", "image/jpeg"),
    ("gif", "image/gif"),
    ("bmp", "image/bmp"),
    ("webp", "image/webp"),
    ("svg", "image/svg+xml"),
    ("ico", "image/vnd.microsoft.icon"),
    ("tif", "image/tiff"),
    ("tiff", "image/tiff"),
    ("heic", "image/heic"),
    ("avif", "image/avif"),
    ("mp3", "audio/mpeg"),
    ("wav", "audio/x-wav"),
    ("ogg", "audio/ogg"),
    ("oga", "audio/ogg"),
    ("flac", "audio/flac"),
    ("aac", "audio/aac"),
    ("m4a", "audio/mp4"),
    ("opus", "audio/opus"),
    ("mp4", "video/mp4"),
    ("m4v", "video/mp4"),
    ("mpeg", "video/mpeg"),
    ("mpg", "video/mpeg"),
    ("mov", "video/quicktime"),
    ("webm", "video/webm"),
    ("avi", "video/x-msvideo"),
    ("mkv", "video/x-matroska"),
    ("ttf", "font/ttf"),
    ("woff", "font/woff"),
    ("woff2", "font/woff2"),
];

#[cfg(test)]
#[expect(clippy::disallowed_methods, reason = "tests set up real files")]
mod tests {
    use super::*;
    use crate::http::Response;
    use crate::testing::FakeTransport;

    fn temp_file(name: &str, data: &[u8]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mercurio-attach-{}", crate::env::system().random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, data).unwrap();
        p
    }

    #[test]
    fn plain_path_and_file_url() {
        let p = temp_file("notes.txt", b"hello");
        let fake = FakeTransport::new();
        let a = AttachSource::parse(p.to_str().unwrap()).unwrap().load(&fake, &Asset::default()).unwrap();
        assert_eq!((a.name.as_str(), a.mime.as_str(), &a.data[..]), ("notes.txt", "text/plain", &b"hello"[..]));
        let url = format!("file://{}?name=renamed.csv", crate::url::quote(p.to_str().unwrap(), "/"));
        let a = AttachSource::parse(&url).unwrap().load(&fake, &Asset::default()).unwrap();
        assert_eq!((a.name.as_str(), a.mime.as_str()), ("renamed.csv", "text/csv"));
        let url = format!("file://{}?mime=image/png", p.display());
        assert_eq!(AttachSource::parse(&url).unwrap().load(&fake, &Asset::default()).unwrap().mime, "image/png");
        assert!(fake.requests().is_empty());
    }

    #[test]
    fn invalid_options() {
        assert!(AttachSource::parse("file:///tmp/x?mime=not/a-type").is_err());
        assert!(AttachSource::parse("file:///tmp/x?cache=-1").is_err());
        assert!(matches!(AttachSource::parse("ftp://host/x"), Err(Error::UnknownScheme(_))));
        let missing = AttachSource::parse("/definitely/not/here.bin").unwrap();
        assert!(missing.load(&FakeTransport::new(), &Asset::default()).is_err());
    }

    #[test]
    fn cache_values() {
        assert_eq!(Cache::parse("no").unwrap(), Cache::Off);
        assert_eq!(Cache::parse("0").unwrap(), Cache::Off);
        assert_eq!(Cache::parse("yes").unwrap(), Cache::Forever);
        assert_eq!(Cache::parse("30").unwrap(), Cache::Seconds(30));
        assert_eq!(Cache::parse("invalid").unwrap(), Cache::Off);
    }

    #[test]
    fn size_limit_from_asset() {
        let p = temp_file("big.bin", &[7u8; 64]);
        let asset = Asset { attachment_max_size: 63, ..Asset::default() };
        let s = AttachSource::file(&p);
        assert!(s.load(&FakeTransport::new(), &asset).is_err());
        assert!(s.load(&FakeTransport::new(), &Asset { attachment_max_size: 64, ..Asset::default() }).is_ok());
        let fake = FakeTransport::new();
        fake.respond(200, vec![1u8; 64]);
        assert!(AttachSource::parse("http://h/f.bin").unwrap().load(&fake, &asset).is_err());
        let fake = FakeTransport::new();
        fake.respond_with(Response::new(200, "x").with_header("Content-Length", "100"));
        assert!(AttachSource::parse("http://h/f.bin").unwrap().load(&fake, &asset).is_err());
    }

    #[test]
    fn downloads_stop_at_the_attachment_limit() {
        let source = AttachSource::parse("https://example.com/big.bin").unwrap();
        // Larger than the 16 MiB every other response may have: loads, the request carries the attachment limit.
        let fake = FakeTransport::new();
        fake.respond(200, vec![b'x'; 20 * 1024 * 1024]);
        let att = source.load(&fake, &Asset::default()).unwrap();
        assert_eq!(att.data.len(), 20 * 1024 * 1024);
        assert_eq!(fake.last_request().unwrap().max_body, Asset::default().attachment_max_size);
        source.invalidate();
        // Over the limit: the transport stops reading and the usual error comes back.
        let fake = FakeTransport::new();
        fake.respond(200, vec![b'x'; 2048]);
        let small = Asset { attachment_max_size: 1024, ..Asset::default() };
        let err = source.load(&fake, &small).unwrap_err().to_string();
        assert!(err.contains("exceeds the maximum size (1KB)"), "{err}");
        assert_eq!(fake.last_request().unwrap().max_body, 1024);
    }

    #[test]
    fn http_download_details() {
        let fake = FakeTransport::new();
        fake.respond_with(
            Response::new(200, "PNG")
                .with_header("Content-Type", "image/png")
                .with_header("Content-Disposition", "attachment; filename=\"chart.png\""),
        );
        let s = AttachSource::parse("https://user:pw@example.com:8443/a/b?id=1&+X-Token=t&verify=no&cache=no").unwrap();
        let a = s.load(&fake, &Asset::default()).unwrap();
        assert_eq!((a.name.as_str(), a.mime.as_str()), ("chart.png", "image/png"));
        let r = &fake.requests()[0];
        assert_eq!(r.url, "https://example.com:8443/a/b?id=1");
        assert_eq!(r.header_value("x-token"), Some("t"));
        assert_eq!(r.header_value("user-agent"), Some("Mercurio"));
        assert!(r.header_value("authorization").unwrap().starts_with("Basic "));
        assert!(!r.verify_tls);
        assert!(!format!("{s:?}").contains("pw"));

        // No disposition: the URL basename, MIME from the response.
        let fake = FakeTransport::new();
        fake.respond_with(Response::new(200, "x").with_header("Content-Type", "text/plain"));
        let a = AttachSource::parse("http://h/dir/log.txt").unwrap().load(&fake, &Asset::default()).unwrap();
        assert_eq!((a.name.as_str(), a.mime.as_str()), ("log.txt", "text/plain"));

        // Nothing to go on: a generated name from the MIME type.
        let fake = FakeTransport::new();
        fake.respond_with(Response::new(200, "x").with_header("Content-Type", "image/gif"));
        let a = AttachSource::parse("http://h/").unwrap().load(&fake, &Asset::default()).unwrap();
        assert_eq!(a.name, "mercurio-attachment.gif");
        let fake = FakeTransport::new();
        fake.respond_with(Response::new(200, "x"));
        let a = AttachSource::parse("http://h/").unwrap().load(&fake, &Asset::default()).unwrap();
        assert_eq!((a.name.as_str(), a.mime.as_str()), ("mercurio-attachment.bin", "application/octet-stream"));

        let fake = FakeTransport::new();
        fake.respond(404, "");
        assert!(matches!(
            AttachSource::parse("http://h/x").unwrap().load(&fake, &Asset::default()),
            Err(Error::Http { status: 404, .. })
        ));
    }

    #[test]
    fn caching() {
        let fake = FakeTransport::new();
        fake.default_response(Response::new(200, "x"));
        let s = AttachSource::parse("http://h/x.txt").unwrap();
        s.load(&fake, &Asset::default()).unwrap();
        s.load(&fake, &Asset::default()).unwrap();
        assert_eq!(fake.requests().len(), 1, "default cache reuses the download");
        let s = AttachSource::parse("http://h/x.txt?cache=no").unwrap();
        s.load(&fake, &Asset::default()).unwrap();
        s.load(&fake, &Asset::default()).unwrap();
        assert_eq!(fake.requests().len(), 3);
        s.invalidate();
    }

    #[test]
    fn memory_sources() {
        let a = AttachSource::text("hi", None).load(&FakeTransport::new(), &Asset::default()).unwrap();
        assert!(a.name.ends_with(".txt") && a.mime == "text/plain");
        let a = AttachSource::memory(vec![1, 2], Some("x.bin"), None)
            .load(&FakeTransport::new(), &Asset::default())
            .unwrap();
        assert_eq!((a.name.as_str(), a.mime.as_str()), ("x.bin", "application/octet-stream"));
        assert!(AttachSource::parse("memory://x.txt").unwrap().load(&FakeTransport::new(), &Asset::default()).is_err());
    }

    #[test]
    fn set_location_rules() {
        let mut hosted = AttachmentSet::default().location(Location::Hosted);
        assert!(hosted.add("/etc/passwd").is_err());
        assert!(hosted.add("file:///etc/passwd").is_err());
        assert!(hosted.add("https://example.com/a.png").is_ok());
        let mut off = AttachmentSet::default().location(Location::Inaccessible);
        assert!(off.add("https://example.com/a.png").is_err());
        let mut any = AttachmentSet::default();
        assert!(any.add_all(["/tmp/a", "http://x/y", "gopher://z"]).len() == 1);
        assert_eq!(any.len(), 2);
    }

    #[test]
    fn mime_helpers() {
        assert_eq!(guess_mime("a.PNG"), Some("image/png"));
        assert_eq!(guess_mime("noext"), None);
        assert_eq!(extension_for("image/jpeg"), Some(".jpg"));
        assert_eq!(extension_for("text/plain; charset=utf-8"), None);
        assert!(is_known_mime("application/pdf"));
    }
}
