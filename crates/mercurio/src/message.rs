use std::fmt;

use bytes::Bytes;

/// Severity of a notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum NotifyType {
    /// Informational (the default).
    #[default]
    Info,
    /// Something succeeded.
    Success,
    /// Something needs attention.
    Warning,
    /// Something failed.
    Failure,
}

impl NotifyType {
    /// Every type: info, success, warning, failure.
    pub const ALL: [NotifyType; 4] = [Self::Info, Self::Success, Self::Warning, Self::Failure];

    /// Lower-case name: `info`, `success`, `warning` or `failure`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Success => "success",
            Self::Warning => "warning",
            Self::Failure => "failure",
        }
    }

    /// Parse a type name (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "info" => Some(Self::Info),
            "success" => Some(Self::Success),
            "warning" => Some(Self::Warning),
            "failure" => Some(Self::Failure),
            _ => None,
        }
    }
}

impl fmt::Display for NotifyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Body markup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum NotifyFormat {
    /// Plain text.
    #[default]
    Text,
    /// HTML.
    Html,
    /// Markdown (rendered as CommonMark with GFM tables).
    Markdown,
}

impl NotifyFormat {
    /// Lower-case name: `text`, `html` or `markdown`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Html => "html",
            Self::Markdown => "markdown",
        }
    }

    /// Parse a format name (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "text" => Some(Self::Text),
            "html" => Some(Self::Html),
            "markdown" => Some(Self::Markdown),
            _ => None,
        }
    }
}

impl fmt::Display for NotifyFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What to do when a message exceeds a service's limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum OverflowMode {
    /// Send as-is; the service decides.
    #[default]
    Upstream,
    /// Cut at the limit.
    Truncate,
    /// Send several messages.
    Split,
}

impl OverflowMode {
    /// Lower-case name: `upstream`, `truncate` or `split`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upstream => "upstream",
            Self::Truncate => "truncate",
            Self::Split => "split",
        }
    }

    /// Parse an overflow mode name (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "upstream" => Some(Self::Upstream),
            "truncate" => Some(Self::Truncate),
            "split" => Some(Self::Split),
            _ => None,
        }
    }
}

/// A file sent along with a notification.
#[derive(Clone, PartialEq, Eq)]
pub struct Attachment {
    /// File name shown to the recipient.
    pub name: String,
    /// MIME type, e.g. `image/png`.
    pub mime: String,
    /// File content. Shared, so every service that sends the message reads the same buffer.
    pub data: Bytes,
}

impl Attachment {
    /// An attachment from bytes already in memory.
    pub fn new(name: impl Into<String>, mime: impl Into<String>, data: impl Into<Bytes>) -> Self {
        Self { name: name.into(), mime: mime.into(), data: data.into() }
    }

    /// Read a file from disk, guessing its MIME type from the extension.
    #[expect(clippy::disallowed_methods, reason = "a caller-side helper; delivery never calls it")]
    pub fn from_path(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        let data = std::fs::read(path)?;
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "attachment".into());
        let mime = guess_mime(&name).to_string();
        Ok(Self { name, mime, data: data.into() })
    }

    /// `true` when the MIME type is `image/*`.
    pub fn is_image(&self) -> bool {
        self.mime.starts_with("image/")
    }
}

impl fmt::Debug for Attachment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attachment")
            .field("name", &self.name)
            .field("mime", &self.mime)
            .field("len", &self.data.len())
            .finish()
    }
}

/// Small extension-based MIME guess; enough for common attachment types.
pub fn guess_mime(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "bmp" => "image/bmp",
        "txt" | "log" => "text/plain",
        "html" | "htm" => "text/html",
        "md" => "text/markdown",
        "csv" => "text/csv",
        "json" => "application/json",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        _ => "application/octet-stream",
    }
}

/// A notification to send.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    /// Title; may be empty. Services without a title field get it merged into the body.
    pub title: String,
    /// Body text.
    pub body: String,
    /// Notification type; picks colours, images and priorities.
    pub kind: NotifyType,
    /// Markup of `body`. `None` passes the body through untouched.
    pub format: Option<NotifyFormat>,
    /// Files to send; services without attachment support ignore them.
    pub attachments: Vec<Attachment>,
}

impl Message {
    /// A message with this body, no title, type `info` and no declared format.
    ///
    /// ```
    /// use mercurio::{Message, NotifyFormat, NotifyType};
    ///
    /// let msg = Message::new("**Disk** at 91%")
    ///     .title("server-1")
    ///     .kind(NotifyType::Warning)
    ///     .format(NotifyFormat::Markdown);
    /// assert_eq!(msg.title, "server-1");
    /// assert_eq!(msg.format, Some(NotifyFormat::Markdown));
    /// ```
    pub fn new(body: impl Into<String>) -> Self {
        Self { body: body.into(), ..Default::default() }
    }

    /// Set the title.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    /// Set the notification type.
    pub fn kind(mut self, kind: NotifyType) -> Self {
        self.kind = kind;
        self
    }

    /// Declare the body markup; services convert it to what they accept.
    pub fn format(mut self, format: NotifyFormat) -> Self {
        self.format = Some(format);
        self
    }

    /// Add an attachment.
    pub fn attach(mut self, attachment: Attachment) -> Self {
        self.attachments.push(attachment);
        self
    }
}

/// One piece of a message as handed to a service, after title merging and overflow handling.
#[derive(Debug, Clone, Copy)]
pub struct Prepared<'a> {
    /// Title of this piece (empty when merged into the body).
    pub title: &'a str,
    /// Body of this piece, already converted to `format`.
    pub body: &'a str,
    /// Notification type; picks colours, images and priorities.
    pub kind: NotifyType,
    /// Format of `body` as the service should treat it.
    pub format: NotifyFormat,
    /// `true` when the caller gave no input format.
    pub passthrough: bool,
    /// The caller's declared input format, before conversion to `format` (`None` when passthrough).
    pub input_format: Option<NotifyFormat>,
    /// Attachments when this piece carries them; empty on the other pieces of a split message.
    pub attachments: &'a [Attachment],
    /// The message as the caller sent it.
    pub message: &'a Message,
    /// Zero-based index of this piece when the message was split.
    pub index: usize,
    /// Number of pieces the message was split into (1 when not split).
    pub total: usize,
}
