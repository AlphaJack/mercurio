use std::path::PathBuf;

use crate::message::{NotifyFormat, NotifyType};

/// Image sizes services request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImageSize {
    /// 32×32 pixels.
    Xy32,
    /// 72×72 pixels.
    Xy72,
    /// 128×128 pixels.
    Xy128,
    /// 256×256 pixels.
    Xy256,
}

impl ImageSize {
    /// The size as written in image file names, e.g. `"72x72"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Xy32 => "32x32",
            Self::Xy72 => "72x72",
            Self::Xy128 => "128x128",
            Self::Xy256 => "256x256",
        }
    }
}

/// Branding and presentation defaults shared by all services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    /// Application name: sent as `User-Agent` and used as sender name by many services.
    pub app_id: String,
    /// Longer application description.
    pub app_desc: String,
    /// Application homepage, used in footers and links.
    pub app_url: String,
    /// Follow HTTP redirects when a URL does not set `?redirect=` (default `true`).
    pub http_redirects: bool,
    /// Id of the call chain, sent as `X-Apprise-ID` by `apprise://` targets.
    /// `None` sends each target's own random id.
    pub uid: Option<String>,
    /// Apprise API servers the current call already went through:
    /// `apprise://` targets send it plus one as `X-Apprise-Recursion-Count`.
    pub recursion: u32,
    /// Image theme substituted for `{THEME}` (default `"default"`).
    pub theme: String,
    /// `{THEME}`, `{TYPE}`, `{XY}`, `{EXTENSION}` are substituted.
    pub image_url_mask: Option<String>,
    /// Logo URL mask; same substitutions as `image_url_mask`. `None` disables the logo.
    pub image_url_logo: Option<String>,
    /// Icon file for local notifiers (desktop), with the substitutions of `image_url_mask`. `None` uses the bundled icon ([`ICON_SVG`] or [`ICON_PNG`]); an empty mask sends no icon.
    pub image_path_mask: Option<String>,
    /// The app's own icon for local notifiers, used instead of the bundled one when `image_path_mask` is unset: JPEG or PNG only (anything else falls back to the bundled icon, with a warning logged once), written under the temporary directory with a name taken from their content. Pass `include_bytes!("icon.png")`.
    pub image_bytes: Option<&'static [u8]>,
    /// Extension substituted for `{EXTENSION}` when none is given (default `".png"`).
    pub default_extension: String,
    /// `#RRGGBB` colour per [`NotifyType`], in `info`, `success`, `warning`, `failure` order.
    pub colors: [String; 4],
    /// Colour used when no type-specific colour applies.
    pub default_color: String,
    /// ASCII marker per [`NotifyType`] (`[i]`, `[+]`, `[~]`, `[!]`), same order as `colors`.
    pub ascii: [String; 4],
    /// ASCII marker used when no type-specific marker applies (`[?]`).
    pub default_ascii: String,
    /// Input format assumed when a [`Message`](crate::Message) has none. `None` passes bodies through untouched.
    pub body_format: Option<NotifyFormat>,
    /// Largest attachment [`crate::AttachmentSet`] loads, in bytes (0 = unlimited).
    pub attachment_max_size: u64,
    /// Directory for persistent stores. `None` keeps every store in memory.
    pub storage_path: Option<PathBuf>,
    /// Hex characters of a URL id ([`crate::Target::url_id`]) that are kept: Apprise's `storage_idlen`, default 8; 0 keeps the whole SHA-256.
    pub storage_idlen: usize,
    /// Bytes hashed in front of a URL's identifying parts for its URL id: Apprise's `storage_salt`, default none.
    pub storage_salt: Vec<u8>,
    /// When stores are written to [`Asset::storage_path`] (Apprise's `storage_mode`).
    pub storage_mode: StorageMode,
    /// Zone for the dates services write (e-mail `Date:`, syslog) when a URL has no `?tz=`: an IANA name such as `Europe/Paris` (Apprise's asset `timezone`). `None`: the machine's zone.
    pub timezone: Option<String>,
    /// `:shortcode:` emoji (Apprise's `interpret_emojis`): `None` (default) lets each URL turn them on with `?emojis=yes`; `Some(true)` turns them on unless a URL says `?emojis=no`; `Some(false)` turns them off for every URL.
    pub interpret_emojis: Option<bool>,
    /// Generate a PGP key pair in the storage folder when e-mail encryption needs one and none exists (Apprise's `pgp_autogen`).
    pub pgp_autogen: bool,
}

/// When a persistent store reaches the disk (Apprise's `PersistentStoreMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum StorageMode {
    /// Write once a send is over (Apprise's default).
    #[default]
    Auto,
    /// Write before every I/O step of a send and after it, so a send cut short keeps what it saved.
    Flush,
    /// Never read or write the disk, even with a storage path.
    Memory,
}

impl StorageMode {
    /// `auto`, `flush` or `memory` (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "flush" => Some(Self::Flush),
            "memory" => Some(Self::Memory),
            _ => None,
        }
    }

    /// The lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Flush => "flush",
            Self::Memory => "memory",
        }
    }
}

/// [`Asset::storage_idlen`] by default.
pub const DEFAULT_STORAGE_IDLEN: usize = 8;
pub const DEFAULT_APP_ID: &str = "Mercurio";
pub const DEFAULT_APP_DESC: &str = "Mercurio Notifications";
/// The repository (`repository` in the workspace `Cargo.toml`, the only place it is written).
pub const REPOSITORY_URL: &str = env!("CARGO_PKG_REPOSITORY");
/// The repository's GitHub Pages site, derived from [`REPOSITORY_URL`]: the book and the icons services link to.
pub const PAGES_URL: &str = env!("MERCURIO_PAGES_URL");
/// Default [`Asset::app_url`].
pub const DEFAULT_APP_URL: &str = REPOSITORY_URL;
/// Default [`Asset::image_url_mask`] and [`Asset::image_url_logo`]: the icon published with the book (`crates/mercurio/assets/logo.png`).
pub const DEFAULT_IMAGE_URL_MASK: &str = concat!(env!("MERCURIO_PAGES_URL"), "/assets/icons/logo.png");
/// Default [`Asset::image_url_logo`].
pub const DEFAULT_IMAGE_URL_LOGO: &str = DEFAULT_IMAGE_URL_MASK;
/// The bundled icon as SVG, for local notifiers that read SVG.
pub const ICON_SVG: &[u8] = include_bytes!("../assets/logo.svg");
/// The bundled icon as a 256 px PNG, for local notifiers that need a raster image.
pub const ICON_PNG: &[u8] = include_bytes!("../assets/logo.png");

impl Default for Asset {
    fn default() -> Self {
        Self {
            app_id: DEFAULT_APP_ID.into(),
            app_desc: DEFAULT_APP_DESC.into(),
            app_url: DEFAULT_APP_URL.into(),
            http_redirects: true,
            uid: None,
            recursion: 0,
            theme: "default".into(),
            image_url_mask: Some(DEFAULT_IMAGE_URL_MASK.into()),
            image_url_logo: Some(DEFAULT_IMAGE_URL_LOGO.into()),
            image_path_mask: None,
            image_bytes: None,
            default_extension: ".png".into(),
            colors: ["#3AA3E3".into(), "#3AA337".into(), "#CACF29".into(), "#A32037".into()],
            default_color: "#888888".into(),
            ascii: ["[i]".into(), "[+]".into(), "[~]".into(), "[!]".into()],
            default_ascii: "[?]".into(),
            body_format: None,
            attachment_max_size: crate::attachment::DEFAULT_MAX_SIZE,
            storage_path: None,
            storage_idlen: DEFAULT_STORAGE_IDLEN,
            storage_salt: Vec::new(),
            storage_mode: StorageMode::Auto,
            timezone: None,
            pgp_autogen: true,
            interpret_emojis: None,
        }
    }
}

fn idx(kind: NotifyType) -> usize {
    match kind {
        NotifyType::Info => 0,
        NotifyType::Success => 1,
        NotifyType::Warning => 2,
        NotifyType::Failure => 3,
    }
}

impl Asset {
    /// Persist stores under `path` in `mode` (builder style).
    #[must_use]
    pub fn with_storage(mut self, path: impl Into<PathBuf>) -> Self {
        self.storage_path = Some(path.into());
        self
    }

    /// Image URL for `kind` at `size`; `None` when images are disabled.
    pub fn image_url(&self, kind: NotifyType, size: ImageSize) -> Option<String> {
        self.image_url_ext(kind, size, None)
    }

    /// Like [`Asset::image_url`], with an explicit `{EXTENSION}` value (`None` uses `default_extension`).
    pub fn image_url_ext(&self, kind: NotifyType, size: ImageSize, ext: Option<&str>) -> Option<String> {
        let mask = self.image_url_mask.as_deref()?;
        Some(self.substitute(mask, kind, size, ext))
    }

    /// The icon file a local notifier shows for `kind`, first match wins: the [`Asset::image_path_mask`] file, the app's [`Asset::image_bytes`] when they are JPEG or PNG, or the bundled icon with `ext` (`svg` or `png`). The last two are written under the temporary directory by the transport (`Command::file`). `None` when the mask is empty.
    pub fn icon_file(&self, kind: NotifyType, ext: &str) -> Option<IconFile> {
        let dir = std::env::temp_dir().join("mercurio");
        let app = self.image_bytes.and_then(|b| image_ext(b).map(|e| (b, e)));
        if self.image_bytes.is_some() && app.is_none() {
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| log::warn!("Asset::image_bytes is neither JPEG nor PNG; using the bundled icon."));
        }
        let (name, bytes) = match (self.image_path_mask.as_deref(), app) {
            (Some(""), _) => return None,
            (Some(mask), _) => {
                return Some(IconFile { path: self.substitute(mask, kind, ImageSize::Xy256, None), bundled: None });
            }
            (None, Some((b, e))) => (format!("icon-{}.{e}", crate::crypto::hex(&crate::crypto::sha256(b)[..8])), b),
            (None, None) => (format!("icon.{ext}"), if ext == "svg" { ICON_SVG } else { ICON_PNG }),
        };
        Some(IconFile { path: dir.join(name).to_string_lossy().into_owned(), bundled: Some(bytes) })
    }

    /// Logo URL; `None` when `image_url_logo` is unset.
    pub fn logo_url(&self) -> Option<String> {
        let mask = self.image_url_logo.as_deref()?;
        Some(self.substitute(mask, NotifyType::Info, ImageSize::Xy256, None))
    }

    fn substitute(&self, mask: &str, kind: NotifyType, size: ImageSize, ext: Option<&str>) -> String {
        let re = crate::regex!(r"(?i)\{(THEME|TYPE|XY|EXTENSION)\}");
        re.replace_all(mask, |c: &crate::re::Captures| match c[1].to_ascii_uppercase().as_str() {
            "THEME" => self.theme.clone(),
            "TYPE" => kind.as_str().to_string(),
            "XY" => size.as_str().to_string(),
            _ => ext.unwrap_or(&self.default_extension).to_string(),
        })
        .into_owned()
    }

    /// Hex colour like `#3AA3E3`.
    pub fn color(&self, kind: NotifyType) -> &str {
        &self.colors[idx(kind)]
    }

    /// Colour as an integer (`0x3AA3E3`).
    pub fn color_int(&self, kind: NotifyType) -> u32 {
        u32::from_str_radix(self.color(kind).trim_start_matches('#'), 16).unwrap_or(0)
    }

    /// Colour as `(r, g, b)`.
    pub fn color_rgb(&self, kind: NotifyType) -> (u8, u8, u8) {
        let v = self.color_int(kind);
        ((v >> 16) as u8, (v >> 8) as u8, v as u8)
    }

    /// ASCII marker like `[i]`.
    pub fn ascii(&self, kind: NotifyType) -> &str {
        &self.ascii[idx(kind)]
    }
}

/// The file extension of JPEG or PNG bytes, told by their signature; `None` for anything else.
fn image_ext(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("jpeg")
    } else {
        None
    }
}

/// An icon file for a local notifier ([`Asset::icon_file`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IconFile {
    /// Where the notifier reads it.
    pub path: String,
    /// The bytes the transport writes to `path` first (the bundled icon or [`Asset::image_bytes`]); `None` for a user file.
    pub bundled: Option<&'static [u8]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP_PNG: &[u8] = b"\x89PNG\r\n\x1a\napp icon";

    #[test]
    fn icon_file_prefers_mask_then_app_icon_then_bundled() {
        let mut a = Asset { image_bytes: Some(APP_PNG), ..Asset::default() };
        let app = a.icon_file(NotifyType::Info, "svg").unwrap();
        assert_eq!(app.bundled, Some(APP_PNG));
        let name = std::path::Path::new(&app.path).file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(name, format!("icon-{}.png", crate::crypto::hex(&crate::crypto::sha256(APP_PNG)[..8])));

        a.image_path_mask = Some("/icons/{TYPE}.png".into());
        assert_eq!(
            a.icon_file(NotifyType::Info, "png").unwrap(),
            IconFile { path: "/icons/info.png".into(), bundled: None }
        );

        a.image_path_mask = Some(String::new());
        assert_eq!(a.icon_file(NotifyType::Info, "png"), None);

        let bundled = Asset::default().icon_file(NotifyType::Info, "svg").unwrap();
        assert_eq!(bundled.bundled, Some(ICON_SVG));
        assert!(bundled.path.ends_with("icon.svg"));
    }

    #[test]
    fn app_icon_extension_follows_its_format() {
        let jpeg: &'static [u8] = &[0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10];
        let a = Asset { image_bytes: Some(jpeg), ..Asset::default() };
        let f = a.icon_file(NotifyType::Info, "png").unwrap();
        assert!(f.path.ends_with(".jpeg") && f.bundled == Some(jpeg));

        // Anything but JPEG or PNG falls back to the bundled icon.
        let a = Asset { image_bytes: Some(b"<svg xmlns='http://www.w3.org/2000/svg'/>"), ..Asset::default() };
        let f = a.icon_file(NotifyType::Info, "png").unwrap();
        assert!(f.path.ends_with("icon.png") && f.bundled == Some(ICON_PNG));
    }
}
