//! Stored configurations, in the compatible on-disk layout so an existing configuration directory can be mounted unchanged.
//!
//! - `hash` (default): `<dir>/<h[0..2]>/<h[2..]>.text|.yaml`, gzip compressed, where `h = sha224(SECRET_KEY + key)`.
//! - `simple`: `<dir>/<key>.cfg|.yml`, plain text.
//! - `disabled`: nothing is read or written.
//!
//! Next to each entry: `.<name>.created` (creation time marker) and `.<name>.lock` (per-key login, JSON `{"access", "username", "digest"}`).

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use mercurio::ConfigFormat;
use serde_json::{Value, json};
use tokio::fs;
use tokio::io::AsyncWriteExt;

use super::codec;

/// Largest stored configuration read back (decompressed).
const MAX_READ: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Hash,
    Simple,
    Disabled,
}

impl Mode {
    pub fn parse(v: &str) -> Option<Mode> {
        match v.trim().to_ascii_lowercase().as_str() {
            "hash" => Some(Mode::Hash),
            "simple" => Some(Mode::Simple),
            "disabled" => Some(Mode::Disabled),
            v => match v.as_bytes().first() {
                Some(b'h') => Some(Mode::Hash),
                Some(b's') => Some(Mode::Simple),
                Some(b'd') => Some(Mode::Disabled),
                _ => None,
            },
        }
    }
}

/// Outcome of removing something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cleared {
    Removed,
    Nothing,
    Failed,
}

/// Outcome of [`ConfigStore::move_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Moved {
    Done,
    NotFound,
    Conflict,
    Failed,
}

/// One per-key login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRecord {
    pub access: String,
    pub username: Option<String>,
    pub digest: Option<String>,
}

pub const ACCESS_USER: &str = "user";
pub const ACCESS_LOCKED: &str = "locked";
pub const ACCESS_PUBLIC: &str = "public";
pub const ACCESS_DISABLED: &str = "disabled";
pub const ACCESS_CHOICES: [&str; 4] = [ACCESS_USER, ACCESS_LOCKED, ACCESS_PUBLIC, ACCESS_DISABLED];

pub struct ConfigStore {
    pub root: PathBuf,
    pub mode: Mode,
    salt: String,
}

impl ConfigStore {
    pub fn new(root: PathBuf, mode: Mode, salt: String) -> Self {
        ConfigStore { root, mode, salt }
    }

    pub fn enabled(&self) -> bool {
        self.mode != Mode::Disabled
    }

    /// Directory and file stem for `key`.
    fn path(&self, key: &str) -> (PathBuf, String) {
        match self.mode {
            Mode::Hash => {
                let h = codec::sha224_hex(format!("{}{key}", self.salt).as_bytes());
                let (dir, rest) = h.split_at(2);
                (self.root.join(dir), rest.to_string())
            }
            Mode::Simple | Mode::Disabled => (self.root.clone(), key.to_string()),
        }
    }

    fn ext(&self, fmt: ConfigFormat) -> &'static str {
        match (self.mode, fmt) {
            (Mode::Hash, ConfigFormat::Text) => "text",
            (Mode::Hash, ConfigFormat::Yaml) => "yaml",
            (_, ConfigFormat::Text) => "cfg",
            (_, ConfigFormat::Yaml) => "yml",
        }
    }

    fn content_path(&self, key: &str, fmt: ConfigFormat) -> PathBuf {
        let (dir, name) = self.path(key);
        dir.join(format!("{name}.{}", self.ext(fmt)))
    }

    fn marker(&self, key: &str, suffix: &str) -> PathBuf {
        let (dir, name) = self.path(key);
        dir.join(format!(".{name}.{suffix}"))
    }

    /// The stored configuration: `Ok(None)` when there is none, `Err` when it could not be read.
    pub async fn get(&self, key: &str) -> Result<Option<(String, ConfigFormat)>, ()> {
        if !self.enabled() {
            return Ok(None);
        }
        for fmt in [ConfigFormat::Text, ConfigFormat::Yaml] {
            let path = self.content_path(key, fmt);
            if !is_file(&path).await {
                continue;
            }
            let raw = fs::read(&path).await.map_err(|_| ())?;
            let raw = if self.mode == Mode::Hash { codec::gunzip(&raw, MAX_READ).ok_or(())? } else { raw };
            return String::from_utf8(raw).map(|s| Some((s, fmt))).map_err(|_| ());
        }
        Ok(None)
    }

    /// Save `content` atomically, replacing the other format.
    pub async fn put(&self, key: &str, content: &str, fmt: ConfigFormat) -> bool {
        if !self.enabled() {
            return false;
        }
        let created = self.created(key).await;
        let data = if self.mode == Mode::Hash { codec::gzip(content.as_bytes()) } else { content.as_bytes().to_vec() };
        if write_atomic(&self.content_path(key, fmt), &data).await.is_err() {
            log::error!("could not save the configuration for KEY: {key}");
            return false;
        }
        let other = if fmt == ConfigFormat::Text { ConfigFormat::Yaml } else { ConfigFormat::Text };
        if remove(&self.content_path(key, other)).await == Cleared::Failed {
            remove(&self.content_path(key, fmt)).await;
            return false;
        }
        let marker = self.marker(key, "created");
        if !fs::try_exists(&marker).await.unwrap_or(false)
            && let Ok(f) = fs::File::create(&marker).await
            && let Some(t) = created
            && let Err(e) = f.into_std().await.set_modified(t)
        {
            log::debug!("could not keep the creation time of KEY {key}: {e}");
        }
        true
    }

    /// Remove the configuration (both formats and the creation marker).
    pub async fn clear(&self, key: &str) -> Cleared {
        if !self.enabled() {
            return Cleared::Nothing;
        }
        let mut result = Cleared::Nothing;
        for fmt in [ConfigFormat::Text, ConfigFormat::Yaml] {
            match remove(&self.content_path(key, fmt)).await {
                Cleared::Removed if result != Cleared::Failed => result = Cleared::Removed,
                Cleared::Failed => result = Cleared::Failed,
                Cleared::Removed | Cleared::Nothing => {}
            }
        }
        if result != Cleared::Failed && remove(&self.marker(key, "created")).await == Cleared::Failed {
            result = Cleared::Failed;
        }
        result
    }

    /// Creation time: the marker, else the oldest content file time.
    async fn created(&self, key: &str) -> Option<SystemTime> {
        if let Ok(t) = fs::metadata(self.marker(key, "created")).await.and_then(|m| m.modified()) {
            return Some(t);
        }
        let mut oldest = None;
        for f in [ConfigFormat::Text, ConfigFormat::Yaml] {
            if let Ok(t) = fs::metadata(self.content_path(key, f)).await.and_then(|m| m.modified()) {
                oldest = Some(oldest.map_or(t, |o: SystemTime| o.min(t)));
            }
        }
        oldest
    }

    /// `(created, modified)` of the stored configuration.
    pub async fn file_times(&self, key: &str) -> Option<(SystemTime, SystemTime)> {
        let mut found = None;
        for f in [ConfigFormat::Text, ConfigFormat::Yaml] {
            if let Ok(m) = fs::metadata(self.content_path(key, f)).await {
                found = Some(m);
                break;
            }
        }
        let modified = found?.modified().ok()?;
        Some((self.created(key).await.unwrap_or(modified), modified))
    }

    /// Stored keys (`simple` mode only), including keys holding only a login.
    pub async fn keys(&self) -> Vec<String> {
        if self.mode != Mode::Simple {
            return Vec::new();
        }
        let mut keys = std::collections::BTreeSet::new();
        let Ok(mut entries) = fs::read_dir(&self.root).await else { return Vec::new() };
        while let Ok(Some(e)) = entries.next_entry().await {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(hidden) = name.strip_prefix('.') {
                if let Some(k) = hidden.strip_suffix(".lock").filter(|k| !k.is_empty()) {
                    keys.insert(k.to_string());
                }
                continue;
            }
            if is_file(&e.path()).await {
                let stem = Path::new(&name).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or(name);
                keys.insert(stem);
            }
        }
        keys.into_iter().collect()
    }

    /// Writable check used by `/status` (touches `<dir>/.tmp_hc`).
    pub async fn writable(&self) -> bool {
        writable(&self.root).await
    }

    fn lock_path(&self, key: &str) -> PathBuf {
        self.marker(key, "lock")
    }

    /// The saved login: `Ok(None)` when there is none, `Err` when unreadable.
    pub async fn auth(&self, key: &str) -> Result<Option<AuthRecord>, ()> {
        let text = match fs::read_to_string(self.lock_path(key)).await {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(()),
        };
        let v: Value = serde_json::from_str(text.trim()).map_err(|_| ())?;
        let access = v.get("access").and_then(Value::as_str).ok_or(())?.to_string();
        let opt = |k: &str| -> Result<Option<String>, ()> {
            match v.get(k) {
                Some(Value::Null) => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.clone())),
                _ => Err(()),
            }
        };
        let (username, digest) = (opt("username")?, opt("digest")?);
        let open = access == ACCESS_PUBLIC || access == ACCESS_DISABLED;
        if !ACCESS_CHOICES.contains(&access.as_str())
            || username.is_none() != digest.is_none()
            || (digest.is_none() && !open)
        {
            return Err(());
        }
        Ok(Some(AuthRecord { access, username, digest }))
    }

    pub async fn write_auth(&self, key: &str, rec: &AuthRecord) -> bool {
        let body = json!({"access": rec.access, "username": rec.username, "digest": rec.digest});
        write_atomic(&self.lock_path(key), body.to_string().as_bytes()).await.is_ok()
    }

    pub async fn clear_auth(&self, key: &str) -> Cleared {
        remove(&self.lock_path(key)).await
    }

    /// Refresh the login's age (a user cleared their configuration).
    pub async fn touch_auth(&self, key: &str) {
        if let Ok(f) = fs::OpenOptions::new().write(true).open(self.lock_path(key)).await
            && let Err(e) = f.into_std().await.set_modified(SystemTime::now())
        {
            log::debug!("could not refresh the login age of KEY {key}: {e}");
        }
    }

    /// Move configuration, login and creation marker to a free key.
    pub async fn move_key(&self, from: &str, to: &str) -> Moved {
        if !self.enabled() {
            return Moved::Failed;
        }
        let pairs: Vec<(PathBuf, PathBuf)> = vec![
            (self.content_path(from, ConfigFormat::Text), self.content_path(to, ConfigFormat::Text)),
            (self.content_path(from, ConfigFormat::Yaml), self.content_path(to, ConfigFormat::Yaml)),
            (self.lock_path(from), self.lock_path(to)),
            (self.marker(from, "created"), self.marker(to, "created")),
        ];
        let mut sources: Vec<&(PathBuf, PathBuf)> = Vec::new();
        let mut taken = false;
        for pair in &pairs {
            if is_file(&pair.0).await {
                sources.push(pair);
            }
            taken |= is_file(&pair.1).await;
        }
        if !sources.iter().any(|(s, _)| !s.ends_with(".created") && !s.to_string_lossy().ends_with(".created")) {
            return Moved::NotFound;
        }
        if taken {
            return Moved::Conflict;
        }
        let mut done: Vec<(&PathBuf, &PathBuf)> = Vec::new();
        for (src, dst) in sources {
            let parent_ok = match dst.parent() {
                Some(p) => fs::create_dir_all(p).await.is_ok(),
                None => false,
            };
            if !parent_ok || fs::hard_link(src, dst).await.is_err() {
                for (s, d) in done {
                    if fs::rename(d, s).await.is_err() {
                        log::error!("could not restore {}", s.display());
                    }
                }
                let mut taken = false;
                for (_, d) in &pairs {
                    taken |= is_file(d).await;
                }
                return if taken { Moved::Conflict } else { Moved::Failed };
            }
            if let Err(e) = fs::remove_file(src).await {
                log::warn!("could not remove {} after moving it: {e}", src.display());
            }
            done.push((src, dst));
        }
        Moved::Done
    }
}

/// `true` when `path` is a regular file.
async fn is_file(path: &Path) -> bool {
    fs::metadata(path).await.is_ok_and(|m| m.is_file())
}

/// Writable check used by `/status` (touches `<dir>/.tmp_hc`).
pub async fn writable(dir: &Path) -> bool {
    fs::create_dir_all(dir).await.is_ok() && fs::write(dir.join(".tmp_hc"), b"").await.is_ok()
}

async fn remove(path: &Path) -> Cleared {
    match fs::remove_file(path).await {
        Ok(()) => Cleared::Removed,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Cleared::Nothing,
        Err(_) => Cleared::Failed,
    }
}

/// Write to a hidden temporary file beside `path`, then rename it into place.
async fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir).await?;
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let tmp = dir.join(format!(".{}.{}.tmp", name.trim_start_matches('.'), mercurio::crypto::random_hex(6)));
    let result = async {
        let mut f = fs::File::create(&tmp).await?;
        f.write_all(data).await?;
        f.sync_all().await?;
        fs::rename(&tmp, path).await
    }
    .await;
    if result.is_err() && fs::remove_file(&tmp).await.is_err() {
        log::debug!("could not remove {}", tmp.display());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hash_layout_is_salted_sha224_shards() {
        let dir = std::env::temp_dir().join(format!("mercurio-store-{}", std::process::id()));
        let store = ConfigStore::new(dir.clone(), Mode::Hash, "salt".into());
        assert!(store.put("abc", "json://localhost", ConfigFormat::Text).await);
        // File name: sha224(salt + key), first two hex digits as a directory.
        let h = codec::sha224_hex(b"saltabc");
        let (sub, rest) = h.split_at(2);
        let file = dir.join(sub).join(format!("{rest}.text"));
        let raw = std::fs::read(&file).unwrap_or_default();
        assert_eq!(codec::gunzip(&raw, 1024).as_deref(), Some(&b"json://localhost"[..]));
        assert_eq!(store.get("abc").await, Ok(Some(("json://localhost".into(), ConfigFormat::Text))));
        assert!(store.put("abc", "urls: []", ConfigFormat::Yaml).await);
        assert!(!file.exists());
        assert_eq!(store.move_key("abc", "def").await, Moved::Done);
        assert_eq!(store.get("abc").await, Ok(None));
        assert_eq!(store.get("def").await.ok().flatten().map(|c| c.1), Some(ConfigFormat::Yaml));
        assert_eq!(store.clear("def").await, Cleared::Removed);
        assert_eq!(store.clear("def").await, Cleared::Nothing);
        std::fs::remove_dir_all(dir).ok();
    }
}
