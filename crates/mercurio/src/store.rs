//! Key/value store per target.
//!
//! Services cache tokens, sessions and lookups between sends. Every [`Target`](crate::Target) owns one namespace, named after its URL id (a SHA-256 of the URL's identifying parts), so several URLs with the same credentials share it.
//!
//! Without a storage path (or with `?store=no`) entries live as long as the target. With one, entries saved with [`Store::set`] are written to disk on every change; [`Store::remember`] keeps a value (an access token) in memory only.
//!
//! ```text
//! <storage_path>/<url_id>/cache.json   saved entries
//! <storage_path>/<url_id>/tmp/         staging area for atomic writes
//! <storage_path>/<url_id>/var/         files services keep (keys, subscriptions)
//! ```
//!
//! `cache.json` maps keys to `{"v": value, "x": expiry_unix_secs|null}`. Files are created `0600` (directories `0700`), written to `tmp/` and renamed into place.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

/// Values are JSON. A `null` value reads back as `Some(Value::Null)`; services treat it like a missing key.
pub trait Store: Send + Sync + fmt::Debug {
    /// The value for `key`, unless it is missing or expired.
    fn get(&self, key: &str) -> Option<Value>;

    /// Save `value` under `key`; `expires` is relative to now (`None`: never). Returns `false` when it could not be written.
    fn set(&self, key: &str, value: Value, expires: Option<Duration>) -> bool;

    /// Keep `value` under `key` in memory only (never written to disk).
    fn remember(&self, key: &str, value: Value, expires: Option<Duration>);

    /// Remove `keys`; an empty slice removes everything.
    fn clear(&self, keys: &[&str]) -> bool;

    /// Every key currently held, including expired ones.
    fn keys(&self) -> Vec<String>;

    /// The namespace directory, when disk-backed.
    fn path(&self) -> Option<PathBuf> {
        None
    }

    /// `true` when `key` holds a live (unexpired) entry.
    fn contains(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// The value for `key` when present and not `null`.
    fn get_some(&self, key: &str) -> Option<Value> {
        self.get(key).filter(|v| !v.is_null())
    }

    /// `get` as a string.
    fn get_str(&self, key: &str) -> Option<String> {
        self.get(key).and_then(|v| v.as_str().map(str::to_string))
    }
}

/// Shared handle to a [`Store`]; cheap to clone into plan continuations.
pub type StoreRef = Arc<dyn Store>;

/// Caches untouched for this long are removed by [`disk_prune`]: 31 days.
pub const DEFAULT_FILE_EXPIRY: Duration = Duration::from_secs(2_678_400);

/// Name of the cache file inside a namespace directory.
pub const CACHE_FILE: &str = "cache.json";
const TEMP_DIR: &str = "tmp";
const DATA_DIR: &str = "var";

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Namespaces and keys: an alphanumeric first character, then alphanumerics, `.`, `_`, `-`.
pub fn is_valid_key(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

#[derive(Debug, Clone, PartialEq)]
struct Entry {
    value: Value,
    expires: Option<f64>,
    /// Written to disk ([`Store::set`]) rather than kept in memory.
    saved: bool,
}

impl Entry {
    fn live(&self) -> bool {
        self.expires.is_none_or(|x| x > now())
    }
}

/// The built-in [`Store`]: memory or a JSON file per namespace.
///
/// Entries saved with [`Store::set`] are written to disk on every change; [`Store::remember`] keeps a value in memory only.
///
/// ```
/// use std::time::Duration;
/// use mercurio::{PersistentStore, Store};
/// use serde_json::json;
///
/// let dir = std::env::temp_dir().join(format!("mercurio-doc-{}", std::process::id()));
/// let store = PersistentStore::new(Some(&dir), "abcd1234");
/// store.set("token", json!("secret"), Some(Duration::from_secs(3600)));
/// assert_eq!(store.get_str("token").as_deref(), Some("secret"));
/// assert!(dir.join("abcd1234").join("cache.json").exists());
///
/// // A new store over the same directory sees the entry.
/// let again = PersistentStore::new(Some(&dir), "abcd1234");
/// assert_eq!(again.get_str("token").as_deref(), Some("secret"));
/// # std::fs::remove_dir_all(&dir).ok();
/// ```
pub struct PersistentStore {
    /// The namespace directory; `None` keeps everything in memory.
    base: Option<PathBuf>,
    /// Loaded from disk on first use.
    entries: Mutex<Option<BTreeMap<String, Entry>>>,
}

impl fmt::Debug for PersistentStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistentStore").field("path", &self.base).finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl PersistentStore {
    /// A store for `namespace` under `path`; in memory when `path` is `None`. An invalid namespace falls back to memory with a warning.
    pub fn new(path: Option<&Path>, namespace: &str) -> Self {
        let valid = is_valid_key(namespace);
        if path.is_some() && !valid {
            log::warn!("persistent storage namespace {namespace:?} is invalid; using memory");
        }
        // Directories are created on the first write, so URLs that never store anything leave no trace on disk.
        Self { base: path.filter(|_| valid).map(|p| p.join(namespace)), entries: Mutex::default() }
    }

    /// An in-memory store.
    pub fn memory() -> Self {
        Self::new(None, "memory")
    }

    /// Wrap into a [`StoreRef`].
    pub fn shared(self) -> StoreRef {
        Arc::new(self)
    }

    fn cache_file(&self) -> Option<PathBuf> {
        self.base.as_ref().map(|b| b.join(CACHE_FILE))
    }

    fn with<R>(&self, f: impl FnOnce(&mut BTreeMap<String, Entry>) -> R) -> R {
        let mut guard = lock(&self.entries);
        f(guard.get_or_insert_with(|| self.load()))
    }

    /// Read the cache file; a corrupt one is removed.
    fn load(&self) -> BTreeMap<String, Entry> {
        let Some(file) = self.cache_file() else { return BTreeMap::new() };
        let bytes = match std::fs::read(&file) {
            Ok(b) => b,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    log::warn!("could not load persistent cache {}: {e}", file.display());
                }
                return BTreeMap::new();
            }
        };
        // Keep the cache from being pruned while it is in use.
        if let Ok(f) = std::fs::File::options().write(true).open(&file) {
            f.set_modified(SystemTime::now()).ok();
        }
        let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(&bytes) else {
            log::warn!("corrupted persistent cache content: {}", file.display());
            std::fs::remove_file(&file).ok();
            return BTreeMap::new();
        };
        map.into_iter()
            .filter_map(|(k, v)| {
                let expires = match v.get("x") {
                    None | Some(Value::Null) => None,
                    Some(x) => Some(x.as_f64()?),
                };
                Some((k, Entry { value: v.get("v")?.clone(), expires, saved: true }))
            })
            .collect()
    }

    /// Write the saved, live entries (or remove the file when there are none).
    fn save(&self, entries: &BTreeMap<String, Entry>) -> bool {
        let (Some(base), Some(file)) = (&self.base, self.cache_file()) else { return true };
        let saved: BTreeMap<&String, Value> = entries
            .iter()
            .filter(|(_, e)| e.saved && e.live())
            .map(|(k, e)| (k, json!({"v": e.value, "x": e.expires})))
            .collect();
        if saved.is_empty() {
            return match std::fs::remove_file(&file) {
                Ok(()) => true,
                Err(e) => e.kind() == std::io::ErrorKind::NotFound,
            };
        }
        let Ok(text) = serde_json::to_vec(&saved) else { return false };
        let tmp = base.join(TEMP_DIR);
        let ok = [base.clone(), tmp.clone(), base.join(DATA_DIR)].iter().all(|d| create_private_dir(d).is_ok())
            && write_atomic(&tmp, &file, &text).is_ok();
        if !ok {
            log::warn!("could not write persistent cache {}", file.display());
        }
        ok
    }
}

impl Store for PersistentStore {
    fn get(&self, key: &str) -> Option<Value> {
        self.with(|entries| entries.get(key).filter(|e| e.live()).map(|e| e.value.clone()))
    }

    fn set(&self, key: &str, value: Value, expires: Option<Duration>) -> bool {
        let entry = Entry { value, expires: expires.map(|d| now() + d.as_secs_f64()), saved: true };
        let mut guard = lock(&self.entries);
        let entries = guard.get_or_insert_with(|| self.load());
        // Rewriting an identical, non-expiring entry changes nothing.
        if entry.expires.is_none() && entries.get(key) == Some(&entry) {
            return true;
        }
        entries.insert(key.to_string(), entry);
        self.save(entries)
    }

    fn remember(&self, key: &str, value: Value, expires: Option<Duration>) {
        let entry = Entry { value, expires: expires.map(|d| now() + d.as_secs_f64()), saved: false };
        self.with(|entries| entries.insert(key.to_string(), entry));
    }

    fn clear(&self, keys: &[&str]) -> bool {
        let mut guard = lock(&self.entries);
        let entries = guard.get_or_insert_with(|| self.load());
        let mut changed = false;
        if keys.is_empty() {
            changed = entries.values().any(|e| e.saved);
            entries.clear();
        } else {
            for k in keys {
                changed |= entries.remove(*k).is_some_and(|e| e.saved);
            }
        }
        !changed || self.save(entries)
    }

    fn keys(&self) -> Vec<String> {
        self.with(|entries| {
            let mut k: Vec<String> = entries.keys().cloned().collect();
            k.sort();
            k
        })
    }

    fn path(&self) -> Option<PathBuf> {
        self.base.clone()
    }
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

/// Write `data` to a fresh `0600` file in `tmp_dir`, sync it and rename it over `dest` (atomic on POSIX filesystems).
pub(crate) fn write_atomic(tmp_dir: &Path, dest: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = tmp_dir.join(format!(".{}-{}.tmp", std::process::id(), crate::crypto::random_hex(6)));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let res = opts.open(&tmp).and_then(|mut f| {
        f.write_all(data)?;
        f.sync_all()
    });
    let res = res.and_then(|()| std::fs::rename(&tmp, dest));
    if res.is_err() {
        std::fs::remove_file(&tmp).ok();
    }
    res
}

/// Write `data` to `path` as a private (`0600`) file, atomically, creating its directory (`0700`) first. For services that keep files next to their cache (keys, subscriptions).
pub fn write_private_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().ok_or_else(|| std::io::Error::other("no parent directory"))?;
    create_private_dir(dir)?;
    write_atomic(dir, path, data)
}

/// Bytes used by every file below `path`.
pub fn dir_size(path: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(path) else { return 0 };
    rd.flatten()
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => dir_size(&e.path()),
            Ok(t) if t.is_file() => e.metadata().map(|m| m.len()).unwrap_or(0),
            _ => 0,
        })
        .sum()
}

/// Namespaces (directories) under `path`, optionally only those starting with one of `prefixes`. Sorted.
pub fn disk_scan(path: &Path, prefixes: &[String]) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(path) else { return Vec::new() };
    let mut out: Vec<String> = rd
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| is_valid_key(n))
        .filter(|n| prefixes.is_empty() || prefixes.iter().any(|p| n.starts_with(p.as_str())))
        .collect();
    out.sort();
    out
}

/// One file found by [`disk_prune`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrunedFile {
    /// The file found.
    pub path: PathBuf,
    /// `true` when it was deleted (`false` for a dry run or a failed delete).
    pub removed: bool,
}

/// Find (and with `action`, remove) store files under `path` not modified for `older_than`. Empty namespace directories are removed afterwards. `older_than == 0` matches everything.
pub fn disk_prune(
    path: &Path,
    prefixes: &[String],
    older_than: Duration,
    action: bool,
) -> BTreeMap<String, Vec<PrunedFile>> {
    let cutoff = SystemTime::now().checked_sub(older_than).unwrap_or(UNIX_EPOCH);
    let mut out = BTreeMap::new();
    for ns in disk_scan(path, prefixes) {
        let base = path.join(&ns);
        let data = base.join(DATA_DIR);
        let temp = base.join(TEMP_DIR);
        let mut files = vec![base.join(CACHE_FILE)];
        files.extend(std::fs::read_dir(&temp).into_iter().flatten().flatten().map(|e| e.path()));
        let mut sweep = true;
        let mut records = Vec::new();
        for f in files.into_iter().filter(|p| p.is_file()) {
            let Ok(mtime) = std::fs::metadata(&f).and_then(|m| m.modified()) else {
                sweep = false;
                continue;
            };
            if mtime > cutoff {
                continue;
            }
            let mut removed = false;
            if action {
                match std::fs::remove_file(&f) {
                    Ok(()) => {
                        removed = true;
                        log::info!("removed persistent file {}", f.display());
                    }
                    Err(e) => {
                        log::error!("could not remove persistent file {}: {e}", f.display());
                        sweep = false;
                    }
                }
            }
            records.push(PrunedFile { path: f, removed });
        }
        if sweep && action {
            for d in [&temp, &data, &base] {
                std::fs::remove_dir(d).ok();
            }
        }
        out.insert(ns, records);
    }
    out
}

/// Per-notification scratch space shared by the retry attempts of one send (values to remember; delivery marks for services that track finer than per target). Disabled (no-op) when retries are off. Clones share the same slots.
#[derive(Debug, Default, Clone)]
pub struct Memo {
    slots: Option<Arc<Mutex<BTreeMap<String, Value>>>>,
}

impl Memo {
    /// A memo that forgets everything (retries disabled).
    pub const fn disabled() -> Memo {
        Memo { slots: None }
    }

    /// A memo that keeps values (retries enabled).
    pub fn enabled() -> Memo {
        Memo { slots: Some(Arc::new(Mutex::new(BTreeMap::new()))) }
    }

    /// `true` when an earlier attempt called [`Memo::mark_delivered`] for `key`.
    pub fn is_delivered(&self, key: &str) -> bool {
        self.recall(&format!("\u{0}delivered\u{0}{key}")).is_some()
    }

    /// Record that `key` accepted this notification.
    pub fn mark_delivered(&self, key: &str) {
        self.remember(&format!("\u{0}delivered\u{0}{key}"), Value::Bool(true));
    }

    /// Keep `value` for later attempts of this notification.
    pub fn remember(&self, key: &str, value: Value) {
        if let Some(m) = &self.slots {
            lock(m).insert(key.to_string(), value);
        }
    }

    /// What an earlier attempt remembered under `key`.
    pub fn recall(&self, key: &str) -> Option<Value> {
        self.slots.as_ref().and_then(|m| lock(m).get(key).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mercurio-store-{tag}-{}", crate::crypto::random_hex(6)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn keys() {
        assert!(is_valid_key("abc") && is_valid_key("a.b-c_1"));
        assert!(!is_valid_key("") && !is_valid_key("-a") && !is_valid_key("a/b"));
    }

    #[test]
    fn memory_get_set_expiry_clear() {
        let s = PersistentStore::memory();
        assert!(s.set("a", json!(1), None));
        s.remember("t", json!("tok"), None);
        assert!(s.set("old", json!(2), Some(Duration::ZERO)));
        assert_eq!(s.get("a"), Some(json!(1)));
        assert_eq!(s.get_str("t").as_deref(), Some("tok"));
        assert_eq!(s.get("old"), None);
        assert!(s.clear(&["a"]));
        assert_eq!(s.keys(), vec!["old", "t"]);
        assert!(s.clear(&[]));
        assert!(s.keys().is_empty());
    }

    #[test]
    fn saved_entries_survive_and_remembered_ones_do_not() {
        let dir = tmpdir("disk");
        let s = PersistentStore::new(Some(&dir), "ns");
        assert!(s.set("a", json!({"x": 1}), None));
        s.remember("token", json!("secret"), None);
        let file = dir.join("ns").join(CACHE_FILE);
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains("\"a\"") && !text.contains("secret"), "{text}");
        let again = PersistentStore::new(Some(&dir), "ns");
        assert_eq!(again.get("a"), Some(json!({"x": 1})));
        assert_eq!(again.get("token"), None);
        assert!(again.clear(&[]));
        assert!(!file.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_cache_is_dropped() {
        let dir = tmpdir("corrupt");
        std::fs::create_dir_all(dir.join("ns")).unwrap();
        std::fs::write(dir.join("ns").join(CACHE_FILE), b"not json").unwrap();
        let s = PersistentStore::new(Some(&dir), "ns");
        assert!(s.keys().is_empty());
        assert!(!dir.join("ns").join(CACHE_FILE).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn invalid_namespace_uses_memory() {
        let dir = tmpdir("invalid");
        let s = PersistentStore::new(Some(&dir), "../x");
        assert!(s.path().is_none());
        assert!(s.set("a", json!(1), None));
        std::fs::remove_dir_all(&dir).ok();
    }
}
