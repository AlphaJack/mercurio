//! Key/value store per target.
//!
//! Services cache tokens, sessions and lookups between sends. Every [`Target`](crate::Target) owns one namespace, named after its URL id (a SHA-256 of the URL's identifying parts), so several URLs with the same credentials share it.
//!
//! Without a storage path (or with `?store=no`) entries live as long as the target. With one, the store is read from disk before the target's first send, and entries saved with [`Store::set`] are written back before each I/O step of a send and after it; [`Store::remember`] keeps a value (an access token) in memory only. The reads and writes are [`FileOp`]s run on the transport.
//!
//! ```text
//! <storage_path>/<url_id>/cache.json   saved entries
//! <storage_path>/<url_id>/tmp/         staging area for atomic writes
//! <storage_path>/<url_id>/var/         files services keep (keys, subscriptions)
//! ```
//!
//! `cache.json` maps keys to `{"v": value, "x": expiry_unix_secs|null, "!": checksum}`; an entry whose checksum does not match is dropped on load, as in Apprise. Files are created `0600` (directories `0700`), written to `tmp/` and renamed into place.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde_json::{Value, json};

use crate::crypto;
use crate::plan::Plan;
use crate::transport::{FileOp, FileOutput};

/// Values are JSON. A `null` value reads back as `Some(Value::Null)`; services treat it like a missing key.
pub trait Store: Send + Sync + fmt::Debug {
    /// The value for `key`, unless it is missing or expired.
    fn get(&self, key: &str) -> Option<Value>;

    /// Save `value` under `key`; `expires` is relative to now (`None`: never). Returns `true` once the value is held in memory; a failed write to disk is logged when the store is flushed.
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

    /// The file steps that read the store from disk, once; run before a send.
    #[doc(hidden)]
    fn load(self: Arc<Self>) -> Plan {
        Plan::Done
    }

    /// The file steps that write unsaved changes to disk; run between the steps of a send and after it.
    #[doc(hidden)]
    fn flush(self: Arc<Self>) -> Plan {
        Plan::Done
    }
}

/// Shared handle to a [`Store`]; cheap to clone into plan continuations.
pub type StoreRef = Arc<dyn Store>;

/// Caches untouched for this long are removed by `mercurio storage prune`: 31 days.
pub const DEFAULT_FILE_EXPIRY: Duration = Duration::from_secs(2_678_400);

/// Name of the cache file inside a namespace directory.
pub const CACHE_FILE: &str = "cache.json";
/// Directory of a namespace where writes are staged before they replace a file.
pub const STAGING_DIR: &str = "tmp";
/// Directory of a namespace for the files services keep (keys, subscriptions).
pub const DATA_DIR: &str = "var";

/// Entry expiry runs on the real clock: it is bookkeeping, not request content.
#[expect(clippy::disallowed_methods, reason = "store expiry is bookkeeping, not request content")]
fn now() -> f64 {
    crate::env::system().unix_time_f64()
}

/// Namespaces and keys: an alphanumeric first character, then alphanumerics, `.`, `_`, `-`.
pub fn is_valid_key(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Hex characters of an entry's SHA-256 kept as its checksum, as in Apprise.
const HASH_LENGTH: usize = 6;

/// The checksum of a saved entry: the leading [`HASH_LENGTH`] hex characters of the SHA-256 of `<value JSON>:<expiry>`.
fn checksum(value: &Value, expires: Option<f64>) -> String {
    let x = expires.map_or_else(|| "never".to_owned(), |x| x.to_string());
    let mut sum = crypto::hex(&crypto::sha256(format!("{value}:{x}").as_bytes()));
    sum.truncate(HASH_LENGTH);
    sum
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
/// The store itself does no I/O. A target's sends read it from disk first and write entries saved with [`Store::set`] back as they go; [`Store::remember`] keeps a value in memory only.
///
/// ```
/// use std::time::Duration;
/// use mercurio::{store::PersistentStore, store::Store};
/// use serde_json::json;
///
/// let store = PersistentStore::memory();
/// store.set("token", json!("secret"), Some(Duration::from_secs(3600)));
/// assert_eq!(store.get_str("token").as_deref(), Some("secret"));
/// ```
pub struct PersistentStore {
    /// The namespace directory; `None` keeps everything in memory.
    base: Option<PathBuf>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    entries: BTreeMap<String, Entry>,
    /// The cache file was read (or reading it was attempted).
    loaded: bool,
    /// Saved entries changed since the last flush.
    dirty: bool,
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
        Self { base: path.filter(|_| valid).map(|p| p.join(namespace)), state: Mutex::default() }
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
}

/// The saved entries of a cache file and whether any were dropped (malformed or failing their checksum); `None` when the file is corrupt.
fn parse_cache(bytes: &[u8]) -> Option<(BTreeMap<String, Entry>, bool)> {
    let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(bytes) else { return None };
    let total = map.len();
    let entries: BTreeMap<_, _> = map
        .into_iter()
        .filter_map(|(k, v)| {
            let expires = match v.get("x") {
                None | Some(Value::Null) => None,
                Some(x) => Some(x.as_f64()?),
            };
            let value = v.get("v")?.clone();
            if v.get("!").and_then(Value::as_str) != Some(checksum(&value, expires).as_str()) {
                log::debug!("tampering detected with cache entry {k:?}");
                return None;
            }
            Some((k, Entry { value, expires, saved: true }))
        })
        .collect();
    let dropped = entries.len() < total;
    Some((entries, dropped))
}

impl Store for PersistentStore {
    fn get(&self, key: &str) -> Option<Value> {
        lock(&self.state).entries.get(key).filter(|e| e.live()).map(|e| e.value.clone())
    }

    fn set(&self, key: &str, value: Value, expires: Option<Duration>) -> bool {
        let entry = Entry { value, expires: expires.map(|d| now() + d.as_secs_f64()), saved: true };
        let mut st = lock(&self.state);
        // Rewriting an identical, non-expiring entry changes nothing.
        if entry.expires.is_none() && st.entries.get(key) == Some(&entry) {
            return true;
        }
        st.entries.insert(key.to_string(), entry);
        st.dirty = true;
        true
    }

    fn remember(&self, key: &str, value: Value, expires: Option<Duration>) {
        let entry = Entry { value, expires: expires.map(|d| now() + d.as_secs_f64()), saved: false };
        lock(&self.state).entries.insert(key.to_string(), entry);
    }

    fn clear(&self, keys: &[&str]) -> bool {
        let mut st = lock(&self.state);
        let changed = if keys.is_empty() {
            let saved = st.entries.values().any(|e| e.saved);
            st.entries.clear();
            saved
        } else {
            let mut changed = false;
            for k in keys {
                changed |= st.entries.remove(*k).is_some_and(|e| e.saved);
            }
            changed
        };
        st.dirty |= changed;
        true
    }

    fn keys(&self) -> Vec<String> {
        lock(&self.state).entries.keys().cloned().collect()
    }

    fn path(&self) -> Option<PathBuf> {
        self.base.clone()
    }

    /// Stat and read the cache file; a corrupt one is removed, a good one touched so pruning keeps it while it is in use.
    fn load(self: Arc<Self>) -> Plan {
        let Some(file) = self.cache_file() else { return Plan::Done };
        if std::mem::replace(&mut lock(&self.state).loaded, true) {
            return Plan::Done;
        }
        Plan::file(FileOp::Stat { path: file.clone() }, move |stat| {
            if let Err(e) = &stat {
                log::warn!("could not load persistent cache {}: {e}", file.display());
            }
            if !matches!(stat, Ok(FileOutput::Meta(Some(_)))) {
                return Plan::Done;
            }
            Plan::file(FileOp::Read { path: file.clone(), max: 0 }, move |read| {
                let bytes = match read {
                    Ok(FileOutput::Bytes(b)) => b,
                    Ok(_) => return Plan::Done,
                    Err(e) => {
                        log::warn!("could not load persistent cache {}: {e}", file.display());
                        return Plan::Done;
                    }
                };
                let Some((disk, dropped)) = parse_cache(&bytes) else {
                    log::warn!("corrupted persistent cache content: {}", file.display());
                    return Plan::file(FileOp::Remove { path: file }, |_| Plan::Done);
                };
                let mut st = lock(&self.state);
                // Rewrite the file without the dropped entries on the next flush.
                st.dirty |= dropped;
                for (k, e) in disk {
                    st.entries.entry(k).or_insert(e);
                }
                Plan::file(FileOp::Touch { path: file }, |_| Plan::Done)
            })
        })
    }

    /// Write the saved, live entries (or remove the file when there are none).
    fn flush(self: Arc<Self>) -> Plan {
        let mut st = lock(&self.state);
        let (Some(base), Some(file)) = (&self.base, self.cache_file()) else { return Plan::Done };
        if !std::mem::take(&mut st.dirty) {
            return Plan::Done;
        }
        let saved: BTreeMap<&String, Value> = st
            .entries
            .iter()
            .filter(|(_, e)| e.saved && e.live())
            .map(|(k, e)| (k, json!({"v": e.value, "x": e.expires, "!": checksum(&e.value, e.expires)})))
            .collect();
        if saved.is_empty() {
            return Plan::file(FileOp::Remove { path: file }, |_| Plan::Done);
        }
        let Ok(data) = serde_json::to_vec(&saved) else { return Plan::Done };
        let failed = move |file: PathBuf| {
            log::warn!("could not write persistent cache {}", file.display());
            Plan::Done
        };
        Plan::file(FileOp::CreateDir { path: base.join(DATA_DIR), private: true }, move |res| match res {
            Ok(_) => {
                Plan::file(FileOp::WriteAtomic { path: file.clone(), data, private: true }, move |res| match res {
                    Ok(_) => Plan::Done,
                    Err(_) => failed(file),
                })
            }
            Err(_) => failed(file),
        })
    }
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
    use crate::testing::FakeTransport;
    use crate::testing::run_files;

    fn disk(fake: &FakeTransport, ns: &str) -> StoreRef {
        let s = PersistentStore::new(Some(Path::new("/data")), ns).shared();
        run_files(s.clone().load(), fake);
        s
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
    fn flush_writes_saved_entries_and_load_reads_them() {
        let fake = FakeTransport::new();
        let s = disk(&fake, "ns");
        s.set("a", json!({"x": 1}), None);
        s.remember("token", json!("secret"), None);
        run_files(s.clone().flush(), &fake);
        let file = PathBuf::from("/data/ns/cache.json");
        let text = String::from_utf8(fake.files()[&file].clone()).unwrap();
        assert!(text.contains("\"a\"") && !text.contains("secret"), "{text}");
        assert!(fake.file_ops().contains(&FileOp::CreateDir { path: "/data/ns/var".into(), private: true }));

        let again = disk(&fake, "ns");
        assert_eq!(again.get("a"), Some(json!({"x": 1})));
        assert_eq!(again.get("token"), None);
        assert_eq!(fake.file_ops().last(), Some(&FileOp::Touch { path: file.clone() }));
        again.clear(&[]);
        run_files(again.flush(), &fake);
        assert!(!fake.files().contains_key(&file));
    }

    #[test]
    fn load_and_flush_run_once() {
        let fake = FakeTransport::new();
        let s = disk(&fake, "ns");
        run_files(s.clone().load(), &fake);
        run_files(s.clone().flush(), &fake);
        assert_eq!(fake.file_ops(), vec![FileOp::Stat { path: "/data/ns/cache.json".into() }]);
    }

    #[test]
    fn corrupt_cache_is_removed() {
        let fake = FakeTransport::new();
        fake.file("/data/ns/cache.json", "not json");
        let s = disk(&fake, "ns");
        assert!(s.keys().is_empty());
        assert!(fake.files().is_empty());
    }

    #[test]
    fn entries_failing_their_checksum_are_dropped() {
        let fake = FakeTransport::new();
        let good = checksum(&json!("tok"), None);
        assert_eq!(good.len(), HASH_LENGTH);
        let text = json!({
            "good": {"v": "tok", "x": null, "!": good},
            "edited": {"v": "forged", "x": null, "!": good},
            "unsigned": {"v": "tok", "x": null},
        });
        fake.file("/data/ns/cache.json", text.to_string());
        let s = disk(&fake, "ns");
        assert_eq!(s.keys(), vec!["good"]);
        run_files(s.flush(), &fake);
        let text = String::from_utf8(fake.files()[&PathBuf::from("/data/ns/cache.json")].clone()).unwrap();
        assert!(text.contains("good") && !text.contains("forged") && !text.contains("unsigned"), "{text}");
    }

    #[test]
    fn checksums_survive_a_json_round_trip() {
        let fake = FakeTransport::new();
        let s = disk(&fake, "ns");
        let keys: Vec<String> = (0..2000).map(|i| format!("k{i}")).collect();
        for (i, k) in keys.iter().enumerate() {
            let secs = 3600.0 + f64::from(u32::try_from(i).unwrap()) * 0.123_456_789;
            s.set(k, json!(secs), Some(Duration::from_secs_f64(secs)));
        }
        run_files(s.flush(), &fake);
        assert_eq!(disk(&fake, "ns").keys().len(), keys.len());
    }

    #[test]
    fn invalid_namespace_uses_memory() {
        let s = PersistentStore::new(Some(Path::new("/data")), "../x");
        assert!(s.path().is_none());
        assert!(s.set("a", json!(1), None));
    }
}
