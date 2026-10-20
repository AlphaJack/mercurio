//! The persistent stores on disk, for `mercurio storage`: sizes, namespaces and pruning, on `tokio::fs`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mercurio::store::{CACHE_FILE, DATA_DIR, STAGING_DIR, is_valid_key};
use tokio::fs;

/// Bytes used by every file below `path`.
pub async fn dir_size(path: &Path) -> u64 {
    let mut total = 0;
    let mut dirs = vec![path.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        let Ok(mut entries) = fs::read_dir(&dir).await else { continue };
        while let Ok(Some(e)) = entries.next_entry().await {
            match e.file_type().await {
                Ok(t) if t.is_dir() => dirs.push(e.path()),
                Ok(t) if t.is_file() => total += e.metadata().await.map(|m| m.len()).unwrap_or(0),
                _ => {}
            }
        }
    }
    total
}

/// Namespaces (directories) under `path`, optionally only those starting with one of `prefixes`. Sorted.
pub async fn scan(path: &Path, prefixes: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(mut entries) = fs::read_dir(path).await else { return out };
    while let Ok(Some(e)) = entries.next_entry().await {
        let Ok(name) = e.file_name().into_string() else { continue };
        if e.file_type().await.is_ok_and(|t| t.is_dir())
            && is_valid_key(&name)
            && (prefixes.is_empty() || prefixes.iter().any(|p| name.starts_with(p.as_str())))
        {
            out.push(name);
        }
    }
    out.sort();
    out
}

/// One file found by [`prune`].
pub struct Pruned {
    pub path: PathBuf,
    /// Deleted (not a dry run, and the delete worked).
    pub removed: bool,
}

/// Find (and with `action`, remove) store files under `path` not modified for `older_than`. Empty namespace directories are removed afterwards. `older_than == 0` matches everything.
pub async fn prune(
    path: &Path,
    prefixes: &[String],
    older_than: Duration,
    action: bool,
) -> BTreeMap<String, Vec<Pruned>> {
    let cutoff = SystemTime::now().checked_sub(older_than).unwrap_or(UNIX_EPOCH);
    let mut out = BTreeMap::new();
    for ns in scan(path, prefixes).await {
        let base = path.join(&ns);
        let (data, temp) = (base.join(DATA_DIR), base.join(STAGING_DIR));
        let mut files = vec![base.join(CACHE_FILE)];
        if let Ok(mut entries) = fs::read_dir(&temp).await {
            while let Ok(Some(e)) = entries.next_entry().await {
                files.push(e.path());
            }
        }
        let mut sweep = true;
        let mut records = Vec::new();
        for f in files {
            let Ok(meta) = fs::metadata(&f).await else { continue };
            if !meta.is_file() {
                continue;
            }
            let Ok(mtime) = meta.modified() else {
                sweep = false;
                continue;
            };
            if mtime > cutoff {
                continue;
            }
            let mut removed = false;
            if action {
                match fs::remove_file(&f).await {
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
            records.push(Pruned { path: f, removed });
        }
        if sweep && action {
            for d in [&temp, &data, &base] {
                fs::remove_dir(d).await.ok();
            }
        }
        out.insert(ns, records);
    }
    out
}
