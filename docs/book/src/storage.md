# Persistent storage

Some services keep state between notifications (an OAuth token, a login
session, a channel lookup) in a small key/value store per URL, so the next
notification does not log in or look things up again:

| Service | What is stored | Kept for |
|---|---|---|
| Telegram | the bot owner (`bot_owner`) when no chat id is given | until removed |
| Opsgenie, Jira | request ids of open alerts | 60 days |
| Nextcloud | group member lookups | 1 day |
| SendPulse | access token | `expires_in` minus 10 s |
| WeChat | access token | `expires_in` minus 300 s; dropped on token errors |
| Office 365 | access token (memory only), sender `from`/`name`, rotated refresh token | token lifetime |
| Bluesky | resolved DID and service endpoint, session | session 3590 s |
| Mattermost | channel ids (`c:<channel>`) | 20 days |
| Vapid (Web Push) | generated key pair, `subscriptions.json`, retired (expired) endpoints | retired: 30 days |
| Matrix | login session, joined rooms, user lookups, end-to-end encryption keys (`?keystore=DIR` keeps this URL's store under `DIR`) | until removed or expired |
| Reddit, RingCentral, Emby, Jellyfin | session or token | lifetime of the target (memory only) |

Other services write nothing to disk.

## Where it lives

The command line uses persistent storage by default:

| | Default |
|---|---|
| Location | `~/.local/share/mercurio/cache` (`%APPDATA%/Mercurio/cache` on Windows) |
| Override | `-S PATH` / `--storage-path PATH`, else `$APPRISE_STORAGE_PATH` |
| Prune age | 30 days; `-SPD` / `--storage-prune-days` or `$APPRISE_STORAGE_PRUNE_DAYS` |

Each URL gets a namespace directory named after its URL id:

```text
<storage path>/<url id>/cache.json   the entries of this namespace
<storage path>/<url id>/tmp/         staging area for atomic writes
<storage path>/<url id>/var/         service files (Vapid keys and subscriptions)
```

`cache.json` maps each key to `{"v": value, "x": expiry}` (the expiry
in Unix seconds or `null`). The file is read before a URL's first
notification and rewritten during and after each notification that changed
it; there are no storage modes. Directories are created
on the first write with mode `0700`, files with `0600`. Files are written
to `tmp/` and renamed into place. A file that is not valid JSON is removed
with a warning. When no saved entry is left, `cache.json` is deleted.

Services can also keep a value in memory only (an access token, for
example): such entries are never written and live as long as the target.

Without a storage path (the library default) every store is in memory.
So are the stores of URLs with `?store=no` or of services that opt
out of URL ids.

## URL ids

The namespace is named by a URL id: a SHA-256 hash of the parts that
identify the account (scheme, user, password, host, port, path and the
secure flag), cut to 8 hexadecimal characters by default. Two URLs that differ only
in options share a namespace. Some services hash their own
parts instead (for example only the bot
token for Telegram).

`--storage-uid-length N` (`-SUL`, `APPRISE_STORAGE_UID_LENGTH`, at least
2; the server accepts 2 to 64) keeps N characters instead, which moves
every URL to a new namespace. In the library, `Asset::storage_idlen` (0
keeps all 64) and `Asset::storage_salt` (bytes hashed first) work like
Apprise's `storage_idlen` and `storage_salt`, so the ids match Apprise's
for the same settings.

`?store=no` keeps a URL's store in memory even when a storage path is set.

## `mercurio storage`

```text
mercurio storage [list|prune|clear] [UID-prefix...|URL...] [-S PATH] [-c CONFIG] [-g TAG] [-d]
```

The action may be abbreviated (`l`, `p`, `c`); `clean` is accepted for
`clear`. `list` is the default.

- `list`: URL ids of the configured services (from URLs on the command
  line, `-c`, `$APPRISE_URLS` or the default configuration files) next to
  what is on disk. Each row shows the size and a state: `active` (on disk
  and configured), `unused` (configured, nothing stored yet), `stale` (on
  disk, not configured; only shown when no `-g` is given).
- `prune`: remove store files not modified for `-SPD` days (default 30).
- `clear`: remove every store file.

Arguments containing `://` select URLs; other arguments are URL id
prefixes. `-g` restricts the action to tagged configuration entries. `-d`
shows what `prune` or `clear` would remove without removing it. Empty
namespace directories are removed after a prune.

```text
$ mercurio storage -S /tmp/demo/store "json://localhost/hook?tag=ci"
   1. e058d7a2                                             0.00B    unused
      - json://localhost/...
      tags: ci

$ mercurio storage prune -d -S /tmp/demo/store
abcdef12: would remove /tmp/demo/store/abcdef12/cache.json
```

Prune and clear only remove mercurio's own files; other files in a
namespace directory are left alone.

## In the library

`Mercurio::new()` keeps stores in memory. Give the `Asset` a storage path
to persist them:

```rust
use mercurio::{Asset, Mercurio};

let dir = std::env::temp_dir().join("mercurio-book-storage");
let mut m = Mercurio::new().asset(Asset::default().with_storage(&dir));
m.add("json://example.com/hook")?;
# Ok::<(), mercurio::Error>(())
```

A YAML configuration can set the path under `asset:` (`storage_path`, a
mercurio extension, see [Asset overrides](config/assets.md)). Each
`ReportEntry` carries the `url_id` of its target.

`mercurio::store::PersistentStore` is usable on its own; services read
their namespace as `Context::store`.
