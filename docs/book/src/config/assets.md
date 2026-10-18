# Asset overrides

The asset is the application identity shared by all services: the name
sent as `User-Agent` and sender, the description and URL some services
show, the per-type images and where persistent state is kept. A YAML
configuration can override it (TEXT files cannot):

```yaml
version: 1
asset:
  app_id: Backup Bot
  image_url_mask: https://img.example.com/{THEME}/{TYPE}-{XY}{EXTENSION}
  storage_path: ~/.cache/backup-bot
urls:
  - json://localhost:8080/hook
```

{{#include ../generated/asset-keys.md}}

## Keys without effect

{{#include ../generated/asset-ignored.md}}
Use `-e`, `-Da` or `?redirect=no` for what some of them
control. Keys starting or ending with `_` are ignored with a warning;
unknown keys (including `interpret_emojis`, `storage_mode`, `storage_salt`,
`storage_idlen`) and values of the wrong type are rejected with a warning
(`WARNING - Invalid asset key "storage_mode".`, visible with
`mercurio check -v`).

## Scope

- The overrides apply to every service of that configuration and its
  includes; when several files of one load set a key, the last one read
  wins.
- They do not affect other `-c` sources or URLs on the command line.
- They override the CLI's `--storage-path` and the library's `Asset` for
  those services. They only take effect when they set at least one key
  from the table.
- In the library, `Config::asset_for(&base)` returns the asset a
  configuration applies on top of `base`.
