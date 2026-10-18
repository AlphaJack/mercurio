# Includes

A configuration can pull in other sources, to share services between
machines or keep secrets in a file with tighter permissions.

```text
include /etc/apprise/shared.yml
include secrets.conf
include https://config.example.com/get/team
critical=json://localhost:9000/local
```

```yaml
version: 1
include:              # or a single string
  - /etc/apprise/shared.yml
  - secrets.conf
urls:
  - json://localhost:9000/local
```

Each included source has its own format, detected as for `-c`
([Sources](index.md#sources)). The including file's services load first,
then each include's, in the order written.

| Include | Resolved as |
|---|---|
| `relative/path.conf` | relative to the including file's directory (for HTTP sources: the current directory) |
| `/absolute/path.yml`, `~/path` | that file |
| `file:///path?format=yaml` | that file, format forced |
| `http://...`, `https://...` | fetched with `POST`, like `-c` |

`memory://` and any other scheme are skipped with a warning.

## Depth

Includes are followed to a limited depth, so loops end. Includes inside an
included file count against the same depth.

| Caller | Default | Change it with |
|---|---|---|
| CLI | 1: the files you name and the files they include | `-R N` (`-R 0` ignores `include`) |
| HTTP server | 1 | `APPRISE_RECURSION_MAX` |
| Library | 0: includes ignored | `ConfigOptions { recursion: N, .. }` |

## Which source may include which

Local files may include anything. HTTP sources and in-memory sources
(library `Config::from_text`, configurations stored on the server) may only
include HTTP(S) sources, so a remote configuration server cannot make the
loader read local files. A forbidden include is skipped with a warning
(`Including file:// based configuration is prohibited. Ignoring URL
file:///...`). The library can lift this with
`ConfigOptions::insecure_includes`; the CLI cannot.

Every included source has the same 128 KiB limit. Asset overrides from an
included YAML file apply to all services of the load.
