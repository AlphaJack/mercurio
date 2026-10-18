# Configuration files

A configuration file lists notification URLs once, with tags, so commands
and programs only say which group to notify. Two formats share tags,
`include`, groups and (YAML only) `${NAME}` templates:

| Format | Use it for |
|---|---|
| [TEXT](text.md) | one URL per line, optional tags |
| [YAML](yaml.md) | settings per URL, one URL expanded into several services, file-wide tags, [asset overrides](assets.md), [templates](templates.md) |

```yaml
# ~/.config/apprise/apprise.yml
version: 1
urls:
  - ntfys://ntfy.example.com/alerts:
      tag: devops
  - mailtos://user:pass@example.com:
      to: oncall@example.com
      tag: devops, critical
```

```text
# the same in TEXT: ~/.config/apprise/apprise.conf
devops=ntfys://ntfy.example.com/alerts
devops, critical=mailtos://user:pass@example.com?to=oncall@example.com
```

```sh
mercurio -g critical -b "Disk full"
```

The command line reads the [default files](../cli.md#where-services-come-from)
when no URL, `-c` or `APPRISE_URLS` is given.

## Sources

`-c` (repeatable) and `include` accept:

| Source | Example | Format |
|---|---|---|
| local path | `~/alerts.yml`, `./alerts.conf` | YAML when the name ends in `.yml` or `.yaml`, TEXT otherwise |
| `file://` URL | `file:///etc/alerts?format=yaml` | as above; `?format=text` or `?format=yaml` forces one |
| `http://`, `https://` | `https://config.example.com/get/team` | YAML for `Content-Type` `text/yaml`, `text/x-yaml`, `application/yaml`, `application/x-yaml`, TEXT otherwise; `?format=` forces one |

`~` is expanded in paths. On a bare path `?format=` becomes part of the
file name. HTTP sources are fetched with `POST`; `user:pass@` becomes Basic
authentication, `?+Header=value` adds a header and `?verify=no` disables
certificate checks.

## Checking a configuration

`mercurio check -c FILE` loads the file and prints one line per service.
The loader keeps the valid entries of a file and drops invalid ones with a
warning, so a service that seems to be missing is explained by `-v`:

```text
$ mercurio check -v -c alerts.yml
WARNING - Could not load URL discord://only-a-token/... (YAML entry #3, item #1): Discord: an invalid Discord Webhook Token was specified
ok   ntfys:// (ntfy) (template: host, topic)
ok   json:// (JSON) (template: topic)
```

`mercurio -d -c FILE -g TAG` applies the tag filter and template values and
lists what would be notified, with each entry's tags.

## Limits

- A source larger than 128 KiB is rejected, includes too.
- Files must be UTF-8.
- A file that fails to parse as a whole (invalid YAML, a TEXT line that
  matches no rule) yields no services; the error is logged.

The same loader is `mercurio::Config` and `Mercurio::add_config` in the
[library](../library/index.md).
