# YAML format

YAML adds what one-line URLs cannot express: settings written next to the
URL, several services from one URL, file-wide tags, asset overrides and
`${NAME}` templates.

```yaml
version: 1

# Tags added to every URL in this file
tag: home

asset:
  app_id: Backup Bot

groups:
  oncall: devops, critical

urls:
  # A plain URL
  - json://localhost:8080/plain

  # A URL with settings: each key becomes ?key=value
  - ntfys://ntfy.example.com/alerts:
      tag: devops
      priority: high
      format: markdown

  # A list under one URL creates one service per entry
  - mailtos://user:pass@example.com:
      - to: oncall@example.com
        tag: critical
      - to: boss@example.com
        tag: always
        name: Backup Bot

  # Header and payload groups
  - json://localhost:8080/hook:
      tag: devops
      headers:
        X-Token: abc123
      payload:
        message: text
```

## Top-level keys

{{#include ../generated/yaml-top-level.md}}

Other top-level keys are ignored, which makes them a convenient place for
YAML anchors (see [Anchors](#anchors-aliases-and-merge-keys)).

A file-wide `tag:` tags every entry, so nothing in that file is notified
when Mercurio runs without `--tag` (only untagged entries are). The example
above prints `no URLs matched the given tags` (exit code 3) without
`-g`.

## The `urls` list

Each item is a URL string, a URL with a mapping of settings (one service)
or a URL with a list of mappings (one service per item, each with its own
settings: one account, several recipients). A URL with nothing after the
colon is the plain string form.

## How settings are applied

Settings are folded into the URL's query string, so any parameter of a
[service page](../services/index.md) or the
[common parameters](../url-parameters.md) can be written as a setting.

{{#include ../generated/yaml-settings.md}}

Rules:

- A setting overrides the same parameter written in the URL.
- Writing any `+` setting (or `headers:`) replaces all the URL's own `+`
  parameters; the same holds for `-` (`params:`) and `:` (`payload:`).
- `user` and `password` also replace `?user=` / `?pass=` in the URL.
- Keys must start with a letter or digit (or one of the prefixes). Other
  keys are ignored with a warning. So is a mapping given as the value of
  an ordinary key.

Because the loader encodes values, credentials with `@`, `/` or `:` need
no escaping. Settings can also complete a URL that does not parse on its own:

```yaml
urls:
  - json://:
      host: localhost
      port: 8080
      user: bob
      password: "p@ss/word"
```

## Groups

```yaml
groups:
  oncall: devops, critical
  everyone: [oncall, family]     # groups can contain groups
```

A list of single-key mappings works too. Naming a group again adds to
it. See [Tags](tags.md).

## Anchors, aliases and merge keys

Anchors (`&name`), aliases (`*name`) and merge keys (`<<`) work as in
YAML 1.1. Merged keys come first and the mapping's own keys override them.

```yaml
version: 1
defaults: &defaults
  tag: ops
  format: markdown
urls:
  - json://localhost/hook:
      <<: *defaults
      headers:
        X-Token: abc
  - ntfy://alerts:
      <<: *defaults
      priority: high
```

## Scalars

Values are read with YAML 1.1 rules:

- `yes`, `no`, `on`, `off`, `true`, `false` are booleans (and become
  `yes` / `no` in the URL). Quote them to keep them as text.
- Octal (`0755`), hex (`0x1F`), binary and sexagesimal (`1:30`) integers
  are numbers. Quote values such as phone numbers or IDs with leading zeros:
  `to: "0711234567"`.
- `~` and `null` are null.
