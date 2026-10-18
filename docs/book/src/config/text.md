# TEXT format

One entry per line:

```text
# Lines starting with # or ; are comments
; this too

# Untagged: notified when mercurio runs without --tag
json://localhost:8080/untagged

# One or more tags before '=' (separated by commas and/or spaces)
devops=ntfy://ntfy.example.com/alerts
devops, critical=mailtos://user:pass@example.com?to=oncall@example.com
family kitchen=kodi://user:pass@kitchen.local

# Groups: name = tags (a group may contain other groups)
team = devops, family
everyone = team, critical

include /etc/apprise/extra.conf
```

| Line | Meaning |
|---|---|
| empty, `# ...`, `; ...` | ignored |
| `URL` or `=URL` | a service without tags |
| `tags=URL` | a service with tags, separated by commas and/or spaces |
| `group = tag, tag` | a tag group (no `://` on the right-hand side) |
| `include SOURCE` | another configuration source, see [Includes](includes.md) |

- A URL starts with a scheme of 1 to 32 letters or digits followed by
  `://`; the rest of the line, trimmed, is the URL. Line endings may be
  `\n` or `\r\n`.
- Tags are letters, digits, `_`, `-` and `:`, lower-cased. A trailing `:N`
  (a retry count, `ops:3`) rejects the tag and its line's URL with a
  warning; use `?retry=3`. A leading `N:` (`2:ops`) is a
  [priority](tags.md#priorities).
- **One line that matches no rule invalidates the whole file**
  (`ERROR - Invalid TEXT configuration format found on line 2.`).
- A URL that does not parse or that its service rejects is skipped with a
  warning; the other lines still load.

## Groups

`name = tag1, tag2` gives every entry carrying `tag1` or `tag2` the extra
tag `name`. Groups may name groups (expanded recursively). A group listed
twice adds to its members. Group lines can appear anywhere. With the
example above `mercurio -d -c alerts.txt -g team` selects the ntfy, mailtos
and kodi entries, each with `team` and `everyone` among its tags. See
[Tags](tags.md).

## What TEXT cannot express

Every service setting fits in the URL's query string, so TEXT can configure
every service. It lacks YAML's settings written outside the URL (no
percent-encoding), one URL expanded into several services, file-wide tags,
`asset:` overrides and `${NAME}` templates.
