# Tags

| Where | Syntax |
|---|---|
| TEXT file | `devops, critical=ntfy://alerts` (commas and/or spaces before `=`) |
| YAML, one entry | `tag: devops, critical` or `tag: [devops, critical]` under the URL |
| YAML, every entry | top-level `tag: home` |
| Groups | TEXT `oncall = devops, critical`; YAML `groups:` |
| Any URL | `?tag=devops,critical` (mercurio extension) |
| Library | `?tag=` or `Target::with_tags(...)` before `Mercurio::push` |

Tags are case-insensitive (stored lower-cased), made of letters, digits,
`_` and `-`; duplicates are removed. In a configuration file, `?tag=` values
are added to the entry's tags.

## Selecting services on the command line

| Command | Notifies |
|---|---|
| no `-g` | only services **without** tags; every URL given on the command line |
| `-g devops` | services tagged `devops` |
| `-g "devops,critical"` or `-g "devops critical"` | services tagged `devops` **and** `critical` |
| `-g devops -g critical` | services tagged `devops` **or** `critical` |
| `-g "a,b" -g c` | (`a` and `b`) or `c` |
| `-g all` | every service, tagged or not |

- `all` as a filter matches everything; do not use it as a tag name.
- Services tagged `always` join every tagged run (any `-g`), not the run
  without `-g`.
- When nothing matches, mercurio prints `no URLs matched the given tags`
  and exits with code 3.
- The library's `TagFilter::parse("a,b")` and the HTTP server's `tag=a,b`
  mean `a` **or** `b`; the server's `tag=a b` means both. See
  [Using the library](../library/index.md#configuration-tags-and-templates).

## Groups

A group is a tag that stands for other tags (TEXT `group = tag1, tag2`,
YAML `groups:`). Every entry with a member tag also gets the group name,
so `-g group` selects them all. Groups may contain groups (expanded
recursively, loops ignored). Assigning to an existing group adds
members. `mercurio -d` shows each entry's expanded tags:

```yaml
version: 1
groups:
  - oncall: devops, critical
  - oncall: database
urls:
  - json://localhost/a:
      tag: database
  - json://localhost/c:
      tag: always
  - json://localhost/d
```

```text
$ mercurio -d -c tags.yml -g oncall
   1. json://localhost/...
      tags: database, oncall
   2. json://localhost/...
      tags: always
```

## Priorities

A tag may carry a priority prefix, `2:ops`. A filter with a priority
(`-g 2:ops`) matches only services whose `ops` tag has priority 2; a plain
filter (`-g ops`) matches every priority. All matched services are notified
together. A filter's retry suffix (`-g ops:3`) is ignored; in configuration
files a tag with one (`ops:3`) is rejected. Use `?retry=` in the URL.
