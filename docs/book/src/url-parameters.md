# Common URL parameters

These query parameters work on every URL. Service-specific parameters are
on each [service page](services/index.md). In YAML configuration they can
also be written as settings under the URL.

{{#include generated/common-params.md}}

Boolean values accept `yes`, `true`, `on`, `1`, `enable`, `allow` and their
opposites (`no`, `false`, `off`, `0`, `disable`, `deny`, `never`),
case-insensitive.

## `format`

The caller declares the input format (`mercurio -i markdown`,
`Message::format`); Mercurio converts it to the service format. A service
with one format uses `?format=` if given, else its default. A service with
several formats uses `?format=` if it supports it, else the input format if
it supports that, else its default (the first one on its page). See
[Formats and conversion](messages/formats.md).

## `verify`, `redirect`, `cto`, `rto`

`?verify=no` disables certificate checks for that URL (self-signed
servers); attachment URLs and HTTP configuration URLs accept it too. To
trust a private CA instead, point `SSL_CERT_FILE` (or `REQUESTS_CA_BUNDLE`)
at a PEM bundle: it replaces the bundled Mozilla roots for every
connection, HTTP and socket services alike. The bundle is read once, at the
first TLS connection; restart `mercurio serve` (or your program) after
changing it.

Timeouts are decimal seconds (`?cto=2.5`). A value that is not a number
greater than zero falls back to the default.

## `retry` and `wait`

```sh
mercurio -b "disk full" "ntfy://alerts?retry=3&wait=2"
```

`retry` above 10 is capped and `wait` is clamped to 0–20 s. Mercurio only
repeats an attempt when repeating cannot deliver the message twice. Every
error has an `ErrorClass` (`mercurio::Error::class()`):

| Class | Comes from | Retried |
|---|---|---|
| `RateLimited { retry_after }` | HTTP 429; HTTP 503 with `Retry-After` | yes, after `max(wait, Retry-After)` |
| `Transient` | HTTP 408 and 5xx; DNS and connect failures (nothing was sent) | yes, after `wait` |
| `Auth` | HTTP 401, 403 | no |
| `InvalidTarget` | other 4xx; URL, configuration and message errors | no |
| `Unknown` | timeouts or resets after the request was sent, failures the service reported, unexpected statuses | no |

- An attempt with several errors (one per target) is retried only when
  every error is `RateLimited` or `Transient`.
- Services that make several requests name the failing step first
  (`login: HTTP 500: server error`); the class is that of the underlying
  error.
- `Retry-After` is read as seconds or as an IMF-fixdate HTTP date. Longer
  than `mercurio::service::MAX_RETRY_AFTER` (300 s) ends the retries instead of
  blocking. A 429 without it waits `wait`; Discord uses its
  `X-RateLimit-Reset` instead.
- Targets and pieces of a split message that an earlier attempt delivered
  are skipped and reported as delivered. Some services track finer state
  (Slack channel ids and uploads, Matrix rooms, HumHub post ids, Opsgenie
  and Jira batches). This tracking lasts one notification and is not
  written to disk.
- `-v` logs each retry (`WARNING - ntfy: attempt 1/4 failed; trying
  again`). In the library each attempt is in `ReportEntry::attempts`.

## `store`

`?store=no` keeps that URL's state (login tokens, lookups, sessions) in
memory, for as long as the target lives, even when a storage path is set.

## `tag`

`?tag=a,b` tags a URL given on the command line, in `APPRISE_URLS` or in
the library, so `--tag` / `TagFilter` can select it like a configuration
entry. In a configuration file the values are added to the entry's tags.

```sh
mercurio -g ops -b "on call" "ntfy://ops-alerts?tag=ops" "ntfy://everyone"   # only the first
```
