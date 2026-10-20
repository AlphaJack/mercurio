# HTTP server

`mercurio serve` runs an HTTP notification API in the same binary. Clients
send a message to the URLs in the request (stateless) or to a
configuration stored on the server under a key (stateful). There is no web
UI.

```sh
mercurio serve                          # listens on 127.0.0.1:8000
mercurio serve --bind 0.0.0.0:8000 -v   # all interfaces, warnings too
```

There is no TLS: bind to localhost or put a reverse proxy in front. Turn
on [authentication](#authentication) before exposing it. The
[install page](install.md) has a container image and a systemd unit.

## Settings

Every setting is a flag of `mercurio serve` and an environment variable
(named as in apprise-api); the flag wins. Boolean values are true when they
start with `y`, `t`, `1`, `e`, `a` or `+`. `--bind ADDR` (default
`127.0.0.1:8000`) sets the listen address. From `mercurio serve --help`:

```text
{{#include generated/serve-settings.txt}}
```

URL and host rules (`APPRISE_ATTACH_*_URL`) are separated by spaces or
commas. A rule is a host (`*.example.com`, `cdn.net:8080`), a URL with an
optional path prefix (`https://example.com/files/`, `example.com/files/`),
or `internal` for every address that is not public (loopback, private,
link-local). `*` matches any run of characters, `?` one.

Limits: request bodies up to 64 MiB (`413` beyond), 512 requests in progress
(more get `503` with `Retry-After: 1`). A request head, and each piece of a
body, must arrive within 30 s.

## Request log

Every request is one line on stderr, with the fields that apply:

```text
2026-10-20T13:53:41.630353Z  INFO request: method="POST" route="/notify/{key}" status=424 duration_ms=35.555 remote=127.0.0.1 key="k1" apprise_id="chain-1" bytes_in=41 services=2 failed=1 error="One or more notification could not be sent" detail="skipped bogus://x/...: unsupported URL scheme: bogus://"
```

`route` is the matched path (absent for a `404`), `key` the Config ID
used, `services` and `failed` count the services notified, `error` is the
message of an error answer and `detail` lists problems that did not fail
the request. A live stream logs `stream=true`; its results are not in the
line. A `/status` or `/metrics` request that succeeds (the container's
health check, a metrics scrape) is not logged. `-v` adds warnings, `-vv`
everything at INFO, `-vvv` debug output.

## Endpoints

```text
{{#include generated/serve-endpoints.txt}}
```

Keys are 1 to 128 letters, digits, `_` or `-`; a path with any other key is
`404`. Paths work with or without a trailing slash. A known path with the
wrong method returns `405` with an `Allow` header.

`/details` describes each service as Apprise's `details()` does: URL
`templates`, `tokens`, `args` and `kwargs`, plus a `setup_url` that links to
its page in this book.

`/add`, `/get`, `/del`, `/move`, `/json/urls` and `/auth` also work without
the key in the path: send it in an `X-Apprise-Config-ID` header instead,
which keeps it out of access logs. The header wins over a key in the path;
an invalid header is `400`.

## Requests

Every POST accepts form fields (`application/x-www-form-urlencoded`), a JSON
object (`Content-Type: application/json`) or `multipart/form-data` (text
parts are fields, file parts attachments).

```text
{{#include generated/serve-fields.txt}}
```

### Plain text bodies

A notification can also be the whole request body. The content type sets
its format: `text/plain`, `text/html` or `text/markdown`; `?format=` wins.

```sh
curl -X POST -H 'Content-Type: text/plain' -H 'X-Apprise-Tag: devops' \
    --data-raw 'Deployment completed' http://127.0.0.1:8000/notify/demo
```

### Headers

```text
{{#include generated/serve-headers.txt}}
```

When a field comes from several places, the first found wins: the payload,
then the header, then the query string (`?title=`, `?type=`, `?format=`,
`?tag=`). Header values must be ASCII.

### Field mapping

Query parameters starting with `:` rename payload fields before they are
read, for senders that can not use these names:

| Rule | Effect |
|---|---|
| `?:subject=title` | the `subject` field becomes `title` |
| `?:debug=` | the `debug` field is removed |
| `?:type=warning` | `type` is set to `warning` |
| `?:event.items[0].text=body` | a nested value (dots and `[index]`, at most 5 steps) becomes `body`; a missing path is `400` |

```sh
curl -X POST -H 'Content-Type: application/json' \
    -d '{"subject": "CPU", "event": {"state": "critical"}}' \
    'http://127.0.0.1:8000/notify/demo?:subject=title&:event.state=body'
```

### Tags

| `tag` | Notifies |
|---|---|
| absent | stored configuration: entries without tags; stateless: everything |
| `devops` | entries tagged `devops` |
| `devops critical` (also `&`, `+`) | entries tagged both |
| `dev, qa` (also `\|`) | entries tagged `dev` or `qa` |
| `leaders teamA, leaders teamB` | (`leaders` and `teamA`) or (`leaders` and `teamB`) |
| `all` | everything |

Entries tagged `always` are included whenever a tag is given. A JSON list is
a list of alternatives; a nested list is an AND group. Characters other than
letters, digits, `_`, `-`, `:` and the separators are `400`.

### Attachments

Multipart file parts become attachments (type from the part, else the file
name). URLs are downloaded by the server after the URL rules allow them;
anything that is not `http(s)://` (a server-local path, `file://`) is
refused, so clients can never read files on the server. Any problem with an
attachment is `400 Bad Attachment` (the reason is logged).

## Responses

The response format follows `Accept`, and, without one (or with `*/*`), the
request's content type:

- JSON (`application/json`): errors are `{"error": "..."}`; successes of
  `/add`, `/del`, `/move` are `{"error": null}`;
- otherwise plain text.

Notifications answer with their log, one line per service
(`2026-10-17 12:00:00,000 - INFO - Sent json:// (JSON) notification.`); a
JSON failure is
`{"error":"One or more notifications could not be sent","details":[[level, time, message], ...]}`.
With `Accept: text/html` the log is an HTML list (`<ul class="logs">`).

### Live progress

`?stream=yes` or `Accept: text/event-stream` answers with server-sent
events as the services finish: `log` events, `: heartbeat` comments every
15 s while waiting and one final `result` event.

```text
: connected

event: log
data: {"asctime":"2026-10-17 12:00:00,000","level":"INFO","message":"Sent json:// (JSON) notification.","service":"json"}

event: result
data: {"status":"SUCCESS"}
```

The status is `SUCCESS`, `PARTIAL`, `FAILURE`, `NOMATCH` or `TIMEOUT`.
Streams beyond the [stream limits](#settings) get `503` with
`Retry-After: 15`.

### Result webhook

With `APPRISE_WEBHOOK_URL`, every notification POSTs
`{"source": "<client address>", "status": 0 | 1, "output": [[level, time, message], ...]}`
to that URL (credentials in the URL become Basic Auth).

## Stored configurations

`/add/{key}` stores either `urls` (saved as TEXT, only the URLs that parse)
or a `config` in TEXT or YAML. A configuration with no usable URL is still
saved; YAML that can not be read at all is `400`. `/add` answers with
`X-Apprise-Config-Created`, `X-Apprise-Config-MTime` and
`X-Apprise-Timezone` headers (UTC).

| `APPRISE_STATEFUL_MODE` | Files |
|---|---|
| `hash` | `<dir>/<h[0..2]>/<h[2..]>.text` or `.yaml`, gzip compressed, `h = sha224(SECRET_KEY + key)` |
| `simple` | `<dir>/<key>.cfg` or `<key>.yml`, plain text |
| `disabled` | none; stateful endpoints answer `403` |

Beside each entry: `.<name>.created` (creation time) and `.<name>.lock`
(the key's login). The layout is the one the existing API servers use, so
their configuration directory can be mounted as it is (with the same
`SECRET_KEY` in `hash` mode).

`/get` returns YAML as `text/yaml`, TEXT as `text/plain` or
`{"format", "config"}` as JSON; `204` when nothing is stored. `/del` returns
`200`; `204` when nothing was stored. `/notify/{key}` without a stored
configuration is `404`.

`/json/urls/{key}` lists every entry:

```json
{
  "tags": ["devops", "home"],
  "urls": [
    {"id": "1a2b3c4d", "service_name": "JSON", "enabled": true,
     "url": "json://127.0.0.1:8766/ops", "retry": 0, "optional": false,
     "tags": ["devops"],
     "tag_details": [{"name": "devops", "priority": 0, "token": "devops", "exact": "0:devops"}],
     "template": {}}
  ]
}
```

`?privacy=yes` hides everything after the host of each URL. `template` maps
each `${NAME}` of the entry to its configuration default (`null` with
`privacy` or `APPRISE_CONFIG_LOCK`). `?tag=` filters, comma separated.

Stored configurations go through the library's configuration loader: tags,
groups, `${NAME}` templates (values from the request, the configuration
defaults, then `APPRISE_TEMPLATE_<NAME>`) and `include`, which may only
point at `http(s)://`.

## Authentication

With `APPRISE_AUTH_REQUIRED=yes` every request needs Basic Auth:

- the administrator (`APPRISE_USER` / `APPRISE_PASSWORD`) may do
  everything;
- a key's own login may use that key (in the path or
  `X-Apprise-Config-ID`), `/status` and `/details`;
- anything else is `401` with `WWW-Authenticate`.

Each key has one access mode:

| Access | Effect |
|---|---|
| `user` | its login may read, change and clear the configuration; tags optional; may send stateless notifications with `X-Apprise-Config-ID` |
| `locked` | its login may only notify, with a specific tag (not `all`); content hidden |
| `public` | anyone may `POST /notify/{key}` with a specific tag; everything else needs a login |
| `disabled` | only the administrator may use the key (`403` otherwise) |

```sh
# The administrator gives a key its own login; the key's user may later
# change the password (not the access). GET reads it, DELETE removes it.
curl -u admin:pw -H 'Content-Type: application/json' \
    -d '{"access": "user", "username": "alice", "password": "s3cret"}' http://127.0.0.1:8000/auth/team
```

`APPRISE_CONFIG_LOCK` turns `user` into `locked` without changing what is
saved. It allows reading or changing configuration content only to the
administrator. Logins are stored as salted PBKDF2-SHA256 digests;
successful checks are remembered for five minutes. Without
`APPRISE_AUTH_REQUIRED`, saved logins are ignored and `/auth` answers `403`.

## Status codes

| Code | Meaning |
|---|---|
| 200 | sent, saved, deleted, moved or the requested data |
| 204 | nothing stored for the key (`/get`, `/cfg/{key}`, `/del`, `/json/urls`) |
| 400 | bad payload, key, header, tag, template, format or attachment; no URLs; no body and no attachment |
| 401 | Basic Auth missing or wrong |
| 403 | refused by a mode, the lock or the key's access |
| 404 | unknown path or key; no stored configuration for `/notify/{key}` |
| 405 | known path, wrong method |
| 406 | `X-Apprise-Recursion-Count` above the limit |
| 409 | `/move` to a key that is taken |
| 413 | request body over 64 MiB |
| 417 | `/status` found a problem (`CONFIG_PERMISSION_ISSUE`, `STORE_PERMISSION_ISSUE`) |
| 424 | at least one notification failed; nothing matched the tag |
| 500 | the configuration or login could not be saved or read |
| 503 | too many requests or live streams in progress |
