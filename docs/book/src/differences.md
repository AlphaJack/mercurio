# Differences with Apprise

mercurio aims to accept every Apprise URL and configuration file; sending
byte-for-byte the same requests is not a goal. Each entry reads: what Apprise
does -> what mercurio does -> status, where *intentional* means it stays that
way and *todo* means it could be added. Differences of a single service are
on its page (see the [service list](services/index.md)), taken from the
`# Differences with Apprise` section of its module docs.

## General

- **Markdown.** Apprise renders with the Python `markdown` package ->
  mercurio renders CommonMark plus GFM tables (`pulldown-cmark`); ordinary
  Markdown gives the same HTML, edge cases differ (headings with seven or
  more `#`, some entities, list continuation lines). *intentional*
- **Request throttle.** Apprise waits 5.5 s between requests to the same
  service (`NotifyBase.request_rate_per_sec`) -> mercurio keeps only the
  explicit per-plugin throttles and drops the inherited default. *intentional*
- **Basic auth without a password.** Apprise's `requests` sends
  `user:None` -> mercurio sends `user:`. *intentional*
- **URL parser.** Apprise checks hosts in `parse_url` and turns `+` in
  query values into a space for Office 365 -> mercurio leaves host checks
  to the services that connect and never turns `+` into a space. *intentional*
- **`?tag=` on a URL.** Apprise ignores it -> mercurio tags the URL for
  `--tag` / `TagFilter`; in a configuration file the values are added to
  the entry's tags. *intentional*
- **`?emojis=`, `-j`, `interpret_emojis`.** Apprise expands `:shortcode:`
  emoji -> mercurio sends text as written and ignores the parameter, except
  `discord://?emojis=no`, which escapes `:name:` as Apprise does. *todo*
- **`%2F` in a URL path.** Both decode it into a separator, so
  `json://`, `xml://` and `form://` request another path (Apprise issue
  #1799). Keeping it encoded for every service would also change xmpp
  JIDs and signalgrid channels. *todo*
- **`?tz=`.** Apprise validates the name against a time zone database ->
  mercurio passes it to the services that read it without validating;
  e-mail `Date:` and syslog timestamps are UTC. *todo*
- **`?optional=`.** Parsed by both; no effect in mercurio. *intentional*
- **Overflow.** Apprise lets each plugin tune overflow (`overflow_*`
  attributes), numbers split pieces (`[01/03]`) and may repeat the title ->
  mercurio uses one policy: title on the first piece only, no counters,
  `truncate` keeps the first piece `split` would produce. *intentional*
- **Malformed HTML** (for example a malformed `<![` section). Apprise
  fails the notification -> mercurio fails too when the core converts it,
  but the Pushover and Telegram reducers send it unreduced. *intentional*
- **Upstream bugs.** Where Apprise's behaviour is clearly a bug mercurio
  does the correct thing; see the service entries for e-mail, IFTTT, IRC,
  Plivo, PushWard, Remote Syslog, SMPP and Synology Chat. Also fixed without
  an entry of their own: target order in Bark, ntfy and MQTT, LaMetric
  `sound=thunder`, Slack gov webhook query
  parameters, Mattermost webhook ports, Matrix `!id:None` room ids and
  `null` GET bodies, Office 365 re-sending an expired token on login,
  Burst SMS `country=US`, Twitter `mode=DM`, VoIP.ms stopping on one bad
  reply, Home Assistant `svc:a,b,c` lists and `storage prune` deleting
  Apprise's `*.psdata` files.
  *intentional*
- **Not available.** Pickling a loaded notifier, internationalised
  messages (`i18n`). *intentional* Apprise's `async_notify` is
  `AsyncMercurio::notify`.

## CLI

- **Default input format.** Apprise's CLI assumes `text` -> mercurio passes
  the body through when `-i` is not given; `-i text` gives Apprise's
  behaviour. *intentional*
- **`-e`.** Apprise runs its full escape decoder -> the CLI decodes `\n`,
  `\r`, `\t` and `\\` only (`Asset::interpret_escapes` in the library runs
  the full decoder). *intentional*
- **`-g` with URLs on the command line.** Apprise ignores it and notifies
  all of them -> mercurio filters them by their `?tag=` values. *intentional*
- **No services** (nothing given, nothing configured) exits with 2.
  *intentional*
- **Not implemented:** `-P/--plugin-path` (register custom services from
  Rust), `-T/--theme`, `-j/--interpret-emojis`, `-SM/--storage-mode`,
  `-D/--debug` (use `-vvv`). *todo* for `-T`, `-SM`; *intentional* for the
  rest.
- **`-d`** does not print storage URL ids; use `mercurio storage`.
  *intentional*
- **`check`, `serve`, `services`** are mercurio subcommands. *intentional*

## Server

- **Web UI.** apprise-api serves a web UI (`/`, login/logout, `/qr`,
  `/cfg/@`, themes, `APPRISE_API_ONLY`) -> mercurio has none: those paths
  are `404` and the setting is ignored. *intentional*
- **Non-ASCII header values** (UTF-8 titles in `X-Apprise-Title`).
  apprise-api gets them as WSGI Latin-1 strings -> mercurio decodes them as
  UTF-8, as Latin-1 only when they are not valid UTF-8. *intentional*
- **Basic Auth credentials.** apprise-api decodes them as UTF-8, so a
  non-ASCII password from Apprise Mobile (which sends Latin-1) fails ->
  mercurio decodes them as UTF-8, as Latin-1 only when they are not valid
  UTF-8. *intentional*
- **Translated messages.** apprise-api translates its error and status
  messages by `Accept-Language` or cookie and sets `Content-Language` ->
  mercurio answers in English only. *intentional*
- **Returned logs.** Both return the library's own log lines for the
  request's level and stream them live while sending. mercurio's lines
  have their own wording, redact URLs, and add one INFO or ERROR line per
  finished service; `APPRISE_WEBHOOK_URL` gets INFO and up. *intentional*
- **Persistent storage.** apprise-api prunes storage and logins on a
  schedule -> mercurio uses a different layout and no automatic pruning;
  `APPRISE_STORAGE_UID_LENGTH` works the same. *todo*
- **Workers.** apprise-api sizes gunicorn by `WORKER_COUNT` /
  `WORKER_TIMEOUT` -> mercurio allows 512 requests in flight and a 30 s
  socket timeout. *intentional*
- **Request log.** apprise-api logs requests through nginx (`combined`
  format) plus `NOTIFY - ip - ...` warnings -> mercurio logs one line per
  request with its key, services, failures and error. *intentional*
- **Unknown paths.** apprise-api answers `404` with an error message ->
  mercurio answers an empty `404`, before authentication; its `405`
  `Allow` header omits `OPTIONS`. *intentional*
- **Metrics.** apprise-api exports the full `django_prometheus` set ->
  mercurio exports a subset plus one latency histogram. *todo*
- **Other settings.** Plugin paths and `INTERPRET_EMOJIS` are ignored.
  *todo*; plugin paths *intentional*
- **Logins and times.** apprise-api accepts argon2 and bcrypt password
  hashes and reports times in the `TZ` zone -> mercurio stores PBKDF2-SHA256
  only and reports UTC. *todo* (hashes), *intentional* (UTC)
- **JSON `/add` without `format`.** apprise-api rejects it -> mercurio
  detects TEXT or YAML. *intentional*
- **Stored configurations** cannot include local files; attachment fields
  only accept `http(s)://` URLs (a local path is a `400`). *intentional*

## Config and YAML

- **Results.** The loader matches Apprise on 326 of 329 recorded
  configurations and 424 of 431 YAML documents; the rest are below.
- **`${NAME}` in an e-mail port.** Apprise's e-mail parser drops the host
  and the marker with it, so the port is ignored -> mercurio keeps the
  entry pending and rejects a non-numeric value when it is resolved.
  *intentional*
- **Self-referencing YAML anchor.** Apprise rejects only that entry ->
  mercurio rejects the whole document. *intentional*
- **YAML parser** (`saphyr-parser` plus a composer instead of PyYAML):
  several documents (`---`), custom `!tags` and collection keys are
  rejected; explicit `? key` entries are not supported; timestamps stay
  strings; `1`, `1.0` and `true` are three distinct keys; tabs are accepted
  as separators and trailing whitespace; `=` is a plain string; a quoted
  continuation line less indented than its block is an error. *intentional*
- **`asset:` keys.** `storage_path` is accepted in configuration files (a
  mercurio extension; Apprise takes it only as a constructor argument);
  `interpret_emojis` is rejected with a warning; keys mercurio has no use
  for (`interpret_escapes`, `async_mode`, `encoding`, `image_path_*`, ...)
  are accepted without effect; the defaults name mercurio
  (`app_id: Mercurio`). *intentional*

## Storage

- **File format.** Apprise writes gzip `cache.psdata` -> mercurio writes
  plain JSON `cache.json`; neither reads the other's file (prune and clear
  remove both). *intentional*
- **Modes.** Apprise has `auto`, `flush` and `memory` -> mercurio writes
  saved entries on every change; entries carry no checksum and there is no
  size cap. *todo* (`-SM`)
- **`mercurio storage list`** shows every configured URL, including
  services that never store anything (`unused`); Apprise omits them.
  *intentional*
- **`${NAME}` template targets** are rebuilt per call, so their in-memory
  store does not outlive the call. *intentional*
- **Rate-limit state** (Bluesky, Mastodon, Reddit, Twitter) is kept per
  send, not across sends. *todo*
- **Remote stores.** Store I/O is local only. *intentional*

## Attachments

- **`?+Header=`** on an attachment URL. Apprise sends it as a header and a
  query parameter -> mercurio only as a header. *intentional*
- **Downloads.** Apprise streams to a temporary file and stops early ->
  mercurio buffers the body, then checks the size. *todo*
- **Split messages.** Apprise plugins can pick the piece that carries the
  attachments (`_attachment_send_index`) -> mercurio always sends them with
  the first piece. *intentional*

## Retries

- **Policy.** Apprise retries every failure `?retry=` times after a fixed
  `?wait=` and ignores `Retry-After` -> mercurio retries only rate limits
  (429, 503 with `Retry-After`) and transient failures (408, 5xx, DNS and
  connect errors). It stops on authentication errors, other 4xx and
  failures after the request was sent. It honours `Retry-After` up to
  300 s. *intentional*
- **`?wait=`.** Apprise defaults to 0 -> mercurio defaults to 0.5 s. Both
  cap it at 20 s. *intentional*
- **Unclassified failures.** `Error::Service` failures (for example a JSON
  body with `"ok": false`) and `register_scheme` closures are not retried.
  *intentional*
- **Service hints.** Apprise reads neither Telegram's
  `parameters.retry_after` nor Matrix's `retry_after_ms` -> mercurio feeds
  both into the retry loop as the 429's wait (Matrix once its own back-off
  gives up). *intentional*

## Services

- **Microsoft Teams (`msteams://`).** Apprise's retired plugin is not
  provided; use `workflows://`. *intentional*

## Later

- Alertmanager / Grafana webhook receiver mode (fan-out to URLs).
- Upload the notify-type image instead of sending its URL (`image=yes`,
  Telegram).
