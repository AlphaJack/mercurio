# Differences with Apprise

mercurio aims to accept every Apprise URL and configuration file; sending
byte-for-byte the same requests is not a goal. Each entry says what Apprise
does, what mercurio does instead, and a status: *intentional* means it stays
that way, *todo* means it could be added. Differences of a single service are
on its page (see the [service list](services/index.md)), taken from the
`# Differences with Apprise` section of its module docs.

## General

- **Markdown.** Apprise renders with the Python `markdown` package, while mercurio renders CommonMark plus GFM tables (`pulldown-cmark`); ordinary
  Markdown gives the same HTML, edge cases differ (headings with seven or
  more `#`, some entities, list continuation lines). *intentional*
- **Request throttle.** Apprise waits 5.5 s between requests to the same
  service (`NotifyBase.request_rate_per_sec`), while mercurio keeps only the
  explicit per-plugin throttles and drops the inherited default. *intentional*
- **Basic auth without a password.** Apprise's `requests` sends
  `user:None`, while mercurio sends `user:`. *intentional*
- **URL parser.** Apprise checks hosts in `parse_url` and turns `+` in
  query values into a space for Office 365, while mercurio leaves host checks
  to the services that connect and never turns `+` into a space. *intentional*
- **`?tag=` on a URL.** Apprise ignores it, while mercurio tags the URL for
  `--tag` / `TagFilter`; in a configuration file the values are added to
  the entry's tags. *intentional*
- **Emoji names.** Apprise expands `:shortcode:` from its own table, while mercurio uses GitHub's gemoji names (the `emojis` crate). They agree on
  1,843 of Apprise's 1,855 names; 10 give another emoji (`:grinning:` is
  😀, not 😄; `:beetle:` 🪲, not 🐞), `:blond_woman:` and
  `:information_deskperson:` stay as text, and about 70 gemoji names that
  Apprise lacks are expanded. *intentional*
- **`%2F` in a URL path.** Apprise decodes it into a separator, so
  `json://`, `xml://` and `form://` request another path (its issue #1799),
  while mercurio keeps it encoded for those three, so `a%2Fb` stays one path
  segment. Other services decode it as Apprise does (xmpp JIDs, signalgrid
  channels). *intentional*
- **`?tz=`.** Validated as in Apprise (the UTC family, any case, or the
  location alone such as `paris`; an unknown zone rejects the URL). E-mail
  `Date:` and syslog timestamps use it, else a YAML `asset:` `timezone`
  (or `tz`), else the machine's zone. *intentional*
- **`?optional=`.** Parsed by both; no effect in mercurio. *intentional*
- **Overflow.** Apprise lets each plugin tune overflow (`overflow_*`
  attributes), numbers split pieces (`[01/03]`) and may repeat the title, while mercurio uses one policy: title on the first piece only, no counters,
  `truncate` keeps the first piece `split` would produce. *intentional*
- **Malformed HTML** (for example a malformed `<![` section). Apprise
  fails the notification, while mercurio fails too when the core converts it,
  but the Pushover and Telegram reducers send it unreduced. *intentional*
- **Upstream bugs.** Where Apprise's behaviour is clearly a bug mercurio
  does the correct thing; see the service entries for e-mail, IFTTT, IRC,
  Mastodon, Plivo, PushWard, Reddit, Remote Syslog, SMPP and Synology Chat.
  Also fixed without
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

- **Default input format.** Apprise's CLI assumes `text`, while mercurio passes
  the body through when `-i` is not given; `-i text` gives Apprise's
  behaviour. *intentional*
- **`-e`.** Apprise runs its full escape decoder, while the CLI decodes `\n`,
  `\r`, `\t` and `\\` only (`Asset::interpret_escapes` in the library runs
  the full decoder). *intentional*
- **`-g` with URLs on the command line.** Apprise ignores it and notifies
  all of them, while mercurio filters them by their `?tag=` values. *intentional*
- **No services** (nothing given, nothing configured) exits with 2.
  *intentional*
- **Not implemented:** `-P/--plugin-path` (register custom services from
  Rust), `-D/--debug` (use `-vvv`). *intentional*
- **`-d`** does not print storage URL ids; use `mercurio storage`.
  *intentional*
- **`check`, `serve`, `services`** are mercurio subcommands. *intentional*

## Server

- **Alertmanager and Grafana webhooks.** apprise-api needs a field mapping
  and still cannot build a body from a list of alerts, while mercurio reads
  their webhook payloads directly on `/notify` (see
  [Alertmanager and Grafana webhooks](server.md#alertmanager-and-grafana-webhooks)).
  *intentional*
- **Web UI.** apprise-api serves a web UI (`/`, login/logout, `/qr`,
  `/cfg/@`, themes, `APPRISE_API_ONLY`), while mercurio has none: those paths
  are `404` and the setting is ignored. *intentional*
- **Non-ASCII header values** (UTF-8 titles in `X-Apprise-Title`).
  apprise-api gets them as WSGI Latin-1 strings, while mercurio decodes them as
  UTF-8, as Latin-1 only when they are not valid UTF-8. *intentional*
- **Basic Auth credentials.** apprise-api decodes them as UTF-8, so a
  non-ASCII password from Apprise Mobile (which sends Latin-1) fails, while mercurio decodes them as UTF-8, as Latin-1 only when they are not valid
  UTF-8. *intentional*
- **Translated messages.** apprise-api translates its error and status
  messages by `Accept-Language` or cookie and sets `Content-Language`, while mercurio answers in English only. *intentional*
- **Returned logs.** Both return the library's own log lines for the
  request's level and stream them live while sending. mercurio's lines
  have their own wording, redact URLs, and add one INFO or ERROR line per
  finished service; `APPRISE_WEBHOOK_URL` gets INFO and up. *intentional*
- **Persistent storage.** Both prune old persistent storage and logins
  without a configuration once at start-up and then daily
  (`APPRISE_PRUNE_ENABLED`, `APPRISE_PRUNE_INTERVAL_SECONDS`,
  `APPRISE_PRUNE_TIMEOUT_SECONDS`, `APPRISE_STORAGE_PRUNE_DAYS`,
  `APPRISE_AUTH_PRUNE_SECONDS`): apprise-api in a separate container
  process, mercurio inside the server. The storage layout differs and
  `APPRISE_STORAGE_UID_LENGTH` works the same. *intentional*
- **Workers.** apprise-api sizes gunicorn by `APPRISE_WORKER_COUNT` (twice the
  CPUs plus one by default), gives a worker `APPRISE_WORKER_TIMEOUT` seconds
  (300 by default) and recycles it after `APPRISE_WORKER_MAX_REQUESTS`
  requests, while mercurio reads the first two with its own meaning and
  defaults. Each worker stands for 128 requests in progress (4 workers, so
  512, by default), and the timeout is how long a request head, and each
  piece of a body, may take to arrive (30 s by default). It has no worker
  processes to recycle, so `APPRISE_WORKER_MAX_REQUESTS` and its jitter are
  ignored. *intentional*
- **Request log.** apprise-api logs requests through nginx (`combined`
  format) plus `NOTIFY - ip - ...` warnings, while mercurio logs one line per
  request with its key, services, failures and error. *intentional*
- **Unknown paths.** apprise-api answers `404` with an error message, while mercurio answers an empty `404`, before authentication; its `405`
  `Allow` header omits `OPTIONS`. *intentional*
- **Metrics.** apprise-api exports the full `django_prometheus` set, while mercurio exports its HTTP metrics under the same names (request and
  response counts, latency overall and by view, body sizes, streaming
  responses) and, on Linux, `prometheus_client`'s `process_*` metrics.
  Django's model, database, cache and migration metrics and Python's `gc`
  and `info` metrics have no equivalent. *intentional*
- **Other settings.** Plugin paths are ignored. *intentional*
- **Logins and times.** apprise-api checks logins with Django's default
  hashers; without `argon2-cffi` and `bcrypt` (not in its requirements) those
  are `pbkdf2_sha256`, `pbkdf2_sha1` and `scrypt`, and it writes
  `pbkdf2_sha256`. It reports times in the `TZ` zone, while mercurio reads both
  PBKDF2 forms and writes `pbkdf2_sha256`; a `scrypt` digest, which
  apprise-api never writes, is rejected. Times are UTC. *intentional*
- **JSON `/add` without `format`.** apprise-api rejects it, while mercurio
  detects TEXT or YAML. *intentional*
- **Stored configurations** cannot include local files; attachment fields
  only accept `http(s)://` URLs (a local path is a `400`). *intentional*

## Config and YAML

- **Results.** The loader matches Apprise on 326 of 329 recorded
  configurations and 424 of 431 YAML documents; the rest are below.
- **`${NAME}` in an e-mail port.** Apprise's e-mail parser drops the host
  and the marker with it, so the port is ignored, while mercurio keeps the
  entry pending and rejects a non-numeric value when it is resolved.
  *intentional*
- **Self-referencing YAML anchor.** Apprise rejects only that entry, while mercurio rejects the whole document. *intentional*
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

- **File format.** Apprise writes gzip `cache.psdata`, while mercurio writes
  plain JSON `cache.json`; neither reads the other's file (prune and clear
  remove both). *intentional*
- **Modes.** `auto`, `flush` and `memory` (`-SM`, `APPRISE_STORAGE_MODE`,
  `Asset::storage_mode`) as in Apprise; `flush` writes before each I/O step
  of a send rather than on every change. *intentional*
- **Entry checksum.** Each `cache.json` entry carries a 6-character
  SHA-256 checksum (`"!"`), and entries that fail it are dropped on load,
  as in Apprise. The hashed text differs (Apprise hashes its Python
  `repr`), so the checksums are not interchangeable; the files are not
  shared anyway. Caches written by earlier mercurio versions have no
  checksum and are dropped once. *intentional*
- **Size cap.** Apprise refuses `write()` calls that would push a
  namespace past 1 MiB; mercurio has no `write()` API for named files, and
  Apprise's cache itself is uncapped, so there is no cap. *intentional*
- **`mercurio storage list`** shows every configured URL, including
  services that never store anything (`unused`); Apprise omits them.
  *intentional*
- **`${NAME}` template targets** are rebuilt per call, so their in-memory
  store does not outlive the call. *intentional*
- **Rate-limit state** (Bluesky, Mastodon, Reddit, Twitter) is kept for
  the life of a URL, across sends, as in Apprise. *intentional*
- **Remote stores.** Store I/O is local only. *intentional*

## Attachments

- **`?+Header=`** on an attachment URL. Apprise sends it as a header and a
  query parameter, while mercurio only as a header. *intentional*
- **Downloads.** Apprise streams to a temporary file and stops early, while mercurio reads into memory and also stops once the body passes
  `attachment_max_size`. *intentional*
- **Split messages.** Apprise plugins can pick the piece that carries the
  attachments (`_attachment_send_index`), while mercurio always sends them with
  the first piece. *intentional*

## Retries

- **Policy.** Apprise retries every failure `?retry=` times after a fixed
  `?wait=` and ignores `Retry-After`, while mercurio retries only rate limits
  (429, 503 with `Retry-After`) and transient failures (408, 5xx, DNS and
  connect errors). It stops on authentication errors, other 4xx and
  failures after the request was sent. It honours `Retry-After` up to
  300 s. *intentional*
- **`?wait=`.** Apprise defaults to 0, while mercurio defaults to 0.5 s. Both
  cap it at 20 s. *intentional*
- **Unclassified failures.** `Error::Service` failures (for example a JSON
  body with `"ok": false`) and `register_scheme` closures are not retried.
  *intentional*
- **Service hints.** Apprise reads neither Telegram's
  `parameters.retry_after` nor Matrix's `retry_after_ms`, while mercurio feeds
  both into the retry loop as the 429's wait (Matrix once its own back-off
  gives up). *intentional*

## Services

- **Microsoft Teams (`msteams://`).** Apprise's retired plugin is not
  provided; use `workflows://`. *intentional*
- **Discontinued services.** Apprise still ships plugins for services that
  no longer run, while mercurio does not provide them, and their URLs fail as an
  unknown scheme. *intentional*
  - Growl (`growl://`): the project was retired in November 2020.
  - Guilded (`guilded://`): Roblox shut it down on 19 December 2025.
  - Kumulos (`kumulos://`): acquired by Optimove in 2022; the API host
    `messages.kumulos.com` no longer resolves.
  - Pushed (`pushed://`): the API host `api.pushed.co` no longer resolves.
  - Pushjet (`pjet://`, `pjets://`): the project is abandoned and its
    domain redirects to an unrelated site.

## Later

- Upload the notify-type image instead of sending its URL (`image=yes`,
  Telegram).
