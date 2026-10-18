# Notification URLs

Main idea:

```text
scheme://[user[:password]@]host[:port][/path/token/target...][?key=value&...]
```

Notification URLs are not RFC 3986 URLs: tokens may contain `:`, `/` or
`@`. The path carries API keys and targets. The query string carries
options. Each [service page](services/index.md) lists the forms it accepts
and its parameters; the [common parameters](url-parameters.md) work on
every URL.

| Part | Meaning |
|---|---|
| Scheme | Selects the service, case-insensitive. A scheme ending in `s` (`ntfys`, `jsons`, `mailtos`) sets the secure flag, which most HTTP services turn into `https://`. |
| `user:password@` | Credentials or a token in the user position. Everything up to the first `@` is the user part, split at the first `:`. |
| Host | A hostname or IP address; a token or ID for services that use the host position (`discord://webhook_id/webhook_token`). Only services that connect to the host check it (`an invalid hostname or port was specified`). |
| Port | Optional. Services that connect to the host reject a non-numeric port. |
| Path | Split on `/` (for some services also on spaces, commas and `\`) into tokens and targets. Repeated slashes collapse. `/#name` is a literal `#` (Slack, Discord or IRC channels), not a fragment. |
| Query | Options. Keys are lower-cased and trimmed, values percent-decoded and trimmed. A repeated key keeps the last value. |

## Special characters

Percent-encode `@` (`%40`), `:` (`%3A`), `/` (`%2F`), `?` (`%3F`), `&`
(`%26`), `#` (`%23`), `%` (`%25`) and space (`%20`) inside a password,
token or target. `json://user:p%40ss%2Fword@example.com/hook` has the
password `p@ss/word`. A `+` in a query value stays a `+` (`%2B` works too).
YAML settings written under the URL (`user:`, `password:`, `to:`) need no
encoding; the loader encodes them.

`?user=` and `?pass=` (or `?password=`) replace the credentials written
before `@`. With `?user=` alone, the value before `@` becomes the password.

## Prefixed parameters: `+`, `-` and `:`

Three query prefixes pass free-form data to services that read them (the
custom `json://`, `form://` and `xml://` services and some others; their
pages say which):

| Prefix | Example | Meaning for `json://` |
|---|---|---|
| `+` | `?+X-Token=abc` | add or replace an HTTP header (case kept) |
| `-` | `?-page=2` | add a query parameter to the request URL |
| `:` | `?:message=text` | rename the payload field `message` to `text`; an empty value (`?:type=`) removes it; an unknown key adds it |

```sh
mercurio -b "hi" "json://localhost:8080/hook?+X-Token=abc&:message=text&:type="
```

`form://` and `xml://` differ in details (`xml://` has no `-` parameters).
Other services use `:` for template tokens or extra fields. For attachment
URLs, `+` entries are headers only.

## Vendor URLs

31 services accept the URL the vendor gives you, among
them Discord, Slack, Power Automate workflows, Mattermost, Google Chat,
Matrix, ntfy, Zoom, Splunk, IFTTT and Webex Teams. When the scheme is not a
known service, each service's vendor URL parser is tried in turn. The
"Vendor URLs accepted" row of a service page says whether it does.

```sh
mercurio -b "hi" "https://discord.com/api/webhooks/1234567890/abcdefghijkl"
```

## Validating URLs and secrets

`mercurio check URL...` parses URLs without sending; each invalid URL
prints the reason and makes the exit code 1:

```text
$ mercurio check "json://localhost/x" "unknown://x" "discord://only"
error: unknown://x/...: unsupported URL scheme: unknown://
error: discord://only/...: Discord: an invalid Discord Webhook Token was specified
ok   json:// (JSON)
```

Log lines, errors, `check` and `--dry-run` output show only the scheme and
host (`json://localhost:8080/...`); a token in the host position
(`tgram://BOT_TOKEN/...`) is therefore printed. In the library,
`Debug` output of parsed URLs is redacted the same way. `mercurio::redact_url` gives the
redacted form for your own logs.
