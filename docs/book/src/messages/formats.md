# Formats and conversion

The **input format** is what the caller says the body is written in (`-i`,
the server's `format` field, `Message::format`). The **service format** is
what the service renders (its default or `?format=`). When they differ,
Mercurio converts the body. With no input format declared nothing is
converted: the body passes through as the service's own format.

| Input | Meaning |
|---|---|
| none | passthrough: no conversion, no Markdown repair |
| `text` | plain text; escaped when a service renders HTML or Markdown |
| `markdown` | CommonMark (with GFM tables); rendered to HTML where needed |
| `html` | HTML; reduced to text or Markdown where needed |

The CLI and the HTTP server declare none unless `-i` or `format` is given;
the library uses `Message::format`, else `Asset::body_format`.

## Conversion table

| From \ To | text | html | markdown |
|---|---|---|---|
| text | unchanged | HTML-escaped, newlines become `<br/>` | syntax characters backslash-escaped |
| html | tags removed, block elements become line breaks, entities decoded | unchanged | converted to Markdown |
| markdown | unchanged (no converter) | rendered (CommonMark, GFM tables, soft breaks as `<br />`) | unchanged |

For services without a title field, the title is converted the same way
and merged into the body (see [the pipeline](index.md#the-pipeline)).

## Service formats

Each service declares its formats, the first being its default; the
service pages list them under "Body formats". Most services are text only;
e-mail and the mail APIs default to HTML; Slack, Google Chat, Webex Teams,
Rocket.Chat and others take Markdown. `?format=` picks one
([resolution rules](../url-parameters.md#format)). Markdown input to a
text-only service is sent unchanged.

## Dialects

Some services have their own markup and convert each piece after the
generic conversion (`Notify::convert`):

| Service | Dialect |
|---|---|
| [Slack](../services/slack.md) | Slack mrkdwn (`*bold*`, `<url\|text>` links) |
| [Google Chat](../services/googlechat.md) | Google Chat text formatting |
| [Telegram](../services/telegram.md) | Telegram HTML (reduced tag set) or MarkdownV1/V2 |
| [Matrix](../services/matrix.md) | HTML (`formatted_body`); Slack-style text in Slack mode |
| [Pushover](../services/pushover.md) | Pushover's HTML subset |
| [Signal API](../services/signalapi.md) | Signal styled text ranges |
| [Evolution API](../services/evolution.md) (WhatsApp) | WhatsApp formatting |
| [KOOK](../services/kook.md) | KMarkdown |
| [Mastodon](../services/mastodon.md) | Mastodon text |

Dialect conversion only runs for a declared input format. Because the
converted text can be longer, size limits are applied again: with
`overflow=split` the converted piece is re-split, with `truncate` it is
cut to fit.

## Markdown rendering

Markdown is rendered with `pulldown-cmark` (CommonMark plus GFM tables);
HTML to text and HTML to Markdown use a small HTML tokenizer. When a split
cuts Markdown, Mercurio repairs unclosed emphasis, code fences and link
syntax.