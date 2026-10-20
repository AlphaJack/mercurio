# Messages

A notification is a title, a body, a type, an optional input format and
optional attachments. Each selected service gets its own copy shaped to
its limits and markup.

| Part | CLI | HTTP server | Library |
|---|---|---|---|
| Body | `-b TEXT` or stdin | `body` | `Message::new(body)` |
| Title | `-t TEXT` | `title` | `.title(..)` |
| Type | `-n info\|success\|warning\|failure` | `type` | `.kind(NotifyType::..)` |
| Input format | `-i text\|html\|markdown` | `format` | `.format(NotifyFormat::..)` |
| Attachments | `-a PATH\|URL` | `attach`, multipart files | `.attach(..)`, `AttachmentSet` |

A message needs a body or at least one attachment; a body-less message
fails for services without attachment support.

| Type | Colour | ASCII marker |
|---|---|---|
| `info` (default) | `#3AA3E3` | `[i]` |
| `success` | `#3AA337` | `[+]` |
| `warning` | `#CACF29` | `[~]` |
| `failure` | `#A32037` | `[!]` |

Services use the type where they have a notion of it: embed colour,
icon images, priority or the `type` field of `json://`, `form://` and
`xml://`. Colours, markers and image URLs come from the
[asset](../config/assets.md). Services that send images honour `?image=no`.

`-e` turns `\n`, `\r`, `\t` and `\\` in the CLI's title and body into the
characters they stand for (`mercurio -e -b 'sda: 91%\nsdb: 40%' ...`); other
escapes stay as written. The library does not decode escapes.

`:shortcode:` emoji (`:rocket:`, `:+1:`: GitHub's gemoji names,
case-insensitive) become the emoji itself when emoji are on for a URL:

- `-j` / `--interpret-emojis` (CLI), `APPRISE_INTERPRET_EMOJIS=yes`
  (server) or `Asset::interpret_emojis = Some(true)` (library) turn them on
  for every URL, unless a URL says `?emojis=no`;
- without those, a URL can turn them on with `?emojis=yes`;
- `APPRISE_INTERPRET_EMOJIS=no` or `Some(false)` turns them off everywhere.

Unknown names stay as written. The replacement happens before format
conversion, in the title and the body.

## The pipeline

Every service receives the message through the same steps:

1. **Format resolution**: input format from the message, else
   `Asset::body_format`, else none (passthrough); service format as in
   [`?format=`](../url-parameters.md#format).
2. **Conversion** of the body to the service format. The title is converted
   too when the service has no title field. Passthrough messages are not converted.
3. **Limits**: the service's limits or limits computed for this message (Matrix sizes
   them from the rendered content).
4. **Title merge**: services without a title field (`title_maxlen` 0) get
   the title prepended: `<b>title</b><br />` for HTML, `# title` for
   Markdown, `title\r\n` for text.
5. **Line cap**: services with a line limit keep the first N lines.
6. **Overflow**: `upstream`, `truncate` or `split` ([Overflow](overflow.md)).
7. **Dialect conversion**: services with their own markup convert each
   piece of a declared-format message; pieces that grow past the limit are
   split again ([Formats](formats.md#dialects)).
8. **Attachments** go with the first piece; with `overflow=truncate` only
   the first attachment is sent.

Services also see the original `Message` next to each piece (Telegram rich
templates build their payload from it). `Target::plan` runs the pipeline
for the first piece and returns the plan without sending.
