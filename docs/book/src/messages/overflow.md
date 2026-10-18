# Overflow

Most services limit how long a title or body can be. `?overflow=` on a
URL says what to do with a message that does not fit:

| Mode | Behaviour |
|---|---|
| `upstream` (default) | send the whole message; the service enforces (or rejects) its own limit |
| `truncate` | send one message with as much of the body as fits; drop the rest |
| `split` | send the whole body as several messages, each within the limit, in order |

```sh
mercurio -b "$(cat build.log)" 'tgram://BOT_TOKEN/CHAT_ID?overflow=split'
mercurio -b "$(cat build.log)" 'ntfy://builds?overflow=truncate'
```

`split` can turn one long message into many. On SMS and other paid
channels every piece may be billed.

## Limits

Each service has three limits, shown on its [page](../services/index.md):

| Limit | Meaning |
|---|---|
| `title_maxlen` | longest title in characters; `0` means the service has no title field, so the title is merged into the body |
| `body_maxlen` | longest body in characters |
| `body_max_line_count` | lines kept from the body; `0` means unlimited (desktop notifications keep 2 to 10 lines) |

Limits count Unicode code points, not bytes. A few
services size their limit from the content (Matrix, after rendering HTML).
The line cap applies in every overflow mode, including `upstream`.

## How `truncate` works

The title is cut to `title_maxlen` characters. The body is cut the way
`split` would cut it. Only the first piece is kept. Leading line
breaks and trailing whitespace of the result are removed. For Markdown a
trailing lone backslash, which would escape whatever the service appends,
is dropped. With `truncate` and several attachments only the first
attachment is sent.

## How `split` works

The body is cut into pieces of at most `body_maxlen` characters, looking
for the best break before the limit, in this order:

1. a newline;
2. a space or tab;
3. punctuation followed by whitespace;
4. a hard cut at the limit.

For HTML it never cuts inside a tag or an entity; for Markdown it does not
cut inside a link or an escape and repairs emphasis and code fences that a
cut leaves open.

Only the first piece carries the title; the others are sent without one.
No `[01/03]` counters are added.

Services with a [dialect](formats.md#dialects) convert each piece and split
again if the converted text grew past the limit.
