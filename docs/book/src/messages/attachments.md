# Attachments

Files can go with a notification to services that support them: e-mail,
Discord, Slack, Telegram, Matrix, Pushover, ntfy, the `json://`,
`form://` and `xml://` webhooks and many more. The
[services index](../services/index.md) has an "Attachments" column and
every service page says yes or no. A service without attachment support
still gets the text of the message; a message with attachments but no body
fails for such a service.

## Sources

| Source | Example |
|---|---|
| Local path | `/var/log/backup.log`, `./report.pdf` |
| `file://` URL | `file:///var/log/backup.log` |
| `http://`, `https://` | `https://example.com/report?id=7`, `https://user:pass@cam.local/snapshot.jpg` |
| `memory://` | in-memory content (library); a URL only names it |

Remote files are downloaded through the notifier's transport before
sending, so `FakeTransport` covers them in tests and a custom
[transport](../library/index.md#transports-and-testing) applies to them. Credentials in the
URL authenticate the download; treat such URLs as secrets.

## URL options

| Option | Meaning |
|---|---|
| `?name=report.pdf` | file name the recipient sees (base name only) |
| `?mime=image/png` | MIME type; must be a known type |
| `?cache=yes\|no\|SECONDS` | how long a loaded copy is reused (default 600 s); `no` or `0` reloads every time |
| `?verify=no` | (http) skip TLS certificate verification |
| `?cto=`, `?rto=` | (http) connect and read timeouts |
| `?+Header=value` | (http) extra request header |
| anything else | (http) forwarded to the server as a query parameter |

Without `?name=`, the name comes from the `Content-Disposition` header,
then the URL path, then `mercurio-attachment.<ext>` (the extension
guessed from the MIME type). Without `?mime=`, the type comes from the
`Content-Type` header, then the file extension, then
`application/octet-stream`.

## Size limit

`Asset::attachment_max_size` caps each attachment: 1000 MiB by default,
`0` for no limit. The check uses the file size,
the `Content-Length` header and the downloaded body.

## Command line

```sh
mercurio -t 'Nightly backup' -b 'See the log' \
  -a /var/log/backup.log \
  -a 'https://example.com/report?id=7&name=report.pdf' \
  'mailto://user:pass@example.com'
```

`-a` is repeatable. A file that cannot be loaded is an error before
anything is sent.

The [HTTP server](../server.md) accepts multipart file parts and `attach`
fields holding `http(s)://` URLs; a local path or `file://` is rejected
with HTTP 400, so clients cannot read files on the server.

## Library

`Message::attach` takes an in-memory `Attachment` (name, MIME type,
bytes). `AttachmentSet` parses the sources above and loads them:

```rust
use mercurio::testing::FakeTransport;
use mercurio::{AttachSource, AttachmentSet, Asset, Attachment, Message, transport::Response};

let fake = FakeTransport::new();
fake.respond_with(Response::new(200, "a,b\n1,2\n").with_header("Content-Type", "text/csv"));

let mut set = AttachmentSet::new();
set.add("https://example.com/export?id=7&name=readings.csv")?;
set.push(AttachSource::text("generated in memory", Some("notes.txt")))?;

let mut msg = Message::new("Nightly export")
    .attach(Attachment::new("hello.bin", "application/octet-stream", vec![1, 2, 3]));
msg.attachments.extend(set.load(&fake, &Asset::default())?);

let names: Vec<&str> = msg.attachments.iter().map(|a| a.name.as_str()).collect();
assert_eq!(names, ["hello.bin", "readings.csv", "notes.txt"]);
assert_eq!(msg.attachments[1].mime, "text/csv");
// `name=` is an option, not part of the download URL.
assert_eq!(fake.requests()[0].url, "https://example.com/export?id=7");
# Ok::<(), mercurio::Error>(())
```

Loading stops at the first failure.

When a message is split, the attachments go with the first piece; with
`overflow=truncate` only the first attachment is sent.
