# Introduction

<img src="assets/icons/logo.svg" alt="a talaria (winged sandal)" width="64" height="64" align="right">

{{description}} It ships as a single static binary. [Installing](install.md) covers the binaries, the
container image and building from source.

## Send a notification

Each URL names a service and carries its credentials and options. Find the
format of yours in the [service list](services/index.md).

```sh
mercurio -t "Backup" -b "Finished in 42s" ntfy://my-topic "discord://ID/TOKEN"

# body from stdin
df -h / | mercurio -t "Disk usage" mailto://user:password@example.com 

# advanced formatting
mercurio -n failure -i markdown -b "**db-1** is down" tgram://BOT_TOKEN/CHAT_ID
```

`-n` sets the type (`info`, `success`, `warning`, `failure`), which services
turn into colours, icons or priorities. `-i` declares the body's markup;
mercurio converts it for each service ([Formats](messages/formats.md)).
`mercurio check URL...` validates URLs without sending. `-d` lists what
would be notified. The exit code is 0 sent, 1 failed, 2 usage error, 3
nothing matched the tags, 4 partly sent ([Command line](cli.md)).

## Use a configuration file

Without URLs on the command line, mercurio reads `~/.config/apprise/apprise.conf`:

```yaml
version: 1
urls:
  - ntfy://my-topic
  - mailto://user:password@example.com:
      - to: oncall@example.com
        tag: critical
  - slack://xoxb-token/#ops:
      tag: devops, critical
```

```sh
mercurio -b "untagged entries only"           # ntfy
mercurio -g critical -b "page someone"        # e-mail and Slack
mercurio -g all -d                            # list everything
```

See [Configuration files](config/index.md) for the TEXT and YAML formats, tags, includes and templates.

## Use the library

```rust,no_run
use mercurio::{Mercurio, Message, NotifyType};

let mut m = Mercurio::new();
m.add("ntfy://my-topic")?;
m.add("slack://xoxb-token/#alerts")?;
let report = m.notify(&Message::new("Deploy finished").title("ci").kind(NotifyType::Success));
assert!(report.is_success());
# Ok::<(), mercurio::Error>(())
```

`notify` blocks until every service has answered, the
`Report` lists each URL's outcome. Services are sans-IO: they return a plan
of requests, so any transport (async, proxy, test double) can run them and
tests need no accounts. See [Using the library](library/index.md).

## Run the HTTP server

Mercurio ships an Apprise-compatible http server:

```sh
mercurio serve --bind 127.0.0.1:8000
curl -X POST -d 'urls=ntfy://my-topic' -d 'body=hello' http://127.0.0.1:8000/notify
```

See [HTTP server](server.md).

## How this book is organised

- **User guide**: the command line, URLs, configuration files, messages and
  the HTTP server. All of it applies to the library as well.
- **Library**: using mercurio from Rust. The API reference is rustdoc
  ([api/mercurio](api/mercurio/index.html) in the published book).
- **Services**: one page per service: URL formats, every query parameter
  with its default, examples and known differences.
- **Reference**: [Differences with Apprise](differences.md).
