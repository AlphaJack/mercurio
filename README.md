# mercurio

<img src="https://raw.githubusercontent.com/AlphaJack/mercurio/main/crates/mercurio/assets/logo.svg" alt="a talaria (winged sandal)" width="64" height="64" align="right">

Apprise-compatible Rust library, CLI and HTTP server to send notifications to 150+ services via a single URL.

## Installation

```sh
cargo binstall mercurio-cli
```

Homebrew, Scoop, Chocolatey, installer scripts, release archives, the container image and a systemd unit: [docs/book/src/install.md](docs/book/src/install.md).

## Usage

As a binary:

```sh
mercurio --help
mercurio -t "Backup" -b "Finished in 42s" "ntfy://my-topic"
echo "disk 91% full" | mercurio -n warning tgram://123456789:ABCdefGHI/CHAT_ID
```

As a library:

```rust
// cargo add mercurio tokio --features tokio/macros,tokio/rt-multi-thread

use mercurio::{AsyncMercurio, Message};

#[tokio::main]
async fn main() -> Result<(), mercurio::Error> {
    let mut m = AsyncMercurio::new();
    m.add("ntfy://my-topic")?;
    m.add("slack://xoxb-token/#alerts")?;

    let msg = Message::new("Finished in 42s").title("Backup");
    let report = m.notify(&msg).await;
    println!("success: {}", report.is_success());
    m.close().await;
    Ok(())
}

// blocking variant, no runtime:
// cargo add mercurio --no-default-features --features all-services,transport-blocking

use mercurio::{Mercurio, Message};

fn main() -> Result<(), mercurio::Error> {
    let mut m = Mercurio::new();
    m.add("ntfy://my-topic")?;
    m.add("slack://xoxb-token/#alerts")?;

    let msg = Message::new("Finished in 42s").title("Backup");
    // `notify` blocks until every service has answered
    let report = m.notify(&msg);
    println!("success: {}", report.is_success());
    Ok(())
}
```

As a server:

```sh
docker run -d -p 8000:8000 ghcr.io/alphajack/mercurio:latest
curl -X POST -d 'urls=ntfy://my-topic' -d 'title=Backup' -d 'body=Finished in 42s' http://localhost:8000/notify
```

## Documentation

- [Book](https://alphajack.github.io/mercurio/): guide for command line, library, server, URLs, configuration files.
- [CONTRIBUTING.md](CONTRIBUTING.md): contributor guidelines

## Credits

mercurio is a Rust port of [Apprise](https://github.com/caronc/apprise) by Chris Caron.
Its URL schemes, service behaviour, defaults and much of the documentation follow Apprise.
mercurio is an independent project, not affiliated with or endorsed by Apprise.