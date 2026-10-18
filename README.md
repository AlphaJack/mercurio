# mercurio

<img src="crates/mercurio/assets/logo.svg" alt="a talaria (winged sandal)" width="64" height="64" align="right">

Apprise-compatible Rust library, CLI and HTTP server to send notifications to 150+ services via a single URL.

## Installation

```sh
cargo binstall mercurio-cli
```

Installer scripts, release archives, the container image and a systemd unit: [docs/book/src/install.md](docs/book/src/install.md).

## Usage

As a binary:

```sh
mercurio --help
mercurio -t "Backup" -b "Finished in 42s" "ntfy://my-topic"
echo "disk 91% full" | mercurio -n warning tgram://123456789:ABCdefGHI/CHAT_ID
```

As a library:

```rust
// cargo add mercurio


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

// async variant:


use std::sync::Arc;
use mercurio::{Mercurio, Message};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut m = Mercurio::new();
    m.add("ntfy://my-topic")?;
    m.add("slack://xoxb-token/#alerts")?;
    let m = Arc::new(m);

    let msg = Message::new("Finished in 42s").title("Backup");
    // run `notify` on the runtime's blocking pool
    let report = tokio::task::spawn_blocking(move || m.notify(&msg)).await?;
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

Apprise is licensed under the BSD 2-Clause License:

> Copyright (c) 2026, Chris Caron <lead2gold@gmail.com>
> All rights reserved.
>
> Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
>
> 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
> 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
