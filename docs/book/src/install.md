# Installing

Every GitHub release ships a prebuilt `mercurio` binary with support for every service.

## Cargo

```sh
cargo binstall mercurio-cli
```

## Homebrew

```sh
brew install AlphaJack/tap/mercurio
```

## Container

In server mode:

```sh
docker run --rm -p 8000:8000 {{image}}
```

Any other arguments go to the CLI:

```sh
docker run --rm {{image}} -t "Backup" -b "Finished" ntfy://my-topic
```

## Installer script

Linux and macOS:

```sh
curl -LsSf {{repository}}/releases/latest/download/mercurio-cli-installer.sh | sh
```

Windows (PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -c "irm {{repository}}/releases/latest/download/mercurio-cli-installer.ps1 | iex"
```

Both put `mercurio` in `$CARGO_HOME/bin` (`~/.cargo/bin`). 
Archives and their `.sha256` checksums are on the [releases page]({{repository}}/releases).

## AUR

The compiled binary and systemd unit can be installed from the Arch User Repository as `mercurio-bin`
