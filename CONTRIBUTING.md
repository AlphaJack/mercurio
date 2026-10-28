# Contributing

## Setup

```sh
cargo install mdbook cargo-insta
```

Or open the repository in its dev container (`.devcontainer`), which sets all of this up on Linux.

## Add or fix a service

```sh
cargo xtask new <id>                               # add a new service
cargo test -p mercurio --test it services::<id>    # run its fixture
cargo insta review                                 # check each request against the API docs, accept
cargo xtask try 'gotify://real.host/TOKEN'         # send real test messages with your working tree
```

- Everything about a service lives in `crates/mercurio/src/services/<id>.rs` and `crates/mercurio/tests/fixtures/services/<id>.json`. `build.rs` registers both. Code shared by several services goes in a `_<name>.rs` helper, never in another service's module, so each service compiles on its own.
- `SERVICE` declares the URL templates, path tokens and query parameters. The service page and `mercurio services --json` are generated from them. `tests/it/params.rs` fails when a declared key is never read or a declared default is not what the parser does; mark a default that depends on the rest of the URL with `.inferred()`.
- Services never touch the file system, the network or local programs themselves: they return a `Plan` (`Plan::http`, `Plan::socket`, `Plan::command`, `Plan::file`) and declare the files they read in `Notify::files`, the downloads they need first (a remote template) in `Notify::fetches` and extra stores in `Notify::stores`. They read the time and randomness from `ctx.env()` (the transport's `Env`) and build multipart bodies with `ctx.multipart()`. `crates/mercurio/clippy.toml` denies `std::fs`, `std::net`, `std::process::Command`, `SystemTime::now`, `ring`'s `SystemRandom` and `Multipart::new` outside the transports.
- A fixture case is one line in the `cases` list: a `name`, a `url`, and only what differs from the defaults: `title`, `body`, `type`, `format`, `attachments`, scripted `responses`, `ignore` for changing values. Add one per URL form, option and error branch. Every field is described in the rustdoc of `mercurio::testing::fixtures`.

## Checks

Run these checks before pushing:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo xtask docs
```

## Pull requests

The PR title is a conventional commit such as `feat(services): gotify`.
PRs are squash-merged with the title as the commit and the description as its body.
[pr-title.yml](.github/workflows/pr-title.yml) checks the title against these types and scopes:

| Type | For |
| --- | --- |
| `feat` | something users can do that they could not before |
| `fix` | a bug users hit |
| `perf` | the same behaviour, faster or smaller |
| `refactor`, `docs`, `test`, `ci`, `chore` | anything users do not notice |

[release-plz.toml](release-plz.toml) gives `feat`, `fix` and `perf` their heading in the release notes and leaves the others out unless breaking.

The scope is optional and becomes a heading under the type. Leave it out for changes across the whole project.

| Scope | For |
| --- | --- |
| `services` | notification services, desktop ones included |
| `lib` | the rest of the Rust API |
| `serve` | the HTTP server |
| `cli` | the commands and their output |
| `config` | configuration files, text and YAML |
| `install` | installing, packages and images |
| `deps` | dependency bumps users notice |

At the end of the description, after some text:

- `Fixes #12` adds "fixes #12" to the entry.
- With `!` after the scope, `BREAKING CHANGE: <what users must do>` shows that line under the entry.

## Release process

1. Every push to main that passes CI updates a release PR, in which release-plz sets the version and the changelog from the PR titles since the last release.
2. Merging it tags `vX.Y.Z` and drafts a GitHub release.
3. The tag starts [release.yml](.github/workflows/release.yml), where cargo-dist builds the binaries and installers.
4. The publish and post-announce jobs in [dist-workspace.toml](dist-workspace.toml) then publish the packages, crates.io included. Their workflows in `.github/workflows` can be run again for a tag by hand.
