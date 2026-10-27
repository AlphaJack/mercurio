# Contributing

## Setup

```sh
cargo install mdbook cargo-insta
```

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

The PR title must be a conventional commit (`feat(services): gotify`, `fix(cli): ...`): PRs are squash-merged and release-plz builds the changelog and version from these titles.
Allowed types and scopes: [pr-title.yml](.github/workflows/pr-title.yml).
Use `feat`, `fix` and `perf` only for changes users notice: the changelog skips `build`, `chore`, `ci`, `docs`, `refactor` and `test` unless they are breaking (`!`).
The scope becomes a changelog heading, so name what users touch: `desktop` for desktop notifications, `services` for the other notification services, `lib` for the rest of the Rust API.
