# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [0.2.1](https://github.com/AlphaJack/mercurio/compare/v0.2.0...v0.2.1) - 2026-10-22

### Fixed

#### Services

- wipe every copy of the PKCS#1 key built for RSA signing ([#102](https://github.com/AlphaJack/mercurio/pull/102))

### Other

#### Lib

- drop redundant clones, for_each, match-to-unwrap and constant flags ([#103](https://github.com/AlphaJack/mercurio/pull/103))
- mark Param #[non_exhaustive] ([#106](https://github.com/AlphaJack/mercurio/pull/106))
- mark methods returning Self #[must_use] ([#104](https://github.com/AlphaJack/mercurio/pull/104))
## [0.2.0](https://github.com/AlphaJack/mercurio/compare/v0.1.1...v0.2.0) - 2026-10-21

### Added

#### Cli

- adding -T / --theme for the {THEME} of image URLs ([#40](https://github.com/AlphaJack/mercurio/pull/40))

#### Lib

- **breaking**: expand :shortcode: emoji (-j, ?emojis=, interpret_emojis) ([#37](https://github.com/AlphaJack/mercurio/pull/37))
- **breaking**: storage modes auto, flush and memory (-SM) ([#35](https://github.com/AlphaJack/mercurio/pull/35))
- **breaking**: configurable URL id length and salt (-SUL) ([#34](https://github.com/AlphaJack/mercurio/pull/34))
- **breaking**: run delivery on an async core with a default tokio transport ([#15](https://github.com/AlphaJack/mercurio/pull/15))
- bundle the time zone database by default ([#82](https://github.com/AlphaJack/mercurio/pull/82))
- report each URL as it finishes with notify_with_progress ([#31](https://github.com/AlphaJack/mercurio/pull/31))

#### Serve

- receive alertmanager and grafana webhooks on /notify ([#67](https://github.com/AlphaJack/mercurio/pull/67))
- per-view latency, body size, streaming and process metrics ([#47](https://github.com/AlphaJack/mercurio/pull/47))
- prune old storage and unused logins on a schedule ([#46](https://github.com/AlphaJack/mercurio/pull/46))
- add a json log format (--log-format json) ([#33](https://github.com/AlphaJack/mercurio/pull/33))
- return and stream the library's own log lines ([#32](https://github.com/AlphaJack/mercurio/pull/32))

#### Server

- add ctrl-c support ([#8](https://github.com/AlphaJack/mercurio/pull/8))

#### Services

- **breaking**: one cargo feature per service ([#12](https://github.com/AlphaJack/mercurio/pull/12))

### Fixed

#### Cli

- skip cached files modified within the last 2 s ([#100](https://github.com/AlphaJack/mercurio/pull/100))
- log sends to stdout as Apprise does ([#55](https://github.com/AlphaJack/mercurio/pull/55))

#### Serve

- install signal handlers before announcing the listener ([#30](https://github.com/AlphaJack/mercurio/pull/30))

### Other

#### Cli

- drop the Args copy of clap's options ([#28](https://github.com/AlphaJack/mercurio/pull/28))
- use tracing-subscriber for every command ([#20](https://github.com/AlphaJack/mercurio/pull/20))
- dispatch on a command enum instead of strings ([#19](https://github.com/AlphaJack/mercurio/pull/19))

#### Lib

- **breaking**: move config and attachment detail types into modules ([#98](https://github.com/AlphaJack/mercurio/pull/98))
- **breaking**: move transport and service-author types into modules ([#95](https://github.com/AlphaJack/mercurio/pull/95))
- **breaking**: mark the report and plan structs non-exhaustive ([#94](https://github.com/AlphaJack/mercurio/pull/94))
- **breaking**: replace the notify variants with NotifyOptions ([#93](https://github.com/AlphaJack/mercurio/pull/93))
- **breaking**: replace reqwest with an in-house HTTP/1.1 client ([#91](https://github.com/AlphaJack/mercurio/pull/91))
- **breaking**: share attachment data instead of copying it ([#73](https://github.com/AlphaJack/mercurio/pull/73))
- **breaking**: share message and request bodies instead of copying them ([#69](https://github.com/AlphaJack/mercurio/pull/69))
- **breaking**: mark public enums non-exhaustive ([#17](https://github.com/AlphaJack/mercurio/pull/17))
- fence internal modules behind __private ([#23](https://github.com/AlphaJack/mercurio/pull/23))
- move date helpers from crypto to time ([#22](https://github.com/AlphaJack/mercurio/pull/22))

#### Release

- add apprise tag to crates ([#89](https://github.com/AlphaJack/mercurio/pull/89))

#### Serve

- copy request bodies less and cap the bytes read at once ([#56](https://github.com/AlphaJack/mercurio/pull/56))
- stop test servers gracefully ([#49](https://github.com/AlphaJack/mercurio/pull/49))
- cache stored configurations and logins behind a stat check ([#24](https://github.com/AlphaJack/mercurio/pull/24))
- use idiomatic axum and tower, validate against apk ([#16](https://github.com/AlphaJack/mercurio/pull/16))

## [0.1.1](https://github.com/AlphaJack/mercurio/compare/v0.1.0...v0.1.1) - 2026-10-18

### Fixed

- include README in crates.io packages ([#5](https://github.com/AlphaJack/mercurio/pull/5))

### Other

- add license notice ([#1](https://github.com/AlphaJack/mercurio/pull/1))

## [0.1.0](https://github.com/AlphaJack/mercurio/releases/tag/v0.1.0) - 2026-10-18

### Other

- Move to public repository
