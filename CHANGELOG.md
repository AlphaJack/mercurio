# Changelog

## [0.2.5](https://github.com/AlphaJack/mercurio/compare/v0.2.4...v0.2.5) - 2026-10-28

### Fixed

#### Lib

- A stalled server no longer hangs the blocking transport on Windows ([#145](https://github.com/AlphaJack/mercurio/pull/145))

#### Serve

- Stop on Ctrl-Break on Windows too ([#146](https://github.com/AlphaJack/mercurio/pull/146))

## [0.2.4](https://github.com/AlphaJack/mercurio/compare/v0.2.3...v0.2.4) - 2026-10-26

### Added

#### Lib

- Keep each URL's warnings in ReportEntry::warnings ([#132](https://github.com/AlphaJack/mercurio/pull/132))
- Add Report::error_summary, Mercurio::app, and URL names in add_all errors ([#131](https://github.com/AlphaJack/mercurio/pull/131))
- Let apps set their own desktop icon with Asset::image_bytes ([#129](https://github.com/AlphaJack/mercurio/pull/129))
- Show windows:// as a WinRT toast, falling back to the balloon ([#128](https://github.com/AlphaJack/mercurio/pull/128))
- Fall back to osascript for macOS notifications ([#127](https://github.com/AlphaJack/mercurio/pull/127))

### Fixed

#### Lib

- Mask secrets in the host position of redacted URLs ([#133](https://github.com/AlphaJack/mercurio/pull/133))
- Write desktop icons to the user's own directory on Linux, accept SVG app icons there ([#130](https://github.com/AlphaJack/mercurio/pull/130))
- Run commands without a console window on Windows ([#125](https://github.com/AlphaJack/mercurio/pull/125))

## [0.2.3](https://github.com/AlphaJack/mercurio/compare/v0.2.2...v0.2.3) - 2026-10-24

### Added

#### Lib

- Enable transport-blocking by default ([#123](https://github.com/AlphaJack/mercurio/pull/123))

### Fixed

#### Lib

- Convert HTML without the html feature ([#122](https://github.com/AlphaJack/mercurio/pull/122))

### Other

#### Lib

- Gate tests and doctests on the services they use ([#116](https://github.com/AlphaJack/mercurio/pull/116))

## [0.2.2](https://github.com/AlphaJack/mercurio/compare/v0.2.1...v0.2.2) - 2026-10-24

### Added

#### Lib

- Add timezones feature, UTC only without it ([#113](https://github.com/AlphaJack/mercurio/pull/113))
- Add regex-unicode feature, regex-lite without it ([#112](https://github.com/AlphaJack/mercurio/pull/112))
- Make heavy dependencies optional behind cargo features ([#109](https://github.com/AlphaJack/mercurio/pull/109))

### Fixed

#### Lib

- Adopt fixes for IFTTT, Pushover, Streamlabs and incident actions ([#115](https://github.com/AlphaJack/mercurio/pull/115))

### Other

#### Lib

- One sans-IO HTTP/1.1 client for both transports, drop ureq ([#114](https://github.com/AlphaJack/mercurio/pull/114))

## [0.2.1](https://github.com/AlphaJack/mercurio/compare/v0.2.0...v0.2.1) - 2026-10-22

### Fixed

#### Services

- Wipe every copy of the PKCS#1 key built for RSA signing ([#102](https://github.com/AlphaJack/mercurio/pull/102))

### Other

#### Lib

- Drop redundant clones, for_each, match-to-unwrap and constant flags ([#103](https://github.com/AlphaJack/mercurio/pull/103))
- Mark Param #[non_exhaustive] ([#106](https://github.com/AlphaJack/mercurio/pull/106))
- Mark methods returning Self #[must_use] ([#104](https://github.com/AlphaJack/mercurio/pull/104))

## [0.2.0](https://github.com/AlphaJack/mercurio/compare/v0.1.1...v0.2.0) - 2026-10-21

### Added

#### Cli

- Adding -T / --theme for the {THEME} of image URLs ([#40](https://github.com/AlphaJack/mercurio/pull/40))

#### Lib

- **breaking**: Expand :shortcode: emoji (-j, ?emojis=, interpret_emojis) ([#37](https://github.com/AlphaJack/mercurio/pull/37))
- **breaking**: Storage modes auto, flush and memory (-SM) ([#35](https://github.com/AlphaJack/mercurio/pull/35))
- **breaking**: Configurable URL id length and salt (-SUL) ([#34](https://github.com/AlphaJack/mercurio/pull/34))
- **breaking**: Run delivery on an async core with a default tokio transport ([#15](https://github.com/AlphaJack/mercurio/pull/15))
- Bundle the time zone database by default ([#82](https://github.com/AlphaJack/mercurio/pull/82))
- Report each URL as it finishes with notify_with_progress ([#31](https://github.com/AlphaJack/mercurio/pull/31))

#### Serve

- Receive alertmanager and grafana webhooks on /notify ([#67](https://github.com/AlphaJack/mercurio/pull/67))
- Per-view latency, body size, streaming and process metrics ([#47](https://github.com/AlphaJack/mercurio/pull/47))
- Prune old storage and unused logins on a schedule ([#46](https://github.com/AlphaJack/mercurio/pull/46))
- Add a json log format (--log-format json) ([#33](https://github.com/AlphaJack/mercurio/pull/33))
- Return and stream the library's own log lines ([#32](https://github.com/AlphaJack/mercurio/pull/32))

#### Server

- Add ctrl-c support ([#8](https://github.com/AlphaJack/mercurio/pull/8))

#### Services

- **breaking**: One cargo feature per service ([#12](https://github.com/AlphaJack/mercurio/pull/12))

### Fixed

#### Cli

- Skip cached files modified within the last 2 s ([#100](https://github.com/AlphaJack/mercurio/pull/100))
- Log sends to stdout as Apprise does ([#55](https://github.com/AlphaJack/mercurio/pull/55))

#### Serve

- Install signal handlers before announcing the listener ([#30](https://github.com/AlphaJack/mercurio/pull/30))

### Other

#### Cli

- Drop the Args copy of clap's options ([#28](https://github.com/AlphaJack/mercurio/pull/28))
- Use tracing-subscriber for every command ([#20](https://github.com/AlphaJack/mercurio/pull/20))
- Dispatch on a command enum instead of strings ([#19](https://github.com/AlphaJack/mercurio/pull/19))

#### Lib

- **breaking**: Move config and attachment detail types into modules ([#98](https://github.com/AlphaJack/mercurio/pull/98))
- **breaking**: Move transport and service-author types into modules ([#95](https://github.com/AlphaJack/mercurio/pull/95))
- **breaking**: Mark the report and plan structs non-exhaustive ([#94](https://github.com/AlphaJack/mercurio/pull/94))
- **breaking**: Replace the notify variants with NotifyOptions ([#93](https://github.com/AlphaJack/mercurio/pull/93))
- **breaking**: Replace reqwest with an in-house HTTP/1.1 client ([#91](https://github.com/AlphaJack/mercurio/pull/91))
- **breaking**: Share attachment data instead of copying it ([#73](https://github.com/AlphaJack/mercurio/pull/73))
- **breaking**: Share message and request bodies instead of copying them ([#69](https://github.com/AlphaJack/mercurio/pull/69))
- **breaking**: Mark public enums non-exhaustive ([#17](https://github.com/AlphaJack/mercurio/pull/17))
- Fence internal modules behind __private ([#23](https://github.com/AlphaJack/mercurio/pull/23))
- Move date helpers from crypto to time ([#22](https://github.com/AlphaJack/mercurio/pull/22))

#### Release

- Add apprise tag to crates ([#89](https://github.com/AlphaJack/mercurio/pull/89))

#### Serve

- Copy request bodies less and cap the bytes read at once ([#56](https://github.com/AlphaJack/mercurio/pull/56))
- Stop test servers gracefully ([#49](https://github.com/AlphaJack/mercurio/pull/49))
- Cache stored configurations and logins behind a stat check ([#24](https://github.com/AlphaJack/mercurio/pull/24))
- Use idiomatic axum and tower, validate against apk ([#16](https://github.com/AlphaJack/mercurio/pull/16))

## [0.1.1](https://github.com/AlphaJack/mercurio/compare/v0.1.0...v0.1.1) - 2026-10-18

### Fixed

- Include README in crates.io packages ([#5](https://github.com/AlphaJack/mercurio/pull/5))

### Other

- Add license notice ([#1](https://github.com/AlphaJack/mercurio/pull/1))

## [0.1.0](https://github.com/AlphaJack/mercurio/releases/tag/v0.1.0) - 2026-10-18

### Other

- Move to public repository
