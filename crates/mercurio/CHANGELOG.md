# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [0.2.3](https://github.com/AlphaJack/mercurio/compare/mercurio-v0.2.2...mercurio-v0.2.3) - 2026-10-24

### Added

#### Lib

- enable transport-blocking by default ([#123](https://github.com/AlphaJack/mercurio/pull/123))

### Fixed

#### Lib

- convert HTML without the html feature ([#122](https://github.com/AlphaJack/mercurio/pull/122))

### Other

#### Lib

- gate tests and doctests on the services they use ([#116](https://github.com/AlphaJack/mercurio/pull/116))
## [0.2.2](https://github.com/AlphaJack/mercurio/compare/mercurio-v0.2.1...mercurio-v0.2.2) - 2026-10-24

### Added

#### Lib

- add timezones feature, UTC only without it ([#113](https://github.com/AlphaJack/mercurio/pull/113))
- add regex-unicode feature, regex-lite without it ([#112](https://github.com/AlphaJack/mercurio/pull/112))
- make heavy dependencies optional behind cargo features ([#109](https://github.com/AlphaJack/mercurio/pull/109))

### Fixed

#### Lib

- adopt fixes for IFTTT, Pushover, Streamlabs and incident actions ([#115](https://github.com/AlphaJack/mercurio/pull/115))

### Other

#### Lib

- one sans-IO HTTP/1.1 client for both transports, drop ureq ([#114](https://github.com/AlphaJack/mercurio/pull/114))
## [0.2.1](https://github.com/AlphaJack/mercurio/compare/mercurio-v0.2.0...mercurio-v0.2.1) - 2026-10-22

### Fixed

#### Services

- wipe every copy of the PKCS#1 key built for RSA signing ([#102](https://github.com/AlphaJack/mercurio/pull/102))

### Other

#### Lib

- mark Param #[non_exhaustive] ([#106](https://github.com/AlphaJack/mercurio/pull/106))
- mark methods returning Self #[must_use] ([#104](https://github.com/AlphaJack/mercurio/pull/104))
- drop redundant clones, for_each, match-to-unwrap and constant flags ([#103](https://github.com/AlphaJack/mercurio/pull/103))
## [0.2.0](https://github.com/AlphaJack/mercurio/compare/mercurio-v0.1.1...mercurio-v0.2.0) - 2026-10-21

### Added

#### Cli

- adding -T / --theme for the {THEME} of image URLs ([#40](https://github.com/AlphaJack/mercurio/pull/40))

#### Lib

- **breaking**: per-request body limit; attachments stop at their limit ([#42](https://github.com/AlphaJack/mercurio/pull/42))
- **breaking**: expand :shortcode: emoji (-j, ?emojis=, interpret_emojis) ([#37](https://github.com/AlphaJack/mercurio/pull/37))
- **breaking**: storage modes auto, flush and memory (-SM) ([#35](https://github.com/AlphaJack/mercurio/pull/35))
- **breaking**: escalate tag priority groups and honor -g tag:N ([#36](https://github.com/AlphaJack/mercurio/pull/36))
- **breaking**: configurable URL id length and salt (-SUL) ([#34](https://github.com/AlphaJack/mercurio/pull/34))
- **breaking**: run delivery on an async core with a default tokio transport ([#15](https://github.com/AlphaJack/mercurio/pull/15))
- bundle the time zone database by default ([#82](https://github.com/AlphaJack/mercurio/pull/82))
- checksum persistent cache entries as in apprise ([#54](https://github.com/AlphaJack/mercurio/pull/54))
- report each URL as it finishes with notify_with_progress ([#31](https://github.com/AlphaJack/mercurio/pull/31))
- give AsyncMercurio the same API as Mercurio ([#29](https://github.com/AlphaJack/mercurio/pull/29))

#### Services

- **breaking**: native d-bus client for dbus, glib and gnome ([#57](https://github.com/AlphaJack/mercurio/pull/57))
- **breaking**: use consistent service names ([#13](https://github.com/AlphaJack/mercurio/pull/13))
- **breaking**: one cargo feature per service ([#12](https://github.com/AlphaJack/mercurio/pull/12))
- generate pgp keys and send the autocrypt header ([#86](https://github.com/AlphaJack/mercurio/pull/86))
- look pgp keys up in the recipient's web key directory ([#85](https://github.com/AlphaJack/mercurio/pull/85))
- encrypt e-mail and delta chat with pgp ([#84](https://github.com/AlphaJack/mercurio/pull/84))
- sign e-mail and delta chat with pgp ([#81](https://github.com/AlphaJack/mercurio/pull/81))
- upload the notify-type image to telegram as apprise does ([#75](https://github.com/AlphaJack/mercurio/pull/75))
- check matrix cross-signing before sharing room keys ([#74](https://github.com/AlphaJack/mercurio/pull/74))
- seal matrix e2ee state at rest ([#72](https://github.com/AlphaJack/mercurio/pull/72))
- scram-plus channel binding for xmpp ([#71](https://github.com/AlphaJack/mercurio/pull/71))
- accept compressed p256dh keys in VAPID subscriptions ([#52](https://github.com/AlphaJack/mercurio/pull/52))
- http(s) key and subscription files for VAPID ([#51](https://github.com/AlphaJack/mercurio/pull/51))
- http(s) templates for Telegram, Slack and Workflows ([#50](https://github.com/AlphaJack/mercurio/pull/50))
- feed Telegram and Matrix rate-limit hints into ?retry= ([#27](https://github.com/AlphaJack/mercurio/pull/27))
- add file:// destination ([#11](https://github.com/AlphaJack/mercurio/pull/11))

### Fixed

#### Lib

- share one send budget between both notifiers ([#18](https://github.com/AlphaJack/mercurio/pull/18))
- cap concurrent sends at 128 per process ([#10](https://github.com/AlphaJack/mercurio/pull/10))

#### Services

- keep Mastodon and Twitter account lookups across sends ([#48](https://github.com/AlphaJack/mercurio/pull/48))
- keep %2F encoded in json, xml and form paths ([#44](https://github.com/AlphaJack/mercurio/pull/44))
- keep rate-limit budgets across sends ([#38](https://github.com/AlphaJack/mercurio/pull/38))

### Other

- drop the per-entry intentional markers from the service docs ([#77](https://github.com/AlphaJack/mercurio/pull/77))
- write the differences as prose instead of arrows ([#61](https://github.com/AlphaJack/mercurio/pull/61))
- drop statements left over from the blocking core ([#26](https://github.com/AlphaJack/mercurio/pull/26))
- rename Differences to Differences with Apprise ([#25](https://github.com/AlphaJack/mercurio/pull/25))

#### Lib

- **breaking**: move config and attachment detail types into modules ([#98](https://github.com/AlphaJack/mercurio/pull/98))
- **breaking**: name the Target send methods after what they return ([#96](https://github.com/AlphaJack/mercurio/pull/96))
- **breaking**: move transport and service-author types into modules ([#95](https://github.com/AlphaJack/mercurio/pull/95))
- **breaking**: mark the report and plan structs non-exhaustive ([#94](https://github.com/AlphaJack/mercurio/pull/94))
- **breaking**: replace the notify variants with NotifyOptions ([#93](https://github.com/AlphaJack/mercurio/pull/93))
- **breaking**: give each notifier its own service registry ([#92](https://github.com/AlphaJack/mercurio/pull/92))
- **breaking**: replace reqwest with an in-house HTTP/1.1 client ([#91](https://github.com/AlphaJack/mercurio/pull/91))
- **breaking**: share attachment data instead of copying it ([#73](https://github.com/AlphaJack/mercurio/pull/73))
- **breaking**: share message and request bodies instead of copying them ([#69](https://github.com/AlphaJack/mercurio/pull/69))
- **breaking**: mark public enums non-exhaustive ([#17](https://github.com/AlphaJack/mercurio/pull/17))
- replace md-5, async-lock and thiserror with in-house code ([#97](https://github.com/AlphaJack/mercurio/pull/97))
- expect every file to be executable on windows ([#90](https://github.com/AlphaJack/mercurio/pull/90))
- write more services from the borrowed message ([#83](https://github.com/AlphaJack/mercurio/pull/83))
- move the remaining JSON services to the borrowed message, review e-mail and mqtt ([#79](https://github.com/AlphaJack/mercurio/pull/79))
- write service payloads from the borrowed message ([#78](https://github.com/AlphaJack/mercurio/pull/78))
- write json, form and xml bodies from the borrowed message ([#70](https://github.com/AlphaJack/mercurio/pull/70))
- derive error's display and source with thiserror ([#63](https://github.com/AlphaJack/mercurio/pull/63))
- read the clock and randomness from the transport's Env ([#39](https://github.com/AlphaJack/mercurio/pull/39))
- fence internal modules behind __private ([#23](https://github.com/AlphaJack/mercurio/pull/23))
- move date helpers from crypto to time ([#22](https://github.com/AlphaJack/mercurio/pull/22))
- split notify.rs into target, report and notify ([#21](https://github.com/AlphaJack/mercurio/pull/21))

#### Release

- add apprise tag to crates ([#89](https://github.com/AlphaJack/mercurio/pull/89))

#### Serve

- use idiomatic axum and tower, validate against apk ([#16](https://github.com/AlphaJack/mercurio/pull/16))

#### Services

- drop p256 and aes-gcm for ring and in-house code ([#99](https://github.com/AlphaJack/mercurio/pull/99))
- split pgp and matrix e2ee into modules ([#88](https://github.com/AlphaJack/mercurio/pull/88))
- make the socket protocols sans-IO ([#43](https://github.com/AlphaJack/mercurio/pull/43))

## [0.1.1](https://github.com/AlphaJack/mercurio/compare/mercurio-v0.1.0...mercurio-v0.1.1) - 2026-10-18

### Fixed

- include README in crates.io packages ([#5](https://github.com/AlphaJack/mercurio/pull/5))

### Other

- add license notice ([#1](https://github.com/AlphaJack/mercurio/pull/1))

## [0.1.0](https://github.com/AlphaJack/mercurio/releases/tag/mercurio-v0.1.0) - 2026-10-18

### Fixed

- *(ci)* clippy 1.99 lints, desktop snapshots, Windows paths, cargo-deny wrapper ([#2](https://github.com/AlphaJack/mercurio/pull/2))

### Other

- Move to public repository
