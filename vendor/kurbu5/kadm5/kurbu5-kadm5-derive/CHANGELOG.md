# Changelog — kurbu5-kadm5-derive

## [Unreleased]


## [0.1.3] — 2026-07-31

No functional changes; version bump for workspace consistency.

## [0.1.2] — 2026-04-29

No functional changes; version bump for workspace consistency.

## [0.1.1] — 2026-04-14

### Added

- Fedora RPM packaging

### Fixed

- Pedantic clippy warning fixes

## [0.1.0] — 2026-04-04

### Added

- Proc-macro derives for KADM5 plugin interfaces
- Cargo.toml

### Fixed

- Emit NAME constant in hostrealm, kdcpolicy, and certauth derives
- Emit `&'static CStr` for NAME; fix an2ln delegate
