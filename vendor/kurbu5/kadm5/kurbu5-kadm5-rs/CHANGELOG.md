# Changelog — kurbu5-kadm5-rs

## [Unreleased]

### Added

- `PluginContext::parse_principal` and `PluginContext::build_principal`, delegating to `kurbu5_rs::principal::OwnedPrincipal`

### Changed

- `PluginContext::unparse_principal` now accepts anything convertible to a `kurbu5_rs::principal::PrincipalRef`, instead of only `&krb5_principal_data`

## [0.1.3] — 2026-07-31

No functional changes; version bump for workspace consistency.

## [0.1.2] — 2026-04-29

### Added

- New `AdminHandle` type providing a safe Rust interface to the full KADM5 administration API
- `PluginContext::as_raw()` is now public, enabling FFI interop from downstream crates
- New `Profile::from_raw_context` constructor and `PluginContext::profile` accessor for reading krb5 configuration from within a plugin

### Changed

- `Krb5Error` is now the same type shared with kurbu5-rs, removing conversions at the crate boundary

### Fixed

- `initvt_plugin!` now accepts trailing commas and turbofish paths without a compile error

## [0.1.1] — 2026-04-14

### Added

- Fedora RPM packaging

### Fixed

- Pedantic clippy warning fixes

## [0.1.0] — 2026-04-04

### Added

- Add kurbu5-rs dependency for shared TL-data types
- Wrap bridge functions with catch_unwind to prevent panic UB
- Change NAME constant type to `&'static CStr`
- Implement KADM5_HOOK plugin interface
- Implement KADM5_AUTH plugin interface
- Public API and `initvt_plugin!` macro
- Cargo.toml with `kadm5_auth` and `kadm5_hook` features

### Fixed

- Shared error, context, and principal-entry types
