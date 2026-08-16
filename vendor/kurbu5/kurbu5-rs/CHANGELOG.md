# Changelog — kurbu5-rs

## [Unreleased]

### Added

- `principal` module: `OwnedPrincipal` (parse a principal string via `krb5_parse_name`, or build one directly from a realm and explicit components, bypassing libkrb5's C-variadic `krb5_build_principal_ext`) and `PrincipalRef` (zero-copy accessors — realm, components, name type — over any `&krb5_principal_data` reference, including the ones plugin trait methods already receive)
- `PluginContext::parse_principal` and `PluginContext::build_principal`
- `KdcpreauthCallbacks::client_name_principal`, returning the client principal as a structural `PrincipalRef` (alongside the existing `client_name_string`, which unparses it to a `String`)

### Changed

- `PluginContext::unparse_principal` now accepts anything convertible to a `PrincipalRef` (a raw `&krb5_principal_data` reference, or a `&OwnedPrincipal`), instead of only `&krb5_principal_data`

## [0.1.3] — 2026-07-31

### Added

- `fx_cf2_simple` crypto wrapper for KRB-FX-CF2 key combination (RFC 6113)
- `encrypting_key` and `reply` fields on `ReturnPadataRequest` for plugins that modify the reply key or session key
- `request_packet` and `request` fields on `ReturnPadataRequest` for RFC 8636 KDF key derivation
- `supply_gic_opts` optional method on `ClpreauthModule` for receiving `kinit -X` attributes
- `KeyblockRef::from_raw` constructor for wrapping raw keyblock pointers

## [0.1.2] — 2026-04-29

### Added

- New `Profile::from_raw_context` constructor and `PluginContext::profile` accessor for building a `Profile` from a raw plugin context pointer

### Fixed

- Corrected broken intra-doc links and table-of-contents order in the crate documentation
- `initvt_plugin!` now accepts trailing commas and turbofish paths without a compile error

## [0.1.1] — 2026-04-14

### Added

- Fedora RPM packaging

### Fixed

- Pedantic clippy warning fixes

## [0.1.0] — 2026-04-04

### Added

- Audit feature flag and re-exports
- Glue layer
- `AuditStateRef` view type and `AuditModule` trait
- TGT principal accessors on `TgsRequest`
- OTP feature forwarding from kurbu5-sys
- Crypto wrappers for encrypt, decrypt, and random_bytes
- `Profile` RAII wrapper for krb5 config access
- `fast_armor()` and `client_name_string()` accessors
- `KeyblockRef::as_ptr()`
- Shared `tl_data` module
- Bridge functions wrapped with `catch_unwind` to prevent panic UB
- KDC preauth `pa_data` allocated with the C allocator
- NAME constant typed as `&'static CStr`
- kurbu5-rs and kadm5 README API references
- Integration tests for CLPREAUTH, KDCPREAUTH, CERTAUTH, KDCPOLICY, CCSELECT, LOCALAUTH, HOSTREALM, and PWQUAL vtables
- Implementations of all the above plugin interfaces
- PWQUAL minimum-length example binary
- Public API surface and `initvt_plugin!` macro
- Shared `PluginContext<'ctx>` wrapper
- Shared `Krb5Error` type
- Cargo.toml with per-interface feature flags

### Fixed

- NAME constant type corrected from `&'static str` to `&'static CStr`
- `Display` and `Error` impls added to `Krb5Error` and `PwqualError`

### Removed

- Redundant outer `unsafe` blocks in certauth, kdcpolicy, and localauth glue
- `unsafe` qualifier removed from `catch_unwind`-wrapped bridge functions
- `get_module` helper with a false `'static` lifetime
