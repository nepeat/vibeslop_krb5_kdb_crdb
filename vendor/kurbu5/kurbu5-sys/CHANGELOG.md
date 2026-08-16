# Changelog — kurbu5-sys

## [Unreleased]


## [0.1.3] — 2026-07-31

### Added

- `krb5_c_fx_cf2_simple`, `krb5_free_keyblock`, and `krb5_free_keyblock_contents` added to the bindgen allowlist for PA-PKINIT-KX (RFC 6112) support

## [0.1.2] — 2026-04-29

### Added

- The bindgen allowlist for KADM5 now covers all types and functions declared in `admin.h`

## [0.1.1] — 2026-04-14

### Added

- Fedora RPM packaging

### Fixed

- Pedantic clippy warning fixes

## [0.1.0] — 2026-04-04

### Added

- `audit_plugin.h` vendored with bindgen bindings
- OTP preauth types with encode, decode, and free symbols
- Profile, crypto, and principal utility bindings
- `Krb5Context` owned RAII wrapper and context integration tests
- MIT krb5 license wired into all Cargo manifests
- Raw MIT krb5 FFI bindings via bindgen
